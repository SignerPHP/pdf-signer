<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfArrayNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfDictionaryNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfRawNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfStringNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfSyntaxParser;

final class PdfSyntaxParserTest extends TestCase
{
    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function literalStrings(): iterable
    {
        yield 'plain' => ['(abc)', 'abc'];
        yield 'keeps surrounding spaces' => ['(  a b  )', '  a b  '];
        yield 'nested parentheses' => ['(a(b(c))d)', 'a(b(c))d'];
        yield 'escaped parentheses and backslash' => ['(\\(x\\) \\\\)', '(x) \\'];
        yield 'named escapes' => ['(\\n\\r\\t\\b\\f)', "\n\r\t\x08\f"];
        yield 'octal escapes' => ['(\\351\\0\\12a\\1234)', "\xE9\0\na\x534"];
        yield 'octal overflow wraps to a byte' => ['(\\777)', "\xFF"];
        yield 'line continuation LF' => ["(ab\\\ncd)", 'abcd'];
        yield 'line continuation CRLF' => ["(ab\\\r\ncd)", 'abcd'];
        yield 'line continuation CR' => ["(ab\\\rcd)", 'abcd'];
        yield 'unescaped CRLF becomes LF' => ["(a\r\nb)", "a\nb"];
        yield 'unescaped CR becomes LF' => ["(a\rb)", "a\nb"];
        yield 'unknown escape drops the backslash' => ['(\\q)', 'q'];
        yield 'percent is not a comment inside strings' => ['(50% off)', '50% off'];
    }

    #[DataProvider('literalStrings')]
    public function test_decodes_literal_strings(string $source, string $expected): void
    {
        $node = (new PdfSyntaxParser($source))->parseValue();

        self::assertInstanceOf(PdfStringNode::class, $node);
        self::assertSame($expected, $node->bytes);
    }

    public function test_decodes_hex_strings_with_whitespace_and_odd_length(): void
    {
        $node = (new PdfSyntaxParser("<48 65\n6C6c 6F7>"))->parseValue();

        self::assertInstanceOf(PdfStringNode::class, $node);
        self::assertSame("Hello\x70", $node->bytes);
        self::assertEquals(new PdfStringNode(''), (new PdfSyntaxParser('<>'))->parseValue());
    }

    public function test_parses_dictionaries_arrays_references_and_comments(): void
    {
        $source = "<< /Type /Page % comment\n /Kids [1 0 R 2 0 R 3] /Num 12 /Neg -1.5 /Flag true /Nested << /A null >> /Empty [] >>";
        $node = (new PdfSyntaxParser($source))->parseValue();

        self::assertInstanceOf(PdfDictionaryNode::class, $node);
        self::assertSame('/Page', $node->rawToken('Type'));
        self::assertSame('12', $node->rawToken('Num'));
        self::assertSame('-1.5', $node->rawToken('Neg'));
        self::assertSame('true', $node->rawToken('Flag'));
        self::assertNull($node->rawToken('Kids'));
        self::assertNull($node->rawToken('Missing'));
        self::assertFalse($node->has('Missing'));

        $kids = $node->get('Kids');
        self::assertInstanceOf(PdfArrayNode::class, $kids);
        self::assertEquals([new PdfRawNode('1 0 R'), new PdfRawNode('2 0 R'), new PdfRawNode('3')], $kids->items);

        $nested = $node->get('Nested');
        self::assertInstanceOf(PdfDictionaryNode::class, $nested);
        self::assertSame('null', $nested->rawToken('A'));

        self::assertEquals(new PdfArrayNode([]), $node->get('Empty'));

        $function = (new PdfSyntaxParser('[{1 add}]'))->parseValue();
        self::assertEquals(new PdfArrayNode([new PdfRawNode('{'), new PdfRawNode('1'), new PdfRawNode('add'), new PdfRawNode('}')]), $function);
    }

    public function test_numbers_followed_by_non_reference_tokens_are_kept_apart(): void
    {
        $node = (new PdfSyntaxParser('[1 2 3 0 obj 4 5 /R]'))->parseValue();

        self::assertInstanceOf(PdfArrayNode::class, $node);
        self::assertEquals(
            ['1', '2', '3', '0', 'obj', '4', '5', '/R'],
            array_map(static fn (PdfRawNode $item): string => $item->token, $node->items),
        );
    }

    public function test_dictionary_set_replaces_existing_and_appends_new_keys(): void
    {
        $dictionary = new PdfDictionaryNode([['A', new PdfRawNode('1')]]);
        $dictionary->set('A', new PdfRawNode('2'))->set('B', new PdfRawNode('3'));

        self::assertEquals([['A', new PdfRawNode('2')], ['B', new PdfRawNode('3')]], $dictionary->entries());
    }

    public function test_reads_object_headers_and_resets_position_on_failure(): void
    {
        $parser = new PdfSyntaxParser("  12 3 obj\n<< >>");
        self::assertSame([12, 3], $parser->readObjectHeader());

        $invalid = new PdfSyntaxParser('12 x obj');
        self::assertNull($invalid->readObjectHeader());
        self::assertSame(0, $invalid->position());

        self::assertNull((new PdfSyntaxParser('/Name'))->readKeyword());
        self::assertNull((new PdfSyntaxParser('   '))->readKeyword());
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function malformedObjects(): iterable
    {
        yield 'empty' => [''];
        yield 'only a comment' => ['% nothing here'];
        yield 'unterminated literal string' => ['(abc'];
        yield 'unterminated hex string' => ['<414243'];
        yield 'invalid hex string' => ['<41zz>'];
        yield 'unterminated dictionary' => ['<< /A 1'];
        yield 'unterminated array' => ['[1 2'];
        yield 'dictionary key is not a name' => ['<< 1 2 >>'];
        yield 'unexpected closing parenthesis' => [')'];
        yield 'unexpected closing bracket' => [']'];
        yield 'unexpected closing angle' => ['>'];
        yield 'dictionary value missing' => ['<< /A'];
    }

    #[DataProvider('malformedObjects')]
    public function test_rejects_malformed_objects(string $source): void
    {
        $this->expectException(ProtectionProcessException::class);

        (new PdfSyntaxParser($source))->parseValue();
    }
}
