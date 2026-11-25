<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Asn1Node;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;

final class Asn1NodeTest extends TestCase
{
    public function test_reads_a_definite_length_element_and_ignores_trailing_padding(): void
    {
        $node = Asn1Node::read("\x30\x03\x02\x01\x05\x00\x00");

        self::assertSame(0x30, $node->tag);
        self::assertSame("\x30\x03\x02\x01\x05", $node->encoded);
        self::assertFalse($node->indefiniteLength);
        self::assertSame("\x05", $node->child(0, Asn1Node::TAG_INTEGER)->content);
    }

    public function test_reads_long_form_lengths(): void
    {
        $value = str_repeat('A', 300);
        $node = Asn1Node::readExact(Der::octetString($value));

        self::assertSame($value, $node->octets());
    }

    public function test_reads_indefinite_lengths_and_constructed_octet_strings(): void
    {
        // SEQUENCE (indefinite) { OCTET STRING (constructed, indefinite) { "ab", "cd" } }
        $ber = "\x30\x80\x24\x80\x04\x02ab\x04\x02cd\x00\x00\x00\x00";
        $node = Asn1Node::readExact($ber);

        self::assertTrue($node->indefiniteLength);
        self::assertSame('abcd', $node->child(0)->octets());
        self::assertSame("\x30\x0C\x24\x80\x04\x02ab\x04\x02cd\x00\x00", $node->withTag(0x30));
    }

    /**
     * @return array<string, array{0:string, 1:string}>
     */
    public static function malformed(): array
    {
        return [
            'empty' => ['', 'Truncated ASN.1 element.'],
            'single byte' => ["\x30", 'Truncated ASN.1 element.'],
            'high tag number' => ["\x1F\x01\x00", 'High-tag-number ASN.1 identifiers are not supported.'],
            'indefinite primitive' => ["\x04\x80\x00\x00", 'Indefinite length on a primitive ASN.1 element.'],
            'missing end-of-contents' => ["\x30\x80\x02\x01\x01", 'Missing end-of-contents in indefinite-length element.'],
            'more than four length bytes' => ["\x30\x85\x00\x00\x00\x00\x01", 'Unsupported ASN.1 length.'],
            'length bytes cut short' => ["\x30\x82\x01", 'Truncated ASN.1 length.'],
            'value past the end' => ["\x30\x05\x02\x01\x00", 'ASN.1 element exceeds its container.'],
        ];
    }

    #[DataProvider('malformed')]
    public function test_rejects_malformed_input(string $der, string $message): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage($message);

        Asn1Node::read($der);
    }

    public function test_rejects_trailing_data_in_exact_mode(): void
    {
        $this->expectExceptionMessage('Trailing data after ASN.1 element.');

        Asn1Node::readExact("\x05\x00\x00");
    }

    public function test_rejects_excessive_nesting(): void
    {
        $this->expectExceptionMessage('ASN.1 nesting is too deep.');

        Asn1Node::read(str_repeat("\x30\x80", 70).str_repeat("\x00\x00", 70));
    }

    public function test_navigation_errors_are_reported(): void
    {
        $sequence = Asn1Node::read("\x30\x03\x02\x01\x05");

        try {
            $sequence->child(1);
            self::fail('A missing child must throw.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('Missing ASN.1 element #1.', $exception->getMessage());
        }

        try {
            $sequence->child(0, Asn1Node::TAG_OID);
            self::fail('An unexpected tag must throw.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('Unexpected ASN.1 tag 0x02, expected 0x06.', $exception->getMessage());
        }

        $this->expectExceptionMessage('ASN.1 element is not constructed.');
        $sequence->child(0)->children();
    }

    /**
     * @return array<string, array{0:string}>
     */
    public static function objectIdentifiers(): array
    {
        return [
            'sha256' => ['2.16.840.1.101.3.4.2.1'],
            'rsaEncryption' => ['1.2.840.113549.1.1.1'],
            'first arc 0' => ['0.9.2342.19200300.100.1.1'],
            'first arc 2 with a large second arc' => ['2.999.3'],
        ];
    }

    #[DataProvider('objectIdentifiers')]
    public function test_decodes_object_identifiers(string $oid): void
    {
        self::assertSame($oid, Asn1Node::readExact(Der::objectIdentifier($oid))->oid());
    }

    public function test_rejects_malformed_object_identifiers(): void
    {
        foreach (["\x06\x00", "\x06\x01\x81", "\x06\x0B\x2A".str_repeat("\xFF", 9)."\x7F"] as $der) {
            try {
                Asn1Node::readExact($der)->oid();
                self::fail('Malformed OID accepted: '.bin2hex($der));
            } catch (\UnexpectedValueException $exception) {
                self::assertStringContainsString('OBJECT IDENTIFIER', $exception->getMessage());
            }
        }
    }
}
