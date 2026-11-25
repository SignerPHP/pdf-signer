<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\ProtectionOptionsDto;
use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\EncryptedPdfDocument;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;

final class EncryptedPdfDocumentTest extends TestCase
{
    private static ?EncryptedPdfDocument $document = null;

    public function test_appends_an_encrypted_revision_with_a_chained_xref(): void
    {
        $document = self::document();
        $updated = $document->appendRevision($document->plainMirror()."9 0 obj\n<</Note (clear note)>>\nendobj\nxref\n9 1\n0000000000 00000 n\r\ntrailer\n<</Size 10 /Root 1 0 R>>\nstartxref\n0\n%%EOF\n");

        $content = $updated->content();
        self::assertStringStartsWith($document->content(), $content);
        self::assertStringNotContainsString('clear note', $content);
        self::assertMatchesRegularExpression('/\/Prev \d+/', $content);
        self::assertMatchesRegularExpression('/\/Encrypt \d+ 0 R/', substr($content, strlen($document->content())));
        // The mirror writes strings as hex.
        self::assertStringContainsString('<'.bin2hex('clear note').'>', $updated->plainMirror());
    }

    public function test_takes_the_trailer_of_a_revision_written_with_an_xref_stream(): void
    {
        $document = self::document();
        $revision = "9 0 obj\n<</Note (n)>>\nendobj\n10 0 obj\n<</Type /XRef /Size 11 /Root 1 0 R /W [1 2 1] /Length 0>>\nstream\n\nendstream\nendobj\nstartxref\n0\n%%EOF\n";

        $content = $document->appendRevision($document->plainMirror().$revision)->content();

        self::assertMatchesRegularExpression('/\/Size 11/', substr($content, strlen($document->content())));
    }

    public function test_fills_the_signature_placeholder_over_the_final_bytes(): void
    {
        $document = self::document();
        $placeholder = str_repeat('0', 64);
        $revision = "9 0 obj\n<</Type /Sig /ByteRange [0 0 0 0] /Contents <$placeholder> /M (D:20260101000000Z)>>\nendobj\nxref\n9 1\n0000000000 00000 n\r\ntrailer\n<</Size 10 /Root 1 0 R>>\nstartxref\n0\n%%EOF\n";

        $signedWith = null;
        $updated = $document->appendSignedRevision($document->plainMirror().$revision, static function (string $bytes, array $byteRange) use (&$signedWith): string {
            $signedWith = [$bytes, $byteRange];

            return 'ABCD';
        });

        $content = $updated->content();
        self::assertNotNull($signedWith);
        [$bytes, [, $start, $end, $length2]] = $signedWith;
        self::assertSame('<ABCD'.str_repeat('0', 60).'>', substr($content, $start, $end - $start));
        self::assertSame(strlen($content) - $end, $length2);
        self::assertSame(substr($content, 0, $start).substr($content, $end), $bytes);
        self::assertMatchesRegularExpression('/\/ByteRange \[0 '.$start.' '.$end.' '.$length2.' *\]/', $content);
        self::assertStringNotContainsString('D:20260101', $content);
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: bool}>
     */
    public static function invalidRevisions(): iterable
    {
        $xref = "xref\n9 1\n0000000000 00000 n\r\ntrailer\n<</Size 10 /Root 1 0 R>>\nstartxref\n0\n%%EOF\n";

        yield 'no signature placeholder' => ["9 0 obj\n<</Note (n)>>\nendobj\n".$xref, 'Expected one signature placeholder in the PDF update, found 0.', true];
        yield 'object without endobj' => ["9 0 obj\n<</Note (n)>>\n".$xref, 'Malformed object 9 in the PDF update.', false];
        yield 'no trailer' => ["9 0 obj\n<</Note (n)>>\nendobj\n", 'The PDF update has no objects or no trailer.', false];
        yield 'stream with an indirect length' => ["9 0 obj\n<</Length 3 0 R>>\nstream\nabc\nendstream\nendobj\n".$xref, 'Streams in a PDF update must have a direct /Length.', false];
        yield 'stream length mismatch' => ["9 0 obj\n<</Length 1>>\nstream\nabc\nendstream\nendobj\n".$xref, 'Stream /Length does not match its data in the PDF update.', false];
    }

    #[DataProvider('invalidRevisions')]
    public function test_rejects_malformed_updates(string $revision, string $message, bool $signed): void
    {
        $document = self::document();

        $this->expectException(ProtectionProcessException::class);
        $this->expectExceptionMessage($message);

        $signed
            ? $document->appendSignedRevision($document->plainMirror().$revision, static fn (): string => '')
            : $document->appendRevision($document->plainMirror().$revision);
    }

    public function test_rejects_an_update_that_does_not_extend_the_mirror(): void
    {
        $this->expectExceptionMessage('The update was not appended to the clear mirror of the encrypted PDF.');

        self::document()->appendRevision('%PDF-1.7 something else');
    }

    public function test_rejects_a_signature_larger_than_its_placeholder(): void
    {
        $document = self::document();
        $revision = "9 0 obj\n<</Type /Sig /ByteRange [0 0 0 0] /Contents <0000>>>\nendobj\nxref\n9 1\n0000000000 00000 n\r\ntrailer\n<</Size 10 /Root 1 0 R>>\nstartxref\n0\n%%EOF\n";

        $this->expectExceptionMessage('The signature does not fit the reserved /Contents of the encrypted PDF.');

        $document->appendSignedRevision($document->plainMirror().$revision, static fn (): string => 'ABCDEF');
    }

    public function test_appends_after_a_file_that_does_not_end_with_a_line_break(): void
    {
        $content = rtrim(self::document()->content());
        $document = EncryptedPdfDocument::open($content);
        self::assertNotNull($document);

        $updated = $document->appendRevision($document->plainMirror()."9 0 obj\n<</Note (n)>>\nendobj\nxref\n9 1\n0000000000 00000 n\r\ntrailer\n<</Size 10 /Root 1 0 R>>\nstartxref\n0\n%%EOF\n");

        self::assertStringStartsWith($content."\n9 0 obj", $updated->content());
    }

    public function test_opens_a_document_whose_encryption_dictionary_is_inline_in_the_trailer(): void
    {
        $content = self::document()->content();
        self::assertSame(1, preg_match('/(\d+) 0 obj\n(<<\/Filter \/Standard.*?>>)\nendobj/s', $content, $encrypt));
        // The object that held the dictionary becomes null (same length, so xref offsets stay valid).
        $withoutObject = str_replace($encrypt[2], str_pad('null', strlen($encrypt[2])), $content);
        $inline = str_replace('/Encrypt '.$encrypt[1].' 0 R', '/Encrypt '.$encrypt[2], $withoutObject);

        $document = EncryptedPdfDocument::open($inline);

        self::assertNotNull($document);
        self::assertStringContainsString('/Type /Catalog', $document->plainMirror());
    }

    private static function document(): EncryptedPdfDocument
    {
        return self::$document ??= EncryptedPdfDocument::open(
            Signer::protection()
                ->withPdfContent(PdfFixtureFactory::minimalPdf())
                ->withProtection(ProtectionOptionsDto::preventCopy(ownerPassword: 'owner'))
                ->protect(),
        ) ?? throw new \LogicException('not encrypted');
    }
}
