<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\PdfSignatureExtractor;

final class PdfSignatureExtractorTest extends TestCase
{
    public function test_extractor_returns_empty_when_no_signatures_exist(): void
    {
        $extractor = new PdfSignatureExtractor;
        $signatures = $extractor->extract('%PDF-1.7 no signatures');

        self::assertSame([], $signatures);
    }

    public function test_extractor_parses_signature_dictionary_and_byte_range(): void
    {
        $pdf = <<<'PDF'
%PDF-1.7
1 0 obj
<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 12 20 8] /Contents <A1B2C3D4> >>
endobj
HelloSignedContent
PDF;

        $extractor = new PdfSignatureExtractor;
        $signatures = $extractor->extract($pdf);

        self::assertCount(1, $signatures);
        self::assertSame([0, 12, 20, 8], $signatures[0]->byteRange);
        self::assertSame('A1B2C3D4', $signatures[0]->signatureHex);
    }

    public function test_extractor_skips_dictionary_when_type_is_not_sig(): void
    {
        $pdf = <<<'PDF'
%PDF-1.7
1 0 obj
<< /Type /Catalog /ByteRange [0 12 20 8] /Contents <A1B2C3D4> >>
endobj
PDF;

        $extractor = new PdfSignatureExtractor;

        self::assertSame([], $extractor->extract($pdf));
    }

    public function test_extractor_skips_dictionary_without_contents(): void
    {
        $pdf = <<<'PDF'
%PDF-1.7
1 0 obj
<< /Type /Sig /ByteRange [0 12 20 8] >>
endobj
PDF;

        $extractor = new PdfSignatureExtractor;

        self::assertSame([], $extractor->extract($pdf));
    }

    public function test_extractor_skips_when_candidate_dictionary_boundaries_cannot_be_resolved(): void
    {
        $pdf = '%PDF-1.7 /ByteRange [0 2 4 2] stray bytes without dictionary terminator';

        $extractor = new PdfSignatureExtractor;

        self::assertSame([], $extractor->extract($pdf));
    }

    public function test_extractor_marks_signature_as_invalid_when_byte_range_boundaries_are_invalid(): void
    {
        $pdf = <<<'PDF'
%PDF-1.7
1 0 obj
<< /Type /Sig /ByteRange [0 12 10 5] /Contents <AA55> >>
endobj
payload
PDF;

        $extractor = new PdfSignatureExtractor;
        $signatures = $extractor->extract($pdf);

        self::assertCount(1, $signatures);
        self::assertFalse($signatures[0]->byteRangeValid);
        self::assertSame('Invalid ByteRange boundaries.', $signatures[0]->byteRangeError);
        self::assertSame('', $signatures[0]->signedContent);
    }

    public function test_extractor_marks_signature_as_invalid_when_byte_range_exceeds_document_size(): void
    {
        $pdf = <<<'PDF'
%PDF-1.7
1 0 obj
<< /Type /Sig /ByteRange [0 10 200 10] /Contents <A1> >>
endobj
tiny
PDF;

        $extractor = new PdfSignatureExtractor;
        $signatures = $extractor->extract($pdf);

        self::assertCount(1, $signatures);
        self::assertFalse($signatures[0]->byteRangeValid);
        self::assertSame('ByteRange exceeds PDF size.', $signatures[0]->byteRangeError);
        self::assertSame('', $signatures[0]->signedContent);
    }
}
