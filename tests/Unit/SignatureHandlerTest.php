<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfCore\Metadata;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfCore\PDFObject;
use SignerPHP\PdfCore\PdfValue\PDFValueList;
use SignerPHP\PdfCore\PdfValue\PDFValueObject;
use SignerPHP\PdfCore\PdfValue\PDFValueReference;
use SignerPHP\PdfCore\SignatureAppearance;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\SignatureHandler;

final class SignatureHandlerTest extends TestCase
{
    public function test_has_certificate_changes_after_with_certificate(): void
    {
        $signature = SignatureHandler::new();
        self::assertFalse($signature->hasCertificate());

        $signature->withCertificate(['cert' => 'CERT', 'pkey' => 'KEY', 'extracerts' => '']);
        self::assertTrue($signature->hasCertificate());
    }

    public function test_generate_signature_in_document_applies_custom_subfilter(): void
    {
        $document = $this->buildDocumentWithSinglePage();

        $signature = SignatureHandler::new()
            ->withPdfDocument($document)
            ->withMetadata(Metadata::new()->withName('Tester'))
            ->withSubFilter(SignatureObject::SUBFILTER_ETSI_CADES_DETACHED)
            ->withoutAppearance();

        $result = $signature->generateSignatureInDocument();

        self::assertSame(SignatureObject::SUBFILTER_ETSI_CADES_DETACHED, (string) $result['SubFilter']);
    }

    public function test_generate_signature_in_document_requires_pdf_document(): void
    {
        $signature = SignatureHandler::new()->withMetadata(Metadata::new()->withName('Tester'));

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('PDF document is required to generate the signature.');
        $signature->generateSignatureInDocument();
    }

    public function test_generate_signature_in_document_requires_metadata(): void
    {
        $signature = SignatureHandler::new()->withPdfDocument($this->buildDocumentWithSinglePage());

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Metadata is required to generate the signature.');
        $signature->generateSignatureInDocument();
    }

    private function buildDocumentWithSinglePage(): PdfDocument
    {
        $document = new PdfDocument;
        $document->setTrailerObject(new PDFValueObject([
            'Root' => new PDFValueReference(1),
        ]));

        $root = new PDFObject(1, [
            'Type' => '/Catalog',
            'Pages' => new PDFValueReference(2),
        ]);
        $pages = new PDFObject(2, [
            'Type' => '/Pages',
            'Kids' => new PDFValueList([new PDFValueReference(3)]),
            'Count' => 1,
            'MediaBox' => new PDFValueList([0, 0, 595, 842]),
        ]);
        $page = new PDFObject(3, [
            'Type' => '/Page',
            'Parent' => new PDFValueReference(2),
            'MediaBox' => new PDFValueList([0, 0, 595, 842]),
        ]);

        $document->addObject($root);
        $document->addObject($pages);
        $document->addObject($page);
        $document->acquirePagesInfo();

        SignatureAppearance::new()->withBackgroundImage(null)->withRect([0, 0, 0, 0]);

        return $document;
    }
}
