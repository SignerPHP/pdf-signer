<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native;

use SignerPHP\PdfSigner\Application\Contract\PdfSigningEngineInterface;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderFactoryInterface;
use SignerPHP\PdfSigner\Application\DTO\LocalSigningContextDto;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\EncryptedSignedBufferBuilderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PdfDocumentPreparerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureFactoryInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignedBufferBuilderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\EncryptedPdfDocument;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProviderFactory;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\PdfDocumentPreparer;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\PdfSignatureFactory;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Pkcs7Signer;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\SignedBufferBuilder;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\XrefContentResolver;

final readonly class NativePdfSigningEngine implements PdfSigningEngineInterface
{
    public function __construct(
        private PdfDocumentPreparerInterface $documentPreparer = new PdfDocumentPreparer,
        private SignatureFactoryInterface $signatureFactory = new PdfSignatureFactory,
        private SignedBufferBuilderInterface $signedBufferBuilder = new SignedBufferBuilder(
            new XrefContentResolver,
            new Pkcs7Signer,
        ),
        private SignatureProviderFactoryInterface $signatureProviderFactory = new LocalPrivateKeySignatureProviderFactory,
    ) {}

    public function sign(LocalSigningContextDto $context): string
    {
        try {
            $signingContext = $context->signingContext;
            $encryptedDocument = $this->openEncrypted($signingContext->pdf->content, $signingContext->options->pdfPassword);
            if ($encryptedDocument !== null) {
                if (! $this->signedBufferBuilder instanceof EncryptedSignedBufferBuilderInterface) {
                    throw new \LogicException('Signing an encrypted PDF requires an encryption-aware signed buffer builder.');
                }

                $pdfDocument = $this->documentPreparer->prepare($encryptedDocument->plainMirror());
                $signature = $this->signatureFactory->create($signingContext, $pdfDocument);
                $signatureProvider = $this->signatureProviderFactory->create($context->verifiedCertificate);

                return (string) $this->signedBufferBuilder->buildEncrypted($encryptedDocument, $pdfDocument, $signature, $signingContext, $signatureProvider);
            }

            $pdfDocument = $this->documentPreparer->prepare($signingContext->pdf->content);
            $signature = $this->signatureFactory->create($signingContext, $pdfDocument);
            $signatureProvider = $this->signatureProviderFactory->create($context->verifiedCertificate);

            return (string) $this->signedBufferBuilder->build($pdfDocument, $signature, $signingContext, $signatureProvider);
        } catch (\Throwable $throwable) {
            throw new SignProcessException(
                sprintf('Could not sign PDF using native v1 engine. Root cause: %s', $throwable->getMessage()),
                previous: $throwable,
            );
        }
    }

    /**
     * pdf-core reads PDFs in clear: an encrypted input is signed through its clear mirror, and the
     * signature revision is appended to it encrypted with the document key.
     */
    private function openEncrypted(string $content, ?string $password): ?EncryptedPdfDocument
    {
        if (preg_match('/\/Encrypt\b/', $content) !== 1) {
            return null;
        }

        return EncryptedPdfDocument::open($content, $password ?? '');
    }
}
