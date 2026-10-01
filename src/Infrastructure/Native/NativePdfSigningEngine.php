<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native;

use SignerPHP\PdfSigner\Application\Contract\PdfSigningEngineInterface;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderFactoryInterface;
use SignerPHP\PdfSigner\Application\DTO\LocalSigningContextDto;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PdfDocumentPreparerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureFactoryInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignedBufferBuilderInterface;
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
}
