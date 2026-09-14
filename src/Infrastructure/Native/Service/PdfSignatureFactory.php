<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfCore\Metadata;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfCore\SignatureAppearance;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\DefaultSignatureAppearanceProviderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureFactoryInterface;
use SignerPHP\PdfSigner\Infrastructure\PdfCore\Signature;

final class PdfSignatureFactory implements SignatureFactoryInterface
{
    public function __construct(
        private readonly DefaultSignatureAppearanceProviderInterface $defaultAppearanceProvider = new DefaultSignatureAppearanceProvider,
    ) {}

    public function create(SigningContextDto $context, PdfDocument $pdfDocument): Signature
    {
        $signature = Signature::new()
            ->withPdfDocument($pdfDocument)
            ->withCertificate($context->verifiedCertificate->bundle)
            ->withMetadata($this->toMetadata($context))
            ->withSubFilter($this->resolveSubFilter($context))
            ->withCertificationLevel($context->request->options->certificationLevel);

        $appearance = $this->resolveAppearance($context);
        if ($appearance !== null) {
            $signature->withAppearance(
                SignatureAppearance::new()
                    ->withBackgroundImage($appearance->backgroundImagePath)
                    ->withXObject($appearance->xObject)
                    ->withSignatureImage($appearance->signatureImagePath)
                    ->withSignatureImageFrame($appearance->signatureImageFrame)
                    ->withRect($appearance->normalizedRect())
                    ->addSignAppearanceInPage($appearance->page)
            );
        }

        return $signature;
    }

    private function resolveAppearance(SigningContextDto $context): ?SignatureAppearanceDto
    {
        $appearance = $context->request->options->appearance;
        if ($appearance !== null) {
            return $appearance;
        }

        if (! $context->request->options->useDefaultAppearance) {
            return null;
        }

        return $this->defaultAppearanceProvider->makeDefault();
    }

    private function toMetadata(SigningContextDto $context): Metadata
    {
        $metadata = $context->request->options->metadata;

        return Metadata::new()
            ->withName($metadata?->actor?->name)
            ->withReason($metadata?->reason)
            ->withLocation($metadata?->location)
            ->withContactInfo($metadata?->actor?->contactInfo);
    }

    private function resolveSubFilter(SigningContextDto $context): string
    {
        return match ($context->request->options->signatureProfile) {
            SignatureProfile::PadesBaselineB, SignatureProfile::PadesBaselineT, SignatureProfile::PadesBaselineLT, SignatureProfile::PadesBaselineLTA => SignatureObject::SUBFILTER_ETSI_CADES_DETACHED,
            default => SignatureObject::SUBFILTER_PKCS7_DETACHED,
        };
    }
}
