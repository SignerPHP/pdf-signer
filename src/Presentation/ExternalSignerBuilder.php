<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Presentation;

use SignerPHP\PdfSigner\Application\DTO\CertificationLevel;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\PreparedExternalSignature;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Application\DTO\SigningCertificateDto;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Application\DTO\SigningOptionsDto;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\ExternalPdfSigningService;

final class ExternalSignerBuilder
{
    private ?PdfContentDto $content = null;

    private ?string $certificatePem = null;

    private ?SignatureMetadataDto $metadata = null;

    private ?SignatureAppearanceDto $appearance = null;

    private bool $useDefaultAppearance = true;

    private SignatureProfile $signatureProfile = SignatureProfile::PdfBasic;

    private ?CertificationLevel $certificationLevel = null;

    private HashAlgorithm $hashAlgorithm = HashAlgorithm::Sha256;

    public function __construct(
        private readonly ExternalPdfSigningService $service = new ExternalPdfSigningService,
    ) {}

    public static function new(?ExternalPdfSigningService $service = null): self
    {
        return new self($service ?? new ExternalPdfSigningService);
    }

    public function withPdfContent(string $content): self
    {
        $this->content = new PdfContentDto($content);

        return $this;
    }

    public function withCertificate(string $certificatePem): self
    {
        if (! $this->isCertificate($certificatePem)) {
            throw new SignerException('A valid PEM signing certificate is required.');
        }

        $this->certificatePem = $certificatePem;

        return $this;
    }

    public function withMetadata(SignatureMetadataDto $metadata): self
    {
        $this->metadata = $metadata;

        return $this;
    }

    public function withAppearance(SignatureAppearanceDto $appearance): self
    {
        $this->appearance = $appearance;

        return $this;
    }

    public function withoutDefaultAppearance(): self
    {
        $this->useDefaultAppearance = false;

        return $this;
    }

    public function withPadesBaselineB(): self
    {
        $this->signatureProfile = SignatureProfile::PadesBaselineB;

        return $this;
    }

    public function withCertificationLevel(CertificationLevel|int $level): self
    {
        $resolved = is_int($level) ? CertificationLevel::fromInt($level) : $level;
        if ($resolved === null) {
            throw new SignerException('Certification level must be one of: 1, 2 or 3.');
        }

        $this->certificationLevel = $resolved;

        return $this;
    }

    public function withHashAlgorithm(HashAlgorithm|string $algorithm): self
    {
        $this->hashAlgorithm = HashAlgorithm::fromString($algorithm);

        return $this;
    }

    public function prepare(): PreparedExternalSignature
    {
        if ($this->content === null) {
            throw new SignerException('PDF content is required. Use withPdfContent().');
        }

        if ($this->certificatePem === null) {
            throw new SignerException('Signing certificate is required. Use withCertificate().');
        }

        $context = new SigningContextDto(
            $this->content,
            new SigningOptionsDto(
                $this->metadata,
                $this->appearance,
                null,
                $this->useDefaultAppearance,
                $this->signatureProfile,
                $this->certificationLevel,
            ),
            new SigningCertificateDto($this->certificatePem),
        );

        return $this->service->prepare($context, $this->hashAlgorithm);
    }

    public function complete(string $state, string $rawSignature): string
    {
        return $this->service->complete($state, $rawSignature);
    }

    public function completeBase64(string $state, string $rawSignatureBase64): string
    {
        $signature = base64_decode($rawSignatureBase64, true);
        if (! is_string($signature) || $signature === '') {
            throw new SignerException('Raw signature must be valid non-empty base64.');
        }

        return $this->complete($state, $signature);
    }

    private function isCertificate(string $certificatePem): bool
    {
        set_error_handler(static fn (): bool => true);

        try {
            return openssl_x509_read($certificatePem) !== false;
        } finally {
            restore_error_handler();
        }
    }
}
