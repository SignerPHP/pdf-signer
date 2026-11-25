<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\DTO;

final readonly class SigningOptionsDto
{
    public function __construct(
        public ?SignatureMetadataDto $metadata = null,
        public ?SignatureAppearanceDto $appearance = null,
        public ?TimestampOptionsDto $timestamp = null,
        public bool $useDefaultAppearance = true,
        public SignatureProfile $signatureProfile = SignatureProfile::PdfBasic,
        public ?CertificationLevel $certificationLevel = null,
        public ?SignaturePolicyIdentifierDto $signaturePolicy = null,
        /** Password that opens an encrypted input PDF (user or owner); the empty user password is tried by default. */
        #[\SensitiveParameter]
        public ?string $pdfPassword = null,
    ) {}

    public static function empty(): self
    {
        return new self;
    }
}
