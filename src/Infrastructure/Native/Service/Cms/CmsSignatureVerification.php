<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

final readonly class CmsSignatureVerification
{
    public function __construct(
        public bool $valid,
        public ?string $message = null,
        public ?string $signerCertificateDer = null,
    ) {}

    public function signerCertificatePem(): ?string
    {
        if ($this->signerCertificateDer === null) {
            return null;
        }

        return "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($this->signerCertificateDer), 64, "\n")."-----END CERTIFICATE-----\n";
    }
}
