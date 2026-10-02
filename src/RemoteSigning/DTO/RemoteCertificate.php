<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\RemoteSigning\DTO;

use SignerPHP\PdfSigner\Application\DTO\SigningCertificateDto;

final readonly class RemoteCertificate
{
    public function __construct(
        public string $identifier,
        public SigningCertificateDto $certificate,
    ) {}
}
