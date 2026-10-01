<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\DTO;

final readonly class SigningContextDto
{
    public function __construct(
        public PdfContentDto $pdf,
        public SigningOptionsDto $options,
        public SigningCertificateDto $certificate,
    ) {}
}
