<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\DTO;

final readonly class SigningCertificateDto
{
    /** @param list<string> $chainPem */
    public function __construct(
        public string $certificatePem,
        public array $chainPem = [],
    ) {}
}
