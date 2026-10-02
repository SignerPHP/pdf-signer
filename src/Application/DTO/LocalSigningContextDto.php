<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\DTO;

use SignerPHP\PdfSigner\Domain\ValueObject\VerifiedCertificate;

final readonly class LocalSigningContextDto
{
    public function __construct(
        public SigningContextDto $signingContext,
        public VerifiedCertificate $verifiedCertificate,
    ) {}
}
