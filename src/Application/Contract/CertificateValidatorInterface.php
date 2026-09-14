<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\Contract;

use SignerPHP\PdfSigner\Application\DTO\CertificateCredentialsDto;
use SignerPHP\PdfSigner\Domain\ValueObject\VerifiedCertificate;

interface CertificateValidatorInterface
{
    public function validate(CertificateCredentialsDto $credentials): VerifiedCertificate;
}
