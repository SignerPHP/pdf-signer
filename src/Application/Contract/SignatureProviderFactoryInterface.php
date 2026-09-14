<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\Contract;

use SignerPHP\PdfSigner\Domain\ValueObject\VerifiedCertificate;

interface SignatureProviderFactoryInterface
{
    public function create(VerifiedCertificate $certificate): SignatureProviderInterface;
}
