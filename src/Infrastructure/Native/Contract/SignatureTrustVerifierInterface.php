<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfSigner\Application\DTO\SignatureValidationOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\SignatureTrustVerification;

interface SignatureTrustVerifierInterface
{
    public function verify(string $signatureHex, SignatureValidationOptionsDto $options): SignatureTrustVerification;
}
