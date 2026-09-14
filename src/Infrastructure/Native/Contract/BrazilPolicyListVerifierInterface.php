<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfSigner\Application\DTO\SignatureValidationOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\SignaturePolicyVerification;

interface BrazilPolicyListVerifierInterface
{
    public function verifyPadesPolicy(SignatureValidationOptionsDto $options): SignaturePolicyVerification;
}
