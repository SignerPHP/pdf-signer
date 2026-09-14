<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\Contract;

use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;

interface SignatureProviderInterface
{
    public function sign(SigningPayload $payload): SignatureValue;
}
