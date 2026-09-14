<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\Contract;

use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;

interface PdfSigningEngineInterface
{
    public function sign(SigningContextDto $context): string;
}
