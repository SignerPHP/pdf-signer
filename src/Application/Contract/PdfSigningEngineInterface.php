<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\Contract;

use SignerPHP\PdfSigner\Application\DTO\LocalSigningContextDto;

interface PdfSigningEngineInterface
{
    public function sign(LocalSigningContextDto $context): string;
}
