<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\Contract;

use SignerPHP\PdfSigner\Application\DTO\ProtectPdfRequestDto;

interface PdfProtectionEngineInterface
{
    public function protect(ProtectPdfRequestDto $request): string;
}
