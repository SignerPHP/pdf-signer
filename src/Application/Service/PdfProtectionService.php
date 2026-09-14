<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\Service;

use SignerPHP\PdfSigner\Application\Contract\PdfProtectionEngineInterface;
use SignerPHP\PdfSigner\Application\DTO\ProtectPdfRequestDto;

final readonly class PdfProtectionService
{
    public function __construct(private PdfProtectionEngineInterface $protectionEngine) {}

    public function protect(ProtectPdfRequestDto $request): string
    {
        return $this->protectionEngine->protect($request);
    }
}
