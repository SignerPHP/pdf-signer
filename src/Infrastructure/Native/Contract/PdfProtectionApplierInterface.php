<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfSigner\Application\DTO\ProtectionOptionsDto;

interface PdfProtectionApplierInterface
{
    public function apply(string $pdfContent, ProtectionOptionsDto $options): string;
}
