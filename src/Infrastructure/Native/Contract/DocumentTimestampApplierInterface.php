<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;

interface DocumentTimestampApplierInterface
{
    public function apply(string $signedPdfContent, TimestampOptionsDto $options): string;
}
