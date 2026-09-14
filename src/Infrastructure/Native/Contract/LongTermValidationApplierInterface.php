<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

interface LongTermValidationApplierInterface
{
    public function apply(string $signedPdfContent): string;
}
