<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ExtractedPdfSignature;

interface PdfSignatureExtractorInterface
{
    /**
     * @return array<int, ExtractedPdfSignature>
     */
    public function extract(string $pdfContent): array;
}
