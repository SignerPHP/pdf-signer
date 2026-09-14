<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfCore\PdfDocument;

interface PdfDocumentPreparerInterface
{
    public function prepare(string $pdfContent): PdfDocument;
}
