<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PdfDocumentPreparerInterface;

final class PdfDocumentPreparer implements PdfDocumentPreparerInterface
{
    public function prepare(string $pdfContent): PdfDocument
    {
        return (new \SignerPHP\PdfCore\Service\PdfDocumentPreparer)->prepare($pdfContent);
    }
}
