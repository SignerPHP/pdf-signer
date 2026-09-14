<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\XrefContentResolverInterface;

final class XrefContentResolver implements XrefContentResolverInterface
{
    public function resolve(PdfDocument $pdfDocument, array $objectOffsets, int $xrefOffset): Buffer
    {
        return (new \SignerPHP\PdfCore\Service\XrefContentResolver)->resolve($pdfDocument, $objectOffsets, $xrefOffset);
    }
}
