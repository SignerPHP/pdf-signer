<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\PdfDocument;

interface XrefContentResolverInterface
{
    /**
     * @param  array<int, int>  $objectOffsets
     */
    public function resolve(PdfDocument $pdfDocument, array $objectOffsets, int $xrefOffset): Buffer;
}
