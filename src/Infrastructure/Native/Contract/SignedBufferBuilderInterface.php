<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Infrastructure\PdfCore\Signature;

interface SignedBufferBuilderInterface
{
    public function build(PdfDocument $pdfDocument, Signature $signatureHandler, SigningContextDto $context): Buffer;
}
