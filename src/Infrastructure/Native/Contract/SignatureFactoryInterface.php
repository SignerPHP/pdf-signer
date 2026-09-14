<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\SignatureHandler;

interface SignatureFactoryInterface
{
    public function create(SigningContextDto $context, PdfDocument $pdfDocument): SignatureHandler;
}
