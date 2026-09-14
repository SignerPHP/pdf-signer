<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\SignatureHandler;

interface SignedBufferBuilderInterface
{
    public function build(
        PdfDocument $pdfDocument,
        SignatureHandler $signatureHandler,
        SigningContextDto $context,
        SignatureProviderInterface $signatureProvider,
    ): Buffer;
}
