<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfSigner\Infrastructure\PdfCore\Signature;

interface Pkcs7SignerInterface
{
    public function sign(Signature $signatureHandler, Buffer $signableDocument): string;
}
