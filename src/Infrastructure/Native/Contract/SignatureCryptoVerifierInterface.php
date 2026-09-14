<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\SignatureCryptoVerification;

interface SignatureCryptoVerifierInterface
{
    public function verify(string $signedContent, string $signatureHex): SignatureCryptoVerification;
}
