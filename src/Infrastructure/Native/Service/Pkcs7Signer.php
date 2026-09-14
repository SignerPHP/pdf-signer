<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\Pkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\PdfCore\Signature;

final class Pkcs7Signer implements Pkcs7SignerInterface
{
    public function sign(Buffer $signableDocument, SignatureProviderInterface $signatureProvider): string
    {
        $signatureValue = $signatureProvider->sign(new SigningPayload($signableDocument->raw()));

        return str_pad(bin2hex($signatureValue->bytes), Signature::SIGNATURE_MAX_LENGTH, '0');
    }
}
