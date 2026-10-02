<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\DTO;

enum SignatureEncoding: string
{
    case RsaPkcs1 = 'rsa-pkcs1';
    case EcdsaDer = 'ecdsa-der';
}
