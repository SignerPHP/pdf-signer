<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\DTO;

/**
 * Bytes produced by a signature provider.
 *
 * The local OpenSSL provider currently returns detached CMS/PKCS#7 DER because
 * openssl_pkcs7_sign fuses CMS assembly with the private-key operation.
 */
final readonly class SignatureValue
{
    public function __construct(
        public string $bytes,
    ) {}
}
