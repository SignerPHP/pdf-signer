<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\Csc;

use SignerPHP\PdfSigner\Application\DTO\SigningCertificateDto;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\RemoteSigning\Contract\RemoteCertificateDiscoveryInterface;
use SignerPHP\PdfSigner\RemoteSigning\DTO\RemoteCertificate;

final readonly class CscCertificateDiscovery implements RemoteCertificateDiscoveryInterface
{
    public const RSA_PKCS1_OID = '1.2.840.113549.1.1.1';

    public const SHA256_RSA_OID = '1.2.840.113549.1.1.11';

    public function __construct(private CscClient $client) {}

    public function certificates(?string $identifier = null): array
    {
        $this->client->assertVersion();
        if ($identifier !== null && trim($identifier) === '') {
            throw new SignerException('CSC credential ID cannot be empty.');
        }
        if ($identifier === null) {
            $list = $this->client->post('credentials/list')['credentialIDs'] ?? null;
            if (! is_array($list) || ! array_is_list($list)) {
                throw new SignerException('CSC returned an invalid credential list.');
            }
            $ids = $list;
        } else {
            $ids = [$identifier];
        }
        $result = [];
        foreach ($ids as $id) {
            if (! is_string($id) || trim($id) === '') {
                throw new SignerException('CSC returned an invalid credential ID.');
            }
            $info = $this->client->post('credentials/info', [
                'credentialID' => $id,
                'certificates' => 'chain',
            ]);
            $key = $info['key'] ?? null;
            $algorithms = is_array($key) ? ($key['algo'] ?? null) : null;
            if (! is_array($key) || ($key['status'] ?? null) !== 'enabled'
                || ! is_array($algorithms) || ! array_is_list($algorithms)
                || ! array_intersect([self::RSA_PKCS1_OID, self::SHA256_RSA_OID], $algorithms)) {
                throw new SignerException('CSC credential cannot sign SHA-256 RSA PKCS#1 v1.5.');
            }
            $chain = $info['cert']['certificates'] ?? null;
            if (! is_array($chain) || ! array_is_list($chain) || $chain === []) {
                throw new SignerException('CSC credential has no certificate.');
            }
            $certificates = array_map(static function (mixed $value): string {
                $der = is_string($value) ? base64_decode($value, true) : false;
                if (! is_string($der) || $der === '') {
                    throw new SignerException('CSC returned malformed certificate data.');
                }
                $pem = "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END CERTIFICATE-----\n";
                set_error_handler(static fn (): bool => true);
                try {
                    $valid = openssl_x509_read($pem) !== false;
                } finally {
                    restore_error_handler();
                }
                if (! $valid) {
                    throw new SignerException('CSC returned an invalid X.509 certificate.');
                }

                return $pem;
            }, $chain);
            $public = openssl_pkey_get_public($certificates[0]);
            $details = $public === false ? false : openssl_pkey_get_details($public);
            if (! is_array($details) || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
                throw new SignerException('CSC certificate must contain an RSA public key.');
            }
            $result[] = new RemoteCertificate($id, new SigningCertificateDto($certificates[0], array_slice($certificates, 1)));
        }

        return $result;
    }
}
