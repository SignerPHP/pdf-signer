<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\Csc;

use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureEncoding;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningInputType;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\RemoteSigning\Contract\RemoteSignatureProviderInterface;
use SignerPHP\PdfSigner\RemoteSigning\DTO\RemoteCertificate;

final readonly class CscSignatureProvider implements RemoteSignatureProviderInterface
{
    public function __construct(private CscClient $client) {}

    public function sign(ExternalSigningPayload $payload, RemoteCertificate $certificate): SignatureValue
    {
        if ($payload->inputType !== SigningInputType::Digest
            || $payload->digestAlgorithm !== HashAlgorithm::Sha256
            || $payload->signatureAlgorithm !== SignatureAlgorithm::RsaPkcs1V15
            || $payload->signatureEncoding !== SignatureEncoding::RsaPkcs1) {
            throw new SignerException('CSC v1 signing requires a SHA-256 digest with RSA PKCS#1 v1.5.');
        }
        $digest = $payload->input();
        if (strlen($digest) !== 32 || trim($certificate->identifier) === '') {
            throw new SignerException('CSC signing requires an exact SHA-256 digest and credential ID.');
        }
        $this->client->assertVersion();
        $info = $this->client->post('credentials/info', ['credentialID' => $certificate->identifier, 'certificates' => 'single']);
        $encoded = $info['cert']['certificates'][0] ?? null;
        $actual = is_string($encoded) ? base64_decode($encoded, true) : false;
        $expected = @openssl_x509_read($certificate->certificate->certificatePem);
        $expectedPem = '';
        $expectedDer = $expected !== false && openssl_x509_export($expected, $expectedPem)
            ? base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $expectedPem) ?? '', true)
            : false;
        if (! is_string($actual) || ! is_string($expectedDer) || ! hash_equals($expectedDer, $actual)) {
            throw new SignerException('CSC credential certificate changed after discovery.');
        }
        $algorithms = $info['key']['algo'] ?? null;
        if (($info['key']['status'] ?? null) !== 'enabled' || ! is_array($algorithms)
            || ! array_intersect([CscCertificateDiscovery::RSA_PKCS1_OID, CscCertificateDiscovery::SHA256_RSA_OID], $algorithms)) {
            throw new SignerException('CSC credential does not support the requested algorithm.');
        }
        // SCAL 2 requires hash-bound authorization. Also pin the hash in SCAL 1.
        $authorization = $this->client->post('credentials/authorize', [
            'credentialID' => $certificate->identifier,
            'numSignatures' => 1,
            'hash' => [$payload->inputBase64],
        ]);
        $sad = $authorization['SAD'] ?? null;
        if (! is_string($sad) || $sad === '') {
            throw new SignerException('CSC did not return a usable SAD.');
        }
        $response = $this->client->post('signatures/signHash', [
            'credentialID' => $certificate->identifier,
            'SAD' => $sad,
            'hash' => [$payload->inputBase64],
            'hashAlgo' => '2.16.840.1.101.3.4.2.1',
            'signAlgo' => CscCertificateDiscovery::SHA256_RSA_OID,
        ]);
        $signatures = $response['signatures'] ?? null;
        if (! is_array($signatures) || ! array_is_list($signatures) || count($signatures) !== 1) {
            throw new SignerException('CSC returned an invalid signature list.');
        }
        $signature = is_string($signatures[0]) ? base64_decode($signatures[0], true) : false;
        $publicKey = openssl_pkey_get_public($certificate->certificate->certificatePem);
        $details = $publicKey === false ? false : openssl_pkey_get_details($publicKey);
        $digestInfo = hex2bin('3031300d060960864801650304020105000420').$digest;
        if (! is_string($signature) || ! is_array($details) || $details['type'] !== OPENSSL_KEYTYPE_RSA
            || strlen($signature) !== (int) ceil($details['bits'] / 8)
            || ! @openssl_public_decrypt($signature, $recovered, $publicKey, OPENSSL_PKCS1_PADDING)
            || ! hash_equals($digestInfo, $recovered)) {
            throw new SignerException('CSC returned a signature inconsistent with the selected certificate and digest.');
        }

        return new SignatureValue($signature);
    }
}
