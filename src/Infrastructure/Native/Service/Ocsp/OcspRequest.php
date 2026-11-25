<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp;

use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;

/**
 * RFC 6960 OCSPRequest for a single certificate, encoded in DER without the OpenSSL CLI.
 *
 * The CertID uses SHA-1 for the issuer name and key hashes (what every responder accepts);
 * responses are matched against the hash algorithm they declare, so SHA-2 CertIDs echoed by
 * a responder are recognised too.
 */
final readonly class OcspRequest
{
    private const NONCE_OID = '1.3.6.1.5.5.7.48.1.2';

    private const CERT_ID_HASHES = [
        '1.3.14.3.2.26' => 'sha1',
        '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384',
        '2.16.840.1.101.3.4.2.3' => 'sha512',
    ];

    /**
     * @param  ?string  $nonce  DER value of the nonce extension (an OCTET STRING), as echoed by responders
     */
    private function __construct(
        public string $der,
        public ?string $nonce,
        private string $issuerNameDer,
        private string $issuerPublicKey,
        private string $serialNumberDer,
    ) {}

    /**
     * @param  ?string  $nonceBytes  random bytes for the nonce extension, or null for a request without nonce
     */
    public static function forCertificate(string $certificateDer, string $issuerDer, ?string $nonceBytes = null): ?self
    {
        try {
            $certificate = self::tbsFields($certificateDer);
            $issuer = self::tbsFields($issuerDer);
        } catch (\UnexpectedValueException) {
            return null;
        }

        $certId = Der::sequence(
            Der::algorithmIdentifier('1.3.14.3.2.26')
            .Der::octetString(sha1($issuer['subject'], true))
            .Der::octetString(sha1($issuer['publicKey'], true))
            .$certificate['serial']
        );

        $nonce = $nonceBytes === null ? null : Der::octetString($nonceBytes);
        $extensions = $nonce === null ? '' : Der::contextSpecific(2, Der::sequence(Der::sequence(
            Der::objectIdentifier(self::NONCE_OID).Der::octetString($nonce)
        )));

        return new self(
            der: Der::sequence(Der::sequence(Der::sequence(Der::sequence($certId)).$extensions)),
            nonce: $nonce,
            issuerNameDer: $issuer['subject'],
            issuerPublicKey: $issuer['publicKey'],
            serialNumberDer: $certificate['serial'],
        );
    }

    /**
     * POSTs the request (RFC 6960 appendix A.1) and returns the raw response body, or null on any transport or HTTP failure.
     */
    public function send(HttpClientInterface $httpClient, string $url, int $timeoutSeconds): ?string
    {
        $response = $httpClient->request(
            'POST',
            $url,
            ['Content-Type: application/ocsp-request', 'Accept: application/ocsp-response'],
            $this->der,
            $timeoutSeconds,
        );

        return $response->transportError === null && $response->isSuccessful() && $response->body !== ''
            ? $response->body
            : null;
    }

    /**
     * The first SingleResponse of the response that answers for this request's certificate.
     */
    public function findStatus(OcspResponse $response): ?OcspSingleResponse
    {
        foreach ($response->responses as $single) {
            $algorithm = self::CERT_ID_HASHES[$single->hashAlgorithmOid] ?? null;
            if ($algorithm !== null
                && hash_equals($this->serialNumberDer, $single->serialNumberDer)
                && hash_equals(hash($algorithm, $this->issuerNameDer, true), $single->issuerNameHash)
                && hash_equals(hash($algorithm, $this->issuerPublicKey, true), $single->issuerKeyHash)) {
                return $single;
            }
        }

        return null;
    }

    /**
     * @return array{serial: string, subject: string, publicKey: string} serial INTEGER and subject Name as DER, subjectPublicKey bits
     */
    private static function tbsFields(string $certificateDer): array
    {
        $certificate = Der::readTlvStrict($certificateDer);
        $tbs = Der::readTlvStrict($certificate[1]);
        if ($certificate[0] !== 0x30 || $tbs[0] !== 0x30) {
            throw new \UnexpectedValueException('Not an X.509 certificate.');
        }

        $fields = [];
        for ($offset = 0; $offset < strlen($tbs[1]);) {
            $start = $offset;
            [$tag, , $offset] = Der::readTlvStrict($tbs[1], $offset);
            if ($tag !== 0xA0) {
                $fields[] = substr($tbs[1], $start, $offset - $start);
            }
        }

        // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
        $spki = count($fields) >= 6 ? Der::readTlvStrict($fields[5]) : [0, ''];
        [$keyTag, $keyBits] = $spki[1] === '' ? [0, ''] : Der::readTlvStrict($spki[1], Der::readTlvStrict($spki[1])[2]);
        if ($keyTag !== 0x03 || $keyBits === '' || ord($fields[0][0]) !== 0x02 || ord($fields[4][0]) !== 0x30) {
            throw new \UnexpectedValueException('Unsupported X.509 certificate.');
        }

        return ['serial' => $fields[0], 'subject' => $fields[4], 'publicKey' => substr($keyBits, 1)];
    }
}
