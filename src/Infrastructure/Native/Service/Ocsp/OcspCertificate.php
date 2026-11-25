<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp;

/**
 * The X.509 fields OCSP needs: serial number (CertID), subject Name (issuerNameHash,
 * ResponderID byName) and subjectPublicKey bits (issuerKeyHash, ResponderID byKey).
 *
 * @internal
 */
final readonly class OcspCertificate
{
    private function __construct(
        public string $serialNumberDer,
        public string $subjectDer,
        public string $publicKeyBits,
    ) {}

    public static function fromDer(string $certificateDer): ?self
    {
        try {
            [[$tbsTag, , $tbsDer]] = OcspDer::children($certificateDer) + [[0, '', '']];
            $fields = $tbsTag === OcspDer::SEQUENCE ? OcspDer::children($tbsDer) : [];
            if (($fields[0][0] ?? null) === 0xA0) {
                array_shift($fields); // version
            }

            // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
            if (count($fields) < 6 || $fields[4][0] !== OcspDer::SEQUENCE) {
                return null;
            }

            $publicKeyInfo = OcspDer::children($fields[5][2]);
            $bits = count($publicKeyInfo) === 2 ? OcspDer::expect($publicKeyInfo[1][2], 0x03) : '';
            if (strlen($bits) < 2 || $bits[0] !== "\x00") {
                return null;
            }

            return new self(OcspDer::integer($fields[0][2]), $fields[4][2], substr($bits, 1));
        } catch (\UnexpectedValueException) {
            return null;
        }
    }

    public static function fromPem(string $pem): ?self
    {
        $der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pem) ?? '', true);

        return $der === false ? null : self::fromDer($der);
    }
}
