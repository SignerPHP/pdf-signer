<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

/**
 * Verifies the signature of CMS SignerInfos with PHP's OpenSSL extension, the native
 * counterpart of `openssl cms -verify -noverify`: it proves the signature and content binding,
 * not trust in the signer's certificate, which the trust verifier checks separately.
 */
final class CmsSignatureVerifier
{
    private const DIGESTS = [
        '1.3.14.3.2.26' => 'sha1',
        '2.16.840.1.101.3.4.2.4' => 'sha224',
        '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384',
        '2.16.840.1.101.3.4.2.3' => 'sha512',
    ];

    /** Signature algorithms that carry their own hash. */
    private const SIGNATURE_DIGESTS = [
        '1.2.840.113549.1.1.5' => 'sha1',
        '1.2.840.113549.1.1.14' => 'sha224',
        '1.2.840.113549.1.1.11' => 'sha256',
        '1.2.840.113549.1.1.12' => 'sha384',
        '1.2.840.113549.1.1.13' => 'sha512',
        '1.2.840.10045.4.1' => 'sha1',
        '1.2.840.10045.4.3.1' => 'sha224',
        '1.2.840.10045.4.3.2' => 'sha256',
        '1.2.840.10045.4.3.3' => 'sha384',
        '1.2.840.10045.4.3.4' => 'sha512',
    ];

    /** Key algorithms used as signature algorithm, signing with the SignerInfo digest algorithm. */
    private const BARE_KEY_ALGORITHMS = [
        '1.2.840.113549.1.1.1', // rsaEncryption
        '1.2.840.10045.2.1', // id-ecPublicKey
    ];

    private const OID_RSASSA_PSS = '1.2.840.113549.1.1.10';

    private const OID_MGF1 = '1.2.840.113549.1.1.8';

    /**
     * Verifies every SignerInfo; the result is valid only when there is at least one and all pass.
     * The returned certificate is the first signer's.
     *
     * @param  string|null  $detachedContent  the signed content when the CMS is detached
     */
    public function verify(CmsSignedData $signedData, ?string $detachedContent = null): CmsSignatureVerification
    {
        if ($signedData->signerInfos === []) {
            return new CmsSignatureVerification(false, 'CMS SignedData has no SignerInfo.');
        }

        $content = $detachedContent ?? $signedData->encapsulatedContent;
        if ($content === null) {
            return new CmsSignatureVerification(false, 'CMS signature is detached and no content was supplied.');
        }

        $first = null;
        foreach ($signedData->signerInfos as $signerInfo) {
            $result = $this->verifySignerInfo($signedData, $signerInfo, $content);
            if (! $result->valid) {
                return $result;
            }
            $first ??= $result;
        }

        return $first ?? new CmsSignatureVerification(false, 'CMS SignedData has no SignerInfo.');
    }

    private function verifySignerInfo(CmsSignedData $signedData, CmsSignerInfo $signerInfo, string $content): CmsSignatureVerification
    {
        $certificate = $this->signerCertificate($signedData->certificates, $signerInfo);
        if ($certificate === null) {
            return new CmsSignatureVerification(false, 'Signer certificate not found in the CMS certificates.');
        }

        $digest = self::DIGESTS[$signerInfo->digestAlgorithm] ?? null;
        if ($digest === null) {
            return new CmsSignatureVerification(false, sprintf('Unsupported CMS digest algorithm %s.', $signerInfo->digestAlgorithm));
        }

        try {
            $signedBytes = $this->signedBytes($signedData, $signerInfo, $content, $digest);
        } catch (\UnexpectedValueException $exception) {
            return new CmsSignatureVerification(false, $exception->getMessage());
        }

        $publicKey = @openssl_pkey_get_public(self::pem($certificate));
        if ($publicKey === false) {
            return new CmsSignatureVerification(false, 'Could not read the signer certificate public key.');
        }

        try {
            $verified = $this->verifySignatureValue($signerInfo, $signedBytes, $publicKey, $digest);
        } catch (\UnexpectedValueException $exception) {
            return new CmsSignatureVerification(false, $exception->getMessage());
        }

        return $verified
            ? new CmsSignatureVerification(true, signerCertificateDer: $certificate)
            : new CmsSignatureVerification(false, 'CMS signature value does not verify with the signer certificate.');
    }

    /**
     * With signed attributes the signature covers their DER, which must carry the content type
     * and the digest of the content (RFC 5652, 5.3 and 5.4); without them it covers the content.
     */
    private function signedBytes(CmsSignedData $signedData, CmsSignerInfo $signerInfo, string $content, string $digest): string
    {
        $signedAttributes = $signerInfo->signedAttributesDer();
        if ($signedAttributes === null) {
            return $content;
        }

        $contentType = $signerInfo->signedAttribute(CmsSignerInfo::OID_CONTENT_TYPE);
        if ($contentType === null || $contentType->oid() !== $signedData->encapsulatedContentType) {
            throw new \UnexpectedValueException('CMS content-type attribute is missing or does not match the encapsulated content type.');
        }

        $messageDigest = $signerInfo->signedAttribute(CmsSignerInfo::OID_MESSAGE_DIGEST);
        if ($messageDigest === null || $messageDigest->tag !== Asn1Node::TAG_OCTET_STRING) {
            throw new \UnexpectedValueException('CMS message-digest attribute is missing.');
        }
        if (! hash_equals($messageDigest->octets(), hash($digest, $content, true))) {
            throw new \UnexpectedValueException('CMS message digest does not match the signed content.');
        }

        return $signedAttributes;
    }

    private function verifySignatureValue(CmsSignerInfo $signerInfo, string $signedBytes, \OpenSSLAsymmetricKey $publicKey, string $digest): bool
    {
        $algorithm = $signerInfo->signatureAlgorithm;
        if ($algorithm === self::OID_RSASSA_PSS) {
            return $this->verifyRsaPss($signedBytes, $signerInfo->signature, $publicKey, $signerInfo->signatureAlgorithmParameters);
        }

        $hash = self::SIGNATURE_DIGESTS[$algorithm] ?? (in_array($algorithm, self::BARE_KEY_ALGORITHMS, true) ? $digest : null);
        if ($hash === null) {
            throw new \UnexpectedValueException(sprintf('Unsupported CMS signature algorithm %s.', $algorithm));
        }

        return openssl_verify($signedBytes, $signerInfo->signature, $publicKey, $hash) === 1;
    }

    /**
     * RSASSA-PSS (RFC 8017, 8.1.2 and 9.1.2); PHP's openssl_verify() has no PSS padding.
     */
    private function verifyRsaPss(string $message, string $signature, \OpenSSLAsymmetricKey $publicKey, ?Asn1Node $parameters): bool
    {
        [$hash, $mgfHash, $saltLength] = $this->pssParameters($parameters);

        $details = openssl_pkey_get_details($publicKey);
        if (! is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            return false;
        }

        $modulusBits = (int) $details['bits'];
        $modulusLength = intdiv($modulusBits + 7, 8);
        if (strlen($signature) !== $modulusLength) {
            return false;
        }
        if (! @openssl_public_decrypt($signature, $decrypted, $publicKey, OPENSSL_NO_PADDING)) {
            return false;
        }

        $emBits = $modulusBits - 1;
        $emLength = intdiv($emBits + 7, 8);
        $decrypted = str_pad((string) $decrypted, $modulusLength, "\x00", STR_PAD_LEFT);
        if ($modulusLength > $emLength && $decrypted[0] !== "\x00") {
            return false;
        }
        $encoded = substr($decrypted, $modulusLength - $emLength);

        $hashLength = strlen(hash($hash, '', true));
        if ($emLength < $hashLength + $saltLength + 2 || $encoded[$emLength - 1] !== "\xBC") {
            return false;
        }

        $maskedDb = substr($encoded, 0, $emLength - $hashLength - 1);
        $h = substr($encoded, $emLength - $hashLength - 1, $hashLength);
        $topMask = 0xFF >> (8 * $emLength - $emBits);
        if ((ord($maskedDb[0]) & ~$topMask & 0xFF) !== 0) {
            return false;
        }

        $db = $maskedDb ^ $this->mgf1($h, strlen($maskedDb), $mgfHash);
        $db[0] = chr(ord($db[0]) & $topMask);

        $paddingLength = $emLength - $hashLength - $saltLength - 2;
        if (substr($db, 0, $paddingLength) !== str_repeat("\x00", $paddingLength) || $db[$paddingLength] !== "\x01") {
            return false;
        }

        $salt = substr($db, $paddingLength + 1);

        return hash_equals($h, hash($hash, str_repeat("\x00", 8).hash($hash, $message, true).$salt, true));
    }

    /**
     * RSASSA-PSS-params defaults: SHA-1, MGF1 with SHA-1, 20-byte salt, trailer field 1.
     *
     * @return array{0:string, 1:string, 2:int}
     */
    private function pssParameters(?Asn1Node $parameters): array
    {
        $hash = 'sha1';
        $mgfHash = 'sha1';
        $saltLength = 20;
        if ($parameters === null || $parameters->tag === 0x05) {
            return [$hash, $mgfHash, $saltLength];
        }

        foreach ($parameters->expectTag(Asn1Node::TAG_SEQUENCE)->children() as $field) {
            $value = $field->child(0);
            switch ($field->tag) {
                case 0xA0:
                    $hash = self::DIGESTS[$value->child(0)->oid()] ?? throw new \UnexpectedValueException('Unsupported RSASSA-PSS hash algorithm.');
                    break;
                case 0xA1:
                    if ($value->child(0)->oid() !== self::OID_MGF1) {
                        throw new \UnexpectedValueException('Unsupported RSASSA-PSS mask generation function.');
                    }
                    $mgfHash = self::DIGESTS[$value->child(1)->child(0)->oid()] ?? throw new \UnexpectedValueException('Unsupported RSASSA-PSS MGF1 hash algorithm.');
                    break;
                case 0xA2:
                    $saltLength = $this->smallInteger($value);
                    break;
                case 0xA3:
                    if ($this->smallInteger($value) !== 1) {
                        throw new \UnexpectedValueException('Unsupported RSASSA-PSS trailer field.');
                    }
                    break;
                default:
                    throw new \UnexpectedValueException('Malformed RSASSA-PSS parameters.');
            }
        }

        return [$hash, $mgfHash, $saltLength];
    }

    private function smallInteger(Asn1Node $integer): int
    {
        $bytes = $integer->expectTag(Asn1Node::TAG_INTEGER)->content;
        if ($bytes === '' || strlen($bytes) > 4 || (ord($bytes[0]) & 0x80) !== 0) {
            throw new \UnexpectedValueException('Malformed RSASSA-PSS integer parameter.');
        }

        return (int) hexdec(bin2hex($bytes));
    }

    private function mgf1(string $seed, int $length, string $hash): string
    {
        $mask = '';
        for ($counter = 0; strlen($mask) < $length; $counter++) {
            $mask .= hash($hash, $seed.pack('N', $counter), true);
        }

        return substr($mask, 0, $length);
    }

    /**
     * @param  list<string>  $certificates
     */
    private function signerCertificate(array $certificates, CmsSignerInfo $signerInfo): ?string
    {
        foreach ($certificates as $certificate) {
            if ($signerInfo->issuerAndSerialNumber !== null && self::issuerAndSerialNumber($certificate) === $signerInfo->issuerAndSerialNumber) {
                return $certificate;
            }
            if ($signerInfo->subjectKeyIdentifier !== null && self::subjectKeyIdentifier($certificate) === $signerInfo->subjectKeyIdentifier) {
                return $certificate;
            }
        }

        return null;
    }

    private static function issuerAndSerialNumber(string $certificateDer): ?string
    {
        // TBSCertificate { [0] version?, serialNumber, signature, issuer, ... }
        try {
            $tbs = Asn1Node::readExact($certificateDer)->expectTag(Asn1Node::TAG_SEQUENCE)->child(0, Asn1Node::TAG_SEQUENCE);
            $fields = $tbs->children();
            $offset = ($fields[0] ?? null)?->tag === 0xA0 ? 1 : 0;
            $serial = ($fields[$offset] ?? throw new \UnexpectedValueException('Certificate has no serial number.'))->expectTag(Asn1Node::TAG_INTEGER);
            $issuer = ($fields[$offset + 2] ?? throw new \UnexpectedValueException('Certificate has no issuer.'))->expectTag(Asn1Node::TAG_SEQUENCE);
        } catch (\UnexpectedValueException) {
            return null;
        }

        return Der::sequence($issuer->encoded.$serial->encoded);
    }

    private static function subjectKeyIdentifier(string $certificateDer): ?string
    {
        $parsed = @openssl_x509_parse(self::pem($certificateDer));
        $identifier = is_array($parsed) ? ($parsed['extensions']['subjectKeyIdentifier'] ?? null) : null;

        return is_string($identifier) ? (string) hex2bin(str_replace(':', '', $identifier)) : null;
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END CERTIFICATE-----\n";
    }
}
