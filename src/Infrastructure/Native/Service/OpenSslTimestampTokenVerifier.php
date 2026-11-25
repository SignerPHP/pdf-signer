<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureCryptoVerifierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignatureVerifier;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignedData;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\SignatureCryptoVerification;

/**
 * Cryptographic check of a document timestamp (/SubFilter /ETSI.RFC3161, ISO 32000-2 12.8.5):
 *  1. the TimeStampToken's CMS signature over its encapsulated content is valid;
 *  2. the encapsulated content type is id-ct-TSTInfo;
 *  3. the TSTInfo message imprint equals the hash of the ByteRange bytes;
 *  4. the signer certificate carries the timeStamping extended key usage (RFC 3161, 2.3);
 *  5. the TSTInfo carries a well-formed genTime, returned as the signing time so the trust
 *     verifier can check the TSA chain at that instant.
 * Like the CMS verifier, the certificate chain is left to the trust verifier.
 */
final class OpenSslTimestampTokenVerifier implements SignatureCryptoVerifierInterface
{
    private const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';

    /**
     * X509_PURPOSE_TIMESTAMP_SIGN from OpenSSL's x509v3.h. PHP only exposes the constant since 8.4,
     * and this library supports PHP 8.2.
     */
    private const PURPOSE_TIMESTAMP_SIGN = 9;

    private const DIGESTS = [
        '1.3.14.3.2.26' => 'sha1',
        '2.16.840.1.101.3.4.2.4' => 'sha224',
        '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384',
        '2.16.840.1.101.3.4.2.3' => 'sha512',
    ];

    /**
     * @param  ProcessRunnerInterface|null  $processRunner  unused since verification became native; kept for constructor compatibility
     *
     * @psalm-suppress UnusedParam
     */
    public function __construct(
        ?ProcessRunnerInterface $processRunner = null,
        private readonly CmsSignatureVerifier $cmsVerifier = new CmsSignatureVerifier,
    ) {}

    public function verify(string $signedContent, string $signatureHex): SignatureCryptoVerification
    {
        $contents = ($signatureHex !== '' && strlen($signatureHex) % 2 === 0 && ctype_xdigit($signatureHex)) ? hex2bin($signatureHex) : false;
        if ($contents === false || trim($contents, "\0") === '') {
            return new SignatureCryptoVerification(false, 'Empty or invalid timestamp token.');
        }

        try {
            // /Contents is zero-padded; the token ends where its outer length says.
            $signedData = CmsSignedData::fromDer($contents);
        } catch (\UnexpectedValueException) {
            return new SignatureCryptoVerification(false, 'Document timestamp is not a valid CMS SignedData structure.');
        }
        if ($signedData->encapsulatedContentType !== self::OID_TST_INFO) {
            return new SignatureCryptoVerification(false, 'Document timestamp does not encapsulate an RFC 3161 TSTInfo.');
        }

        $signature = $this->cmsVerifier->verify($signedData);
        if (! $signature->valid) {
            return new SignatureCryptoVerification(false, 'Timestamp token signature is invalid: '.$signature->message);
        }

        $tstInfo = (string) $signedData->encapsulatedContent;
        $imprintError = $this->messageImprintError($tstInfo, $signedContent);
        if ($imprintError !== null) {
            return new SignatureCryptoVerification(false, $imprintError);
        }

        $genTime = $this->genTime($tstInfo);
        if ($genTime === null) {
            return new SignatureCryptoVerification(false, 'Timestamp token has a missing or invalid genTime.');
        }

        $signer = @openssl_x509_parse((string) $signature->signerCertificatePem());
        // OpenSSL's timestampsign purpose requires the critical, exclusive timeStamping
        // EKU specified by RFC 3161 and checks the key usage, independently of chain trust.
        if (! is_array($signer) || ($signer['purposes'][self::PURPOSE_TIMESTAMP_SIGN][0] ?? false) !== true) {
            return new SignatureCryptoVerification(false, 'Timestamp signer certificate does not satisfy the RFC 3161 timeStamping purpose.');
        }

        return new SignatureCryptoVerification(true, signingTime: $genTime);
    }

    /**
     * TSTInfo { version, policy, messageImprint { hashAlgorithm, hashedMessage }, ... }
     */
    private function messageImprintError(string $tstInfo, string $signedContent): ?string
    {
        try {
            [, $fields] = Der::readTlvStrict($tstInfo);
            [, , $afterVersion] = Der::readTlvStrict($fields);
            [, , $afterPolicy] = Der::readTlvStrict($fields, $afterVersion);
            [, $messageImprint] = Der::readTlvStrict($fields, $afterPolicy);
            [, $algorithm, $afterAlgorithm] = Der::readTlvStrict($messageImprint);
            [$oidTag, $oid] = Der::readTlvStrict($algorithm);
            [, $hashedMessage] = Der::readTlvStrict($messageImprint, $afterAlgorithm);
        } catch (\Throwable) {
            return 'Timestamp token has a malformed TSTInfo.';
        }

        $hashAlgorithm = null;
        foreach (self::DIGESTS as $dotted => $name) {
            if (Der::objectIdentifier($dotted) === Der::tlv($oidTag, $oid)) {
                $hashAlgorithm = $name;
            }
        }
        if ($hashAlgorithm === null) {
            return 'Timestamp message imprint uses an unsupported hash algorithm.';
        }

        if (! hash_equals($hashedMessage, hash($hashAlgorithm, $signedContent, true))) {
            return 'Timestamp message imprint does not match the signed ByteRange.';
        }

        return null;
    }

    /**
     * TSTInfo { version, policy, messageImprint, serialNumber, genTime GeneralizedTime, ... }.
     * RFC 3161, 2.4.2: YYYYMMDDhhmmss[.s...]Z, always UTC.
     */
    private function genTime(string $tstInfo): ?\DateTimeImmutable
    {
        try {
            [, $fields] = Der::readTlvStrict($tstInfo);
            $offset = 0;
            for ($field = 0; $field < 4; $field++) {
                [, , $offset] = Der::readTlvStrict($fields, $offset);
            }
            [$tag, $value] = Der::readTlvStrict($fields, $offset);
        } catch (\Throwable) {
            return null;
        }

        if ($tag !== 0x18 || preg_match('/\A(\d{14})(?:\.\d*[1-9])?Z\z/', $value, $match) !== 1) {
            return null;
        }

        $time = \DateTimeImmutable::createFromFormat('!YmdHis', $match[1], new \DateTimeZone('UTC'));

        return ($time !== false && $time->format('YmdHis') === $match[1]) ? $time : null;
    }
}
