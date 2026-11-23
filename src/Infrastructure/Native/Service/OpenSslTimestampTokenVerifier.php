<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Domain\Exception\SignatureValidationException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureCryptoVerifierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\SignatureCryptoVerification;

/**
 * Cryptographic check of a document timestamp (/SubFilter /ETSI.RFC3161, ISO 32000-2 12.8.5):
 *  1. the TimeStampToken's CMS signature over its encapsulated content is valid;
 *  2. the encapsulated content type is id-ct-TSTInfo;
 *  3. the TSTInfo message imprint equals the hash of the ByteRange bytes;
 *  4. the signer certificate carries the timeStamping extended key usage (RFC 3161, 2.3).
 * Like the CMS verifier, the certificate chain is left to the trust verifier.
 */
final class OpenSslTimestampTokenVerifier implements SignatureCryptoVerifierInterface
{
    private const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';

    private const DIGESTS = [
        '1.3.14.3.2.26' => 'sha1',
        '2.16.840.1.101.3.4.2.4' => 'sha224',
        '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384',
        '2.16.840.1.101.3.4.2.3' => 'sha512',
    ];

    public function __construct(
        private readonly ProcessRunnerInterface $processRunner = new ShellProcessRunner,
    ) {}

    public function verify(string $signedContent, string $signatureHex): SignatureCryptoVerification
    {
        $contents = ($signatureHex !== '' && strlen($signatureHex) % 2 === 0 && ctype_xdigit($signatureHex)) ? hex2bin($signatureHex) : false;
        if ($contents === false || trim($contents, "\0") === '') {
            return new SignatureCryptoVerification(false, 'Empty or invalid timestamp token.');
        }

        try {
            // /Contents is zero-padded; the token ends where its outer DER length says.
            [, , $end] = $this->readTlv($contents);
            $token = substr($contents, 0, $end);
            if ($this->encapsulatedContentType($token) !== Der::objectIdentifier(self::OID_TST_INFO)) {
                return new SignatureCryptoVerification(false, 'Document timestamp does not encapsulate an RFC 3161 TSTInfo.');
            }
        } catch (\Throwable) {
            return new SignatureCryptoVerification(false, 'Document timestamp is not a valid CMS SignedData structure.');
        }

        $tokenFile = $this->createTempFile('pdf-ts-token');
        $tstInfoFile = $this->createTempFile('pdf-ts-tstinfo');
        $signerFile = $this->createTempFile('pdf-ts-signer');
        file_put_contents($tokenFile, $token);

        try {
            $result = $this->processRunner->run(sprintf(
                'openssl cms -verify -binary -inform DER -in %s -noverify -out %s -signer %s',
                escapeshellarg($tokenFile),
                escapeshellarg($tstInfoFile),
                escapeshellarg($signerFile),
            ));
            if (! $result->succeeded()) {
                return new SignatureCryptoVerification(false, 'Timestamp token signature is invalid: '.$result->outputAsString());
            }

            $imprintError = $this->messageImprintError((string) file_get_contents($tstInfoFile), $signedContent);
            if ($imprintError !== null) {
                return new SignatureCryptoVerification(false, $imprintError);
            }

            $signer = @openssl_x509_parse((string) file_get_contents($signerFile));
            $extendedKeyUsage = is_array($signer) ? (string) ($signer['extensions']['extendedKeyUsage'] ?? '') : '';
            if (! str_contains($extendedKeyUsage, 'Time Stamping')) {
                return new SignatureCryptoVerification(false, 'Timestamp signer certificate lacks the timeStamping extended key usage.');
            }

            return new SignatureCryptoVerification(true);
        } finally {
            @unlink($tokenFile);
            @unlink($tstInfoFile);
            @unlink($signerFile);
        }
    }

    /**
     * ContentInfo { contentType, [0] SignedData { version, digestAlgorithms, encapContentInfo { eContentType, ... } } }
     */
    private function encapsulatedContentType(string $token): string
    {
        [, $contentInfo] = $this->readTlv($token);
        [, , $afterContentType] = $this->readTlv($contentInfo);
        [, $explicit] = $this->readTlv($contentInfo, $afterContentType);
        [, $signedData] = $this->readTlv($explicit);
        [, , $afterVersion] = $this->readTlv($signedData);
        [, , $afterDigestAlgorithms] = $this->readTlv($signedData, $afterVersion);
        [, $encapContentInfo] = $this->readTlv($signedData, $afterDigestAlgorithms);
        [$tag, $oid] = $this->readTlv($encapContentInfo);

        return Der::tlv($tag, $oid);
    }

    /**
     * TSTInfo { version, policy, messageImprint { hashAlgorithm, hashedMessage }, ... }
     */
    private function messageImprintError(string $tstInfo, string $signedContent): ?string
    {
        try {
            [, $fields] = $this->readTlv($tstInfo);
            [, , $afterVersion] = $this->readTlv($fields);
            [, , $afterPolicy] = $this->readTlv($fields, $afterVersion);
            [, $messageImprint] = $this->readTlv($fields, $afterPolicy);
            [, $algorithm, $afterAlgorithm] = $this->readTlv($messageImprint);
            [$oidTag, $oid] = $this->readTlv($algorithm);
            [, $hashedMessage] = $this->readTlv($messageImprint, $afterAlgorithm);
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
     * Der::readTlv() with bounds checks, so truncated input is rejected instead of read past its end.
     *
     * @return array{0:int,1:string,2:int}
     */
    private function readTlv(string $der, int $offset = 0): array
    {
        if ($offset + 2 > strlen($der)) {
            throw new \UnexpectedValueException('Truncated DER.');
        }

        $first = ord($der[$offset + 1]);
        $header = 2 + (($first & 0x80) === 0 ? 0 : ($first & 0x7F));
        if ($offset + $header > strlen($der)) {
            throw new \UnexpectedValueException('Truncated DER length.');
        }

        $tlv = Der::readTlv($der, $offset);
        if ($tlv[2] > strlen($der)) {
            throw new \UnexpectedValueException('DER value exceeds its container.');
        }

        return $tlv;
    }

    private function createTempFile(string $prefix): string
    {
        $path = tempnam(sys_get_temp_dir(), $prefix);
        if ($path === false) {
            throw new SignatureValidationException('Could not create temporary files for timestamp validation.');
        }

        return $path;
    }
}
