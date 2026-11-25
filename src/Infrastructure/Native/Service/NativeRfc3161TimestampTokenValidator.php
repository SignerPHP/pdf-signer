<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimestampTokenValidatorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignatureVerifier;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignedData;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;

/**
 * Validates RFC 3161 token integrity and imprint binding in PHP. Like `openssl cms -noverify`, it deliberately
 * does not establish trust in the TSA's certificate chain; policy validation must do that separately.
 */
final class NativeRfc3161TimestampTokenValidator implements TimestampTokenValidatorInterface
{
    public function __construct(
        private readonly CmsSignatureVerifier $cmsVerifier = new CmsSignatureVerifier,
    ) {}

    public function assertValid(string $tokenDer, string $signatureValue): void
    {
        try {
            $token = CmsSignedData::fromDer($tokenDer);
        } catch (\UnexpectedValueException) {
            throw new SignProcessException('Invalid RFC 3161 signature timestamp token (CMS signature verification failed).');
        }

        if (! $this->cmsVerifier->verify($token)->valid) {
            throw new SignProcessException('Invalid RFC 3161 signature timestamp token (CMS signature verification failed).');
        }

        if ($token->encapsulatedContent === null || ! $this->matchesImprint($token->encapsulatedContent, $signatureValue)) {
            throw new SignProcessException('Invalid RFC 3161 signature timestamp token (message imprint mismatch or invalid TSTInfo).');
        }
    }

    private function matchesImprint(string $tstInfoDer, string $signatureValue): bool
    {
        try {
            [$tag, $tstInfo, $end] = Der::readTlv($tstInfoDer);
            if ($tag !== 0x30 || $end !== strlen($tstInfoDer)) {
                return false;
            }

            [$versionTag, , $offset] = Der::readTlv($tstInfo, 0);
            [$policyTag, , $offset] = Der::readTlv($tstInfo, $offset);
            [$imprintTag, $imprint] = Der::readTlv($tstInfo, $offset);
            if ($versionTag !== 0x02 || $policyTag !== 0x06 || $imprintTag !== 0x30) {
                return false;
            }

            [$algorithmTag, $algorithm, $imprintOffset] = Der::readTlv($imprint);
            [$digestTag, $digest, $digestEnd] = Der::readTlv($imprint, $imprintOffset);
            if ($algorithmTag !== 0x30 || $digestTag !== 0x04 || $digestEnd !== strlen($imprint)) {
                return false;
            }

            [$oidTag, , $oidEnd] = Der::readTlv($algorithm);
            if ($oidTag !== 0x06) {
                return false;
            }
            $oid = substr($algorithm, 0, $oidEnd);
            $hash = match ($oid) {
                Der::objectIdentifier('1.3.14.3.2.26') => 'sha1',
                Der::objectIdentifier('2.16.840.1.101.3.4.2.4') => 'sha224',
                Der::objectIdentifier('2.16.840.1.101.3.4.2.1') => 'sha256',
                Der::objectIdentifier('2.16.840.1.101.3.4.2.2') => 'sha384',
                Der::objectIdentifier('2.16.840.1.101.3.4.2.3') => 'sha512',
                default => null,
            };

            return $hash !== null && hash_equals(hash($hash, $signatureValue, true), $digest);
        } catch (\Throwable) {
            return false;
        }
    }
}
