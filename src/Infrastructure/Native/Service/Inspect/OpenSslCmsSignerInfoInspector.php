<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Inspect;

use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Asn1Node;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignedData;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignerInfo;

/**
 * Extracts CMS SignerInfo metadata (digest algorithm, signature algorithm,
 * and authenticated-attribute signing time) from a PKCS#7/CMS DER blob.
 * Names and the time format follow what `openssl cms -print` showed before parsing became native.
 */
final class OpenSslCmsSignerInfoInspector
{
    private const ALGORITHM_NAMES = [
        '1.3.14.3.2.26' => 'sha1',
        '2.16.840.1.101.3.4.2.4' => 'sha224',
        '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384',
        '2.16.840.1.101.3.4.2.3' => 'sha512',
        '1.2.840.113549.1.1.1' => 'rsaEncryption',
        '1.2.840.113549.1.1.5' => 'sha1WithRSAEncryption',
        '1.2.840.113549.1.1.14' => 'sha224WithRSAEncryption',
        '1.2.840.113549.1.1.11' => 'sha256WithRSAEncryption',
        '1.2.840.113549.1.1.12' => 'sha384WithRSAEncryption',
        '1.2.840.113549.1.1.13' => 'sha512WithRSAEncryption',
        '1.2.840.113549.1.1.10' => 'rsassaPss',
        '1.2.840.10045.2.1' => 'id-ecPublicKey',
        '1.2.840.10045.4.1' => 'ecdsa-with-SHA1',
        '1.2.840.10045.4.3.1' => 'ecdsa-with-SHA224',
        '1.2.840.10045.4.3.2' => 'ecdsa-with-SHA256',
        '1.2.840.10045.4.3.3' => 'ecdsa-with-SHA384',
        '1.2.840.10045.4.3.4' => 'ecdsa-with-SHA512',
    ];

    /**
     * @param  ProcessRunnerInterface|null  $processRunner  unused since parsing became native; kept for constructor compatibility
     *
     * @psalm-suppress UnusedParam
     */
    public function __construct(?ProcessRunnerInterface $processRunner = null) {}

    /**
     * @return array{digest_algorithm:string|null,signature_algorithm:string|null,cms_signing_time:string|null}
     */
    public function inspect(string $signatureHex): array
    {
        $empty = ['digest_algorithm' => null, 'signature_algorithm' => null, 'cms_signing_time' => null];

        try {
            $signerInfo = CmsSignedData::fromHex($signatureHex)->signerInfos[0] ?? null;
            if ($signerInfo === null) {
                return $empty;
            }

            return [
                'digest_algorithm' => self::ALGORITHM_NAMES[$signerInfo->digestAlgorithm] ?? $signerInfo->digestAlgorithm,
                'signature_algorithm' => self::ALGORITHM_NAMES[$signerInfo->signatureAlgorithm] ?? $signerInfo->signatureAlgorithm,
                'cms_signing_time' => $this->signingTime($signerInfo->signedAttribute(CmsSignerInfo::OID_SIGNING_TIME)),
            ];
        } catch (\UnexpectedValueException) {
            return $empty;
        }
    }

    /**
     * UTCTime (YYMMDDhhmmssZ) or GeneralizedTime (YYYYMMDDhhmmss[.f]Z) as "May  6 18:56:01 2026 GMT".
     */
    private function signingTime(?Asn1Node $time): ?string
    {
        if ($time === null) {
            return null;
        }

        $pattern = match ($time->tag) {
            0x17 => '/\A(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})()Z\z/',
            0x18 => '/\A(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z\z/',
            default => null,
        };
        if ($pattern === null || preg_match($pattern, $time->content, $m) !== 1) {
            return null;
        }

        $year = (int) $m[1];
        if ($time->tag === 0x17) {
            $year += $year < 50 ? 2000 : 1900;
        }
        $month = (int) $m[2];
        if ($month < 1 || $month > 12) {
            return null;
        }

        $months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

        return sprintf('%s %2d %s:%s:%s%s %d GMT', $months[$month - 1], (int) $m[3], $m[4], $m[5], $m[6], $m[7] ?? '', $year);
    }
}
