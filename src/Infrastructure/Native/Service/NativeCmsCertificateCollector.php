<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureCertificateCollectorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignedData;

/**
 * Lists the X.509 certificates embedded in a CMS signature, read in PHP (no `openssl` binary).
 */
final class NativeCmsCertificateCollector implements SignatureCertificateCollectorInterface
{
    public function collectDerCertificates(string $signatureHex): array
    {
        try {
            return CmsSignedData::fromHex(trim($signatureHex))->certificates;
        } catch (\UnexpectedValueException) {
            return [];
        }
    }
}
