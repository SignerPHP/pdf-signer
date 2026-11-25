<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureCertificateCollectorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignedData;

/**
 * Lists the X.509 certificates embedded in a CMS signature, read in PHP (no `openssl` binary).
 */
final class OpenSslCmsCertificateCollector implements SignatureCertificateCollectorInterface
{
    /**
     * @param  ProcessRunnerInterface|null  $processRunner  unused since parsing became native; kept for constructor compatibility
     *
     * @psalm-suppress UnusedParam
     */
    public function __construct(?ProcessRunnerInterface $processRunner = null) {}

    public function collectDerCertificates(string $signatureHex): array
    {
        try {
            return CmsSignedData::fromHex(trim($signatureHex))->certificates;
        } catch (\UnexpectedValueException) {
            return [];
        }
    }
}
