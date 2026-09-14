<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Application\Contract\SignatureProviderFactoryInterface;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Domain\ValueObject\VerifiedCertificate;

final class LocalPrivateKeySignatureProviderFactory implements SignatureProviderFactoryInterface
{
    public function create(VerifiedCertificate $certificate): SignatureProviderInterface
    {
        $cert = (string) ($certificate->bundle['cert'] ?? '');
        $privateKey = (string) ($certificate->bundle['pkey'] ?? '');
        if ($cert === '' || $privateKey === '') {
            throw new SignProcessException('Verified certificate is missing PEM material for local signing.');
        }

        return new LocalPrivateKeySignatureProvider($privateKey);
    }
}
