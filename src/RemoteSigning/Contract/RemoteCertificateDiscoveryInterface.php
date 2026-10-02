<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\RemoteSigning\Contract;

use SignerPHP\PdfSigner\RemoteSigning\DTO\RemoteCertificate;

interface RemoteCertificateDiscoveryInterface
{
    /** @return list<RemoteCertificate> */
    public function certificates(?string $identifier = null): array;
}
