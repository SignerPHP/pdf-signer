<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\RemoteSigning\Contract;

use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\RemoteSigning\DTO\RemoteCertificate;

interface RemoteSignatureProviderInterface
{
    public function sign(ExternalSigningPayload $payload, RemoteCertificate $certificate): SignatureValue;
}
