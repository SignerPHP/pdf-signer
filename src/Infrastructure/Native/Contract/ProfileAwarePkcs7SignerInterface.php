<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;

interface ProfileAwarePkcs7SignerInterface extends Pkcs7SignerInterface
{
    public function signWithProfile(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem, SignatureProfile $profile): string;
}
