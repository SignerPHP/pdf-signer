<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\SignaturePolicyIdentifierDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;

/**
 * CMS signer able to declare an explicit signature policy (id-aa-ets-sigPolicyId).
 */
interface PolicyAwarePkcs7SignerInterface extends ProfileAwarePkcs7SignerInterface
{
    public function signWithPolicy(
        Buffer $signableDocument,
        SignatureProviderInterface $signatureProvider,
        string $certificatePem,
        SignatureProfile $profile,
        SignaturePolicyIdentifierDto $signaturePolicy,
    ): string;
}
