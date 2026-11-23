<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;

/**
 * CMS signer able to embed the signer's certificate chain in the SignedData certificates set,
 * so validators can build the path to a trust anchor from the signature alone.
 */
interface ChainAwarePkcs7SignerInterface extends ProfileAwarePkcs7SignerInterface
{
    /**
     * @param  list<string>  $certificateChainPem  intermediate (and optionally root) certificates
     */
    public function signWithChain(
        Buffer $signableDocument,
        SignatureProviderInterface $signatureProvider,
        string $certificatePem,
        SignatureProfile $profile,
        array $certificateChainPem,
    ): string;
}
