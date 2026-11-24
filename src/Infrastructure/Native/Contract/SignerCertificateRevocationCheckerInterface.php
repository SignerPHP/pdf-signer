<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

interface SignerCertificateRevocationCheckerInterface
{
    /**
     * Throws when a revocation source reports the signing certificate as revoked.
     * An unreachable or inconclusive source does not throw.
     *
     * @param  list<string>  $chainPem
     */
    public function assertNotRevoked(string $certificatePem, array $chainPem): void;
}
