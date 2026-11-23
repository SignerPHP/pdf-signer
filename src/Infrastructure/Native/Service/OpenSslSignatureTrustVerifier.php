<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Application\DTO\SignatureValidationOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureCertificateCollectorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimeAwareSignatureTrustVerifierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\SignatureTrustVerification;

final readonly class OpenSslSignatureTrustVerifier implements TimeAwareSignatureTrustVerifierInterface
{
    public function __construct(
        private SignatureCertificateCollectorInterface $certificateCollector = new OpenSslCmsCertificateCollector,
        private IcpBrasilTrustAnchorBundleProvider $trustAnchorBundleProvider = new IcpBrasilTrustAnchorBundleProvider,
        private ProcessRunnerInterface $processRunner = new ShellProcessRunner,
    ) {}

    public function verify(string $signatureHex, SignatureValidationOptionsDto $options): SignatureTrustVerification
    {
        return $this->verifyChain($signatureHex, $options, null);
    }

    /**
     * Validates the chain at $validationTime (openssl verify -attime) instead of now.
     */
    public function verifyAt(string $signatureHex, SignatureValidationOptionsDto $options, \DateTimeImmutable $validationTime): SignatureTrustVerification
    {
        return $this->verifyChain($signatureHex, $options, $validationTime);
    }

    private function verifyChain(string $signatureHex, SignatureValidationOptionsDto $options, ?\DateTimeImmutable $validationTime): SignatureTrustVerification
    {
        if (! $options->checkTrustChain) {
            return new SignatureTrustVerification(true);
        }

        $trustStore = $this->resolveTrustStore($options);
        if ($trustStore === null) {
            return new SignatureTrustVerification(false, 'No trust store found for certificate chain validation.');
        }

        $certificatesDer = $this->certificateCollector->collectDerCertificates($signatureHex);
        if ($certificatesDer === []) {
            return new SignatureTrustVerification(false, 'Could not extract certificates from signature CMS payload.');
        }

        $signerIndex = $this->signerCertificateIndex($signatureHex, $certificatesDer);
        $leafPem = $this->derToPem($certificatesDer[$signerIndex]);
        if ($leafPem === null) {
            return new SignatureTrustVerification(false, 'Could not decode signer certificate from CMS payload.');
        }

        $chainPem = '';
        $others = $certificatesDer;
        unset($others[$signerIndex]);
        foreach ($others as $certDer) {
            $pem = $this->derToPem($certDer);
            if ($pem !== null) {
                $chainPem .= $pem;
            }
        }

        $tmpDir = sys_get_temp_dir();
        $leafFile = tempnam($tmpDir, 'pdf-sig-leaf');
        if ($leafFile === false) {
            return new SignatureTrustVerification(false, 'Could not create temporary file for signer certificate.');
        }

        file_put_contents($leafFile, $leafPem);

        $chainFile = null;
        if ($chainPem !== '') {
            $chainFile = tempnam($tmpDir, 'pdf-sig-chain');
            if ($chainFile !== false) {
                file_put_contents($chainFile, $chainPem);
            }
        }

        try {
            $command = sprintf(
                'openssl verify -CAfile %s%s%s %s',
                escapeshellarg($trustStore),
                $chainFile !== null ? ' -untrusted '.escapeshellarg($chainFile) : '',
                $validationTime !== null ? ' -attime '.$validationTime->getTimestamp() : '',
                escapeshellarg($leafFile),
            );

            $result = $this->processRunner->run($command);
            if (! $result->succeeded()) {
                $message = trim($result->outputAsString());
                if ($message === '') {
                    $message = 'OpenSSL verify failed for signer certificate chain.';
                }

                return new SignatureTrustVerification(false, $message);
            }

            return new SignatureTrustVerification(true);
        } finally {
            @unlink($leafFile);
            if ($chainFile !== null) {
                @unlink($chainFile);
            }
        }
    }

    private function resolveTrustStore(SignatureValidationOptionsDto $options): ?string
    {
        $explicitPath = $options->trustStorePath;
        if ($explicitPath !== null) {
            return is_file($explicitPath) ? $explicitPath : null;
        }

        if ($options->policy === 'br-iti') {
            $directory = $options->trustAnchorsDirectory ?? rtrim(sys_get_temp_dir(), '/').'/signer-php/trust-anchors';
            $urls = $options->trustAnchorsUrls ?? [];
            if ($urls !== []) {
                $bundle = $this->trustAnchorBundleProvider->resolveBundle($directory, $urls);
                if ($bundle !== null && is_file($bundle)) {
                    return $bundle;
                }
            }
        }

        $candidates = [
            '/etc/ssl/certs/ca-certificates.crt',
            '/etc/pki/tls/certs/ca-bundle.crt',
            '/etc/ssl/ca-bundle.pem',
        ];

        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * Index of the certificate that matches the first SignerInfo's sid (issuerAndSerialNumber or
     * subjectKeyIdentifier). The certificates SET is unordered - a TSA token commonly lists its CA
     * first - so position alone does not identify the signer. Falls back to the first certificate.
     *
     * @param  array<int, string>  $certificatesDer
     */
    private function signerCertificateIndex(string $signatureHex, array $certificatesDer): int
    {
        try {
            $cms = (string) hex2bin(strlen($signatureHex) % 2 === 0 ? $signatureHex : $signatureHex.'0');
            [, $contentInfo] = Der::readTlvStrict($cms);
            [, , $offset] = Der::readTlvStrict($contentInfo);
            [, $explicit] = Der::readTlvStrict($contentInfo, $offset);
            [, $signedData] = Der::readTlvStrict($explicit);

            // version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
            $offset = 0;
            for ($field = 0; $field < 3; $field++) {
                [, , $offset] = Der::readTlvStrict($signedData, $offset);
            }
            do {
                [$tag, $value, $next] = Der::readTlvStrict($signedData, $offset);
                $offset = $next;
            } while ($tag === 0xA0 || $tag === 0xA1);

            [, $signerInfo] = Der::readTlvStrict($value);
            [, , $offset] = Der::readTlvStrict($signerInfo);
            [$sidTag, $sid, $sidEnd] = Der::readTlvStrict($signerInfo, $offset);
            $sidDer = substr($signerInfo, $offset, $sidEnd - $offset);
        } catch (\Throwable) {
            return 0;
        }

        foreach (array_values($certificatesDer) as $index => $certificateDer) {
            if ($sidTag === 0x30 && $this->issuerAndSerial($certificateDer) === $sidDer) {
                return array_keys($certificatesDer)[$index];
            }
            if ($sidTag === 0x80 && $this->subjectKeyIdentifier($certificateDer) === $sid) {
                return array_keys($certificatesDer)[$index];
            }
        }

        return array_key_first($certificatesDer) ?? 0;
    }

    /**
     * DER of IssuerAndSerialNumber { issuer Name, serialNumber } built from the certificate's TBS.
     */
    private function issuerAndSerial(string $certificateDer): ?string
    {
        try {
            [, $certificate] = Der::readTlvStrict($certificateDer);
            [, $tbs] = Der::readTlvStrict($certificate);
            [$tag, , $offset] = Der::readTlvStrict($tbs);
            $serialStart = $tag === 0xA0 ? $offset : 0;
            [, , $serialEnd] = Der::readTlvStrict($tbs, $serialStart);
            [, , $algorithmEnd] = Der::readTlvStrict($tbs, $serialEnd);
            [, , $issuerEnd] = Der::readTlvStrict($tbs, $algorithmEnd);
        } catch (\Throwable) {
            return null;
        }

        return Der::sequence(substr($tbs, $algorithmEnd, $issuerEnd - $algorithmEnd).substr($tbs, $serialStart, $serialEnd - $serialStart));
    }

    private function subjectKeyIdentifier(string $certificateDer): ?string
    {
        $parsed = @openssl_x509_parse((string) $this->derToPem($certificateDer));
        $ski = is_array($parsed) ? ($parsed['extensions']['subjectKeyIdentifier'] ?? null) : null;

        return is_string($ski) ? (string) hex2bin(str_replace(':', '', $ski)) : null;
    }

    private function derToPem(string $der): ?string
    {
        if ($der === '') {
            return null;
        }

        return "-----BEGIN CERTIFICATE-----\n".
            chunk_split(base64_encode($der), 64, "\n").
            "-----END CERTIFICATE-----\n";
    }
}
