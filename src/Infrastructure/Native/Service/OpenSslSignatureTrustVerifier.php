<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Application\DTO\SignatureValidationOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureCertificateCollectorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimeAwareSignatureTrustVerifierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\X509PathValidator;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\SignatureTrustVerification;

final readonly class OpenSslSignatureTrustVerifier implements TimeAwareSignatureTrustVerifierInterface
{
    public function __construct(
        private SignatureCertificateCollectorInterface $certificateCollector = new OpenSslCmsCertificateCollector,
        private IcpBrasilTrustAnchorBundleProvider $trustAnchorBundleProvider = new IcpBrasilTrustAnchorBundleProvider,
        /**
         * @deprecated Unused since certificate chain validation is native PHP; kept for constructor compatibility.
         */
        private ?ProcessRunnerInterface $processRunner = null,
        private X509PathValidator $pathValidator = new X509PathValidator,
    ) {}

    public function verify(string $signatureHex, SignatureValidationOptionsDto $options): SignatureTrustVerification
    {
        return $this->verifyChain($signatureHex, $options, null);
    }

    /**
     * Validates the chain at $validationTime (e.g. a timestamp's genTime) instead of now.
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
        if ($signerIndex === null) {
            return new SignatureTrustVerification(false, 'Could not identify signer certificate from CMS payload.');
        }

        $trustStoreContents = @file_get_contents($trustStore);
        $trustedDer = is_string($trustStoreContents) ? X509PathValidator::certificatesFromBundle($trustStoreContents) : [];

        $untrustedDer = $certificatesDer;
        unset($untrustedDer[$signerIndex]);

        $error = $this->pathValidator->validate(
            $certificatesDer[$signerIndex],
            $untrustedDer,
            $trustedDer,
            $validationTime ?? new \DateTimeImmutable,
        );

        return new SignatureTrustVerification($error === null, $error);
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
     * first - so position alone does not identify the signer. Reject missing or ambiguous matches.
     *
     * @param  array<int, string>  $certificatesDer
     */
    private function signerCertificateIndex(string $signatureHex, array $certificatesDer): ?int
    {
        try {
            if ($signatureHex === '' || strlen($signatureHex) % 2 !== 0 || ! ctype_xdigit($signatureHex)) {
                return null;
            }
            $cms = (string) hex2bin($signatureHex);
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
            return null;
        }

        $match = null;
        foreach ($certificatesDer as $index => $certificateDer) {
            if (($sidTag === 0x30 && $this->issuerAndSerial($certificateDer) === $sidDer)
                || ($sidTag === 0x80 && $this->subjectKeyIdentifier($certificateDer) === $sid)) {
                if ($match !== null && $certificatesDer[$match] !== $certificateDer) {
                    return null;
                }
                $match = $index;
            }
        }

        return $match;
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
