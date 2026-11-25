<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

/**
 * Native X.509 certification path validation (RFC 5280 subset) for a signer certificate:
 * builds leaf -> trust anchor from the supplied intermediates (any order, irrelevant ones ignored)
 * and checks every signature, validity period, CA basicConstraints/pathLen and keyCertSign usage
 * at the reference time. Any certificate of the trust store can be the anchor. Revocation is not
 * checked here. Error messages follow OpenSSL's wording ("certificate has expired", ...).
 */
final readonly class X509PathValidator
{
    public const MAX_PATH_LENGTH = 10;

    private const NO_ISSUER = 'unable to get local issuer certificate';

    public function __construct(private int $maxPathLength = self::MAX_PATH_LENGTH) {}

    /**
     * @param  array<array-key, string>  $untrustedDer  intermediates offered by the signature
     * @param  array<array-key, string>  $trustedDer  trust anchors
     * @return string|null null when a valid path exists, otherwise the reason it does not
     */
    public function validate(string $leafDer, array $untrustedDer, array $trustedDer, \DateTimeImmutable $validationTime): ?string
    {
        $leaf = X509PathCertificate::fromDer($leafDer);
        if ($leaf === null) {
            return 'Could not decode signer certificate from CMS payload.';
        }

        $trusted = self::decodeAll($trustedDer);
        if ($trusted === []) {
            return 'Trust store does not contain any readable certificate.';
        }
        $untrusted = self::decodeAll($untrustedDer);
        $time = $validationTime->getTimestamp();

        $problem = $this->certificateProblem($leaf, $time);
        if ($problem !== null) {
            return self::describe($problem, 0, $leaf);
        }
        foreach ($trusted as $anchor) {
            if ($anchor->hasSameIdentityAs($leaf)) {
                return null;
            }
        }

        /** @var list<array{0:string,1:int,2:X509PathCertificate}> $errors */
        $errors = [];
        if ($this->extend([$leaf], $trusted, $untrusted, $time, $errors)) {
            return null;
        }

        [$message, $depth, $certificate] = $errors[0] ?? [self::NO_ISSUER, 0, $leaf];

        return self::describe($message, $depth, $certificate);
    }

    /**
     * Certificates of a PEM trust bundle (OpenSSL CAfile format), or of a single DER file, as DER.
     *
     * @return list<string>
     */
    public static function certificatesFromBundle(string $contents): array
    {
        if (preg_match_all('/-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----(.*?)-----END (?:X509 |TRUSTED )?CERTIFICATE-----/s', $contents, $matches) < 1) {
            return str_starts_with($contents, "\x30") ? [$contents] : [];
        }

        $certificates = [];
        foreach ($matches[1] as $body) {
            $der = base64_decode((string) preg_replace('/\s+/', '', $body), true);
            if ($der === false || $der === '') {
                continue;
            }
            try {
                // A TRUSTED CERTIFICATE carries auxiliary trust data after the certificate itself.
                [, , $end] = Der::readTlvStrict($der);
            } catch (\Throwable) {
                continue;
            }
            $certificates[] = substr($der, 0, $end);
        }

        return $certificates;
    }

    /**
     * Depth-first search for an issuer chain from the last certificate of $path to a trust anchor,
     * trying trust-store issuers first. Rejected candidates are recorded in $errors (first one wins).
     *
     * @param  non-empty-list<X509PathCertificate>  $path
     * @param  list<X509PathCertificate>  $trusted
     * @param  list<X509PathCertificate>  $untrusted
     * @param  list<array{0:string,1:int,2:X509PathCertificate}>  $errors
     */
    private function extend(array $path, array $trusted, array $untrusted, int $time, array &$errors): bool
    {
        $depth = count($path) - 1;
        $current = $path[$depth];
        $candidates = $this->issuerCandidates($current, $path, $trusted, $untrusted);
        if ($candidates === []) {
            $message = ! $current->isSelfIssued()
                ? self::NO_ISSUER
                : ($depth === 0 ? 'self-signed certificate' : 'self-signed certificate in certificate chain');
            $errors[] = [$message, $depth, $current];

            return false;
        }

        foreach ($candidates as [$issuer, $isAnchor]) {
            if (openssl_x509_verify($current->pem, $issuer->pem) !== 1) {
                $errors[] = ['certificate signature failure', $depth, $current];

                continue;
            }

            $problem = $this->issuerProblem($issuer, $path) ?? $this->certificateProblem($issuer, $time);
            if ($problem !== null) {
                $errors[] = [$problem, $depth + 1, $issuer];

                continue;
            }

            if ($isAnchor) {
                return true;
            }

            if ($depth + 2 >= $this->maxPathLength) {
                $errors[] = ['certificate chain too long', $depth + 1, $issuer];

                continue;
            }

            if ($this->extend([...$path, $issuer], $trusted, $untrusted, $time, $errors)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Possible issuers of $certificate: subject equals its issuer name and, when both sides carry
     * key identifiers, SKI equals its AKI. Certificates already on the path are skipped (no loops),
     * and an intermediate that is also a trust anchor is taken from the trust store.
     *
     * @param  list<X509PathCertificate>  $path
     * @param  list<X509PathCertificate>  $trusted
     * @param  list<X509PathCertificate>  $untrusted
     * @return list<array{0:X509PathCertificate,1:bool}> candidate, is trust anchor
     */
    private function issuerCandidates(X509PathCertificate $certificate, array $path, array $trusted, array $untrusted): array
    {
        $candidates = [];
        foreach ([[$trusted, true], [$untrusted, false]] as [$pool, $isAnchor]) {
            foreach ($pool as $issuer) {
                if ($issuer->subjectDer !== $certificate->issuerDer
                    || ($certificate->authorityKeyIdentifier !== null && $issuer->subjectKeyIdentifier !== null
                        && $certificate->authorityKeyIdentifier !== $issuer->subjectKeyIdentifier)) {
                    continue;
                }
                foreach ([...$path, ...array_column($candidates, 0)] as $known) {
                    if ($known->hasSameIdentityAs($issuer)) {
                        continue 2;
                    }
                }
                $candidates[] = [$issuer, $isAnchor];
            }
        }

        return $candidates;
    }

    /**
     * CA checks for a certificate used to sign the last certificate of $path.
     *
     * @param  non-empty-list<X509PathCertificate>  $path
     */
    private function issuerProblem(X509PathCertificate $issuer, array $path): ?string
    {
        // As OpenSSL: without basicConstraints, only a v1 self-signed root or a keyCertSign key usage makes a CA.
        $isCa = $issuer->isCa ?? (($issuer->version === 1 && $issuer->isSelfIssued()) || $issuer->keyCertSign === true);
        if (! $isCa) {
            return 'invalid CA certificate';
        }
        if ($issuer->keyCertSign === false) {
            return 'key usage does not include certificate signing';
        }

        if ($issuer->pathLength !== null) {
            $intermediates = 0;
            foreach (array_slice($path, 1) as $certificate) {
                $intermediates += $certificate->isSelfIssued() ? 0 : 1;
            }
            if ($intermediates > $issuer->pathLength) {
                return 'path length constraint exceeded';
            }
        }

        return null;
    }

    private function certificateProblem(X509PathCertificate $certificate, int $time): ?string
    {
        if ($time < $certificate->notBefore) {
            return 'certificate is not yet valid';
        }
        if ($time > $certificate->notAfter) {
            return 'certificate has expired';
        }
        if ($certificate->unrecognizedCriticalExtensions !== []) {
            return 'unhandled critical extension';
        }

        return null;
    }

    /**
     * @param  array<array-key, string>  $certificatesDer
     * @return list<X509PathCertificate>
     */
    private static function decodeAll(array $certificatesDer): array
    {
        $certificates = [];
        foreach ($certificatesDer as $der) {
            $certificate = X509PathCertificate::fromDer($der);
            if ($certificate !== null) {
                $certificates[] = $certificate;
            }
        }

        return $certificates;
    }

    private static function describe(string $message, int $depth, X509PathCertificate $certificate): string
    {
        return sprintf('%s (depth %d: %s)', $message, $depth, $certificate->subjectName());
    }
}
