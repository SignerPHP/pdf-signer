<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\SignatureValidationOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureCertificateCollectorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\DetachedCmsAssembler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\X509Certificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\X509PathValidator;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\IcpBrasilTrustAnchorBundleProvider;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProvider;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeFunctionOverrideState;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslSignatureTrustVerifier;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\HttpResponse;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ProcessResult;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

final class OpenSslSignatureTrustVerifierTest extends TestCase
{
    protected function tearDown(): void
    {
        NativeFunctionOverrideState::$forceIsFileFalse = false;
    }

    /** @return array{string, string} */
    private function signingFixture(): array
    {
        $bundle = Pkcs12Fixture::load();
        $cms = (new DetachedCmsAssembler)->assemble('data', $bundle['cert'], new LocalPrivateKeySignatureProvider($bundle['pkey']));

        return [bin2hex($cms), X509Certificate::fromPem($bundle['cert'])->der];
    }

    public function test_verify_returns_valid_when_trust_validation_is_disabled(): void
    {
        $collector = new class implements SignatureCertificateCollectorInterface
        {
            public function collectDerCertificates(string $signatureHex): array
            {
                return [];
            }
        };

        $verifier = new OpenSslSignatureTrustVerifier($collector);
        $result = $verifier->verify('ABCD', new SignatureValidationOptionsDto(checkTrustChain: false));

        self::assertTrue($result->valid);
    }

    public function test_verify_returns_invalid_when_explicit_trust_store_does_not_exist(): void
    {
        $collector = new class implements SignatureCertificateCollectorInterface
        {
            public function collectDerCertificates(string $signatureHex): array
            {
                return [];
            }
        };

        $verifier = new OpenSslSignatureTrustVerifier($collector);
        $result = $verifier->verify('ABCD', new SignatureValidationOptionsDto(
            checkTrustChain: true,
            trustStorePath: '/path/that/does/not/exist.pem',
        ));

        self::assertFalse($result->valid);
        self::assertStringContainsString('No trust store found', (string) $result->message);
    }

    public function test_verify_returns_invalid_when_no_certificates_are_extracted(): void
    {
        $collector = new class implements SignatureCertificateCollectorInterface
        {
            public function collectDerCertificates(string $signatureHex): array
            {
                return [];
            }
        };

        $trustStore = tempnam(sys_get_temp_dir(), 'trust-store');
        self::assertNotFalse($trustStore);
        file_put_contents($trustStore, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n");

        try {
            $verifier = new OpenSslSignatureTrustVerifier($collector);
            $result = $verifier->verify('ABCD', new SignatureValidationOptionsDto(
                checkTrustChain: true,
                trustStorePath: $trustStore,
            ));

            self::assertFalse($result->valid);
            self::assertStringContainsString('Could not extract certificates', (string) $result->message);
        } finally {
            @unlink($trustStore);
        }
    }

    #[DataProvider('invalidCmsPayloads')]
    public function test_verify_returns_invalid_when_signer_certificate_cannot_be_identified(string $signatureHex): void
    {
        [, $signerDer] = $this->signingFixture();
        $collector = new class($signerDer) implements SignatureCertificateCollectorInterface
        {
            public function __construct(private readonly string $signerDer) {}

            public function collectDerCertificates(string $signatureHex): array
            {
                return [$this->signerDer];
            }
        };

        $trustStore = tempnam(sys_get_temp_dir(), 'trust-store');
        self::assertNotFalse($trustStore);
        file_put_contents($trustStore, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n");

        try {
            $verifier = new OpenSslSignatureTrustVerifier($collector);
            $result = $verifier->verify($signatureHex, new SignatureValidationOptionsDto(
                checkTrustChain: true,
                trustStorePath: $trustStore,
            ));

            self::assertFalse($result->valid);
            self::assertStringContainsString('Could not identify signer certificate', (string) $result->message);
        } finally {
            @unlink($trustStore);
        }
    }

    public static function invalidCmsPayloads(): array
    {
        return [
            'empty' => [''],
            'odd length' => ['ABC'],
            'not hexadecimal' => ['NOPE'],
            'malformed DER' => ['ABCD'],
        ];
    }

    public function test_verify_validates_a_real_chain_natively_without_running_processes(): void
    {
        $pki = $this->chainFixture();

        try {
            $verifier = new OpenSslSignatureTrustVerifier($pki['collector'], processRunner: new class implements ProcessRunnerInterface
            {
                public function run(string $command): ProcessResult
                {
                    throw new \LogicException('Chain validation must not run external processes: '.$command);
                }
            });
            $options = new SignatureValidationOptionsDto(checkTrustChain: true, trustStorePath: $pki['dir'].'/root.crt');

            $result = $verifier->verify($pki['signatureHex'], $options);
            self::assertTrue($result->valid, (string) $result->message);
            self::assertNull($result->message);
        } finally {
            exec('rm -rf '.escapeshellarg($pki['dir']));
        }
    }

    public function test_verify_at_validates_the_chain_at_the_given_time(): void
    {
        $pki = $this->chainFixture('20200101000000Z', '20210101000000Z');

        try {
            $verifier = new OpenSslSignatureTrustVerifier($pki['collector']);
            $options = new SignatureValidationOptionsDto(checkTrustChain: true, trustStorePath: $pki['dir'].'/root.crt');

            $atGenTime = $verifier->verifyAt($pki['signatureHex'], $options, new \DateTimeImmutable('2020-06-15T12:00:00Z'));
            $today = $verifier->verify($pki['signatureHex'], $options);

            self::assertTrue($atGenTime->valid, (string) $atGenTime->message);
            self::assertFalse($today->valid, 'regular signatures keep the current time');
            self::assertSame('certificate has expired (depth 0: /CN=Verifier Leaf)', $today->message);
        } finally {
            exec('rm -rf '.escapeshellarg($pki['dir']));
        }
    }

    public function test_verify_reports_a_missing_intermediate(): void
    {
        $pki = $this->chainFixture(withIntermediate: false);

        try {
            $result = (new OpenSslSignatureTrustVerifier($pki['collector']))->verify(
                $pki['signatureHex'],
                new SignatureValidationOptionsDto(checkTrustChain: true, trustStorePath: $pki['dir'].'/root.crt'),
            );

            self::assertFalse($result->valid);
            self::assertSame('unable to get local issuer certificate (depth 0: /CN=Verifier Leaf)', $result->message);
        } finally {
            exec('rm -rf '.escapeshellarg($pki['dir']));
        }
    }

    public function test_verify_reports_an_unreadable_trust_store(): void
    {
        [$signatureHex, $signerDer] = $this->signingFixture();
        $collector = new class($signerDer) implements SignatureCertificateCollectorInterface
        {
            public function __construct(private readonly string $signerDer) {}

            public function collectDerCertificates(string $signatureHex): array
            {
                return [$this->signerDer];
            }
        };

        $trustStore = (string) tempnam(sys_get_temp_dir(), 'trust-store');
        file_put_contents($trustStore, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n");

        try {
            $result = (new OpenSslSignatureTrustVerifier($collector))->verify(
                $signatureHex,
                new SignatureValidationOptionsDto(checkTrustChain: true, trustStorePath: $trustStore),
            );

            self::assertFalse($result->valid);
            self::assertSame('Trust store does not contain any readable certificate.', $result->message);
        } finally {
            @unlink($trustStore);
        }
    }

    /**
     * Root -> Intermediate -> "Verifier Leaf" issued with `openssl ca`, and a CMS signed by the leaf
     * whose certificates SET lists the intermediate (when requested) before the leaf.
     *
     * @return array{dir: string, signatureHex: string, collector: SignatureCertificateCollectorInterface}
     */
    private function chainFixture(string $leafNotBefore = '20150101000000Z', string $leafNotAfter = '20450101000000Z', bool $withIntermediate = true): array
    {
        $dir = sys_get_temp_dir().'/trust-chain-'.bin2hex(random_bytes(4));
        mkdir($dir.'/newcerts', 0777, true);
        touch($dir.'/index.txt');
        file_put_contents($dir.'/serial', "1000\n");
        file_put_contents($dir.'/ca.cnf', implode("\n", [
            '[req]', 'distinguished_name = dn', '[dn]',
            '[ca]', 'default_ca = test_ca',
            '[test_ca]', 'dir = '.$dir, 'database = $dir/index.txt', 'new_certs_dir = $dir/newcerts',
            'serial = $dir/serial', 'default_md = sha256', 'policy = any', 'unique_subject = no',
            '[any]', 'commonName = supplied',
            '[v3_ca]', 'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign, cRLSign',
            '[v3_leaf]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature', '',
        ]));
        $newKey = '-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes';
        $certfile = $withIntermediate ? '-certfile int.crt' : '';
        exec('(set -e; cd '.escapeshellarg($dir).<<<SH
            ;
            openssl req -new $newKey -keyout root.key -out root.csr -subj /CN=Verifier-Root -config ca.cnf
            openssl ca -batch -selfsign -config ca.cnf -keyfile root.key -in root.csr -out root.crt -extensions v3_ca -startdate 20150101000000Z -enddate 20450101000000Z -notext
            openssl req -new $newKey -keyout int.key -out int.csr -subj /CN=Verifier-Intermediate -config ca.cnf
            openssl ca -batch -config ca.cnf -cert root.crt -keyfile root.key -in int.csr -out int.crt -extensions v3_ca -startdate 20150101000000Z -enddate 20450101000000Z -notext
            openssl req -new $newKey -keyout leaf.key -out leaf.csr -subj "/CN=Verifier Leaf" -config ca.cnf
            openssl ca -batch -config ca.cnf -cert int.crt -keyfile int.key -in leaf.csr -out leaf.crt -extensions v3_leaf -startdate $leafNotBefore -enddate $leafNotAfter -notext
            printf data > d
            openssl cms -sign -binary -nodetach -outform DER -signer leaf.crt -inkey leaf.key $certfile -in d -out t.der
            SH.') 2>&1', $output, $exitCode);
        self::assertSame(0, $exitCode, implode("\n", $output));

        $certificatesDer = [];
        foreach ($withIntermediate ? ['int', 'leaf'] : ['leaf'] as $name) {
            $certificatesDer[] = X509PathValidator::certificatesFromBundle((string) file_get_contents("$dir/$name.crt"))[0];
        }

        return [
            'dir' => $dir,
            'signatureHex' => bin2hex((string) file_get_contents("$dir/t.der")),
            'collector' => new class($certificatesDer) implements SignatureCertificateCollectorInterface
            {
                /** @param list<string> $certificatesDer */
                public function __construct(private readonly array $certificatesDer) {}

                public function collectDerCertificates(string $signatureHex): array
                {
                    return $this->certificatesDer;
                }
            },
        ];
    }

    public function test_verify_uses_the_signer_certificate_even_when_the_ca_is_listed_first(): void
    {
        self::assertSame('Order-Signer', $this->trustedSignerSubject('', ['ca', 's']));
    }

    public function test_verify_matches_a_signer_identified_by_subject_key_identifier(): void
    {
        self::assertSame('Order-Signer', $this->trustedSignerSubject('-keyid', ['ca', 's']));
    }

    public function test_verify_rejects_when_no_certificate_matches_the_signer(): void
    {
        self::assertSame('', $this->trustedSignerSubject('', ['ca'], expectValid: false));
    }

    public function test_verify_rejects_ambiguous_subject_key_identifiers(): void
    {
        self::assertSame('', $this->trustedSignerSubject('-keyid', ['ca', 's', 'same-ski'], expectValid: false));
    }

    public function test_verify_skips_undecodable_certificates_while_matching_the_signer(): void
    {
        self::assertSame('Order-Signer', $this->trustedSignerSubject('', ['garbage', 'ca', 's']));
    }

    /**
     * Signs with a self-signed leaf, offers the verifier the listed certificates in that order
     * ('ca', 's' for the signer, 'garbage' for undecodable DER) and trusts only the signer's own
     * certificate, so the chain validates only when the verifier picked the signer as the leaf.
     * Returns the CN of the trusted signer on success, '' otherwise.
     *
     * @param  list<string>  $certificates
     */
    private function trustedSignerSubject(string $signFlags, array $certificates, bool $expectValid = true): string
    {
        $dir = sys_get_temp_dir().'/trust-order-'.bin2hex(random_bytes(4));
        mkdir($dir);
        $d = escapeshellarg($dir);
        // Explicit SKI: LibreSSL does not add one to self-signed certificates, and -keyid needs it.
        file_put_contents("$dir/x509.cnf", "[req]\ndistinguished_name = dn\n[dn]\n[v3]\nsubjectKeyIdentifier = hash\n");
        exec("cd $d && openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -subj /CN=Order-CA -days 1 -config x509.cnf -extensions v3 2>&1"
            .' && openssl req -x509 -newkey rsa:2048 -nodes -keyout s.key -out s.crt -subj /CN=Order-Signer -days 1 -config x509.cnf -extensions v3 2>&1'
            .' && openssl req -x509 -key s.key -out same-ski.crt -subj /CN=Order-Other -days 1 -config x509.cnf -extensions v3 2>&1'
            ." && printf data > d && openssl cms -sign -binary -nodetach -outform DER $signFlags -signer s.crt -inkey s.key -certfile ca.crt -in d -out t.der 2>&1", $output, $exitCode);
        self::assertSame(0, $exitCode, implode("\n", $output));

        $certificatesDer = [];
        foreach ($certificates as $name) {
            $certificatesDer[] = $name === 'garbage'
                ? "\x30\x03\x02\x01\x00"
                : (string) base64_decode((string) preg_replace('/-----[A-Z ]+-----|\s/', '', (string) file_get_contents("$dir/$name.crt")));
        }
        $collector = new class($certificatesDer) implements SignatureCertificateCollectorInterface
        {
            /** @param list<string> $certificatesDer */
            public function __construct(private readonly array $certificatesDer) {}

            public function collectDerCertificates(string $signatureHex): array
            {
                return $this->certificatesDer;
            }
        };

        try {
            $result = (new OpenSslSignatureTrustVerifier($collector))->verify(
                bin2hex((string) file_get_contents("$dir/t.der")),
                new SignatureValidationOptionsDto(checkTrustChain: true, trustStorePath: "$dir/s.crt"),
            );

            self::assertSame($expectValid, $result->valid, (string) $result->message);
            if (! $result->valid) {
                self::assertSame('Could not identify signer certificate from CMS payload.', $result->message);

                return '';
            }

            $parsed = openssl_x509_parse((string) file_get_contents("$dir/s.crt"));

            return is_array($parsed) ? (string) ($parsed['subject']['CN'] ?? '') : '';
        } finally {
            exec('rm -rf '.$d);
        }
    }

    public function test_verify_uses_system_trust_store_candidates_when_no_explicit_store_is_given(): void
    {
        $collector = new class implements SignatureCertificateCollectorInterface
        {
            public function collectDerCertificates(string $signatureHex): array
            {
                return [];
            }
        };

        $verifier = new OpenSslSignatureTrustVerifier($collector);
        $result = $verifier->verify('ABCD', new SignatureValidationOptionsDto(
            checkTrustChain: true,
        ));

        self::assertFalse($result->valid);
        self::assertStringContainsString('Could not extract certificates', (string) $result->message);
    }

    public function test_verify_returns_no_trust_store_when_all_candidates_are_missing(): void
    {
        NativeFunctionOverrideState::$forceIsFileFalse = true;

        $collector = new class implements SignatureCertificateCollectorInterface
        {
            public function collectDerCertificates(string $signatureHex): array
            {
                return [];
            }
        };

        $verifier = new OpenSslSignatureTrustVerifier($collector);
        $result = $verifier->verify('ABCD', new SignatureValidationOptionsDto(
            checkTrustChain: true,
        ));

        self::assertFalse($result->valid);
        self::assertStringContainsString('No trust store found', (string) $result->message);
    }

    public function test_verify_uses_brazil_policy_trust_anchor_bundle_when_available(): void
    {
        $systemBundle = '/etc/ssl/certs/ca-certificates.crt';
        if (! is_file($systemBundle)) {
            self::markTestSkipped('System CA bundle not available.');
        }

        $bundleContent = file_get_contents($systemBundle);
        if (! is_string($bundleContent) || $bundleContent === '') {
            self::markTestSkipped('System CA bundle is not readable.');
        }
        if (! preg_match('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $bundleContent, $m)) {
            self::markTestSkipped('No PEM certificate found in system bundle.');
        }
        $pem = $m[0];

        $http = new class($pem) implements HttpClientInterface
        {
            public function __construct(private readonly string $pem) {}

            public function request(
                string $method,
                string $url,
                array $headers = [],
                string $body = '',
                int $timeoutSeconds = 10,
                bool $followRedirects = false
            ): HttpResponse {
                return new HttpResponse(200, $this->pem);
            }
        };

        $trustProvider = new IcpBrasilTrustAnchorBundleProvider($http);
        $collector = new class implements SignatureCertificateCollectorInterface
        {
            public function collectDerCertificates(string $signatureHex): array
            {
                return [];
            }
        };

        $verifier = new OpenSslSignatureTrustVerifier(
            certificateCollector: $collector,
            trustAnchorBundleProvider: $trustProvider
        );

        $result = $verifier->verify('ABCD', new SignatureValidationOptionsDto(
            checkTrustChain: true,
            policy: 'br-iti',
            trustAnchorsDirectory: sys_get_temp_dir().'/signer-php-anchors-'.uniqid('', true),
            trustAnchorsUrls: ['https://anchor.local/root.crt'],
        ));

        self::assertFalse($result->valid);
        self::assertStringContainsString('Could not extract certificates', (string) $result->message);
    }
}
