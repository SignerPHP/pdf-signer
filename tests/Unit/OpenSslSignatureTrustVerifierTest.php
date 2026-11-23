<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\SignatureValidationOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureCertificateCollectorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\IcpBrasilTrustAnchorBundleProvider;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeFunctionOverrideState;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslSignatureTrustVerifier;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\HttpResponse;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ProcessResult;

final class OpenSslSignatureTrustVerifierTest extends TestCase
{
    protected function tearDown(): void
    {
        NativeFunctionOverrideState::$forceTempnamFailure = false;
        NativeFunctionOverrideState::$forceIsFileFalse = false;
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

    public function test_verify_returns_invalid_when_signer_certificate_cannot_be_decoded(): void
    {
        $collector = new class implements SignatureCertificateCollectorInterface
        {
            public function collectDerCertificates(string $signatureHex): array
            {
                return [''];
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
            self::assertStringContainsString('Could not decode signer certificate', (string) $result->message);
        } finally {
            @unlink($trustStore);
        }
    }

    public function test_verify_returns_default_message_when_openssl_fails_without_output(): void
    {
        $collector = new class implements SignatureCertificateCollectorInterface
        {
            public function collectDerCertificates(string $signatureHex): array
            {
                return ['abc'];
            }
        };

        $runner = new class implements ProcessRunnerInterface
        {
            public function run(string $command): ProcessResult
            {
                return new ProcessResult(1, []);
            }
        };

        $trustStore = tempnam(sys_get_temp_dir(), 'trust-store');
        self::assertNotFalse($trustStore);
        file_put_contents($trustStore, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n");

        try {
            $verifier = new OpenSslSignatureTrustVerifier($collector, processRunner: $runner);
            $result = $verifier->verify('ABCD', new SignatureValidationOptionsDto(
                checkTrustChain: true,
                trustStorePath: $trustStore,
            ));

            self::assertFalse($result->valid);
            self::assertSame('OpenSSL verify failed for signer certificate chain.', $result->message);
        } finally {
            @unlink($trustStore);
        }
    }

    public function test_verify_returns_valid_when_openssl_succeeds_and_chain_is_present(): void
    {
        $collector = new class implements SignatureCertificateCollectorInterface
        {
            public function collectDerCertificates(string $signatureHex): array
            {
                return ['leaf-der', 'intermediate-der'];
            }
        };

        $runner = new class implements ProcessRunnerInterface
        {
            public string $command = '';

            public function run(string $command): ProcessResult
            {
                $this->command = $command;

                return new ProcessResult(0, ['ok']);
            }
        };

        $trustStore = tempnam(sys_get_temp_dir(), 'trust-store');
        self::assertNotFalse($trustStore);
        file_put_contents($trustStore, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n");

        try {
            $verifier = new OpenSslSignatureTrustVerifier($collector, processRunner: $runner);
            $result = $verifier->verify('ABCD', new SignatureValidationOptionsDto(
                checkTrustChain: true,
                trustStorePath: $trustStore,
            ));

            self::assertTrue($result->valid);
            self::assertStringContainsString('openssl verify -CAfile', $runner->command);
            self::assertStringContainsString(' -untrusted ', $runner->command);
        } finally {
            @unlink($trustStore);
        }
    }

    public function test_verify_at_validates_the_chain_at_the_given_time(): void
    {
        $collector = new class implements SignatureCertificateCollectorInterface
        {
            public function collectDerCertificates(string $signatureHex): array
            {
                return ['leaf-der'];
            }
        };

        $runner = new class implements ProcessRunnerInterface
        {
            /** @var list<string> */
            public array $commands = [];

            public function run(string $command): ProcessResult
            {
                $this->commands[] = $command;

                return new ProcessResult(0, ['ok']);
            }
        };

        $trustStore = (string) tempnam(sys_get_temp_dir(), 'trust-store');
        file_put_contents($trustStore, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n");

        try {
            $verifier = new OpenSslSignatureTrustVerifier($collector, processRunner: $runner);
            $options = new SignatureValidationOptionsDto(checkTrustChain: true, trustStorePath: $trustStore);

            $verifier->verifyAt('ABCD', $options, new \DateTimeImmutable('2020-06-15T12:00:00Z'));
            $verifier->verify('ABCD', $options);

            self::assertStringContainsString(' -attime 1592222400 ', $runner->commands[0]);
            self::assertStringNotContainsString('-attime', $runner->commands[1], 'regular signatures keep the current time');
        } finally {
            @unlink($trustStore);
        }
    }

    public function test_verify_uses_the_signer_certificate_even_when_the_ca_is_listed_first(): void
    {
        $dir = sys_get_temp_dir().'/trust-order-'.bin2hex(random_bytes(4));
        mkdir($dir);
        $d = escapeshellarg($dir);
        exec("cd $d && openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -subj /CN=Order-CA -days 1 2>&1"
            .' && openssl req -x509 -newkey rsa:2048 -nodes -keyout s.key -out s.crt -subj /CN=Order-Signer -days 1 2>&1'
            .' && printf data > d && openssl cms -sign -binary -nodetach -outform DER -signer s.crt -inkey s.key -certfile ca.crt -in d -out t.der 2>&1', $output, $exitCode);
        self::assertSame(0, $exitCode, implode("\n", $output));

        $runner = new class implements ProcessRunnerInterface
        {
            public string $leafSubject = '';

            public function run(string $command): ProcessResult
            {
                preg_match("/'([^']+)'$/", $command, $leaf);
                $parsed = openssl_x509_parse((string) file_get_contents($leaf[1] ?? ''));
                $this->leafSubject = is_array($parsed) ? (string) ($parsed['subject']['CN'] ?? '') : '';

                return new ProcessResult(0, ['ok']);
            }
        };

        try {
            (new OpenSslSignatureTrustVerifier(processRunner: $runner))->verify(
                bin2hex((string) file_get_contents("$dir/t.der")),
                new SignatureValidationOptionsDto(checkTrustChain: true, trustStorePath: "$dir/ca.crt"),
            );

            self::assertSame('Order-Signer', $runner->leafSubject);
        } finally {
            exec('rm -rf '.$d);
        }
    }

    public function test_verify_returns_invalid_when_temp_file_cannot_be_created(): void
    {
        NativeFunctionOverrideState::$forceTempnamFailure = true;

        $collector = new class implements SignatureCertificateCollectorInterface
        {
            public function collectDerCertificates(string $signatureHex): array
            {
                return ['leaf-der'];
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
            self::assertStringContainsString('temporary file', (string) $result->message);
        } finally {
            @unlink($trustStore);
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
