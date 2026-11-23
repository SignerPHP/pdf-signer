<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslOcspSignerCertificateRevocationChecker;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ProcessResult;

final class OpenSslOcspSignerCertificateRevocationCheckerTest extends TestCase
{
    private const REVOKED = [
        'Response verify OK',
        '/tmp/ocsp-signer-certAbc: revoked',
        '	This Update: Nov 23 16:00:00 2026 GMT',
        '	Next Update: Nov 30 16:00:00 2026 GMT',
        '	Reason: keyCompromise',
        '	Revocation Time: Nov 23 15:00:00 2026 GMT',
    ];

    private const GOOD = [
        'Response verify OK',
        '/tmp/ocsp-signer-certAbc: good',
        '	This Update: Nov 23 16:00:00 2026 GMT',
        '	Next Update: Nov 30 16:00:00 2026 GMT',
    ];

    /** @var array{ca:string, leaf:string, twoResponders:string, leafWithoutOcsp:string, intermediateOnly:string} */
    private static array $pki;

    public static function setUpBeforeClass(): void
    {
        $config = (string) tempnam(sys_get_temp_dir(), 'ocsp-test-cnf');
        file_put_contents($config, implode("\n", [
            '[req]',
            'distinguished_name = dn',
            '[dn]',
            '[v3_ca]',
            'basicConstraints = critical, CA:TRUE',
            'keyUsage = critical, keyCertSign, cRLSign',
            '[v3_leaf]',
            'basicConstraints = critical, CA:FALSE',
            'authorityInfoAccess = OCSP;URI:http://ocsp.example.test/',
            '[v3_two]',
            'basicConstraints = critical, CA:FALSE',
            'authorityInfoAccess = OCSP;URI:http://ocsp-a.example.test/, OCSP;URI:http://ocsp-b.example.test/',
            '[v3_plain]',
            'basicConstraints = critical, CA:FALSE',
            '',
        ]));

        try {
            $options = ['config' => $config, 'digest_alg' => 'sha256', 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
            $caKey = openssl_pkey_new($options);
            $ca = openssl_csr_sign(openssl_csr_new(['commonName' => 'Revocation Test CA'], $caKey, $options), null, $caKey, 1, $options + ['x509_extensions' => 'v3_ca'], 1);

            $issue = function (string $cn, string $section, int $serial) use ($ca, $caKey, $options): string {
                $key = openssl_pkey_new($options);
                $cert = openssl_csr_sign(openssl_csr_new(['commonName' => $cn], $key, $options), $ca, $caKey, 1, $options + ['x509_extensions' => $section], $serial);
                openssl_x509_export($cert, $pem);

                return $pem;
            };

            openssl_x509_export($ca, $caPem);
            self::$pki = [
                'ca' => $caPem,
                'leaf' => $issue('Revocation Test Signer', 'v3_leaf', 2),
                'twoResponders' => $issue('Two Responders Signer', 'v3_two', 3),
                'leafWithoutOcsp' => $issue('Signer Without OCSP', 'v3_plain', 4),
                // Issued by the CA but not self-signed: usable as issuer, never as a trust anchor.
                'intermediateOnly' => $issue('Revocation Test CA', 'v3_ca', 5),
            ];
        } finally {
            unlink($config);
        }
    }

    public function test_verified_revoked_response_is_fatal(): void
    {
        $runner = $this->runner([self::REVOKED]);

        try {
            $this->checker($runner)->assertNotRevoked(self::$pki['leaf'], [self::$pki['ca']]);
            self::fail('A revoked certificate must not be accepted.');
        } catch (SignProcessException $exception) {
            self::assertStringContainsString('"Revocation Test Signer" is revoked', $exception->getMessage());
            self::assertStringContainsString('http://ocsp.example.test/', $exception->getMessage());
            self::assertStringContainsString('Nov 23 15:00:00 2026 GMT', $exception->getMessage());
            self::assertStringContainsString('keyCompromise', $exception->getMessage());
        }
    }

    public function test_response_signature_is_verified_against_the_signer_chain(): void
    {
        $runner = $this->runner([self::GOOD]);

        $this->checker($runner)->assertNotRevoked(self::$pki['leaf'], [self::$pki['ca']]);

        self::assertCount(1, $runner->commands);
        $command = $runner->commands[0];
        self::assertStringNotContainsString('-noverify', $command);
        self::assertStringNotContainsString('-no_nonce', $command);
        self::assertStringContainsString('-CAfile ', $command);
        self::assertStringContainsString('-verify_other ', $command);
        self::assertStringContainsString('-validity_period 300', $command);
        self::assertStringContainsString('-status_age 86400', $command);
    }

    public function test_unverified_revoked_response_is_ignored(): void
    {
        $forged = self::REVOKED;
        $forged[0] = 'Response Verify Failure';

        $this->checker($this->runner([$forged]))->assertNotRevoked(self::$pki['leaf'], [self::$pki['ca']]);
        $this->checker($this->runner([array_slice(self::REVOKED, 1)]))->assertNotRevoked(self::$pki['leaf'], [self::$pki['ca']]);
        $this->checker($this->runner([self::REVOKED], exitCode: 1))->assertNotRevoked(self::$pki['leaf'], [self::$pki['ca']]);

        $this->addToAssertionCount(1);
    }

    public function test_stale_or_replayed_revoked_response_is_ignored(): void
    {
        $this->checker($this->runner([[...self::REVOKED, 'WARNING: Status times invalid.']]))->assertNotRevoked(self::$pki['leaf'], [self::$pki['ca']]);
        $this->checker($this->runner([['WARNING: Nonce Verify error', ...self::REVOKED]]))->assertNotRevoked(self::$pki['leaf'], [self::$pki['ca']]);

        $this->addToAssertionCount(1);
    }

    public function test_every_responder_is_asked_and_any_verified_revocation_wins(): void
    {
        $runner = $this->runner([self::GOOD, self::REVOKED]);

        try {
            $this->checker($runner)->assertNotRevoked(self::$pki['twoResponders'], [self::$pki['ca']]);
            self::fail('A revocation reported by the second responder must not be ignored.');
        } catch (SignProcessException $exception) {
            self::assertStringContainsString('http://ocsp-b.example.test/', $exception->getMessage());
        }

        self::assertCount(2, $runner->commands);
        self::assertStringContainsString("-url 'http://ocsp-a.example.test/'", $runner->commands[0]);
        self::assertStringContainsString("-url 'http://ocsp-b.example.test/'", $runner->commands[1]);
    }

    public function test_good_from_every_responder_passes(): void
    {
        $runner = $this->runner([self::GOOD, self::GOOD]);

        $this->checker($runner)->assertNotRevoked(self::$pki['twoResponders'], [self::$pki['ca']]);

        self::assertCount(2, $runner->commands);
    }

    public function test_skips_the_check_without_url_issuer_trust_anchor_or_certificate(): void
    {
        $runner = $this->runner([self::REVOKED]);
        $checker = $this->checker($runner);

        $checker->assertNotRevoked(self::$pki['leafWithoutOcsp'], [self::$pki['ca']]);
        $checker->assertNotRevoked(self::$pki['leaf'], []);
        $checker->assertNotRevoked(self::$pki['leaf'], [self::$pki['intermediateOnly']]);
        $checker->assertNotRevoked('', [self::$pki['ca']]);
        $checker->assertNotRevoked('not a certificate', [self::$pki['ca']]);

        self::assertSame([], $runner->commands);
    }

    private function checker(ProcessRunnerInterface $runner): OpenSslOcspSignerCertificateRevocationChecker
    {
        return new OpenSslOcspSignerCertificateRevocationChecker(processRunner: $runner);
    }

    /**
     * @param  list<list<string>>  $outputs  one output per call, in order
     */
    private function runner(array $outputs, int $exitCode = 0): ProcessRunnerInterface
    {
        return new class($outputs, $exitCode) implements ProcessRunnerInterface
        {
            /** @var list<string> */
            public array $commands = [];

            /** @param list<list<string>> $outputs */
            public function __construct(private array $outputs, private int $exitCode) {}

            public function run(string $command): ProcessResult
            {
                $this->commands[] = $command;

                return new ProcessResult($this->exitCode, $this->outputs[count($this->commands) - 1] ?? []);
            }
        };
    }
}
