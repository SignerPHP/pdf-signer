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
    /** @var array{ca:string, leaf:string, leafWithoutOcsp:string} */
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
            '[v3_plain]',
            'basicConstraints = critical, CA:FALSE',
            '',
        ]));

        try {
            $options = ['config' => $config, 'digest_alg' => 'sha256', 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
            $caKey = openssl_pkey_new($options);
            $caCsr = openssl_csr_new(['commonName' => 'Revocation Test CA'], $caKey, $options);
            $ca = openssl_csr_sign($caCsr, null, $caKey, 1, $options + ['x509_extensions' => 'v3_ca'], 1);

            $issue = function (string $cn, string $section, int $serial) use ($ca, $caKey, $options): string {
                $key = openssl_pkey_new($options);
                $csr = openssl_csr_new(['commonName' => $cn], $key, $options);
                $cert = openssl_csr_sign($csr, $ca, $caKey, 1, $options + ['x509_extensions' => $section], $serial);
                openssl_x509_export($cert, $pem);

                return $pem;
            };

            openssl_x509_export($ca, $caPem);
            self::$pki = [
                'ca' => $caPem,
                'leaf' => $issue('Revocation Test Signer', 'v3_leaf', 2),
                'leafWithoutOcsp' => $issue('Signer Without OCSP', 'v3_plain', 3),
            ];
        } finally {
            unlink($config);
        }
    }

    public function test_throws_when_the_responder_reports_the_certificate_as_revoked(): void
    {
        $runner = $this->runner([
            '/tmp/ocsp-signer-certAbc: revoked',
            '	This Update: Nov 23 16:00:00 2026 GMT',
            '	Reason: keyCompromise',
            '	Revocation Time: Nov 23 15:00:00 2026 GMT',
        ]);

        try {
            (new OpenSslOcspSignerCertificateRevocationChecker(processRunner: $runner))->assertNotRevoked(self::$pki['leaf'], [self::$pki['ca']]);
            self::fail('A revoked certificate must not be accepted.');
        } catch (SignProcessException $exception) {
            self::assertStringContainsString('"Revocation Test Signer" is revoked', $exception->getMessage());
            self::assertStringContainsString('http://ocsp.example.test/', $exception->getMessage());
            self::assertStringContainsString('Nov 23 15:00:00 2026 GMT', $exception->getMessage());
            self::assertStringContainsString('keyCompromise', $exception->getMessage());
        }

        self::assertCount(1, $runner->commands);
        self::assertStringContainsString("-url 'http://ocsp.example.test/'", $runner->commands[0]);
    }

    public function test_accepts_a_good_certificate(): void
    {
        $runner = $this->runner(['/tmp/ocsp-signer-certAbc: good']);

        (new OpenSslOcspSignerCertificateRevocationChecker(processRunner: $runner))->assertNotRevoked(self::$pki['leaf'], [self::$pki['ca']]);

        self::assertCount(1, $runner->commands);
    }

    public function test_does_not_block_when_the_responder_is_unreachable(): void
    {
        $runner = $this->runner(['Error querying OCSP responder'], exitCode: 1);

        (new OpenSslOcspSignerCertificateRevocationChecker(processRunner: $runner))->assertNotRevoked(self::$pki['leaf'], [self::$pki['ca']]);

        self::assertCount(1, $runner->commands);
    }

    public function test_skips_the_check_without_ocsp_url_issuer_or_certificate(): void
    {
        $runner = $this->runner(['should not run']);
        $checker = new OpenSslOcspSignerCertificateRevocationChecker(processRunner: $runner);

        $checker->assertNotRevoked(self::$pki['leafWithoutOcsp'], [self::$pki['ca']]);
        $checker->assertNotRevoked(self::$pki['leaf'], []);
        $checker->assertNotRevoked('', [self::$pki['ca']]);
        $checker->assertNotRevoked('not a certificate', [self::$pki['ca']]);

        self::assertSame([], $runner->commands);
    }

    /**
     * @param  list<string>  $output
     */
    private function runner(array $output, int $exitCode = 0): ProcessRunnerInterface
    {
        return new class($output, $exitCode) implements ProcessRunnerInterface
        {
            /** @var list<string> */
            public array $commands = [];

            /** @param list<string> $output */
            public function __construct(private array $output, private int $exitCode) {}

            public function run(string $command): ProcessResult
            {
                $this->commands[] = $command;

                return new ProcessResult($this->exitCode, $this->output);
            }
        };
    }
}
