<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeFunctionOverrideState;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslRfc3161TimestampTokenValidator;

final class OpenSslRfc3161TimestampTokenValidatorTest extends TestCase
{
    public static function verificationCases(): iterable
    {
        yield 'valid signed token and matching imprint' => ['valid', false];
        yield 'valid signed token with mismatched imprint' => ['wrong-imprint', true];
        yield 'structurally incomplete CMS' => ['incomplete', true];
        yield 'truncated signed token' => ['truncated', true];
    }

    #[DataProvider('verificationCases')]
    public function test_timestamp_token_verification(string $scenario, bool $mustReject): void
    {
        $token = $this->generateToken('signature-bytes');
        $signature = 'signature-bytes';

        if ($scenario === 'wrong-imprint') {
            $signature = 'other-signature-bytes';
        } elseif ($scenario === 'incomplete') {
            $token = hex2bin('300b06092a864886f70d010702');
        } elseif ($scenario === 'truncated') {
            $token = substr($token, 0, -20);
        }

        if ($mustReject) {
            $this->expectException(SignProcessException::class);
        }

        (new OpenSslRfc3161TimestampTokenValidator)->assertValid($token, $signature);
        if (! $mustReject) {
            self::assertTrue(true);
        }
    }

    public function test_reports_temporary_file_allocation_failure(): void
    {
        NativeFunctionOverrideState::$forceTempnamFailure = true;

        try {
            $this->expectException(SignProcessException::class);
            $this->expectExceptionMessage('Could not create temporary files for signature timestamp verification.');

            (new OpenSslRfc3161TimestampTokenValidator)->assertValid('token', 'signature');
        } finally {
            NativeFunctionOverrideState::$forceTempnamFailure = false;
        }
    }

    private function generateToken(string $signature): string
    {
        $dir = sys_get_temp_dir().'/signerphp-local-tsa-'.bin2hex(random_bytes(8));
        self::assertTrue(mkdir($dir, 0700));
        try {
            file_put_contents($dir.'/signature', $signature);
            file_put_contents($dir.'/serial', "01\n");
            file_put_contents($dir.'/tsa.conf', sprintf(
                "[tsa]\ndefault_tsa=tsa_config\n[tsa_config]\nserial=%s/serial\nsigner_cert=%s/cert.pem\nsigner_key=%s/key.pem\ndefault_policy=1.2.3.4\ndigests=sha256\nsigner_digest=sha256\n",
                $dir, $dir, $dir,
            ));
            $this->runCommand('openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout '
                .escapeshellarg($dir.'/key.pem').' -out '.escapeshellarg($dir.'/cert.pem')
                .' -subj '.escapeshellarg('/CN=Test TSA')
                .' -addext '.escapeshellarg('extendedKeyUsage=critical,timeStamping')
                .' -addext '.escapeshellarg('keyUsage=critical,digitalSignature'));
            $this->runCommand('openssl ts -query -data '.escapeshellarg($dir.'/signature')
                .' -sha256 -cert -out '.escapeshellarg($dir.'/query'));
            $this->runCommand('openssl ts -reply -config '.escapeshellarg($dir.'/tsa.conf')
                .' -queryfile '.escapeshellarg($dir.'/query').' -out '.escapeshellarg($dir.'/reply'));
            $this->runCommand('openssl ts -reply -in '.escapeshellarg($dir.'/reply')
                .' -token_out -out '.escapeshellarg($dir.'/token'));
            $token = file_get_contents($dir.'/token');
            self::assertIsString($token);

            return $token;
        } finally {
            foreach (glob($dir.'/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }

    private function runCommand(string $command): void
    {
        $output = [];
        $status = 0;
        exec($command.' 2>&1', $output, $status);
        self::assertSame(0, $status, implode("\n", $output));
    }
}
