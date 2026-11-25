<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeRfc3161TimestampTokenValidator;

final class NativeRfc3161TimestampTokenValidatorTest extends TestCase
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

        (new NativeRfc3161TimestampTokenValidator)->assertValid($token, $signature);
        if (! $mustReject) {
            self::assertTrue(true);
        }
    }

    public function test_rejects_a_token_whose_signature_was_modified(): void
    {
        $token = $this->generateToken('signature-bytes');
        $last = strlen($token) - 1;
        $token[$last] = chr(ord($token[$last]) ^ 0x01);

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('CMS signature verification failed');

        (new NativeRfc3161TimestampTokenValidator)->assertValid($token, 'signature-bytes');
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
