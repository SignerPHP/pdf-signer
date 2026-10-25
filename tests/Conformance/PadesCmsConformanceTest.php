<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Conformance;

use FilesystemIterator;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * Verify the public PDF signing contract using the independent OpenSSL CLI.
 * No internal PDF signature validator or CMS parser is used here.
 */
final class PadesCmsConformanceTest extends TestCase
{
    public function test_basic_and_pades_baseline_b_signatures_with_rsa_and_ecdsa(): void
    {
        $temporaryFile = tempnam(sys_get_temp_dir(), 'signerphp-pades-');
        self::assertNotFalse($temporaryFile);
        unlink($temporaryFile);
        self::assertTrue(mkdir($temporaryFile, 0700));

        try {
            // Preparation exits before the external signatures are generated.
            $this->execute([PHP_BINARY, __DIR__.'/fixture.php', 'prepare', $temporaryFile]);

            foreach (['rsa', 'ec'] as $keyType) {
                $directory = $temporaryFile.'/'.$keyType;
                self::assertFileExists($directory.'/state.json');
                self::assertFileExists($directory.'/digest.bin');
                self::assertSame(32, filesize($directory.'/digest.bin'), $keyType.' external SHA-256 digest length');

                // A separate OpenSSL process signs the digest; the CMS library never accesses its key.
                $this->execute([
                    'openssl', 'pkeyutl', '-sign', '-inkey', $directory.'/key.pem',
                    '-in', $directory.'/digest.bin', '-pkeyopt', 'digest:sha256',
                    '-out', $directory.'/signature.der',
                ]);
                // Remove the private key before the independent completion process.
                self::assertTrue(unlink($directory.'/key.pem'));
            }

            // Completion runs after preparation has terminated, without an in-memory state or key.
            $this->execute([PHP_BINARY, __DIR__.'/fixture.php', 'complete', $temporaryFile]);

            foreach (['rsa', 'ec'] as $keyType) {
                foreach (['sync-basic' => false, 'sync-pades' => true, 'external-pades' => true] as $name => $pades) {
                    $this->assertIndependentConformance($temporaryFile.'/'.$keyType, $name, $pades);
                }
            }

            // Negative control: independently reject a modified ByteRange payload.
            $rsa = $temporaryFile.'/rsa';
            $tampered = (string) file_get_contents($rsa.'/sync-pades.signed-content.bin');
            $tampered[0] = '!';
            file_put_contents($rsa.'/tampered.bin', $tampered);
            $this->executeExpectFailure([
                'openssl', 'cms', '-verify', '-binary', '-inform', 'DER',
                '-in', $rsa.'/sync-pades.cms.der', '-content', $rsa.'/tampered.bin',
                '-CAfile', $rsa.'/cert.pem', '-purpose', 'any', '-out', '/dev/null',
            ]);
        } finally {
            $this->removeFixtureDirectory($temporaryFile);
        }
    }

    private function assertIndependentConformance(string $directory, string $fileBaseName, bool $pades): void
    {
        $pdfFile = $directory.'/'.$fileBaseName.'.pdf';
        $pdf = file_get_contents($pdfFile);
        self::assertIsString($pdf);
        self::assertStringStartsWith('%PDF-', $pdf);
        self::assertSame(1, preg_match_all('/\/ByteRange\s*\[/', $pdf), $pdfFile);
        self::assertSame(1, preg_match('/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/', $pdf, $match), $pdfFile);

        [$offset, $firstLength, $secondOffset, $secondLength] = array_map('intval', array_slice($match, 1));
        self::assertSame(0, $offset);
        self::assertSame(strlen($pdf), $secondOffset + $secondLength);
        self::assertGreaterThan($firstLength + 2, $secondOffset);

        $contents = substr($pdf, $firstLength, $secondOffset - $firstLength);
        self::assertMatchesRegularExpression('/^<[0-9A-Fa-f]+>$/D', $contents);
        $contentsHex = substr($contents, 1, -1);
        $raw = hex2bin($contentsHex);
        self::assertIsString($raw);
        $cms = $this->unpadDer($raw);
        self::assertSame(str_repeat("\x00", strlen($raw) - strlen($cms)), substr($raw, strlen($cms)), $pdfFile);

        self::assertSame(1, preg_match('/\/M\s*\(D:\d{14}(?:[+\-Z].*?)?\)/', $pdf), $pdfFile.' must retain PDF /M');
        $subfilter = $pades ? 'ETSI.CAdES.detached' : 'adbe.pkcs7.detached';
        self::assertSame(1, preg_match('/\/SubFilter\s*\/'.preg_quote($subfilter, '/').'\b/', $pdf), $pdfFile);

        $cmsFile = $directory.'/'.$fileBaseName.'.cms.der';
        $payloadFile = $directory.'/'.$fileBaseName.'.signed-content.bin';
        file_put_contents($cmsFile, $cms);
        $content = substr($pdf, $offset, $firstLength).substr($pdf, $secondOffset, $secondLength);
        file_put_contents($payloadFile, $content);

        // OpenSSL performs the cryptographic verification, independent of SignerPHP.
        $this->execute([
            'openssl', 'cms', '-verify', '-binary', '-inform', 'DER',
            '-in', $cmsFile, '-content', $payloadFile,
            '-CAfile', $directory.'/cert.pem', '-purpose', 'any',
            '-out', '/dev/null',
        ]);
        $print = $this->execute(['openssl', 'cms', '-cmsout', '-print', '-inform', 'DER', '-in', $cmsFile]);
        self::assertStringContainsString('eContentType: pkcs7-data', $print);
        self::assertStringContainsString('eContent: <ABSENT>', $print);
        self::assertSame(1, preg_match('/signedAttrs:\s*\R(.*?)\R\s*signatureAlgorithm:/s', $print, $blocks));
        $attributes = $blocks[1];
        self::assertSame(1, substr_count($attributes, 'object: contentType'));
        self::assertSame(1, substr_count($attributes, 'object: messageDigest'));
        self::assertStringContainsString('OBJECT:pkcs7-data', $attributes);

        $asn1 = $this->execute(['openssl', 'asn1parse', '-inform', 'DER', '-in', $cmsFile, '-i']);
        $signedContentHash = strtoupper(hash('sha256', $content));
        self::assertMatchesRegularExpression(
            '/OBJECT\s+:messageDigest\R(?:[^\r\n]*\R){1,3}[^\r\n]*OCTET STRING\s+\[HEX DUMP\]:'.preg_quote($signedContentHash, '/').'\b/',
            $asn1,
            $pdfFile.' must embed the digest of ByteRange bytes',
        );

        if ($pades) {
            self::assertStringNotContainsString('object: signingTime', $attributes);
            self::assertStringNotContainsString('object: id-smime-aa-signingCertificate (', $attributes);
            self::assertSame(1, substr_count($attributes, 'object: id-smime-aa-signingCertificateV2'));
            $certificateHash = strtoupper(hash('sha256', $this->certificateDer($directory.'/cert.pem')));
            self::assertMatchesRegularExpression(
                '/OBJECT\s+:id-smime-aa-signingCertificateV2\R(?:[^\r\n]*\R){3,6}[^\r\n]*OCTET STRING\s+\[HEX DUMP\]:'.preg_quote($certificateHash, '/').'\b/',
                $asn1,
                $pdfFile.' must reference the exact DER signer certificate',
            );
            $issuerDetails = substr($asn1, (int) strpos($asn1, 'id-smime-aa-signingCertificateV2'), 3600);
            self::assertStringContainsString('cont [ 4 ]', $issuerDetails);
            self::assertStringContainsString('SignerPHP conformance '.basename($directory), $issuerDetails);
            $serialInfo = $this->execute(['openssl', 'x509', '-in', $directory.'/cert.pem', '-noout', '-serial']);
            self::assertSame(1, preg_match('/serial=([0-9a-f]+)/i', $serialInfo, $certificateSerial));
            self::assertSame(1, preg_match('/INTEGER\s+:([0-9a-f]+)/i', $issuerDetails, $referencedSerial));
            self::assertSame(
                strtoupper(ltrim($certificateSerial[1], '0')),
                strtoupper(ltrim($referencedSerial[1], '0')),
                $pdfFile.' must reference the signer certificate serial number',
            );
        } else {
            self::assertSame(1, substr_count($attributes, 'object: signingTime'));
            self::assertStringNotContainsString('object: id-smime-aa-signingCertificateV2', $attributes);
        }
    }

    private function certificateDer(string $path): string
    {
        $pem = file_get_contents($path);
        self::assertIsString($pem);
        $encoded = preg_replace('/-----[^-]+-----|\s+/', '', $pem);
        self::assertIsString($encoded);
        $der = base64_decode($encoded, true);
        self::assertIsString($der);

        return $der;
    }

    /** Removes PDF zero padding without interpreting any CMS attributes. */
    private function unpadDer(string $bytes): string
    {
        self::assertGreaterThanOrEqual(3, strlen($bytes));
        self::assertSame(0x30, ord($bytes[0]));
        $first = ord($bytes[1]);
        if ($first < 128) {
            $length = $first;
            $header = 2;
        } else {
            $count = $first & 0x7F;
            self::assertGreaterThan(0, $count);
            self::assertLessThanOrEqual(4, $count);
            $header = 2 + $count;
            $length = 0;
            for ($index = 0; $index < $count; $index++) {
                $length = ($length << 8) | ord($bytes[2 + $index]);
            }
        }
        self::assertLessThanOrEqual(strlen($bytes), $header + $length);

        return substr($bytes, 0, $header + $length);
    }

    /** @param list<string> $arguments */
    private function execute(array $arguments): string
    {
        $output = [];
        $status = 0;
        exec(implode(' ', array_map('escapeshellarg', $arguments)).' 2>&1', $output, $status);
        self::assertSame(0, $status, implode("\n", $output));

        return implode("\n", $output);
    }

    /** @param list<string> $arguments */
    private function executeExpectFailure(array $arguments): void
    {
        $output = [];
        $status = 0;
        exec(implode(' ', array_map('escapeshellarg', $arguments)).' 2>&1', $output, $status);
        self::assertNotSame(0, $status, 'OpenSSL unexpectedly accepted tampered signed content.');
    }

    private function removeFixtureDirectory(string $directory): void
    {
        if (! is_dir($directory)) {
            return;
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );
        foreach ($iterator as $item) {
            if ($item->isDir() && ! $item->isLink()) {
                rmdir($item->getPathname());
            } else {
                unlink($item->getPathname());
            }
        }
        rmdir($directory);
    }
}
