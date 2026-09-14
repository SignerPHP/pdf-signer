<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Support;

use PHPUnit\Framework\Assert;

final class Pkcs12Fixture
{
    /**
     * @return array{cert: string, pkey: string}
     */
    public static function load(): array
    {
        if (! function_exists('openssl_pkcs12_read')) {
            Assert::markTestSkipped('OpenSSL PKCS#12 support is required.');
        }

        $certPath = __DIR__.'/../../exemplos/cert.pfx';
        if (! is_file($certPath)) {
            Assert::markTestSkipped('Test certificate exemplos/cert.pfx not found.');
        }

        $bundle = [];
        if (! openssl_pkcs12_read((string) file_get_contents($certPath), $bundle, '1234**')) {
            Assert::markTestSkipped('Could not read exemplos/cert.pfx.');
        }

        return [
            'cert' => (string) $bundle['cert'],
            'pkey' => (string) $bundle['pkey'],
        ];
    }

    public static function cmsVerifies(string $cmsDer, string $payload): bool
    {
        $cmsFile = tempnam(sys_get_temp_dir(), 'cms');
        $payloadFile = tempnam(sys_get_temp_dir(), 'dat');
        if ($cmsFile === false || $payloadFile === false) {
            return false;
        }

        try {
            file_put_contents($cmsFile, $cmsDer);
            file_put_contents($payloadFile, $payload);
            $command = sprintf(
                'openssl cms -verify -binary -inform DER -in %s -content %s -noverify -out /dev/null 2>&1',
                escapeshellarg($cmsFile),
                escapeshellarg($payloadFile),
            );
            exec($command, $output, $exitCode);

            return $exitCode === 0;
        } finally {
            @unlink($cmsFile);
            @unlink($payloadFile);
        }
    }
}
