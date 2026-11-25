<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\E2E;

use PHPUnit\Framework\TestCase;

final class DoctorCliTest extends TestCase
{
    public function test_doctor_command_outputs_valid_json_report(): void
    {
        $output = $this->runCommand([
            PHP_BINARY,
            __DIR__.'/../../bin/signer-doctor',
            '--json',
        ], $exitCode);

        self::assertContains($exitCode, [0, 1], 'doctor exit code must be 0 or 1');

        $report = json_decode($output, true);
        self::assertIsArray($report);
        self::assertArrayHasKey('ok', $report);
        self::assertArrayHasKey('checks', $report);
        self::assertIsBool($report['ok']);
        self::assertIsArray($report['checks']);
        self::assertNotEmpty($report['checks']);

        foreach ($report['checks'] as $check) {
            self::assertIsArray($check);
            self::assertArrayHasKey('name', $check);
            self::assertArrayHasKey('required', $check);
            self::assertArrayHasKey('ok', $check);
        }
    }

    public function test_doctor_does_not_require_external_binaries(): void
    {
        $report = json_decode($this->runCommand([PHP_BINARY, __DIR__.'/../../bin/signer-doctor', '--json']), true);
        self::assertIsArray($report);

        $names = array_column($report['checks'], 'name');
        foreach ($names as $name) {
            self::assertStringNotContainsStringIgnoringCase('binary', $name);
            self::assertStringNotContainsStringIgnoringCase('qpdf', $name);
        }
        self::assertContains('PHP extension "openssl"', $names);
    }

    /**
     * @param  array<int, string>  $args
     */
    private function runCommand(array $args, ?int &$exitCode = null): string
    {
        $command = implode(' ', array_map('escapeshellarg', $args)).' 2>&1';
        $outputLines = [];
        $code = 1;
        exec($command, $outputLines, $code);
        $exitCode = $code;

        return implode("\n", $outputLines);
    }
}
