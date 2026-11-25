<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Integration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\ProtectionOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativePdfProtectionApplier;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;
use SignerPHP\PdfSigner\Tests\Support\ProtectionPdfFixtures;

/**
 * Cross-checks the native encryption with qpdf, an independent PDF implementation.
 * qpdf is only a test oracle here; the library itself never runs it. Skipped when qpdf is not installed.
 */
final class NativePdfProtectionQpdfTest extends TestCase
{
    /** @var list<string> */
    private array $tempFiles = [];

    protected function setUp(): void
    {
        if (trim((string) shell_exec('command -v qpdf 2>/dev/null')) === '') {
            // CI installs qpdf: there the interoperability check must run, never be skipped.
            if (getenv('CI') !== false && getenv('CI') !== '') {
                self::fail('qpdf is required in CI to check native PDF protection.');
            }
            self::markTestSkipped('qpdf is not installed.');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            @unlink($file);
        }
    }

    /**
     * @return iterable<string, array{0: string, 1: ProtectionOptionsDto}>
     */
    public static function protectionModes(): iterable
    {
        foreach ([256, 128] as $bits) {
            yield "{$bits} user+owner, everything allowed" => [(string) $bits, new ProtectionOptionsDto('owner-pw', 'user-pw', true, true, true, $bits)];
            yield "{$bits} owner only, nothing allowed, clear metadata" => [(string) $bits, new ProtectionOptionsDto('owner-pw', '', false, false, false, $bits, false)];
            yield "{$bits} random owner, print only" => [(string) $bits, new ProtectionOptionsDto(null, 'só-usuário', true, false, false, $bits)];
            yield "{$bits} copy and modify, no print" => [(string) $bits, new ProtectionOptionsDto('dono', 'usuário', false, true, true, $bits)];
        }
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function documents(): iterable
    {
        yield 'minimal' => ['minimal'];
        yield 'rich syntax' => ['rich'];
        yield 'object and xref streams' => ['object-streams'];
        yield 'linearized' => ['linearized'];
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: ProtectionOptionsDto}>
     */
    public static function cases(): iterable
    {
        foreach (self::documents() as $documentName => [$document]) {
            foreach (self::protectionModes() as $modeName => [, $options]) {
                yield "{$documentName} / {$modeName}" => [$document, $modeName, $options];
            }
        }
    }

    #[DataProvider('cases')]
    public function test_qpdf_accepts_and_decrypts_native_encryption(string $document, string $mode, ProtectionOptionsDto $options): void
    {
        $source = $this->document($document);
        $sourceFile = $this->tempFile($source);
        $protectedFile = $this->tempFile((new NativePdfProtectionApplier)->apply($source, $options));
        $openPassword = $options->userPassword !== '' ? $options->userPassword : (string) $options->ownerPassword;

        [$exitCode, $check] = $this->qpdf(['--check', '--password='.$openPassword, $protectedFile]);
        self::assertSame(0, $exitCode, $check);
        self::assertStringContainsString('No syntax or stream encoding errors found', $check);
        self::assertStringContainsString($options->keyLengthBits === 256 ? 'PDF Version: 1.7 extension level 8' : 'PDF Version: 1.6', $check);

        $this->assertEncryptionReport($protectedFile, $options);

        if ($options->userPassword !== '') {
            [$exitCode, $output] = $this->qpdf(['--check', $protectedFile]);
            self::assertSame(2, $exitCode, $output);
            self::assertStringContainsString('invalid password', $output);

            [$exitCode, $output] = $this->qpdf(['--check', '--password=wrong-'.$options->userPassword, $protectedFile]);
            self::assertSame(2, $exitCode, $output);

            [, $report] = $this->qpdf(['--show-encryption', '--password='.$options->userPassword, $protectedFile]);
            self::assertStringContainsString('Supplied password is user password', $report);
        } else {
            [$exitCode, $output] = $this->qpdf(['--check', $protectedFile]);
            self::assertSame(0, $exitCode, $output);
        }

        $decryptedFile = $this->tempFile('');
        [$exitCode, $output] = $this->qpdf(['--decrypt', '--password='.$openPassword, $protectedFile, $decryptedFile]);
        self::assertSame(0, $exitCode, $output);
        [$exitCode, $output] = $this->qpdf(['--check', $decryptedFile]);
        self::assertSame(0, $exitCode, $output);

        $expected = $this->comparableObjects($sourceFile, null);
        self::assertNotEmpty($expected);
        self::assertSame(
            $expected,
            $this->comparableObjects($protectedFile, $openPassword),
            "Decrypted objects differ from the source ({$mode})",
        );
    }

    private function assertEncryptionReport(string $file, ProtectionOptionsDto $options): void
    {
        if ($options->ownerPassword === null) {
            [, $report] = $this->qpdf(['--show-encryption', '--password='.$options->userPassword, $file]);
        } else {
            [, $report] = $this->qpdf(['--show-encryption', '--password='.$options->ownerPassword, $file]);
            self::assertStringContainsString('Supplied password is owner password', $report);
        }

        $method = $options->keyLengthBits === 256 ? 'AESv3' : 'AESv2';
        $allowed = static fn (bool $flag): string => $flag ? 'allowed' : 'not allowed';

        $expected = [
            'R = '.($options->keyLengthBits === 256 ? '6' : '4'),
            'extract for accessibility: allowed',
            'extract for any purpose: '.$allowed($options->allowCopy),
            'print low resolution: '.$allowed($options->allowPrint),
            'print high resolution: '.$allowed($options->allowPrint),
            'modify document assembly: '.$allowed($options->allowModify),
            'modify forms: '.$allowed($options->allowModify),
            'modify annotations: '.$allowed($options->allowModify),
            'modify other: '.$allowed($options->allowModify),
            'modify anything: '.$allowed($options->allowModify),
            'stream encryption method: '.$method,
            'string encryption method: '.$method,
            'file encryption method: '.$method,
        ];

        foreach ($expected as $line) {
            self::assertMatchesRegularExpression('/^'.preg_quote($line, '/').'$/m', $report);
        }
    }

    /**
     * Objects as reported by qpdf (decrypted, raw stream data), without what a rewrite legitimately changes.
     *
     * @return array<string, mixed>
     */
    private function comparableObjects(string $file, ?string $password): array
    {
        $arguments = ['--json=2', '--json-key=qpdf', '--json-stream-data=inline', '--decode-level=none'];
        if ($password !== null) {
            $arguments[] = '--password='.$password;
        }
        $arguments[] = $file;

        [$exitCode, $json] = $this->qpdf($arguments, false);
        self::assertSame(0, $exitCode, $json);

        /** @var array{qpdf: array{0: array<string, mixed>, 1: array<string, array<string, mixed>>}} $decoded */
        $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        $comparable = [];

        foreach ($decoded['qpdf'][1] as $key => $object) {
            if ($key === 'trailer') {
                continue;
            }

            $dictionary = $object['value'] ?? ($object['stream']['dict'] ?? null);
            if (is_array($dictionary) && (in_array($dictionary['/Type'] ?? null, ['/ObjStm', '/XRef'], true)
                || isset($dictionary['/Linearized']) || isset($dictionary['/Filter'], $dictionary['/O'], $dictionary['/U']))) {
                continue;
            }

            if (isset($object['stream']['dict'])) {
                unset($object['stream']['dict']['/Length']);
            }

            if (is_array($object['value'] ?? null) && ($object['value']['/Type'] ?? null) === '/Catalog') {
                unset($object['value']['/Extensions']);
            }

            $comparable[$key] = $object;
        }

        ksort($comparable);

        return $comparable;
    }

    private function document(string $name): string
    {
        return match ($name) {
            'minimal' => PdfFixtureFactory::minimalPdf(),
            'rich' => ProtectionPdfFixtures::richPdf(),
            'object-streams' => (string) file_get_contents(__DIR__.'/../Fixtures/protection/object-streams.pdf'),
            default => $this->linearized(),
        };
    }

    private function linearized(): string
    {
        $input = $this->tempFile(ProtectionPdfFixtures::richPdf());
        $output = $this->tempFile('');
        [$exitCode, $message] = $this->qpdf(['--linearize', $input, $output]);
        self::assertSame(0, $exitCode, $message);

        return (string) file_get_contents($output);
    }

    /**
     * @param  list<string>  $arguments
     * @return array{0: int, 1: string}
     */
    private function qpdf(array $arguments, bool $mergeStderr = true): array
    {
        $command = 'qpdf '.implode(' ', array_map('escapeshellarg', $arguments)).($mergeStderr ? ' 2>&1' : ' 2>/dev/null');
        exec($command, $output, $exitCode);

        return [$exitCode, implode("\n", $output)];
    }

    /**
     * The file name ends in .pdf because Ubuntu's AppArmor profile for qpdf only lets it open files with
     * a PDF or JSON extension (tempnam() names have none, and qpdf fails with "Permission denied").
     */
    private function tempFile(string $content): string
    {
        $placeholder = (string) tempnam(sys_get_temp_dir(), 'native-protection-');
        $file = $placeholder.'.pdf';
        rename($placeholder, $file);
        file_put_contents($file, $content);
        $this->tempFiles[] = $file;

        return $file;
    }
}
