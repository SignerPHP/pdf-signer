<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\ProtectionOptionsDto;
use SignerPHP\PdfSigner\Application\DTO\ProtectPdfRequestDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\CommandExecutorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\NativePdfProtectionEngine;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\QpdfPdfProtectionApplier;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;
use SignerPHP\PdfSigner\Tests\Support\StandardSecurityTestDecryptor;

final class QpdfPdfProtectionApplierTest extends TestCase
{
    public function test_deprecated_applier_delegates_to_native_encryption_without_running_commands(): void
    {
        $executor = new class implements CommandExecutorInterface
        {
            public function run(string $command, string $errorMessage): void
            {
                throw new RuntimeException('No external command must be executed: '.$command);
            }
        };

        /** @psalm-suppress DeprecatedClass */
        $applier = new QpdfPdfProtectionApplier($executor);
        $protected = $applier->apply(
            PdfFixtureFactory::minimalPdf(),
            new ProtectionOptionsDto(ownerPassword: 'owner-secret', userPassword: 'user-secret', allowCopy: false, keyLengthBits: 128),
        );

        $decryptor = new StandardSecurityTestDecryptor($protected);
        self::assertSame(4, $decryptor->revision());
        self::assertNotNull($decryptor->fileKey('user-secret'));
        self::assertSame(0, $decryptor->permissions() & 0x10);
    }

    public function test_default_constructor_still_works(): void
    {
        /** @psalm-suppress DeprecatedClass */
        $protected = (new QpdfPdfProtectionApplier)->apply(PdfFixtureFactory::minimalPdf(), new ProtectionOptionsDto(ownerPassword: 'owner'));

        self::assertSame(6, (new StandardSecurityTestDecryptor($protected))->revision());
    }

    public function test_protection_engine_uses_native_applier_by_default(): void
    {
        $engine = new NativePdfProtectionEngine;
        $protected = $engine->protect(new ProtectPdfRequestDto(
            new PdfContentDto(PdfFixtureFactory::minimalPdf()),
            new ProtectionOptionsDto(ownerPassword: 'owner', userPassword: 'user'),
        ));

        self::assertNotNull((new StandardSecurityTestDecryptor($protected))->fileKey('user'));
    }
}
