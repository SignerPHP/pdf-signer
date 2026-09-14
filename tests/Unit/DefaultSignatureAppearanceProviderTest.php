<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\DefaultSignatureAppearanceProvider;

final class DefaultSignatureAppearanceProviderTest extends TestCase
{
    public function test_provider_returns_styled_internal_asset_with_expected_defaults(): void
    {
        $provider = new DefaultSignatureAppearanceProvider;
        $appearance = $provider->makeDefault();

        self::assertIsString($appearance->backgroundImagePath);
        self::assertStringContainsString('default-signature-stamp.png', $appearance->backgroundImagePath ?? '');
        self::assertFileExists($appearance->backgroundImagePath ?? '');
        self::assertSame([36, 36, 276, 120], $appearance->normalizedRect());
        self::assertSame(0, $appearance->page);
    }

    public function test_provider_falls_back_to_embedded_base64_when_asset_is_missing(): void
    {
        $assetPath = __DIR__.'/../../src/Infrastructure/Native/Assets/default-signature-stamp.png';
        $backupPath = $assetPath.'.bak';
        self::assertFileExists($assetPath);

        rename($assetPath, $backupPath);
        try {
            $appearance = (new DefaultSignatureAppearanceProvider)->makeDefault();
            self::assertIsString($appearance->backgroundImagePath);
            self::assertStringStartsWith('iVBORw0KGgo', $appearance->backgroundImagePath ?? '');
        } finally {
            rename($backupPath, $assetPath);
        }
    }
}
