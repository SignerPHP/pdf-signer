<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceXObjectDto;

final class SignatureAppearanceXObjectDtoTest extends TestCase
{
    public function test_xobject_accepts_required_stream_parameter(): void
    {
        $xObject = new SignatureAppearanceXObjectDto('q /Im0 Do Q');

        self::assertSame('q /Im0 Do Q', $xObject->stream);
        self::assertNull($xObject->resources);
    }

    public function test_xobject_accepts_optional_resources(): void
    {
        $resources = [
            'Font' => [
                'F1' => [
                    'Type' => '/Font',
                    'Subtype' => '/Type1',
                    'BaseFont' => '/Helvetica',
                ],
            ],
        ];

        $xObject = new SignatureAppearanceXObjectDto('BT /F1 12 Tf (ok) Tj ET', $resources);

        self::assertSame($resources, $xObject->resources);
    }
}
