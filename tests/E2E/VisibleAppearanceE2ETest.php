<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\E2E;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\SignatureActorDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceXObjectDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto;
use SignerPHP\PdfSigner\Presentation\Signer;

final class VisibleAppearanceE2ETest extends TestCase
{
    public function test_signs_pdf_with_background_image_and_xobject_text(): void
    {
        if (! function_exists('openssl_pkcs12_read')) {
            self::markTestSkipped('OpenSSL extension is required.');
        }

        $inputPath = __DIR__.'/../../exemplos/pdfs/Untitled.pdf';
        $certPath = __DIR__.'/../../exemplos/cert.pfx';
        $backgroundPath = __DIR__.'/../../src/Infrastructure/Native/Assets/default-signature-stamp.png';

        self::assertFileExists($inputPath);
        self::assertFileExists($certPath);
        self::assertFileExists($backgroundPath);

        $input = file_get_contents($inputPath);
        self::assertIsString($input);

        $xObject = new SignatureAppearanceXObjectDto(
            stream: "BT\n/F1 10 Tf\n0 0 0 rg\n8 42 Td\n(Signed by Demo User) Tj\n0 -12 Td\n(Document approved) Tj\nET\n",
            resources: [
                'Font' => [
                    'F1' => [
                        'Type' => '/Font',
                        'Subtype' => '/Type1',
                        'BaseFont' => '/Helvetica',
                    ],
                ],
            ],
        );

        $appearance = new SignatureAppearanceDto(
            backgroundImagePath: $backgroundPath,
            rect: [40, 60, 280, 140],
            page: 0,
            xObject: $xObject,
        );

        $signed = Signer::signer()
            ->withPdfContent($input)
            ->withCertificatePath($certPath, '1234**')
            ->withMetadata(new SignatureMetadataDto(
                reason: 'Visible appearance E2E',
                actor: new SignatureActorDto(name: 'SignerPHP Test'),
            ))
            ->withAppearance($appearance)
            ->sign();

        $validation = Signer::validation()
            ->withPdfContent($signed)
            ->validate();

        self::assertTrue($validation->hasSignatures, 'Signed PDF must contain at least one signature');
        self::assertTrue($validation->allValid, 'Generated signature must be valid');

        self::assertStringContainsString('/n0 Do', $signed, 'Appearance must include background layer n0');
        self::assertStringContainsString('/n2 Do', $signed, 'Appearance must include text layer n2');
        self::assertStringContainsString('/Subtype/Image', $signed, 'Appearance must embed image XObject');
        self::assertStringContainsString('/Helvetica', $signed, 'Appearance must include font resource for text xObject');
        self::assertStringContainsString('Signed by Demo User', $signed, 'Text stream must be embedded in signed PDF');
    }

    public function test_signs_pdf_with_16bit_png_background_image(): void
    {
        if (! function_exists('openssl_pkcs12_read')) {
            self::markTestSkipped('OpenSSL extension is required.');
        }

        $inputPath = __DIR__.'/../../exemplos/pdfs/Untitled.pdf';
        $certPath = __DIR__.'/../../exemplos/cert.pfx';
        self::assertFileExists($inputPath);
        self::assertFileExists($certPath);

        $input = file_get_contents($inputPath);
        self::assertIsString($input);

        $backgroundPath = $this->create16BitPngBackgroundFile();
        try {
            $appearance = new SignatureAppearanceDto(
                backgroundImagePath: $backgroundPath,
                rect: [40, 60, 280, 140],
                page: 0,
                xObject: new SignatureAppearanceXObjectDto(
                    stream: "BT\n/F1 10 Tf\n0 0 0 rg\n8 42 Td\n(16-bit background) Tj\nET\n",
                    resources: [
                        'Font' => [
                            'F1' => [
                                'Type' => '/Font',
                                'Subtype' => '/Type1',
                                'BaseFont' => '/Helvetica',
                            ],
                        ],
                    ],
                ),
            );

            $signed = Signer::signer()
                ->withPdfContent($input)
                ->withCertificatePath($certPath, '1234**')
                ->withMetadata(new SignatureMetadataDto(
                    reason: 'Visible appearance with 16-bit PNG',
                    actor: new SignatureActorDto(name: 'SignerPHP Test'),
                ))
                ->withAppearance($appearance)
                ->sign();

            $validation = Signer::validation()
                ->withPdfContent($signed)
                ->validate();

            self::assertTrue($validation->hasSignatures, 'Signed PDF must contain at least one signature');
            self::assertTrue($validation->allValid, 'Generated signature must be valid');

            self::assertStringContainsString('/n0 Do', $signed, 'Appearance must include background layer n0');
            self::assertStringContainsString('/Subtype/Image', $signed, 'Appearance must embed image XObject');
            self::assertStringContainsString('/BitsPerComponent 16', $signed, '16-bit PNG background must preserve BitsPerComponent=16');
            self::assertStringContainsString('16-bit background', $signed, 'Text xObject must still be embedded with 16-bit background');
        } finally {
            @unlink($backgroundPath);
        }
    }

    public function test_signs_pdf_with_16bit_rgba_png_background_image(): void
    {
        if (! function_exists('openssl_pkcs12_read')) {
            self::markTestSkipped('OpenSSL extension is required.');
        }

        $inputPath = __DIR__.'/../../exemplos/pdfs/Untitled.pdf';
        $certPath = __DIR__.'/../../exemplos/cert.pfx';
        self::assertFileExists($inputPath);
        self::assertFileExists($certPath);

        $input = file_get_contents($inputPath);
        self::assertIsString($input);

        // 16-bit RGBA PNG (colorType=6, bitsPerChannel=16) — same type Imagick produces from SVGs.
        // Previously, the alpha channel extraction regex had a trailing '.' that consumed 9
        // bytes per pixel instead of 8, corrupting the SMask and rendering the image garbled.
        $backgroundPath = $this->create16BitRgbaPngBackgroundFile();
        try {
            $appearance = new SignatureAppearanceDto(
                backgroundImagePath: $backgroundPath,
                rect: [40, 60, 280, 140],
                page: 0,
                xObject: new SignatureAppearanceXObjectDto(
                    stream: "BT\n/F1 10 Tf\n0 0 0 rg\n8 42 Td\n(16-bit RGBA background) Tj\nET\n",
                    resources: [
                        'Font' => [
                            'F1' => [
                                'Type' => '/Font',
                                'Subtype' => '/Type1',
                                'BaseFont' => '/Helvetica',
                            ],
                        ],
                    ],
                ),
            );

            $signed = Signer::signer()
                ->withPdfContent($input)
                ->withCertificatePath($certPath, '1234**')
                ->withMetadata(new SignatureMetadataDto(
                    reason: 'Visible appearance with 16-bit RGBA PNG',
                    actor: new SignatureActorDto(name: 'SignerPHP Test'),
                ))
                ->withAppearance($appearance)
                ->sign();

            $validation = Signer::validation()
                ->withPdfContent($signed)
                ->validate();

            self::assertTrue($validation->hasSignatures, 'Signed PDF must contain at least one signature');
            self::assertTrue($validation->allValid, 'Generated signature must be valid');

            self::assertStringContainsString('/n0 Do', $signed, 'Appearance must include background layer n0');
            self::assertStringContainsString('/Subtype/Image', $signed, 'Appearance must embed image XObject');
            self::assertStringContainsString('/SMask', $signed, '16-bit RGBA PNG must embed an SMask for the alpha channel');
            self::assertStringContainsString('/BitsPerComponent 16', $signed, '16-bit RGBA SMask must preserve BitsPerComponent=16');
            self::assertStringContainsString('16-bit RGBA background', $signed, 'Text xObject must still be embedded');
        } finally {
            @unlink($backgroundPath);
        }
    }

    public function test_signs_pdf_with_global_background_and_xobject_with_its_own_background(): void
    {
        $xObject = new SignatureAppearanceXObjectDto(
            stream: "q\n0.95 0.95 0.95 rg\n0 0 240 80 re f\nQ\nBT\n/F1 10 Tf\n0 0 0 rg\n8 56 Td\n(XObject own background) Tj\n0 -14 Td\n(Rich text on top) Tj\nET\n",
            resources: [
                'Font' => [
                    'F1' => [
                        'Type' => '/Font',
                        'Subtype' => '/Type1',
                        'BaseFont' => '/Helvetica',
                    ],
                ],
            ],
        );

        $appearance = new SignatureAppearanceDto(
            backgroundImagePath: __DIR__.'/../../src/Infrastructure/Native/Assets/default-signature-stamp.png',
            rect: [40, 60, 280, 140],
            page: 0,
            xObject: $xObject,
        );

        $signed = $this->signWithAppearance($appearance, 'Visible appearance with nested background');

        self::assertStringContainsString('/n0 Do', $signed, 'Global background layer must be present');
        self::assertStringContainsString('/n2 Do', $signed, 'XObject layer must be present');
        self::assertStringContainsString('/Subtype/Image', $signed, 'Global background image must be embedded');
        self::assertStringContainsString('0 0 240 80 re f', $signed, 'XObject should contain its own background rectangle fill');
        self::assertStringContainsString('XObject own background', $signed, 'XObject rich text must be embedded');
    }

    public function test_signs_pdf_with_xobject_inline_image_left_and_rich_text_right(): void
    {
        $xObject = new SignatureAppearanceXObjectDto(
            stream: "q\n32 0 0 48 8 18 cm\nBI\n/W 1\n/H 1\n/BPC 8\n/CS /RGB\n/F [/ASCIIHexDecode]\nID\n3366CC>\nEI\nQ\nBT\n/F1 11 Tf\n0 0 0 rg\n50 52 Td\n(Signature preview) Tj\n0 -14 Td\n/F1 9 Tf\n(Rich text aligned right) Tj\nET\n",
            resources: [
                'Font' => [
                    'F1' => [
                        'Type' => '/Font',
                        'Subtype' => '/Type1',
                        'BaseFont' => '/Helvetica',
                    ],
                ],
            ],
        );

        $appearance = new SignatureAppearanceDto(
            backgroundImagePath: null,
            rect: [40, 60, 280, 140],
            page: 0,
            xObject: $xObject,
        );

        $signed = $this->signWithAppearance($appearance, 'Visible appearance with inline image in xobject');

        self::assertStringContainsString('/n2 Do', $signed, 'XObject layer must be present');
        self::assertStringContainsString('BI', $signed, 'XObject should include inline image operator');
        self::assertStringContainsString('/ASCIIHexDecode', $signed, 'Inline image filter should be present in xObject stream');
        self::assertStringContainsString('Signature preview', $signed, 'Rich text title must be embedded');
        self::assertStringContainsString('Rich text aligned right', $signed, 'Rich text subtitle must be embedded');
    }

    public function test_signs_pdf_with_global_background_and_xobject_inline_image_plus_rich_text(): void
    {
        $xObject = new SignatureAppearanceXObjectDto(
            stream: "q\n0.98 0.98 0.98 rg\n0 0 240 80 re f\nQ\nq\n30 0 0 46 8 20 cm\nBI\n/W 1\n/H 1\n/BPC 8\n/CS /RGB\n/F [/ASCIIHexDecode]\nID\nCC3333>\nEI\nQ\nBT\n/F1 11 Tf\n0 0 0 rg\n50 54 Td\n(Combined layout) Tj\n0 -14 Td\n/F1 9 Tf\n(Image left + rich text right) Tj\nET\n",
            resources: [
                'Font' => [
                    'F1' => [
                        'Type' => '/Font',
                        'Subtype' => '/Type1',
                        'BaseFont' => '/Helvetica',
                    ],
                ],
            ],
        );

        $appearance = new SignatureAppearanceDto(
            backgroundImagePath: __DIR__.'/../../src/Infrastructure/Native/Assets/default-signature-stamp.png',
            rect: [40, 60, 280, 140],
            page: 0,
            xObject: $xObject,
        );

        $signed = $this->signWithAppearance($appearance, 'Visible appearance combined scenario');

        self::assertStringContainsString('/n0 Do', $signed, 'Global background layer must be present');
        self::assertStringContainsString('/n2 Do', $signed, 'XObject layer must be present');
        self::assertStringContainsString('/Subtype/Image', $signed, 'Global background image must be embedded');
        self::assertStringContainsString('BI', $signed, 'XObject should include inline image operator');
        self::assertStringContainsString('Combined layout', $signed, 'Combined scenario text must be embedded');
        self::assertStringContainsString('Image left + rich text right', $signed, 'Combined scenario rich text must be embedded');
    }

    private function signWithAppearance(SignatureAppearanceDto $appearance, string $reason): string
    {
        if (! function_exists('openssl_pkcs12_read')) {
            self::markTestSkipped('OpenSSL extension is required.');
        }

        $inputPath = __DIR__.'/../../exemplos/pdfs/Untitled.pdf';
        $certPath = __DIR__.'/../../exemplos/cert.pfx';
        self::assertFileExists($inputPath);
        self::assertFileExists($certPath);

        $input = file_get_contents($inputPath);
        self::assertIsString($input);

        $signed = Signer::signer()
            ->withPdfContent($input)
            ->withCertificatePath($certPath, '1234**')
            ->withMetadata(new SignatureMetadataDto(
                reason: $reason,
                actor: new SignatureActorDto(name: 'SignerPHP Test'),
            ))
            ->withAppearance($appearance)
            ->sign();

        $validation = Signer::validation()
            ->withPdfContent($signed)
            ->validate();

        self::assertTrue($validation->hasSignatures, 'Signed PDF must contain at least one signature');
        self::assertTrue($validation->allValid, 'Generated signature must be valid');

        return $signed;
    }

    private function create16BitPngBackgroundFile(): string
    {
        $scanline = "\x00\xFF\xFF\x00\x00\x00\x00";
        $idat = (string) gzcompress($scanline);

        $ihdrData = pack('N', 1)
            .pack('N', 1)
            .chr(16)
            .chr(2)
            .chr(0)
            .chr(0)
            .chr(0);

        $png = "\x89PNG\r\n\x1a\n"
            .$this->pngChunk('IHDR', $ihdrData)
            .$this->pngChunk('IDAT', $idat)
            .$this->pngChunk('IEND', '');

        $path = tempnam(sys_get_temp_dir(), 'signerphp-16bit-');
        if ($path === false) {
            self::fail('Could not create temporary file for 16-bit PNG fixture');
        }

        file_put_contents($path, $png);

        return $path;
    }

    private function create16BitRgbaPngBackgroundFile(): string
    {
        // 1×1 pixel, 16-bit RGBA (colorType=6, bitsPerChannel=16).
        // This is the exact format Imagick produces when rasterising an SVG.
        // Scanline: filter_byte(0=None) + R(2 bytes) + G(2 bytes) + B(2 bytes) + A(2 bytes)
        $scanline = "\x00"     // filter byte: None
            ."\xFF\xFF"        // R = 65535 (full red)
            ."\x00\x00"        // G = 0
            ."\x00\x00"        // B = 0
            ."\x7F\xFF";       // A = ~50% (semi-transparent)
        $idat = (string) gzcompress($scanline);

        $ihdrData = pack('N', 1)   // width = 1
            .pack('N', 1)          // height = 1
            .chr(16)               // bit depth = 16
            .chr(6)                // color type = 6 (RGBA)
            .chr(0)                // compression method
            .chr(0)                // filter method
            .chr(0);               // interlace method

        $png = "\x89PNG\r\n\x1a\n"
            .$this->pngChunk('IHDR', $ihdrData)
            .$this->pngChunk('IDAT', $idat)
            .$this->pngChunk('IEND', '');

        $path = tempnam(sys_get_temp_dir(), 'signerphp-16bit-rgba-');
        if ($path === false) {
            self::fail('Could not create temporary file for 16-bit RGBA PNG fixture');
        }

        file_put_contents($path, $png);

        return $path;
    }

    private function pngChunk(string $type, string $data): string
    {
        $length = pack('N', strlen($data));
        $crc = pack('N', crc32($type.$data));

        return $length.$type.$data.$crc;
    }
}
