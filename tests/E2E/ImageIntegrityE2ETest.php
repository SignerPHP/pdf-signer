<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\E2E;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\SignatureActorDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceXObjectDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto;
use SignerPHP\PdfSigner\Presentation\Signer;

/**
 * Image pixel-integrity E2E test suite.
 *
 * These tests answer the question "does the image embedded in the signed PDF
 * contain the same pixels as the original source file?" for every bit-depth and
 * colour-type combination that matters in practice.
 *
 * Strategy
 * --------
 * 1. Build a minimal PNG from known raw scanline bytes (no GD, no Imagick).
 * 2. Sign a real PDF with that PNG as either a background (imagePath / n0 layer)
 *    or a positioned overlay (userImagePath / n2 layer).
 * 3. Extract all image XObject streams from the signed PDF binary.
 * 4. Decompress each stream with gzuncompress() and assert pixel values.
 *
 * Because signer-php stores image channel data as plain FlateDecode with
 * Predictor 15, gzuncompress() returns the filtered scanline data:
 * one filter-byte per row followed by the raw channel bytes.  For the solid
 * single-pixel images used here the filter byte is always 0 (None), so the
 * decompressed data is simply:  0x00 <pixel-bytes…>
 *
 * The 16-bit RGBA test case is the regression scenario: when a PNG produced by
 * Imagick (which always generates 16-bit RGBA when rasterising an SVG) was
 * embedded, a bug in the alpha-channel extraction regex caused the SMask to
 * be corrupted, making the background image appear garbled in PDF viewers.
 */
final class ImageIntegrityE2ETest extends TestCase
{
    private const INPUT_PATH = __DIR__.'/../../exemplos/pdfs/Untitled.pdf';

    private const CERT_PATH = __DIR__.'/../../exemplos/cert.pfx';

    // Signature rect used for all tests (screen coords on page 0)
    private const RECT = [40, 60, 280, 140];

    // -----------------------------------------------------------------------
    // Background-image (n0 layer) integrity tests
    // -----------------------------------------------------------------------

    /**
     * 8-bit RGB PNG (no alpha channel).
     *
     * Solid magenta (R=255, G=0, B=255) pixel surviving the full sign pipeline.
     * Decompressed colour stream must be: filter-byte + R + G + B.
     */
    public function test_8bit_rgb_pixel_data_intact_after_signing_as_background(): void
    {
        // Scanline: filter=None, R=0xFF, G=0x00, B=0xFF
        $scanline = "\x00\xFF\x00\xFF";
        $pngPath = $this->buildPngFile(width: 1, height: 1, bits: 8, colorType: 2, scanline: $scanline);

        try {
            $signed = $this->signWithBackgroundImage($pngPath, '8-bit RGB background');

            $xObjects = $this->extractImageXObjects($signed);
            $colorStream = $this->findStream($xObjects, cs: 'DeviceRGB', bpc: 8);

            self::assertNotNull($colorStream, 'Signed PDF must contain an 8-bit DeviceRGB image XObject');

            $pixels = gzuncompress($colorStream);
            self::assertNotFalse($pixels, '8-bit RGB stream must be valid FlateDecode data');
            self::assertSame(
                "\x00\xFF\x00\xFF",
                $pixels,
                '8-bit RGB pixel (magenta) must be intact: filter-byte + R=255 G=0 B=255'
            );
        } finally {
            @unlink($pngPath);
        }
    }

    /**
     * 8-bit RGBA PNG (colour + alpha channel).
     *
     * Pixel: R=200, G=100, B=50, A=180.
     * After channel splitting:
     *   colour stream → filter-byte + R + G + B
     *   alpha stream  → filter-byte + A          (DeviceGray SMask)
     */
    public function test_8bit_rgba_colour_and_alpha_intact_after_signing_as_background(): void
    {
        // Scanline: filter=None, R=0xC8, G=0x64, B=0x32, A=0xB4
        $scanline = "\x00\xC8\x64\x32\xB4";
        $pngPath = $this->buildPngFile(width: 1, height: 1, bits: 8, colorType: 6, scanline: $scanline);

        try {
            $signed = $this->signWithBackgroundImage($pngPath, '8-bit RGBA background');

            $xObjects = $this->extractImageXObjects($signed);

            // Colour channel
            $colorStream = $this->findStream($xObjects, cs: 'DeviceRGB', bpc: 8);
            self::assertNotNull($colorStream, 'Signed PDF must contain an 8-bit DeviceRGB image XObject');
            $colorPixels = gzuncompress($colorStream);
            self::assertSame(
                "\x00\xC8\x64\x32",
                $colorPixels,
                '8-bit RGBA colour channel must be intact: filter-byte + R=200 G=100 B=50'
            );

            // Alpha channel (SMask)
            $alphaStream = $this->findStream($xObjects, cs: 'DeviceGray', bpc: 8);
            self::assertNotNull($alphaStream, 'Signed PDF must contain an 8-bit DeviceGray SMask XObject');
            $alphaPixels = gzuncompress($alphaStream);
            self::assertSame(
                "\x00\xB4",
                $alphaPixels,
                '8-bit RGBA alpha channel must be intact: filter-byte + A=180'
            );
        } finally {
            @unlink($pngPath);
        }
    }

    /**
     * 16-bit RGBA PNG — the regression scenario.
     *
     * Imagick always produces 16-bit RGBA when rasterising SVG images (e.g. a
     * watermark logo).  A bug in the alpha-channel regex consumed one extra byte
     * per pixel, truncating the last pixel's alpha value.
     *
     * Pixel: R=0xFFFF, G=0x0000, B=0x0000, A=0x7FFF (full red, ~50 % alpha).
     * After channel splitting:
     *   colour stream (DeviceRGB,  BPC=16) → filter-byte + R(2) + G(2) + B(2) = 7 bytes
     *   alpha  stream (DeviceGray, BPC=16) → filter-byte + A(2)               = 3 bytes
     */
    public function test_16bit_rgba_colour_and_alpha_intact_after_signing_as_background(): void
    {
        // Scanline: filter=None, R=0xFFFF, G=0x0000, B=0x0000, A=0x7FFF
        $scanline = "\x00\xFF\xFF\x00\x00\x00\x00\x7F\xFF";
        $pngPath = $this->buildPngFile(width: 1, height: 1, bits: 16, colorType: 6, scanline: $scanline);

        try {
            $signed = $this->signWithBackgroundImage($pngPath, '16-bit RGBA background');

            $xObjects = $this->extractImageXObjects($signed);

            // Colour channel
            $colorStream = $this->findStream($xObjects, cs: 'DeviceRGB', bpc: 16);
            self::assertNotNull($colorStream, 'Signed PDF must contain a 16-bit DeviceRGB image XObject');
            $colorPixels = gzuncompress($colorStream);
            self::assertSame(
                "\x00\xFF\xFF\x00\x00\x00\x00",
                $colorPixels,
                '16-bit RGBA colour channel must be intact: filter-byte + R=FFFF G=0000 B=0000'
            );

            // Alpha channel (SMask, also 16-bit after the fix)
            $alphaStream = $this->findStream($xObjects, cs: 'DeviceGray', bpc: 16);
            self::assertNotNull(
                $alphaStream,
                'Signed PDF must contain a 16-bit DeviceGray SMask (regression: SMask was 8-bit before fix)'
            );
            $alphaPixels = gzuncompress($alphaStream);
            self::assertSame(
                "\x00\x7F\xFF",
                $alphaPixels,
                '16-bit RGBA alpha channel must be intact: filter-byte + A=7FFF (regression: was corrupted)'
            );
        } finally {
            @unlink($pngPath);
        }
    }

    // -----------------------------------------------------------------------
    // User-image (n2 layer via userImagePath) integrity tests
    // -----------------------------------------------------------------------

    /**
     * A user-provided image placed in the n2 xObject layer on the LEFT half of
     * the signature rect (the typical "drawn signature" pattern).
     *
     * The RIGHT half carries a text description as PDF text operators.
     * imagePath is null, so n0 is blank.
     *
     * Verifies that the pixel data survives the n2 embedding path.
     */
    public function test_8bit_rgb_user_image_pixel_data_intact_in_n2_layer(): void
    {
        // Solid green pixel: R=0, G=255, B=0
        $scanline = "\x00\x00\xFF\x00";
        $pngPath = $this->buildPngFile(width: 1, height: 1, bits: 8, colorType: 2, scanline: $scanline);

        try {
            $signed = $this->signWithUserImageInN2($pngPath, '8-bit RGB user image n2');

            $xObjects = $this->extractImageXObjects($signed);

            $colorStream = $this->findStream($xObjects, cs: 'DeviceRGB', bpc: 8);
            self::assertNotNull($colorStream, 'Signed PDF must contain an 8-bit DeviceRGB image in the n2 layer');

            $pixels = gzuncompress($colorStream);
            self::assertSame(
                "\x00\x00\xFF\x00",
                $pixels,
                '8-bit RGB user-image pixel must be intact in n2: filter-byte + R=0 G=255 B=0'
            );
        } finally {
            @unlink($pngPath);
        }
    }

    /**
     * 16-bit RGBA user image placed in the n2 layer.
     *
     * Pixel: R=0x0000, G=0x0000, B=0xFFFF, A=0xBFFF (full blue, ~75 % alpha).
     * Verifies both the colour and alpha streams are intact for a 16-bit RGBA
     * image going through the userImagePath/n2 embedding pipeline.
     */
    public function test_16bit_rgba_user_image_colour_and_alpha_intact_in_n2_layer(): void
    {
        // Scanline: filter=None, R=0x0000, G=0x0000, B=0xFFFF, A=0xBFFF
        $scanline = "\x00\x00\x00\x00\x00\xFF\xFF\xBF\xFF";
        $pngPath = $this->buildPngFile(width: 1, height: 1, bits: 16, colorType: 6, scanline: $scanline);

        try {
            $signed = $this->signWithUserImageInN2($pngPath, '16-bit RGBA user image n2');

            $xObjects = $this->extractImageXObjects($signed);

            $colorStream = $this->findStream($xObjects, cs: 'DeviceRGB', bpc: 16);
            self::assertNotNull($colorStream, 'Signed PDF must contain a 16-bit DeviceRGB image XObject in n2');
            $colorPixels = gzuncompress($colorStream);
            self::assertSame(
                "\x00\x00\x00\x00\x00\xFF\xFF",
                $colorPixels,
                '16-bit colour channel must be intact: filter-byte + R=0000 G=0000 B=FFFF'
            );

            $alphaStream = $this->findStream($xObjects, cs: 'DeviceGray', bpc: 16);
            self::assertNotNull($alphaStream, 'Signed PDF must contain a 16-bit DeviceGray SMask in n2');
            $alphaPixels = gzuncompress($alphaStream);
            self::assertSame(
                "\x00\xBF\xFF",
                $alphaPixels,
                '16-bit alpha channel must be intact in n2: filter-byte + A=BFFF'
            );
        } finally {
            @unlink($pngPath);
        }
    }

    /**
     * Reproduces the "graphic + description" render pattern:
     * a background image fully covers n0, a user image occupies the left half
     * of n2, and description text occupies the right half of n2.
     *
     * Both images are solid-colour 1×1 PNGs with distinct colours so that each
     * stream can be identified and verified independently.
     *
     *   Background : solid blue  (R=0,   G=0,   B=255)  8-bit RGB
     *   User image : solid green (R=0,   G=255, B=0  )  8-bit RGB
     */
    public function test_background_and_user_image_both_intact_in_combined_appearance(): void
    {
        // Background: solid blue
        $bgScanline = "\x00\x00\x00\xFF";
        $bgPath = $this->buildPngFile(width: 1, height: 1, bits: 8, colorType: 2, scanline: $bgScanline);

        // User image: solid green
        $usrScanline = "\x00\x00\xFF\x00";
        $usrPath = $this->buildPngFile(width: 1, height: 1, bits: 8, colorType: 2, scanline: $usrScanline);

        try {
            $bboxW = 240;
            $bboxH = 80;
            $halfW = (float) $bboxW / 2.0;

            $appearance = new SignatureAppearanceDto(
                backgroundImagePath: $bgPath,
                rect: self::RECT,
                page: 0,
                xObject: new SignatureAppearanceXObjectDto(
                    stream: sprintf(
                        "BT\n/F1 10.00 Tf\n0 0 0 rg\n%.2F 60.00 Td\n(Description text) Tj\nET\n",
                        $halfW + 2.0,
                    ),
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
                signatureImagePath: $usrPath,
                signatureImageFrame: [0.0, 0.0, $halfW, (float) $bboxH],
            );

            $signed = $this->doSign($appearance, 'Combined: background n0 + user image n2 left + text n2 right');

            $xObjects = $this->extractImageXObjects($signed);

            // Collect all 8-bit DeviceRGB streams and verify our two known pixel
            // patterns are each present.  (The PDF may contain additional DeviceRGB
            // structures; asserting pixel content is more robust than asserting count.)
            $rgbStreams = array_filter($xObjects, static fn (array $o) => $o['cs'] === 'DeviceRGB' && $o['bpc'] === 8);
            self::assertNotEmpty($rgbStreams, 'There must be at least one DeviceRGB 8-bit image XObject in the signed PDF');

            // Extract decompressed pixel data from all matching streams
            $decompressed = array_map(
                static fn (array $o) => gzuncompress($o['stream']),
                array_values($rgbStreams),
            );

            self::assertContains(
                "\x00\x00\x00\xFF",
                $decompressed,
                'Background image pixel (solid blue) must be intact'
            );
            self::assertContains(
                "\x00\x00\xFF\x00",
                $decompressed,
                'User image pixel (solid green) must be intact'
            );
        } finally {
            @unlink($bgPath);
            @unlink($usrPath);
        }
    }

    /**
     * Background image aspect-ratio preservation.
     *
     * The background (n0 layer) must be scaled to "contain" inside the bbox –
     * i.e. the image's natural aspect ratio must be maintained and the image
     * must be centred rather than stretched to fill the bbox.
     *
     * Setup:
     *   PNG natural size : 4 × 2 pixels  → aspect ratio 2 : 1
     *   Bbox (from RECT)  : 240 × 80 pt  → aspect ratio 3 : 1
     *
     * Expected "contain" geometry:
     *   scale  = min(240/4, 80/2) = min(60, 40) = 40
     *   drawW  = 4  × 40 = 160 pt
     *   drawH  = 2  × 40 =  80 pt
     *   drawX  = (240 − 160) / 2 =  40 pt  (centred horizontally)
     *   drawY  = (80  −  80) / 2 =   0 pt
     *
     * The PDF content stream uses:
     *   ContentGeneration::tx(drawX, drawY) → " 1 0 0 1 40.00 0.00 cm"
     *   ContentGeneration::sx(drawW, drawH) → " 160.00 0 0 80.00 0 0 cm"
     *
     * If the image were stretched (old behaviour):
     *   ContentGeneration::sx(240, 80) → " 240.00 0 0 80.00 0 0 cm"
     */
    public function test_background_image_is_contained_and_centred_not_stretched(): void
    {
        // Build a 4×2 solid-red PNG (natural aspect = 2:1)
        // Two rows × 4 pixels × 3 channels = scanlines of 13 bytes each
        $row = "\x00".str_repeat("\xFF\x00\x00", 4); // filter + 4 red pixels
        $scanline = $row.$row;                             // two identical rows
        $pngPath = $this->buildPngFile(width: 4, height: 2, bits: 8, colorType: 2, scanline: $scanline);

        try {
            $signed = $this->signWithBackgroundImage($pngPath, 'background aspect-ratio test');

            // "Contain" geometry: scale=40, drawW=160, drawH=80, centred at drawX=40
            self::assertStringContainsString(
                ' 1 0 0 1 40.00 0.00 cm',
                $signed,
                'Background image must be centred horizontally: x-offset should be 40 pt, not 0'
            );
            self::assertStringContainsString(
                ' 160.00 0 0 80.00 0 0 cm',
                $signed,
                'Background image CTM must reflect "contain" scale (160×80), not bbox fill (240×80)'
            );
            self::assertStringNotContainsString(
                ' 240.00 0 0 80.00 0 0 cm',
                $signed,
                'Background image must NOT be stretched to fill the full bbox width (240 pt)'
            );
        } finally {
            @unlink($pngPath);
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Builds a minimal single-scanline PNG file from raw bytes and returns its path.
     * The caller is responsible for unlinking the temporary file.
     */
    private function buildPngFile(int $width, int $height, int $bits, int $colorType, string $scanline): string
    {
        $idat = (string) gzcompress($scanline);
        $ihdrData = pack('NNCCCCC', $width, $height, $bits, $colorType, 0, 0, 0);

        $png = "\x89PNG\r\n\x1a\n"
             .$this->pngChunk('IHDR', $ihdrData)
             .$this->pngChunk('IDAT', $idat)
             .$this->pngChunk('IEND', '');

        $path = (string) tempnam(sys_get_temp_dir(), 'signerphp-img-integrity-');
        file_put_contents($path, $png);

        return $path;
    }

    private function pngChunk(string $type, string $data): string
    {
        return pack('N', strlen($data)).$type.$data.pack('N', crc32($type.$data));
    }

    /**
     * Signs the test PDF with the given PNG as the background image (imagePath / n0 layer).
     * An empty xObject is used so the test focuses on image data only.
     */
    private function signWithBackgroundImage(string $pngPath, string $reason): string
    {
        $appearance = new SignatureAppearanceDto(
            backgroundImagePath: $pngPath,
            rect: self::RECT,
            page: 0,
            xObject: null,
        );

        return $this->doSign($appearance, $reason);
    }

    /**
     * Signs the test PDF with the given PNG as a positioned user image (userImagePath / n2 layer).
     * The image is placed on the left half of the signature area.
     * imagePath is null so n0 stays blank – isolating the n2 path.
     */
    private function signWithUserImageInN2(string $pngPath, string $reason): string
    {
        $bboxW = self::RECT[2] - self::RECT[0];  // 240
        $bboxH = self::RECT[3] - self::RECT[1];  // 80

        $appearance = new SignatureAppearanceDto(
            backgroundImagePath: null,
            rect: self::RECT,
            page: 0,
            xObject: null,
            signatureImagePath: $pngPath,
            signatureImageFrame: [0.0, 0.0, (float) $bboxW / 2.0, (float) $bboxH],
        );

        return $this->doSign($appearance, $reason);
    }

    private function doSign(SignatureAppearanceDto $appearance, string $reason): string
    {
        if (! function_exists('openssl_pkcs12_read')) {
            self::markTestSkipped('OpenSSL extension is required.');
        }

        self::assertFileExists(self::INPUT_PATH);
        self::assertFileExists(self::CERT_PATH);

        $input = file_get_contents(self::INPUT_PATH);
        self::assertIsString($input);

        $signed = Signer::signer()
            ->withPdfContent($input)
            ->withCertificatePath(self::CERT_PATH, '1234**')
            ->withMetadata(new SignatureMetadataDto(
                reason: $reason,
                actor: new SignatureActorDto(name: 'SignerPHP Integrity Test'),
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

    /**
     * Scans the signed PDF binary for image XObject streams.
     *
     * signer-php serialises PDF objects using the format:
     *   N 0 obj\n<<…/Subtype /Image…/Length NNN…>>\nstream\r\n<NNN bytes>\nendstream
     *
     * For each image XObject found, we record:
     *   cs     – /ColorSpace value     (DeviceRGB, DeviceGray, Indexed, …)
     *   bpc    – /BitsPerComponent     (8 or 16)
     *   stream – the raw NNN-byte compressed stream (FlateDecode)
     *
     * The header region is anchored to the most recent "N 0 obj" boundary before
     * each stream\r\n, preventing a consecutive object's fields from being
     * mistaken for the current object's /Length or /ColorSpace.
     *
     * @return list<array{cs:string, bpc:int, stream:string}>
     */
    private function extractImageXObjects(string $pdf): array
    {
        // Limit the scan to the incremental update section (bytes appended after the
        // original PDF's first %%EOF marker) so that pre-existing images in the test
        // fixture do not pollute the results.
        $updateStart = 0;
        $eofPos = strpos($pdf, "%%EOF\n");
        if ($eofPos === false) {
            $eofPos = strpos($pdf, "%%EOF\r\n");
        }
        if ($eofPos !== false) {
            $updateStart = $eofPos + strlen("%%EOF\n");
        }

        $found = [];
        $searchFrom = $updateStart;

        while (($streamKwPos = strpos($pdf, "stream\r\n", $searchFrom)) !== false) {
            $searchFrom = $streamKwPos + 1;

            // Look back for the most recent "N 0 obj" marker within 4000 bytes.
            // This isolates the current object's header even when objects are
            // serialised back-to-back and a previous stream's binary data appears
            // in a naive fixed-size lookback window.
            $lookBack = min($streamKwPos, 4000);
            $region = substr($pdf, $streamKwPos - $lookBack, $lookBack);

            // Anchor to the LAST "N 0 obj\n" or "N 0 obj\r\n" in the region
            $header = $region;
            if (preg_match_all('/\d+ 0 obj[\r\n]/', $region, $objMatches, PREG_OFFSET_CAPTURE)) {
                $last = end($objMatches[0]);
                $header = substr($region, (int) $last[1]);
            }

            // Must be an image XObject
            if (! str_contains($header, '/Subtype /Image') && ! str_contains($header, '/Subtype/Image')) {
                continue;
            }

            // Extract /Length — guaranteed to come from the current object now
            if (! preg_match('/\/Length\s+(\d+)/', $header, $lenm)) {
                continue;
            }
            $length = (int) $lenm[1];

            // Resolve /ColorSpace
            $cs = 'unknown';
            if (str_contains($header, '/DeviceRGB')) {
                $cs = 'DeviceRGB';
            } elseif (str_contains($header, '/DeviceGray')) {
                $cs = 'DeviceGray';
            } elseif (str_contains($header, '/Indexed')) {
                $cs = 'Indexed';
            }

            // Resolve /BitsPerComponent
            $bpc = 8;
            if (preg_match('/\/BitsPerComponent\s+(\d+)/', $header, $bm)) {
                $bpc = (int) $bm[1];
            }

            $dataStart = $streamKwPos + strlen("stream\r\n");
            $rawStream = substr($pdf, $dataStart, $length);

            $found[] = ['cs' => $cs, 'bpc' => $bpc, 'stream' => $rawStream];
        }

        return $found;
    }

    /**
     * Finds the first image XObject whose ColorSpace and BitsPerComponent match
     * and returns its raw (compressed) stream, or null if not found.
     *
     * @param  list<array{cs:string,bpc:int,stream:string}>  $xObjects
     */
    private function findStream(array $xObjects, string $cs, int $bpc): ?string
    {
        foreach ($xObjects as $obj) {
            if ($obj['cs'] === $cs && $obj['bpc'] === $bpc) {
                return $obj['stream'];
            }
        }

        return null;
    }
}
