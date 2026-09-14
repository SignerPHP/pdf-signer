<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\E2E;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\SignatureActorDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceXObjectDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto;
use SignerPHP\PdfSigner\Presentation\Signer;

final class VisibleSignatureScenariosE2ETest extends TestCase
{
    private const INPUT_PATH = __DIR__.'/../../exemplos/pdfs/Untitled.pdf';

    private const CERT_PATH = __DIR__.'/../../exemplos/cert.pfx';

    private const BACKGROUND_PATH = __DIR__.'/../../src/Infrastructure/Native/Assets/default-signature-stamp.png';

    // Realistic A4 element (PDF bottom-left coords, page=1):
    //   llx=85, lly=700, urx=310, ury=770
    // Converted to screen coords with pageHeight=841.89:
    //   rect = [85, 71.89, 310, 141.89]
    private const A4_PAGE_HEIGHT = 841.89;

    private const ELEMENT_LLX = 85.0;

    private const ELEMENT_LLY = 700.0;

    private const ELEMENT_URX = 310.0;

    private const ELEMENT_URY = 770.0;

    private const ELEMENT_WIDTH = self::ELEMENT_URX - self::ELEMENT_LLX; // 225

    private const ELEMENT_HEIGHT = self::ELEMENT_URY - self::ELEMENT_LLY; // 70

    // --- Scenario 1 -------------------------------------------------------
    // RENDER_MODE_DESCRIPTION_ONLY, background disabled, no user image.
    // PhpNativeHandler currently produces this when background is disabled.
    // xObject text spans the full width.
    // -----------------------------------------------------------------------
    public function test_pdfsignerphp_description_only_no_background_and_no_user_image(): void
    {
        $width = (int) self::ELEMENT_WIDTH;
        $height = (int) self::ELEMENT_HEIGHT;

        $appearance = new SignatureAppearanceDto(
            backgroundImagePath: null,
            rect: $this->toScreenRect(
                self::ELEMENT_LLX, self::ELEMENT_LLY,
                self::ELEMENT_URX, self::ELEMENT_URY,
                self::A4_PAGE_HEIGHT,
            ),
            page: 0, // PdfSignerPHP page=1 → 0-based index=0
            xObject: $this->buildTextOnlyXObject(
                width: $width,
                height: $height,
                lines: ['Signed with PdfSignerPHP', 'admin', 'Issuer: Common Name', 'Date: 2026.03.03 15:14:23 UTC'],
                startX: 2.0, // full-width: starts near left edge
            ),
        );

        $signed = $this->sign($appearance, 'PdfSignerPHP: text-only, no background');

        self::assertStringContainsString('/n2 Do', $signed, 'Must have text layer n2');
        self::assertStringContainsString('Signed with PdfSignerPHP', $signed, 'Text must be embedded');
        // No background image expected
        self::assertStringNotContainsString('/Subtype/Image', $signed, 'Must NOT embed background image XObject when imagePath is null');
    }

    // --- Scenario 2 -------------------------------------------------------
    // RENDER_MODE_DESCRIPTION_ONLY, background enabled.
    // PhpNativeHandler: imagePath=background, xObject=text on full width.
    // This is what PdfSignerPHP currently sends even for graphic+description mode
    // (broken: user signature image missing).
    // -----------------------------------------------------------------------
    public function test_pdfsignerphp_description_only_with_background_no_user_image(): void
    {
        self::assertFileExists(self::BACKGROUND_PATH);
        $width = (int) self::ELEMENT_WIDTH;
        $height = (int) self::ELEMENT_HEIGHT;

        $appearance = new SignatureAppearanceDto(
            backgroundImagePath: self::BACKGROUND_PATH,
            rect: $this->toScreenRect(
                self::ELEMENT_LLX, self::ELEMENT_LLY,
                self::ELEMENT_URX, self::ELEMENT_URY,
                self::A4_PAGE_HEIGHT,
            ),
            page: 0,
            xObject: $this->buildTextOnlyXObject(
                width: $width,
                height: $height,
                lines: ['Signed with PdfSignerPHP', 'admin', 'Issuer: Common Name', 'Date: 2026.03.03 15:14:23 UTC'],
                startX: 2.0,
            ),
        );

        $signed = $this->sign($appearance, 'PdfSignerPHP: text-only, background enabled (current broken state)');

        self::assertStringContainsString('/n0 Do', $signed, 'Must have background layer n0');
        self::assertStringContainsString('/n2 Do', $signed, 'Must have text layer n2');
        self::assertStringContainsString('/Subtype/Image', $signed, 'Background image must be embedded');
        self::assertStringContainsString('Signed with PdfSignerPHP', $signed, 'Text must be embedded');
        // This scenario is valid structurally but incomplete: no user signature on the left.
    }

    // --- Scenario 3 -------------------------------------------------------
    // RENDER_MODE_GRAPHIC_AND_DESCRIPTION, background disabled.
    // Expected: user signature image constrained to left half of n2 via
    // userImagePath/userImageRect; description text on right half.
    // n0 is blank (imagePath=null).
    // -----------------------------------------------------------------------
    public function test_pdfsignerphp_graphic_and_description_user_image_left_text_right_no_background(): void
    {
        $width = (int) self::ELEMENT_WIDTH;
        $height = (int) self::ELEMENT_HEIGHT;
        $halfW = (float) $width / 2.0;

        $userSignaturePng = $this->makeMinimalUserSignaturePng();
        try {
            $appearance = new SignatureAppearanceDto(
                backgroundImagePath: null,
                rect: $this->toScreenRect(
                    self::ELEMENT_LLX, self::ELEMENT_LLY,
                    self::ELEMENT_URX, self::ELEMENT_URY,
                    self::A4_PAGE_HEIGHT,
                ),
                page: 0,
                xObject: $this->buildTextOnlyXObject(
                    width: $width,
                    height: $height,
                    lines: ['Signed with PdfSignerPHP', 'admin', 'Issuer: Common Name', 'Date: 2026.03.03 15:14:23 UTC'],
                    startX: $halfW + 2.0, // right half
                ),
                signatureImagePath: $userSignaturePng,
                signatureImageFrame: [0.0, 0.0, $halfW, (float) $height],
            );

            $signed = $this->sign($appearance, 'PdfSignerPHP: graphic+description, no background');

            self::assertStringContainsString('/n2 Do', $signed, 'Must have xObject layer n2');
            // User image is an external XObject (not inline BI) placed in n2 via userImagePath
            self::assertStringContainsString('/Subtype/Image', $signed, 'User image must be embedded as XObject in n2');
            self::assertStringNotContainsString("BI\n/W", $signed, 'Must NOT use inline image — use external XObject instead');
            self::assertStringContainsString('Signed with PdfSignerPHP', $signed, 'Text must be embedded in xObject');
            // imagePath=null → n0 must be blank (DSBlank)
            self::assertStringContainsString('DSBlank', $signed, 'n0 layer must be blank when imagePath is null');
        } finally {
            @unlink($userSignaturePng);
        }
    }

    // --- Scenario 4 -------------------------------------------------------
    // RENDER_MODE_GRAPHIC_AND_DESCRIPTION, background enabled.
    // Expected: background fills n0 via imagePath; user signature constrained to
    // left half of n2 via userImagePath/userImageRect; description text on right.
    // -----------------------------------------------------------------------
    public function test_pdfsignerphp_graphic_and_description_user_image_left_text_right_with_background(): void
    {
        self::assertFileExists(self::BACKGROUND_PATH);
        $width = (int) self::ELEMENT_WIDTH;
        $height = (int) self::ELEMENT_HEIGHT;
        $halfW = (float) $width / 2.0;

        $userSignaturePng = $this->makeMinimalUserSignaturePng();
        try {
            $appearance = new SignatureAppearanceDto(
                backgroundImagePath: self::BACKGROUND_PATH,
                rect: $this->toScreenRect(
                    self::ELEMENT_LLX, self::ELEMENT_LLY,
                    self::ELEMENT_URX, self::ELEMENT_URY,
                    self::A4_PAGE_HEIGHT,
                ),
                page: 0,
                xObject: $this->buildTextOnlyXObject(
                    width: $width,
                    height: $height,
                    lines: ['Signed with PdfSignerPHP', 'admin', 'Issuer: Common Name', 'Date: 2026.03.03 15:14:23 UTC'],
                    startX: $halfW + 2.0,
                ),
                signatureImagePath: $userSignaturePng,
                signatureImageFrame: [0.0, 0.0, $halfW, (float) $height],
            );

            $signed = $this->sign($appearance, 'graphic+description, background enabled');

            self::assertStringContainsString('/n0 Do', $signed, 'Must have background layer n0');
            self::assertStringContainsString('/n2 Do', $signed, 'Must have xObject layer n2');
            self::assertStringContainsString('/Subtype/Image', $signed, 'At least one image XObject must be embedded (background + user image)');
            self::assertStringNotContainsString("BI\n/W", $signed, 'Must NOT use inline image — both images are external XObjects');
            self::assertStringContainsString('Signed with PdfSignerPHP', $signed, 'Text must be embedded in xObject');
        } finally {
            @unlink($userSignaturePng);
        }
    }

    // --- Scenario 5 -------------------------------------------------------
    // RENDER_MODE_SIGNAME_AND_DESCRIPTION, background enabled.
    // Expected: signer name as large Tf/BT text operators on the LEFT half of n2
    //           + description lines on the right half + background fills n0.
    // No user image file — the name is rendered as PDF text operators directly
    // inside the xObject stream (no inline BI, no userImagePath).
    // -----------------------------------------------------------------------
    public function test_pdfsignerphp_signame_and_description_name_text_left_description_right_with_background(): void
    {
        self::assertFileExists(self::BACKGROUND_PATH);
        $width = (int) self::ELEMENT_WIDTH;
        $height = (int) self::ELEMENT_HEIGHT;

        $signerName = 'John Doe';
        $nameFontSize = 18.0;

        $appearance = new SignatureAppearanceDto(
            backgroundImagePath: self::BACKGROUND_PATH,
            rect: $this->toScreenRect(
                self::ELEMENT_LLX, self::ELEMENT_LLY,
                self::ELEMENT_URX, self::ELEMENT_URY,
                self::A4_PAGE_HEIGHT,
            ),
            page: 0,
            xObject: $this->buildSignerNameAndDescriptionXObject(
                width: $width,
                height: $height,
                name: $signerName,
                nameFontSize: $nameFontSize,
                descLines: ['Issuer: Common Name', 'Date: 2026.03.03 15:14:23 UTC'],
            ),
        );

        $signed = $this->sign($appearance, 'PdfSignerPHP: signame+description, background enabled');

        self::assertStringContainsString('/n0 Do', $signed, 'Must have background layer n0');
        self::assertStringContainsString('/n2 Do', $signed, 'Must have xObject layer n2');
        self::assertStringContainsString('/Subtype/Image', $signed, 'Background image must be embedded in n0');
        // Name appears as raw PDF string operator — no image needed
        self::assertStringContainsString('John Doe', $signed, 'Signer name must be present as text in xObject stream');
        self::assertStringContainsString(
            sprintf('/F1 %.2F Tf', $nameFontSize),
            $signed,
            'Signer name font size operator must be present'
        );
        self::assertStringNotContainsString("BI\n/W", $signed, 'Must NOT use inline image in signame+description mode');
        self::assertStringContainsString('Issuer: Common Name', $signed, 'Description text must be embedded');
    }

    // --- Helpers ----------------------------------------------------------

    /**
     * Converts PdfSignerPHP PDF bottom-left coords to the screen top-left coords
     * expected by signer-php (which internally re-converts to PDF rect).
     *
     * @return array{0: float, 1: float, 2: float, 3: float}
     */
    private function toScreenRect(float $llx, float $lly, float $urx, float $ury, float $pageHeight): array
    {
        return [
            $llx,
            $pageHeight - $ury,  // screen top-left Y = pageH - PDF ury
            $urx,
            $pageHeight - $lly,  // screen bottom-left Y = pageH - PDF lly
        ];
    }

    /**
     * Builds an xObject stream that renders the signer name in a large font on the
     * LEFT half of the signature bbox and description lines on the RIGHT half.
     *
     * This mirrors the SIGNAME_AND_DESCRIPTION render mode: the name is expressed
     * as PDF text operators (BT/Tf/Td/Tj/ET) rather than as an image — no file is
     * needed and no inline image (BI) is produced.
     *
     * @param  string[]  $descLines
     */
    private function buildSignerNameAndDescriptionXObject(
        int $width,
        int $height,
        string $name,
        float $nameFontSize,
        array $descLines,
    ): SignatureAppearanceXObjectDto {
        $halfW = (float) $width / 2.0;

        // Center the name vertically in the left half
        $nameY = max(0.0, ((float) $height - $nameFontSize) / 2.0);
        $escaped = str_replace(['\\', '(', ')'], ['\\\\', '\\(', '\\)'], $name);
        $stream = sprintf(
            "BT\n/F1 %.2F Tf\n0 0 0 rg\n2.00 %.2F Td\n(%s) Tj\nET\n",
            $nameFontSize,
            $nameY,
            $escaped,
        );

        // Description lines on the right half
        $descFontSize = 10.0;
        $lineHeight = $descFontSize * 1.2;
        $currentY = max(0.0, (float) $height - $descFontSize - 2.0);
        foreach ($descLines as $line) {
            if ($currentY < 0.0) {
                break;
            }
            $escapedLine = str_replace(['\\', '(', ')'], ['\\\\', '\\(', '\\)'], $line);
            $stream .= sprintf(
                "BT\n/F1 %.2F Tf\n0 0 0 rg\n%.2F %.2F Td\n(%s) Tj\nET\n",
                $descFontSize,
                $halfW + 2.0,
                $currentY,
                $escapedLine,
            );
            $currentY -= $lineHeight;
        }

        return new SignatureAppearanceXObjectDto(
            stream: $stream,
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
    }

    /**
     * Builds a description-text-only XObject stream (no image).
     * startX controls horizontal origin — use 2.0 for full-width, width/2+2 for right half.
     */
    private function buildTextOnlyXObject(int $width, int $height, array $lines, float $startX): SignatureAppearanceXObjectDto
    {
        $fontSize = 10.0;
        $lineHeight = $fontSize * 1.2;
        $currentY = max(0.0, (float) $height - $fontSize - 2.0);
        $stream = '';
        foreach ($lines as $line) {
            if ($currentY < 0) {
                break;
            }
            $escaped = str_replace(['\\', '(', ')'], ['\\\\', '\\(', '\\)'], $line);
            $stream .= sprintf("BT\n/F1 %.2F Tf\n0 0 0 rg\n%.2F %.2F Td\n(%s) Tj\nET\n",
                $fontSize, $startX, $currentY, $escaped);
            $currentY -= $lineHeight;
        }

        return new SignatureAppearanceXObjectDto(
            stream: $stream,
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
    }

    /**
     * Creates a minimal valid PNG file representing what a user draws as signature.
     * Returns the temp file path (caller must unlink).
     */
    private function makeMinimalUserSignaturePng(): string
    {
        // 10×5 pixel image: white background with a black horizontal stroke in the center
        $gd = imagecreatetruecolor(10, 5);
        $white = imagecolorallocate($gd, 255, 255, 255);
        $black = imagecolorallocate($gd, 0, 0, 0);
        imagefill($gd, 0, 0, $white);
        // Draw a simple "stroke" — two horizontal lines representing a drawn signature
        imageline($gd, 1, 2, 8, 2, $black);
        imageline($gd, 2, 3, 7, 3, $black);

        $path = tempnam(sys_get_temp_dir(), 'pdfsignerphp-usersig-').'.png';
        imagepng($gd, $path);
        imagedestroy($gd);

        self::assertFileExists($path, 'Could not create user signature fixture PNG');

        return $path;
    }

    private function sign(SignatureAppearanceDto $appearance, string $reason): string
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
                actor: new SignatureActorDto(name: 'PdfSignerPHP Test'),
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
}
