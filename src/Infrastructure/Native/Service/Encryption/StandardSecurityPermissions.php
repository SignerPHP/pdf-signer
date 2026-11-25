<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

use SignerPHP\PdfSigner\Application\DTO\ProtectionOptionsDto;

/**
 * Builds the /P user access permission flags (ISO 32000-2 §7.6.4.2, table 22).
 */
final class StandardSecurityPermissions
{
    /** Bits 7, 8 and 13–32 are reserved and must be 1; bits 1–2 must be 0. */
    private const RESERVED = 0xFFFFF0C0;

    private const PRINT = 1 << 2;

    private const MODIFY = 1 << 3;

    private const COPY = 1 << 4;

    private const ANNOTATE = 1 << 5;

    private const FILL_FORMS = 1 << 8;

    private const ACCESSIBILITY = 1 << 9;

    private const ASSEMBLE = 1 << 10;

    private const PRINT_HIGH_QUALITY = 1 << 11;

    /**
     * Returns the flags as the signed 32-bit integer written in /P.
     */
    public static function fromOptions(ProtectionOptionsDto $options): int
    {
        $flags = self::RESERVED | self::ACCESSIBILITY;

        if ($options->allowPrint) {
            $flags |= self::PRINT | self::PRINT_HIGH_QUALITY;
        }

        if ($options->allowCopy) {
            $flags |= self::COPY;
        }

        if ($options->allowModify) {
            $flags |= self::MODIFY | self::ANNOTATE | self::FILL_FORMS | self::ASSEMBLE;
        }

        return $flags - 0x100000000;
    }
}
