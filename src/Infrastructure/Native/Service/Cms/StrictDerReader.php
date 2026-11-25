<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

/**
 * Reads DER (X.690 §10) and refuses anything that is only valid BER: indefinite lengths,
 * non-minimal length encodings, high-tag-number tags, elements running past their container
 * and trailing bytes after a complete element. Every violation throws UnexpectedValueException.
 */
final class StrictDerReader
{
    /**
     * Reads the single element that must span all of $der.
     *
     * @return array{0:int,1:string} tag, value
     */
    public static function readExact(string $der): array
    {
        [$tag, $value, $next] = self::read($der);
        if ($next !== strlen($der)) {
            throw new \UnexpectedValueException('Trailing bytes after DER element.');
        }

        return [$tag, $value];
    }

    /**
     * Reads the consecutive elements that must fill all of $contents (a constructed value).
     *
     * @return list<array{0:int,1:string,2:string}> tag, value and the element's full encoding
     */
    public static function children(string $contents): array
    {
        $children = [];
        $offset = 0;
        while ($offset < strlen($contents)) {
            [$tag, $value, $next] = self::read($contents, $offset);
            $children[] = [$tag, $value, substr($contents, $offset, $next - $offset)];
            $offset = $next;
        }

        return $children;
    }

    /**
     * @return array{0:int,1:string,2:int} tag, value, offset after the element
     */
    public static function read(string $der, int $offset = 0): array
    {
        $size = strlen($der);
        if ($offset + 2 > $size) {
            throw new \UnexpectedValueException('Truncated DER element.');
        }

        $tag = ord($der[$offset]);
        if (($tag & 0x1F) === 0x1F) {
            throw new \UnexpectedValueException('Unsupported DER high-tag-number form.');
        }

        $first = ord($der[$offset + 1]);
        $offset += 2;
        if ($first < 0x80) {
            $length = $first;
        } else {
            $count = $first & 0x7F;
            if ($count === 0) {
                throw new \UnexpectedValueException('Indefinite length is not allowed in DER.');
            }
            if ($count > 4) {
                throw new \UnexpectedValueException('Unsupported DER length.');
            }
            if ($offset + $count > $size) {
                throw new \UnexpectedValueException('Truncated DER length.');
            }

            $lengthBytes = substr($der, $offset, $count);
            $length = (int) hexdec(bin2hex($lengthBytes));
            if ($lengthBytes[0] === "\x00" || $length < 0x80) {
                throw new \UnexpectedValueException('Non-minimal DER length.');
            }
            $offset += $count;
        }

        if ($length > $size - $offset) {
            throw new \UnexpectedValueException('DER value exceeds its container.');
        }

        return [$tag, substr($der, $offset, $length), $offset + $length];
    }
}
