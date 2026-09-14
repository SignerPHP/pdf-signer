<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

final class Der
{
    public static function sequence(string $contents): string
    {
        return self::tlv(0x30, $contents);
    }

    public static function set(string $contents): string
    {
        return self::tlv(0x31, $contents);
    }

    public static function octetString(string $bytes): string
    {
        return self::tlv(0x04, $bytes);
    }

    public static function null(): string
    {
        return "\x05\x00";
    }

    public static function utcTime(\DateTimeInterface $time): string
    {
        return self::tlv(0x17, $time->setTimezone(new \DateTimeZone('UTC'))->format('ymdHis').'Z');
    }

    public static function objectIdentifier(string|array $oid): string
    {
        $parts = is_array($oid)
            ? array_values($oid)
            : array_map(static fn (string $part): int => (int) $part, explode('.', $oid));
        if (count($parts) < 2) {
            throw new \InvalidArgumentException('OID must have at least two arcs.');
        }

        $bytes = chr(40 * $parts[0] + $parts[1]);
        $count = count($parts);
        for ($i = 2; $i < $count; $i++) {
            $value = $parts[$i];
            $encoded = chr($value & 0x7F);
            $value >>= 7;
            while ($value > 0) {
                $encoded = chr(0x80 | ($value & 0x7F)).$encoded;
                $value >>= 7;
            }
            $bytes .= $encoded;
        }

        return self::tlv(0x06, $bytes);
    }

    public static function algorithmIdentifier(string|array $oid, bool $withNullParameters = true): string
    {
        return self::sequence(self::objectIdentifier($oid).($withNullParameters ? self::null() : ''));
    }

    public static function contextSpecific(int $tag, string $contents, bool $constructed = true): string
    {
        $classTag = 0x80 | ($constructed ? 0x20 : 0) | $tag;

        return self::tlv($classTag, $contents);
    }

    public static function tlv(int $tag, string $value): string
    {
        return chr($tag).self::length(strlen($value)).$value;
    }

    public static function length(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)).$bytes;
    }

    /**
     * @return array{0: int, 1: string, 2: int} tag, value, next offset
     */
    public static function readTlv(string $der, int $offset = 0): array
    {
        $tag = ord($der[$offset]);
        $offset++;
        $first = ord($der[$offset]);
        $offset++;
        if (($first & 0x80) === 0) {
            $length = $first;
        } else {
            $count = $first & 0x7F;
            $length = unpack('N', str_pad(substr($der, $offset, $count), 4, "\x00", STR_PAD_LEFT))[1];
            $offset += $count;
        }

        return [$tag, substr($der, $offset, $length), $offset + $length];
    }
}
