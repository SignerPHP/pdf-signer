<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp;

use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\StrictDerReader;

/**
 * Strict DER primitives for OCSP structures received from the network. Built on
 * StrictDerReader (no BER: indefinite or non-minimal lengths, trailing bytes); every
 * violation throws UnexpectedValueException.
 *
 * @internal
 */
final class OcspDer
{
    public const SEQUENCE = 0x30;

    /**
     * The value of $der, which must be exactly one element with the given tag.
     */
    public static function expect(string $der, int $tag): string
    {
        [$actual, $value] = StrictDerReader::readExact($der);
        if ($actual !== $tag) {
            throw new \UnexpectedValueException(sprintf('Expected DER tag 0x%02X, found 0x%02X.', $tag, $actual));
        }

        return $value;
    }

    /**
     * The elements of the constructed value of $der, which must carry the given tag.
     *
     * @return list<array{0:int,1:string,2:string}> tag, value and full encoding of each element
     */
    public static function children(string $der, int $tag = self::SEQUENCE): array
    {
        return StrictDerReader::children(self::expect($der, $tag));
    }

    /**
     * Dotted form of an OBJECT IDENTIFIER element, rejecting non-minimal, unterminated and oversized arcs.
     */
    public static function oid(string $der): string
    {
        $value = self::expect($der, 0x06);
        if ($value === '' || (ord($value[strlen($value) - 1]) & 0x80) !== 0) {
            throw new \UnexpectedValueException('Unterminated OBJECT IDENTIFIER.');
        }

        $arcs = [];
        $arc = 0;
        $arcStart = true;
        foreach (str_split($value) as $byte) {
            $octet = ord($byte);
            if ($arcStart && $octet === 0x80) {
                throw new \UnexpectedValueException('Non-minimal OBJECT IDENTIFIER arc.');
            }
            if ($arc > (PHP_INT_MAX >> 7)) {
                throw new \UnexpectedValueException('OBJECT IDENTIFIER arc is too large.');
            }

            $arc = ($arc << 7) | ($octet & 0x7F);
            $arcStart = ($octet & 0x80) === 0;
            if ($arcStart) {
                $arcs[] = $arc;
                $arc = 0;
            }
        }

        $first = min(intdiv($arcs[0], 40), 2);

        return implode('.', [$first, $arcs[0] - 40 * $first, ...array_slice($arcs, 1)]);
    }

    /**
     * An INTEGER element, checked for minimal two's-complement encoding; returned as its full encoding.
     */
    public static function integer(string $der): string
    {
        $value = self::expect($der, 0x02);
        if ($value === ''
            || (strlen($value) > 1 && $value[0] === "\x00" && ord($value[1]) < 0x80)
            || (strlen($value) > 1 && $value[0] === "\xFF" && ord($value[1]) >= 0x80)) {
            throw new \UnexpectedValueException('Non-minimal INTEGER.');
        }

        return $der;
    }

    /**
     * A single-octet non-negative INTEGER or ENUMERATED value.
     */
    public static function smallNumber(string $der, int $tag): int
    {
        $value = self::expect($der, $tag);
        if (strlen($value) !== 1 || ord($value) >= 0x80) {
            throw new \UnexpectedValueException('Unsupported number.');
        }

        return ord($value);
    }

    /**
     * Unix time of a DER GeneralizedTime (UTC, "Z", no trailing zeros in the fraction).
     */
    public static function generalizedTime(string $der): int
    {
        $value = self::expect($der, 0x18);
        if (preg_match('/^(\d{14})(?:\.\d*[1-9])?Z$/', $value, $matches) !== 1) {
            throw new \UnexpectedValueException('Invalid GeneralizedTime.');
        }

        $time = \DateTimeImmutable::createFromFormat('!YmdHis', $matches[1], new \DateTimeZone('UTC'));
        if ($time === false || $time->format('YmdHis') !== $matches[1]) {
            throw new \UnexpectedValueException('Invalid GeneralizedTime.');
        }

        return $time->getTimestamp();
    }

    /**
     * RFC 5280 Extensions: OID => extnValue contents, rejecting duplicates and a DER-forbidden explicit FALSE.
     *
     * @return array<string, string>
     */
    public static function extensions(string $der): array
    {
        $extensions = [];
        foreach (self::children($der) as [, , $extension]) {
            $parts = self::children($extension);
            $critical = count($parts) === 3 ? array_splice($parts, 1, 1)[0] : null;
            if (count($parts) !== 2 || ($critical !== null && self::expect($critical[2], 0x01) !== "\xFF")) {
                throw new \UnexpectedValueException('Malformed extension.');
            }

            $oid = self::oid($parts[0][2]);
            if (isset($extensions[$oid])) {
                throw new \UnexpectedValueException('Duplicate extension.');
            }
            $extensions[$oid] = self::expect($parts[1][2], 0x04);
        }

        if ($extensions === []) {
            throw new \UnexpectedValueException('Empty extensions.');
        }

        return $extensions;
    }
}
