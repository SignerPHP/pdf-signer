<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

/**
 * One BER/DER element. Reading accepts BER (indefinite lengths, constructed strings), as
 * CMS producers such as BouncyCastle stream it; every read is bounds-checked and malformed
 * input throws \UnexpectedValueException.
 */
final readonly class Asn1Node
{
    private const MAX_DEPTH = 64;

    public const TAG_INTEGER = 0x02;

    public const TAG_OCTET_STRING = 0x04;

    public const TAG_OID = 0x06;

    public const TAG_SEQUENCE = 0x30;

    public const TAG_SET = 0x31;

    /**
     * @param  string  $encoded  the full element (identifier, length and contents)
     * @param  string  $content  the contents octets, without the end-of-contents marker
     */
    private function __construct(
        public int $tag,
        public string $encoded,
        public string $content,
        public bool $indefiniteLength,
        private int $depth,
    ) {}

    /**
     * Reads the element at $offset. Bytes after it are ignored (PDF /Contents is zero-padded).
     */
    public static function read(string $data, int $offset = 0): self
    {
        return self::parse($data, $offset, 0);
    }

    /**
     * Reads one element that must span the whole input.
     */
    public static function readExact(string $data): self
    {
        $node = self::read($data);
        if (strlen($node->encoded) !== strlen($data)) {
            throw new \UnexpectedValueException('Trailing data after ASN.1 element.');
        }

        return $node;
    }

    public function isConstructed(): bool
    {
        return ($this->tag & 0x20) !== 0;
    }

    /**
     * @return list<self>
     */
    public function children(): array
    {
        if (! $this->isConstructed()) {
            throw new \UnexpectedValueException('ASN.1 element is not constructed.');
        }

        $children = [];
        $offset = 0;
        $length = strlen($this->content);
        while ($offset < $length) {
            $child = self::parse($this->content, $offset, $this->depth + 1);
            $children[] = $child;
            $offset += strlen($child->encoded);
        }

        return $children;
    }

    public function child(int $index, ?int $expectedTag = null): self
    {
        $child = $this->children()[$index] ?? throw new \UnexpectedValueException(sprintf('Missing ASN.1 element #%d.', $index));
        if ($expectedTag !== null) {
            $child->expectTag($expectedTag);
        }

        return $child;
    }

    public function expectTag(int $tag): self
    {
        if ($this->tag !== $tag) {
            throw new \UnexpectedValueException(sprintf('Unexpected ASN.1 tag 0x%02X, expected 0x%02X.', $this->tag, $tag));
        }

        return $this;
    }

    /**
     * Value of an OCTET STRING (or an implicitly tagged one), joining BER constructed segments.
     */
    public function octets(): string
    {
        if (! $this->isConstructed()) {
            return $this->content;
        }

        $value = '';
        foreach ($this->children() as $segment) {
            $value .= $segment->octets();
        }

        return $value;
    }

    /**
     * Dotted form of an OBJECT IDENTIFIER.
     */
    public function oid(): string
    {
        $this->expectTag(self::TAG_OID);
        $bytes = $this->content;
        if ($bytes === '' || (ord($bytes[strlen($bytes) - 1]) & 0x80) !== 0) {
            throw new \UnexpectedValueException('Malformed OBJECT IDENTIFIER.');
        }

        $arcs = [];
        $value = 0;
        $length = strlen($bytes);
        for ($i = 0; $i < $length; $i++) {
            if ($value > (PHP_INT_MAX >> 7)) {
                throw new \UnexpectedValueException('OBJECT IDENTIFIER arc is too large.');
            }
            $byte = ord($bytes[$i]);
            $value = ($value << 7) | ($byte & 0x7F);
            if (($byte & 0x80) === 0) {
                if ($arcs === []) {
                    $first = min(intdiv($value, 40), 2);
                    $arcs[] = $first;
                    $arcs[] = $value - 40 * $first;
                } else {
                    $arcs[] = $value;
                }
                $value = 0;
            }
        }

        return implode('.', $arcs);
    }

    /**
     * DER of this element with a different identifier octet, e.g. [0] IMPLICIT SET -> SET.
     * Indefinite-length input is re-encoded with a definite length.
     */
    public function withTag(int $tag): string
    {
        return Der::tlv($tag, $this->content);
    }

    private static function parse(string $data, int $offset, int $depth): self
    {
        if ($depth > self::MAX_DEPTH) {
            throw new \UnexpectedValueException('ASN.1 nesting is too deep.');
        }

        $total = strlen($data);
        if ($offset < 0 || $offset + 2 > $total) {
            throw new \UnexpectedValueException('Truncated ASN.1 element.');
        }

        $tag = ord($data[$offset]);
        if (($tag & 0x1F) === 0x1F) {
            throw new \UnexpectedValueException('High-tag-number ASN.1 identifiers are not supported.');
        }

        $position = $offset + 1;
        $first = ord($data[$position++]);

        if ($first === 0x80) {
            if (($tag & 0x20) === 0) {
                throw new \UnexpectedValueException('Indefinite length on a primitive ASN.1 element.');
            }

            $contentStart = $position;
            while (true) {
                if ($position + 2 > $total) {
                    throw new \UnexpectedValueException('Missing end-of-contents in indefinite-length element.');
                }
                if ($data[$position] === "\x00" && $data[$position + 1] === "\x00") {
                    break;
                }
                $position += strlen(self::parse($data, $position, $depth + 1)->encoded);
            }

            return new self(
                $tag,
                substr($data, $offset, $position + 2 - $offset),
                substr($data, $contentStart, $position - $contentStart),
                true,
                $depth,
            );
        }

        if (($first & 0x80) !== 0) {
            $count = $first & 0x7F;
            if ($count > 4) {
                throw new \UnexpectedValueException('Unsupported ASN.1 length.');
            }
            if ($position + $count > $total) {
                throw new \UnexpectedValueException('Truncated ASN.1 length.');
            }
            $length = 0;
            for ($i = 0; $i < $count; $i++) {
                $length = ($length << 8) | ord($data[$position + $i]);
            }
            $position += $count;
        } else {
            $length = $first;
        }

        if ($position + $length > $total) {
            throw new \UnexpectedValueException('ASN.1 element exceeds its container.');
        }

        return new self(
            $tag,
            substr($data, $offset, $position + $length - $offset),
            substr($data, $position, $length),
            false,
            $depth,
        );
    }
}
