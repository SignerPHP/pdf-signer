<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;

/**
 * Minimal PDF object syntax parser (ISO 32000-1 §7.2–§7.3).
 *
 * Unlike a general purpose parser it keeps every token needed to write the object back
 * and decodes strings to raw bytes, which is what the encryption step needs.
 */
final class PdfSyntaxParser
{
    private const WHITESPACE = "\0\t\n\f\r ";

    private const DELIMITERS = '()<>[]{}/%';

    private const OCTAL_DIGITS = '01234567';

    private readonly int $length;

    public function __construct(private readonly string $data, private int $position = 0)
    {
        $this->length = strlen($data);
    }

    public function position(): int
    {
        return $this->position;
    }

    public function skipWhitespaceAndComments(): void
    {
        while ($this->position < $this->length) {
            $char = $this->data[$this->position];

            if (str_contains(self::WHITESPACE, $char)) {
                $this->position++;

                continue;
            }

            if ($char === '%') {
                $this->position += strcspn($this->data, "\r\n", $this->position);

                continue;
            }

            break;
        }
    }

    /**
     * Reads the next regular token (number or keyword), or returns null when the next token is a delimiter or EOF.
     */
    public function readKeyword(): ?string
    {
        $this->skipWhitespaceAndComments();
        $token = $this->regularTokenAt($this->position);
        if ($token === '') {
            return null;
        }

        $this->position += strlen($token);

        return $token;
    }

    /**
     * Reads an indirect object header ("12 0 obj") and returns its object and generation numbers.
     *
     * @return array{0: int, 1: int}|null
     */
    public function readObjectHeader(): ?array
    {
        $start = $this->position;
        $objectNumber = $this->readKeyword();
        $generation = $this->readKeyword();
        $keyword = $this->readKeyword();

        if ($objectNumber === null || $generation === null || $keyword !== 'obj'
            || ! ctype_digit($objectNumber) || ! ctype_digit($generation)) {
            $this->position = $start;

            return null;
        }

        return [(int) $objectNumber, (int) $generation];
    }

    public function parseValue(): PdfNode
    {
        $this->skipWhitespaceAndComments();

        if ($this->position >= $this->length) {
            throw new ProtectionProcessException('Unexpected end of PDF data while parsing an object.');
        }

        if (substr($this->data, $this->position, 2) === '<<') {
            return $this->parseDictionary();
        }

        $char = $this->data[$this->position];

        return match ($char) {
            '[' => $this->parseArray(),
            '(' => new PdfStringNode($this->parseLiteralString()),
            '<' => new PdfStringNode($this->parseHexString()),
            '/' => new PdfRawNode($this->parseName()),
            '{', '}' => $this->parseSingleCharacter($char),
            ')', '>', ']' => throw new ProtectionProcessException(sprintf('Unexpected "%s" in PDF object at offset %d.', $char, $this->position)),
            default => $this->parseAtom(),
        };
    }

    private function parseSingleCharacter(string $char): PdfRawNode
    {
        $this->position++;

        return new PdfRawNode($char);
    }

    private function parseDictionary(): PdfDictionaryNode
    {
        $this->position += 2;
        $entries = [];

        while (true) {
            $this->skipWhitespaceAndComments();

            if ($this->position >= $this->length) {
                throw new ProtectionProcessException('Unterminated dictionary in PDF object.');
            }

            if (substr($this->data, $this->position, 2) === '>>') {
                $this->position += 2;

                return new PdfDictionaryNode($entries);
            }

            if ($this->data[$this->position] !== '/') {
                throw new ProtectionProcessException(sprintf('Invalid dictionary key in PDF object at offset %d.', $this->position));
            }

            $key = substr($this->parseName(), 1);
            $entries[] = [$key, $this->parseValue()];
        }
    }

    private function parseArray(): PdfArrayNode
    {
        $this->position++;
        $items = [];

        while (true) {
            $this->skipWhitespaceAndComments();

            if ($this->position >= $this->length) {
                throw new ProtectionProcessException('Unterminated array in PDF object.');
            }

            if ($this->data[$this->position] === ']') {
                $this->position++;

                return new PdfArrayNode($items);
            }

            $items[] = $this->parseValue();
        }
    }

    private function parseName(): string
    {
        $name = '/'.$this->regularTokenAt($this->position + 1);
        $this->position += strlen($name);

        return $name;
    }

    private function parseAtom(): PdfRawNode
    {
        $token = (string) $this->readKeyword();

        if (ctype_digit($token)) {
            $afterNumber = $this->position;
            $generation = $this->readKeyword();
            if ($generation !== null && ctype_digit($generation) && $this->readKeyword() === 'R') {
                return new PdfRawNode($token.' '.$generation.' R');
            }

            $this->position = $afterNumber;
        }

        return new PdfRawNode($token);
    }

    private function parseLiteralString(): string
    {
        $this->position++;
        $depth = 1;
        $bytes = '';

        while ($this->position < $this->length) {
            $char = $this->data[$this->position++];

            if ($char === '\\') {
                $bytes .= $this->parseEscapeSequence();

                continue;
            }

            if ($char === '(') {
                $depth++;
            } elseif ($char === ')') {
                $depth--;
                if ($depth === 0) {
                    return $bytes;
                }
            } elseif ($char === "\r") {
                // §7.3.4.2: an unescaped end-of-line marker is read as a single line feed.
                if (($this->data[$this->position] ?? '') === "\n") {
                    $this->position++;
                }
                $char = "\n";
            }

            $bytes .= $char;
        }

        throw new ProtectionProcessException('Unterminated literal string in PDF object.');
    }

    private function parseEscapeSequence(): string
    {
        $char = $this->data[$this->position++] ?? '';

        switch ($char) {
            case 'n':
                return "\n";
            case 'r':
                return "\r";
            case 't':
                return "\t";
            case 'b':
                return "\x08";
            case 'f':
                return "\f";
            case "\r":
                if (($this->data[$this->position] ?? '') === "\n") {
                    $this->position++;
                }

                return '';
            case "\n":
                return '';
        }

        if ($char !== '' && str_contains(self::OCTAL_DIGITS, $char)) {
            $octal = $char;
            while (strlen($octal) < 3 && $this->position < $this->length
                && str_contains(self::OCTAL_DIGITS, $this->data[$this->position])) {
                $octal .= $this->data[$this->position++];
            }

            return chr((int) octdec($octal) & 0xFF);
        }

        // "\(", "\)", "\\" and unknown escapes: the backslash is ignored.
        return $char;
    }

    private function parseHexString(): string
    {
        $end = strpos($this->data, '>', $this->position);
        if ($end === false) {
            throw new ProtectionProcessException('Unterminated hexadecimal string in PDF object.');
        }

        $hex = (string) preg_replace('/[\0\t\n\f\r ]+/', '', substr($this->data, $this->position + 1, $end - $this->position - 1));
        $this->position = $end + 1;

        if ($hex !== '' && ! ctype_xdigit($hex)) {
            throw new ProtectionProcessException('Invalid hexadecimal string in PDF object.');
        }

        if (strlen($hex) % 2 === 1) {
            $hex .= '0';
        }

        return (string) hex2bin($hex);
    }

    private function regularTokenAt(int $offset): string
    {
        if ($offset >= $this->length) {
            return '';
        }

        return substr($this->data, $offset, strcspn($this->data, self::WHITESPACE.self::DELIMITERS, $offset));
    }
}
