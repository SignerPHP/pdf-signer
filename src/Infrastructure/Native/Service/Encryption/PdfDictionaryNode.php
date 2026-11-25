<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

final class PdfDictionaryNode implements PdfNode
{
    /**
     * @param  list<array{0: string, 1: PdfNode}>  $entries  key (without the leading slash) and value pairs, in source order
     */
    public function __construct(private array $entries = []) {}

    /**
     * @return list<array{0: string, 1: PdfNode}>
     */
    public function entries(): array
    {
        return $this->entries;
    }

    public function get(string $key): ?PdfNode
    {
        foreach ($this->entries as [$entryKey, $value]) {
            if ($entryKey === $key) {
                return $value;
            }
        }

        return null;
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    public function set(string $key, PdfNode $value): self
    {
        foreach ($this->entries as $index => [$entryKey]) {
            if ($entryKey === $key) {
                $this->entries[$index] = [$key, $value];

                return $this;
            }
        }

        $this->entries[] = [$key, $value];

        return $this;
    }

    /**
     * Returns the token of a raw value (e.g. "/Sig", "12", "3 0 R"), or null when absent or not a raw token.
     */
    public function rawToken(string $key): ?string
    {
        $value = $this->get($key);

        return $value instanceof PdfRawNode ? $value->token : null;
    }
}
