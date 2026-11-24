<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;

final class DerTest extends TestCase
{
    public function test_object_identifier_rejects_oid_with_fewer_than_two_arcs(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('OID must have at least two arcs.');

        Der::objectIdentifier('1');
    }

    /**
     * @return array<string, array{0:string, 1:int, 2:string}>
     */
    public static function malformedDer(): array
    {
        return [
            'offset past the end' => ["\x30", 0, 'Truncated DER.'],
            'more than four length bytes' => ["\x30\x85\x00\x00\x00\x00\x01", 0, 'Unsupported DER length.'],
            'length bytes cut short' => ["\x30\x82\x01", 0, 'Truncated DER length.'],
            'value longer than its container' => ["\x30\x05\x02\x01\x00", 0, 'DER value exceeds its container.'],
            'nested value past the end' => ["\x02\x01\x00\x30\x04", 3, 'DER value exceeds its container.'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('malformedDer')]
    public function test_read_tlv_strict_rejects_malformed_input(string $der, int $offset, string $message): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage($message);

        Der::readTlvStrict($der, $offset);
    }

    public function test_read_tlv_strict_reads_a_complete_value(): void
    {
        self::assertSame([0x02, "\x05", 5], Der::readTlvStrict("\x30\x00\x02\x01\x05", 2));
    }
}
