<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimestampTokenProviderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\DocumentTimestampApplier;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;

final class DocumentTimestampApplierFlowTest extends TestCase
{
    public function test_apply_appends_doc_timestamp_when_token_provider_returns_hex(): void
    {
        $input = PdfFixtureFactory::minimalPdf();

        $provider = new class implements TimestampTokenProviderInterface
        {
            public array $receivedByteRange = [];

            public string $receivedSignableDocument = '';

            public string $receivedHashAlgorithm = '';

            public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string
            {
                $this->receivedByteRange = $byteRange;
                $this->receivedSignableDocument = $signableDocument;
                $this->receivedHashAlgorithm = $options->hashAlgorithm->value;

                return 'A1B2C3';
            }
        };

        $result = (new DocumentTimestampApplier(timestampTokenProvider: $provider))->apply(
            $input,
            new TimestampOptionsDto(tsaUrl: 'https://tsa.local')
        );

        self::assertNotSame($input, $result);
        self::assertStringContainsString('/DocTimeStamp', $result);
        self::assertCount(4, $provider->receivedByteRange);
        self::assertNotSame('', $provider->receivedSignableDocument);
        self::assertSame('sha256', $provider->receivedHashAlgorithm);
    }

    public function test_timestamped_bytes_are_exactly_the_byte_range_of_the_final_document(): void
    {
        $input = PdfFixtureFactory::minimalPdf();

        $provider = new class implements TimestampTokenProviderInterface
        {
            public string $timestampedBytes = '';

            public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string
            {
                [$offset1, $length1, $offset2, $length2] = $byteRange;
                $this->timestampedBytes = substr($signableDocument, $offset1, $length1).substr($signableDocument, $offset2, $length2);

                return 'A1B2C3';
            }
        };

        $result = (new DocumentTimestampApplier(timestampTokenProvider: $provider))->apply(
            $input,
            new TimestampOptionsDto(tsaUrl: 'https://tsa.local')
        );

        $matches = [];
        preg_match_all('/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/', $result, $matches, PREG_SET_ORDER);
        $last = end($matches);
        self::assertIsArray($last);
        [, $offset1, $length1, $offset2, $length2] = array_map('intval', $last);

        $covered = substr($result, $offset1, $length1).substr($result, $offset2, $length2);
        self::assertSame(strlen($result), $offset2 + $length2, 'the ByteRange must reach the end of the file');
        self::assertSame(hash('sha256', $covered), hash('sha256', $provider->timestampedBytes));
    }

    public function test_apply_throws_when_provider_returns_non_hex_token(): void
    {
        $input = PdfFixtureFactory::minimalPdf();

        $provider = new class implements TimestampTokenProviderInterface
        {
            public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string
            {
                return 'NOT-HEX';
            }
        };

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('RFC3161 timestamp token is not valid hex.');

        (new DocumentTimestampApplier(timestampTokenProvider: $provider))->apply(
            $input,
            new TimestampOptionsDto(tsaUrl: 'https://tsa.local')
        );
    }
}
