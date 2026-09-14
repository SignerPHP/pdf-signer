<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\Presentation\SignerBuilder;

final class PublicApiTest extends TestCase
{
    public function test_documented_facade_builds_the_signer(): void
    {
        self::assertInstanceOf(SignerBuilder::class, Signer::signer());
    }

    public function test_documented_dto_is_the_pdf_signer_type(): void
    {
        $metadata = new SignatureMetadataDto(reason: 'signed');

        self::assertSame('signed', $metadata->reason);
    }
}
