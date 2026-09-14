<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\Application\DTO\SignatureMetadataDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto as NewSignatureMetadataDto;
use SignerPHP\PdfSigner\Presentation\SignerBuilder as NewSignerBuilder;
use SignerPHP\Presentation\Signer;

final class PublicApiCompatibilityTest extends TestCase
{
    public function test_documented_facade_alias_still_builds_the_signer(): void
    {
        self::assertTrue(class_exists(Signer::class));
        self::assertInstanceOf(NewSignerBuilder::class, Signer::signer());
    }

    public function test_documented_dto_alias_constructs_the_pdf_signer_type(): void
    {
        $metadata = new SignatureMetadataDto(reason: 'signed');

        self::assertInstanceOf(NewSignatureMetadataDto::class, $metadata);
        self::assertSame('signed', $metadata->reason);
    }
}
