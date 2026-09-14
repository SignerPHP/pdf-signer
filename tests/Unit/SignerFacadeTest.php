<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Presentation\PdfProtectionBuilder;
use SignerPHP\PdfSigner\Presentation\PdfSignatureValidatorBuilder;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\Presentation\SignerBuilder;
use SignerPHP\PdfSigner\Presentation\TimestampBuilder;

final class SignerFacadeTest extends TestCase
{
    public function test_facade_returns_builder(): void
    {
        $builder = Signer::signer();

        self::assertInstanceOf(SignerBuilder::class, $builder);
    }

    public function test_facade_returns_protection_builder(): void
    {
        $builder = Signer::protection();

        self::assertInstanceOf(PdfProtectionBuilder::class, $builder);
    }

    public function test_facade_returns_signature_validator_builder(): void
    {
        $builder = Signer::validation();

        self::assertInstanceOf(PdfSignatureValidatorBuilder::class, $builder);
    }

    public function test_facade_returns_timestamp_builder(): void
    {
        $builder = Signer::timestamp();

        self::assertInstanceOf(TimestampBuilder::class, $builder);
    }
}
