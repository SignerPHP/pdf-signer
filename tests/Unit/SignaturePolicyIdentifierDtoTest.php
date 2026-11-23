<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\IcpBrasilPadesPolicy;
use SignerPHP\PdfSigner\Application\DTO\SignaturePolicyIdentifierDto;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;

final class SignaturePolicyIdentifierDtoTest extends TestCase
{
    public function test_icp_brasil_policies_match_the_official_policy_list(): void
    {
        $expected = [
            'AdRbV1_3' => ['2.16.76.1.7.1.11.1.3', 'PA_PAdES_AD_RB_v1_3.der'],
            'AdRtV1_3' => ['2.16.76.1.7.1.12.1.3', 'PA_PAdES_AD_RT_v1_3.der'],
            'AdRcV1_4' => ['2.16.76.1.7.1.13.1.4', 'PA_PAdES_AD_RC_v1_4.der'],
            'AdRaV1_4' => ['2.16.76.1.7.1.14.1.4', 'PA_PAdES_AD_RA_v1_4.der'],
        ];

        foreach (IcpBrasilPadesPolicy::cases() as $policy) {
            $identifier = $policy->toIdentifier();
            self::assertSame($expected[$policy->name][0], $identifier->oid);
            self::assertSame('http://politicas.icpbrasil.gov.br/'.$expected[$policy->name][1], $identifier->uri);
            self::assertSame(HashAlgorithm::Sha256, $identifier->hashAlgorithm);
            self::assertSame(32, strlen($identifier->digest));
        }
    }

    public function test_rejects_an_invalid_oid(): void
    {
        $this->expectException(SignerException::class);
        $this->expectExceptionMessage('Invalid signature policy OID');

        new SignaturePolicyIdentifierDto('2.16.x', str_repeat("\0", 32));
    }

    public function test_rejects_a_digest_that_does_not_match_the_hash_algorithm(): void
    {
        $this->expectException(SignerException::class);
        $this->expectExceptionMessage('must have 48 bytes for sha384');

        new SignaturePolicyIdentifierDto('1.2.3.4', str_repeat("\0", 32), HashAlgorithm::Sha384);
    }

    public function test_from_hex_rejects_non_hex_digests(): void
    {
        $this->expectException(SignerException::class);
        $this->expectExceptionMessage('hexadecimal');

        SignaturePolicyIdentifierDto::fromHex('1.2.3.4', 'zz');
    }

    public function test_rejects_a_non_ascii_uri(): void
    {
        $this->expectException(SignerException::class);

        new SignaturePolicyIdentifierDto('1.2.3.4', str_repeat("\0", 32), uri: 'https://exemplo.br/política');
    }
}
