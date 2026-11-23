<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\IcpBrasilPadesPolicy;
use SignerPHP\PdfSigner\Application\DTO\SignaturePolicyIdentifierDto;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;

/**
 * The fixtures in tests/Fixtures/icp-brasil are unmodified copies of the official files:
 *   https://politicas.icpbrasil.gov.br/LPA_PAdES.der
 *   http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_3.der
 *   http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RT_v1_3.der
 */
final class SignaturePolicyIdentifierDtoTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../Fixtures/icp-brasil/';

    public function test_digest_is_the_sha256_of_the_official_policy_document(): void
    {
        foreach (IcpBrasilPadesPolicy::cases() as $policy) {
            $document = (string) file_get_contents(self::FIXTURES.basename($policy->uri()));

            self::assertSame(hash('sha256', $document), $policy->sha256DigestHex(), $policy->name);
            self::assertStringContainsString(Der::objectIdentifier($policy->value), $document, $policy->name.' document declares its own OID');
        }
    }

    public function test_policy_matches_an_unrevoked_entry_of_the_official_policy_list(): void
    {
        $lpa = (string) file_get_contents(self::FIXTURES.'LPA_PAdES.der');

        foreach (IcpBrasilPadesPolicy::cases() as $policy) {
            // PolicyInfo ::= SEQUENCE { signingPeriod, revocationDate GeneralizedTime OPTIONAL, policyOID, policyURI, policyDigest }
            $oidAndUri = Der::objectIdentifier($policy->value).Der::tlv(0x16, $policy->uri());
            $position = strpos($lpa, $oidAndUri);
            self::assertNotFalse($position, $policy->name.' OID and URI are listed together in the LPA');

            $digest = Der::sequence(
                Der::algorithmIdentifier('2.16.840.1.101.3.4.2.1', withNullParameters: false)
                .Der::octetString((string) hex2bin($policy->sha256DigestHex()))
            );
            self::assertSame($digest, substr($lpa, $position + strlen($oidAndUri), strlen($digest)), $policy->name.' digest follows its URI in the LPA');

            // Without revocationDate the 34-byte signingPeriod SEQUENCE (two GeneralizedTimes) sits right before the OID.
            self::assertSame("\x30\x22", substr($lpa, $position - 36, 2), $policy->name.' has no revocation date in the LPA');
        }
    }

    public function test_only_ad_rt_requires_a_signature_timestamp(): void
    {
        self::assertFalse(IcpBrasilPadesPolicy::AdRbV1_3->toIdentifier()->requiresSignatureTimestamp);
        self::assertTrue(IcpBrasilPadesPolicy::AdRtV1_3->toIdentifier()->requiresSignatureTimestamp);
        self::assertSame(HashAlgorithm::Sha256, IcpBrasilPadesPolicy::AdRtV1_3->toIdentifier()->hashAlgorithm);
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
