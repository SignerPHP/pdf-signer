<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeRfc3161TimestampTokenValidator;
use SignerPHP\PdfSigner\Tests\Support\CmsTestFactory;

/**
 * Isolates TSTInfo parsing: each crafted TSTInfo is wrapped in a validly signed CMS.
 * NativeRfc3161TimestampTokenValidatorTest uses tokens issued by a real TSA.
 */
final class NativeRfc3161TstInfoTest extends TestCase
{
    public static function tstInfoCases(): iterable
    {
        yield 'SHA-1 imprint' => ['sha1', true];
        yield 'SHA-224 imprint' => ['sha224', true];
        yield 'SHA-256 imprint' => ['sha256', true];
        yield 'SHA-384 imprint' => ['sha384', true];
        yield 'SHA-512 imprint' => ['sha512', true];
        yield 'unknown digest algorithm' => ['unknown-alg', false];
        yield 'wrong message digest' => ['wrong-digest', false];
        yield 'non-sequence TSTInfo' => ['not-sequence', false];
        yield 'wrong version tag' => ['bad-version', false];
        yield 'wrong policy tag' => ['bad-policy', false];
        yield 'wrong imprint tag' => ['bad-imprint', false];
        yield 'wrong algorithm tag' => ['bad-algorithm', false];
        yield 'wrong digest tag' => ['bad-digest-tag', false];
        yield 'wrong hash OID tag' => ['bad-oid-tag', false];
    }

    #[DataProvider('tstInfoCases')]
    public function test_decoded_tstinfo_is_checked_before_acceptance(string $scenario, bool $valid): void
    {
        $signature = 'signature-bytes';
        $tstInfo = self::tstInfo($scenario, $signature);
        // A real signature over the crafted TSTInfo, so only the TSTInfo checks can fail.
        $token = CmsTestFactory::sign($tstInfo, attached: true);

        if (! $valid) {
            $this->expectException(SignProcessException::class);
            $this->expectExceptionMessage('message imprint mismatch or invalid TSTInfo');
        }

        (new NativeRfc3161TimestampTokenValidator)->assertValid($token, $signature);

        if ($valid) {
            self::assertTrue(true);
        }
    }

    private static function tstInfo(string $scenario, string $signature): string
    {
        if ($scenario === 'not-sequence') {
            return Der::octetString('not a TSTInfo');
        }

        $hashAlgorithm = match ($scenario) {
            'sha1' => 'sha1',
            'sha224' => 'sha224',
            'sha384' => 'sha384',
            'sha512' => 'sha512',
            default => 'sha256',
        };
        $hashOid = match ($scenario) {
            'sha1' => '1.3.14.3.2.26',
            'sha224' => '2.16.840.1.101.3.4.2.4',
            'sha384' => '2.16.840.1.101.3.4.2.2',
            'sha512' => '2.16.840.1.101.3.4.2.3',
            'unknown-alg' => '1.2.3.4.5',
            default => '2.16.840.1.101.3.4.2.1',
        };
        $algorithm = match ($scenario) {
            'bad-algorithm' => Der::octetString(Der::objectIdentifier($hashOid)),
            'bad-oid-tag' => Der::sequence(Der::octetString('not an OID')),
            default => Der::algorithmIdentifier($hashOid),
        };
        $digest = hash($hashAlgorithm, $scenario === 'wrong-digest' ? 'other-signature' : $signature, true);
        $digestField = $scenario === 'bad-digest-tag' ? Der::tlv(0x16, $digest) : Der::octetString($digest);
        $imprint = $scenario === 'bad-imprint'
            ? Der::octetString($algorithm.$digestField)
            : Der::sequence($algorithm.$digestField);

        return Der::sequence(
            ($scenario === 'bad-version' ? Der::octetString(chr(1)) : Der::tlv(0x02, chr(1)))
            .($scenario === 'bad-policy' ? Der::octetString('bad policy') : Der::objectIdentifier('1.2.3.4'))
            .$imprint
            .Der::tlv(0x02, chr(2))
            .Der::tlv(0x18, '20261123230000Z')
        );
    }
}
