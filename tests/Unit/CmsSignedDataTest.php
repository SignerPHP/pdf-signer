<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Asn1Node;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignedData;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignerInfo;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Tests\Support\CmsTestFactory;

final class CmsSignedDataTest extends TestCase
{
    public function test_reads_the_structure_of_a_detached_signature(): void
    {
        $signedData = CmsSignedData::fromHex(str_pad(bin2hex(CmsTestFactory::sign('content')), 8192, '0'));

        self::assertSame('1.2.840.113549.1.7.1', $signedData->encapsulatedContentType);
        self::assertNull($signedData->encapsulatedContent);
        self::assertCount(1, $signedData->certificates);
        self::assertCount(1, $signedData->signerInfos);

        $signerInfo = $signedData->signerInfos[0];
        self::assertNotNull($signerInfo->issuerAndSerialNumber);
        self::assertNull($signerInfo->subjectKeyIdentifier);
        self::assertSame('2.16.840.1.101.3.4.2.1', $signerInfo->digestAlgorithm);
        self::assertSame("\x31", substr((string) $signerInfo->signedAttributesDer(), 0, 1));
        self::assertNull($signerInfo->signedAttribute('1.2.3.4'));
        self::assertSame([], $signerInfo->unsignedAttributes);
    }

    public function test_reads_attached_content_crls_and_unsigned_attributes(): void
    {
        $cms = CmsTestFactory::mapSignedDataFields(CmsTestFactory::sign('attached content', attached: true), static function (array $fields): array {
            // Insert an (empty) [1] crls set before signerInfos and an unsigned attribute in the SignerInfo.
            $signerInfos = array_pop($fields);
            $fields[] = Der::contextSpecific(1, '');
            $signerInfo = Asn1Node::read($signerInfos)->child(0);
            $unsigned = Der::contextSpecific(1, Der::sequence(Der::objectIdentifier('1.2.840.113549.1.9.16.2.14').Der::set(Der::null())));
            $fields[] = Der::set(Der::sequence($signerInfo->content.$unsigned));

            return $fields;
        });

        $signedData = CmsSignedData::fromDer($cms);

        self::assertSame('attached content', $signedData->encapsulatedContent);
        self::assertArrayHasKey('1.2.840.113549.1.9.16.2.14', $signedData->signerInfos[0]->unsignedAttributes);
    }

    public function test_skips_certificate_choices_that_are_not_x509_and_reencodes_ber_certificates(): void
    {
        $cms = CmsTestFactory::mapSignedDataFields(CmsTestFactory::sign('content'), static function (array $fields): array {
            $certificate = Asn1Node::read($fields[3])->child(0);
            $berCertificate = "\x30\x80".$certificate->content."\x00\x00";
            $fields[3] = Der::contextSpecific(0, Der::contextSpecific(2, 'attribute certificate').$berCertificate);

            return $fields;
        });

        $certificates = CmsSignedData::fromDer($cms)->certificates;

        self::assertCount(1, $certificates);
        self::assertNotFalse(openssl_x509_read("-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($certificates[0]), 64, "\n")."-----END CERTIFICATE-----\n"));
    }

    /**
     * @return array<string, array{0:\Closure(string): string, 1:string}>
     */
    public static function malformedSignedData(): array
    {
        return [
            'not a SignedData' => [
                static fn (string $cms): string => Der::sequence(Der::objectIdentifier('1.2.840.113549.1.7.1').Asn1Node::read($cms)->child(1)->encoded),
                'CMS ContentInfo is not a SignedData.',
            ],
            'no version' => [self::fields(static fn (array $f): array => []), 'SignedData has no version.'],
            'no digestAlgorithms' => [self::fields(static fn (array $f): array => [$f[0]]), 'SignedData has no digestAlgorithms.'],
            'no encapContentInfo' => [self::fields(static fn (array $f): array => [$f[0], $f[1]]), 'SignedData has no encapContentInfo.'],
            'no signerInfos' => [self::fields(static fn (array $f): array => [$f[0], $f[1], $f[2], $f[3]]), 'SignedData has no signerInfos.'],
            'trailing field' => [self::fields(static fn (array $f): array => [...$f, Der::null()]), 'Unexpected trailing fields in SignedData.'],
            'no SignerInfo version' => [self::signerInfo(static fn (array $f): array => []), 'SignerInfo has no version.'],
            'no sid' => [self::signerInfo(static fn (array $f): array => [$f[0]]), 'SignerInfo has no sid.'],
            'unknown sid' => [self::signerInfo(static fn (array $f): array => [$f[0], Der::null(), ...array_slice($f, 2)]), 'SignerInfo sid is neither issuerAndSerialNumber nor subjectKeyIdentifier.'],
            'no digestAlgorithm' => [self::signerInfo(static fn (array $f): array => [$f[0], $f[1]]), 'SignerInfo has no digestAlgorithm.'],
            'no signatureAlgorithm' => [self::signerInfo(static fn (array $f): array => [$f[0], $f[1], $f[2], $f[3]]), 'SignerInfo has no signatureAlgorithm.'],
            'no signature' => [self::signerInfo(static fn (array $f): array => [$f[0], $f[1], $f[2], $f[3], $f[4]]), 'SignerInfo has no signature.'],
            'trailing SignerInfo field' => [self::signerInfo(static fn (array $f): array => [...$f, Der::null()]), 'Unexpected trailing fields in SignerInfo.'],
            'duplicate attribute' => [
                self::signerInfo(static function (array $f): array {
                    $attributes = Asn1Node::read($f[3])->content;
                    $first = Asn1Node::read($attributes)->encoded;
                    $f[3] = Der::contextSpecific(0, $attributes.$first);

                    return $f;
                }),
                'Duplicate CMS attribute',
            ],
        ];
    }

    /**
     * @param  \Closure(string): string  $mutate
     */
    #[DataProvider('malformedSignedData')]
    public function test_rejects_malformed_structures(\Closure $mutate, string $message): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage($message);

        CmsSignedData::fromDer($mutate(CmsTestFactory::sign('content')));
    }

    public function test_rejects_empty_or_invalid_hex(): void
    {
        foreach (['', '00000000', 'ABC', 'XY'] as $hex) {
            try {
                CmsSignedData::fromHex($hex);
                self::fail('Accepted '.$hex);
            } catch (\UnexpectedValueException $exception) {
                self::assertSame('Empty or invalid CMS hex payload.', $exception->getMessage());
            }
        }
    }

    public function test_a_signed_attribute_with_several_values_is_rejected(): void
    {
        $cms = CmsTestFactory::mapFirstSignerInfoFields(CmsTestFactory::sign('content'), static function (array $fields): array {
            $fields[3] = Der::contextSpecific(0, Der::sequence(Der::objectIdentifier(CmsSignerInfo::OID_SIGNING_TIME).Der::set(Der::null().Der::null())));

            return $fields;
        });

        $this->expectExceptionMessage('must have exactly one value');

        CmsSignedData::fromDer($cms)->signerInfos[0]->signedAttribute(CmsSignerInfo::OID_SIGNING_TIME);
    }

    /**
     * @param  callable(list<string>): list<string>  $map
     * @return \Closure(string): string
     */
    private static function fields(callable $map): \Closure
    {
        return static fn (string $cms): string => CmsTestFactory::mapSignedDataFields($cms, $map);
    }

    /**
     * @param  callable(list<string>): list<string>  $map
     * @return \Closure(string): string
     */
    private static function signerInfo(callable $map): \Closure
    {
        return static fn (string $cms): string => CmsTestFactory::mapFirstSignerInfoFields($cms, $map);
    }
}
