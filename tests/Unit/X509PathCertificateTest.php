<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\X509PathCertificate;

/**
 * DER decoding of the fields used by path validation, on hand-built certificates (the signature
 * value is irrelevant to decoding).
 */
final class X509PathCertificateTest extends TestCase
{
    public function test_decodes_the_path_validation_fields(): void
    {
        $certificate = X509PathCertificate::fromDer(self::certificate(extensions: [
            self::extension('2.5.29.19', Der::sequence("\x01\x01\xFF\x02\x01\x03"), critical: true),
            self::extension('2.5.29.15', "\x03\x02\x01\x06", critical: true),
            self::extension('2.5.29.14', Der::octetString('ski')),
            self::extension('2.5.29.35', Der::sequence("\xA2\x00\x80\x03aki")),
            self::extension('2.5.29.32', Der::sequence(''), critical: true),
            self::extension('2.999.7', Der::null(), critical: true),
            self::extension('1.2.3', Der::null(), critical: false, explicitFalse: true),
        ]));

        self::assertNotNull($certificate);
        self::assertSame(3, $certificate->version);
        self::assertTrue($certificate->isCa);
        self::assertSame(3, $certificate->pathLength);
        self::assertTrue($certificate->keyCertSign);
        self::assertSame('ski', $certificate->subjectKeyIdentifier);
        self::assertSame('aki', $certificate->authorityKeyIdentifier);
        self::assertSame(['2.999.7'], $certificate->unrecognizedCriticalExtensions);
        self::assertSame(gmmktime(0, 0, 0, 1, 1, 1999), $certificate->notBefore);
        self::assertSame(gmmktime(12, 30, 0, 6, 1, 2051), $certificate->notAfter);
        self::assertTrue($certificate->isSelfIssued());
    }

    public function test_defaults_when_extensions_are_absent_or_minimal(): void
    {
        $certificate = X509PathCertificate::fromDer(self::certificate(version: null, extensions: [
            self::extension('2.5.29.19', Der::sequence('')),
            self::extension('2.5.29.15', "\x03\x02\x07\x80"),
            self::extension('2.5.29.35', Der::sequence("\x81\x00")),
        ], issuer: 'Other'));

        self::assertNotNull($certificate);
        self::assertSame(1, $certificate->version);
        self::assertFalse($certificate->isCa);
        self::assertNull($certificate->pathLength);
        self::assertFalse($certificate->keyCertSign);
        self::assertNull($certificate->subjectKeyIdentifier);
        self::assertNull($certificate->authorityKeyIdentifier);
        self::assertFalse($certificate->isSelfIssued());
        self::assertSame('/CN=Test', $certificate->subjectName());
    }

    public function test_subject_name_falls_back_when_openssl_cannot_parse_the_certificate(): void
    {
        $certificate = new X509PathCertificate('', 'not a certificate', 3, '', '', '', 0, 0, null, null, null, null, null, []);

        self::assertSame('(unnamed certificate)', $certificate->subjectName());
    }

    #[DataProvider('malformedCertificates')]
    public function test_rejects_malformed_certificates(string $der): void
    {
        self::assertNull(X509PathCertificate::fromDer($der));
    }

    /** @return array<string, array{string}> */
    public static function malformedCertificates(): array
    {
        $valid = self::certificate();

        return [
            'empty' => [''],
            'not a sequence' => ["\x04\x00"],
            'trailing bytes' => [$valid."\x00"],
            'truncated' => [substr($valid, 0, -3)],
            'tbs not a sequence' => [Der::sequence(Der::octetString('x'))],
            'serial not an integer' => [self::certificate(serial: Der::octetString("\x01"))],
            'bad UTCTime' => [self::certificate(notBefore: Der::tlv(0x17, '99010100000Z'))],
            'unknown time type' => [self::certificate(notAfter: Der::tlv(0x04, '20510601123000Z'))],
            'extension without OID' => [self::certificate(extensions: [Der::sequence(Der::octetString('x'))])],
            'extension value not an OCTET STRING' => [self::certificate(extensions: [Der::sequence(Der::objectIdentifier('2.5.29.15').Der::null())])],
            'keyUsage not a BIT STRING' => [self::certificate(extensions: [self::extension('2.5.29.15', Der::null())])],
            'malformed basicConstraints' => [self::certificate(extensions: [self::extension('2.5.29.19', "\x30\x05")])],
        ];
    }

    /**
     * @param  list<string>  $extensions
     */
    private static function certificate(
        ?int $version = 2,
        ?string $serial = null,
        ?string $notBefore = null,
        ?string $notAfter = null,
        array $extensions = [],
        string $issuer = 'Test',
    ): string {
        $name = static fn (string $cn): string => Der::sequence(Der::set(Der::sequence(Der::objectIdentifier('2.5.4.3').Der::tlv(0x0C, $cn))));
        $tbs = ($version !== null ? Der::contextSpecific(0, Der::tlv(0x02, chr($version))) : '')
            .($serial ?? Der::tlv(0x02, "\x01"))
            .Der::algorithmIdentifier('1.2.840.113549.1.1.11')
            .$name($issuer)
            .Der::sequence(($notBefore ?? Der::tlv(0x17, '990101000000Z')).($notAfter ?? Der::tlv(0x18, '20510601123000.5Z')))
            .$name('Test')
            .Der::sequence(Der::algorithmIdentifier('1.2.840.113549.1.1.1').Der::tlv(0x03, "\x00\x01"))
            .($extensions !== [] ? Der::contextSpecific(3, Der::sequence(implode('', $extensions))) : '');

        return Der::sequence(Der::sequence($tbs).Der::algorithmIdentifier('1.2.840.113549.1.1.11').Der::tlv(0x03, "\x00\x00"));
    }

    private static function extension(string $oid, string $value, bool $critical = false, bool $explicitFalse = false): string
    {
        $flag = $critical ? "\x01\x01\xFF" : ($explicitFalse ? "\x01\x01\x00" : '');

        return Der::sequence(Der::objectIdentifier($oid).$flag.Der::octetString($value));
    }
}
