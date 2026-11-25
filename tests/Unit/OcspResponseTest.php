<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspRequest;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspResponse;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspSingleResponse;
use SignerPHP\PdfSigner\Tests\Support\OcspTestPki;

final class OcspResponseTest extends TestCase
{
    private const BASIC = '1.3.6.1.5.5.7.48.1.1';

    public function test_parses_every_field_of_a_basic_response(): void
    {
        $revoked = Der::contextSpecific(1, self::time('20261120100000Z').Der::contextSpecific(0, Der::tlv(0x0A, "\x01")));
        $tbs = Der::sequence(
            Der::contextSpecific(0, Der::tlv(0x02, "\x00"))
            .Der::contextSpecific(2, Der::octetString(str_repeat("\x01", 20)))
            .self::time('20261124120000Z')
            .Der::sequence(
                self::single("\x80\x00", '20261124120000.123Z', Der::contextSpecific(0, self::time('20261125120000Z')).Der::contextSpecific(1, Der::sequence('')))
                .self::single($revoked, '20261124120000Z')
                .self::single(Der::contextSpecific(1, self::time('20261120100000Z')), '20261124120000Z')
                .self::single("\x82\x00", '20261124120000Z', '', '2.16.840.1.101.3.4.2.1')
            )
            .Der::contextSpecific(1, Der::sequence(
                Der::sequence(Der::objectIdentifier('1.3.6.1.5.5.7.48.1.9').Der::octetString('x'))
                .Der::sequence(Der::objectIdentifier('1.3.6.1.5.5.7.48.1.2').Der::tlv(0x01, "\x00").Der::octetString(Der::octetString('nonce')))
            ))
        );

        $response = OcspResponse::parse(self::response($tbs, '1.2.840.10045.4.3.2', Der::contextSpecific(0, Der::sequence(Der::sequence('cert')))));

        self::assertNotNull($response);
        self::assertSame($tbs, $response->tbsResponseData);
        self::assertSame('sha256', $response->signatureDigest);
        self::assertSame('signature', $response->signature);
        self::assertSame([Der::sequence('cert')], $response->certificates);
        self::assertSame(Der::octetString('nonce'), $response->nonce);
        self::assertCount(4, $response->responses);

        [$good, $withReason, $withoutReason, $unknown] = $response->responses;
        self::assertSame(OcspSingleResponse::GOOD, $good->status);
        self::assertSame(gmmktime(12, 0, 0, 11, 24, 2026), $good->thisUpdate);
        self::assertSame(gmmktime(12, 0, 0, 11, 25, 2026), $good->nextUpdate);
        self::assertSame('1.3.14.3.2.26', $good->hashAlgorithmOid);
        self::assertSame(str_repeat("\x02", 20), $good->issuerNameHash);
        self::assertSame(str_repeat("\x03", 20), $good->issuerKeyHash);
        self::assertSame(Der::tlv(0x02, "\x05"), $good->serialNumberDer);
        self::assertSame(OcspSingleResponse::REVOKED, $withReason->status);
        self::assertSame(gmmktime(10, 0, 0, 11, 20, 2026), $withReason->revocationTime);
        self::assertSame('keyCompromise', $withReason->revocationReasonName());
        self::assertNull($withoutReason->revocationReasonName());
        self::assertNull($withoutReason->nextUpdate);
        self::assertSame(OcspSingleResponse::UNKNOWN, $unknown->status);
        self::assertSame('2.16.840.1.101.3.4.2.1', $unknown->hashAlgorithmOid);
    }

    public function test_response_without_optional_parts(): void
    {
        $response = OcspResponse::parse(self::response(self::tbs(self::single("\x80\x00", '20261124120000Z')), '1.2.840.113549.1.1.10'));

        self::assertNotNull($response);
        self::assertNull($response->signatureDigest, 'RSASSA-PSS is not supported, so it cannot be verified.');
        self::assertSame([], $response->certificates);
        self::assertNull($response->nonce);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedResponses(): iterable
    {
        $good = self::single("\x80\x00", '20261124120000Z');

        yield 'empty' => [''];
        yield 'not DER' => ['garbage'];
        yield 'trailing bytes' => [self::response(self::tbs($good)).'x'];
        yield 'unauthorized' => [Der::sequence(Der::tlv(0x0A, "\x06"))];
        yield 'successful without bytes' => [Der::sequence(Der::tlv(0x0A, "\x00"))];
        yield 'other response type' => [self::response(self::tbs($good), type: '1.3.6.1.5.5.7.48.1.99')];
        yield 'response bytes not an octet string' => [Der::sequence(Der::tlv(0x0A, "\x00").Der::contextSpecific(0, Der::sequence(Der::objectIdentifier(self::BASIC).Der::sequence(''))))];
        yield 'incomplete basic response' => [self::wrap(Der::sequence(self::tbs($good)))];
        yield 'basic response with wrong types' => [self::wrap(Der::sequence(self::tbs($good).Der::sequence('').Der::octetString('sig')))];
        yield 'response data without responses' => [self::response(Der::sequence(Der::contextSpecific(2, Der::octetString('k')).self::time('20261124120000Z')))];
        yield 'unknown status' => [self::response(self::tbs(self::single("\x83\x00", '20261124120000Z')))];
        yield 'incomplete single response' => [self::response(self::tbs(Der::sequence(self::certId())))];
        yield 'incomplete cert id' => [self::response(self::tbs(Der::sequence(Der::sequence(Der::octetString('x')).Der::tlv(0x80, '').self::time('20261124120000Z'))))];
        yield 'invalid time' => [self::response(self::tbs(self::single("\x80\x00", '2026112412Z')))];
        yield 'invalid next update' => [self::response(self::tbs(self::single("\x80\x00", '20261124120000Z', Der::contextSpecific(0, Der::tlv(0x17, '261124120000Z')))))];
    }

    #[DataProvider('rejectedResponses')]
    public function test_rejects_malformed_or_unsuccessful_responses(string $der): void
    {
        self::assertNull(OcspResponse::parse($der));
    }

    public function test_single_response_validity_window(): void
    {
        $now = 1_800_000_000;
        $status = static fn (int $thisUpdate, ?int $nextUpdate): OcspSingleResponse => new OcspSingleResponse('', '', '', '', OcspSingleResponse::GOOD, $thisUpdate, $nextUpdate);

        self::assertTrue($status($now - 60, $now + 3600)->isCurrent($now, 300, 86400));
        self::assertTrue($status($now + 299, $now + 3600)->isCurrent($now, 300, 86400));
        self::assertFalse($status($now + 301, $now + 3600)->isCurrent($now, 300, 86400));
        self::assertTrue($status($now - 7200, $now - 299)->isCurrent($now, 300, 86400));
        self::assertFalse($status($now - 7200, $now - 301)->isCurrent($now, 300, 86400));
        self::assertFalse($status($now, $now - 10)->isCurrent($now, 300, 86400), 'nextUpdate before thisUpdate');
        self::assertTrue($status($now - 86400, null)->isCurrent($now, 300, 86400));
        self::assertFalse($status($now - 86401, null)->isCurrent($now, 300, 86400));
        self::assertTrue($status($now - 10 * 86400, $now + 60)->isCurrent($now, 300, 86400), 'status age only applies without nextUpdate');
    }

    public function test_revocation_reason_names(): void
    {
        $reason = static fn (int $code): ?string => (new OcspSingleResponse('', '', '', '', OcspSingleResponse::REVOKED, 0, null, 0, $code))->revocationReasonName();

        self::assertSame('unspecified', $reason(0));
        self::assertSame('certificateHold', $reason(6));
        self::assertSame('aACompromise', $reason(10));
        self::assertSame('reason 7', $reason(7));
    }

    public function test_request_matches_cert_ids_by_their_own_hash_algorithm(): void
    {
        if (! OcspTestPki::opensslAvailable()) {
            self::markTestSkipped('The OpenSSL CLI is required for the test PKI.');
        }
        $pki = new OcspTestPki;
        $request = OcspRequest::forCertificate($pki->der('leaf'), $pki->der('ca'), 'nonce');
        self::assertNotNull($request);
        self::assertSame(Der::octetString('nonce'), $request->nonce);

        // A responder answering a SHA-256 CertID is still recognised by the SHA-1 request.
        $sha256 = OcspResponse::parse($pki->respond($pki->cliRequest('leaf', 'ca', 'sha256')));
        self::assertNotNull($sha256);
        self::assertSame('2.16.840.1.101.3.4.2.1', $sha256->responses[0]->hashAlgorithmOid);
        self::assertSame(OcspSingleResponse::GOOD, $request->findStatus($sha256)?->status);

        $otherCertificate = OcspResponse::parse($pki->respond($pki->cliRequest('leafWithoutOcsp', 'ca', 'sha1'), certificate: 'leafWithoutOcsp'));
        $unsupportedHash = OcspResponse::parse(self::response(self::tbs(self::single("\x80\x00", '20261124120000Z', '', '1.2.840.113549.2.5'))));
        self::assertNotNull($otherCertificate);
        self::assertNotNull($unsupportedHash);
        self::assertNull($request->findStatus($otherCertificate));
        self::assertNull($request->findStatus($unsupportedHash));
    }

    public function test_request_requires_parseable_certificates(): void
    {
        $certificate = Der::sequence(Der::sequence(Der::tlv(0x02, "\x01").Der::sequence('')));

        self::assertNull(OcspRequest::forCertificate('garbage', 'garbage'));
        self::assertNull(OcspRequest::forCertificate(Der::octetString('x'), Der::octetString('x')));
        self::assertNull(OcspRequest::forCertificate($certificate, $certificate));
        self::assertNull(OcspRequest::forCertificate(
            Der::sequence(Der::sequence(str_repeat(Der::tlv(0x02, "\x01"), 5).Der::sequence(Der::sequence('').Der::tlv(0x03, '')))),
            Der::sequence(Der::sequence(str_repeat(Der::tlv(0x02, "\x01"), 5).Der::sequence(''))),
        ));
    }

    private static function time(string $value): string
    {
        return Der::tlv(0x18, $value);
    }

    private static function certId(string $hash = '1.3.14.3.2.26'): string
    {
        return Der::sequence(
            Der::algorithmIdentifier($hash)
            .Der::octetString(str_repeat("\x02", 20))
            .Der::octetString(str_repeat("\x03", 20))
            .Der::tlv(0x02, "\x05")
        );
    }

    private static function single(string $status, string $thisUpdate, string $optional = '', string $hash = '1.3.14.3.2.26'): string
    {
        return Der::sequence(self::certId($hash).$status.self::time($thisUpdate).$optional);
    }

    private static function tbs(string $singleResponses): string
    {
        return Der::sequence(
            Der::contextSpecific(2, Der::octetString(str_repeat("\x01", 20)))
            .self::time('20261124120000Z')
            .Der::sequence($singleResponses)
        );
    }

    private static function response(string $tbs, string $algorithm = '1.2.840.113549.1.1.11', string $certificates = '', string $type = self::BASIC): string
    {
        return self::wrap(Der::sequence($tbs.Der::algorithmIdentifier($algorithm).Der::tlv(0x03, "\x00signature").$certificates), $type);
    }

    private static function wrap(string $basic, string $type = self::BASIC): string
    {
        return Der::sequence(Der::tlv(0x0A, "\x00").Der::contextSpecific(0, Der::sequence(Der::objectIdentifier($type).Der::octetString($basic))));
    }
}
