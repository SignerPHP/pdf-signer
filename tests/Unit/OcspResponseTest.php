<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspCertificate;
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
                self::single("\x80\x00", '20261124120000.123Z', Der::contextSpecific(0, self::time('20261125120000Z')).Der::contextSpecific(1, self::extensions(self::extension('1.3.6.1.5.5.7.48.1.9', 'x'))))
                .self::single($revoked, '20261124120000Z')
                .self::single(Der::contextSpecific(1, self::time('20261120100000Z')), '20261124120000Z')
                .self::single("\x82\x00", '20261124120000Z', '', '2.16.840.1.101.3.4.2.1')
            )
            .Der::contextSpecific(1, self::extensions(
                self::extension('1.3.6.1.5.5.7.48.1.9', 'x')
                .self::extension('1.3.6.1.5.5.7.48.1.2', Der::octetString('nonce'), "\xFF")
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
        self::assertSame(str_repeat("\x01", 20), $response->responderKeyHash);
        self::assertNull($response->responderName);
        self::assertSame(gmmktime(12, 0, 0, 11, 24, 2026), $response->producedAt);

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

        $basic = static fn (string $tbs, string $tail = ''): string => self::wrap(Der::sequence($tbs.Der::algorithmIdentifier('1.2.840.113549.1.1.11').Der::tlv(0x03, "\x00sig").$tail));
        $tbs = static fn (string $responder, string $producedAt, string $responses, string $tail = ''): string => Der::sequence($responder.$producedAt.$responses.$tail);
        $byKey = Der::contextSpecific(2, Der::octetString(str_repeat("\x01", 20)));
        $now = self::time('20261124120000Z');
        $withSingle = static fn (string $single): string => self::response(self::tbs($single));
        $certIdWith = static fn (string $algorithm, string $serial): string => self::response(self::tbs(Der::sequence(
            Der::sequence($algorithm.Der::octetString('n').Der::octetString('k').$serial)."\x80\x00".self::time('20261124120000Z')
        )));
        $sha1 = Der::algorithmIdentifier('1.3.14.3.2.26');
        $serial = Der::tlv(0x02, "\x05");
        $withOid = static fn (string $oidValue): string => $certIdWith(Der::sequence(Der::tlv(0x06, $oidValue)), $serial);

        // DER, not BER
        yield 'empty' => [''];
        yield 'not DER' => ['garbage'];
        yield 'trailing bytes' => [self::response(self::tbs($good)).'x'];
        yield 'indefinite length' => ["\x30\x80".Der::tlv(0x0A, "\x00")."\x00\x00"];
        yield 'non-minimal length' => ["\x30\x81\x03".Der::tlv(0x0A, "\x00")];
        yield 'length with leading zero' => ["\x30\x82\x00\x83".str_repeat("\x05\x00", 65)."\x05"];
        yield 'five-byte length' => ["\x30\x85\x00\x00\x00\x00\x03"];
        yield 'truncated length' => ["\x30\x82\x01"];
        yield 'high tag number' => [Der::sequence("\x1F\x81\x00\x00")];

        // OCSPResponse / ResponseBytes
        yield 'unauthorized' => [Der::sequence(Der::tlv(0x0A, "\x06"))];
        yield 'two-byte status' => [Der::sequence(Der::tlv(0x0A, "\x00\x00"))];
        yield 'successful without bytes' => [Der::sequence(Der::tlv(0x0A, "\x00"))];
        yield 'empty response' => [Der::sequence('')];
        yield 'extra element in OCSPResponse' => [Der::sequence(Der::tlv(0x0A, "\x00").Der::contextSpecific(0, Der::sequence(Der::objectIdentifier(self::BASIC).Der::octetString(Der::sequence(self::tbs($good).Der::algorithmIdentifier('1.2.840.113549.1.1.11').Der::tlv(0x03, "\x00sig"))))).Der::null())];
        yield 'other response type' => [self::response(self::tbs($good), type: '1.3.6.1.5.5.7.48.1.99')];
        yield 'response bytes not an octet string' => [Der::sequence(Der::tlv(0x0A, "\x00").Der::contextSpecific(0, Der::sequence(Der::objectIdentifier(self::BASIC).Der::sequence(''))))];

        // BasicOCSPResponse
        yield 'incomplete basic response' => [self::wrap(Der::sequence(self::tbs($good)))];
        yield 'basic response with wrong types' => [self::wrap(Der::sequence(self::tbs($good).Der::sequence('').Der::octetString('sig')))];
        yield 'extra element in BasicOCSPResponse' => [$basic(self::tbs($good), Der::contextSpecific(0, Der::sequence('')).Der::null())];
        yield 'certs with the wrong tag' => [$basic(self::tbs($good), Der::contextSpecific(1, Der::sequence('')))];
        yield 'certs holding a non-certificate' => [$basic(self::tbs($good), Der::contextSpecific(0, Der::sequence(Der::null())))];
        yield 'signature with unused bits' => [self::wrap(Der::sequence(self::tbs($good).Der::algorithmIdentifier('1.2.840.113549.1.1.11').Der::tlv(0x03, "\x01sig")))];
        yield 'empty signature' => [self::wrap(Der::sequence(self::tbs($good).Der::algorithmIdentifier('1.2.840.113549.1.1.11').Der::tlv(0x03, "\x00")))];
        yield 'empty signature algorithm' => [self::wrap(Der::sequence(self::tbs($good).Der::sequence('').Der::tlv(0x03, "\x00sig")))];
        yield 'signature algorithm with extra parts' => [self::wrap(Der::sequence(self::tbs($good).Der::sequence(Der::objectIdentifier('1.2.840.113549.1.1.11').Der::null().Der::null()).Der::tlv(0x03, "\x00sig")))];

        // ResponseData
        yield 'version 2' => [$basic(Der::sequence(Der::contextSpecific(0, Der::tlv(0x02, "\x01")).$byKey.$now.Der::sequence($good)))];
        yield 'unknown responder id' => [$basic($tbs(Der::contextSpecific(3, Der::octetString('k')), $now, Der::sequence($good)))];
        yield 'responder key hash of the wrong size' => [$basic($tbs(Der::contextSpecific(2, Der::octetString('short')), $now, Der::sequence($good)))];
        yield 'responder name that is not a Name' => [$basic($tbs(Der::contextSpecific(1, Der::octetString('name')), $now, Der::sequence($good)))];
        yield 'producedAt as UTCTime' => [$basic($tbs($byKey, Der::tlv(0x17, '261124120000Z'), Der::sequence($good)))];
        yield 'no single responses' => [$basic($tbs($byKey, $now, Der::sequence('')))];
        yield 'extra element in ResponseData' => [$basic($tbs($byKey, $now, Der::sequence($good), Der::contextSpecific(1, self::extensions(self::extension('1.2.3', 'x'))).Der::null()))];
        yield 'response data without responses' => [self::response(Der::sequence(Der::contextSpecific(2, Der::octetString('k')).self::time('20261124120000Z')))];
        yield 'duplicate nonce' => [$basic($tbs($byKey, $now, Der::sequence($good), Der::contextSpecific(1, self::extensions(self::extension('1.3.6.1.5.5.7.48.1.2', 'a').self::extension('1.3.6.1.5.5.7.48.1.2', 'b')))))];
        yield 'explicit non-critical flag' => [$basic($tbs($byKey, $now, Der::sequence($good), Der::contextSpecific(1, self::extensions(self::extension('1.2.3', 'x', "\x00")))))];
        yield 'empty extensions' => [$basic($tbs($byKey, $now, Der::sequence($good), Der::contextSpecific(1, Der::sequence(''))))];
        yield 'extension without value' => [$basic($tbs($byKey, $now, Der::sequence($good), Der::contextSpecific(1, Der::sequence(Der::sequence(Der::objectIdentifier('1.2.3'))))))];

        // SingleResponse
        yield 'unknown status' => [$withSingle(self::single("\x83\x00", '20261124120000Z'))];
        yield 'good with a value' => [$withSingle(self::single("\x80\x01\x00", '20261124120000Z'))];
        yield 'empty revoked info' => [$withSingle(self::single(Der::contextSpecific(1, ''), '20261124120000Z'))];
        yield 'revoked info with extra element' => [$withSingle(self::single(Der::contextSpecific(1, self::time('20261120100000Z').Der::contextSpecific(0, Der::tlv(0x0A, "\x01")).Der::null()), '20261124120000Z'))];
        yield 'unused CRL reason 7' => [$withSingle(self::single(Der::contextSpecific(1, self::time('20261120100000Z').Der::contextSpecific(0, Der::tlv(0x0A, "\x07"))), '20261124120000Z'))];
        yield 'unknown optional element' => [$withSingle(self::single("\x80\x00", '20261124120000Z', Der::contextSpecific(2, Der::null())))];
        yield 'repeated next update' => [$withSingle(self::single("\x80\x00", '20261124120000Z', str_repeat(Der::contextSpecific(0, self::time('20261125120000Z')), 2)))];
        yield 'optional elements out of order' => [$withSingle(self::single("\x80\x00", '20261124120000Z', Der::contextSpecific(1, self::extensions(self::extension('1.2.3', 'x'))).Der::contextSpecific(0, self::time('20261125120000Z'))))];
        yield 'incomplete single response' => [self::response(self::tbs(Der::sequence(self::certId())))];
        yield 'incomplete cert id' => [self::response(self::tbs(Der::sequence(Der::sequence(Der::octetString('x')).Der::tlv(0x80, '').self::time('20261124120000Z'))))];
        yield 'serial with redundant leading zero' => [$certIdWith($sha1, Der::tlv(0x02, "\x00\x05"))];
        yield 'serial with redundant leading ones' => [$certIdWith($sha1, Der::tlv(0x02, "\xFF\x85"))];
        yield 'empty serial' => [$certIdWith($sha1, Der::tlv(0x02, ''))];
        yield 'invalid time' => [$withSingle(self::single("\x80\x00", '2026112412Z'))];
        yield 'time with trailing fraction zero' => [$withSingle(self::single("\x80\x00", '20261124120000.10Z'))];
        yield 'impossible date' => [$withSingle(self::single("\x80\x00", '20261324120000Z'))];
        yield 'invalid next update' => [$withSingle(self::single("\x80\x00", '20261124120000Z', Der::contextSpecific(0, Der::tlv(0x17, '261124120000Z'))))];

        // OBJECT IDENTIFIER
        yield 'empty OID' => [$withOid('')];
        yield 'unterminated OID' => [$withOid("\x2B\x81")];
        yield 'non-minimal OID arc' => [$withOid("\x2B\x80\x01")];
        yield 'oversized OID arc' => [$withOid("\x2B".str_repeat("\xFF", 10)."\x7F")];
    }

    public function test_controls_for_the_rejected_fixtures_parse(): void
    {
        $good = self::single("\x80\x00", '20261124120000Z');
        $byKey = Der::contextSpecific(2, Der::octetString(str_repeat("\x01", 20)));
        $now = self::time('20261124120000Z');
        $basic = static fn (string $tbs, string $tail = ''): string => self::wrap(Der::sequence($tbs.Der::algorithmIdentifier('1.2.840.113549.1.1.11').Der::tlv(0x03, "\x00sig").$tail));
        $controls = [
            $basic(Der::sequence(Der::contextSpecific(0, Der::tlv(0x02, "\x00")).$byKey.$now.Der::sequence($good))),
            $basic(Der::sequence(Der::contextSpecific(1, Der::sequence('')).$now.Der::sequence($good))),
            $basic(Der::sequence($byKey.$now.Der::sequence($good).Der::contextSpecific(1, self::extensions(self::extension('1.2.3', 'x', "\xFF"))))),
            $basic(self::tbs($good), Der::contextSpecific(0, Der::sequence(Der::sequence('')))),
            self::response(self::tbs(self::single(Der::contextSpecific(1, self::time('20261120100000Z').Der::contextSpecific(0, Der::tlv(0x0A, "\x0A"))), '20261124120000Z'))),
            self::response(self::tbs(self::single("\x80\x00", '20261124120000.1Z', Der::contextSpecific(0, self::time('20261125120000Z')).Der::contextSpecific(1, self::extensions(self::extension('1.2.3', 'x')))))),
            self::response(self::tbs(Der::sequence(Der::sequence(Der::sequence(Der::tlv(0x06, "\x2B\x0E\x03\x02\x1A")).Der::octetString('n').Der::octetString('k').Der::tlv(0x02, "\x00\x85"))."\x80\x00".$now))),
            self::response(self::tbs(Der::sequence(Der::sequence(Der::algorithmIdentifier('1.3.14.3.2.26').Der::octetString('n').Der::octetString('k').Der::tlv(0x02, "\xFF\x05"))."\x80\x00".$now))),
        ];

        foreach ($controls as $index => $der) {
            self::assertNotNull(OcspResponse::parse($der), 'control #'.$index);
        }
    }

    public function test_responder_id_by_name_and_by_key(): void
    {
        if (! OcspTestPki::opensslAvailable()) {
            self::markTestSkipped('The OpenSSL CLI is required for the test PKI.');
        }
        $pki = new OcspTestPki;
        $request = $pki->cliRequest('leaf', 'ca', 'sha1');
        $ca = OcspCertificate::fromPem($pki->pem('ca'));
        $responder = OcspCertificate::fromPem($pki->pem('responder'));
        self::assertNotNull($ca);
        self::assertNotNull($responder);

        $byName = OcspResponse::parse($pki->respond($request));
        $byKey = OcspResponse::parse($pki->respond($request, byKey: true));
        self::assertNotNull($byName);
        self::assertNotNull($byKey);

        self::assertSame($ca->subjectDer, $byName->responderName);
        self::assertNull($byName->responderKeyHash);
        self::assertTrue($byName->identifies($ca));
        self::assertFalse($byName->identifies($responder));
        self::assertNull($byKey->responderName);
        self::assertTrue($byKey->identifies($ca));
        self::assertFalse($byKey->identifies($responder));
        self::assertEqualsWithDelta(time(), $byName->producedAt, 60);
    }

    public function test_certificate_fields_require_a_well_formed_certificate(): void
    {
        $tbs = static fn (string $publicKeyInfo, string $serial = "\x02\x01\x01"): string => Der::sequence(Der::sequence(
            $serial.Der::sequence('').Der::sequence('').Der::sequence('').Der::sequence('').$publicKeyInfo
        ));

        self::assertNotNull(OcspCertificate::fromDer($tbs(Der::sequence(Der::sequence('').Der::tlv(0x03, "\x00k")))));
        self::assertNull(OcspCertificate::fromDer($tbs(Der::sequence(Der::sequence('').Der::tlv(0x03, "\x01k")))));
        self::assertNull(OcspCertificate::fromDer($tbs(Der::sequence(Der::sequence('')))));
        self::assertNull(OcspCertificate::fromDer($tbs(Der::sequence(Der::sequence('').Der::tlv(0x03, "\x00k")), "\x02\x02\x00\x01")));
        self::assertNull(OcspCertificate::fromDer(Der::sequence('')));
        self::assertNull(OcspCertificate::fromDer(Der::sequence(Der::octetString('x'))));
        self::assertNull(OcspCertificate::fromPem('-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----'));
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

    private static function extensions(string $extensions): string
    {
        return Der::sequence($extensions);
    }

    private static function extension(string $oid, string $value, string $critical = ''): string
    {
        return Der::sequence(Der::objectIdentifier($oid).($critical === '' ? '' : Der::tlv(0x01, $critical)).Der::octetString($value));
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
