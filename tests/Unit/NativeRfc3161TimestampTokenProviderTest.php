<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeRfc3161TimestampTokenProvider;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\HttpResponse;

/**
 * The TSA endpoint is faked by an HTTP client that answers each request with a real
 * TimeStampResp issued by a throwaway TSA through `openssl ts -reply`.
 */
final class NativeRfc3161TimestampTokenProviderTest extends TestCase
{
    private const DOCUMENT = '1234567890ABCDEF';

    /** Bytes covered by the ByteRange [0, 4, 8, 4] of DOCUMENT. */
    private const COVERED = '123490AB';

    private const TSA_URL = 'https://tsa.local/stamp';

    private const TOKEN_URL = 'https://tsa.local/token';

    private static string $dir;

    public static function setUpBeforeClass(): void
    {
        self::$dir = sys_get_temp_dir().'/rfc3161-provider-test-'.bin2hex(random_bytes(4));
        mkdir(self::$dir);
        $d = escapeshellarg(self::$dir);

        file_put_contents(self::$dir.'/ext.cnf', implode("\n", [
            '[req]', 'distinguished_name = dn', 'prompt = no', '[dn]', 'CN = TSA Test',
            '[v3_ca]', 'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign',
            '[v3_tsa]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature', 'extendedKeyUsage = critical, timeStamping', '',
        ]));
        file_put_contents(self::$dir.'/tsa.cnf', implode("\n", [
            '[tsa]', 'default_tsa = t', '[t]',
            'serial = '.self::$dir.'/serial', 'crypto_device = builtin',
            'signer_cert = '.self::$dir.'/tsa.crt', 'signer_key = '.self::$dir.'/tsa.key', 'certs = '.self::$dir.'/ca.crt',
            'signer_digest = sha256', 'default_policy = 1.2.3.4.1', 'digests = sha224, sha256, sha384, sha512', 'ess_cert_id_alg = sha256', '',
        ]));
        file_put_contents(self::$dir.'/serial', "01\n");
        file_put_contents(self::$dir.'/covered.bin', self::COVERED);
        file_put_contents(self::$dir.'/other.bin', 'other content');

        self::shell(<<<SH
            cd $d
            openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=TSA-Test-CA -config ext.cnf -extensions v3_ca
            openssl req -new -newkey rsa:2048 -nodes -keyout tsa.key -out tsa.csr -subj /CN=TSA-Test -config ext.cnf
            openssl x509 -req -in tsa.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tsa.crt -days 2 -extfile ext.cnf -extensions v3_tsa
            openssl x509 -in tsa.crt -outform DER -out tsa.der
            openssl ts -query -data covered.bin -sha256 -cert -out other-nonce.tsq
            openssl ts -reply -config tsa.cnf -queryfile other-nonce.tsq -out other-nonce.tsr
            openssl ts -query -data covered.bin -sha256 -cert -no_nonce -out no-nonce.tsq
            openssl ts -reply -config tsa.cnf -queryfile no-nonce.tsq -out no-nonce.tsr
            openssl ts -query -data other.bin -sha256 -cert -out other-data.tsq
            openssl ts -reply -config tsa.cnf -queryfile other-data.tsq -out other-data.tsr
            SH);
    }

    public static function tearDownAfterClass(): void
    {
        self::shell('rm -rf '.escapeshellarg(self::$dir));
    }

    protected function setUp(): void
    {
        $reflection = new \ReflectionClass(NativeRfc3161TimestampTokenProvider::class);
        $cache = $reflection->getProperty('oauthTokenCache');
        $cache->setValue(null, []);
    }

    public function test_request_token_hex_returns_the_token_issued_by_the_tsa(): void
    {
        foreach (['sha224', 'sha256', 'sha384', 'sha512'] as $algorithm) {
            $client = $this->tsaClient();
            $provider = new NativeRfc3161TimestampTokenProvider($client);

            $hex = $provider->requestTokenHex(self::DOCUMENT, [0, 4, 8, 4], new TimestampOptionsDto(
                tsaUrl: self::TSA_URL,
                hashAlgorithm: $algorithm,
                username: 'user',
                password: 'pass',
            ));

            self::assertMatchesRegularExpression('/^[0-9A-F]+$/', $hex);
            $token = (string) hex2bin($hex);
            self::assertSame($this->tokenOf($client->lastReply), $token, $algorithm);
            self::assertStringContainsString(hash($algorithm, self::COVERED, true), $token, $algorithm);
            // certReq defaults to true, so the TSA embeds its certificate in the token.
            self::assertStringContainsString((string) file_get_contents(self::$dir.'/tsa.der'), $token, $algorithm);

            $call = $client->calls[0];
            self::assertSame('POST', $call['method']);
            self::assertSame(self::TSA_URL, $call['url']);
            self::assertContains('Content-Type: application/timestamp-query', $call['headers']);
            self::assertContains('Accept: application/timestamp-reply', $call['headers']);
            self::assertContains('Content-Length: '.strlen($call['body']), $call['headers']);
            self::assertContains('Authorization: Basic '.base64_encode('user:pass'), $call['headers']);
        }
    }

    public function test_request_is_a_der_time_stamp_req_with_a_fresh_nonce(): void
    {
        $client = $this->tsaClient();
        $provider = new NativeRfc3161TimestampTokenProvider($client);
        $options = new TimestampOptionsDto(tsaUrl: self::TSA_URL);

        $provider->requestTokenHex(self::DOCUMENT, [0, 4, 8, 4], $options);
        $provider->requestTokenHex(self::DOCUMENT, [0, 4, 8, 4], $options);

        $sha256 = Der::sequence(Der::objectIdentifier('2.16.840.1.101.3.4.2.1').Der::null());
        $prefix = "\x02\x01\x01".Der::sequence($sha256.Der::octetString(hash('sha256', self::COVERED, true)));
        $nonces = [];
        foreach ($client->calls as $call) {
            [$tag, $request, $end] = Der::readTlvStrict($call['body']);
            self::assertSame(0x30, $tag);
            self::assertSame(strlen($call['body']), $end);
            self::assertStringStartsWith($prefix, $request);

            [$tag, $nonce, $offset] = Der::readTlvStrict($request, strlen($prefix));
            self::assertSame(0x02, $tag);
            self::assertSame(16, strlen($nonce));
            self::assertLessThan(0x80, ord($nonce[0]));
            self::assertSame("\x01\x01\xFF", substr($request, $offset));
            $nonces[] = $nonce;
        }

        self::assertNotSame($nonces[0], $nonces[1]);
    }

    public function test_request_omits_cert_req_when_disabled(): void
    {
        $client = $this->tsaClient();

        $hex = (new NativeRfc3161TimestampTokenProvider($client))->requestTokenHex(
            self::DOCUMENT,
            [0, 4, 8, 4],
            new TimestampOptionsDto(tsaUrl: self::TSA_URL, hashAlgorithm: 'sha256', certReq: false),
        );

        [, $request] = Der::readTlvStrict($client->calls[0]['body']);
        [, , $offset] = Der::readTlvStrict($request);
        [, , $offset] = Der::readTlvStrict($request, $offset);
        [$tag, , $offset] = Der::readTlvStrict($request, $offset);
        self::assertSame(0x02, $tag);
        self::assertSame(strlen($request), $offset, 'certReq FALSE is the DEFAULT and is not encoded.');
        self::assertStringNotContainsString((string) file_get_contents(self::$dir.'/tsa.der'), (string) hex2bin($hex));
    }

    public function test_request_token_hex_throws_for_unsupported_hash_algorithm(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported hash algorithm: md5');

        (new NativeRfc3161TimestampTokenProvider($this->tsaClient()))->requestTokenHex('abcd', [0, 2, 2, 2], new TimestampOptionsDto(
            tsaUrl: self::TSA_URL,
            hashAlgorithm: 'md5',
        ));
    }

    public function test_request_token_hex_reports_a_request_rejected_by_the_tsa(): void
    {
        // The test TSA does not accept SHA-1 imprints and answers with rejection / badAlg.
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessageMatches('/^TSA did not grant the timestamp request\. Status: rejection\. Failure info: badAlg\. Status text: .+/');

        (new NativeRfc3161TimestampTokenProvider($this->tsaClient()))->requestTokenHex(
            self::DOCUMENT,
            [0, 4, 8, 4],
            new TimestampOptionsDto(tsaUrl: self::TSA_URL, hashAlgorithm: 'sha1'),
        );
    }

    public function test_request_token_hex_reports_status_without_text_and_unknown_failure_bits(): void
    {
        // waiting, no statusString, failInfo with systemFailure (bit 25) and an unassigned bit 26.
        $reply = Der::sequence(Der::sequence("\x02\x01\x03".Der::tlv(0x03, "\x05\x00\x00\x00\x60")));

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('TSA did not grant the timestamp request. Status: waiting. Failure info: systemFailure, bit 26. Status text: none');

        $this->requestWithReply($reply);
    }

    public function test_request_token_hex_reports_an_unknown_status_with_its_text(): void
    {
        $reply = Der::sequence(Der::sequence("\x02\x01\x09".Der::sequence(Der::tlv(0x0C, 'busy').Der::tlv(0x0C, 'retry later'))));

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('TSA did not grant the timestamp request. Status: 9. Failure info: none. Status text: busy | retry later');

        $this->requestWithReply($reply);
    }

    public function test_request_token_hex_rejects_a_token_for_another_nonce(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('TSA response nonce does not match the timestamp request.');

        $this->requestWithReply((string) file_get_contents(self::$dir.'/other-nonce.tsr'));
    }

    public function test_request_token_hex_rejects_a_token_without_the_nonce(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('TSA response does not echo the timestamp request nonce.');

        $this->requestWithReply((string) file_get_contents(self::$dir.'/no-nonce.tsr'));
    }

    public function test_request_token_hex_rejects_a_token_for_other_data(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('TSA response message imprint does not match the timestamp request.');

        $this->requestWithReply((string) file_get_contents(self::$dir.'/other-data.tsr'));
    }

    /**
     * @return iterable<string, array{0:string,1:string}>
     */
    public static function malformedReplies(): iterable
    {
        $granted = Der::sequence("\x02\x01\x00");
        $tstInfoOid = Der::objectIdentifier('1.2.840.113549.1.9.16.1.4');
        $token = static fn (string $contentType, string $encap): string => Der::sequence(
            Der::objectIdentifier($contentType).Der::contextSpecific(0, Der::sequence("\x02\x01\x03".Der::set('').$encap.Der::set('')))
        );

        yield 'not DER' => ['not-der', 'DER value exceeds its container.'];
        yield 'not a SEQUENCE' => ["\x04\x00", 'TimeStampResp is malformed.'];
        yield 'status info not a SEQUENCE' => [Der::sequence("\x04\x00"), 'PKIStatusInfo is malformed.'];
        yield 'status not an INTEGER' => [Der::sequence(Der::sequence("\x04\x01\x00")), 'PKIStatus is malformed.'];
        yield 'empty status' => [Der::sequence(Der::sequence("\x02\x00")), 'PKIStatus is not a valid integer.'];
        yield 'granted without token' => [Der::sequence($granted), 'TimeStampResp has no timeStampToken.'];
        yield 'token not a SEQUENCE' => [Der::sequence($granted."\x04\x00"), 'timeStampToken is malformed.'];
        yield 'token not SignedData' => [
            Der::sequence($granted.$token('1.2.840.113549.1.7.1', Der::sequence($tstInfoOid))),
            'timeStampToken is not a CMS SignedData.',
        ];
        yield 'token without TSTInfo' => [
            Der::sequence($granted.$token('1.2.840.113549.1.7.2', Der::sequence(Der::objectIdentifier('1.2.840.113549.1.7.1').Der::contextSpecific(0, Der::octetString(''))))),
            'timeStampToken does not encapsulate a TSTInfo.',
        ];
        yield 'TSTInfo not an OCTET STRING' => [
            Der::sequence($granted.$token('1.2.840.113549.1.7.2', Der::sequence($tstInfoOid.Der::contextSpecific(0, Der::set(''))))),
            'eContent is malformed.',
        ];
        yield 'TSTInfo not a SEQUENCE' => [
            Der::sequence($granted.$token('1.2.840.113549.1.7.2', Der::sequence($tstInfoOid.Der::contextSpecific(0, Der::octetString(Der::set('')))))),
            'TSTInfo is malformed.',
        ];
        yield 'bytes after the TSTInfo' => [
            Der::sequence($granted.$token('1.2.840.113549.1.7.2', Der::sequence($tstInfoOid.Der::contextSpecific(0, Der::octetString(Der::sequence('')."\x00"))))),
            'Trailing bytes after DER element.',
        ];
        yield 'SignedData without signerInfos' => [
            Der::sequence($granted.Der::sequence(Der::objectIdentifier('1.2.840.113549.1.7.2').Der::contextSpecific(0, Der::sequence("\x02\x01\x03")))),
            'SignedData is malformed.',
        ];
        yield 'bytes after the TimeStampResp' => [Der::sequence($granted)."\x00", 'Trailing bytes after DER element.'];
        yield 'extra element in TimeStampResp' => [Der::sequence($granted.Der::sequence('').Der::null()), 'TimeStampResp is malformed.'];
        yield 'unexpected element in PKIStatusInfo' => [Der::sequence(Der::sequence("\x02\x01\x02\x02\x01\x00")), 'PKIStatusInfo is malformed.'];
        yield 'status text not a UTF8String' => [Der::sequence(Der::sequence("\x02\x01\x02".Der::sequence(Der::octetString('busy')))), 'PKIFreeText is malformed.'];
        yield 'indefinite length' => ["\x30\x80".$granted."\x00\x00", 'Indefinite length is not allowed in DER.'];
        yield 'long form for a short length' => ["\x30\x81".chr(strlen($granted)).$granted, 'Non-minimal DER length.'];
        yield 'length with a leading zero byte' => ["\x30\x82\x00".chr(strlen($granted)).$granted, 'Non-minimal DER length.'];
        yield 'length over four bytes' => ["\x30\x85\x00\x00\x00\x00\x05", 'Unsupported DER length.'];
        yield 'truncated length' => ["\x30\x82\x01", 'Truncated DER length.'];
        yield 'truncated element' => ["\x30", 'Truncated DER element.'];
        yield 'high-tag-number form' => ["\x1F\x01\x00", 'Unsupported DER high-tag-number form.'];
    }

    public function test_request_token_hex_rejects_bytes_after_a_real_reply(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not extract RFC3161 token from TSA response. Trailing bytes after DER element.');

        $this->requestWithReply((string) file_get_contents(self::$dir.'/other-nonce.tsr')."\x00");
    }

    #[DataProvider('malformedReplies')]
    public function test_request_token_hex_rejects_a_malformed_reply(string $reply, string $reason): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not extract RFC3161 token from TSA response. '.$reason);

        $this->requestWithReply($reply);
    }

    public function test_request_token_hex_throws_when_tsa_reply_request_fails(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not fetch RFC3161 timestamp response from TSA endpoint. Status: 503. Transport error: none. Body: unavailable');

        $this->requestWithReply('unavailable', 503);
    }

    public function test_request_token_hex_throws_when_tsa_reply_is_empty(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not fetch RFC3161 timestamp response from TSA endpoint. Status: 200. Transport error: none. Body: [empty]');

        $this->requestWithReply('');
    }

    public function test_request_token_hex_accepts_201_responses(): void
    {
        $client = $this->tsaClient(tsaStatus: 201);

        $hex = (new NativeRfc3161TimestampTokenProvider($client))->requestTokenHex(self::DOCUMENT, [0, 4, 8, 4], new TimestampOptionsDto(tsaUrl: self::TSA_URL));

        self::assertSame($this->tokenOf($client->lastReply), hex2bin($hex));
    }

    public function test_request_token_hex_allows_custom_timestamp_headers(): void
    {
        $client = $this->tsaClient();

        (new NativeRfc3161TimestampTokenProvider($client))->requestTokenHex(self::DOCUMENT, [0, 4, 8, 4], new TimestampOptionsDto(
            tsaUrl: self::TSA_URL,
            username: 'user',
            password: 'pass',
            customHeaders: ['x_api_key' => 'secret-key', 'authorization' => 'Token custom'],
        ));

        $headers = $client->calls[0]['headers'];
        self::assertContains('X-Api-Key: secret-key', $headers);
        self::assertContains('Authorization: Token custom', $headers);
        self::assertNotContains('Authorization: Basic '.base64_encode('user:pass'), $headers);
    }

    public function test_request_token_hex_reuses_cached_oauth_token(): void
    {
        $client = $this->tsaClient(oauthBody: '{"access_token":"cached-token","expires_in":300}');
        $provider = new NativeRfc3161TimestampTokenProvider($client);
        $options = $this->oauthOptions();

        $provider->requestTokenHex('abcdefgh', [0, 4, 4, 4], $options);
        $provider->requestTokenHex('12345678', [0, 4, 4, 4], $options);

        self::assertSame(1, $client->tokenRequests);
        $tokenCall = $client->calls[0];
        self::assertSame(self::TOKEN_URL, $tokenCall['url']);
        self::assertSame('grant_type=client_credentials', $tokenCall['body']);
        self::assertContains('Authorization: Basic '.base64_encode('id:secret'), $tokenCall['headers']);
        self::assertContains('Authorization: Bearer cached-token', $client->calls[1]['headers']);
        self::assertContains('Authorization: Bearer cached-token', $client->calls[2]['headers']);
    }

    public function test_request_token_hex_oauth_cache_uses_default_expiration_when_expires_in_is_missing(): void
    {
        $client = $this->tsaClient(oauthBody: '{"access_token":"token-without-exp"}');
        $provider = new NativeRfc3161TimestampTokenProvider($client);
        $options = $this->oauthOptions();

        $provider->requestTokenHex('abcdefgh', [0, 4, 4, 4], $options);
        $provider->requestTokenHex('ijklmnop', [0, 4, 4, 4], $options);

        self::assertSame(1, $client->tokenRequests);
        self::assertContains('Authorization: Bearer token-without-exp', $client->calls[2]['headers']);
    }

    public function test_request_token_hex_refreshes_an_expiring_oauth_token(): void
    {
        // expires_in is raised to a 60s floor; a cached token within 30s of expiring is requested again.
        $client = $this->tsaClient(oauthBody: '{"access_token":"short","expires_in":1}');
        $provider = new NativeRfc3161TimestampTokenProvider($client);
        $options = $this->oauthOptions();

        $provider->requestTokenHex('abcdefgh', [0, 4, 4, 4], $options);
        $cache = new \ReflectionProperty(NativeRfc3161TimestampTokenProvider::class, 'oauthTokenCache');
        /** @var array<string, array{token:string,expiresAt:int}> $entries */
        $entries = $cache->getValue();
        $key = array_key_first($entries);
        self::assertNotNull($key);
        self::assertGreaterThanOrEqual(time() + 59, $entries[$key]['expiresAt']);
        $entries[$key]['expiresAt'] = time() + 10;
        $cache->setValue(null, $entries);

        $provider->requestTokenHex('abcdefgh', [0, 4, 4, 4], $options);

        self::assertSame(2, $client->tokenRequests);
    }

    public function test_request_token_hex_throws_when_oauth_token_response_is_invalid(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Invalid OAuth token response from TSA auth endpoint.');

        (new NativeRfc3161TimestampTokenProvider($this->tsaClient(oauthBody: '{"token_type":"Bearer"}')))
            ->requestTokenHex('abcdef', [0, 3, 3, 3], $this->oauthOptions());
    }

    public function test_request_token_hex_throws_when_oauth_endpoint_returns_non_200(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not fetch OAuth token from TSA auth endpoint. Status: 401. Transport error: none. Body: denied');

        (new NativeRfc3161TimestampTokenProvider($this->tsaClient(oauthBody: 'denied', oauthStatus: 401)))
            ->requestTokenHex('abcdef', [0, 3, 3, 3], $this->oauthOptions());
    }

    private function oauthOptions(): TimestampOptionsDto
    {
        return new TimestampOptionsDto(
            tsaUrl: self::TSA_URL,
            oauthClientId: 'id',
            oauthClientSecret: 'secret',
            oauthTokenUrl: self::TOKEN_URL,
        );
    }

    private function requestWithReply(string $reply, int $status = 200): string
    {
        $client = new class($reply, $status) implements HttpClientInterface
        {
            public function __construct(private readonly string $reply, private readonly int $status) {}

            public function request(string $method, string $url, array $headers = [], string $body = '', int $timeoutSeconds = 10, bool $followRedirects = false): HttpResponse
            {
                return new HttpResponse($this->status, $this->reply);
            }
        };

        return (new NativeRfc3161TimestampTokenProvider($client))->requestTokenHex(
            self::DOCUMENT,
            [0, 4, 8, 4],
            new TimestampOptionsDto(tsaUrl: self::TSA_URL),
        );
    }

    /**
     * An HTTP client that issues real TimeStampResp values with `openssl ts -reply` and, for the
     * OAuth endpoint, returns the given body.
     */
    private function tsaClient(int $tsaStatus = 200, string $oauthBody = '', int $oauthStatus = 200): HttpClientInterface
    {
        return new class(self::$dir, $tsaStatus, $oauthBody, $oauthStatus) implements HttpClientInterface
        {
            /** @var list<array{method:string,url:string,headers:array<int,string>,body:string}> */
            public array $calls = [];

            public int $tokenRequests = 0;

            public string $lastReply = '';

            public function __construct(
                private readonly string $dir,
                private readonly int $tsaStatus,
                private readonly string $oauthBody,
                private readonly int $oauthStatus,
            ) {}

            public function request(string $method, string $url, array $headers = [], string $body = '', int $timeoutSeconds = 10, bool $followRedirects = false): HttpResponse
            {
                $this->calls[] = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body];

                if ($url === 'https://tsa.local/token') {
                    $this->tokenRequests++;

                    return new HttpResponse($this->oauthStatus, $this->oauthBody);
                }

                $query = $this->dir.'/request-'.count($this->calls).'.tsq';
                $reply = $this->dir.'/request-'.count($this->calls).'.tsr';
                file_put_contents($query, $body);
                exec(sprintf(
                    'openssl ts -reply -config %s -queryfile %s -out %s 2>&1',
                    escapeshellarg($this->dir.'/tsa.cnf'),
                    escapeshellarg($query),
                    escapeshellarg($reply),
                ), $output, $exitCode);
                if ($exitCode !== 0) {
                    throw new \RuntimeException(implode("\n", $output));
                }

                $this->lastReply = (string) file_get_contents($reply);

                return new HttpResponse($this->tsaStatus, $this->lastReply);
            }
        };
    }

    /**
     * The timeStampToken of a TimeStampResp, cut out with `openssl ts -reply -token_out` for comparison.
     */
    private function tokenOf(string $reply): string
    {
        $in = self::$dir.'/compare.tsr';
        $out = self::$dir.'/compare.tst';
        file_put_contents($in, $reply);
        self::shell(sprintf('openssl ts -reply -in %s -token_out -out %s', escapeshellarg($in), escapeshellarg($out)));

        return (string) file_get_contents($out);
    }

    private static function shell(string $script): void
    {
        exec('{ set -e; '.$script."\n} 2>&1", $output, $exitCode);
        if ($exitCode !== 0) {
            self::fail(implode("\n", $output));
        }
    }
}
