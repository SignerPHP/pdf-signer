<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimestampTokenProviderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;

/**
 * Requests an RFC 3161 timestamp token over HTTP. The TimeStampReq is built and the TimeStampResp
 * is read in PHP, so no external binary is needed.
 */
final class OpenSslRfc3161TimestampTokenProvider implements TimestampTokenProviderInterface
{
    private const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

    private const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';

    private const PKI_STATUS = [
        0 => 'granted',
        1 => 'grantedWithMods',
        2 => 'rejection',
        3 => 'waiting',
        4 => 'revocationWarning',
        5 => 'revocationNotification',
    ];

    private const PKI_FAILURE_INFO = [
        0 => 'badAlg',
        2 => 'badRequest',
        5 => 'badDataFormat',
        14 => 'timeNotAvailable',
        15 => 'unacceptedPolicy',
        16 => 'unacceptedExtension',
        17 => 'addInfoNotAvailable',
        25 => 'systemFailure',
    ];

    /**
     * @var array<string, array{token:string,expiresAt:int}>
     */
    private static array $oauthTokenCache = [];

    /**
     * @param  ProcessRunnerInterface  $processRunner  Deprecated and unused since the request and the
     *                                                 response are handled natively; kept for backward compatibility.
     */
    public function __construct(
        private readonly HttpClientInterface $httpClient = new CurlHttpClient,
        /** @deprecated No longer used: no external process is run anymore. */
        private readonly ProcessRunnerInterface $processRunner = new ShellProcessRunner,
    ) {}

    public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string
    {
        $toTimestamp = $this->extractByteRangeData($signableDocument, $byteRange);

        $hashOid = Der::objectIdentifier($this->hashAlgorithmOid($options->hashAlgorithm));
        $digest = hash($options->hashAlgorithm->value, $toTimestamp, true);
        $nonce = $this->generateNonce();

        $query = $this->buildTimeStampRequest($hashOid, $digest, $nonce, $options->certReq);
        $reply = $this->requestTimestampReply($options, $query);
        $token = $this->extractTimeStampToken($reply, $hashOid, $digest, $nonce);

        return strtoupper(bin2hex($token));
    }

    /**
     * @param  array{0:int,1:int,2:int,3:int}  $byteRange
     */
    private function extractByteRangeData(string $document, array $byteRange): string
    {
        [$offset1, $length1, $offset2, $length2] = $byteRange;

        return substr($document, $offset1, $length1).substr($document, $offset2, $length2);
    }

    private function hashAlgorithmOid(HashAlgorithm $algorithm): string
    {
        return match ($algorithm) {
            HashAlgorithm::Sha1 => '1.3.14.3.2.26',
            HashAlgorithm::Sha224 => '2.16.840.1.101.3.4.2.4',
            HashAlgorithm::Sha256 => '2.16.840.1.101.3.4.2.1',
            HashAlgorithm::Sha384 => '2.16.840.1.101.3.4.2.2',
            HashAlgorithm::Sha512 => '2.16.840.1.101.3.4.2.3',
        };
    }

    /**
     * A positive 64-bit random nonce; the top byte is kept in
     * 0x40..0x7F so the INTEGER is minimally encoded and needs no sign byte.
     */
    private function generateNonce(): string
    {
        $nonce = random_bytes(8);
        $nonce[0] = chr((ord($nonce[0]) & 0x3F) | 0x40);

        return $nonce;
    }

    /**
     * TimeStampReq ::= SEQUENCE { version INTEGER (v1), messageImprint, reqPolicy OPTIONAL,
     * nonce INTEGER OPTIONAL, certReq BOOLEAN DEFAULT FALSE, extensions [0] OPTIONAL } (RFC 3161 §2.4.1).
     */
    private function buildTimeStampRequest(string $hashOid, string $digest, string $nonce, bool $certReq): string
    {
        $messageImprint = Der::sequence(
            Der::sequence($hashOid.Der::null()).Der::octetString($digest)
        );

        return Der::sequence(
            Der::tlv(0x02, "\x01")
            .$messageImprint
            .Der::tlv(0x02, $nonce)
            // certReq is DEFAULT FALSE, so DER leaves it out unless it is true.
            .($certReq ? Der::tlv(0x01, "\xFF") : '')
        );
    }

    private function requestTimestampReply(TimestampOptionsDto $options, string $query): string
    {
        $headerMap = [
            'Content-Type' => 'application/timestamp-query',
            'Accept' => 'application/timestamp-reply',
            'Content-Length' => (string) strlen($query),
        ];

        if ($options->oauthClientId !== null && $options->oauthClientSecret !== null && $options->oauthTokenUrl !== null) {
            $headerMap['Authorization'] = 'Bearer '.$this->requestOAuthBearerToken($options);
        } elseif ($options->username !== null && $options->password !== null) {
            $headerMap['Authorization'] = 'Basic '.base64_encode($options->username.':'.$options->password);
        }

        foreach ($options->customHeaders as $name => $value) {
            $headerMap[$name] = $value;
        }

        $headers = $this->toHeaderList($headerMap);

        $response = $this->httpClient->request(
            'POST',
            $options->tsaUrl,
            $headers,
            $query,
            $options->timeoutSeconds
        );
        if (($response->statusCode !== 200 && $response->statusCode !== 201) || $response->body === '') {
            $bodySnippet = trim(substr($response->body, 0, 240));
            throw new SignProcessException(sprintf(
                'Could not fetch RFC3161 timestamp response from TSA endpoint. Status: %d. Transport error: %s. Body: %s',
                $response->statusCode,
                $response->transportError ?? 'none',
                $bodySnippet !== '' ? $bodySnippet : '[empty]',
            ));
        }

        return $response->body;
    }

    /**
     * @param  array<string, string>  $headers
     * @return array<int, string>
     */
    private function toHeaderList(array $headers): array
    {
        $result = [];
        foreach ($headers as $name => $value) {
            $result[] = $name.': '.$value;
        }

        return $result;
    }

    private function requestOAuthBearerToken(TimestampOptionsDto $options): string
    {
        $cacheKey = hash('sha256', implode('|', [
            (string) $options->oauthTokenUrl,
            (string) $options->oauthClientId,
            (string) $options->oauthClientSecret,
        ]));
        $now = time();

        $cached = self::$oauthTokenCache[$cacheKey] ?? null;
        if ($cached !== null && $cached['expiresAt'] > ($now + 30)) {
            return $cached['token'];
        }

        $content = http_build_query([
            'grant_type' => 'client_credentials',
        ]);

        $headers = [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json',
            'Authorization: Basic '.base64_encode($options->oauthClientId.':'.$options->oauthClientSecret),
            'Content-Length: '.strlen($content),
        ];

        $response = $this->httpClient->request(
            'POST',
            (string) $options->oauthTokenUrl,
            $headers,
            $content,
            $options->timeoutSeconds
        );
        if ($response->statusCode !== 200 || $response->body === '') {
            $bodySnippet = trim(substr($response->body, 0, 240));
            throw new SignProcessException(sprintf(
                'Could not fetch OAuth token from TSA auth endpoint. Status: %d. Transport error: %s. Body: %s',
                $response->statusCode,
                $response->transportError ?? 'none',
                $bodySnippet !== '' ? $bodySnippet : '[empty]',
            ));
        }

        $json = json_decode($response->body, true);
        if (! is_array($json) || ! isset($json['access_token']) || ! is_string($json['access_token']) || $json['access_token'] === '') {
            throw new SignProcessException('Invalid OAuth token response from TSA auth endpoint.');
        }

        $expiresIn = isset($json['expires_in']) && is_numeric($json['expires_in'])
            ? (int) $json['expires_in']
            : 3600;

        self::$oauthTokenCache[$cacheKey] = [
            'token' => $json['access_token'],
            'expiresAt' => $now + max($expiresIn, 60),
        ];

        return $json['access_token'];
    }

    /**
     * Reads a TimeStampResp, checks its PKIStatusInfo and returns the DER of its timeStampToken
     * (a CMS ContentInfo), after checking that the TSTInfo answers this request.
     */
    private function extractTimeStampToken(string $reply, string $hashOid, string $digest, string $nonce): string
    {
        try {
            [$tag, $response] = Der::readTlvStrict($reply);
            $this->expectTag($tag, 0x30, 'TimeStampResp');

            [$tag, $statusInfo, $offset] = Der::readTlvStrict($response);
            $this->expectTag($tag, 0x30, 'PKIStatusInfo');
            $this->assertGranted($statusInfo);

            if ($offset >= strlen($response)) {
                throw new \UnexpectedValueException('TimeStampResp has no timeStampToken.');
            }

            [$tag, , $end] = Der::readTlvStrict($response, $offset);
            $this->expectTag($tag, 0x30, 'timeStampToken');
            $token = substr($response, $offset, $end - $offset);

            $this->assertTstInfoMatchesRequest($this->readTstInfo($token), $hashOid, $digest, $nonce);
        } catch (\UnexpectedValueException $e) {
            throw new SignProcessException('Could not extract RFC3161 token from TSA response. '.$e->getMessage(), 0, $e);
        }

        return $token;
    }

    private function assertGranted(string $statusInfo): void
    {
        [$tag, $statusValue, $offset] = Der::readTlvStrict($statusInfo);
        $this->expectTag($tag, 0x02, 'PKIStatus');
        $status = $this->smallInteger($statusValue);
        if ($status === 0 || $status === 1) {
            return;
        }

        $texts = [];
        $failures = [];
        while ($offset < strlen($statusInfo)) {
            [$tag, $value, $offset] = Der::readTlvStrict($statusInfo, $offset);
            if ($tag === 0x30) {
                $texts = $this->freeText($value);
            } elseif ($tag === 0x03) {
                $failures = $this->failureInfo($value);
            }
        }

        throw new SignProcessException(sprintf(
            'TSA did not grant the timestamp request. Status: %s. Failure info: %s. Status text: %s',
            self::PKI_STATUS[$status] ?? (string) $status,
            $failures !== [] ? implode(', ', $failures) : 'none',
            $texts !== [] ? implode(' | ', $texts) : 'none',
        ));
    }

    private function smallInteger(string $value): int
    {
        if ($value === '' || strlen($value) > 4) {
            throw new \UnexpectedValueException('PKIStatus is not a valid integer.');
        }

        return (int) hexdec(bin2hex($value));
    }

    /**
     * @return list<string>
     */
    private function freeText(string $sequence): array
    {
        $texts = [];
        $offset = 0;
        while ($offset < strlen($sequence)) {
            [, $text, $offset] = Der::readTlvStrict($sequence, $offset);
            $texts[] = $text;
        }

        return $texts;
    }

    /**
     * @return list<string>
     */
    private function failureInfo(string $bitString): array
    {
        $failures = [];
        $bits = substr($bitString, 1);
        for ($bit = 0; $bit < 8 * strlen($bits); $bit++) {
            if ((ord($bits[$bit >> 3]) & (0x80 >> ($bit & 7))) !== 0) {
                $failures[] = self::PKI_FAILURE_INFO[$bit] ?? 'bit '.$bit;
            }
        }

        return $failures;
    }

    /**
     * ContentInfo { id-signedData, [0] SignedData { version, digestAlgorithms,
     * EncapsulatedContentInfo { id-ct-TSTInfo, [0] OCTET STRING TSTInfo }, ... } }.
     */
    private function readTstInfo(string $token): string
    {
        [, $contentInfo] = Der::readTlvStrict($token);
        [$tag, $contentType, $offset] = Der::readTlvStrict($contentInfo);
        if ($tag !== 0x06 || $contentType !== substr(Der::objectIdentifier(self::OID_SIGNED_DATA), 2)) {
            throw new \UnexpectedValueException('timeStampToken is not a CMS SignedData.');
        }

        [$tag, $explicit] = Der::readTlvStrict($contentInfo, $offset);
        $this->expectTag($tag, 0xA0, 'SignedData content');
        [$tag, $signedData] = Der::readTlvStrict($explicit);
        $this->expectTag($tag, 0x30, 'SignedData');

        [, , $offset] = Der::readTlvStrict($signedData);
        [, , $offset] = Der::readTlvStrict($signedData, $offset);
        [$tag, $encapContentInfo] = Der::readTlvStrict($signedData, $offset);
        $this->expectTag($tag, 0x30, 'EncapsulatedContentInfo');

        [$tag, $eContentType, $offset] = Der::readTlvStrict($encapContentInfo);
        if ($tag !== 0x06 || $eContentType !== substr(Der::objectIdentifier(self::OID_TST_INFO), 2)) {
            throw new \UnexpectedValueException('timeStampToken does not encapsulate a TSTInfo.');
        }

        [$tag, $explicit] = Der::readTlvStrict($encapContentInfo, $offset);
        $this->expectTag($tag, 0xA0, 'eContent');
        [$tag, $tstInfo] = Der::readTlvStrict($explicit);
        $this->expectTag($tag, 0x04, 'eContent');

        return $tstInfo;
    }

    /**
     * TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime,
     * accuracy OPTIONAL, ordering DEFAULT FALSE, nonce OPTIONAL, tsa [0] OPTIONAL, extensions [1] OPTIONAL }.
     */
    private function assertTstInfoMatchesRequest(string $tstInfoDer, string $hashOid, string $digest, string $nonce): void
    {
        [$tag, $tstInfo] = Der::readTlvStrict($tstInfoDer);
        $this->expectTag($tag, 0x30, 'TSTInfo');

        [, , $offset] = Der::readTlvStrict($tstInfo);
        [, , $offset] = Der::readTlvStrict($tstInfo, $offset);
        [$tag, $messageImprint, $offset] = Der::readTlvStrict($tstInfo, $offset);
        $this->expectTag($tag, 0x30, 'TSTInfo messageImprint');

        [, $algorithm, $imprintOffset] = Der::readTlvStrict($messageImprint);
        [, $hashedMessage] = Der::readTlvStrict($messageImprint, $imprintOffset);
        [, $oid] = Der::readTlvStrict($algorithm);
        if ($oid !== substr($hashOid, 2) || $hashedMessage !== $digest) {
            throw new SignProcessException('TSA response message imprint does not match the timestamp request.');
        }

        [, , $offset] = Der::readTlvStrict($tstInfo, $offset);
        [, , $offset] = Der::readTlvStrict($tstInfo, $offset);
        while ($offset < strlen($tstInfo)) {
            [$tag, $value, $offset] = Der::readTlvStrict($tstInfo, $offset);
            if ($tag === 0x02) {
                if ($value !== $nonce) {
                    throw new SignProcessException('TSA response nonce does not match the timestamp request.');
                }

                return;
            }
        }

        throw new SignProcessException('TSA response does not echo the timestamp request nonce.');
    }

    private function expectTag(int $tag, int $expected, string $what): void
    {
        if ($tag !== $expected) {
            throw new \UnexpectedValueException($what.' is malformed.');
        }
    }
}
