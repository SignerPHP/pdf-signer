<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimestampTokenProviderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\StrictDerReader;

/**
 * Requests an RFC 3161 timestamp token over HTTP. The TimeStampReq is built and the TimeStampResp
 * is read in PHP, so no external binary is needed.
 */
final class NativeRfc3161TimestampTokenProvider implements TimestampTokenProviderInterface
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

    public function __construct(
        private readonly HttpClientInterface $httpClient = new CurlHttpClient,
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
     * A positive 128-bit INTEGER nonce with 126 random bits: the top byte is kept in 0x40..0x7F
     * so the value is minimally encoded and needs no sign byte.
     */
    private function generateNonce(): string
    {
        $nonce = random_bytes(16);
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
     * (a CMS ContentInfo), after checking that the TSTInfo answers this request. The reply must be
     * strict DER, and each structure read must be complete, with nothing after it.
     */
    private function extractTimeStampToken(string $reply, string $hashOid, string $digest, string $nonce): string
    {
        try {
            // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }
            $response = $this->children($this->exact($reply, 0x30, 'TimeStampResp'), 1, 2, 'TimeStampResp');
            $this->assertGranted($this->value($response[0], 0x30, 'PKIStatusInfo'));

            if (! isset($response[1])) {
                throw new \UnexpectedValueException('TimeStampResp has no timeStampToken.');
            }

            $token = $response[1][2];
            $tstInfo = $this->readTstInfo($this->value($response[1], 0x30, 'timeStampToken'));
            $this->assertTstInfoMatchesRequest($tstInfo, $hashOid, $digest, $nonce);
        } catch (\UnexpectedValueException $e) {
            throw new SignProcessException('Could not extract RFC3161 token from TSA response. '.$e->getMessage(), 0, $e);
        }

        return $token;
    }

    /**
     * PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText OPTIONAL,
     * failInfo PKIFailureInfo OPTIONAL }.
     */
    private function assertGranted(string $statusInfo): void
    {
        $elements = $this->children($statusInfo, 1, 3, 'PKIStatusInfo');
        $status = $this->smallInteger($this->value($elements[0], 0x02, 'PKIStatus'));

        $texts = [];
        $failures = [];
        foreach (array_slice($elements, 1) as $element) {
            if ($element[0] === 0x30 && $texts === [] && $failures === []) {
                $texts = $this->freeText($element[1]);
            } elseif ($element[0] === 0x03 && $failures === []) {
                $failures = $this->failureInfo($element[1]);
            } else {
                throw new \UnexpectedValueException('PKIStatusInfo is malformed.');
            }
        }

        if ($status === 0 || $status === 1) {
            return;
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
        return array_map(
            fn (array $text): string => $this->value($text, 0x0C, 'PKIFreeText'),
            StrictDerReader::children($sequence),
        );
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
    private function readTstInfo(string $contentInfo): string
    {
        $elements = $this->children($contentInfo, 2, 2, 'timeStampToken');
        if ($this->value($elements[0], 0x06, 'timeStampToken content type') !== $this->oidContents(self::OID_SIGNED_DATA)) {
            throw new \UnexpectedValueException('timeStampToken is not a CMS SignedData.');
        }

        $explicit = $this->children($this->value($elements[1], 0xA0, 'SignedData content'), 1, 1, 'SignedData content');
        // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, certificates [0] OPTIONAL,
        // crls [1] OPTIONAL, signerInfos }
        $signedData = $this->children($this->value($explicit[0], 0x30, 'SignedData'), 4, 6, 'SignedData');

        $encapContentInfo = $this->children($this->value($signedData[2], 0x30, 'EncapsulatedContentInfo'), 2, 2, 'EncapsulatedContentInfo');
        if ($this->value($encapContentInfo[0], 0x06, 'eContentType') !== $this->oidContents(self::OID_TST_INFO)) {
            throw new \UnexpectedValueException('timeStampToken does not encapsulate a TSTInfo.');
        }

        $eContent = $this->children($this->value($encapContentInfo[1], 0xA0, 'eContent'), 1, 1, 'eContent');

        return $this->value($eContent[0], 0x04, 'eContent');
    }

    /**
     * TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime,
     * accuracy OPTIONAL, ordering DEFAULT FALSE, nonce OPTIONAL, tsa [0] OPTIONAL, extensions [1] OPTIONAL }.
     */
    private function assertTstInfoMatchesRequest(string $tstInfoDer, string $hashOid, string $digest, string $nonce): void
    {
        $tstInfo = $this->children($this->exact($tstInfoDer, 0x30, 'TSTInfo'), 5, 10, 'TSTInfo');

        // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
        $messageImprint = $this->children($this->value($tstInfo[2], 0x30, 'TSTInfo messageImprint'), 2, 2, 'TSTInfo messageImprint');
        $algorithm = $this->children($this->value($messageImprint[0], 0x30, 'TSTInfo hashAlgorithm'), 1, 2, 'TSTInfo hashAlgorithm');
        $oid = $this->value($algorithm[0], 0x06, 'TSTInfo hashAlgorithm');
        $hashedMessage = $this->value($messageImprint[1], 0x04, 'TSTInfo hashedMessage');
        if ($oid !== substr($hashOid, 2) || $hashedMessage !== $digest) {
            throw new SignProcessException('TSA response message imprint does not match the timestamp request.');
        }

        foreach (array_slice($tstInfo, 5) as [$tag, $value]) {
            if ($tag === 0x02) {
                if ($value !== $nonce) {
                    throw new SignProcessException('TSA response nonce does not match the timestamp request.');
                }

                return;
            }
        }

        throw new SignProcessException('TSA response does not echo the timestamp request nonce.');
    }

    /**
     * The value of the single element that must span all of $der.
     */
    private function exact(string $der, int $expectedTag, string $what): string
    {
        [$tag, $value] = StrictDerReader::readExact($der);

        return $this->value([$tag, $value], $expectedTag, $what);
    }

    /**
     * @return list<array{0:int,1:string,2:string}>
     */
    private function children(string $contents, int $min, int $max, string $what): array
    {
        $children = StrictDerReader::children($contents);
        if (count($children) < $min || count($children) > $max) {
            throw new \UnexpectedValueException($what.' is malformed.');
        }

        return $children;
    }

    /**
     * @param  array{0:int,1:string,2?:string}  $element
     */
    private function value(array $element, int $expectedTag, string $what): string
    {
        if ($element[0] !== $expectedTag) {
            throw new \UnexpectedValueException($what.' is malformed.');
        }

        return $element[1];
    }

    private function oidContents(string $oid): string
    {
        return substr(Der::objectIdentifier($oid), 2);
    }
}
