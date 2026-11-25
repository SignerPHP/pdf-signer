<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp;

use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;

/**
 * A successful id-pkix-ocsp-basic OCSPResponse (RFC 6960 section 4.2.1), parsed without the OpenSSL CLI.
 *
 * Parsing does not imply trust: the signature over tbsResponseData and the responder's
 * authority are checked by the caller.
 */
final readonly class OcspResponse
{
    private const BASIC_RESPONSE_OID = '1.3.6.1.5.5.7.48.1.1';

    private const NONCE_OID = '1.3.6.1.5.5.7.48.1.2';

    private const SIGNATURE_DIGESTS = [
        '1.2.840.113549.1.1.5' => 'sha1',
        '1.2.840.113549.1.1.14' => 'sha224',
        '1.2.840.113549.1.1.11' => 'sha256',
        '1.2.840.113549.1.1.12' => 'sha384',
        '1.2.840.113549.1.1.13' => 'sha512',
        '1.2.840.10045.4.1' => 'sha1',
        '1.2.840.10045.4.3.1' => 'sha224',
        '1.2.840.10045.4.3.2' => 'sha256',
        '1.2.840.10045.4.3.3' => 'sha384',
        '1.2.840.10045.4.3.4' => 'sha512',
    ];

    /**
     * @param  list<OcspSingleResponse>  $responses
     * @param  list<string>  $certificates  DER certificates the responder included
     * @param  ?string  $nonce  DER value of the nonce extension, when the responder returned one
     */
    private function __construct(
        public string $tbsResponseData,
        public ?string $signatureDigest,
        public string $signature,
        public array $certificates,
        public array $responses,
        public ?string $nonce,
    ) {}

    /**
     * @return ?self null unless $der is a well-formed, successful basic OCSP response
     */
    public static function parse(string $der): ?self
    {
        try {
            return self::parseStrict($der);
        } catch (\UnexpectedValueException) {
            return null;
        }
    }

    private static function parseStrict(string $der): ?self
    {
        $outer = self::children(self::expect($der, 0x30));
        if (count($outer) !== 2 || $outer[0][0] !== 0x0A || $outer[0][1] !== "\x00" || $outer[1][0] !== 0xA0) {
            return null; // responseStatus other than successful(0), or no responseBytes
        }

        $responseBytes = self::children(self::expect($outer[1][1], 0x30));
        if (count($responseBytes) !== 2 || self::oid($responseBytes[0]) !== self::BASIC_RESPONSE_OID || $responseBytes[1][0] !== 0x04) {
            return null;
        }

        $basic = self::children(self::expect($responseBytes[1][1], 0x30));
        if (count($basic) < 3 || $basic[0][0] !== 0x30 || $basic[1][0] !== 0x30 || $basic[2][0] !== 0x03) {
            return null;
        }

        $certificates = [];
        if (isset($basic[3]) && $basic[3][0] === 0xA0) {
            foreach (self::children(self::expect($basic[3][1], 0x30)) as $certificate) {
                $certificates[] = $certificate[2];
            }
        }

        [$responses, $nonce] = self::responseData($basic[0][1]);

        return new self(
            tbsResponseData: $basic[0][2],
            signatureDigest: self::SIGNATURE_DIGESTS[self::oid(self::children($basic[1][1])[0] ?? [0, '', ''])] ?? null,
            signature: substr($basic[2][1], 1),
            certificates: $certificates,
            responses: $responses,
            nonce: $nonce,
        );
    }

    /**
     * @return array{0: list<OcspSingleResponse>, 1: ?string}
     */
    private static function responseData(string $tbs): array
    {
        $fields = self::children($tbs);
        if (($fields[0][0] ?? null) === 0xA0) {
            array_shift($fields); // version
        }

        // responderID, producedAt, responses, [1] responseExtensions
        if (count($fields) < 3 || $fields[2][0] !== 0x30) {
            throw new \UnexpectedValueException('Malformed OCSP ResponseData.');
        }

        $responses = array_map(self::singleResponse(...), self::children($fields[2][1]));

        $nonce = null;
        if (isset($fields[3]) && $fields[3][0] === 0xA1) {
            foreach (self::children(self::expect($fields[3][1], 0x30)) as $extension) {
                $parts = self::children($extension[1]);
                $value = end($parts);
                if ($value !== false && self::oid($parts[0]) === self::NONCE_OID) {
                    $nonce = self::expect($value[2], 0x04);
                }
            }
        }

        return [$responses, $nonce];
    }

    /**
     * @param  array{0: int, 1: string, 2: string}  $node
     */
    private static function singleResponse(array $node): OcspSingleResponse
    {
        $fields = self::children(self::expect($node[2], 0x30));
        $certId = self::children(self::expect($fields[0][2] ?? '', 0x30));
        if (count($fields) < 3 || count($certId) !== 4) {
            throw new \UnexpectedValueException('Malformed OCSP SingleResponse.');
        }

        $nextUpdate = null;
        foreach (array_slice($fields, 3) as $optional) {
            if ($optional[0] === 0xA0) {
                $nextUpdate = self::generalizedTime(self::expect($optional[1], 0x18));
            }
        }

        [$statusTag, $statusValue] = $fields[1];
        $revocationTime = null;
        $reason = null;
        $status = match ($statusTag) {
            0x80 => OcspSingleResponse::GOOD,
            0xA1 => OcspSingleResponse::REVOKED,
            0x82 => OcspSingleResponse::UNKNOWN,
            default => throw new \UnexpectedValueException('Unknown OCSP certStatus.'),
        };
        if ($status === OcspSingleResponse::REVOKED) {
            $revoked = self::children($statusValue);
            $revocationTime = self::generalizedTime(self::expect($revoked[0][2] ?? '', 0x18));
            if (isset($revoked[1]) && $revoked[1][0] === 0xA0) {
                $reason = ord(self::expect($revoked[1][1], 0x0A));
            }
        }

        return new OcspSingleResponse(
            hashAlgorithmOid: self::oid(self::children(self::expect($certId[0][2], 0x30))[0] ?? [0, '', '']),
            issuerNameHash: self::expect($certId[1][2], 0x04),
            issuerKeyHash: self::expect($certId[2][2], 0x04),
            serialNumberDer: $certId[3][2],
            status: $status,
            thisUpdate: self::generalizedTime(self::expect($fields[2][2], 0x18)),
            nextUpdate: $nextUpdate,
            revocationTime: $revocationTime,
            revocationReason: $reason,
        );
    }

    /**
     * @return list<array{0: int, 1: string, 2: string}> tag, value and full TLV of each element
     */
    private static function children(string $contents): array
    {
        $children = [];
        for ($offset = 0; $offset < strlen($contents);) {
            $start = $offset;
            [$tag, $value, $offset] = Der::readTlvStrict($contents, $offset);
            $children[] = [$tag, $value, substr($contents, $start, $offset - $start)];
        }

        return $children;
    }

    /**
     * The value of $der, which must be exactly one TLV with the given tag.
     */
    private static function expect(string $der, int $tag): string
    {
        [$actual, $value, $end] = Der::readTlvStrict($der);
        if ($actual !== $tag || $end !== strlen($der)) {
            throw new \UnexpectedValueException('Unexpected DER element.');
        }

        return $value;
    }

    /**
     * @param  array{0: int, 1: string, 2: string}  $node
     */
    private static function oid(array $node): string
    {
        if ($node[0] !== 0x06 || $node[1] === '') {
            return '';
        }

        $arcs = [];
        $value = 0;
        foreach (str_split($node[1]) as $byte) {
            $value = ($value << 7) | (ord($byte) & 0x7F);
            if ((ord($byte) & 0x80) === 0) {
                $arcs[] = $value;
                $value = 0;
            }
        }

        $first = min(intdiv($arcs[0], 40), 2);

        return implode('.', [$first, $arcs[0] - 40 * $first, ...array_slice($arcs, 1)]);
    }

    private static function generalizedTime(string $value): int
    {
        $time = preg_match('/^(\d{14})(?:\.\d+)?Z$/', $value, $matches) === 1
            ? \DateTimeImmutable::createFromFormat('!YmdHis', $matches[1], new \DateTimeZone('UTC'))
            : false;
        if ($time === false) {
            throw new \UnexpectedValueException('Invalid GeneralizedTime.');
        }

        return $time->getTimestamp();
    }
}
