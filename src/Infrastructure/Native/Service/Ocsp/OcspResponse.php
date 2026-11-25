<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp;

/**
 * A successful id-pkix-ocsp-basic OCSPResponse (RFC 6960 section 4.2.1), parsed strictly
 * without the OpenSSL CLI: DER only, every field in its place, no unknown or repeated
 * elements, v1 only.
 *
 * Parsing does not imply trust: the signature over tbsResponseData, the responder's
 * identity (ResponderID) and its authority are checked by the caller.
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

    /** CRLReason values (RFC 5280 section 5.3.1); 7 is not used. */
    private const REVOCATION_REASONS = [0, 1, 2, 3, 4, 5, 6, 8, 9, 10];

    /**
     * @param  ?string  $responderName  ResponderID byName: the responder's subject Name as DER
     * @param  ?string  $responderKeyHash  ResponderID byKey: SHA-1 of the responder's subjectPublicKey bits
     * @param  list<OcspSingleResponse>  $responses
     * @param  list<string>  $certificates  DER certificates the responder included
     * @param  ?string  $nonce  DER value of the nonce extension, when the responder returned one
     */
    private function __construct(
        public string $tbsResponseData,
        public ?string $signatureDigest,
        public string $signature,
        public array $certificates,
        public ?string $responderName,
        public ?string $responderKeyHash,
        public int $producedAt,
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

    /**
     * Whether $certificate is the responder the ResponderID names (RFC 6960 section 4.2.2.3).
     */
    public function identifies(OcspCertificate $certificate): bool
    {
        return $this->responderName !== null
            ? hash_equals($this->responderName, $certificate->subjectDer)
            : hash_equals((string) $this->responderKeyHash, sha1($certificate->publicKeyBits, true));
    }

    private static function parseStrict(string $der): ?self
    {
        // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }
        $outer = OcspDer::children($der);
        if ($outer === [] || count($outer) > 2 || OcspDer::smallNumber($outer[0][2], 0x0A) !== 0) {
            return null;
        }
        if (count($outer) !== 2) {
            throw new \UnexpectedValueException('Successful OCSP response without responseBytes.');
        }

        $responseBytes = OcspDer::children(OcspDer::expect($outer[1][2], 0xA0));
        if (count($responseBytes) !== 2 || OcspDer::oid($responseBytes[0][2]) !== self::BASIC_RESPONSE_OID) {
            return null;
        }

        // BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm, signature BIT STRING, certs [0] EXPLICIT OPTIONAL }
        $basic = OcspDer::children(OcspDer::expect($responseBytes[1][2], 0x04));
        if (count($basic) < 3 || count($basic) > 4) {
            throw new \UnexpectedValueException('Malformed BasicOCSPResponse.');
        }

        $certificates = [];
        if (isset($basic[3])) {
            foreach (OcspDer::children(OcspDer::expect($basic[3][2], 0xA0)) as $certificate) {
                if ($certificate[0] !== OcspDer::SEQUENCE) {
                    throw new \UnexpectedValueException('Malformed certificate in BasicOCSPResponse.');
                }
                $certificates[] = $certificate[2];
            }
        }

        $signature = OcspDer::expect($basic[2][2], 0x03);
        if (strlen($signature) < 2 || $signature[0] !== "\x00") {
            throw new \UnexpectedValueException('Malformed OCSP signature.');
        }

        $data = self::responseData($basic[0][2]);

        return new self(
            tbsResponseData: $basic[0][2],
            signatureDigest: self::SIGNATURE_DIGESTS[self::algorithm($basic[1][2])] ?? null,
            signature: substr($signature, 1),
            certificates: $certificates,
            responderName: $data['responderName'],
            responderKeyHash: $data['responderKeyHash'],
            producedAt: $data['producedAt'],
            responses: $data['responses'],
            nonce: $data['nonce'],
        );
    }

    /**
     * ResponseData ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1, responderID, producedAt,
     * responses SEQUENCE OF SingleResponse, responseExtensions [1] EXPLICIT OPTIONAL }
     *
     * @return array{responderName: ?string, responderKeyHash: ?string, producedAt: int, responses: list<OcspSingleResponse>, nonce: ?string}
     */
    private static function responseData(string $der): array
    {
        $fields = OcspDer::children($der);
        if (($fields[0][0] ?? null) === 0xA0) {
            if (OcspDer::smallNumber(OcspDer::expect($fields[0][2], 0xA0), 0x02) !== 0) {
                throw new \UnexpectedValueException('Unsupported OCSP ResponseData version.');
            }
            array_shift($fields);
        }
        if (count($fields) < 3 || count($fields) > 4) {
            throw new \UnexpectedValueException('Malformed OCSP ResponseData.');
        }

        [$responderTag, $responderValue] = $fields[0];
        $responderName = null;
        $responderKeyHash = null;
        if ($responderTag === 0xA1) {
            $responderName = $responderValue;
            OcspDer::children($responderName); // a Name is a SEQUENCE
        } elseif ($responderTag === 0xA2) {
            $responderKeyHash = OcspDer::expect($responderValue, 0x04);
            if (strlen($responderKeyHash) !== 20) {
                throw new \UnexpectedValueException('ResponderID byKey must be a SHA-1 hash.');
            }
        } else {
            throw new \UnexpectedValueException('Unknown ResponderID.');
        }

        $responses = array_map(
            static fn (array $single): OcspSingleResponse => self::singleResponse($single[2]),
            OcspDer::children($fields[2][2]),
        );
        if ($responses === []) {
            throw new \UnexpectedValueException('OCSP response without SingleResponse.');
        }

        $extensions = isset($fields[3]) ? OcspDer::extensions(OcspDer::expect($fields[3][2], 0xA1)) : [];

        return [
            'responderName' => $responderName,
            'responderKeyHash' => $responderKeyHash,
            'producedAt' => OcspDer::generalizedTime($fields[1][2]),
            'responses' => $responses,
            'nonce' => $extensions[self::NONCE_OID] ?? null,
        ];
    }

    /**
     * SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate, nextUpdate [0] EXPLICIT OPTIONAL,
     * singleExtensions [1] EXPLICIT OPTIONAL }
     */
    private static function singleResponse(string $der): OcspSingleResponse
    {
        $fields = OcspDer::children($der);
        if (count($fields) < 3) {
            throw new \UnexpectedValueException('Malformed OCSP SingleResponse.');
        }

        // CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash OCTET STRING, issuerKeyHash OCTET STRING, serialNumber INTEGER }
        $certId = OcspDer::children($fields[0][2]);
        if (count($certId) !== 4) {
            throw new \UnexpectedValueException('Malformed OCSP CertID.');
        }

        $nextUpdate = null;
        $optional = array_slice($fields, 3);
        $tags = array_column($optional, 0);
        if (! in_array($tags, [[], [0xA0], [0xA1], [0xA0, 0xA1]], true)) {
            throw new \UnexpectedValueException('Unexpected element in OCSP SingleResponse.');
        }
        foreach ($optional as [$tag, , $element]) {
            if ($tag === 0xA0) {
                $nextUpdate = OcspDer::generalizedTime(OcspDer::expect($element, 0xA0));
            } else {
                OcspDer::extensions(OcspDer::expect($element, 0xA1));
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
            // RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, revocationReason [0] EXPLICIT CRLReason OPTIONAL }
            $revoked = OcspDer::children($fields[1][2], 0xA1);
            if ($revoked === [] || count($revoked) > 2) {
                throw new \UnexpectedValueException('Malformed OCSP RevokedInfo.');
            }
            $revocationTime = OcspDer::generalizedTime($revoked[0][2]);
            if (isset($revoked[1])) {
                $reason = OcspDer::smallNumber(OcspDer::expect($revoked[1][2], 0xA0), 0x0A);
                if (! in_array($reason, self::REVOCATION_REASONS, true)) {
                    throw new \UnexpectedValueException('Unknown CRLReason.');
                }
            }
        } elseif ($statusValue !== '') {
            throw new \UnexpectedValueException('OCSP good/unknown status must be NULL.');
        }

        return new OcspSingleResponse(
            hashAlgorithmOid: self::algorithm($certId[0][2]),
            issuerNameHash: OcspDer::expect($certId[1][2], 0x04),
            issuerKeyHash: OcspDer::expect($certId[2][2], 0x04),
            serialNumberDer: OcspDer::integer($certId[3][2]),
            status: $status,
            thisUpdate: OcspDer::generalizedTime($fields[2][2]),
            nextUpdate: $nextUpdate,
            revocationTime: $revocationTime,
            revocationReason: $reason,
        );
    }

    /**
     * AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
     */
    private static function algorithm(string $der): string
    {
        $parts = OcspDer::children($der);
        if ($parts === [] || count($parts) > 2) {
            throw new \UnexpectedValueException('Malformed AlgorithmIdentifier.');
        }

        return OcspDer::oid($parts[0][2]);
    }
}
