<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

/**
 * The fields of an X.509 certificate that certification path validation needs, decoded straight
 * from the DER so the result does not depend on how the local OpenSSL build formats them.
 */
final readonly class X509PathCertificate
{
    private const OID_SUBJECT_KEY_IDENTIFIER = '2.5.29.14';

    private const OID_KEY_USAGE = '2.5.29.15';

    private const OID_BASIC_CONSTRAINTS = '2.5.29.19';

    private const OID_AUTHORITY_KEY_IDENTIFIER = '2.5.29.35';

    /**
     * Extensions this validator understands or that OpenSSL accepts without enforcing them here
     * (alternative names, policies, distribution points, authority information access).
     */
    private const RECOGNIZED_EXTENSIONS = [
        self::OID_SUBJECT_KEY_IDENTIFIER,
        self::OID_KEY_USAGE,
        '2.5.29.17', // subjectAltName
        '2.5.29.18', // issuerAltName
        self::OID_BASIC_CONSTRAINTS,
        '2.5.29.30', // nameConstraints
        '2.5.29.31', // cRLDistributionPoints
        '2.5.29.32', // certificatePolicies
        '2.5.29.33', // policyMappings
        self::OID_AUTHORITY_KEY_IDENTIFIER,
        '2.5.29.36', // policyConstraints
        '2.5.29.37', // extKeyUsage
        '2.5.29.54', // inhibitAnyPolicy
        '1.3.6.1.5.5.7.1.1', // authorityInfoAccess
    ];

    /**
     * @param  list<string>  $unrecognizedCriticalExtensions  dotted OIDs
     */
    public function __construct(
        public string $der,
        public string $pem,
        public int $version,
        public string $issuerDer,
        public string $subjectDer,
        public string $subjectPublicKeyInfoDer,
        public int $notBefore,
        public int $notAfter,
        public ?bool $isCa,
        public ?int $pathLength,
        public ?bool $keyCertSign,
        public ?string $subjectKeyIdentifier,
        public ?string $authorityKeyIdentifier,
        public array $unrecognizedCriticalExtensions,
    ) {}

    /**
     * Decodes a DER certificate, or returns null when it is not a well-formed X.509 certificate.
     */
    public static function fromDer(string $der): ?self
    {
        try {
            [$tag, $certificate, $end] = Der::readTlvStrict($der);
            if ($tag !== 0x30 || $end !== strlen($der)) {
                return null;
            }
            [$tbsTag, $tbs] = Der::readTlvStrict($certificate);
            if ($tbsTag !== 0x30) {
                return null;
            }

            $version = 1;
            $offset = 0;
            [$tag, $value, $next] = Der::readTlvStrict($tbs, $offset);
            if ($tag === 0xA0) {
                [, $versionInteger] = Der::readTlvStrict($value);
                $version = ord($versionInteger[strlen($versionInteger) - 1]) + 1;
                $offset = $next;
            }

            $fields = [];
            for ($index = 0; $index < 6; $index++) {
                [$tag, $value, $next] = Der::readTlvStrict($tbs, $offset);
                $fields[] = [$tag, $value, substr($tbs, $offset, $next - $offset)];
                $offset = $next;
            }
            // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
            if ($fields[0][0] !== 0x02 || $fields[2][0] !== 0x30 || $fields[3][0] !== 0x30
                || $fields[4][0] !== 0x30 || $fields[5][0] !== 0x30) {
                return null;
            }

            [$notBeforeTag, $notBeforeValue, $notBeforeEnd] = Der::readTlvStrict($fields[3][1]);
            [$notAfterTag, $notAfterValue] = Der::readTlvStrict($fields[3][1], $notBeforeEnd);
            $notBefore = self::parseTime($notBeforeTag, $notBeforeValue);
            $notAfter = self::parseTime($notAfterTag, $notAfterValue);
            if ($notBefore === null || $notAfter === null) {
                return null;
            }

            $extensions = [];
            while ($offset < strlen($tbs)) {
                [$tag, $value, $offset] = Der::readTlvStrict($tbs, $offset);
                if ($tag === 0xA3) {
                    $extensions = self::readExtensions($value);
                }
            }
        } catch (\Throwable) {
            return null;
        }

        $isCa = null;
        $pathLength = null;
        $keyCertSign = null;
        $subjectKeyIdentifier = null;
        $authorityKeyIdentifier = null;
        $unrecognized = [];
        try {
            foreach ($extensions as [$oid, $critical, $value]) {
                match ($oid) {
                    self::OID_BASIC_CONSTRAINTS => [$isCa, $pathLength] = self::basicConstraints($value),
                    self::OID_KEY_USAGE => $keyCertSign = self::keyCertSign($value),
                    self::OID_SUBJECT_KEY_IDENTIFIER => $subjectKeyIdentifier = self::octetString($value),
                    self::OID_AUTHORITY_KEY_IDENTIFIER => $authorityKeyIdentifier = self::authorityKeyIdentifier($value),
                    default => null,
                };
                if ($critical && ! in_array($oid, self::RECOGNIZED_EXTENSIONS, true)) {
                    $unrecognized[] = $oid;
                }
            }
        } catch (\Throwable) {
            return null;
        }

        return new self(
            der: $der,
            pem: "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END CERTIFICATE-----\n",
            version: $version,
            issuerDer: $fields[2][2],
            subjectDer: $fields[4][2],
            subjectPublicKeyInfoDer: $fields[5][2],
            notBefore: $notBefore,
            notAfter: $notAfter,
            isCa: $isCa,
            pathLength: $pathLength,
            keyCertSign: $keyCertSign,
            subjectKeyIdentifier: $subjectKeyIdentifier,
            authorityKeyIdentifier: $authorityKeyIdentifier,
            unrecognizedCriticalExtensions: $unrecognized,
        );
    }

    public function isSelfIssued(): bool
    {
        return $this->issuerDer === $this->subjectDer;
    }

    /**
     * Same subject and same public key: two encodings of the same CA (e.g. a re-issued root).
     */
    public function hasSameIdentityAs(self $other): bool
    {
        return $this->subjectDer === $other->subjectDer
            && $this->subjectPublicKeyInfoDer === $other->subjectPublicKeyInfoDer;
    }

    public function subjectName(): string
    {
        $parsed = @openssl_x509_parse($this->pem);
        $name = is_array($parsed) ? ($parsed['name'] ?? null) : null;

        return is_string($name) && $name !== '' ? $name : '(unnamed certificate)';
    }

    private static function parseTime(int $tag, string $value): ?int
    {
        if ($tag === 0x17 && preg_match('/^(\d{2})(\d{10})Z$/', $value, $match) === 1) {
            $year = (int) $match[1];
            $value = ($year < 50 ? '20' : '19').$match[1].$match[2];
        } elseif ($tag === 0x18 && preg_match('/^(\d{14})(?:\.\d+)?Z$/', $value, $match) === 1) {
            $value = $match[1];
        } else {
            return null;
        }

        $time = \DateTimeImmutable::createFromFormat('!YmdHis', $value, new \DateTimeZone('UTC'));

        return $time === false ? null : $time->getTimestamp();
    }

    /**
     * @return list<array{0:string,1:bool,2:string}> OID, critical, extnValue contents
     */
    private static function readExtensions(string $explicit): array
    {
        [, $sequence] = Der::readTlvStrict($explicit);
        $extensions = [];
        $offset = 0;
        while ($offset < strlen($sequence)) {
            [, $extension, $offset] = Der::readTlvStrict($sequence, $offset);
            [$oidTag, $oid, $next] = Der::readTlvStrict($extension);
            if ($oidTag !== 0x06) {
                throw new \UnexpectedValueException('Extension without OID.');
            }
            [$tag, $value, $next] = Der::readTlvStrict($extension, $next);
            $critical = false;
            if ($tag === 0x01) {
                $critical = $value !== "\x00";
                [$tag, $value] = Der::readTlvStrict($extension, $next);
            }
            if ($tag !== 0x04) {
                throw new \UnexpectedValueException('Extension value is not an OCTET STRING.');
            }
            $extensions[] = [self::dottedOid($oid), $critical, $value];
        }

        return $extensions;
    }

    private static function dottedOid(string $bytes): string
    {
        $arcs = [];
        $value = 0;
        $length = strlen($bytes);
        for ($i = 0; $i < $length; $i++) {
            $byte = ord($bytes[$i]);
            $value = ($value << 7) | ($byte & 0x7F);
            if (($byte & 0x80) === 0) {
                $arcs[] = $value;
                $value = 0;
            }
        }
        $first = array_shift($arcs) ?? 0;
        $prefix = $first < 80 ? [intdiv($first, 40), $first % 40] : [2, $first - 80];

        return implode('.', [...$prefix, ...$arcs]);
    }

    /**
     * @return array{0:bool,1:?int}
     */
    private static function basicConstraints(string $value): array
    {
        [, $sequence] = Der::readTlvStrict($value);
        $isCa = false;
        $pathLength = null;
        $offset = 0;
        while ($offset < strlen($sequence)) {
            [$tag, $field, $offset] = Der::readTlvStrict($sequence, $offset);
            if ($tag === 0x01) {
                $isCa = $field !== "\x00";
            } elseif ($tag === 0x02) {
                $pathLength = (int) hexdec(bin2hex($field));
            }
        }

        return [$isCa, $pathLength];
    }

    private static function keyCertSign(string $value): bool
    {
        [$tag, $bits] = Der::readTlvStrict($value);
        if ($tag !== 0x03) {
            throw new \UnexpectedValueException('keyUsage is not a BIT STRING.');
        }

        // Bit 5 (keyCertSign) of the first content byte, after the unused-bits count.
        return strlen($bits) > 1 && (ord($bits[1]) & 0x04) !== 0;
    }

    private static function octetString(string $value): string
    {
        [, $bytes] = Der::readTlvStrict($value);

        return $bytes;
    }

    private static function authorityKeyIdentifier(string $value): ?string
    {
        [, $sequence] = Der::readTlvStrict($value);
        $offset = 0;
        while ($offset < strlen($sequence)) {
            [$tag, $field, $offset] = Der::readTlvStrict($sequence, $offset);
            if ($tag === 0x80) {
                return $field;
            }
        }

        return null;
    }
}
