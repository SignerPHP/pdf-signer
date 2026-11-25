<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp;

/**
 * One SingleResponse of a BasicOCSPResponse (RFC 6960 section 4.2.1).
 */
final readonly class OcspSingleResponse
{
    public const GOOD = 'good';

    public const REVOKED = 'revoked';

    public const UNKNOWN = 'unknown';

    private const REASONS = [
        0 => 'unspecified',
        1 => 'keyCompromise',
        2 => 'cACompromise',
        3 => 'affiliationChanged',
        4 => 'superseded',
        5 => 'cessationOfOperation',
        6 => 'certificateHold',
        8 => 'removeFromCRL',
        9 => 'privilegeWithdrawn',
        10 => 'aACompromise',
    ];

    public function __construct(
        public string $hashAlgorithmOid,
        public string $issuerNameHash,
        public string $issuerKeyHash,
        public string $serialNumberDer,
        public string $status,
        public int $thisUpdate,
        public ?int $nextUpdate,
        public ?int $revocationTime = null,
        public ?int $revocationReason = null,
    ) {}

    /**
     * RFC 6960 section 3.2 / OpenSSL OCSP_check_validity(): thisUpdate not in the future, nextUpdate not in
     * the past (both with clock skew) and, when the responder gives no nextUpdate, a bounded status age.
     */
    public function isCurrent(int $now, int $clockSkewSeconds, int $maxStatusAgeSeconds): bool
    {
        if ($this->thisUpdate > $now + $clockSkewSeconds) {
            return false;
        }

        if ($this->nextUpdate === null) {
            return $this->thisUpdate >= $now - $maxStatusAgeSeconds;
        }

        return $this->nextUpdate >= $now - $clockSkewSeconds && $this->nextUpdate >= $this->thisUpdate;
    }

    public function revocationReasonName(): ?string
    {
        return $this->revocationReason === null
            ? null
            : (self::REASONS[$this->revocationReason] ?? 'reason '.$this->revocationReason);
    }
}
