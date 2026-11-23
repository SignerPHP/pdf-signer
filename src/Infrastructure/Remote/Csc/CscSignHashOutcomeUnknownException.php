<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\Csc;

use SignerPHP\PdfSigner\Domain\Exception\SignerException;

/**
 * A signHash submission may have reached the private key before its outcome
 * became unavailable or invalid. Callers must reconcile, not submit again.
 */
final class CscSignHashOutcomeUnknownException extends SignerException {}
