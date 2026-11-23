<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Domain\Exception;

/**
 * A remote signing operation may have executed, but no valid result is available.
 * The caller must reconcile the attempt before considering another submission.
 */
class RemoteSigningOutcomeUnknownException extends SignerException {}
