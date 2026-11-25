<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

/**
 * A literal or hexadecimal string, holding its decoded bytes.
 */
final readonly class PdfStringNode implements PdfNode
{
    public function __construct(public string $bytes) {}
}
