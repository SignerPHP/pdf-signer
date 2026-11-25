<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

/**
 * A token copied verbatim on output: number, name, boolean, null, keyword or indirect reference ("12 0 R").
 */
final readonly class PdfRawNode implements PdfNode
{
    public function __construct(public string $token) {}
}
