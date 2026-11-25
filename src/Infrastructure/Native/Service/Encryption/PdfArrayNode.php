<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

final readonly class PdfArrayNode implements PdfNode
{
    /**
     * @param  list<PdfNode>  $items
     */
    public function __construct(public array $items) {}
}
