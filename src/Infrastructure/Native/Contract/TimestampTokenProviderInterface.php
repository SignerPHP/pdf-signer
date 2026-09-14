<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;

interface TimestampTokenProviderInterface
{
    /**
     * @param  array{0:int,1:int,2:int,3:int}  $byteRange
     */
    public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string;
}
