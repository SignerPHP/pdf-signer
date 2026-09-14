<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\Contract;

use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;

interface DefaultTimestampOptionsProviderInterface
{
    public function makeDefault(): TimestampOptionsDto;
}
