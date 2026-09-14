<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ProcessResult;

interface ProcessRunnerInterface
{
    public function run(string $command): ProcessResult;
}
