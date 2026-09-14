<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Application\Contract\DefaultTimestampOptionsProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;

final class DefaultTimestampOptionsProvider implements DefaultTimestampOptionsProviderInterface
{
    public function makeDefault(): TimestampOptionsDto
    {
        return new TimestampOptionsDto(
            tsaUrl: 'https://freetsa.org/tsr',
            hashAlgorithm: 'sha256',
            certReq: true,
            username: null,
            password: null,
            timeoutSeconds: 15,
        );
    }
}
