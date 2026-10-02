<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\DTO;

enum SigningInputType: string
{
    case Data = 'data';
    case Digest = 'digest';
}
