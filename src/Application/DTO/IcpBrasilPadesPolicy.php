<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\DTO;

/**
 * ICP-Brasil PAdES signature policies in force (DOC-ICP-15.03), as published in the
 * official policy list https://politicas.icpbrasil.gov.br/LPA_PAdES.der.
 *
 * Digests are the SHA-256 of each policy document, as listed in the LPA. The previous
 * PAdES versions from June 2025 (AD-RB/AD-RT v1.2, AD-RC/AD-RA v1.3) were revoked on
 * 2025-07-23 and are intentionally not offered.
 */
enum IcpBrasilPadesPolicy: string
{
    case AdRbV1_3 = '2.16.76.1.7.1.11.1.3';
    case AdRtV1_3 = '2.16.76.1.7.1.12.1.3';
    case AdRcV1_4 = '2.16.76.1.7.1.13.1.4';
    case AdRaV1_4 = '2.16.76.1.7.1.14.1.4';

    public function uri(): string
    {
        return match ($this) {
            self::AdRbV1_3 => 'http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_3.der',
            self::AdRtV1_3 => 'http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RT_v1_3.der',
            self::AdRcV1_4 => 'http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RC_v1_4.der',
            self::AdRaV1_4 => 'http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RA_v1_4.der',
        };
    }

    public function sha256DigestHex(): string
    {
        return match ($this) {
            self::AdRbV1_3 => '23da544aef71f7a75dc85fa6e17a83875741e4baef41ec178258a5c86ace54dd',
            self::AdRtV1_3 => '92a972e7c292bb884e98e650773d9e9876994effb43eb36199b06bf2864a677c',
            self::AdRcV1_4 => 'defe0ce4a45be8d7bf0a62bfe7baba5329b7665e5585568de00b9f3e56c0ce83',
            self::AdRaV1_4 => 'b77680a623ba7b9757c38404d4759d966791338665ff5cf152c1c0917f97c548',
        };
    }

    public function toIdentifier(): SignaturePolicyIdentifierDto
    {
        return SignaturePolicyIdentifierDto::fromHex($this->value, $this->sha256DigestHex(), HashAlgorithm::Sha256, $this->uri());
    }
}
