<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\Pkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\DetachedCmsAssembler;

final class Pkcs7Signer implements Pkcs7SignerInterface
{
    public function __construct(
        private readonly DetachedCmsAssembler $cmsAssembler = new DetachedCmsAssembler,
    ) {}

    public function sign(
        Buffer $signableDocument,
        SignatureProviderInterface $signatureProvider,
        string $certificatePem,
    ): string {
        if ($certificatePem === '') {
            throw new SignProcessException('Signing certificate PEM is required to assemble CMS.');
        }

        $cms = $this->cmsAssembler->assemble(
            $signableDocument->raw(),
            $certificatePem,
            $signatureProvider,
        );

        return str_pad(bin2hex($cms), SignatureObject::SIGNATURE_MAX_LENGTH, '0');
    }
}
