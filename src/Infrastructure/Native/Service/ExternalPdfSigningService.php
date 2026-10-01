<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfCore\PdfValue\PDFValueSimple;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfCore\Xref\Xref;
use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\PreparedExternalSignature;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PdfDocumentPreparerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureFactoryInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\XrefContentResolverInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\DetachedCmsAssembler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\PreparedDetachedCms;

final readonly class ExternalPdfSigningService
{
    public function __construct(
        private PdfDocumentPreparerInterface $documentPreparer = new PdfDocumentPreparer,
        private SignatureFactoryInterface $signatureFactory = new PdfSignatureFactory,
        private XrefContentResolverInterface $xrefContentResolver = new XrefContentResolver,
        private DetachedCmsAssembler $cmsAssembler = new DetachedCmsAssembler,
    ) {}

    public function prepare(SigningContextDto $context, HashAlgorithm $algorithm = HashAlgorithm::Sha256): PreparedExternalSignature
    {
        $pdfDocument = $this->documentPreparer->prepare($context->request->pdf->content);
        $signatureHandler = $this->signatureFactory->create($context, $pdfDocument);
        $pdfDocument->updateModifyDate();
        $signature = $signatureHandler->generateSignatureInDocument();

        [$docToXref, $objectOffsets] = Xref::new()->withPdfDocument($pdfDocument)->generateContentToXref();
        $xrefOffset = $docToXref->size();
        $objectOffsets[$signature->getOid()] = $docToXref->size();
        $xrefOffset += strlen($signature->toPdfEntry());
        $docFromXref = $this->xrefContentResolver->resolve($pdfDocument, $objectOffsets, $xrefOffset);
        $signature->withSizes($docToXref->size(), $docFromXref->size());
        $signature['Contents'] = new PDFValueSimple('');

        $unsignedPdf = $docToXref->raw().$signature->toPdfEntry().$docFromXref->raw();
        $certificatePem = (string) ($context->verifiedCertificate->bundle['cert'] ?? '');
        $preparedCms = $this->cmsAssembler->prepare($unsignedPdf, $certificatePem, $algorithm);

        return new PreparedExternalSignature(
            new ExternalSigningPayload(
                base64_encode($preparedCms->signedAttributes),
                base64_encode(hash($algorithm->value, $preparedCms->signedAttributes, true)),
                $algorithm,
                $preparedCms->signatureAlgorithm,
            ),
            $this->encodeState($unsignedPdf, $preparedCms),
        );
    }

    public function complete(string $state, string $rawSignature): string
    {
        [$unsignedPdf, $preparedCms] = $this->decodeState($state);
        $cms = $this->cmsAssembler->complete($preparedCms, new SignatureValue($rawSignature));
        $hex = bin2hex($cms);
        if (strlen($hex) > SignatureObject::SIGNATURE_MAX_LENGTH) {
            throw new SignProcessException('CMS signature exceeds the reserved PDF signature size.');
        }

        $range = $this->byteRange($unsignedPdf);
        $position = $range[0] + $range[1];
        $reservedLength = $range[2] - $position;
        if ($reservedLength < 2 || strlen($hex) > $reservedLength - 2) {
            throw new SignProcessException('Prepared PDF contains an invalid signature placeholder.');
        }

        $contents = '<'.str_pad($hex, $reservedLength - 2, '0').'>';

        return substr_replace($unsignedPdf, $contents, $position, 0);
    }

    /** @return array{int, int, int, int} */
    private function byteRange(string $pdf): array
    {
        if (! preg_match_all('/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/', $pdf, $matches, PREG_SET_ORDER)) {
            throw new SignProcessException('Could not read the prepared PDF ByteRange.');
        }

        $range = $matches[array_key_last($matches)];

        return [(int) $range[1], (int) $range[2], (int) $range[3], (int) $range[4]];
    }

    private function encodeState(string $unsignedPdf, PreparedDetachedCms $cms): string
    {
        $payload = [
            'version' => 1,
            'unsignedPdf' => base64_encode($unsignedPdf),
            'certificate' => base64_encode($cms->certificatePem),
            'signedAttributes' => base64_encode($cms->signedAttributes),
            'digestAlgorithm' => $cms->digestAlgorithm->value,
            'signatureAlgorithm' => $cms->signatureAlgorithm->value,
        ];
        $payload['checksum'] = hash('sha256', implode('|', $payload));

        return base64_encode(json_encode($payload, JSON_THROW_ON_ERROR));
    }

    /** @return array{string, PreparedDetachedCms} */
    private function decodeState(string $state): array
    {
        $json = base64_decode($state, true);
        $payload = is_string($json) ? json_decode($json, true) : null;
        if (! is_array($payload) || ($payload['version'] ?? null) !== 1) {
            throw new SignProcessException('Invalid or unsupported external signing state.');
        }

        $checksum = $payload['checksum'] ?? null;
        unset($payload['checksum']);
        if (! is_string($checksum) || ! hash_equals($checksum, hash('sha256', implode('|', $payload)))) {
            throw new SignProcessException('External signing state checksum is invalid.');
        }

        $pdf = base64_decode((string) ($payload['unsignedPdf'] ?? ''), true);
        $certificate = base64_decode((string) ($payload['certificate'] ?? ''), true);
        $attributes = base64_decode((string) ($payload['signedAttributes'] ?? ''), true);
        $digest = HashAlgorithm::tryFrom((string) ($payload['digestAlgorithm'] ?? ''));
        $signature = \SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm::tryFrom((string) ($payload['signatureAlgorithm'] ?? ''));
        if (! is_string($pdf) || $pdf === '' || ! is_string($certificate) || $certificate === '' || ! is_string($attributes) || $attributes === '' || $digest === null || $signature === null) {
            throw new SignProcessException('External signing state is incomplete or corrupted.');
        }

        return [$pdf, new PreparedDetachedCms($certificate, $attributes, $digest, $signature)];
    }
}
