<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfCore\PdfValue\PDFValueHexString;
use SignerPHP\PdfCore\PdfValue\PDFValueSimple;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfCore\Xref\Xref;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ChainAwarePkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\DocumentTimestampApplierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\EncryptedDocumentTimestampApplierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\EncryptedSignedBufferBuilderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\LongTermValidationApplierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\Pkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PolicyAwarePkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProfileAwarePkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignerCertificateRevocationCheckerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\XrefContentResolverInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\EncryptedPdfDocument;

final readonly class SignedBufferBuilder implements EncryptedSignedBufferBuilderInterface
{
    public function __construct(
        private XrefContentResolverInterface $xrefContentResolver,
        private Pkcs7SignerInterface $pkcs7Signer,
        private DocumentTimestampApplierInterface $documentTimestampApplier = new DocumentTimestampApplier,
        private LongTermValidationApplierInterface $longTermValidationApplier = new DocumentLongTermValidationApplier,
        private SignerCertificateRevocationCheckerInterface $revocationChecker = new OpenSslOcspSignerCertificateRevocationChecker,
    ) {}

    public function build(
        PdfDocument $pdfDocument,
        SignatureHandler $signatureHandler,
        SigningContextDto $context,
        SignatureProviderInterface $signatureProvider,
    ): Buffer {
        if (! $signatureHandler->hasCertificate()) {
            return $pdfDocument->getBuffer();
        }

        // LT/LTA embed revocation data for the signer; never produce them for a revoked certificate.
        if (in_array($context->options->signatureProfile, [SignatureProfile::PadesBaselineLT, SignatureProfile::PadesBaselineLTA], true)) {
            $this->revocationChecker->assertNotRevoked($context->certificate->certificatePem, $context->certificate->chainPem);
        }

        $pdfDocument->updateModifyDate();
        $signature = $signatureHandler->generateSignatureInDocument();

        [$docToXref, $objectOffsets] = Xref::new()
            ->withPdfDocument($pdfDocument)
            ->generateContentToXref();

        $xrefOffset = $docToXref->size();
        $objectOffsets[$signature->getOid()] = $docToXref->size();
        $xrefOffset += strlen($signature->toPdfEntry());

        $docFromXref = $this->xrefContentResolver->resolve($pdfDocument, $objectOffsets, $xrefOffset);

        $signature->withSizes($docToXref->size(), $docFromXref->size());
        $signature['Contents'] = new PDFValueSimple('');

        $signableDocument = new Buffer($docToXref->raw().$signature->toPdfEntry().$docFromXref->raw());
        $signatureContents = $this->signCms($signableDocument, $context, $signatureProvider);

        $signature['Contents'] = new PDFValueHexString($signatureContents);
        $docToXref->data($signature->toPdfEntry());

        $signedRaw = $docToXref->raw().$docFromXref->raw();
        $timestamp = $context->options->timestamp;
        if ($timestamp !== null) {
            $signedRaw = $this->documentTimestampApplier->apply($signedRaw, $timestamp);
        }

        if (in_array($context->options->signatureProfile, [SignatureProfile::PadesBaselineLT, SignatureProfile::PadesBaselineLTA], true)) {
            $signedRaw = $this->longTermValidationApplier->apply($signedRaw);
        }

        if ($context->options->signatureProfile === SignatureProfile::PadesBaselineLTA && $timestamp !== null) {
            $signedRaw = $this->documentTimestampApplier->apply($signedRaw, $timestamp);
        }

        return new Buffer($signedRaw);
    }

    public function buildEncrypted(
        EncryptedPdfDocument $encryptedDocument,
        PdfDocument $plainMirrorDocument,
        SignatureHandler $signatureHandler,
        SigningContextDto $context,
        SignatureProviderInterface $signatureProvider,
    ): Buffer {
        if (! $signatureHandler->hasCertificate()) {
            return new Buffer($encryptedDocument->content());
        }

        if (in_array($context->options->signatureProfile, [SignatureProfile::PadesBaselineLT, SignatureProfile::PadesBaselineLTA], true)) {
            $this->revocationChecker->assertNotRevoked($context->certificate->certificatePem, $context->certificate->chainPem);
        }

        $timestamp = $context->options->timestamp;
        if ($timestamp !== null && ! $this->documentTimestampApplier instanceof EncryptedDocumentTimestampApplierInterface) {
            throw new \LogicException('Timestamping an encrypted PDF requires an encryption-aware document timestamp applier.');
        }

        $plainMirrorDocument->updateModifyDate();
        $signature = $signatureHandler->generateSignatureInDocument();

        [$docToXref, $objectOffsets] = Xref::new()
            ->withPdfDocument($plainMirrorDocument)
            ->generateContentToXref();

        $xrefOffset = $docToXref->size();
        $objectOffsets[$signature->getOid()] = $docToXref->size();
        $xrefOffset += strlen($signature->toPdfEntry());

        $docFromXref = $this->xrefContentResolver->resolve($plainMirrorDocument, $objectOffsets, $xrefOffset);
        $signature->withSizes($docToXref->size(), $docFromXref->size());
        // All-zero placeholder: the encrypted revision computes /ByteRange and fills it with the CMS.
        $signature['Contents'] = new PDFValueHexString(str_repeat('0', SignatureObject::SIGNATURE_MAX_LENGTH));

        $document = $encryptedDocument->appendSignedRevision(
            $docToXref->raw().$signature->toPdfEntry().$docFromXref->raw(),
            fn (string $signedBytes): string => $this->signCms(new Buffer($signedBytes), $context, $signatureProvider),
        );

        if ($timestamp !== null) {
            /** @var EncryptedDocumentTimestampApplierInterface $applier */
            $applier = $this->documentTimestampApplier;
            $document = $applier->applyToEncrypted($document, $timestamp);
        }

        if (in_array($context->options->signatureProfile, [SignatureProfile::PadesBaselineLT, SignatureProfile::PadesBaselineLTA], true)) {
            $document = $document->appendRevision($this->longTermValidationApplier->apply($document->plainMirror()));
        }

        if ($context->options->signatureProfile === SignatureProfile::PadesBaselineLTA && $timestamp !== null) {
            /** @var EncryptedDocumentTimestampApplierInterface $applier */
            $applier = $this->documentTimestampApplier;
            $document = $applier->applyToEncrypted($document, $timestamp);
        }

        return new Buffer($document->content());
    }

    private function signCms(Buffer $signableDocument, SigningContextDto $context, SignatureProviderInterface $signatureProvider): string
    {
        $certificatePem = $context->certificate->certificatePem;
        $profile = $context->options->signatureProfile;
        $certificateChainPem = $context->certificate->chainPem;
        $signaturePolicy = $context->options->signaturePolicy;
        if ($this->pkcs7Signer instanceof ChainAwarePkcs7SignerInterface && $certificateChainPem !== []) {
            return $this->pkcs7Signer->signWithChain(
                $signableDocument,
                $signatureProvider,
                $certificatePem,
                $profile,
                $certificateChainPem,
                $signaturePolicy,
                $signaturePolicy !== null ? $context->options->timestamp : null,
            );
        } elseif ($signaturePolicy !== null) {
            if (! $this->pkcs7Signer instanceof PolicyAwarePkcs7SignerInterface) {
                throw new \LogicException('A signature policy requires a policy-aware CMS signer.');
            }

            return $this->pkcs7Signer->signWithPolicy(
                $signableDocument,
                $signatureProvider,
                $certificatePem,
                $profile,
                $signaturePolicy,
                $context->options->timestamp,
            );
        } elseif ($this->pkcs7Signer instanceof ProfileAwarePkcs7SignerInterface) {
            return $this->pkcs7Signer->signWithProfile($signableDocument, $signatureProvider, $certificatePem, $profile);
        } elseif ($profile === SignatureProfile::PdfBasic) {
            return $this->pkcs7Signer->sign($signableDocument, $signatureProvider, $certificatePem);
        } else {
            throw new \LogicException('PAdES signing requires a profile-aware CMS signer.');
        }
    }
}
