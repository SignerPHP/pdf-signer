<?php

declare(strict_types=1);

/**
 * Backward-compatible aliases for the public Signer PHP API.
 * Internal types now live under SignerPHP\PdfSigner.
 */
class_alias(\SignerPHP\PdfSigner\Application\DTO\BrazilPolicyLpaUrlsDto::class, 'SignerPHP\Application\DTO\BrazilPolicyLpaUrlsDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\BrazilSignaturePolicyOptionsDto::class, 'SignerPHP\Application\DTO\BrazilSignaturePolicyOptionsDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\BrazilTrustAnchorsOptionsDto::class, 'SignerPHP\Application\DTO\BrazilTrustAnchorsOptionsDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\CertificateCredentialsDto::class, 'SignerPHP\Application\DTO\CertificateCredentialsDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\CertificationLevel::class, 'SignerPHP\Application\DTO\CertificationLevel');
class_alias(\SignerPHP\PdfSigner\Application\DTO\HashAlgorithm::class, 'SignerPHP\Application\DTO\HashAlgorithm');
class_alias(\SignerPHP\PdfSigner\Application\DTO\PdfContentDto::class, 'SignerPHP\Application\DTO\PdfContentDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\ProtectPdfRequestDto::class, 'SignerPHP\Application\DTO\ProtectPdfRequestDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\ProtectionOptionsDto::class, 'SignerPHP\Application\DTO\ProtectionOptionsDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\SignPdfRequestDto::class, 'SignerPHP\Application\DTO\SignPdfRequestDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\SignatureActorDto::class, 'SignerPHP\Application\DTO\SignatureActorDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceDto::class, 'SignerPHP\Application\DTO\SignatureAppearanceDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceXObjectDto::class, 'SignerPHP\Application\DTO\SignatureAppearanceXObjectDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto::class, 'SignerPHP\Application\DTO\SignatureMetadataDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\SignatureProfile::class, 'SignerPHP\Application\DTO\SignatureProfile');
class_alias(\SignerPHP\PdfSigner\Application\DTO\SignatureValidationEntryDto::class, 'SignerPHP\Application\DTO\SignatureValidationEntryDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\SignatureValidationOptionsDto::class, 'SignerPHP\Application\DTO\SignatureValidationOptionsDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\SignatureValidationResultDto::class, 'SignerPHP\Application\DTO\SignatureValidationResultDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\SigningContextDto::class, 'SignerPHP\Application\DTO\SigningContextDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\SigningOptionsDto::class, 'SignerPHP\Application\DTO\SigningOptionsDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\TimestampConnectionResultDto::class, 'SignerPHP\Application\DTO\TimestampConnectionResultDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto::class, 'SignerPHP\Application\DTO\TimestampOptionsDto');
class_alias(\SignerPHP\PdfSigner\Application\DTO\ValidatePdfRequestDto::class, 'SignerPHP\Application\DTO\ValidatePdfRequestDto');
class_alias(\SignerPHP\PdfSigner\Domain\Exception\InvalidCertificateException::class, 'SignerPHP\Domain\Exception\InvalidCertificateException');
class_alias(\SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException::class, 'SignerPHP\Domain\Exception\ProtectionProcessException');
class_alias(\SignerPHP\PdfSigner\Domain\Exception\SignProcessException::class, 'SignerPHP\Domain\Exception\SignProcessException');
class_alias(\SignerPHP\PdfSigner\Domain\Exception\SignatureValidationException::class, 'SignerPHP\Domain\Exception\SignatureValidationException');
class_alias(\SignerPHP\PdfSigner\Domain\Exception\SignerException::class, 'SignerPHP\Domain\Exception\SignerException');
class_alias(\SignerPHP\PdfSigner\Presentation\PdfProtectionBuilder::class, 'SignerPHP\Presentation\PdfProtectionBuilder');
class_alias(\SignerPHP\PdfSigner\Presentation\PdfSignatureValidatorBuilder::class, 'SignerPHP\Presentation\PdfSignatureValidatorBuilder');
class_alias(\SignerPHP\PdfSigner\Presentation\Signer::class, 'SignerPHP\Presentation\Signer');
class_alias(\SignerPHP\PdfSigner\Presentation\SignerBuilder::class, 'SignerPHP\Presentation\SignerBuilder');
class_alias(\SignerPHP\PdfSigner\Presentation\TimestampBuilder::class, 'SignerPHP\Presentation\TimestampBuilder');
