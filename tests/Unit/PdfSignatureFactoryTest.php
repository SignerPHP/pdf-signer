<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfCore\SignatureAppearance;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfSigner\Application\DTO\CertificateCredentialsDto;
use SignerPHP\PdfSigner\Application\DTO\CertificationLevel;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceXObjectDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Application\DTO\SigningOptionsDto;
use SignerPHP\PdfSigner\Application\DTO\SignPdfRequestDto;
use SignerPHP\PdfSigner\Domain\ValueObject\VerifiedCertificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\DefaultSignatureAppearanceProviderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\PdfSignatureFactory;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\SignatureHandler;

final class PdfSignatureFactoryTest extends TestCase
{
    public function test_factory_uses_default_appearance_when_none_is_provided(): void
    {
        $provider = new class implements DefaultSignatureAppearanceProviderInterface
        {
            public function makeDefault(): SignatureAppearanceDto
            {
                return new SignatureAppearanceDto('base64-image', [1, 2, 3, 4], 2);
            }
        };

        $factory = new PdfSignatureFactory($provider);
        $signature = $factory->create($this->context(new SigningOptionsDto), new PdfDocument);
        $appearance = $this->extractAppearance($signature);

        self::assertSame('base64-image', $appearance->getBackgroundImage());
        self::assertSame([1, 2, 3, 4], $appearance->getRect());
        self::assertSame(2, $appearance->getPageToAppear());
    }

    public function test_factory_skips_default_appearance_when_disabled(): void
    {
        $provider = new class implements DefaultSignatureAppearanceProviderInterface
        {
            public function makeDefault(): SignatureAppearanceDto
            {
                return new SignatureAppearanceDto('base64-image', [1, 2, 3, 4], 2);
            }
        };

        $factory = new PdfSignatureFactory($provider);
        $signature = $factory->create(
            $this->context(new SigningOptionsDto(useDefaultAppearance: false)),
            new PdfDocument
        );
        $appearance = $this->extractAppearance($signature);

        self::assertNull($appearance->getBackgroundImage());
        self::assertSame([0, 0, 0, 0], $appearance->getRect());
        self::assertSame(0, $appearance->getPageToAppear());
    }

    public function test_factory_prioritizes_explicit_appearance_over_default(): void
    {
        $provider = new class implements DefaultSignatureAppearanceProviderInterface
        {
            public function makeDefault(): SignatureAppearanceDto
            {
                return new SignatureAppearanceDto('default-image', [11, 22, 33, 44], 3);
            }
        };

        $factory = new PdfSignatureFactory($provider);
        $signature = $factory->create(
            $this->context(new SigningOptionsDto(
                appearance: new SignatureAppearanceDto('custom-image', [10, 20, 30, 40], 1),
                useDefaultAppearance: true,
            )),
            new PdfDocument
        );
        $appearance = $this->extractAppearance($signature);

        self::assertSame('custom-image', $appearance->getBackgroundImage());
        self::assertSame([10, 20, 30, 40], $appearance->getRect());
        self::assertSame(1, $appearance->getPageToAppear());
    }

    public function test_factory_passes_prepared_xobject_to_signature_appearance(): void
    {
        $provider = new class implements DefaultSignatureAppearanceProviderInterface
        {
            public function makeDefault(): SignatureAppearanceDto
            {
                return new SignatureAppearanceDto('default-image', [11, 22, 33, 44], 3);
            }
        };

        $xObject = new SignatureAppearanceXObjectDto(
            'q 1 0 0 1 0 0 cm BT /F1 12 Tf (Signed) Tj ET Q',
            [
                'Font' => [
                    'F1' => [
                        'Type' => '/Font',
                        'Subtype' => '/Type1',
                        'BaseFont' => '/Helvetica',
                    ],
                ],
            ]
        );

        $factory = new PdfSignatureFactory($provider);
        $signature = $factory->create(
            $this->context(new SigningOptionsDto(
                appearance: new SignatureAppearanceDto('custom-image', [10, 20, 30, 40], 1, $xObject),
            )),
            new PdfDocument
        );
        $appearance = $this->extractAppearance($signature);

        /** @var SignatureAppearanceXObjectDto|null $actualXObject */
        $actualXObject = $this->readPrivateProperty($appearance, 'xObject');

        self::assertInstanceOf(SignatureAppearanceXObjectDto::class, $actualXObject);
        self::assertSame($xObject->stream, $actualXObject->stream);
        self::assertSame($xObject->resources, $actualXObject->resources);
    }

    public function test_factory_sets_pades_sub_filter_when_profile_is_enabled(): void
    {
        $provider = new class implements DefaultSignatureAppearanceProviderInterface
        {
            public function makeDefault(): SignatureAppearanceDto
            {
                return new SignatureAppearanceDto('base64-image', [1, 2, 3, 4], 2);
            }
        };

        $factory = new PdfSignatureFactory($provider);
        $signature = $factory->create(
            $this->context(new SigningOptionsDto(signatureProfile: SignatureProfile::PadesBaselineB)),
            new PdfDocument
        );

        self::assertSame(SignatureObject::SUBFILTER_ETSI_CADES_DETACHED, $this->extractSubFilter($signature));
    }

    public function test_factory_sets_pades_sub_filter_for_baseline_t_profile(): void
    {
        $provider = new class implements DefaultSignatureAppearanceProviderInterface
        {
            public function makeDefault(): SignatureAppearanceDto
            {
                return new SignatureAppearanceDto('base64-image', [1, 2, 3, 4], 2);
            }
        };

        $factory = new PdfSignatureFactory($provider);
        $signature = $factory->create(
            $this->context(new SigningOptionsDto(signatureProfile: SignatureProfile::PadesBaselineT)),
            new PdfDocument
        );

        self::assertSame(SignatureObject::SUBFILTER_ETSI_CADES_DETACHED, $this->extractSubFilter($signature));
    }

    public function test_factory_sets_pades_sub_filter_for_baseline_lt_profile(): void
    {
        $provider = new class implements DefaultSignatureAppearanceProviderInterface
        {
            public function makeDefault(): SignatureAppearanceDto
            {
                return new SignatureAppearanceDto('base64-image', [1, 2, 3, 4], 2);
            }
        };

        $factory = new PdfSignatureFactory($provider);
        $signature = $factory->create(
            $this->context(new SigningOptionsDto(signatureProfile: SignatureProfile::PadesBaselineLT)),
            new PdfDocument
        );

        self::assertSame(SignatureObject::SUBFILTER_ETSI_CADES_DETACHED, $this->extractSubFilter($signature));
    }

    public function test_factory_sets_pades_sub_filter_for_baseline_lta_profile(): void
    {
        $provider = new class implements DefaultSignatureAppearanceProviderInterface
        {
            public function makeDefault(): SignatureAppearanceDto
            {
                return new SignatureAppearanceDto('base64-image', [1, 2, 3, 4], 2);
            }
        };

        $factory = new PdfSignatureFactory($provider);
        $signature = $factory->create(
            $this->context(new SigningOptionsDto(signatureProfile: SignatureProfile::PadesBaselineLTA)),
            new PdfDocument
        );

        self::assertSame(SignatureObject::SUBFILTER_ETSI_CADES_DETACHED, $this->extractSubFilter($signature));
    }

    public function test_factory_forwards_certification_level_to_signature_state(): void
    {
        $provider = new class implements DefaultSignatureAppearanceProviderInterface
        {
            public function makeDefault(): SignatureAppearanceDto
            {
                return new SignatureAppearanceDto('base64-image', [1, 2, 3, 4], 2);
            }
        };

        $options = new SigningOptionsDto(certificationLevel: CertificationLevel::FormFillAndSignatures);
        $factory = new PdfSignatureFactory($provider);
        $signature = $factory->create($this->context($options), new PdfDocument);

        self::assertSame(CertificationLevel::FormFillAndSignatures, $this->readPrivateProperty($signature, 'certificationLevel'));
    }

    private function context(SigningOptionsDto $options): SigningContextDto
    {
        $request = new SignPdfRequestDto(
            new PdfContentDto('pdf-content'),
            new CertificateCredentialsDto('/tmp/cert.pfx', 'pwd'),
            $options
        );

        return new SigningContextDto(
            $request,
            new VerifiedCertificate($request->certificate, ['validTo_time_t' => PHP_INT_MAX], ['cert' => '', 'pkey' => '', 'extracerts' => ''])
        );
    }

    private function extractAppearance(SignatureHandler $signature): SignatureAppearance
    {
        /** @var SignatureAppearance $appearance */
        $appearance = $this->readPrivateProperty($signature, 'appearance');

        return $appearance;
    }

    private function extractSubFilter(SignatureHandler $signature): string
    {
        return (string) $this->readPrivateProperty($signature, 'subFilter');
    }

    private function readPrivateProperty(object $target, string $property): mixed
    {
        return (function (string $property): mixed {
            return $this->{$property};
        })->bindTo($target, $target::class)($property);
    }
}
