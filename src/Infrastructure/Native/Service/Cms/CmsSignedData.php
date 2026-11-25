<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

/**
 * ContentInfo wrapping a SignedData (RFC 5652, 5.1), read without any external process.
 */
final readonly class CmsSignedData
{
    public const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

    /**
     * @param  list<string>  $certificates  DER of each X.509 certificate in the certificates set
     * @param  list<CmsSignerInfo>  $signerInfos
     */
    private function __construct(
        public string $encapsulatedContentType,
        public ?string $encapsulatedContent,
        public array $certificates,
        public array $signerInfos,
    ) {}

    /**
     * Reads a DER/BER ContentInfo. Bytes after the outer element (PDF /Contents padding) are ignored.
     *
     * @throws \UnexpectedValueException when the input is not a well-formed SignedData
     */
    public static function fromDer(string $der): self
    {
        $contentInfo = Asn1Node::read($der)->expectTag(Asn1Node::TAG_SEQUENCE);
        if ($contentInfo->child(0)->oid() !== self::OID_SIGNED_DATA) {
            throw new \UnexpectedValueException('CMS ContentInfo is not a SignedData.');
        }

        $explicit = $contentInfo->child(1, 0xA0);
        $signedData = $explicit->child(0, Asn1Node::TAG_SEQUENCE);
        $fields = $signedData->children();

        ($fields[0] ?? throw new \UnexpectedValueException('SignedData has no version.'))->expectTag(Asn1Node::TAG_INTEGER);
        ($fields[1] ?? throw new \UnexpectedValueException('SignedData has no digestAlgorithms.'))->expectTag(Asn1Node::TAG_SET);

        $encapsulated = ($fields[2] ?? throw new \UnexpectedValueException('SignedData has no encapContentInfo.'))->expectTag(Asn1Node::TAG_SEQUENCE);
        $encapsulatedContentType = $encapsulated->child(0)->oid();
        $encapsulatedContent = null;
        if (isset($encapsulated->children()[1])) {
            $encapsulatedContent = $encapsulated->child(1, 0xA0)->child(0)->octets();
        }

        $index = 3;
        $certificates = [];
        if (($fields[$index] ?? null)?->tag === 0xA0) {
            foreach ($fields[$index++]->children() as $choice) {
                // Only plain X.509 certificates; attribute certificates and "other" formats are skipped.
                if ($choice->tag === Asn1Node::TAG_SEQUENCE) {
                    $certificates[] = $choice->indefiniteLength ? $choice->withTag(Asn1Node::TAG_SEQUENCE) : $choice->encoded;
                }
            }
        }
        if (($fields[$index] ?? null)?->tag === 0xA1) {
            $index++;
        }

        $signerInfos = [];
        $signerInfoSet = ($fields[$index++] ?? throw new \UnexpectedValueException('SignedData has no signerInfos.'))->expectTag(Asn1Node::TAG_SET);
        foreach ($signerInfoSet->children() as $signerInfo) {
            $signerInfos[] = CmsSignerInfo::fromNode($signerInfo);
        }

        if (isset($fields[$index])) {
            throw new \UnexpectedValueException('Unexpected trailing fields in SignedData.');
        }

        return new self($encapsulatedContentType, $encapsulatedContent, $certificates, $signerInfos);
    }

    /**
     * Reads the DER from a hex string as stored in a PDF /Contents entry.
     *
     * @throws \UnexpectedValueException
     */
    public static function fromHex(string $hex): self
    {
        $hex = preg_replace('/\s+/', '', $hex) ?? '';
        if ($hex === '' || strlen($hex) % 2 !== 0 || ! ctype_xdigit($hex) || trim($hex, '0') === '') {
            throw new \UnexpectedValueException('Empty or invalid CMS hex payload.');
        }

        return self::fromDer((string) hex2bin($hex));
    }
}
