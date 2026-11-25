<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

/**
 * SignerInfo (RFC 5652, 5.3), read from a SignedData.
 */
final readonly class CmsSignerInfo
{
    public const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';

    public const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

    public const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';

    /**
     * @param  array<string, list<Asn1Node>>  $signedAttributes  attribute values by attribute type OID
     * @param  array<string, list<Asn1Node>>  $unsignedAttributes  attribute values by attribute type OID
     */
    private function __construct(
        public ?string $issuerAndSerialNumber,
        public ?string $subjectKeyIdentifier,
        public string $digestAlgorithm,
        public ?Asn1Node $signedAttributesNode,
        public array $signedAttributes,
        public string $signatureAlgorithm,
        public ?Asn1Node $signatureAlgorithmParameters,
        public string $signature,
        public array $unsignedAttributes,
    ) {}

    public static function fromNode(Asn1Node $node): self
    {
        $node->expectTag(Asn1Node::TAG_SEQUENCE);
        $fields = $node->children();
        $index = 0;

        ($fields[$index++] ?? throw new \UnexpectedValueException('SignerInfo has no version.'))->expectTag(Asn1Node::TAG_INTEGER);

        $sid = $fields[$index++] ?? throw new \UnexpectedValueException('SignerInfo has no sid.');
        $issuerAndSerialNumber = null;
        $subjectKeyIdentifier = null;
        if ($sid->tag === Asn1Node::TAG_SEQUENCE) {
            $sid->child(0, Asn1Node::TAG_SEQUENCE);
            $sid->child(1, Asn1Node::TAG_INTEGER);
            $issuerAndSerialNumber = $sid->withTag(Asn1Node::TAG_SEQUENCE);
        } elseif ($sid->tag === 0x80 || $sid->tag === 0xA0) {
            $subjectKeyIdentifier = $sid->octets();
        } else {
            throw new \UnexpectedValueException('SignerInfo sid is neither issuerAndSerialNumber nor subjectKeyIdentifier.');
        }

        $digestAlgorithm = self::algorithmOid($fields[$index++] ?? throw new \UnexpectedValueException('SignerInfo has no digestAlgorithm.'));

        $signedAttributesNode = null;
        $signedAttributes = [];
        if (($fields[$index] ?? null)?->tag === 0xA0) {
            $signedAttributesNode = $fields[$index++];
            $signedAttributes = self::attributes($signedAttributesNode);
        }

        $signatureAlgorithmNode = ($fields[$index++] ?? throw new \UnexpectedValueException('SignerInfo has no signatureAlgorithm.'))->expectTag(Asn1Node::TAG_SEQUENCE);
        $signatureAlgorithm = self::algorithmOid($signatureAlgorithmNode);
        $signatureAlgorithmParameters = $signatureAlgorithmNode->children()[1] ?? null;

        $signature = ($fields[$index++] ?? throw new \UnexpectedValueException('SignerInfo has no signature.'))->expectTag(Asn1Node::TAG_OCTET_STRING)->octets();

        $unsignedAttributes = [];
        if (($fields[$index] ?? null)?->tag === 0xA1) {
            $unsignedAttributes = self::attributes($fields[$index++]);
        }

        if (isset($fields[$index])) {
            throw new \UnexpectedValueException('Unexpected trailing fields in SignerInfo.');
        }

        return new self(
            $issuerAndSerialNumber,
            $subjectKeyIdentifier,
            $digestAlgorithm,
            $signedAttributesNode,
            $signedAttributes,
            $signatureAlgorithm,
            $signatureAlgorithmParameters,
            $signature,
            $unsignedAttributes,
        );
    }

    /**
     * The bytes the signature covers when signed attributes are present: their DER with the
     * [0] IMPLICIT tag replaced by the SET OF tag (RFC 5652, 5.4).
     */
    public function signedAttributesDer(): ?string
    {
        return $this->signedAttributesNode?->withTag(Asn1Node::TAG_SET);
    }

    /**
     * The single value of a signed attribute, or null when absent. Several values throw.
     */
    public function signedAttribute(string $oid): ?Asn1Node
    {
        $values = $this->signedAttributes[$oid] ?? null;
        if ($values === null) {
            return null;
        }
        if (count($values) !== 1) {
            throw new \UnexpectedValueException(sprintf('Signed attribute %s must have exactly one value.', $oid));
        }

        return $values[0];
    }

    private static function algorithmOid(Asn1Node $algorithmIdentifier): string
    {
        return $algorithmIdentifier->expectTag(Asn1Node::TAG_SEQUENCE)->child(0)->oid();
    }

    /**
     * @return array<string, list<Asn1Node>>
     */
    private static function attributes(Asn1Node $set): array
    {
        $attributes = [];
        foreach ($set->children() as $attribute) {
            $attribute->expectTag(Asn1Node::TAG_SEQUENCE);
            $oid = $attribute->child(0)->oid();
            if (isset($attributes[$oid])) {
                throw new \UnexpectedValueException(sprintf('Duplicate CMS attribute %s.', $oid));
            }
            $attributes[$oid] = $attribute->child(1, Asn1Node::TAG_SET)->children();
        }

        return $attributes;
    }
}
