<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Support;

use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Asn1Node;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;

/**
 * Builds keys, self-signed certificates and CMS signatures with PHP's OpenSSL extension only,
 * so CMS tests run without the `openssl` binary. Static fixtures for variants the extension
 * cannot produce (RSA-PSS, SKI sid, BER streaming, Ed25519, two signers) live in tests/Fixtures/cms.
 */
final class CmsTestFactory
{
    /** @var array<string, array{cert: string, key: string}> */
    private static array $identities = [];

    /**
     * @return array{cert: string, key: string} PEM certificate and private key
     */
    public static function identity(string $type = 'rsa', string $commonName = 'CMS-Test-Signer', array $extensions = []): array
    {
        $cacheKey = $type.'|'.$commonName.'|'.json_encode($extensions);
        if (isset(self::$identities[$cacheKey])) {
            return self::$identities[$cacheKey];
        }

        $config = self::config($extensions);
        $key = openssl_pkey_new($type === 'ec'
            ? ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => $config]
            : ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048, 'config' => $config]);
        if ($key === false) {
            throw new \RuntimeException('Could not generate a test key.');
        }

        $csr = openssl_csr_new(['commonName' => $commonName], $key, ['digest_alg' => 'sha256', 'config' => $config]);
        $certificate = openssl_csr_sign($csr, null, $key, 2, ['digest_alg' => 'sha256', 'config' => $config, 'x509_extensions' => 'v3'], random_int(1, PHP_INT_MAX));
        @unlink($config);
        if ($certificate === false) {
            throw new \RuntimeException('Could not issue a test certificate.');
        }

        openssl_x509_export($certificate, $certPem);
        openssl_pkey_export($key, $keyPem);

        return self::$identities[$cacheKey] = ['cert' => (string) $certPem, 'key' => (string) $keyPem];
    }

    /**
     * DER CMS SignedData over $content, detached unless $attached.
     *
     * @param  array{cert: string, key: string}|null  $identity
     */
    public static function sign(string $content, bool $attached = false, ?array $identity = null, int $flags = 0): string
    {
        $identity ??= self::identity();
        $in = (string) tempnam(sys_get_temp_dir(), 'cms-in');
        $out = (string) tempnam(sys_get_temp_dir(), 'cms-out');
        file_put_contents($in, $content);

        try {
            $flags |= OPENSSL_CMS_BINARY | ($attached ? 0 : OPENSSL_CMS_DETACHED);
            if (! openssl_cms_sign($in, $out, $identity['cert'], $identity['key'], null, $flags, OPENSSL_ENCODING_DER)) {
                throw new \RuntimeException('openssl_cms_sign failed: '.openssl_error_string());
            }

            return (string) file_get_contents($out);
        } finally {
            @unlink($in);
            @unlink($out);
        }
    }

    public static function fixture(string $name): string
    {
        return (string) file_get_contents(dirname(__DIR__).'/Fixtures/cms/'.$name);
    }

    /**
     * Replaces the only occurrence of $search (hex) in $der, failing when it is absent or repeated.
     */
    public static function replaceOnce(string $der, string $searchHex, string $replaceHex): string
    {
        $search = (string) hex2bin($searchHex);
        if (substr_count($der, $search) !== 1) {
            throw new \RuntimeException(sprintf('Expected exactly one occurrence of %s.', $searchHex));
        }

        return str_replace($search, (string) hex2bin($replaceHex), $der);
    }

    /**
     * Rebuilds a ContentInfo/SignedData after changing the DER of its SignedData fields
     * (version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos).
     *
     * @param  callable(list<string>): list<string>  $map
     */
    public static function mapSignedDataFields(string $cms, callable $map): string
    {
        $contentInfo = Asn1Node::read($cms);
        $signedData = $contentInfo->child(1)->child(0);
        $fields = array_map(static fn (Asn1Node $node): string => $node->encoded, $signedData->children());

        return Der::sequence($contentInfo->child(0)->encoded.Der::contextSpecific(0, Der::sequence(implode('', $map($fields)))));
    }

    /**
     * Rebuilds the CMS after changing the DER fields of its first SignerInfo
     * (version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature, [1] unsignedAttrs?).
     *
     * @param  callable(list<string>): list<string>  $map
     */
    public static function mapFirstSignerInfoFields(string $cms, callable $map): string
    {
        return self::mapSignedDataFields($cms, static function (array $fields) use ($map): array {
            $signerInfos = Asn1Node::read((string) end($fields))->children();
            $first = array_map(static fn (Asn1Node $node): string => $node->encoded, $signerInfos[0]->children());
            $rest = implode('', array_map(static fn (Asn1Node $node): string => $node->encoded, array_slice($signerInfos, 1)));
            $fields[count($fields) - 1] = Der::set(Der::sequence(implode('', $map($first))).$rest);

            return $fields;
        });
    }

    /**
     * @param  array<string, string>  $extensions
     */
    private static function config(array $extensions): string
    {
        $lines = ['[req]', 'default_bits = 2048', 'distinguished_name = dn', '[dn]', '[v3]', 'subjectKeyIdentifier = hash'];
        foreach ($extensions as $name => $value) {
            $lines[] = $name.' = '.$value;
        }
        $path = (string) tempnam(sys_get_temp_dir(), 'cms-cnf');
        file_put_contents($path, implode("\n", $lines)."\n");

        return $path;
    }
}
