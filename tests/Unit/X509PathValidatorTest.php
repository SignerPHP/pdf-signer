<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\X509PathValidator;

/**
 * Certification path validation against real certificates issued in the test with `openssl ca`
 * (explicit validity periods): Root -> Intermediate -> leaf, plus deliberately broken variants.
 */
final class X509PathValidatorTest extends TestCase
{
    private static string $dir;

    /** @var array<string, string> name => DER */
    private static array $certs = [];

    public static function setUpBeforeClass(): void
    {
        self::$dir = sys_get_temp_dir().'/x509-path-'.bin2hex(random_bytes(4));
        mkdir(self::$dir.'/newcerts', 0777, true);
        touch(self::$dir.'/index.txt');
        file_put_contents(self::$dir.'/serial', "1000\n");
        $keyIds = ['subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid'];
        $noKeyIds = ['subjectKeyIdentifier = none', 'authorityKeyIdentifier = none'];
        $ca = ['basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign, cRLSign'];
        $leaf = ['basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature, nonRepudiation'];
        file_put_contents(self::$dir.'/ca.cnf', implode("\n", [
            '[req]', 'distinguished_name = dn', '[dn]',
            '[ca]', 'default_ca = test_ca',
            '[test_ca]', 'dir = '.self::$dir, 'database = $dir/index.txt', 'new_certs_dir = $dir/newcerts',
            'serial = $dir/serial', 'default_md = sha256', 'policy = any', 'unique_subject = no',
            '[any]', 'commonName = supplied',
            '[v3_ca]', ...$ca, ...$keyIds,
            '[v3_ca_pathlen0]', 'basicConstraints = critical, CA:TRUE, pathlen:0', 'keyUsage = critical, keyCertSign, cRLSign', ...$keyIds,
            '[v3_ca_nokeyid]', ...$ca, ...$noKeyIds,
            '[v3_ca_no_cert_sign]', 'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, digitalSignature', ...$keyIds,
            '[v3_ca_key_usage_only]', 'keyUsage = critical, keyCertSign', ...$keyIds,
            '[v3_not_ca]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature, keyCertSign', ...$keyIds,
            '[v3_leaf]', ...$leaf, ...$keyIds,
            '[v3_leaf_nokeyid]', ...$leaf, ...$noKeyIds,
            '[v3_leaf_critical]', ...$leaf, ...$keyIds, '1.2.3.4 = critical, ASN1:NULL', '',
        ]));

        $long = ['20150101000000Z', '20450101000000Z'];
        self::root('root', 'Path Root', 'v3_ca', ...$long);
        self::root('root-reissued', 'Path Root', 'v3_ca', '20160101000000Z', '20450101000000Z', 'root');
        self::root('unrelated', 'Unrelated Root', 'v3_ca', ...$long);
        self::root('twin-a', 'Twin Root', 'v3_ca_nokeyid', ...$long);
        self::root('twin-b', 'Twin Root', 'v3_ca_nokeyid', ...$long);
        self::root('twin-c', 'Twin Root', 'v3_ca', ...$long);
        self::root('twin-d', 'Twin Root', 'v3_ca', ...$long);
        self::root('self-signed-leaf', 'Self Signed Leaf', 'v3_leaf', ...$long);

        self::issue('int', 'Path Intermediate', 'root', 'v3_ca', ...$long);
        self::issue('leaf', 'Path Leaf', 'int', 'v3_leaf', ...$long);
        self::issue('leaf-2020', 'Path Leaf 2020', 'int', 'v3_leaf', '20200101000000Z', '20210101000000Z');
        self::issue('leaf-2040', 'Path Leaf 2040', 'int', 'v3_leaf', '20400101000000Z', '20410101000000Z');
        self::issue('leaf-critical', 'Path Leaf Critical', 'int', 'v3_leaf_critical', ...$long);

        self::issue('int-expired', 'Expired Intermediate', 'root', 'v3_ca', '20150101000000Z', '20160101000000Z');
        self::issue('leaf-expired-int', 'Leaf Under Expired', 'int-expired', 'v3_leaf', ...$long);

        self::issue('not-ca', 'Not A CA', 'root', 'v3_not_ca', ...$long);
        self::issue('leaf-not-ca', 'Leaf Under Not CA', 'not-ca', 'v3_leaf', ...$long);
        self::issue('no-cert-sign', 'No Cert Sign', 'root', 'v3_ca_no_cert_sign', ...$long);
        self::issue('leaf-no-cert-sign', 'Leaf Under No Cert Sign', 'no-cert-sign', 'v3_leaf', ...$long);
        self::issue('ku-only', 'Key Usage Only CA', 'root', 'v3_ca_key_usage_only', ...$long);
        self::issue('leaf-ku-only', 'Leaf Under Key Usage Only', 'ku-only', 'v3_leaf', ...$long);

        self::issue('pathlen0', 'Pathlen Zero', 'root', 'v3_ca_pathlen0', ...$long);
        self::issue('pathlen0-sub', 'Pathlen Sub', 'pathlen0', 'v3_ca', ...$long);
        self::issue('leaf-pathlen', 'Leaf Too Deep', 'pathlen0-sub', 'v3_leaf', ...$long);
        self::issue('leaf-pathlen-ok', 'Leaf Pathlen Ok', 'pathlen0', 'v3_leaf', ...$long);

        self::issue('leaf-twin-b', 'Leaf Twin B', 'twin-b', 'v3_leaf_nokeyid', ...$long);
        self::issue('leaf-twin-c', 'Leaf Twin C', 'twin-c', 'v3_leaf', ...$long);

        foreach (glob(self::$dir.'/*.crt') ?: [] as $file) {
            $der = X509PathValidator::certificatesFromBundle((string) file_get_contents($file));
            self::$certs[basename($file, '.crt')] = $der[0];
        }
    }

    public static function tearDownAfterClass(): void
    {
        exec('rm -rf '.escapeshellarg(self::$dir));
    }

    /**
     * @param  list<string>  $untrusted
     * @param  list<string>  $trusted
     */
    #[DataProvider('validPaths')]
    public function test_accepts_valid_paths(string $leaf, array $untrusted, array $trusted, string $at = 'now'): void
    {
        self::assertNull($this->validate($leaf, $untrusted, $trusted, $at));
    }

    /** @return array<string, array{0:string,1:list<string>,2:list<string>,3?:string}> */
    public static function validPaths(): array
    {
        return [
            'root -> intermediate -> leaf' => ['leaf', ['int'], ['root']],
            'intermediates out of order with irrelevant certificates' => ['leaf', ['unrelated', 'root', 'leaf-2020', 'int', 'not-ca'], ['unrelated', 'root']],
            'valid at the reference time although expired today' => ['leaf-2020', ['int'], ['root'], '2020-06-15T12:00:00Z'],
            'intermediate in the trust store is an anchor' => ['leaf', [], ['int']],
            'embedded intermediate also present in the trust store' => ['leaf', ['int', 'root'], ['int']],
            'leaf itself in the trust store' => ['self-signed-leaf', [], ['self-signed-leaf']],
            'anchor matched by subject and key, not by DER' => ['leaf', ['int', 'root'], ['root-reissued']],
            'issuer with keyCertSign but no basicConstraints' => ['leaf-ku-only', ['ku-only'], ['root']],
            'pathlen 0 issuer signing a leaf' => ['leaf-pathlen-ok', ['pathlen0'], ['root']],
            'same issuer name, other key tried first' => ['leaf-twin-b', [], ['twin-a', 'twin-b']],
            'same issuer name, other key skipped by key identifier' => ['leaf-twin-c', [], ['twin-d', 'twin-c']],
        ];
    }

    /**
     * @param  list<string>  $untrusted
     * @param  list<string>  $trusted
     */
    #[DataProvider('invalidPaths')]
    public function test_rejects_invalid_paths(string $leaf, array $untrusted, array $trusted, string $expected, string $at = 'now'): void
    {
        self::assertSame($expected, $this->validate($leaf, $untrusted, $trusted, $at));
    }

    /** @return array<string, array{0:string,1:list<string>,2:list<string>,3:string,4?:string}> */
    public static function invalidPaths(): array
    {
        return [
            'intermediate missing' => ['leaf', [], ['root'], 'unable to get local issuer certificate (depth 0: /CN=Path Leaf)'],
            'embedded root without intermediate' => ['leaf', ['root'], ['root'], 'unable to get local issuer certificate (depth 0: /CN=Path Leaf)'],
            'anchor outside the trust store, root not embedded' => ['leaf', ['int'], ['unrelated'], 'unable to get local issuer certificate (depth 1: /CN=Path Intermediate)'],
            'anchor outside the trust store, root embedded' => ['leaf', ['int', 'root'], ['unrelated'], 'self-signed certificate in certificate chain (depth 2: /CN=Path Root)'],
            'untrusted self-signed leaf' => ['self-signed-leaf', [], ['root'], 'self-signed certificate (depth 0: /CN=Self Signed Leaf)'],
            'leaf expired today' => ['leaf-2020', ['int'], ['root'], 'certificate has expired (depth 0: /CN=Path Leaf 2020)'],
            'leaf not yet valid' => ['leaf-2040', ['int'], ['root'], 'certificate is not yet valid (depth 0: /CN=Path Leaf 2040)'],
            'leaf not yet valid at the reference time' => ['leaf', ['int'], ['root'], 'certificate is not yet valid (depth 0: /CN=Path Leaf)', '2010-01-01T00:00:00Z'],
            'expired intermediate' => ['leaf-expired-int', ['int-expired'], ['root'], 'certificate has expired (depth 1: /CN=Expired Intermediate)'],
            'issuer without CA:TRUE' => ['leaf-not-ca', ['not-ca'], ['root'], 'invalid CA certificate (depth 1: /CN=Not A CA)'],
            'issuer without keyCertSign' => ['leaf-no-cert-sign', ['no-cert-sign'], ['root'], 'key usage does not include certificate signing (depth 1: /CN=No Cert Sign)'],
            'path length constraint' => ['leaf-pathlen', ['pathlen0-sub', 'pathlen0'], ['root'], 'path length constraint exceeded (depth 2: /CN=Pathlen Zero)'],
            'unknown critical extension' => ['leaf-critical', ['int'], ['root'], 'unhandled critical extension (depth 0: /CN=Path Leaf Critical)'],
            'same issuer name, wrong key only' => ['leaf-twin-b', [], ['twin-a'], 'certificate signature failure (depth 0: /CN=Leaf Twin B)'],
        ];
    }

    public function test_rejects_a_tampered_signature(): void
    {
        $tampered = self::$certs['leaf'];
        $tampered[strlen($tampered) - 5] = chr(ord($tampered[strlen($tampered) - 5]) ^ 0x01);

        $error = (new X509PathValidator)->validate($tampered, [self::$certs['int']], [self::$certs['root']], new \DateTimeImmutable);

        self::assertSame('certificate signature failure (depth 0: /CN=Path Leaf)', $error);
    }

    public function test_limits_the_path_depth(): void
    {
        $validator = new X509PathValidator(maxPathLength: 2);

        self::assertSame(
            'certificate chain too long (depth 1: /CN=Path Intermediate)',
            $validator->validate(self::$certs['leaf'], [self::$certs['int']], [self::$certs['root']], new \DateTimeImmutable),
        );
        self::assertNull($validator->validate(self::$certs['leaf'], [], [self::$certs['int']], new \DateTimeImmutable));
    }

    public function test_reports_undecodable_inputs(): void
    {
        $validator = new X509PathValidator;
        $now = new \DateTimeImmutable;

        self::assertSame('Could not decode signer certificate from CMS payload.', $validator->validate("\x30\x00", [], [self::$certs['root']], $now));
        self::assertSame('Trust store does not contain any readable certificate.', $validator->validate(self::$certs['leaf'], [], ['garbage'], $now));
        self::assertNull($validator->validate(self::$certs['leaf'], ['garbage', self::$certs['int']], [self::$certs['root']], $now));
    }

    public function test_reads_certificates_from_pem_and_der_bundles(): void
    {
        $root = self::$certs['root'];
        $pem = static fn (string $label, string $der): string => "-----BEGIN $label-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END $label-----\n";

        self::assertSame([$root, self::$certs['int']], X509PathValidator::certificatesFromBundle(
            "comment\n".$pem('CERTIFICATE', $root).$pem('CERTIFICATE', self::$certs['int']),
        ));
        self::assertSame([$root], X509PathValidator::certificatesFromBundle($pem('TRUSTED CERTIFICATE', $root."\x30\x00")));
        self::assertSame([$root], X509PathValidator::certificatesFromBundle($pem('X509 CERTIFICATE', $root)));
        self::assertSame([$root], X509PathValidator::certificatesFromBundle($root));
        self::assertSame([], X509PathValidator::certificatesFromBundle('not a certificate'));
        self::assertSame([], X509PathValidator::certificatesFromBundle(
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
            ."-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"
            .$pem('CERTIFICATE', "\x30\x85"),
        ));
    }

    /**
     * @param  list<string>  $untrusted
     * @param  list<string>  $trusted
     */
    private function validate(string $leaf, array $untrusted, array $trusted, string $at): ?string
    {
        $pick = static fn (array $names): array => array_map(static fn (string $name): string => self::$certs[$name], $names);

        return (new X509PathValidator)->validate(self::$certs[$leaf], $pick($untrusted), $pick($trusted), new \DateTimeImmutable($at));
    }

    private static function root(string $file, string $cn, string $extensions, string $notBefore, string $notAfter, ?string $reuseKey = null): void
    {
        $keyFile = ($reuseKey ?? $file).'.key';
        $key = $reuseKey !== null ? "-key $keyFile" : "-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $keyFile";
        self::shell(<<<SH
            openssl req -new $key -out $file.csr -subj "/CN=$cn" -config ca.cnf
            openssl ca -batch -selfsign -config ca.cnf -keyfile $keyFile -in $file.csr -out $file.crt -extensions $extensions -startdate $notBefore -enddate $notAfter -notext
            SH);
    }

    private static function issue(string $file, string $cn, string $issuer, string $extensions, string $notBefore, string $notAfter): void
    {
        self::shell(<<<SH
            openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $file.key -out $file.csr -subj "/CN=$cn" -config ca.cnf
            openssl ca -batch -config ca.cnf -cert $issuer.crt -keyfile $issuer.key -in $file.csr -out $file.crt -extensions $extensions -startdate $notBefore -enddate $notAfter -notext
            SH);
    }

    private static function shell(string $script): void
    {
        exec('(set -e; cd '.escapeshellarg(self::$dir).'; '.$script.') 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            self::fail(implode("\n", $output));
        }
    }
}
