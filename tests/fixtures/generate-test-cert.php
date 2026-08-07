<?php

declare(strict_types=1);

/*
 * Generates the test certificate used by the test suite:
 * tests/fixtures/generated/test-cert.p12 (password "secret").
 *
 * The .p12 container is not committed to the repository (see .gitignore);
 * run `composer fixtures:generate` before `composer test`, or let the tests
 * generate it on demand.
 */

const FIXTURES_DIR = __DIR__;
const GENERATED_DIR = FIXTURES_DIR . '/generated';
const P12_PATH = GENERATED_DIR . '/test-cert.p12';
const CERT_PEM_PATH = GENERATED_DIR . '/cert.pem';
const PASSWORD = 'secret';

if (! is_dir(GENERATED_DIR) && ! mkdir(GENERATED_DIR, 0777, true) && ! is_dir(GENERATED_DIR)) {
    fwrite(STDERR, "Could not create generated fixtures directory.\n");
    exit(1);
}

/*
 * Some PHP images compile OpenSSL statically with a default config path that
 * does not exist (/ssl/openssl.cnf), which makes every openssl_* call fail
 * with "system library::No such file or directory". Pass an explicit config
 * file to the openssl_* calls instead of relying on the environment.
 */
$opensslConf = null;
foreach (['/etc/ssl/openssl.cnf', '/usr/lib/ssl/openssl.cnf'] as $candidate) {
    if (is_file($candidate)) {
        $opensslConf = $candidate;
        break;
    }
}

$keyOptions = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
if ($opensslConf !== null) {
    $keyOptions['config'] = $opensslConf;
}

$key = openssl_pkey_new($keyOptions);
if ($key === false) {
    fwrite(STDERR, "Could not generate RSA key pair.\n");
    exit(1);
}

$dn = [
    'countryName' => 'EC',
    'stateOrProvinceName' => 'Pichincha',
    'localityName' => 'Quito',
    'organizationName' => 'Empresa de Prueba S.A.',
    'organizationalUnitName' => 'Tecnologia',
    'commonName' => 'Firma Prueba Test',
];

$csr = openssl_csr_new($dn, $key, ['digest_alg' => 'sha256'] + ($opensslConf !== null ? ['config' => $opensslConf] : []));
if ($csr === false) {
    fwrite(STDERR, "Could not create certificate request.\n");
    exit(1);
}

$serial = random_int(1_000_000, 99_999_999);

$cert = openssl_csr_sign(
    $csr,
    null,
    $key,
    $days = 36500,
    ['digest_alg' => 'sha256'] + ($opensslConf !== null ? ['config' => $opensslConf] : []),
    $serial
);
if ($cert === false) {
    fwrite(STDERR, "Could not self-sign the certificate.\n");
    exit(1);
}

$pkcs12 = [];
$ok = openssl_pkcs12_export($cert, $pkcs12, $key, PASSWORD);
if ($ok && ! empty($pkcs12)) {
    file_put_contents(P12_PATH, $pkcs12);
} else {
    fwrite(STDERR, 'Could not export PKCS#12 container: ' . openssl_error_string() . PHP_EOL);
    exit(1);
}

openssl_x509_export($cert, $certPem);
file_put_contents(CERT_PEM_PATH, $certPem);

echo "Generated tests/fixtures/generated/test-cert.p12 (password: secret), cert.pem.\n";
exit(0);