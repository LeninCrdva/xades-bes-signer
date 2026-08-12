# XAdES-BES Signer

Librería PHP para firmar y verificar documentos XML bajo el estándar
**XAdES-BES**, compatible con los requisitos de facturación electrónica del
**SRI de Ecuador** (misma estructura que genera la implementación de
referencia XAdES4J que el SRI acepta).

## Características

- Firma **enveloped** XAdES-BES sobre la raíz del documento (XML-DSig +
  XAdES `QualifyingProperties`).
- Estructura espejo de la referencia aceptada por el SRI:
  - 3 referencias en `SignedInfo` en orden: `SignedProperties` → `KeyInfo` → documento.
  - `ds:KeyInfo` con certificado (`ds:X509Certificate`) y clave pública
    (`ds:KeyValue`/`ds:RSAKeyValue`).
  - `xades:Description` = "contenido comprobante" y `xades:MimeType` en `DataObjectFormat`.
  - Base64 envuelto a 76 caracteres por línea.
  - Namespaces `ds`/`xades` declarados una sola vez en `ds:Signature`.
- **SHA-1 por defecto** (`rsa-sha1`, digest `sha1` y `CertDigest` `sha1`), tal
  como exige el SRI; **SHA-256** disponible de forma opcional.
- Verificación exhaustiva: firma RSA sobre `SignedInfo`, digest del
  documento, de `SignedProperties` y de `KeyInfo`, coincidencia de
  `CertDigest`/`IssuerSerial` y vigencia del certificado.
- Soporte de certificados PKCS#12 (`.p12`/.`pfx`) locales.
- Interfaz `PrivateKeySignerInterface` para firmar con **HSM/remoto** o
  cualquier otro origen de clave.
- Firmado por lotes (`BatchSigner`).
- CLI: `bin/xades-bes`.
- Fixtures y validación contra los XSD oficiales del SRI.

## Requisitos

- PHP >= 8.1
- Extensiones: `dom`, `openssl`, `json`
- OpenSSL 3.x con el proveedor **legacy** activado (ver más abajo).

## Instalación

```bash
composer require lenin/xades-bes-signer
```

## OpenSSL 3.x: activar el proveedor legacy

**Importante.** Los certificados `.p12` emitidos por las entidades
certificadoras ecuatorianas (por ejemplo los tokens del SRI o del BCE)
suelen proteger la clave privada con algoritmos legacy como **3DES o RC2**.
OpenSSL 3.x **desactiva esos algoritmos por defecto**, por lo que
`P12CertificateLoader` fallará al leer el contenedor con un error similar a:

```
Could not decrypt PKCS#12 container (wrong password or corrupt file?).
```

Para poder leer estos certificados es **obligatorio activar el proveedor
legacy de OpenSSL**. Incluimos un fichero de configuración listo para usar en
`docker/openssl.cnf`:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
```

### Docker

Monta el fichero sobre la configuración de OpenSSL del contenedor PHP y
reinicia el servicio:

```yaml
services:
  php:
    build: .
    volumes:
      - ./docker/openssl.cnf:/etc/ssl/openssl.cnf:ro
```

> Las imágenes PHP oficiales con OpenSSL compilado de forma estática leen la
> configuración desde una ruta predefinida (p. ej. `/ssl/openssl.cnf`), que
> puede no existir. En ese caso monta el fichero también ahí:
>
> ```yaml
> volumes:
>   - ./docker/openssl.cnf:/ssl/openssl.cnf:ro
> ```
>
> Ten en cuenta que una variable de entorno `OPENSSL_CONF` establecida dentro
> del proceso PHP puede llegar demasiado tarde cuando OpenSSL ya inicializó
> sus proveedores; el montaje del fichero en la ruta esperada es el método
> más fiable.

### Host local

Apunta `OPENSSL_CONF` al fichero antes de arrancar el proceso PHP:

```bash
export OPENSSL_CONF=/ruta/a/docker/openssl.cnf
php -S localhost:8000
```

Si usas PHP-FPM o Apache, exporta la variable en la configuración del
servicio y reinícialo.

### Comprobación

```bash
php -r 'var_dump(openssl_get_provider_configs());'
```

Debe aparecer el proveedor `legacy`. También puedes verificar la lectura
directa de tu certificado:

```bash
php -r 'require "vendor/autoload.php";
$s = \XadesBesSigner\Certificate\P12CertificateLoader::fromFile("token.p12", "clave");
echo $s->getCertificate()->getCommonName(), PHP_EOL;'
```

## Uso rápido

### Firmar un documento

```php
<?php

require 'vendor/autoload.php';

use XadesBesSigner\Certificate\P12CertificateLoader;
use XadesBesSigner\Signature\SignatureContext;
use XadesBesSigner\Signer;

$key = P12CertificateLoader::fromFile('token.p12', 'clave-de-token');

// SHA-1 por defecto (compatible con el SRI).
// Para SHA-256: new SignatureContext(DigestCalculator::SHA256);
$context = new SignatureContext();

$signer = new Signer($key);
$signedXml = $signer->signFromFile('factura.xml', $context);

file_put_contents('factura-firmada.xml', $signedXml);
```

### Verificar un documento firmado

```php
<?php

require 'vendor/autoload.php';

use XadesBesSigner\Verification\Verifier;

$result = (new Verifier())->verifyFromFile('factura-firmada.xml');

if ($result->isValid()) {
    echo 'Firma válida: ' . $result->getSignerCommonName() . PHP_EOL;
    echo 'Fecha: ' . $result->getSigningTime()?->format('c') . PHP_EOL;
} else {
    foreach ($result->getErrors() as $error) {
        echo "- {$error}" . PHP_EOL;
    }
}
```

### Algoritmo de firma

| Algoritmo | Digest | SignatureMethod | Uso |
|-----------|--------|-----------------|-----|
| `sha1` (default) | `sha1` | `rsa-sha1` | Compatibilidad total con el SRI |
| `sha256` | `sha256` | `rsa-sha256` | Alternativa más fuerte |

Selección explícita:

```php
use XadesBesSigner\Xml\DigestCalculator;

$key = P12CertificateLoader::fromFile('token.p12', 'clave', DigestCalculator::SHA256);
$context = new SignatureContext(DigestCalculator::SHA256);
```

> **Nota**: el algoritmo debe ser el mismo al cargar la clave y al crear el
> `SignatureContext`, porque el algoritmo de firma RSA se toma del
> `SignatureMethod` y debe coincidir con el que usó el proveedor de clave.

## Firmado por lotes

```php
use XadesBesSigner\BatchSigner;
use XadesBesSigner\Certificate\P12CertificateLoader;

$key = P12CertificateLoader::fromFile('token.p12', 'clave');
$batch = BatchSigner::with($key);

// Firma todos los *.xml del directorio; cada archivo se escribe como
// <nombre>-signed.xml en la carpeta de salida.
$results = $batch->signDirectory('facturas/', 'facturas/firmadas/');
```

## Firmado remoto / HSM

`P12CertificateLoader` devuelve un `PrivateKeySignerInterface`. Para usar un
HSM, un API o un KMS, implementa la misma interfaz con tu token o servicio:

```php
use XadesBesSigner\Certificate\Certificate;
use XadesBesSigner\KeyProvider\PrivateKeySignerInterface;

final class HsmSigner implements PrivateKeySignerInterface
{
    public function sign(string $data): string
    {
        // Delega en tu HSM/API: `$data` es el SignedInfo canónico (bytes).
    }

    public function getCertificate(): Certificate
    {
        // Certificado del token, p. ej. Certificate::fromPem(...).
    }
}
```

El pipeline de firma y verificación es idéntico al modo local.

## CLI

```bash
# Firmar un archivo (default SHA-1); genera <nombre>-signed.xml
bin/xades-bes sign token.p12 clave factura.xml

# Firmar todos los XML de un directorio
bin/xades-bes sign token.p12 clave facturas/ facturas/firmadas/

# Firmar con SHA-256
bin/xades-bes sign --sha256 token.p12 clave factura.xml

# Verificar
bin/xades-bes verify factura-firmada.xml
```

## Pruebas

```bash
composer install
composer fixtures:generate   # genera tests/fixtures/generated/test-cert.p12
composer test
```

## Compatibilidad con el SRI

La estructura generada es la misma que produce la implementación de
referencia XAdES4J aceptada por el SRI:

- `SignedInfo` con 3 referencias en orden exacto: `SignedProperties`,
  `KeyInfo` y documento.
- `ds:KeyInfo` con `Id`, certificado embebido y `KeyValue`/`RSAKeyValue`.
- `xades:Description` = `contenido comprobante` y `xades:MimeType` = `text/xml`.
- Base64 a 76 columnas y namespaces normalizados.
- SHA-1 en firma, digest y `CertDigest`.

## Licencia

MIT
