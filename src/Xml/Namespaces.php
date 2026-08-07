<?php

declare(strict_types=1);

namespace XadesBesSigner\Xml;

/**
 * URIs and algorithms defined by XMLDSig and XAdES specifications plus the
 * SRI (Ecuador) technical requirements.
 */
final class Namespaces
{
    public const XMLDSIG = 'http://www.w3.org/2000/09/xmldsig#';

    public const XADES = 'http://uri.etsi.org/01903/v1.3.2#';

    public const XADES_TYPE_SIGNED_PROPERTIES = 'http://uri.etsi.org/01903#SignedProperties';

    /** Canonicalization (inclusive) as required by the SRI. */
    public const C14N_INCLUSIVE = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';

    /** Canonicalization 1.1 inclusive-with-comments. */
    public const C14N_INCLUSIVE_WITH_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';

    /** Exclusive canonicalization (not used by default). */
    public const C14N_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    public const SIG_METHOD_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    public const SIG_METHOD_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

    /** Digest method algorithm URIs. */
    public const DIGEST_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

    public const DIGEST_SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';

    public const TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
}