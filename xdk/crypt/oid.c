﻿/**
* \file oid.c
*
* \brief Object Identifier (OID) database
*
*  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
*  SPDX-License-Identifier: Apache-2.0
*
*  Licensed under the Apache License, Version 2.0 (the "License"); you may
*  not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
*  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
*  This file is part of mbed TLS (https://tls.mbed.org)
*/

#include "oid.h"
#include "x509.h"
#include "cipher.h"

#include "../xdkimp.h"
/******************************************************************************************************************/

/*
* Macro to automatically add the size of #define'd OIDs
*/
#define ADD_LEN(s)      s, OID_SIZE(s)

/*
* Macro to generate an internal function for oid_XXX_from_asn1() (used by
* the other functions)
*/
#define FN_OID_TYPED_FROM_ASN1( TYPE_T, NAME, LIST )                    \
    static const TYPE_T * oid_ ## NAME ## _from_asn1(                   \
                                      const asn1_buf *oid )     \
	    {                                                                   \
        const TYPE_T *p = (LIST);                                       \
        const oid_descriptor_t *cur =                           \
            (const oid_descriptor_t *) p;                       \
        if( p == NULL || oid == NULL ) return( NULL );                  \
		        while( cur->asn1 != NULL ) {                                    \
            if( cur->asn1_len == oid->len &&                            \
                xmem_comp( cur->asn1, oid->p, oid->len ) == 0 ) {          \
                return( p );                                            \
			            }                                                           \
            p++;                                                        \
            cur = (const oid_descriptor_t *) p;                 \
				        }                                                               \
        return( NULL );                                                 \
	    }

/*
* Macro to generate a function for retrieving a single attribute from the
* descriptor of an oid_descriptor_t wrapper.
*/
#define FN_OID_GET_DESCRIPTOR_ATTR1(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1) \
int FN_NAME( const asn1_buf *oid, ATTR1_TYPE * ATTR1 )                  \
{                                                                       \
    const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1( oid );        \
    if( data == NULL ) return( C_ERR );            \
    *ATTR1 = data->descriptor.ATTR1;                                    \
    return( 0 );                                                        \
}

/*
* Macro to generate a function for retrieving a single attribute from an
* oid_descriptor_t wrapper.
*/
#define FN_OID_GET_ATTR1(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1) \
int FN_NAME( const asn1_buf *oid, ATTR1_TYPE * ATTR1 )                  \
{                                                                       \
    const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1( oid );        \
    if( data == NULL ) return( C_ERR );            \
    *ATTR1 = data->ATTR1;                                               \
    return( 0 );                                                        \
}

/*
* Macro to generate a function for retrieving two attributes from an
* oid_descriptor_t wrapper.
*/
#define FN_OID_GET_ATTR2(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1,     \
                         ATTR2_TYPE, ATTR2)                                 \
int FN_NAME( const asn1_buf *oid, ATTR1_TYPE * ATTR1,               \
                                          ATTR2_TYPE * ATTR2 )              \
{                                                                           \
    const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1( oid );            \
    if( data == NULL ) return( C_ERR );                 \
    *(ATTR1) = data->ATTR1;                                                 \
    *(ATTR2) = data->ATTR2;                                                 \
    return( 0 );                                                            \
}

/*
* Macro to generate a function for retrieving the OID based on a single
* attribute from a oid_descriptor_t wrapper.
*/
#define FN_OID_GET_OID_BY_ATTR1(FN_NAME, TYPE_T, LIST, ATTR1_TYPE, ATTR1)   \
int FN_NAME( ATTR1_TYPE ATTR1, const char **oid, dword_t *olen )             \
{                                                                           \
    const TYPE_T *cur = (LIST);                                             \
	    while( cur->descriptor.asn1 != NULL ) {                                 \
        if( cur->ATTR1 == (ATTR1) ) {                                       \
            *oid = cur->descriptor.asn1;                                    \
            *olen = cur->descriptor.asn1_len;                               \
            return( 0 );                                                    \
		        }                                                                   \
        cur++;                                                              \
		    }                                                                       \
    return( C_ERR );                                    \
}

/*
* Macro to generate a function for retrieving the OID based on two
* attributes from a oid_descriptor_t wrapper.
*/
#define FN_OID_GET_OID_BY_ATTR2(FN_NAME, TYPE_T, LIST, ATTR1_TYPE, ATTR1,   \
                                ATTR2_TYPE, ATTR2)                          \
int FN_NAME( ATTR1_TYPE ATTR1, ATTR2_TYPE ATTR2, const char **oid ,         \
             dword_t *olen )                                                 \
{                                                                           \
    const TYPE_T *cur = (LIST);                                             \
	    while( cur->descriptor.asn1 != NULL ) {                                 \
        if( cur->ATTR1 == (ATTR1) && cur->ATTR2 == (ATTR2) ) {              \
            *oid = cur->descriptor.asn1;                                    \
            *olen = cur->descriptor.asn1_len;                               \
            return( 0 );                                                    \
		        }                                                                   \
        cur++;                                                              \
		    }                                                                       \
    return( C_ERR );                                   \
}

/*
* For X520 attribute types
*/
typedef struct {
	oid_descriptor_t    descriptor;
	const char          *short_name;
} oid_x520_attr_t;

static const oid_x520_attr_t oid_x520_attr_type[] =
{
	{
		{ ADD_LEN(OID_AT_CN), "id-at-commonName", "Common Name" },
		"CN",
	},
	{
		{ ADD_LEN(OID_AT_COUNTRY), "id-at-countryName", "Country" },
		"C",
	},
	{
		{ ADD_LEN(OID_AT_LOCALITY), "id-at-locality", "Locality" },
		"L",
	},
	{
		{ ADD_LEN(OID_AT_STATE), "id-at-state", "State" },
		"ST",
	},
	{
		{ ADD_LEN(OID_AT_ORGANIZATION), "id-at-organizationName", "Organization" },
		"O",
	},
	{
		{ ADD_LEN(OID_AT_ORG_UNIT), "id-at-organizationalUnitName", "Org Unit" },
		"OU",
	},
	{
		{ ADD_LEN(OID_PKCS9_EMAIL), "emailAddress", "E-mail address" },
		"emailAddress",
	},
	{
		{ ADD_LEN(OID_AT_SERIAL_NUMBER), "id-at-serialNumber", "Serial number" },
		"serialNumber",
	},
	{
		{ ADD_LEN(OID_AT_POSTAL_ADDRESS), "id-at-postalAddress", "Postal address" },
		"postalAddress",
	},
	{
		{ ADD_LEN(OID_AT_POSTAL_CODE), "id-at-postalCode", "Postal code" },
		"postalCode",
	},
	{
		{ ADD_LEN(OID_AT_SUR_NAME), "id-at-surName", "Surname" },
		"SN",
	},
	{
		{ ADD_LEN(OID_AT_GIVEN_NAME), "id-at-givenName", "Given name" },
		"GN",
	},
	{
		{ ADD_LEN(OID_AT_INITIALS), "id-at-initials", "Initials" },
		"initials",
	},
	{
		{ ADD_LEN(OID_AT_GENERATION_QUALIFIER), "id-at-generationQualifier", "Generation qualifier" },
		"generationQualifier",
	},
	{
		{ ADD_LEN(OID_AT_TITLE), "id-at-title", "Title" },
		"title",
	},
	{
		{ ADD_LEN(OID_AT_DN_QUALIFIER), "id-at-dnQualifier", "Distinguished Name qualifier" },
		"dnQualifier",
	},
	{
		{ ADD_LEN(OID_AT_PSEUDONYM), "id-at-pseudonym", "Pseudonym" },
		"pseudonym",
	},
	{
		{ ADD_LEN(OID_DOMAIN_COMPONENT), "id-domainComponent", "Domain component" },
		"DC",
	},
	{
		{ ADD_LEN(OID_AT_UNIQUE_IDENTIFIER), "id-at-uniqueIdentifier", "Unique Identifier" },
		"uniqueIdentifier",
	},
	{
		{ NULL, 0, NULL, NULL },
		NULL,
	}
};

FN_OID_TYPED_FROM_ASN1(oid_x520_attr_t, x520_attr, oid_x520_attr_type)
FN_OID_GET_ATTR1(oid_get_attr_short_name, oid_x520_attr_t, x520_attr, const char *, short_name)

/*
* For X509 extensions
*/
typedef struct {
	oid_descriptor_t    descriptor;
	int                 ext_type;
} oid_x509_ext_t;

static const oid_x509_ext_t oid_x509_ext[] =
{
	{
		{ ADD_LEN(OID_BASIC_CONSTRAINTS), "id-ce-basicConstraints", "Basic Constraints" },
		X509_EXT_BASIC_CONSTRAINTS,
	},
	{
		{ ADD_LEN(OID_KEY_USAGE), "id-ce-keyUsage", "Key Usage" },
		X509_EXT_KEY_USAGE,
	},
	{
		{ ADD_LEN(OID_EXTENDED_KEY_USAGE), "id-ce-extKeyUsage", "Extended Key Usage" },
		X509_EXT_EXTENDED_KEY_USAGE,
	},
	{
		{ ADD_LEN(OID_SUBJECT_ALT_NAME), "id-ce-subjectAltName", "Subject Alt Name" },
		X509_EXT_SUBJECT_ALT_NAME,
	},
	{
		{ ADD_LEN(OID_NS_CERT_TYPE), "id-netscape-certtype", "Netscape Certificate Type" },
		X509_EXT_NS_CERT_TYPE,
	},
	{
		{ NULL, 0, NULL, NULL },
		0,
	},
};

FN_OID_TYPED_FROM_ASN1(oid_x509_ext_t, x509_ext, oid_x509_ext)
FN_OID_GET_ATTR1(oid_get_x509_ext_type, oid_x509_ext_t, x509_ext, int, ext_type)

static const oid_descriptor_t oid_ext_key_usage[] =
{
	{ ADD_LEN(OID_SERVER_AUTH), "id-kp-serverAuth", "TLS Web Server Authentication" },
	{ ADD_LEN(OID_CLIENT_AUTH), "id-kp-clientAuth", "TLS Web Client Authentication" },
	{ ADD_LEN(OID_CODE_SIGNING), "id-kp-codeSigning", "Code Signing" },
	{ ADD_LEN(OID_EMAIL_PROTECTION), "id-kp-emailProtection", "E-mail Protection" },
	{ ADD_LEN(OID_TIME_STAMPING), "id-kp-timeStamping", "Time Stamping" },
	{ ADD_LEN(OID_OCSP_SIGNING), "id-kp-OCSPSigning", "OCSP Signing" },
	{ NULL, 0, NULL, NULL },
};

FN_OID_TYPED_FROM_ASN1(oid_descriptor_t, ext_key_usage, oid_ext_key_usage)
FN_OID_GET_ATTR1(oid_get_extended_key_usage, oid_descriptor_t, ext_key_usage, const char *, description)


/*
* For SignatureAlgorithmIdentifier
*/
typedef struct {
	oid_descriptor_t    descriptor;
	md_type_t           md_alg;
	pk_type_t           pk_alg;
} oid_sig_alg_t;

static const oid_sig_alg_t oid_sig_alg[] =
{
	{
		{ ADD_LEN(OID_PKCS1_MD2), "md2WithRSAEncryption", "RSA with MD2" },
		MD_MD2, PK_RSA,
	},
	{
		{ ADD_LEN(OID_PKCS1_MD4), "md4WithRSAEncryption", "RSA with MD4" },
		MD_MD4, PK_RSA,
	},
	{
		{ ADD_LEN(OID_PKCS1_MD5), "md5WithRSAEncryption", "RSA with MD5" },
		MD_MD5, PK_RSA,
	},
	{
		{ ADD_LEN(OID_PKCS1_SHA1), "sha-1WithRSAEncryption", "RSA with SHA1" },
		MD_SHA1, PK_RSA,
	},
	{
		{ ADD_LEN(OID_PKCS1_SHA224), "sha224WithRSAEncryption", "RSA with SHA-224" },
		MD_SHA224, PK_RSA,
	},
	{
		{ ADD_LEN(OID_PKCS1_SHA256), "sha256WithRSAEncryption", "RSA with SHA-256" },
		MD_SHA256, PK_RSA,
	},
	{
		{ ADD_LEN(OID_PKCS1_SHA384), "sha384WithRSAEncryption", "RSA with SHA-384" },
		MD_SHA384, PK_RSA,
	},
	{
		{ ADD_LEN(OID_PKCS1_SHA512), "sha512WithRSAEncryption", "RSA with SHA-512" },
		MD_SHA512, PK_RSA,
	},
	{
		{ ADD_LEN(OID_RSA_SHA_OBS), "sha-1WithRSAEncryption", "RSA with SHA1" },
		MD_SHA1, PK_RSA,
	},
	{
		{ ADD_LEN(OID_ECDSA_SHA1), "ecdsa-with-SHA1", "ECDSA with SHA1" },
		MD_SHA1, PK_ECDSA,
	},
	{
		{ ADD_LEN(OID_ECDSA_SHA224), "ecdsa-with-SHA224", "ECDSA with SHA224" },
		MD_SHA224, PK_ECDSA,
	},
	{
		{ ADD_LEN(OID_ECDSA_SHA256), "ecdsa-with-SHA256", "ECDSA with SHA256" },
		MD_SHA256, PK_ECDSA,
	},
	{
		{ ADD_LEN(OID_ECDSA_SHA384), "ecdsa-with-SHA384", "ECDSA with SHA384" },
		MD_SHA384, PK_ECDSA,
	},
	{
		{ ADD_LEN(OID_ECDSA_SHA512), "ecdsa-with-SHA512", "ECDSA with SHA512" },
		MD_SHA512, PK_ECDSA,
	},
	{
		{ ADD_LEN(OID_RSASSA_PSS), "RSASSA-PSS", "RSASSA-PSS" },
		MD_NONE, PK_RSASSA_PSS,
	},
	{
		{ NULL, 0, NULL, NULL },
		MD_NONE, PK_NONE,
	},
};

FN_OID_TYPED_FROM_ASN1(oid_sig_alg_t, sig_alg, oid_sig_alg)
FN_OID_GET_DESCRIPTOR_ATTR1(oid_get_sig_alg_desc, oid_sig_alg_t, sig_alg, const char *, description)
FN_OID_GET_ATTR2(oid_get_sig_alg, oid_sig_alg_t, sig_alg, md_type_t, md_alg, pk_type_t, pk_alg)
FN_OID_GET_OID_BY_ATTR2(oid_get_oid_by_sig_alg, oid_sig_alg_t, oid_sig_alg, pk_type_t, pk_alg, md_type_t, md_alg)

/*
* For PublicKeyInfo (PKCS1, RFC 5480)
*/
typedef struct {
	oid_descriptor_t    descriptor;
	pk_type_t           pk_alg;
} oid_pk_alg_t;

static const oid_pk_alg_t oid_pk_alg[] =
{
	{
		{ ADD_LEN(OID_PKCS1_RSA), "rsaEncryption", "RSA" },
		PK_RSA,
	},
	{
		{ ADD_LEN(OID_EC_ALG_UNRESTRICTED), "id-ecPublicKey", "Generic EC key" },
		PK_ECKEY,
	},
	{
		{ ADD_LEN(OID_EC_ALG_ECDH), "id-ecDH", "EC key for ECDH" },
		PK_ECKEY_DH,
	},
	{
		{ NULL, 0, NULL, NULL },
		PK_NONE,
	},
};

FN_OID_TYPED_FROM_ASN1(oid_pk_alg_t, pk_alg, oid_pk_alg)
FN_OID_GET_ATTR1(oid_get_pk_alg, oid_pk_alg_t, pk_alg, pk_type_t, pk_alg)
FN_OID_GET_OID_BY_ATTR1(oid_get_oid_by_pk_alg, oid_pk_alg_t, oid_pk_alg, pk_type_t, pk_alg)

/*
* For namedCurve (RFC 5480)
*/
typedef struct {
	oid_descriptor_t    descriptor;
	ecp_group_id        grp_id;
} oid_ecp_grp_t;

static const oid_ecp_grp_t oid_ecp_grp[] =
{
	{
		{ ADD_LEN(OID_EC_GRP_SECP192R1), "secp192r1", "secp192r1" },
		ECP_DP_SECP192R1,
	},
	{
		{ ADD_LEN(OID_EC_GRP_SECP224R1), "secp224r1", "secp224r1" },
		ECP_DP_SECP224R1,
	},
	{
		{ ADD_LEN(OID_EC_GRP_SECP256R1), "secp256r1", "secp256r1" },
		ECP_DP_SECP256R1,
	},
	{
		{ ADD_LEN(OID_EC_GRP_SECP384R1), "secp384r1", "secp384r1" },
		ECP_DP_SECP384R1,
	},
	{
		{ ADD_LEN(OID_EC_GRP_SECP521R1), "secp521r1", "secp521r1" },
		ECP_DP_SECP521R1,
	},
	{
		{ ADD_LEN(OID_EC_GRP_SECP192K1), "secp192k1", "secp192k1" },
		ECP_DP_SECP192K1,
	},
	{
		{ ADD_LEN(OID_EC_GRP_SECP224K1), "secp224k1", "secp224k1" },
		ECP_DP_SECP224K1,
	},
	{
		{ ADD_LEN(OID_EC_GRP_SECP256K1), "secp256k1", "secp256k1" },
		ECP_DP_SECP256K1,
	},
	{
		{ ADD_LEN(OID_EC_GRP_BP256R1), "brainpoolP256r1", "brainpool256r1" },
		ECP_DP_BP256R1,
	},
	{
		{ ADD_LEN(OID_EC_GRP_BP384R1), "brainpoolP384r1", "brainpool384r1" },
		ECP_DP_BP384R1,
	},
	{
		{ ADD_LEN(OID_EC_GRP_BP512R1), "brainpoolP512r1", "brainpool512r1" },
		ECP_DP_BP512R1,
	},
	{
		{ NULL, 0, NULL, NULL },
		ECP_DP_NONE,
	},
};

FN_OID_TYPED_FROM_ASN1(oid_ecp_grp_t, grp_id, oid_ecp_grp)
FN_OID_GET_ATTR1(oid_get_ec_grp, oid_ecp_grp_t, grp_id, ecp_group_id, grp_id)
FN_OID_GET_OID_BY_ATTR1(oid_get_oid_by_ec_grp, oid_ecp_grp_t, oid_ecp_grp, ecp_group_id, grp_id)


/*
* For PKCS#5 PBES2 encryption algorithm
*/
typedef struct {
	oid_descriptor_t    descriptor;
	cipher_type_t       cipher_alg;
} oid_cipher_alg_t;

static const oid_cipher_alg_t oid_cipher_alg[] =
{
	{
		{ ADD_LEN(OID_DES_CBC), "desCBC", "DES-CBC" },
		CIPHER_DES_CBC,
	},
	{
		{ ADD_LEN(OID_DES_EDE3_CBC), "des-ede3-cbc", "DES-EDE3-CBC" },
		CIPHER_DES_EDE3_CBC,
	},
	{
		{ NULL, 0, NULL, NULL },
		CIPHER_NONE,
	},
};

FN_OID_TYPED_FROM_ASN1(oid_cipher_alg_t, cipher_alg, oid_cipher_alg)
FN_OID_GET_ATTR1(oid_get_cipher_alg, oid_cipher_alg_t, cipher_alg, cipher_type_t, cipher_alg)


/*
* For digestAlgorithm
*/
typedef struct {
	oid_descriptor_t    descriptor;
	md_type_t           md_alg;
} oid_md_alg_t;

static const oid_md_alg_t oid_md_alg[] =
{
	{
		{ ADD_LEN(OID_DIGEST_ALG_MD2), "id-md2", "MD2" },
		MD_MD2,
	},
	{
		{ ADD_LEN(OID_DIGEST_ALG_MD4), "id-md4", "MD4" },
		MD_MD4,
	},
	{
		{ ADD_LEN(OID_DIGEST_ALG_MD5), "id-md5", "MD5" },
		MD_MD5,
	},
	{
		{ ADD_LEN(OID_DIGEST_ALG_SHA1), "id-sha1", "SHA-1" },
		MD_SHA1,
	},
	{
		{ ADD_LEN(OID_DIGEST_ALG_SHA224), "id-sha224", "SHA-224" },
		MD_SHA224,
	},
	{
		{ ADD_LEN(OID_DIGEST_ALG_SHA256), "id-sha256", "SHA-256" },
		MD_SHA256,
	},
	{
		{ ADD_LEN(OID_DIGEST_ALG_SHA384), "id-sha384", "SHA-384" },
		MD_SHA384,
	},
	{
		{ ADD_LEN(OID_DIGEST_ALG_SHA512), "id-sha512", "SHA-512" },
		MD_SHA512,
	},
	{
		{ NULL, 0, NULL, NULL },
		MD_NONE,
	},
};

FN_OID_TYPED_FROM_ASN1(oid_md_alg_t, md_alg, oid_md_alg)
FN_OID_GET_ATTR1(oid_get_md_alg, oid_md_alg_t, md_alg, md_type_t, md_alg)
FN_OID_GET_OID_BY_ATTR1(oid_get_oid_by_md, oid_md_alg_t, oid_md_alg, md_type_t, md_alg)

/*
* For HMAC digestAlgorithm
*/
typedef struct {
	oid_descriptor_t    descriptor;
	md_type_t           md_hmac;
} oid_md_hmac_t;

static const oid_md_hmac_t oid_md_hmac[] =
{
	{
		{ ADD_LEN(OID_HMAC_SHA1), "hmacSHA1", "HMAC-SHA-1" },
		MD_SHA1,
	},
	{
		{ ADD_LEN(OID_HMAC_SHA224), "hmacSHA224", "HMAC-SHA-224" },
		MD_SHA224,
	},
	{
		{ ADD_LEN(OID_HMAC_SHA256), "hmacSHA256", "HMAC-SHA-256" },
		MD_SHA256,
	},
	{
		{ ADD_LEN(OID_HMAC_SHA384), "hmacSHA384", "HMAC-SHA-384" },
		MD_SHA384,
	},
	{
		{ ADD_LEN(OID_HMAC_SHA512), "hmacSHA512", "HMAC-SHA-512" },
		MD_SHA512,
	},
	{
		{ NULL, 0, NULL, NULL },
		MD_NONE,
	},
};

FN_OID_TYPED_FROM_ASN1(oid_md_hmac_t, md_hmac, oid_md_hmac)
FN_OID_GET_ATTR1(oid_get_md_hmac, oid_md_hmac_t, md_hmac, md_type_t, md_hmac)


/*
* For PKCS#12 PBEs
*/
typedef struct {
	oid_descriptor_t    descriptor;
	md_type_t           md_alg;
	cipher_type_t       cipher_alg;
} oid_pkcs12_pbe_alg_t;

static const oid_pkcs12_pbe_alg_t oid_pkcs12_pbe_alg[] =
{
	{
		{ ADD_LEN(OID_PKCS12_PBE_SHA1_DES3_EDE_CBC), "pbeWithSHAAnd3-KeyTripleDES-CBC", "PBE with SHA1 and 3-Key 3DES" },
		MD_SHA1, CIPHER_DES_EDE3_CBC,
	},
	{
		{ ADD_LEN(OID_PKCS12_PBE_SHA1_DES2_EDE_CBC), "pbeWithSHAAnd2-KeyTripleDES-CBC", "PBE with SHA1 and 2-Key 3DES" },
		MD_SHA1, CIPHER_DES_EDE_CBC,
	},
	{
		{ NULL, 0, NULL, NULL },
		MD_NONE, CIPHER_NONE,
	},
};

FN_OID_TYPED_FROM_ASN1(oid_pkcs12_pbe_alg_t, pkcs12_pbe_alg, oid_pkcs12_pbe_alg)
FN_OID_GET_ATTR2(oid_get_pkcs12_pbe_alg, oid_pkcs12_pbe_alg_t, pkcs12_pbe_alg, md_type_t, md_alg, cipher_type_t, cipher_alg)


#define OID_SAFE_SNPRINTF                               \
    do {                                                \
        if( ret < 0 || (dword_t) ret >= n )              \
            return( C_ERR );    \
                                                        \
        n -= (dword_t) ret;                              \
        p += (dword_t) ret;                              \
	    } while( 0 )

/* Return the x.y.z.... style numeric string for the given OID */
int oid_get_numeric_string(char *buf, dword_t size,
const asn1_buf *oid)
{
	int ret;
	dword_t i, n;
	unsigned int value;
	char *p;

	p = buf;
	n = size;

	/* First byte contains first two dots */
	if (oid->len > 0)
	{
		ret = snprintf(p, n, "%d.%d", oid->p[0] / 40, oid->p[0] % 40);
		OID_SAFE_SNPRINTF;
	}

	value = 0;
	for (i = 1; i < oid->len; i++)
	{
		/* Prevent overflow in value. */
		if (((value << 7) >> 7) != value)
			return(C_ERR);

		value <<= 7;
		value += oid->p[i] & 0x7F;

		if (!(oid->p[i] & 0x80))
		{
			/* Last byte */
			ret = snprintf(p, n, ".%d", value);
			OID_SAFE_SNPRINTF;
			value = 0;
		}
	}

	return((int)(size - n));
}

