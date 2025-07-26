/*
*  Privacy Enhanced Mail (PEM) decoding
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

#include "pem.h"
#include "cipher.h"
#include "md5.h"
#include "des.h"
#include "aes.h"
#include "b64.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
/******************************************************************************************************************/

void pem_init(pem_context *ctx)
{
	memset(ctx, 0, sizeof(pem_context));
}

/*
* Read a 16-byte hex string and convert it to binary
*/
static int pem_get_iv(const unsigned char *s, unsigned char *iv,
	uint32_t iv_len)
{
	uint32_t i, j, k;

	memset(iv, 0, iv_len);

	for (i = 0; i < iv_len * 2; i++, s++)
	{
		if (*s >= '0' && *s <= '9') j = *s - '0'; else
			if (*s >= 'A' && *s <= 'F') j = *s - '7'; else
				if (*s >= 'a' && *s <= 'f') j = *s - 'W'; else
				{
					return (-1);
				}

		k = ((i & 1) != 0) ? j : j << 4;

		iv[i >> 1] = (unsigned char)(iv[i >> 1] | k);
	}

	return(0);
}

static int pem_pbkdf1(unsigned char *key, uint32_t keylen,
	unsigned char *iv,
	const unsigned char *pwd, uint32_t pwdlen)
{
	md5_context md5_ctx;
	unsigned char md5sum[16];
	uint32_t use_len;
	int ret;

	md5_init(&md5_ctx);

	/*
	* key[ 0..15] = MD5(pwd || IV)
	*/
	if ((ret = md5_starts(&md5_ctx)) != 0)
		goto exit;
	if ((ret = md5_update(&md5_ctx, pwd, pwdlen)) != 0)
		goto exit;
	if ((ret = md5_update(&md5_ctx, iv, 8)) != 0)
		goto exit;
	if ((ret = md5_finish(&md5_ctx, md5sum)) != 0)
		goto exit;

	if (keylen <= 16)
	{
		memcpy(key, md5sum, keylen);
		goto exit;
	}

	memcpy(key, md5sum, 16);

	/*
	* key[16..23] = MD5(key[ 0..15] || pwd || IV])
	*/
	if ((ret = md5_starts(&md5_ctx)) != 0)
		goto exit;
	if ((ret = md5_update(&md5_ctx, md5sum, 16)) != 0)
		goto exit;
	if ((ret = md5_update(&md5_ctx, pwd, pwdlen)) != 0)
		goto exit;
	if ((ret = md5_update(&md5_ctx, iv, 8)) != 0)
		goto exit;
	if ((ret = md5_finish(&md5_ctx, md5sum)) != 0)
		goto exit;

	use_len = 16;
	if (keylen < 32)
		use_len = keylen - 16;

	memcpy(key + 16, md5sum, use_len);

exit:
	md5_free(&md5_ctx);
	memset(md5sum, 0, 16);

	return(ret);
}

/*
* Decrypt with DES-CBC, using PBKDF1 for key derivation
*/
static int pem_des_decrypt(unsigned char des_iv[8],
	unsigned char *buf, uint32_t buflen,
	const unsigned char *pwd, uint32_t pwdlen)
{
	des_context des_ctx;
	unsigned char des_key[8];
	int ret;

	des_init(&des_ctx);

	if ((ret = pem_pbkdf1(des_key, 8, des_iv, pwd, pwdlen)) != 0)
		goto exit;

	if ((ret = des_setkey_dec(&des_ctx, des_key)) != 0)
		goto exit;
	ret = des_crypt_cbc(&des_ctx, DES_DECRYPT, buflen,
		des_iv, buf, buf);

exit:
	des_free(&des_ctx);
	memset(des_key, 0, 8);

	return(ret);
}

/*
* Decrypt with 3DES-CBC, using PBKDF1 for key derivation
*/
static int pem_des3_decrypt(unsigned char des3_iv[8],
	unsigned char *buf, uint32_t buflen,
	const unsigned char *pwd, uint32_t pwdlen)
{
	des3_context des3_ctx;
	unsigned char des3_key[24];
	int ret;

	des3_init(&des3_ctx);

	if ((ret = pem_pbkdf1(des3_key, 24, des3_iv, pwd, pwdlen)) != 0)
		goto exit;

	if ((ret = des3_set3key_dec(&des3_ctx, des3_key)) != 0)
		goto exit;
	ret = des3_crypt_cbc(&des3_ctx, DES_DECRYPT, buflen,
		des3_iv, buf, buf);

exit:
	des3_free(&des3_ctx);
	memset(des3_key, 0, 24);

	return(ret);
}

/*
* Decrypt with AES-XXX-CBC, using PBKDF1 for key derivation
*/
static int pem_aes_decrypt(unsigned char aes_iv[16], unsigned int keylen,
	unsigned char *buf, uint32_t buflen,
	const unsigned char *pwd, uint32_t pwdlen)
{
	aes_context aes_ctx;
	unsigned char aes_key[32];
	int ret;

	aes_init(&aes_ctx);

	if ((ret = pem_pbkdf1(aes_key, keylen, aes_iv, pwd, pwdlen)) != 0)
		goto exit;

	if ((ret = aes_setkey_dec(&aes_ctx, aes_key, keylen * 8)) != 0)
		goto exit;
	ret = aes_crypt_cbc(&aes_ctx, AES_DECRYPT, buflen,
		aes_iv, buf, buf);

exit:
	aes_free(&aes_ctx);
	memset(aes_key, 0, keylen);

	return(ret);
}

int pem_read_buffer(pem_context *ctx, const char *header, const char *footer,
	const unsigned char *data, const unsigned char *pwd,
	uint32_t pwdlen, uint32_t *use_len)
{
	int ret, enc;
	uint32_t len;
	unsigned char *buf;
	const unsigned char *s1, *s2, *end;
	unsigned char pem_iv[16];
	cipher_type_t enc_alg = CIPHER_NONE;

	assert(ctx != NULL);

	s1 = (unsigned char *)strstr((const char *)data, header);

	if (s1 == NULL)
	{
		return ERR_PEM_NO_HEADER_FOOTER_PRESENT;
	}

	s2 = (unsigned char *)strstr((const char *)data, footer);

	if (s2 == NULL || s2 <= s1)
	{
		return ERR_PEM_NO_HEADER_FOOTER_PRESENT;
	}

	s1 += strlen(header);
	if (*s1 == ' ') s1++;
	if (*s1 == '\r') s1++;
	if (*s1 == '\n') s1++;
	else 
	{
		return ERR_PEM_NO_HEADER_FOOTER_PRESENT;
	}

	end = s2;
	end += strlen(footer);
	if (*end == ' ') end++;
	if (*end == '\r') end++;
	if (*end == '\n') end++;
	*use_len = end - data;

	enc = 0;

	if (s2 - s1 >= 22 && memcmp(s1, "Proc-Type: 4,ENCRYPTED", 22) == 0)
	{
		enc++;

		s1 += 22;
		if (*s1 == '\r') s1++;
		if (*s1 == '\n') s1++;
		else 
		{
			return (-1);
		}

		if (s2 - s1 >= 23 && memcmp(s1, "DEK-Info: DES-EDE3-CBC,", 23) == 0)
		{
			enc_alg = CIPHER_DES_EDE3_CBC;

			s1 += 23;
			if (s2 - s1 < 16 || pem_get_iv(s1, pem_iv, 8) != 0)
			{
				return (-1);
			}

			s1 += 16;
		}
		else if (s2 - s1 >= 18 && memcmp(s1, "DEK-Info: DES-CBC,", 18) == 0)
		{
			enc_alg = CIPHER_DES_CBC;

			s1 += 18;
			if (s2 - s1 < 16 || pem_get_iv(s1, pem_iv, 8) != 0)
			{
				return (-1);
			}

			s1 += 16;
		}

		if (s2 - s1 >= 14 && memcmp(s1, "DEK-Info: AES-", 14) == 0)
		{
			if (s2 - s1 < 22)
			{
				return (-1);
			}
			else if (memcmp(s1, "DEK-Info: AES-128-CBC,", 22) == 0)
				enc_alg = CIPHER_AES_128_CBC;
			else if (memcmp(s1, "DEK-Info: AES-192-CBC,", 22) == 0)
				enc_alg = CIPHER_AES_192_CBC;
			else if (memcmp(s1, "DEK-Info: AES-256-CBC,", 22) == 0)
				enc_alg = CIPHER_AES_256_CBC;
			else
			{
				return (-1);
			}

			s1 += 22;
			if (s2 - s1 < 32 || pem_get_iv(s1, pem_iv, 16) != 0)
			{
				return (-1);
			}

			s1 += 32;
		}

		if (enc_alg == CIPHER_NONE)
		{
			return (-1);
		}

		if (*s1 == '\r') s1++;
		if (*s1 == '\n') s1++;
		else 
		{
			return (-1);
		}
	}

	if (s1 >= s2)
	{
		return (-1);
	}

	ret = base64_decode(NULL, 0, &len, s1, s2 - s1);

	if (ret != 0)
	{
		return (-1);
	}

	if ((buf = malloc(len)) == NULL)
	{
		return (-1);
	}

	if ((ret = base64_decode(buf, len, &len, s1, s2 - s1)) != 0)
	{
		memset(buf, 0, len);
		free(buf);

		return (-1);
	}

	if (enc != 0)
	{
		if (pwd == NULL)
		{
			memset(buf, 0, len);
			free(buf);

			return (-1);
		}

		ret = 0;

		if (enc_alg == CIPHER_DES_EDE3_CBC)
			ret = pem_des3_decrypt(pem_iv, buf, len, pwd, pwdlen);
		else if (enc_alg == CIPHER_DES_CBC)
			ret = pem_des_decrypt(pem_iv, buf, len, pwd, pwdlen);

		if (enc_alg == CIPHER_AES_128_CBC)
			ret = pem_aes_decrypt(pem_iv, 16, buf, len, pwd, pwdlen);
		else if (enc_alg == CIPHER_AES_192_CBC)
			ret = pem_aes_decrypt(pem_iv, 24, buf, len, pwd, pwdlen);
		else if (enc_alg == CIPHER_AES_256_CBC)
			ret = pem_aes_decrypt(pem_iv, 32, buf, len, pwd, pwdlen);

		if (ret != 0)
		{
			free(buf);
			return(ret);
		}

		/*
		* The result will be ASN.1 starting with a SEQUENCE tag, with 1 to 3
		* length bytes (allow 4 to be sure) in all known use cases.
		*
		* Use that as a heuristic to try to detect password mismatches.
		*/
		if (len <= 2 || buf[0] != 0x30 || buf[1] > 0x83)
		{
			memset(buf, 0, len);
			free(buf);

			return (-1);
		}
	}

	ctx->buf = buf;
	ctx->buflen = len;

	return(0);
}

void pem_free(pem_context *ctx)
{
	if (ctx->buf != NULL)
	{
		memset(ctx->buf, 0, ctx->buflen);
		free(ctx->buf);
	}
	free(ctx->info);

	memset(ctx, 0, sizeof(pem_context));
}

int pem_write_buffer(const char *header, const char *footer,
	const unsigned char *der_data, uint32_t der_len,
	unsigned char *buf, uint32_t buf_len, uint32_t *olen)
{
	int ret;
	unsigned char *encode_buf = NULL, *c, *p = buf;
	uint32_t len = 0, use_len, add_len = 0;

	base64_encode(NULL, 0, &use_len, der_data, der_len);
	add_len = strlen(header) + strlen(footer) + (use_len / 64) + 1;

	if (use_len + add_len > buf_len)
	{
		*olen = use_len + add_len;
		{
			return (-1);
		}
	}

	if (use_len != 0 && ((encode_buf = malloc(use_len)) == NULL))
	{
		return (-1);
	}

	if ((ret = base64_encode(encode_buf, use_len, &use_len, der_data,
		der_len)) != 0)
	{
		free(encode_buf);
		return(ret);
	}

	memcpy(p, header, strlen(header));
	p += strlen(header);
	c = encode_buf;

	while (use_len)
	{
		len = (use_len > 64) ? 64 : use_len;
		memcpy(p, c, len);
		use_len -= len;
		p += len;
		c += len;
		*p++ = '\n';
	}

	memcpy(p, footer, strlen(footer));
	p += strlen(footer);

	*p++ = '\0';
	*olen = p - buf;

	free(encode_buf);
	return(0);
}
