
/*
*  Generic ASN.1 parsing
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

#include "asn1.h"

#include <string.h>
#include <stdlib.h>

/*
* ASN.1 DER decoding routines
*/
int asn1_get_len(unsigned char **p,
	const unsigned char *end,
	uint32_t *len)
{
	if ((end - *p) < 1)
	{
		return (int)-1;
	}

	if ((**p & 0x80) == 0)
		*len = *(*p)++;
	else
	{
		switch (**p & 0x7F)
		{
		case 1:
			if ((end - *p) < 2)
			{
				return (int)-1;
			}

			*len = (*p)[1];
			(*p) += 2;
			break;

		case 2:
			if ((end - *p) < 3)
			{
				return (int)-1;
			}

			*len = ((uint32_t)(*p)[1] << 8) | (*p)[2];
			(*p) += 3;
			break;

		case 3:
			if ((end - *p) < 4)
			{
				return (int)-1;
			}

			*len = ((uint32_t)(*p)[1] << 16) |
				((uint32_t)(*p)[2] << 8) | (*p)[3];
			(*p) += 4;
			break;

		case 4:
			if ((end - *p) < 5)
			{
				return (int)-1;
			}

			*len = ((uint32_t)(*p)[1] << 24) | ((uint32_t)(*p)[2] << 16) |
				((uint32_t)(*p)[3] << 8) | (*p)[4];
			(*p) += 5;
			break;

		default:
			return (int)-1;
		}
	}

	if (*len > (uint32_t)(end - *p))
	{
		return (int)-1;
	}

	return(0);
}

int asn1_get_tag(unsigned char **p,
	const unsigned char *end,
	uint32_t *len, int tag)
{
	if ((end - *p) < 1)
	{
		return (int)-1;
	}

	if (**p != tag)
	{
		return ERR_ASN1_UNEXPECTED_TAG;
	}

	(*p)++;

	return(asn1_get_len(p, end, len));
}

int asn1_get_bool(unsigned char **p,
	const unsigned char *end,
	int *val)
{
	int ret;
	uint32_t len;

	if ((ret = asn1_get_tag(p, end, &len, ASN1_BOOLEAN)) != 0)
		return(ret);

	if (len != 1)
	{
		return (int)-1;
	}

	*val = (**p != 0) ? 1 : 0;
	(*p)++;

	return(0);
}

int asn1_get_int(unsigned char **p,
	const unsigned char *end,
	int *val)
{
	int ret;
	uint32_t len;

	if ((ret = asn1_get_tag(p, end, &len, ASN1_INTEGER)) != 0)
		return(ret);

	if (len == 0 || len > sizeof(int) || (**p & 0x80) != 0)
	{
		return (int)-1;
	}

	*val = 0;

	while (len-- > 0)
	{
		*val = (*val << 8) | **p;
		(*p)++;
	}

	return(0);
}

int asn1_get_mpi(unsigned char **p,
	const unsigned char *end,
	mpi *X)
{
	int ret;
	uint32_t len;

	if ((ret = asn1_get_tag(p, end, &len, ASN1_INTEGER)) != 0)
		return(ret);

	ret = mpi_read_binary(X, *p, len);

	*p += len;

	return(ret);
}

int asn1_get_bitstring(unsigned char **p, const unsigned char *end,
	asn1_bitstring *bs)
{
	int ret;

	/* Certificate type is a single byte bitstring */
	if ((ret = asn1_get_tag(p, end, &bs->len, ASN1_BIT_STRING)) != 0)
		return(ret);

	/* Check length, subtract one for actual bit string length */
	if (bs->len < 1)
	{
		return (int)-1;
	}

	bs->len -= 1;

	/* Get number of unused bits, ensure unused bits <= 7 */
	bs->unused_bits = **p;
	if (bs->unused_bits > 7)
	{
		return (int)-1;
	}

	(*p)++;

	/* Get actual bitstring */
	bs->p = *p;
	*p += bs->len;

	if (*p != end)
	{
		return (int)-1;
	}

	return(0);
}

/*
* Get a bit string without unused bits
*/
int asn1_get_bitstring_null(unsigned char **p, const unsigned char *end,
	uint32_t *len)
{
	int ret;

	if ((ret = asn1_get_tag(p, end, len, ASN1_BIT_STRING)) != 0)
		return(ret);

	if ((*len)-- < 2 || *(*p)++ != 0)
	{
		return (int)-1;
	}

	return(0);
}


/*
*  Parses and splits an ASN.1 "SEQUENCE OF <tag>"
*/
int asn1_get_sequence_of(unsigned char **p,
	const unsigned char *end,
	asn1_sequence *cur,
	int tag)
{
	int ret;
	uint32_t len;
	asn1_buf *buf;

	/* Get main sequence tag */
	if ((ret = asn1_get_tag(p, end, &len,
		ASN1_CONSTRUCTED | ASN1_SEQUENCE)) != 0)
		return(ret);

	if (*p + len != end)
	{
		return (int)-1;
	}

	while (*p < end)
	{
		buf = &(cur->buf);
		buf->tag = **p;

		if ((ret = asn1_get_tag(p, end, &buf->len, tag)) != 0)
			return(ret);

		buf->p = *p;
		*p += buf->len;

		/* Allocate and assign next pointer */
		if (*p < end)
		{
			cur->next = (asn1_sequence*)malloc(sizeof(asn1_sequence));

			if (cur->next == NULL)
			{
				return (int)-1;
			}

			cur = cur->next;
		}
	}

	/* Set final sequence entry's next pointer to NULL */
	cur->next = NULL;

	if (*p != end)
	{
		return (int)-1;
	}

	return(0);
}

int asn1_get_alg(unsigned char **p,
	const unsigned char *end,
	asn1_buf *alg, asn1_buf *params)
{
	int ret;
	uint32_t len;

	if ((ret = asn1_get_tag(p, end, &len,
		ASN1_CONSTRUCTED | ASN1_SEQUENCE)) != 0)
		return(ret);

	if ((end - *p) < 1)
	{
		return (int)-1;
	}

	alg->tag = **p;
	end = *p + len;

	if ((ret = asn1_get_tag(p, end, &alg->len, ASN1_OID)) != 0)
		return(ret);

	alg->p = *p;
	*p += alg->len;

	if (*p == end)
	{
		memset((void*)params, 0, sizeof(asn1_buf));
		return(0);
	}

	params->tag = **p;
	(*p)++;

	if ((ret = asn1_get_len(p, end, &params->len)) != 0)
		return(ret);

	params->p = *p;
	*p += params->len;

	if (*p != end)
	{
		return (int)-1;
	}

	return(0);
}

int asn1_get_alg_null(unsigned char **p,
	const unsigned char *end,
	asn1_buf *alg)
{
	int ret;
	asn1_buf params;

	memset((void*)&params, 0, sizeof(asn1_buf));

	if ((ret = asn1_get_alg(p, end, alg, &params)) != 0)
		return(ret);

	if ((params.tag != ASN1_NULL && params.tag != 0) || params.len != 0)
	{
		return (int)-1;
	}

	return(0);
}

void asn1_free_named_data(asn1_named_data *cur)
{
	if (cur == NULL)
		return;

	free(cur->oid.p);
	free(cur->val.p);

	memset((void*)cur, 0, sizeof(asn1_named_data));
}

void asn1_free_named_data_list(asn1_named_data **head)
{
	asn1_named_data *cur;

	while ((cur = *head) != NULL)
	{
		*head = cur->next;
		asn1_free_named_data(cur);
		free(cur);
	}
}

asn1_named_data *asn1_find_named_data(asn1_named_data *list,
	const char *oid, uint32_t len)
{
	while (list != NULL)
	{
		if (list->oid.len == len &&
			memcmp(list->oid.p, oid, len) == 0)
		{
			break;
		}

		list = list->next;
	}

	return(list);
}

#define ASN1_CHK_ADD(g, f)                      \
    do                                          \
		    {                                       \
        if( ( ret = (f) ) < 0 )                 \
            return( ret );                      \
						        else                            \
            (g) += ret;                         \
		    } while( 0 )

int asn1_write_len(unsigned char **p, unsigned char *start, uint32_t len)
{
	if (len < 0x80)
	{
		if (*p - start < 1)
		{
			return (int)-1;
		}

		*--(*p) = (unsigned char)len;
		return(1);
	}

	if (len <= 0xFF)
	{
		if (*p - start < 2)
		{
			return (int)-1;
		}

		*--(*p) = (unsigned char)len;
		*--(*p) = 0x81;
		return(2);
	}

	if (len <= 0xFFFF)
	{
		if (*p - start < 3)
		{
			return (int)-1;
		}

		*--(*p) = (len)& 0xFF;
		*--(*p) = (len >> 8) & 0xFF;
		*--(*p) = 0x82;
		return(3);
	}

	if (len <= 0xFFFFFF)
	{
		if (*p - start < 4)
		{
			return (int)-1;
		}

		*--(*p) = (len)& 0xFF;
		*--(*p) = (len >> 8) & 0xFF;
		*--(*p) = (len >> 16) & 0xFF;
		*--(*p) = 0x83;
		return(4);
	}

#if SIZE_MAX > 0xFFFFFFFF
	if (len <= 0xFFFFFFFF)
#endif
	{
		if (*p - start < 5)
		{
			return (int)-1;
		}

		*--(*p) = (len)& 0xFF;
		*--(*p) = (len >> 8) & 0xFF;
		*--(*p) = (len >> 16) & 0xFF;
		*--(*p) = (len >> 24) & 0xFF;
		*--(*p) = 0x84;
		return(5);
	}

#if SIZE_MAX > 0xFFFFFFFF
	return (int)-1;
#endif

	return (0);
}

int asn1_write_tag(unsigned char **p, unsigned char *start, unsigned char tag)
{
	if (*p - start < 1)
	{
		return (int)-1;
	}

	*--(*p) = tag;

	return(1);
}

int asn1_write_raw_buffer(unsigned char **p, unsigned char *start,
	const unsigned char *buf, uint32_t size)
{
	uint32_t len = 0;

	if (*p < start || (uint32_t)(*p - start) < size)
	{
		return (int)-1;
	}

	len = size;
	(*p) -= len;
	memcpy(*p, buf, len);

	return((int)len);
}

int asn1_write_mpi(unsigned char **p, unsigned char *start, const mpi *X)
{
	int ret;
	uint32_t len = 0;

	// Write the MPI
	//
	len = mpi_size(X);

	if (*p < start || (uint32_t)(*p - start) < len)
	{
		return (int)-1;
	}

	(*p) -= len;
	MPI_CHK(mpi_write_binary(X, *p, len));

	// DER format assumes 2s complement for numbers, so the leftmost bit
	// should be 0 for positive numbers and 1 for negative numbers.
	//
	if (X->s == 1 && **p & 0x80)
	{
		if (*p - start < 1)
		{
			return (int)-1;
		}

		*--(*p) = 0x00;
		len += 1;
	}

	ASN1_CHK_ADD(len, asn1_write_len(p, start, len));
	ASN1_CHK_ADD(len, asn1_write_tag(p, start, ASN1_INTEGER));

	ret = (int)len;

cleanup:
	return(ret);
}

int asn1_write_null(unsigned char **p, unsigned char *start)
{
	int ret;
	uint32_t len = 0;

	// Write NULL
	//
	ASN1_CHK_ADD(len, asn1_write_len(p, start, 0));
	ASN1_CHK_ADD(len, asn1_write_tag(p, start, ASN1_NULL));

	return((int)len);
}

int asn1_write_oid(unsigned char **p, unsigned char *start,
	const char *oid, uint32_t oid_len)
{
	int ret;
	uint32_t len = 0;

	ASN1_CHK_ADD(len, asn1_write_raw_buffer(p, start,
		(const unsigned char *)oid, oid_len));
	ASN1_CHK_ADD(len, asn1_write_len(p, start, len));
	ASN1_CHK_ADD(len, asn1_write_tag(p, start, ASN1_OID));

	return((int)len);
}

int asn1_write_algorithm_identifier(unsigned char **p, unsigned char *start,
	const char *oid, uint32_t oid_len,
	uint32_t par_len)
{
	int ret;
	uint32_t len = 0;

	if (par_len == 0)
		ASN1_CHK_ADD(len, asn1_write_null(p, start));
	else
		len += par_len;

	ASN1_CHK_ADD(len, asn1_write_oid(p, start, oid, oid_len));

	ASN1_CHK_ADD(len, asn1_write_len(p, start, len));
	ASN1_CHK_ADD(len, asn1_write_tag(p, start,
		ASN1_CONSTRUCTED | ASN1_SEQUENCE));

	return((int)len);
}

int asn1_write_bool(unsigned char **p, unsigned char *start, int boolean)
{
	int ret;
	uint32_t len = 0;

	if (*p - start < 1)
	{
		return (int)-1;
	}

	*--(*p) = (boolean) ? 255 : 0;
	len++;

	ASN1_CHK_ADD(len, asn1_write_len(p, start, len));
	ASN1_CHK_ADD(len, asn1_write_tag(p, start, ASN1_BOOLEAN));

	return((int)len);
}

int asn1_write_int(unsigned char **p, unsigned char *start, int val)
{
	int ret;
	uint32_t len = 0;

	if (*p - start < 1)
	{
		return (int)-1;
	}

	len += 1;
	*--(*p) = val;

	if (val > 0 && **p & 0x80)
	{
		if (*p - start < 1)
		{
			return (int)-1;
		}

		*--(*p) = 0x00;
		len += 1;
	}

	ASN1_CHK_ADD(len, asn1_write_len(p, start, len));
	ASN1_CHK_ADD(len, asn1_write_tag(p, start, ASN1_INTEGER));

	return((int)len);
}

int asn1_write_tagged_string(unsigned char **p, unsigned char *start, int tag,
	const char *text, uint32_t text_len)
{
	int ret;
	uint32_t len = 0;

	ASN1_CHK_ADD(len, asn1_write_raw_buffer(p, start,
		(const unsigned char *)text, text_len));

	ASN1_CHK_ADD(len, asn1_write_len(p, start, len));
	ASN1_CHK_ADD(len, asn1_write_tag(p, start, tag));

	return((int)len);
}

int asn1_write_utf8_string(unsigned char **p, unsigned char *start,
	const char *text, uint32_t text_len)
{
	return(asn1_write_tagged_string(p, start, ASN1_UTF8_STRING, text, text_len));
}

int asn1_write_printable_string(unsigned char **p, unsigned char *start,
	const char *text, uint32_t text_len)
{
	return(asn1_write_tagged_string(p, start, ASN1_PRINTABLE_STRING, text, text_len));
}

int asn1_write_ia5_string(unsigned char **p, unsigned char *start,
	const char *text, uint32_t text_len)
{
	return(asn1_write_tagged_string(p, start, ASN1_IA5_STRING, text, text_len));
}

int asn1_write_bitstring(unsigned char **p, unsigned char *start,
	const unsigned char *buf, uint32_t bits)
{
	int ret;
	uint32_t len = 0;
	uint32_t unused_bits, byte_len;

	byte_len = (bits + 7) / 8;
	unused_bits = (byte_len * 8) - bits;

	if (*p < start || (uint32_t)(*p - start) < byte_len + 1)
	{
		return (int)-1;
	}

	len = byte_len + 1;

	/* Write the bitstring. Ensure the unused bits are zeroed */
	if (byte_len > 0)
	{
		byte_len--;
		*--(*p) = buf[byte_len] & ~((0x1 << unused_bits) - 1);
		(*p) -= byte_len;
		memcpy(*p, buf, byte_len);
	}

	/* Write unused bits */
	*--(*p) = (unsigned char)unused_bits;

	ASN1_CHK_ADD(len, asn1_write_len(p, start, len));
	ASN1_CHK_ADD(len, asn1_write_tag(p, start, ASN1_BIT_STRING));

	return((int)len);
}

int asn1_write_octet_string(unsigned char **p, unsigned char *start,
	const unsigned char *buf, uint32_t size)
{
	int ret;
	uint32_t len = 0;

	ASN1_CHK_ADD(len, asn1_write_raw_buffer(p, start, buf, size));

	ASN1_CHK_ADD(len, asn1_write_len(p, start, len));
	ASN1_CHK_ADD(len, asn1_write_tag(p, start, ASN1_OCTET_STRING));

	return((int)len);
}

asn1_named_data *asn1_store_named_data(
	asn1_named_data **head,
	const char *oid, uint32_t oid_len,
	const unsigned char *val,
	uint32_t val_len)
{
	asn1_named_data *cur;

	if ((cur = asn1_find_named_data(*head, oid, oid_len)) == NULL)
	{
		// Add new entry if not present yet based on OID
		//
		cur = (asn1_named_data*)malloc(sizeof(asn1_named_data));
		if (cur == NULL)
			return(NULL);

		cur->oid.len = oid_len;
		cur->oid.p = (unsigned char*)malloc(oid_len);
		if (cur->oid.p == NULL)
		{
			free(cur);
			return(NULL);
		}

		memcpy(cur->oid.p, oid, oid_len);

		cur->val.len = val_len;
		cur->val.p = (unsigned char*)malloc(val_len);
		if (cur->val.p == NULL)
		{
			free(cur->oid.p);
			free(cur);
			return(NULL);
		}

		cur->next = *head;
		*head = cur;
	}
	else if (cur->val.len < val_len)
	{
		/*
		* Enlarge existing value buffer if needed
		* Preserve old data until the allocation succeeded, to leave list in
		* a consistent state in case allocation fails.
		*/
		void *p = malloc(val_len);
		if (p == NULL)
			return(NULL);

		free(cur->val.p);
		cur->val.p = (unsigned char*)p;
		cur->val.len = val_len;
	}

	if (val != NULL)
		memcpy(cur->val.p, val, val_len);

	return(cur);
}


#if defined(OEM_SELF_TEST)

int asn1_self_test(int verbose)
{
	/*int n;
	int total = 0;
	unsigned char tmp[1024];
	unsigned char* p = tmp;

	n = 0x7fffffff - 1;
	n = asn1_write_int(&p, tmp, n);
	printf("write: %d\n", n);

	total = 0;

	total += asn1_get_integer(tmp + total, &n);
	if (n == MAX_BYTE - 1)
		printf("read: %d\n", n);
	else
		printf("read error: %d\n", n);

	total += asn1_read_integer(tmp + total, &n);
	if (n == MAX_SHORT - 1)
		printf("read: %d\n", n);
	else
		printf("read error: %d\n", n);

	total += asn1_read_integer(tmp + total, &n);
	if (n == MAX_LONG - 1)
		printf("read: %d\n", n);
	else
		printf("read error: %d\n", n);

	total = 0;

	total += asn1_write_null(tmp);
	printf("write: NULL\n", n);

	const char str[] = "OCTET TOKEN";
	total += asn1_write_octet_string((tmp + total), str, a_xslen(str));
	printf("write: %s\n", str);

	total = 0;

	total += asn1_read_null((tmp + total));
	if (total)
		printf("rad: NULL\n", n);
	else
		printf("read error: NULL\n", n);

	unsigned char* buf = { 0 };
	total += asn1_read_octet_string((tmp + total), &buf, &n);
	printf("rad: %s\n", buf);*/
}

#endif