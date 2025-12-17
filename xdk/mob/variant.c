/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc variant value document

	@module	variant.c | implement file

	@devnote 张文权 2021.01 - 2021.12	v6.0
***********************************************************************/

/**********************************************************************
This program is free software : you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
LICENSE.GPL3 for more details.
***********************************************************************/

#include "variant.h"

#include "../xdkobj.h"
#include "../xdkstd.h"
#include "../xdkoem.h"
#include "../xdkimp.h"

typedef struct _variant_context{
	memo_head head;

	int type;
	int count;
	void* data;
}variant_context;


static int variant_realloc(variant_t var, byte_t type, int count)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	int sw = 0;

	switch ((type & 0x7F))
	{
	case VV_BOOL:
		count = 1;
		sw = sizeof(bool_t);
		break;
	case VV_BYTE:
		count = 1;
		sw = sizeof(byte_t);
		break;
	case VV_SHORT:
		count = 1;
		sw = sizeof(short);
		break;
	case VV_INT:
		count = 1;
		sw = sizeof(int);
		break;
	case VV_LONG:
		count = 1;
		sw = sizeof(long long);
		break;
	case VV_FLOAT:
		count = 1;
		sw = sizeof(float);
		break;
	case VV_DOUBLE:
		count = 1;
		sw = sizeof(double);
		break;
	case VV_STRING_GB2312:
		sw = sizeof(byte_t) * count;
		break;
	case VV_STRING_UTF8:
		sw = sizeof(byte_t) * count;
		break;
	case VV_STRING_UTF16LIT:
		sw = sizeof(byte_t) * count;
		break;
	case VV_STRING_UTF16BIG:
		sw = sizeof(byte_t) * count;
		break;
	case VV_BOOL_ARRAY:
		sw = sizeof(bool_t) * count;
		break;
	case VV_BYTE_ARRAY:
		sw = sizeof(byte_t) * count;
		break;
	case VV_SHORT_ARRAY:
		sw = sizeof(short) * count;
		break;
	case VV_INT_ARRAY:
		sw = sizeof(int) * count;
		break;
	case VV_LONG_ARRAY:
		sw = sizeof(long long) * count;
		break;
	case VV_FLOAT_ARRAY:
		sw = sizeof(float) * count;
		break;
	case VV_DOUBLE_ARRAY:
		sw = sizeof(double) * count;
		break;
	default:
		type = VV_NULL;
		count = 0;
		sw = 0;
		break;
	}

	pvar->data = xmem_realloc(pvar->data, sw);
	pvar->type = type;
	pvar->count = count;
	
	return sw;
}

/************************************************************************************************************************************************/

variant_t variant_alloc(int type)
{
	variant_context* pvar;

	pvar = (variant_context*)xmem_alloc(sizeof(variant_context));
	pvar->head.tag = MEM_VARIANT;
	PUT_THREEBYTE_LOC(pvar->head.len, 0, (sizeof(variant_context) - 4));

	variant_realloc((variant_t)&(pvar->head), type, 0);

	return (variant_t)&(pvar->head);
}

variant_t variant_clone(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	variant_context* pnew;
	int n;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	pnew = (variant_context*)variant_alloc(pvar->type);
	n = variant_realloc((variant_t)&(pnew->head), pvar->type, pvar->count);
	
	xmem_copy(pnew->data, pvar->data, n);

	return (variant_t)&(pnew->head);
}

void variant_free(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	if (pvar->data)
		xmem_free(pvar->data);

	xmem_free(pvar);
}

int variant_get_type(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	return pvar->type;
}

int variant_get_count(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	return pvar->count;
}

const void* variant_data(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	return pvar->data;
}

void variant_to_null(variant_t var, int type)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	variant_realloc(var, type, 0);
}

bool_t variant_is_null(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	return (pvar->type == VV_NULL) ? 1 : 0;
}

void variant_copy(variant_t dst, variant_t src)
{
	variant_context* psrc = TypePtrFromHead(variant_context, src);
	variant_context* pdst = TypePtrFromHead(variant_context, dst);
	
	int sw;

	XDK_ASSERT(src != NULL && src->tag == MEM_VARIANT && dst != NULL && dst->tag == MEM_VARIANT);

	sw = variant_realloc(dst, psrc->type, psrc->count);

	xmem_copy(pdst->data, psrc->data, sw);
}

int variant_comp(variant_t var1, variant_t var2)
{
	variant_context* pvar1 = TypePtrFromHead(variant_context, var1);
	variant_context* pvar2 = TypePtrFromHead(variant_context, var2);
	byte_t t1, t2;
	void *d1, *d2;
	int n1, n2, i;

	XDK_ASSERT(var1 != NULL && var1->tag == MEM_VARIANT && var2 != NULL && var2->tag == MEM_VARIANT);

	t1 = pvar1->type;
	t2 = pvar2->type;

	if (t1 == VV_NULL && t2 == VV_NULL)
		return 0;
	else if (t1 == VV_NULL)
		return -1;
	else if (t2 == VV_NULL)
		return 1;

	if ((t1 & 0x7F) != (t2 & 0x7F))
		return (t1 < t2) ? -1 : 1;

	n1 = pvar1->count;
	n2 = pvar2->count;
	d1 = pvar1->data;
	d2 = pvar2->data;

	switch ((t2 & 0x7F))
	{
	case VV_BOOL:
		if ((*(bool_t*)d1) >(*(bool_t*)d2))
			return 1;
		else if ((*(bool_t*)d1) < (*(bool_t*)d2))
			return -1;
		else
			return 0;
	case VV_BYTE:
		if ((*(byte_t*)d1) >(*(byte_t*)d2))
			return 1;
		else if ((*(byte_t*)d1) < (*(byte_t*)d2))
			return -1;
		else
			return 0;
	case VV_SHORT:
		if ((*((short*)d1)) > (*((short*)d2)))
			return 1;
		else if((*((short*)d1)) < (*((short*)d2)))
			return -1;
		else
			return 0;
	case VV_INT:
		if ((*((int*)d1)) > (*((int*)d2)))
			return 1;
		else if ((*((int*)d1)) < (*((int*)d2)))
			return -1;
		else
			return 0;
	case VV_LONG:
		if ((*((long*)d1)) > (*((long*)d2)))
			return 1;
		else if ((*((long*)d1)) < (*((long*)d2)))
			return -1;
		else
			return 0;
	case VV_FLOAT:
		if ((*((float*)d1)) > (*((float*)d2)))
			return 1;
		else if ((*((float*)d1)) < (*((float*)d2)))
			return -1;
		else
			return 0;
	case VV_DOUBLE:
		if ((*((double*)d1)) > (*((double*)d2)))
			return 1;
		else if ((*((double*)d1)) < (*((double*)d2)))
			return -1;
		else
			return 0;
	case VV_BOOL_ARRAY:
		i = 0;
		while (i < n1 && i < n2)
		{
			if (((bool_t*)d1)[i] > ((bool_t*)d2)[i])
				return 1;
			else if (((bool_t*)d1)[i] < ((bool_t*)d2)[i])
				return -1;

			i++;
		}
		if (i < n1)
			return 1;
		else if (i < n2)
			return -1;
		else
			return 0;
	case VV_BYTE_ARRAY:
		i = 0;
		while (i < n1 && i < n2)
		{
			if (((byte_t*)d1)[i] >((byte_t*)d2)[i])
				return 1;
			else if (((byte_t*)d1)[i] < ((byte_t*)d2)[i])
				return -1;

			i++;
		}
		if (i < n1)
			return 1;
		else if (i < n2)
			return -1;
		else
			return 0;
	case VV_SHORT_ARRAY:
		i = 0;
		while (i < n1 && i < n2)
		{
			if (((short*)d1)[i] >((short*)d2)[i])
				return 1;
			else if (((short*)d1)[i] < ((short*)d2)[i])
				return -1;

			i++;
		}
		if (i < n1)
			return 1;
		else if (i < n2)
			return -1;
		else
			return 0;
	case VV_INT_ARRAY:
		i = 0;
		while (i < n1 && i < n2)
		{
			if (((int*)d1)[i] >((int*)d2)[i])
				return 1;
			else if (((int*)d1)[i] < ((int*)d2)[i])
				return -1;

			i++;
		}
		if (i < n1)
			return 1;
		else if (i < n2)
			return -1;
		else
			return 0;
	case VV_LONG_ARRAY:
		i = 0;
		while (i < n1 && i < n2)
		{
			if (((long long*)d1)[i] >((long long*)d2)[i])
				return 1;
			else if (((long long*)d1)[i] < ((long long*)d2)[i])
				return -1;

			i++;
		}
		if (i < n1)
			return 1;
		else if (i < n2)
			return -1;
		else
			return 0;
	case VV_FLOAT_ARRAY:
		i = 0;
		while (i < n1 && i < n2)
		{
			if (((float*)d1)[i] >((float*)d2)[i])
				return 1;
			else if (((float*)d1)[i] < ((float*)d2)[i])
				return -1;
			
			i++;
		}
		if (i < n1)
			return 1;
		else if (i < n2)
			return -1;
		else
			return 0;
	case VV_DOUBLE_ARRAY:
		i = 0;
		while (i < n1 && i < n2)
		{
			if (((double*)d1)[i] >((double*)d2)[i])
				return 1;
			else if (((double*)d1)[i] < ((double*)d2)[i])
				return -1;

			i++;
		}
		if (i < n1)
			return 1;
		else if (i < n2)
			return -1;
		else
			return 0;
	case VV_STRING_GB2312:
	case VV_STRING_UTF8:
	case VV_STRING_UTF16LIT:
	case VV_STRING_UTF16BIG:
		i = 0;
		while (i < n1 && i < n2)
		{
			if (((byte_t*)d1)[i] >((byte_t*)d2)[i])
				return 1;
			else if (((byte_t*)d1)[i] < ((byte_t*)d2)[i])
				return -1;

			i++;
		}
		if (i < n1)
			return 1;
		else if (i < n2)
			return -1;
		else
			return 0;
	}

	return 0;
}

int variant_to_string(variant_t var, tchar_t* buf, int max)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t, i, n, k, j;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	n = pvar->count;
	d = pvar->data;

	switch (t & 0x7F)
	{
	case VV_NULL:
		if (buf)
		{
			buf[0] = _T('\0');
		}
		return 0;
	case VV_BOOL:
		if (buf)
		{
			buf[0] = (*((bool_t*)d)) ? _T('1') : _T('0');
			buf[1] = _T('\0');
		}
		return 1;
	case VV_BYTE:
		if (buf)
		{
			format_hexnum(*((byte_t*)d), buf, 2);
		}
		return 1;
	case VV_SHORT:
		return stoxs(*((short*)d), buf, max);
	case VV_INT:
		return ltoxs(*((int*)d), buf, max);
	case VV_LONG:
		return lltoxs(*((long long*)d), buf, max);
	case VV_FLOAT:
		return ftoxs(*((float*)d), buf, max);
	case VV_DOUBLE:
		return numtoxs(*((double*)d), buf, max);
	case VV_BOOL_ARRAY:
		for (i = 0; i < n; i++)
		{
			if (buf)
			{
				buf[i] = (((bool_t*)d)[i]) ? _T('1') : _T('0');
				buf[i + 1] = _T('\0');
			}
		}
		return (i);
	case VV_BYTE_ARRAY:
		for (i = 0; i < n; i++)
		{
			format_hexnum((unsigned int)(((byte_t*)d)[i]), ((buf) ? buf + i * 3 : NULL), 2);
		}
		return (i * 2);
	case VV_SHORT_ARRAY:
		k = 0;
		for (i = 0; i < n; i++)
		{
			j = stoxs(((short*)d)[i], ((buf) ? (buf + k) : NULL), NUM_LEN);
			k += j;

			if (buf)
			{
				buf[k] = _T(' ');
			}
			k++;
		}
		return k;
	case VV_INT_ARRAY:
		k = 0;
		for (i = 0; i < n; i++)
		{
			j = ltoxs(((int*)d)[i], ((buf) ? (buf + k) : NULL), NUM_LEN);
			k += j;

			if (buf)
			{
				buf[k] = _T(' ');
			}
			k++;
		}
		return k;
	case VV_LONG_ARRAY:
		k = 0;
		for (i = 0; i < n; i++)
		{
			j = lltoxs(((long long*)d)[i], ((buf) ? (buf + k) : NULL), NUM_LEN);
			k += j;

			if (buf)
			{
				buf[k] = _T(' ');
			}
			k++;
		}
		return k;
	case VV_FLOAT_ARRAY:
		k = 0;
		for (i = 0; i < n; i++)
		{
			j = ftoxs(((float*)d)[i], ((buf) ? (buf + k) : NULL), NUM_LEN);
			k += j;

			if (buf)
			{
				buf[k] = _T(' ');
			}
			k++;
		}
		return k;
	case VV_DOUBLE_ARRAY:
		k = 0;
		for (i = 0; i < n; i++)
		{
			j = numtoxs(((double*)d)[i], ((buf) ? (buf + k) : NULL), NUM_LEN);
			k += j;

			if (buf)
			{
				buf[k] = _T(' ');
			}
			k++;
		}
		return k;
	case VV_STRING_GB2312:
#ifdef _UNICODE
		n = gb2312_to_ucs((byte_t*)(d), n, buf, max);
#else
		n = gb2312_to_mbs((byte_t*)(d), n, buf, max);
#endif
		if (buf) buf[n] = _T('\0');
		return n;
	case VV_STRING_UTF8:
#ifdef _UNICODE
		n = utf8_to_ucs((byte_t*)(d), n, buf, max);
#else
		n = utf8_to_mbs((byte_t*)(d), n, buf, max);
#endif
		if (buf) buf[n] = _T('\0');
		return n;
	case VV_STRING_UTF16LIT:
#ifdef _UNICODE
		n = utf16lit_to_ucs((byte_t*)(d), n, buf, max);
#else
		n = utf16lit_to_mbs((byte_t*)(d), n, buf, max);
#endif
		if (buf) buf[n] = _T('\0');
		return n;
	case VV_STRING_UTF16BIG:
#ifdef _UNICODE
		n = utf16big_to_ucs((byte_t*)(d), n, buf, max);
#else
		n = utf16big_to_mbs((byte_t*)(d), n, buf, max);
#endif
		if (buf) buf[n] = _T('\0');
		return n;
	}

	return 0;
}

void variant_from_string(variant_t var, const tchar_t* buf, int len)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t, i, n, k, j;
	tchar_t *key;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT); 

	if (len < 0)
		len = xslen(buf);

	t = pvar->type;
	n = pvar->count;
	d = pvar->data;

	switch (t & 0x7F)
	{
	case VV_NULL:
#ifdef _UNICODE
		n = ucs_to_utf8(buf, len, NULL, MAX_LONG);
#else
		n = mbs_to_utf8(buf, len, NULL, MAX_LONG);
#endif
		variant_realloc(var, VV_STRING_UTF8, n);
		d = pvar->data;
#ifdef _UNICODE
		n = ucs_to_utf8(buf, len, (byte_t*)d, n);
#else
		n = mbs_to_utf8(buf, len, (byte_t*)d, n);
#endif
		break;
	case VV_BOOL:
		*((bool_t*)d) = (buf[0] == _T('1')) ? 1 : 0;
		break;
	case VV_BYTE:
		*((byte_t*)d) = (byte_t)parse_hexnum(buf, 2);
		break;
	case VV_SHORT:
		*((short*)d) = xsntos(buf, len);
		break;
	case VV_INT:
		*((int*)d) = xsntol(buf, len);
		break;
	case VV_LONG:
		*((long long*)d) = xsntoll(buf, len);
		break;
	case VV_FLOAT:
		*((float*)d) = xsntof(buf, len);
		break;
	case VV_DOUBLE:
		*((double*)d) = xsntonum(buf, len);
		break;
	case VV_BOOL_ARRAY:
		variant_realloc(var, VV_BOOL_ARRAY, len);
		d = pvar->data;
		for (i = 0; i < len;i++)
		{
			((bool_t*)d)[i] = (buf[i] == _T('1')) ? 1 : 0;
		}
		break;
	case VV_BYTE_ARRAY:
		variant_realloc(var, VV_BYTE_ARRAY, len / 2);
		d = pvar->data;
		for (i = 0; i < len / 2; i++)
		{
			((byte_t*)d)[i] = (byte_t)parse_hexnum(&(buf[i*2]), 2);
		}
		break;
	case VV_SHORT_ARRAY:
		n = parse_string_token_count(buf, len, _T(' '));
		variant_realloc(var, VV_SHORT_ARRAY, n);
		d = pvar->data;

		k = 0;
		i = 0;
		while (n = parse_string_token((buf + k), (len - k), _T(' '), &key, &j))
		{
			((short*)d)[i] = xsntos(key, j);
			k += n;
			i++;
		}
		break;
	case VV_INT_ARRAY:
		n = parse_string_token_count(buf, len, _T(' '));
		variant_realloc(var, VV_INT_ARRAY, n);
		d = pvar->data;

		k = 0;
		i = 0;
		while (n = parse_string_token((buf + k), (len - k), _T(' '), &key, &j))
		{
			((int*)d)[i] = xsntol(key, j);
			k += n;
			i++;
		}
		break;
	case VV_LONG_ARRAY:
		n = parse_string_token_count(buf, len, _T(' '));
		variant_realloc(var, VV_LONG_ARRAY, n);
		d = pvar->data;

		k = 0;
		i = 0;
		while (n = parse_string_token((buf + k), (len - k), _T(' '), &key, &j))
		{
			((long long*)d)[i] = xsntoll(key, j);
			k += n;
			i++;
		}
		break;
	case VV_FLOAT_ARRAY:
		n = parse_string_token_count(buf, len, _T(' '));
		variant_realloc(var, VV_FLOAT_ARRAY, n);
		d = pvar->data;

		k = 0;
		i = 0;
		while (n = parse_string_token((buf + k), (len - k), _T(' '), &key, &j))
		{
			((float*)d)[i] = xsntof(key, j);
			k += n;
			i++;
		}
		break;
	case VV_DOUBLE_ARRAY:
		n = parse_string_token_count(buf, len, _T(' '));
		variant_realloc(var, VV_DOUBLE_ARRAY, n);
		d = pvar->data;

		k = 0;
		i = 0;
		while (n = parse_string_token((buf + k), (len - k), _T(' '), &key, &j))
		{
			((double*)d)[i] = xsntonum(key, j);
			k += n;
			i++;
		}
		break;
	case VV_STRING_GB2312:
#ifdef _UNICODE
		n = ucs_to_gb2312(buf, len, NULL, MAX_LONG);
#else
		n = mbs_to_gb2312(buf, len, NULL, MAX_LONG);
#endif
		variant_realloc(var, VV_STRING_GB2312, n);
		d = pvar->data;
#ifdef _UNICODE
		ucs_to_gb2312(buf, len, (byte_t*)d, n);
#else
		mbs_to_gb2312(buf, len, (byte_t*)d, n);
#endif
		break;
	case VV_STRING_UTF8:
#ifdef _UNICODE
		n = ucs_to_utf8(buf, len, NULL, MAX_LONG);
#else
		n = mbs_to_utf8(buf, len, NULL, MAX_LONG);
#endif
		variant_realloc(var, VV_STRING_UTF8, n);
		d = pvar->data;
#ifdef _UNICODE
		ucs_to_utf8(buf, len, (byte_t*)d, n);
#else
		mbs_to_utf8(buf, len, (byte_t*)d, n);
#endif
		break;
	case VV_STRING_UTF16LIT:
#ifdef _UNICODE
		n = ucs_to_utf16lit(buf, len, NULL, MAX_LONG);
#else
		n = mbs_to_utf16lit(buf, len, NULL, MAX_LONG);
#endif
		variant_realloc(var, VV_STRING_UTF16LIT, n);
		d = pvar->data;
#ifdef _UNICODE
		ucs_to_utf16lit(buf, len, (byte_t*)d, n);
#else
		mbs_to_utf16lit(buf, len, (byte_t*)d, n);
#endif
		break;
	case VV_STRING_UTF16BIG:
#ifdef _UNICODE
		n = ucs_to_utf16big(buf, len, NULL, MAX_LONG);
#else
		n = mbs_to_utf16big(buf, len, NULL, MAX_LONG);
#endif
		variant_realloc(var, VV_STRING_UTF16BIG, n);
		d = pvar->data;
#ifdef _UNICODE
		ucs_to_utf16big(buf, len, (byte_t*)d, n);
#else
		mbs_to_utf16big(buf, len, (byte_t*)d, n);
#endif
		break;
	}
}

void variant_set_bool(variant_t var, bool_t b)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT); 

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_BOOL);

	*((bool_t*)d) = ((b)? 1 : 0);
}

bool_t variant_get_bool(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT); 

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_BOOL);

	return (*((bool_t*)d));
}

void variant_set_short(variant_t var, short c)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_SHORT);

	*((short*)d) = c;
}

short variant_get_short(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_SHORT);

	return (*((short*)d));
}

void variant_set_int(variant_t var, int c)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_INT);

	*((int*)d) = c;
}

int variant_get_int(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_INT);

	return (*((int*)d));
}

void variant_set_long(variant_t var, long long c)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_LONG);

	*((long long*)d) = c;
}

long long variant_get_long(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_LONG);

	return (*((long long*)d));
}

void variant_set_float(variant_t var, float c)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_FLOAT);

	*((float*)d) = c;
}

float variant_get_float(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_FLOAT);

	return (*((float*)d));
}

void variant_set_double(variant_t var, double c)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_DOUBLE);

	*((double*)d) = c;
}

double variant_get_double(variant_t var)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	d = pvar->data;

	XDK_ASSERT(t == VV_DOUBLE);

	return (*((double*)d));
}


void variant_hash32(variant_t var, key32_t* pkey)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t, n, sw;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	n = pvar->count;
	d = pvar->data;

	switch (t & 0x7F)
	{
	case VV_BOOL:
		sw = sizeof(bool_t);
		break;
	case VV_BYTE:
		sw = sizeof(byte_t);
		break;
	case VV_SHORT:
		sw = sizeof(short);
		break;
	case VV_INT:
		sw = sizeof(int);
		break;
	case VV_LONG:
		sw = sizeof(long long);
		break;
	case VV_FLOAT:
		sw = sizeof(float);
		break;
	case VV_DOUBLE:
		sw = sizeof(double);
		break;
	case VV_BOOL_ARRAY:
		sw = sizeof(bool_t) * n;
		break;
	case VV_BYTE_ARRAY:
		sw = sizeof(byte_t) * n;
		break;
	case VV_SHORT_ARRAY:
		sw = sizeof(short) * n;
		break;
	case VV_INT_ARRAY:
		sw = sizeof(int) * n;
		break;
	case VV_LONG_ARRAY:
		sw = sizeof(long long) * n;
		break;
	case VV_FLOAT_ARRAY:
		sw = sizeof(float) * n;
		break;
	case VV_DOUBLE_ARRAY:
		sw = sizeof(double) * n;
		break;
	case VV_STRING_GB2312:
	case VV_STRING_UTF8:
	case VV_STRING_UTF16LIT:
	case VV_STRING_UTF16BIG:
		sw = sizeof(byte_t) * n;
		break;
	default:
		sw = 0;
		break;
	}

	if (sw)
		murhash32((byte_t*)d, sw, (byte_t*)pkey);
	else
		xmem_zero((void*)pkey, sizeof(key32_t));
}

void variant_hash64(variant_t var, key64_t* pkey)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t, n, sw;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	n = pvar->count;
	d = pvar->data;

	switch (t & 0x7F)
	{
	case VV_BOOL:
		sw = sizeof(bool_t);
		break;
	case VV_BYTE:
		sw = sizeof(byte_t);
		break;
	case VV_SHORT:
		sw = sizeof(short);
		break;
	case VV_INT:
		sw = sizeof(int);
		break;
	case VV_LONG:
		sw = sizeof(long long);
		break;
	case VV_FLOAT:
		sw = sizeof(float);
		break;
	case VV_DOUBLE:
		sw = sizeof(double);
		break;
	case VV_BOOL_ARRAY:
		sw = sizeof(bool_t) * n;
		break;
	case VV_BYTE_ARRAY:
		sw = sizeof(byte_t) * n;
		break;
	case VV_SHORT_ARRAY:
		sw = sizeof(short) * n;
		break;
	case VV_INT_ARRAY:
		sw = sizeof(int) * n;
		break;
	case VV_LONG_ARRAY:
		sw = sizeof(long long) * n;
		break;
	case VV_FLOAT_ARRAY:
		sw = sizeof(float) * n;
		break;
	case VV_DOUBLE_ARRAY:
		sw = sizeof(double) * n;
		break;
	case VV_STRING_GB2312:
	case VV_STRING_UTF8:
	case VV_STRING_UTF16LIT:
	case VV_STRING_UTF16BIG:
		sw = sizeof(byte_t) * n;
		break;
	default:
		sw = 0;
		break;
	}

	if (sw)
		siphash64((byte_t*)d, sw, (byte_t*)pkey);
	else
		xmem_zero((void*)pkey, sizeof(key64_t));
}

void variant_hash128(variant_t var, key128_t* pkey)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	void *d;
	int t, n, sw;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	t = pvar->type;
	n = pvar->count;
	d = pvar->data;

	switch (t & 0x7F)
	{
	case VV_BOOL:
		sw = sizeof(bool_t);
		break;
	case VV_BYTE:
		sw = sizeof(byte_t);
		break;
	case VV_SHORT:
		sw = sizeof(short);
		break;
	case VV_INT:
		sw = sizeof(int);
		break;
	case VV_LONG:
		sw = sizeof(long long);
		break;
	case VV_FLOAT:
		sw = sizeof(float);
		break;
	case VV_DOUBLE:
		sw = sizeof(double);
		break;
	case VV_BOOL_ARRAY:
		sw = sizeof(bool_t) * n;
		break;
	case VV_BYTE_ARRAY:
		sw = sizeof(byte_t) * n;
		break;
	case VV_SHORT_ARRAY:
		sw = sizeof(short) * n;
		break;
	case VV_INT_ARRAY:
		sw = sizeof(int) * n;
		break;
	case VV_LONG_ARRAY:
		sw = sizeof(long long) * n;
		break;
	case VV_FLOAT_ARRAY:
		sw = sizeof(float) * n;
		break;
	case VV_DOUBLE_ARRAY:
		sw = sizeof(double) * n;
		break;
	case VV_STRING_GB2312:
	case VV_STRING_UTF8:
	case VV_STRING_UTF16LIT:
	case VV_STRING_UTF16BIG:
		sw = sizeof(byte_t) * n;
		break;
	default:
		sw = 0;
		break;
	}

	if (sw)
		murhash128((byte_t*)d, sw, (byte_t*)pkey);
	else
		xmem_zero((void*)pkey, sizeof(key128_t));
}

/**********************************************************************
ASN.1 CER ENCODING
Variant::=SEQUENCE{
	Type: BYTE
	Count: BYTE[3]
	Data: BYTE[]
}
**********************************************************************/

dword_t variant_encode(variant_t var, byte_t* buf)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	dword_t n, total = 0;

	int i;
	bool_t b;
	byte_t c;
	short s;
	int l;
	long long ll;
	float f;
	double d;

	XDK_ASSERT(var != NULL && var->tag == MEM_VARIANT);

	switch (pvar->type & 0x7F)
	{
	case VV_NULL:
		n = ver_write_null(((buf)? (buf + total) : NULL));
		total += n;
		break;
	case VV_BOOL:
		b = *((bool_t*)pvar->data);
		n = ver_write_bool(((buf)? (buf + total) : NULL), b);
		total += n;
		break;
	case VV_BOOL_ARRAY:
		n = ver_write_bool_array(((buf)? (buf + total) : NULL), (bool_t*)(pvar->data), pvar->count);
		total += n;
		break;
	case VV_BYTE:
		n = ver_write_byte(((buf)? (buf + total) : NULL), (*(byte_t*)(pvar->data)));
		total += n;
		break;
	case VV_BYTE_ARRAY:
		n = ver_write_byte_array(((buf)? (buf + total) : NULL), (byte_t*)(pvar->data), pvar->count);
		total += n;
		break;
	case VV_SHORT:
		n = ver_write_short(((buf)? (buf + total) : NULL), (*(short*)(pvar->data)));
		total += n;
		break;
	case VV_SHORT_ARRAY:
		n = ver_write_short_array(((buf)? (buf + total) : NULL), (short*)(pvar->data), pvar->count);
		total += n;
		break;
	case VV_INT:
		n = ver_write_int(((buf)? (buf + total) : NULL), (*(int*)(pvar->data)));
		total += n;
		break;
	case VV_INT_ARRAY:
		n = ver_write_int_array(((buf)? (buf + total) : NULL), (int*)(pvar->data), pvar->count);
		total += n;
		break;
	case VV_LONG:
		n = ver_write_long(((buf)? (buf + total) : NULL), (*(long long*)(pvar->data)));
		total += n;
		break;
	case VV_LONG_ARRAY:
		n = ver_write_long_array(((buf)? (buf + total) : NULL), (long long*)(pvar->data), pvar->count);
		total += n;
		break;
	case VV_FLOAT:
		n = ver_write_float(((buf)? (buf + total) : NULL), (*(float*)(pvar->data)));
		total += n;
		break;
	case VV_FLOAT_ARRAY:
		n = ver_write_float_array(((buf)? (buf + total) : NULL), (float*)(pvar->data), pvar->count);
		total += n;
		break;
	case VV_DOUBLE:
		n = ver_write_double(((buf)? (buf + total) : NULL), (*(double*)(pvar->data)));
		total += n;
		break;
	case VV_DOUBLE_ARRAY:
		n = ver_write_double_array(((buf)? (buf + total) : NULL), (double*)(pvar->data), pvar->count);
		total += n;
		break;
	case VV_DATETIME:
		n = ver_write_datetime(((buf)? (buf + total) : NULL), (xdate_t*)(pvar->data));
		total += n;
		break;
	case VV_DATETIME_ARRAY:
		n = ver_write_datetime_array(((buf)? (buf + total) : NULL), (xdate_t*)(pvar->data), pvar->count);
		total += n;
		break;
	case VV_STRING_GB2312:
		n = ver_write_gb2312_string(((buf)? (buf + total) : NULL), (byte_t*)(pvar->data), pvar->count);
		total += n;
		break;
	case VV_STRING_UTF8:
		n = ver_write_utf8_string(((buf)? (buf + total) : NULL), (byte_t*)(pvar->data), pvar->count);
		total += n;
		break;
	case VV_STRING_UTF16LIT:
		n = ver_write_utf16lit_string(((buf)? (buf + total) : NULL), (byte_t*)(pvar->data), pvar->count);
		total += n;
		break;
	case VV_STRING_UTF16BIG:
		n = ver_write_utf16big_string(((buf)? (buf + total) : NULL), (byte_t*)(pvar->data), pvar->count);
		total += n;
		break;
	default:
		break;
	}

	return total;
}

dword_t variant_decode(variant_t var, const byte_t* buf)
{
	variant_context* pvar = TypePtrFromHead(variant_context, var);
	dword_t n, total = 0;
	dword_t cnt;
	byte_t tag;
	int t;

	if (!buf)
	{
		if (var)
		{
			t = variant_get_type(var);
			variant_to_null(var, t);
		}
		return 0;
	}

	ver_read_tag(buf, NULL, &tag, &cnt);
	tag &= 0x7F;
	cnt &= 0x00FFFFFF;

	if (!IS_VARIANT_TYPE(tag)) return total;

	if (var)
	{
		variant_realloc(var, tag, cnt);
	}

	switch (tag)
	{
	case VV_NULL:
		n = ver_read_null((buf + total));
		total += n;
		if(var)
		{
			variant_to_null(var, VV_NULL);
		}
		break;
	case VV_BOOL:
		n = ver_read_bool((buf + total), ((var)? (bool_t*)(pvar->data) : NULL));
		total += n;
		break;
	case VV_BOOL_ARRAY:
		n = ver_read_bool_array((buf + total), ((var)? (bool_t*)(pvar->data) : NULL), ((var)? (dword_t)(pvar->count) : MAX_LONG));
		total += n;
		break;
	case VV_BYTE:
		n = ver_read_byte((buf + total), ((var)? (byte_t*)(pvar->data) : NULL));
		total += n;
		break;
	case VV_BYTE_ARRAY:
		n = ver_read_byte_array((buf + total), ((var)? (byte_t*)(pvar->data) : NULL), ((var)? (dword_t)(pvar->count) : MAX_LONG));
		total += n;
		break;
	case VV_SHORT:
		n = ver_read_short((buf + total), ((var)? (short*)(pvar->data) : NULL));
		total += n;
		break;
	case VV_SHORT_ARRAY:
		n = ver_read_short_array((buf + total), ((var)? (short*)(pvar->data) : NULL), ((var)? (dword_t)(pvar->count) : MAX_LONG));
		total += n;
		break;
	case VV_INT:
		n = ver_read_int((buf + total), ((var)? (int*)(pvar->data) : NULL));
		total += n;
		break;
	case VV_INT_ARRAY:
		n = ver_read_int_array((buf + total), ((var)? (int*)(pvar->data) : NULL), ((var)? (dword_t)(pvar->count) : MAX_LONG));
		total += n;
		break;
	case VV_LONG:
		n = ver_read_long((buf + total), ((var)? (long long*)(pvar->data) : NULL));
		total += n;
		break;
	case VV_LONG_ARRAY:
		n = ver_read_long_array((buf + total), ((var)? (long long*)(pvar->data) : NULL), ((var)? (dword_t)(pvar->count) : MAX_LONG));
		total += n;
		break;
	case VV_FLOAT:
		n = ver_read_float((buf + total), ((var)? (float*)(pvar->data) : NULL));
		total += n;
		break;
	case VV_FLOAT_ARRAY:
		n = ver_read_float_array((buf + total), ((var)? (float*)(pvar->data) : NULL), ((var)? (dword_t)(pvar->count) : MAX_LONG));
		total += n;
		break;
	case VV_DOUBLE:
		n = ver_read_double((buf + total), ((var)? (double*)(pvar->data) : NULL));
		total += n;
		break;
	case VV_DOUBLE_ARRAY:
		n = ver_read_double_array((buf + total), ((var)? (double*)(pvar->data) : NULL), ((var)? (dword_t)(pvar->count) : MAX_LONG));
		total += n;
		break;
	case VV_STRING_GB2312:
		n = ver_read_gb2312_string((buf + total), ((var)? (byte_t*)(pvar->data) : NULL), ((var)? (dword_t)(pvar->count) : MAX_LONG));
		total += n;
		break;
	case VV_STRING_UTF8:
		n = ver_read_utf8_string((buf + total), ((var)? (byte_t*)(pvar->data) : NULL), ((var)? (dword_t)(pvar->count) : MAX_LONG));
		total += n;
		break;
	case VV_STRING_UTF16LIT:
		n = ver_read_utf16lit_string((buf + total), ((var)? (byte_t*)(pvar->data) : NULL), ((var)? (dword_t)(pvar->count) : MAX_LONG));
		total += n;
		break;
	case VV_STRING_UTF16BIG:
		n = ver_read_utf16big_string((buf + total), ((var)? (byte_t*)(pvar->data) : NULL), ((var)? (dword_t)(pvar->count) : MAX_LONG));
		total += n;
		break;
	default:
		break;
	}

	return total;
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void variant_self_test()
{
	variant_t v1, v2;
	byte_t* pb;
	dword_t n;

	printf("test variant...\n");

	printf("test variant null\n");
	v1 = variant_alloc(VV_NULL);
	v2 = variant_alloc(VV_NULL);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	n = variant_encode(v1, NULL);
	pb = (byte_t*)xmem_alloc(n);
	variant_encode(v1, pb);
	variant_to_null(v2, VV_NULL);
	variant_decode(v2, pb);
	xmem_free(pb);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	variant_free(v1);
	variant_free(v2);

	printf("test variant bool\n");
	v1 = variant_alloc(VV_BOOL);
	variant_set_bool(v1, 1);
	v2 = variant_alloc(VV_BOOL);
	variant_set_bool(v2, 2);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	n = variant_encode(v1, NULL);
	pb = (byte_t*)xmem_alloc(n);
	variant_encode(v1, pb);
	variant_to_null(v2, VV_NULL);
	variant_decode(v2, pb);
	xmem_free(pb);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	variant_free(v1);
	variant_free(v2);

	printf("test variant long\n");
	v1 = variant_alloc(VV_LONG);
	variant_set_long(v1, MAX_LONGLONG);
	v2 = variant_alloc(VV_LONG);
	variant_set_long(v2, MAX_LONGLONG);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	n = variant_encode(v1, NULL);
	pb = (byte_t*)xmem_alloc(n);
	variant_encode(v1, pb);
	variant_to_null(v2, VV_NULL);
	variant_decode(v2, pb);
	xmem_free(pb);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	variant_free(v1);
	variant_free(v2);

	printf("test variant float\n");
	v1 = variant_alloc(VV_FLOAT);
	variant_set_float(v1, 0.0001);
	v2 = variant_alloc(VV_FLOAT);
	variant_set_float(v2, 0.0001);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	n = variant_encode(v1, NULL);
	pb = (byte_t*)xmem_alloc(n);
	variant_encode(v1, pb);
	variant_to_null(v2, VV_NULL);
	variant_decode(v2, pb);
	xmem_free(pb);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	variant_free(v1);
	variant_free(v2);

	printf("test variant double\n");
	v1 = variant_alloc(VV_DOUBLE);
	variant_set_double(v1, 0.000000001);
	v2 = variant_alloc(VV_DOUBLE);
	variant_set_double(v2, 0.000000001);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	n = variant_encode(v1, NULL);
	pb = (byte_t*)xmem_alloc(n);
	variant_encode(v1, pb);
	variant_to_null(v2, VV_NULL);
	variant_decode(v2, pb);
	xmem_free(pb);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	variant_free(v1);
	variant_free(v2);

	printf("test variant string\n");
	v1 = variant_alloc(VV_STRING_GB2312);
	variant_from_string(v1, _T("您好，世界！"), -1);
	v2 = variant_alloc(VV_STRING_GB2312);
	variant_from_string(v2, _T("您好，世界！"), -1);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	n = variant_encode(v1, NULL);
	pb = (byte_t*)xmem_alloc(n);
	variant_encode(v1, pb);
	variant_to_null(v2, VV_NULL);
	variant_decode(v2, pb);
	xmem_free(pb);
	XDK_ASSERT(variant_comp(v1, v2) == 0);

	variant_free(v1);
	variant_free(v2);

	printf("test variant end...\n");
}
#endif