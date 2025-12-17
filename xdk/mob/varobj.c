/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc object document

	@module	object.c | implement file

	@devnote 张文权 2021.01 - 2021.12	v6.0
***********************************************************************/

/**********************************************************************
This program is free software : you can radistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
LICENSE.GPL3 for more details.
***********************************************************************/

#include "varobj.h"

#include "../xdkobj.h"
#include "../xdkstd.h"
#include "../xdkoem.h"
#include "../xdkimp.h"

#define MIN_NEED_COMPRESS	1024

#define MEM_TYPE_MASK	0x10
#define MEM_SIZE_MASK	0x80000000


typedef struct _object_context{
	memo_head head;

	nuid_t nuid;	// object identify
	dword_t size;	// object encoded or commpressed size in bytes, data may commpressed with high-bit set to 1 
	byte_t* data;	// object encoded or commpressed data
}object_context;

static void _object_compress(object_context* pobj)
{
	byte_t type;
	bool_t ziped;
	dword_t cur, org;
	byte_t* buf;

	type = (pobj->head.tag & MEM_TYPE_MASK);
	ziped = (pobj->size & MEM_SIZE_MASK);

	//object bytes
	org = (pobj->size & (~MEM_SIZE_MASK));
	cur = org;

	//if compresse
	if (ziped || org < MIN_NEED_COMPRESS) return;

	switch (type)
	{
	case MEM_STRING:
		cur += (cur / 10);
		if (cur == org) cur++;

		buf = (byte_t*)xmem_alloc(cur + 4);
		if ((cur = lzf_compress(pobj->data, org, buf, cur)) == 0)
		{
			xmem_free(buf);
			return;
		}
		break;
	default:
		cur += (cur / 10);
		if (cur == org) cur++;

		buf = (byte_t*)xmem_alloc(cur + 4);
		if (xzlib_compress_bytes(pobj->data, org, buf, &cur) == 0)
		{
			xmem_free(buf);
			return;
		}
		break;
	}

	xmem_free(pobj->data);
	pobj->data = buf;
	pobj->size |= MEM_SIZE_MASK;
	PUT_DWORD_NET(pobj->data, 0, cur);
}

static void _object_decompress(object_context* pobj)
{
	byte_t type;
	bool_t ziped;
	dword_t cur, org;
	byte_t* buf;

	type = (pobj->head.tag & MEM_TYPE_MASK);
	ziped = (pobj->size & MEM_SIZE_MASK);

	//if not compressed
	if (!ziped) return;

	//compressed bytes
	org = GET_DWORD_NET(pobj->data, 0);
	//uncompressed bytes
	cur = (pobj->size & (~MEM_SIZE_MASK));
	if (!cur) return;

	buf = (byte_t*)xmem_alloc(cur);

	switch (type)
	{
	case MEM_STRING:
		if ((cur = lzf_decompress((pobj->data + 4), org, buf, cur)) == 0)
		{
			xmem_free(buf);
			return;
		}
		break;
	default:
		if (!xzlib_uncompress_bytes((pobj->data + 4), org, buf, &cur))
		{
			xmem_free(buf);
			return;
		}
		break;
	}
	
	xmem_free(pobj->data);
	pobj->data = buf;
	pobj->size &= 0x7FFFFFFF;
}

/*********************************************************************************/
object_t object_alloc(void)
{
	object_context* pobj;

	pobj = (object_context*)xmem_alloc(sizeof(object_context));
	pobj->head.tag = (MEM_EMPTY | MEM_TYPE_MASK);

	return (object_t)&(pobj->head);
}

void object_free(object_t obj)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	if(pobj->data) xmem_free(pobj->data);

	xmem_free(pobj);
}

void object_clear(object_t obj)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	if(pobj->data) xmem_free(pobj->data);

	pobj->data = NULL;
	pobj->size = 0;
	xmem_zero((void*)&(pobj->nuid), sizeof(nuid_t));
	
	obj->tag = (MEM_EMPTY | MEM_TYPE_MASK);
}

dword_t object_size(object_t obj)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	return (pobj->size & (~MEM_SIZE_MASK));
}

object_t object_clone(object_t obj)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	object_context* pnew;
	dword_t zips;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	pnew = (object_context*)xmem_alloc(sizeof(object_context));
	pnew->head.tag = (MEM_EMPTY | MEM_TYPE_MASK);
	xmem_copy((void*)&(pnew->nuid), (void*)&(pobj->nuid), sizeof(nuid_t));
	if(pobj->size)
	{
		zips = (pobj->size & MEM_SIZE_MASK)? GET_DWORD_NET(pobj->data, 0) : pobj->size;
		pnew->data = (byte_t*)xmem_clone((void*)pobj->data, zips);
	}
	pnew->size = pobj->size;

	return (object_t)&(pnew->head);
}

void object_copy(object_t dst, object_t src)
{
	object_context* pdst = TypePtrFromHead(object_context, dst);
	object_context* psrc = TypePtrFromHead(object_context, src);
	bool_t ziped;

	XDK_ASSERT(dst && IS_OBJECT_TYPE(dst->tag));
	XDK_ASSERT(src && IS_OBJECT_TYPE(src->tag));

	ziped = object_get_commpress(src);
	if(ziped)
	{
		_object_decompress(psrc);
	}

	object_clear(dst);
	
	pdst->head.tag = psrc->head.tag;
	xmem_copy((void*)&(pdst->nuid), (void*)&(psrc->nuid), sizeof(nuid_t));
	pdst->size = psrc->size;
	pdst->data = (byte_t*)xmem_clone((void*)psrc->data, psrc->size);
}

int object_get_type(object_t obj)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	return (int)(obj->tag & 0x0F);
}

bool_t object_get_commpress(object_t obj)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	return (pobj->size & MEM_SIZE_MASK) ? 1 : 0;
}

void object_set_commpress(object_t obj, bool_t b)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	ziped = object_get_commpress(obj);

	if (ziped && b)
		return;
	else if (!ziped && !b)
		return;
	else if (b)
		_object_compress(pobj);
	else
		_object_decompress(pobj);
}

bool_t object_decode_message(object_t obj, message_t val)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	byte_t type;
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	type = object_get_type(obj);
	ziped = object_get_commpress(obj);

	if (type != MEM_MESSAGE)
		return 0;

	if (ziped)
	{
		//decompress first
		_object_decompress(pobj);
	}

	return (pobj->size == message_decode(val, pobj->data))? bool_true : bool_false;
}

void object_encode_message(object_t obj, message_t val)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	object_clear(obj);

	pobj->head.tag = (MEM_MESSAGE | MEM_TYPE_MASK);
	pobj->size = message_encode(val, NULL);
	pobj->data = (byte_t*)xmem_alloc(pobj->size);

	message_encode(val, pobj->data);
}

bool_t object_decode_matrix(object_t obj, matrix_t val)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	byte_t type;
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	type = object_get_type(obj);
	ziped = object_get_commpress(obj);

	if (type != MEM_MATRIX)
		return 0;

	if (ziped)
	{
		//decompress first
		_object_decompress(pobj);
	}

	return (pobj->size == matrix_decode(val, pobj->data))? bool_true : bool_false;
}

void object_encode_matrix(object_t obj, matrix_t val)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	object_clear(obj);

	pobj->head.tag = (MEM_MATRIX | MEM_TYPE_MASK);
	pobj->size = matrix_encode(val, NULL);
	pobj->data = (byte_t*)xmem_alloc(pobj->size);

	matrix_encode(val, pobj->data);
}

bool_t object_decode_vector(object_t obj, vector_t val)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	byte_t type;
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	type = object_get_type(obj);
	ziped = object_get_commpress(obj);

	if (type != MEM_VECTOR)
		return 0;

	if (ziped)
	{
		//decompress first
		_object_decompress(pobj);
	}

	return (pobj->size == vector_decode(val, pobj->data))? bool_true : bool_false;
}

void object_encode_vector(object_t obj, vector_t val)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	object_clear(obj);

	pobj->head.tag = (MEM_VECTOR | MEM_TYPE_MASK);
	pobj->size = vector_encode(val, NULL);
	pobj->data = (byte_t*)xmem_alloc(pobj->size);

	vector_encode(val, pobj->data);
}

bool_t object_decode_map(object_t obj, map_t val)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	byte_t type;
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	type = object_get_type(obj);
	ziped = object_get_commpress(obj);

	if (type != MEM_MAP)
		return 0;

	if (ziped)
	{
		//decompress first
		_object_decompress(pobj);
	}

	return (pobj->size == map_decode(val, pobj->data))? bool_true : bool_false;
}

void object_encode_map(object_t obj, map_t val)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	object_clear(obj);

	pobj->head.tag = (MEM_MAP | MEM_TYPE_MASK);
	pobj->size = map_encode(val, NULL);
	pobj->data = (byte_t*)xmem_alloc(pobj->size);

	map_encode(val, pobj->data);
}

void object_encode_variant(object_t obj, variant_t val)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	dword_t dw;
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	object_clear(obj);

	pobj->size = variant_encode(val, NULL);
	pobj->head.tag = (MEM_VARIANT | MEM_TYPE_MASK);
	pobj->data = (byte_t*)xmem_alloc(pobj->size);

	variant_encode(val, pobj->data);
}

bool_t object_decode_variant(object_t obj, variant_t val)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	byte_t type;
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	type = object_get_type(obj);
	ziped = object_get_commpress(obj);

	if (type != MEM_VARIANT)
		return 0;

	if (ziped)
	{
		//decompress first
		_object_decompress(pobj);
	}

	return (pobj->size == variant_decode(val, pobj->data))? bool_true : bool_false;
}

void object_encode_string(object_t obj, string_t str)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	dword_t dw;
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	object_clear(obj);

	pobj->size = string_encode(str, _UTF8_BOM, NULL, MAX_LONG);
	pobj->head.tag = (MEM_VARIANT | MEM_TYPE_MASK);
	pobj->data = (byte_t*)xmem_alloc(pobj->size);

	string_encode(str, _UTF8_BOM, pobj->data, pobj->size);
}

bool_t object_decode_string(object_t obj, string_t str)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	byte_t type;
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	type = object_get_type(obj);
	ziped = object_get_commpress(obj);

	if (type != MEM_STRING)
		return 0;

	if (ziped)
	{
		//decompress first
		_object_decompress(pobj);
	}

	return (pobj->size == string_decode(str, _UTF8_BOM, pobj->data, pobj->size))? bool_true : bool_false;
}

void object_hash32(object_t obj, key32_t* pkey)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	ziped = object_get_commpress(obj);
	if (ziped)
	{
		_object_decompress(pobj);
	}

	if (pobj->size)
		murhash32(pobj->data, pobj->size, (byte_t*)pkey);
	else
		xmem_zero((void*)pkey, sizeof(key32_t));
}

void object_hash64(object_t obj, key64_t* pkey)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	ziped = object_get_commpress(obj);
	if (ziped)
	{
		_object_decompress(pobj);
	}

	if (pobj->size)
		siphash64(pobj->data, pobj->size, (byte_t*)pkey);
	else
		xmem_zero((void*)pkey, sizeof(key64_t));
}

void object_hash128(object_t obj, key128_t* pkey)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	bool_t ziped;

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	ziped = object_get_commpress(obj);
	if (ziped)
	{
		_object_decompress(pobj);
	}

	if (pobj->size)
		murhash128(pobj->data, pobj->size, (byte_t*)pkey);
	else
		xmem_zero((void*)pkey, sizeof(key128_t));
}

/**********************************************************************
ASN.1 CER ENCODING
Object::=SEQUENCE{
	Type: BYTE
	Uuid: BYTE[36]
	Size: BYTE[4]
	Data: BYTE[]
}
**********************************************************************/

dword_t object_encode(object_t obj, byte_t* buf)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	bool_t ziped;
	dword_t len, n, total = 0;
	byte_t* pos = NULL;
	byte_t md5[16] = {0};

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	ziped = object_get_commpress(obj);
	if (ziped)
	{
		_object_decompress(pobj);
	}

	n = ver_write_sequence(((buf)? (buf + total) : NULL), &pos);
	if(!n)
	{
		set_last_error(_T("object_encode"), _T("ver_write_sequence"), -1);
		return 0;
	} 
	total += n;

	n = ver_write_byte(((buf)? (buf + total) : NULL), obj->tag);
	if(!n)
	{
		set_last_error(_T("object_encode"), _T("ver_write_byte"), -1);
		return 0;
	} 
	total += n;
	
	nuid_to_md5(&(pobj->nuid), md5);
	len = 16;
	n = ver_write_byte_array(((buf)? (buf + total) : NULL), md5, len);
	if(!n)
	{
		set_last_error(_T("object_encode"), _T("ver_write_byte_array"), -1);
		return 0;
	} 
	total += n;
	
	len = pobj->size;
	n = ver_write_int(((buf)? (buf + total) : NULL), len);
	if(!n)
	{
		set_last_error(_T("object_encode"), _T("ver_write_integer"), -1);
		return 0;
	} 
	total += n;

	n = ver_write_byte_array(((buf)? (buf + total) : NULL), pobj->data, pobj->size);
	if(!n)
	{
		set_last_error(_T("object_encode"), _T("ver_write_byte_array"), -1);
		return 0;
	} 
	total += n;

	if(pos) ver_write_sequence_length(pos, total);

	return total;
}

dword_t object_decode(object_t obj, const byte_t* buf)
{
	object_context* pobj = TypePtrFromHead(object_context, obj);
	dword_t len, n, total = 0;
	byte_t* pos = NULL;

	byte_t type;
	byte_t md5[16] = {0};

	XDK_ASSERT(obj && IS_OBJECT_TYPE(obj->tag));

	object_clear(obj);

	if(!buf) return 0;

	n = ver_read_sequence((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("object_decode"), _T("ver_read_sequence"), -1);
		return 0;
	}
	total += n;

	n = ver_read_byte((buf + total), &type);
	if(!n)
	{
		set_last_error(_T("object_decode"), _T("ver_read_byte_array"), -1);
		return 0;
	} 
	total += n;

	if(!IS_OBJECT_TYPE(type))
	{
		set_last_error(_T("object_decode"), _T("object type invalid"), -1);
		return 0;
	}

	n = ver_read_byte_array((buf + total), md5, 16);
	if(!n)
	{
		set_last_error(_T("object_decode"), _T("ver_read_byte_array"), -1);
		return 0;
	} 
	total += n;

	nuid_from_md5(&(pobj->nuid), md5);

	n = ver_read_int((buf + total), (int*)&(pobj->size));
	if(!n)
	{
		set_last_error(_T("object_decode"), _T("ver_read_int"), -1);
		return 0;
	} 
	total += n;

	pobj->data = (byte_t*)xmem_alloc(pobj->size);

	n = ver_read_byte_array((buf + total), pobj->data, pobj->size);
	if(!n)
	{
		set_last_error(_T("object_decode"), _T("ver_read_byte_array"), -1);
		return 0;
	} 
	total += n;

	return total;
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void object_self_test(void)
{
	printf("test object...\n");

	object_t obj = object_alloc();

	tchar_t* str;
	int len;

	string_t s = string_alloc();
	string_cpy(s, _T("object test 字符对象测试"), -1);
	len = string_len(s);
	str = (tchar_t*)string_ptr(s);
	_tprintf(_T("string object test: %s\n"), str);

	object_encode_string(obj, s);
	object_set_commpress(obj, 1);
	len = object_size(obj);
	_tprintf(_T("string object compressed:%d\n"), len);

	string_empty(s);
	object_decode_string(obj, s);
	len = string_len(s);
	str = (tchar_t*)string_ptr(s);
	_tprintf(_T("string object unconpressed: %s\n"), str);
	
	string_cpy(s, _T("object test 变体对象测试"), -1);
	len = string_len(s);
	str = (tchar_t*)string_ptr(s);
	_tprintf(_T("variant object test: %s\n"), str);

	variant_t v = variant_alloc(VV_STRING_UTF8);
	variant_from_string(v, string_ptr(s), string_len(s));

	object_encode_variant(obj, v);
	object_set_commpress(obj, 1);
	len = object_size(obj);
	_tprintf(_T("variant object compressed:%d\n"), len);

	variant_to_null(v, VV_STRING_UTF8);
	object_decode_variant(obj, v);
	len = variant_to_string(v, NULL, MAX_LONG);
	str = xsalloc(len + 1);
	variant_to_string(v, str, len);
	_tprintf(_T("variant object unconpressed: %s\n"), str);
	xsfree(str);

	byte_t* buf;
	dword_t dw;
	dw = object_encode(obj, NULL);
	buf = (byte_t*)xmem_alloc(dw);
	object_encode(obj, buf);

	object_clear(obj);
	object_decode(obj, buf);
	xmem_free(buf);

	object_decode_variant(obj, v);
	len = variant_to_string(v, NULL, MAX_LONG);
	str = xsalloc(len + 1);
	variant_to_string(v, str, len);
	xsfree(str);

	string_free(s);
	variant_free(v);
	object_free(obj);

	printf("test object end\n");
}
#endif