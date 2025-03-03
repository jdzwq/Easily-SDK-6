﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdm object document

	@module	object.h | interface file

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

#ifndef _VAROBJ_H
#define _VAROBJ_H

#include "../xdkdef.h"


#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION object_alloc: alloc a object.
@RETURN object_t: return the object.
*/
EXP_API object_t object_alloc(void);

/*
@FUNCTION object_free: free a object.
@INPUT object_t obj: the object.
@RETURN void: none.
*/
EXP_API void object_free(object_t obj);

/*
@FUNCTION object_clone: clone a new object.
@INPUT object_t obj: the object for copying.
@RETURN object_t: the new object.
*/
EXP_API object_t object_clone(object_t obj);

/*
@FUNCTION object_copy: copy source object to destination object.
@INPUT object_t dst: the destination object.
@INPUT object_t src: the source object.
@RETURN void: none.
*/
EXP_API void object_copy(object_t dst, object_t src);

/*
@FUNCTION object_empty: empty the object.
@INPUT object_t obj: the object.
@RETURN void: none.
*/
EXP_API void object_empty(object_t obj);

/*
@FUNCTION object_size: get object size in bytes.
@INPUT object_t obj: the object.
@RETURN dword_t: bites.
*/
EXP_API dword_t object_size(object_t obj);

/*
@FUNCTION object_get_type: get the object type, it can be _OBJECT_UNKNOWN, _OBJECT_STRING, _OBJECT_VARIANT, _OBJECT_DOMDOC, _OBJECT_BINARY.
@INPUT object_t obj: the object.
@RETURN int: return the object type, default is _OBJECT_UNKNOWN.
*/
EXP_API int object_get_type(object_t obj);

/*
@FUNCTION object_get_commpress: test the object is compressed.
@INPUT object_t obj: the object.
@RETURN boo_t: return nonzero if compressed, otherwise return zero.
*/
EXP_API bool_t object_get_commpress(object_t obj);

/*
@FUNCTION object_set_commpress: compress or decompress object.
@INPUT object_t obj: the object.
@INPUT bool_t b: nonzero for compressing, zero for decompressing.
@RETURN void: none.
*/
EXP_API void object_set_commpress(object_t obj, bool_t b);

/*
@FUNCTION object_set_message: save message to object.
@INPUT object_t obj: the object.
@INPUT message_t val: the message object.
@RETURN void: none.
*/
EXP_API void object_set_message(object_t obj, message_t val);

/*
@FUNCTION object_get_message: get message from object.
@INPUT object_t obj: the object.
@OUTPUT message_t val: the message object.
@RETURN bool_t: return nonzero if succeed
*/
EXP_API bool_t object_get_message(object_t obj, message_t val);

/*
@FUNCTION object_set_queue: save queue to object.
@INPUT object_t obj: the object.
@INPUT queue_t val: the queue object.
@RETURN void: none.
*/
EXP_API void object_set_queue(object_t obj, queue_t val);

/*
@FUNCTION object_get_queue: get queue from object.
@INPUT object_t obj: the object.
@OUTPUT queue_t val: the queue object.
@RETURN bool_t: return nonzero if succeed.
*/
EXP_API bool_t object_get_queue(object_t obj, queue_t val);

/*
@FUNCTION object_set_vector: save vector to object.
@INPUT object_t obj: the object.
@INPUT vector_t val: the vector object.
@RETURN void: none.
*/
EXP_API void object_set_vector(object_t obj, vector_t val);

/*
@FUNCTION object_get_vector: get vector from object.
@INPUT object_t obj: the object.
@OUTPUT vector_t val: the vector object.
@RETURN bool_t: return nonzero if succeeded.
*/
EXP_API bool_t object_get_vector(object_t obj, vector_t val);

/*
@FUNCTION object_set_matrix: save matrix to object.
@INPUT object_t obj: the object.
@INPUT matrix_t val: the matrix object.
@RETURN void: none.
*/
EXP_API void object_set_matrix(object_t obj, matrix_t val);

/*
@FUNCTION object_get_matrix: get matrix from object.
@INPUT object_t obj: the object.
@OUTPUT matrix_t val: the matrix object.
@RETURN bool_t: return nonzero if succeeded.
*/
EXP_API bool_t object_get_matrix(object_t obj, matrix_t val);

/*
@FUNCTION object_set_map: save map to object.
@INPUT object_t obj: the object.
@INPUT map_t val: the map object.
@RETURN void: none.
*/
EXP_API void object_set_map(object_t obj, map_t val);

/*
@FUNCTION object_get_map: get map from object.
@INPUT object_t obj: the object.
@OUTPUT map_t val: the map object.
@RETURN bool_t: return nonzero if succeeded.
*/
EXP_API bool_t object_get_map(object_t obj, map_t val);

/*
@FUNCTION object_set_string: save string to object.
@INPUT object_t obj: the object.
@INPUT string_t val: the string object.
@RETURN void: none.
*/
EXP_API void object_set_string(object_t obj, string_t val);

/*
@FUNCTION object_get_string: get string from object.
@INPUT object_t obj: the object.
@OUTPUT string_t val: the string object.
@RETURN bool_t: return nonzero if succeeded.
*/
EXP_API bool_t object_get_string(object_t obj, string_t val);

/*
@FUNCTION object_set_variant: save variant to object.
@INPUT object_t obj: the object.
@INPUT variant_t val: the variant object.
@RETURN void: none.
*/
EXP_API void object_set_variant(object_t obj, variant_t val);

/*
@FUNCTION object_get_variant: get variant from object.
@INPUT object_t obj: the object.
@OUTPUT variant_t val: the variant object.
@RETURN bool_t: return nonzero if succeeded.
*/
EXP_API bool_t object_get_variant(object_t obj, variant_t val);

#if defined(XDM_SUPPORT_DOC)
/*
@FUNCTION object_set_domdoc: save dom document to object.
@INPUT object_t obj: the object.
@INPUT link_t_ptr dom: the dom document.
@RETURN void: none.
*/
EXP_API void object_set_domdoc(object_t obj, link_t_ptr dom);

/*
@FUNCTION object_get_domdoc: get dom document from object.
@INPUT object_t obj: the object.
@OUTPUT link_t_ptr dom: the dom document.
@RETURN bool_t: return nonzero if succeeded.
*/
EXP_API bool_t object_get_domdoc(object_t obj, link_t_ptr dom);
#endif

/*
@FUNCTION object_set_bytes: save bytes to object.
@INPUT object_t obj: the object.
@INPUT const byte_t* buf: the bytes buffer.
@INPUT dword_t len: the buffer size in bytes.
@RETURN void: none.
*/
EXP_API void object_set_bytes(object_t obj, const byte_t* buf, dword_t len);

/*
@FUNCTION object_add_bytes: append bytes to object.
@INPUT object_t obj: the object.
@INPUT const byte_t* buf: the bytes buffer.
@INPUT dword_t len: the buffer size in bytes.
@RETURN void: none.
*/
EXP_API void object_add_bytes(object_t obj, const byte_t* buf, dword_t len);

/*
@FUNCTION object_add_bytes: delete followed bytes from object.
@INPUT object_t obj: the object.
@INPUT dword_t off: the zero based posotin.
@RETURN void: none.
*/
EXP_API void object_del_bytes(object_t obj, dword_t off);

/*
@FUNCTION object_get_bytes: load bytes from object.
@INPUT object_t obj: the object.
@OUTPUT byte_t* buf: the bytes buffer.
@INPUT dword_t max: the buffer size in bytes.
@RETURN dword_t: return the bytes loaded.
*/
EXP_API dword_t object_get_bytes(object_t obj, byte_t* buf, dword_t max);

/*
@FUNCTION object_encode: encode a object to bytes buffer.
@INPUT object_t obj: the object.
@OUTPUT byte_t* buf: the bytes buffer.
@INPUT dword_t max: the buffer size in bytes.
@RETURN dword_t: return the bytes encoded.
*/
EXP_API dword_t object_encode(object_t obj, byte_t* buf, dword_t max);

/*
@FUNCTION object_decode: decode a object from bytes buffer.
@INPUT object_t obj: the object.
@INPUT const byte_t* data: the bytes buffer.
@RETURN dword_t: return the bytes decoded.
*/
EXP_API dword_t object_decode(object_t obj, const byte_t* data);

/*
@FUNCTION object_hash32: get object object 32bits hash code.
@INPUT object var: the object object.
@OUTPUT key32_t* pkey: the 32bits key buffer.
@RETURN void: none.
*/
EXP_API void object_hash32(object_t obj, key32_t* pkey);

/*
@FUNCTION object_hash64: get object object 64bits hash code.
@INPUT object var: the object object.
@OUTPUT key64_t* pkey: the 64bits key buffer.
@RETURN void: none.
*/
EXP_API void object_hash64(object_t obj, key64_t* pkey);

/*
@FUNCTION object_hash128: get object object 128bits hash code.
@INPUT object var: the object object.
@OUTPUT key128_t* pkey: the 128bits key buffer.
@RETURN void: none.
*/
EXP_API void object_hash128(object_t obj, key128_t* pkey);

#if defined(XDK_SUPPORT_TEST)
	EXP_API void test_object(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_OBJECT_H*/