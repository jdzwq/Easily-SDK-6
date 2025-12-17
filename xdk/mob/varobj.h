/***********************************************************************
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

/**********************************************************************
@FUNCTION: alloc a empty object.
@RETURN: object struct.
***********************************************************************/
EXP_API object_t object_alloc(void);

/**********************************************************************
@FUNCTION: free a object.
@INPUT: the object.
@RETURN: none.
***********************************************************************/
EXP_API void object_free(object_t obj);

/**********************************************************************
@FUNCTION: clone a new object.
@INPUT: the object for copying.
@RETURN: the new object.
***********************************************************************/
EXP_API object_t object_clone(object_t obj);

/**********************************************************************
@FUNCTION: copy a new object from source.
@INPUT: the destination object.
@INPUT: the source object.
@RETURN: none.
***********************************************************************/
EXP_API void object_copy(object_t dst, object_t src);

/**********************************************************************
@FUNCTION: empty the object.
@INPUT: the object.
@RETURN: none.
***********************************************************************/
EXP_API void object_clear(object_t obj);

/**********************************************************************
@FUNCTION: get object data uncompressed size in bytes.
@INPUT: the object.
@RETURN: data bytes.
***********************************************************************/
EXP_API dword_t object_size(object_t obj);

/**********************************************************************
@FUNCTION: get the object type, as the defined _OBJECT_*.
@INPUT: the object.
@RETURN: the object type.
***********************************************************************/
EXP_API int object_get_type(object_t obj);

/**********************************************************************
@FUNCTION: test the object is compressed.
@INPUT: the object.
@RETURN: return nonzero if compressed, otherwise return zero.
***********************************************************************/
EXP_API bool_t object_get_commpress(object_t obj);

/**********************************************************************
@FUNCTION: compress or decompress the object.
@INPUT: the object.
@INPUT: nonzero for compressing, zero for decompressing.
@RETURN void: none.
***********************************************************************/
EXP_API void object_set_commpress(object_t obj, bool_t b);

/**********************************************************************
@FUNCTION: encode a message into object as data content.
@INPUT: the object.
@INPUT: the message object.
@RETURN: none.
***********************************************************************/
EXP_API void object_encode_message(object_t obj, message_t val);

/**********************************************************************
@FUNCTION: decode message from object data content.
@INPUT: the object.
@OUTPUT: the message object.
@RETURN: nonzero if succeed, otherwise zero returned.
***********************************************************************/
EXP_API bool_t object_decode_message(object_t obj, message_t val);

/**********************************************************************
@FUNCTION: encode a vector into object as data content.
@INPUT: the object.
@INPUT: the vector object.
@RETURN: none.
***********************************************************************/
EXP_API void object_encode_vector(object_t obj, vector_t val);

/**********************************************************************
@FUNCTION: decode vector from object data content.
@INPUT: the object.
@OUTPUT: the vector object.
@RETURN: nonzero if succeed, otherwise zero returned.
***********************************************************************/
EXP_API bool_t object_decode_vector(object_t obj, vector_t val);

/**********************************************************************
@FUNCTION: encode a matrix into object as data content.
@INPUT: the object.
@INPUT: the matrix object.
@RETURN: none.
***********************************************************************/
EXP_API void object_encode_matrix(object_t obj, matrix_t val);

/**********************************************************************
@FUNCTION: decode matrix from object data content.
@INPUT: the object.
@OUTPUT: the matrix object.
@RETURN: nonzero if succeed, otherwise zero returned.
***********************************************************************/
EXP_API bool_t object_decode_matrix(object_t obj, matrix_t val);

/**********************************************************************
@FUNCTION: encode a map into object as data content.
@INPUT: the object.
@INPUT: the map object.
@RETURN: none.
***********************************************************************/
EXP_API void object_encode_map(object_t obj, map_t val);

/**********************************************************************
@FUNCTION: decode map from object data content.
@INPUT: the object.
@OUTPUT: the map object.
@RETURN: nonzero if succeed, otherwise zero returned.
***********************************************************************/
EXP_API bool_t object_decode_map(object_t obj, map_t val);

/**********************************************************************
@FUNCTION: encode a string into object as data content.
@INPUT: the object.
@INPUT: the string object.
@RETURN: none.
***********************************************************************/
EXP_API void object_encode_string(object_t obj, string_t val);

/**********************************************************************
@FUNCTION: decode string from object data content.
@INPUT: the object.
@OUTPUT: the string object.
@RETURN: nonzero if succeed, otherwise zero returned.
***********************************************************************/
EXP_API bool_t object_decode_string(object_t obj, string_t val);

/**********************************************************************
@FUNCTION: encode a variant into object as data content.
@INPUT: the object.
@INPUT: the variant object.
@RETURN: none.
***********************************************************************/
EXP_API void object_encode_variant(object_t obj, variant_t val);

/**********************************************************************
@FUNCTION: decode variant from object data content.
@INPUT: the object.
@OUTPUT: the variant object.
@RETURN: nonzero if succeed, otherwise zero returned.
***********************************************************************/
EXP_API bool_t object_decode_variant(object_t obj, variant_t val);

/**********************************************************************
@FUNCTION: get object 32 bytes hash code.
@INPUT: the object.
@OUTPUT: the bytes buffer.
@RETURN: none.
***********************************************************************/
EXP_API void object_hash32(object_t obj, key32_t* pkey);

/**********************************************************************
@FUNCTION: get object 64 bytes hash code.
@INPUT: the object.
@OUTPUT: the bytes buffer.
@RETURN: none.
***********************************************************************/
EXP_API void object_hash64(object_t obj, key64_t* pkey);

/**********************************************************************
@FUNCTION: get object 128 bytes hash code.
@INPUT: the object.
@OUTPUT: the bytes buffer.
@RETURN: none.
***********************************************************************/
EXP_API void object_hash128(object_t obj, key128_t* pkey);

/**********************************************************************
@FUNCTION: encode object to bytes sequence.
@INPUT: the object.
@INPUT: the bytes buffer for encoding.
@RETURN: bytes encoded, zero for failed.
@NOTE: buffer can be NULL for testing how many bytes will be encoded.
***********************************************************************/
EXP_API dword_t object_encode(object_t obj, byte_t* buf);

/**********************************************************************
@FUNCTION: decode object from bytes sequence.
@INPUT: the object.
@INPUT: the bytes buffer with encoded data.
@RETURN: bytes decoded, zero for failed.
@NOTE: var can be NULL for testing how many bytes will be decoded.
***********************************************************************/
EXP_API dword_t object_decode(object_t obj, const byte_t* data);


#if defined (DEBUG) || defined (_DEBUG)
EXP_API void object_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_OBJECT_H*/