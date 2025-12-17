/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc variant value document

	@module	variant.h | interface file

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

#ifndef _VARIANT_H
#define _VARIANT_H

#include "../xdkdef.h"

/*define variant type*/
#define VV_NULL			0x00
#define VV_BOOL			0x01
#define VV_BYTE			0x02
#define VV_SHORT		0x03
#define VV_INT			0x04
#define VV_LONG			0x05
#define VV_FLOAT		0x06
#define VV_DOUBLE		0x07
#define VV_DATETIME			0x08
#define VV_STRING_GB2312	0x0A
#define VV_STRING_UTF8		0x0B
#define VV_STRING_UTF16LIT	0x0C
#define VV_STRING_UTF16BIG	0x0D

#define VV_ARRAY	0x10

#define VV_BOOL_ARRAY	(VV_BOOL | VV_ARRAY)
#define VV_BYTE_ARRAY	(VV_BYTE | VV_ARRAY)
#define VV_SHORT_ARRAY	(VV_SHORT | VV_ARRAY)
#define VV_INT_ARRAY	(VV_INT | VV_ARRAY)
#define VV_LONG_ARRAY	(VV_LONG | VV_ARRAY)
#define VV_FLOAT_ARRAY	(VV_FLOAT | VV_ARRAY)
#define VV_DOUBLE_ARRAY	(VV_DOUBLE | VV_ARRAY)
#define VV_DATETIME_ARRAY	(VV_DATETIME | VV_ARRAY)


#define IS_VARIANT_TYPE(tag) (((tag | VV_ARRAY) >= 0x10 && (tag | VV_ARRAY) <= 0x1D)? 1 : 0)

#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
@FUNCTION: alloc a NULL variant.
@RETURN: variant struct.
***********************************************************************/
EXP_API variant_t variant_alloc(int type);

/**********************************************************************
@FUNCTION: clone a variant.
@INPUT: the source variant.
@RETURN: the new variant struct.
***********************************************************************/
EXP_API variant_t variant_clone(variant_t var);

/**********************************************************************
@FUNCTION: free a variant.
@INPUT: the variant.
@RETURN: none.
***********************************************************************/
EXP_API void variant_free(variant_t var);

/**********************************************************************
@FUNCTION: get variant type.
@INPUT: the variant.
@RETURN: the VV type.
***********************************************************************/
EXP_API int variant_get_type(variant_t var);

/**********************************************************************
@FUNCTION: get variant data.
@INPUT: the variant.
@RETURN: the data buffer.
***********************************************************************/
EXP_API const void* variant_data(variant_t var);

/**********************************************************************
@FUNCTION: copy variant data to destination from source.
@INPUT: the destination variant.
@INPUT: the source variant.
@RETURN: none.
***********************************************************************/
EXP_API void variant_copy(variant_t pdst, variant_t psrc);

/**********************************************************************
@FUNCTION: copy variant data to destination from source.
@INPUT: the destination variant.
@INPUT: the source variant.
@RETURN: none.
***********************************************************************/
EXP_API bool_t variant_is_null(variant_t var);

/**********************************************************************
@FUNCTION: set variant to empty.
@INPUT: the variant.
@INPUT: the VV type.
@RETURN: none.
***********************************************************************/
EXP_API void variant_to_null(variant_t var, int type);

/**********************************************************************
@FUNCTION: format variant value to string token.
@INPUT: the variant.
@INPUT: the string buffer.
@INPUT: the buffer characters, not include zero terminated.
@RETURN: characters formated in buffer.
***********************************************************************/
EXP_API int variant_to_string(variant_t var, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: parse variant value from string token.
@INPUT: the variant.
@INPUT: the string token.
@INPUT: the string characters, not include zero terminated.
@RETURN: none.
@ROTE: the variant VV type no changing .
***********************************************************************/
EXP_API void variant_from_string(variant_t var, const tchar_t* str, int len);

/**********************************************************************
@FUNCTION: set variant boolean value.
@INPUT: the variant.
@INPUT: the boolean value.
@RETURN: none.
@ROTE: the variant VV type must be VV_BOOL.
***********************************************************************/
EXP_API void variant_set_bool(variant_t var, bool_t c);

/**********************************************************************
@FUNCTION: get variant boolean value.
@INPUT: the variant.
@RETURN: boolea value.
@ROTE: the variant VV type must be VV_BOOL.
***********************************************************************/
EXP_API bool_t variant_get_bool(variant_t var);

/**********************************************************************
@FUNCTION: set variant short value.
@INPUT: the variant.
@INPUT: the short integer value.
@RETURN: none.
@ROTE: the variant VV type must be VV_SHORT.
***********************************************************************/
EXP_API void variant_set_short(variant_t var, short c);

/**********************************************************************
@FUNCTION: get variant short value.
@INPUT: the variant.
@RETURN: short value.
@ROTE: the variant VV type must be VV_SHORT.
***********************************************************************/
EXP_API short variant_get_short(variant_t var);

/**********************************************************************
@FUNCTION: set variant integer value.
@INPUT: the variant.
@INPUT: the integer value.
@RETURN: none.
@ROTE: the variant VV type must be VV_INT.
***********************************************************************/
EXP_API void variant_set_int(variant_t var, int c);

/**********************************************************************
@FUNCTION: get variant integer value.
@INPUT: the variant.
@RETURN: integer value.
@ROTE: the variant VV type must be VV_INT.
***********************************************************************/
EXP_API int variant_get_int(variant_t var);

/**********************************************************************
@FUNCTION: set variant long value.
@INPUT: the variant.
@INPUT: the long integer value.
@RETURN: none.
@ROTE: the variant VV type must be VV_LONG.
***********************************************************************/
EXP_API void variant_set_long(variant_t var, long long c);

/**********************************************************************
@FUNCTION: get variant long integer value.
@INPUT: the variant.
@RETURN: long integer value.
@ROTE: the variant VV type must be VV_LONH.
***********************************************************************/
EXP_API long long variant_get_long(variant_t var);

/**********************************************************************
@FUNCTION: set variant float value.
@INPUT: the variant.
@INPUT: the float number.
@RETURN: none.
@ROTE: the variant VV type must be VV_FLOAT.
***********************************************************************/
EXP_API void variant_set_float(variant_t var, float c);

/**********************************************************************
@FUNCTION: get variant float value.
@INPUT: the variant.
@RETURN: float numeric.
@ROTE: the variant VV type must be VV_FLOAT.
***********************************************************************/
EXP_API float variant_get_float(variant_t var);

/**********************************************************************
@FUNCTION: set variant double value.
@INPUT: the variant.
@INPUT: the double number.
@RETURN: none.
@ROTE: the variant VV type must be VV_DOUBLE.
***********************************************************************/
EXP_API void variant_set_double(variant_t var, double c);

/**********************************************************************
@FUNCTION: get variant double value.
@INPUT: the variant.
@RETURN: double numeric.
@ROTE: the variant VV type must be VV_DOUBLE.
***********************************************************************/
EXP_API double variant_get_double(variant_t var);

/**********************************************************************
@FUNCTION: compare two variant.
@INPUT: the destination variant.
@INPUT: the source variant.
@RETURN: -1 for v1 < v2, 0 for v1 = v2, 1 for v1 > v2.
@ROTE: the two variant VV type must be same.
***********************************************************************/
EXP_API int variant_comp(variant_t var1, variant_t var2);

/**********************************************************************
@FUNCTION: get variant 32 bytes hash code.
@INPUT: the variant.
@INPUT: the hash key buffer.
@RETURN: none.
***********************************************************************/
EXP_API void variant_hash32(variant_t var, key32_t* pkey);

/**********************************************************************
@FUNCTION: get variant 64 bytes hash code.
@INPUT: the variant.
@INPUT: the hash key buffer.
@RETURN: none.
***********************************************************************/
EXP_API void variant_hash64(variant_t var, key64_t* pkey);

/**********************************************************************
@FUNCTION: get variant 128 bytes hash code.
@INPUT: the variant.
@INPUT: the hash key buffer.
@RETURN: none.
***********************************************************************/
EXP_API void variant_hash128(variant_t var, key128_t* pkey);

/**********************************************************************
@FUNCTION: encode variant to bytes sequence.
@INPUT: the variant.
@INPUT: the bytes buffer for encoding.
@RETURN: bytes encoded, zero for failed.
@NOTE: buffer can be NULL for testing how many bytes will be encoded.
***********************************************************************/
EXP_API dword_t variant_encode(variant_t var, byte_t* buf);

/**********************************************************************
@FUNCTION: decode variant from bytes sequence.
@INPUT: the variant.
@INPUT: the bytes buffer with encoded data.
@RETURN: bytes decoded, zero for failed.
@NOTE: var can be NULL for testing how many bytes will be decoded.
***********************************************************************/
EXP_API dword_t variant_decode(variant_t var, const byte_t* buf);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void variant_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif //VARIANT_H
