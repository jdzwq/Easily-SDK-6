/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdm vector document

	@module	vector.h | interface file

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

#ifndef _VECTOR_H
#define _VECTOR_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
@FUNCTION: calc vector data content size needed.
@INPUT: array size of vector.
@INPUT: dimension of vector.
@RETURN: the bytes needed.
***********************************************************************/
EXP_API dword_t vector_need_size(int count, int dimen);

/**********************************************************************
@FUNCTION: alloc a empty vector.
@INPUT: the vector array size.
@INPUT: the vector dimens, 1-dimens like: (x), 2-dimens like: (x,y), 3-dimens like (x,y,z).
@RETURN: new vector object.
***********************************************************************/
EXP_API vector_t vector_alloc(int count, int dimen);

/**********************************************************************
@FUNCTION: free the vector.
@INPUT: the vector object.
@RETURN: none.
***********************************************************************/
EXP_API void vector_free(vector_t vec);

/**********************************************************************
@FUNCTION: get vector data buffer.
@INPUT: the vector object.
@RETURN: the vector inner data buffer.
@NOTE: the buffer can reading, but MUST NOT write it.
***********************************************************************/
EXP_API const void* vector_data(vector_t vec);

/**********************************************************************
@FUNCTION: attach a data buffer to vector.
@INPUT: the vector object.
@INPUT: the data buffer.
@RETURN: none.
@NOTE: the data buffer must be attached after vector alloc.
***********************************************************************/
EXP_API void vector_attach(vector_t vec, void* data);

/**********************************************************************
@FUNCTION: detach vector data buffer.
@INPUT the vector object.
@RETURN: the data buffer detached.
@NOTE: the data buffer must be detached before vector free.
***********************************************************************/
EXP_API void* vector_detach(vector_t vec);

/**********************************************************************
@FUNCTION: get vector array size.
@INPUT: the vector object.
@RETURN: the array size.
***********************************************************************/
EXP_API int vector_get_count(vector_t vec);

/**********************************************************************
@FUNCTION: get vector dimensions.
@INPUT: the vector object.
@RETURN: the dimension size.
***********************************************************************/
EXP_API int vector_get_dimen(vector_t vec);

/**********************************************************************
@FUNCTION: set vector element value.
@INPUT: the vector object.
@INPUT: the vector element zero based index.
@INPUT: variant double value to set according to vector dimens.
@RETURN: none.
***********************************************************************/
EXP_API void vector_set_value(vector_t vec, int i, ...);

/**********************************************************************
@FUNCTION: get vector element value.
@INPUT: the vector object.
@INPUT: the vector element zero based index.
@INPUT: variant double value buffer for return more, according to vector dimens.
@RETURN: none.
***********************************************************************/
EXP_API void vector_get_value(vector_t vec, int i, ...);

/**********************************************************************
@FUNCTION: parse vector element value from string.
@INPUT: the vector object.
@INPUT: string token, number separated by space.
@INPUT: length of string token.
@RETURN: none.
***********************************************************************/
EXP_API void vector_parse(vector_t vec, const tchar_t* str, int len);

/**********************************************************************
@FUNCTION: format vector element to string.
@INPUT: the vector object.
@OUTPUT: buffer for formating.
@INPUT: the buffer size in characters, not include terminate character.
@RETURN: the formated string token length.
***********************************************************************/
EXP_API int vector_format(vector_t vec, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: encode vector object to bytes buffer.
@INPUT: the vector object.
@OUTPUT: the bytes buffer.
@INPUT: the buffer size in bytes.
@RETURN: encoded bytes, zero for failed.
@NOTE: buffer can be NULL for testing how many bytes will be encoded.
***********************************************************************/
EXP_API dword_t vector_encode(vector_t vec, byte_t* buf);

/**********************************************************************
@FUNCTION: decode vector object from bytes buffer.
@INPUT: the vector object.
@INPUT: the data buffer.
@RETURN: bytes decoded, zero for failed.
@NOTE: vec can be NULL for testing how many bytes will be decoded.
***********************************************************************/
EXP_API dword_t vector_decode(vector_t vec, const byte_t* buf);

/**********************************************************************
@FUNCTION: set vector all elements value to zero.
@INPUT: the vector struct.
@RETURN: none.
***********************************************************************/
EXP_API void vector_zero(vector_t vec);

/**********************************************************************
@FUNCTION: set vector all elements value to 1.
@INPUT: the vector struct.
@RETURN: none.
***********************************************************************/
EXP_API void vector_unit(vector_t vec);

EXP_API void vector_shift(vector_t dst, vector_t src, ...);

EXP_API void vector_rotate(vector_t dst, vector_t src, double ang);

EXP_API void vector_scale(vector_t dst, vector_t src, ...);

EXP_API void vector_shear(vector_t dst, vector_t src, double sx, double sy);

EXP_API void vector_trans(vector_t dst, vector_t src, matrix_t mt);

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
EXP_API void vector_self_test();
#endif

#ifdef	__cplusplus
}
#endif

#endif /*SET_H*/