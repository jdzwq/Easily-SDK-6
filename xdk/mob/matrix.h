/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc matrix document

	@module	matrix.h | interface file

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

#ifndef _MATRIX_H
#define _MATRIX_H

#include "../xdkdef.h"

#define MATRIX_BITS_PER_COL		(sizeof(double) *８)

#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
@FUNCTION: calc matrix bytes needed.
@INPUT: rows of matrix.
@INPUT: cols of matrix.
@RETURN: the bytes.
@NOTE: use this function to calc and alloc memory or other mapping space,
	then attach it to matrix
***********************************************************************/
EXP_API dword_t matrix_need_size(int rows, int cols);

/**********************************************************************
@FUNCTION: alloc matrix.
@INPUT: rows of matrix.
@INPUT: cols of matrix.
@RETURN: matrix struct.
@NOTE: the matrix data block need to alloc and attach later.
***********************************************************************/
EXP_API matrix_t matrix_alloc(int rows, int cols);

/**********************************************************************
@FUNCTION: free matrix.
@INPUT: the matrix struct.
@RETURN: none.
@NOTE: the matrix data block need to detach first.
***********************************************************************/
EXP_API void matrix_free(matrix_t mat);

/**********************************************************************
@FUNCTION: get matrix data buffer.
@INPUT: the matrix object.
@RETURN: the data buffer if attached, otherwise return NULL.
***********************************************************************/
EXP_API const void* matrix_data(matrix_t mat);

/**********************************************************************
@FUNCTION: attach matrix data buffer.
@INPUT: the matrix object.
@INPUT: the data buffer.
@RETURN: none.
@RETURN: the data buffer bytes must be calced by matrix_need_size.
***********************************************************************/
EXP_API void matrix_attach(matrix_t mat, void* data);

/**********************************************************************
@FUNCTION: detach matrix data buffer.
@INPUT: the matrix object.
@RETURN: the data buffer.
***********************************************************************/
EXP_API void* matrix_detach(matrix_t mat);

/**********************************************************************
@FUNCTION: get the matrix rows.
@INPU: the matrix struct.
@RETURN: rows count.
***********************************************************************/
EXP_API int matrix_get_rows(matrix_t mat);

/**********************************************************************
@FUNCTION: get the matrix cols.
@INPUT: the matrix struct.
@RETURN: cols count.
***********************************************************************/
EXP_API int matrix_get_cols(matrix_t mat);

/**********************************************************************
@FUNCTION: set the matrix elements value to zero.
@INPUT: the matrix struct.
@RETURN: none.
@NOTE: data block must be attached.
***********************************************************************/
EXP_API void matrix_zero(matrix_t mat);

/**********************************************************************
@FUNCTION: set the matrix element value.
@INPUT: the matrix struct.
@INPUT: zero based row index.
@INPUT: zero based col index.
@INPUT: the value to set.
@RETURN: none.
@NOTE: data block must be attached.
***********************************************************************/
EXP_API void matrix_set_value(matrix_t mat, int row, int col, double db);

/**********************************************************************
@FUNCTION: get the matrix element value.
@INPUT: the matrix struct.
@INPUT: zero based row index.
@INPUT: zero based col index.
@RETURN: return the element value if exists.
@NOTE: data block must be attached, and row col index must be valid.
***********************************************************************/
EXP_API double matrix_get_value(matrix_t mat, int row, int col);

/**********************************************************************
@FUNCTION: get the matrix element value in safe way.
@INPUT: the matrix struct.
@INPUT: zero based row index.
@INPUT: zero based col index.
@INPUT: defaule value for return.
@RETURN: return the element value if exists, otherwise default returned.
@NOTE: data block must be attached.
***********************************************************************/
EXP_API double matrix_get_value_safe(matrix_t mat, int row, int col, double def);

/**********************************************************************
@FUNCTION: parse matrix element value from string.
@INPUT: the matrix struct.
@INPUT: string token, number separated by space.
@INPUT: length of string token, -1 for zero-terminated.
@RETURN: none.
@NOTE: parsing according to matrix rows and cols limit, 
	data block size no expand, no shrink.
***********************************************************************/
EXP_API void matrix_parse(matrix_t mat, const tchar_t* str, int len);

/**********************************************************************
@FUNCTION: format matrix element to string.
@INPUT: the matrix struct.
@OUTPUT: buffer for formating.
@INPUT: the buffer size in characters, not include terminate character.
@RETURN: return the formated string token length.
***********************************************************************/
EXP_API int matrix_format(matrix_t mat, tchar_t* buf, int max);

/**********************************************************************
@FUNCTION: encode matrix object to bytes buffer using VER ruler.
@INPUT: the matrix object.
@OUTPUT: the bytes buffer.
@RETURN: bytes encoded, zero for failed.
@NOTE: buffer can be NULL for testing how many bytes will be encoded.
***********************************************************************/
EXP_API dword_t matrix_encode(matrix_t mat, byte_t* buf);

/**********************************************************************
@FUNCTION: decode matrix object from bytes buffer using VER ruler.
@INPUT: the matrix object.
@INPUT: the data buffer.
@RETURN: bytes decoded, zero for failed.
@NOTE: mat can be NULL for testing how many bytes will be decoded.
***********************************************************************/
EXP_API dword_t matrix_decode(matrix_t mat, const byte_t* buf);

/**********************************************************************
@FUNCTION: set the matrix elements value to 1.
@INPUT: the matrix struct.
@RETURN: none.
***********************************************************************/
EXP_API void matrix_unit(matrix_t mat);

/**********************************************************************
@FUNCTION: exchange row/col data from source matrix to destination matrix.
@INPUT: the source and destiation matrix struct.
@RETURN: none.
@NOTE: the destination matrix must be alloced by source cols as rows and
	source rows as cols.
***********************************************************************/
EXP_API void matrix_trans(matrix_t dst, matrix_t src);

/**********************************************************************
@FUNCTION: plus value data from source matrix to destination matrix.
@INPUT: the source and destiation matrix struct.
@RETURN: none.
***********************************************************************/
EXP_API void matrix_plus(matrix_t dst, matrix_t src, double dbl);

/**********************************************************************
@FUNCTION: Md = M1 + M2.
@INPUT: the matrix struct.
@RETURN: none.
***********************************************************************/
EXP_API void matrix_add(matrix_t dst, matrix_t mt1, matrix_t mt2);

/**********************************************************************
@FUNCTION: Md = M1 * M2.
@INPUT: the matrix struct.
@RETURN: none.
***********************************************************************/
EXP_API void matrix_mul(matrix_t dst, matrix_t mt1, matrix_t mt2);

/**********************************************************************
@FUNCTION: det = |M|
@INPUT: the matrix struct.
@RETURN: none.
***********************************************************************/
EXP_API double matrix_det(matrix_t mt);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void matrix_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_MATRIX_H*/