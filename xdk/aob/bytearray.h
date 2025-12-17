/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc bytes buffer document

	@module	varbytes.h | interface file

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

#ifndef _BYTEARRAY_H
#define _BYTEARRAY_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION alloc_byte_array: create a byte array.
@RETURN byte_t**: return the byte array address.
*/
EXP_API byte_t** bytes_alloc(void);

EXP_API byte_t* bytes_realloc(byte_t** pp, int count);

/*
@FUNCTION destroy_byte_array: destroy a byte array.
@INPUT byte_t** ptr: the byte array address.
@RETURN void: none.
*/
EXP_API void bytes_free(byte_t** sa);

/*
@FUNCTION clear_byte_array: delete all byte tokens.
@INPUT byte_t** sa: the byte array address.
@RETURN void: none.
*/
EXP_API void bytes_clear(byte_t** sa);

/*
@FUNCTION get_byte_array_size: get byte array tokenes.
@INPUT byte_t** sa: the byte array address.
@RETURN short: return the count of byte tokens.
*/
EXP_API int bytes_size(byte_t** sa);

/*
@FUNCTION get_byte: copy the byte token by index.
@INPUT byte_t** sa: the byte array address.
@INPUT short index: the zero based array index.
@INPUT tchar_t* buf: the byte buf for copying.
@INPUT short max: the size of buffer.
@RETURN short: return characters copyed.
*/
EXP_API byte_t bytes_byte(byte_t** sa, int index);

EXP_API int bytes_copy(byte_t** sa, int index, byte_t* buf, int max);

/*
@FUNCTION insert_byte: insert the byte token before the position.
@INPUT byte_t** sa: the byte array address.
@INPUT short index: the zero based array index, -1 indicate insertting at last.
@INPUT const tchar_t* token: the byte token to be inserted.
@INPUT short len: the length of token.
@RETURN void: none.
*/
EXP_API void bytes_insert(byte_t** sa, int index, const byte_t* pa, int count);

/*
@FUNCTION delete_byte_token: delete the byte token.
@INPUT byte_t** sa: the byte array address.
@INPUT short index: the zero based array index, -1 indicate delete the last token.
@RETURN void: none.
*/
EXP_API void bytes_delete(byte_t** sa, int index, int count);

EXP_API void bytes_attach(byte_t** pp, byte_t* p, int len);

EXP_API byte_t* bytes_detach(byte_t** pp);

#ifdef	__cplusplus
}
#endif

#endif /*_BYTEARRAY_H*/