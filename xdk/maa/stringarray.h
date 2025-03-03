﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc stringarray document

	@module	stringarray.h | interface file

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

#ifndef _STRARRAY_H
#define _STRARRAY_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION alloc_string_array: create a string array.
@RETURN tchar_t**: return the string array address.
*/
EXP_API tchar_t** alloc_string_array(void);

/*
@FUNCTION destroy_string_array: destroy a string array.
@INPUT tchar_t** ptr: the string array address.
@RETURN void: none.
*/
EXP_API void free_string_array(tchar_t** sa);

/*
@FUNCTION clear_string_array: delete all string tokens.
@INPUT tchar_t** sa: the string array address.
@RETURN void: none.
*/
EXP_API void clear_string_array(tchar_t** sa);

/*
@FUNCTION get_string_array_size: get string array tokenes.
@INPUT tchar_t** sa: the string array address.
@RETURN int: return the count of string tokens.
*/
EXP_API int get_string_array_size(tchar_t** sa);

/*
@FUNCTION get_string_ptr: get string token value string pointer.
@INPUT tchar_t** sa: the string array address.
@INPUT int index: the zero based array index.
@RETURN const tchar_t*: return token value string pointer if exists, otherwise return NULL.
*/
EXP_API const tchar_t* get_string_ptr(tchar_t** sa, int index);

/*
@FUNCTION get_string: copy the string token by index.
@INPUT tchar_t** sa: the string array address.
@INPUT int index: the zero based array index.
@INPUT tchar_t* buf: the string buf for copying.
@INPUT int max: the size of buffer.
@RETURN int: return characters copyed.
*/
EXP_API int get_string(tchar_t** sa, int index, tchar_t* buf, int max);

/*
@FUNCTION insert_string: insert the string token before the position.
@INPUT tchar_t** sa: the string array address.
@INPUT int index: the zero based array index, -1 indicate insertting at last.
@INPUT const tchar_t* token: the string token to be inserted.
@INPUT int len: the length of token.
@RETURN void: none.
*/
EXP_API void insert_string(tchar_t** sa, int index, const tchar_t* token, int len);

/*
@FUNCTION delete_string: delete the string token.
@INPUT tchar_t** sa: the string array address.
@INPUT int index: the zero based array index, -1 indicate delete the last token.
@RETURN void: none.
*/
EXP_API void delete_string(tchar_t** sa, int index);

#if defined(_DEBUG) || defined(DEBUG)

EXP_API void test_string_array(void);

#endif

#ifdef	__cplusplus
}
#endif

#endif //_STRARRAY_H
