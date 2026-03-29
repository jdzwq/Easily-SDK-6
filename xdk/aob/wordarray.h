/***********************************************************************
	Easily SDK 6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc array object document

	@module	wordarray.h | interface file

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

#ifndef _WORDARRAY_H
#define _WORDARRAY_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

EXP_API sword_t** words_alloc(void);

EXP_API sword_t* words_realloc(sword_t** pp, int count);

/*
@FUNCTION destroy_byte_array: destroy a byte array.
@INPUT sword_t** ptr: the byte array address.
@RETURN void: none.
*/
EXP_API void words_free(sword_t** sa);

/*
@FUNCTION clear_byte_array: delete all byte tokens.
@INPUT sword_t** sa: the byte array address.
@RETURN void: none.
*/
EXP_API void words_clear(sword_t** sa);

/*
@FUNCTION get_byte_array_size: get byte array tokenes.
@INPUT sword_t** sa: the byte array address.
@RETURN short: return the count of byte tokens.
*/
EXP_API int words_size(sword_t** sa);

/*
@FUNCTION get_byte: copy the byte token by index.
@INPUT sword_t** sa: the byte array address.
@INPUT short index: the zero based array index.
@INPUT tchar_t* buf: the byte buf for copying.
@INPUT short max: the size of buffer.
@RETURN short: return characters copyed.
*/
EXP_API sword_t get_words(sword_t** sa, int index);
EXP_API sword_t get_words_safe(sword_t** sa, int index, sword_t def);

EXP_API int words_copy(sword_t** sa, int index, sword_t* buf, int max);

/*
@FUNCTION insert_byte: insert the byte token before the position.
@INPUT sword_t** sa: the byte array address.
@INPUT short index: the zero based array index, -1 indicate insertting at last.
@INPUT const tchar_t* token: the byte token to be inserted.
@INPUT short len: the length of token.
@RETURN void: none.
*/
EXP_API void words_insert(sword_t** sa, int index, const sword_t* pa, int count);

/*
@FUNCTION delete_sword_token: delete the byte token.
@INPUT sword_t** sa: the byte array address.
@INPUT short index: the zero based array index, -1 indicate delete the last token.
@RETURN void: none.
*/
EXP_API void words_delete(sword_t** sa, int index, int count);

EXP_API void words_attach(sword_t** pp, sword_t* p, int len);

EXP_API sword_t* words_detach(sword_t** pp);



#ifdef	__cplusplus
}
#endif

#endif //_WORDARRAY_H
