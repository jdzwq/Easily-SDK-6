/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc variant string document

	@module	string.h | interface file

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

#ifndef _VARSTR_H
#define _VARSTR_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
@FUNCTION: alloc a empty string object.
@RETURN: string object.
***********************************************************************/
EXP_API string_t string_alloc(void);

/**********************************************************************
@FUNCTION: free a string object.
@INPUT: the string object.
@RETURN: none.
***********************************************************************/
EXP_API void string_free(string_t vs);

/**********************************************************************
@FUNCTION: attach outer characters buffer to string.
@INPUT: the string object.
@INPUT: the characters buffer.
@RETURN: none.
***********************************************************************/
EXP_API void string_attach(string_t vs, tchar_t* data);

/**********************************************************************
@FUNCTION: detach string characters buffer.
@INPUT: the string object.
@RETURN: the characters buffer.
***********************************************************************/
EXP_API tchar_t* string_detach(string_t vs);

/**********************************************************************
@FUNCTION: increase string object buffer size.
@INPUT: the string object.
@INPUT: length in characters to increased.
@RETURN: none.
***********************************************************************/
EXP_API void string_incre(string_t vs, int len);

/**********************************************************************
@FUNCTION: cat a string token to string object.
@INPUT: the string object.
@INPUT: the string token.
@INPUT: length in characters of string token.
@RETURN: now string length in characters after catting.
***********************************************************************/
EXP_API int	string_cat(string_t vs, const tchar_t* str, int len);

/**********************************************************************
@FUNCTION: copy a string token to string object.
@INPUT: the string object.
@INPUT: the string token.
@INPUT: length in characters of string token.
@RETURN: now string length in characters after copying.
***********************************************************************/
EXP_API int	string_cpy(string_t vs, const tchar_t* str, int len);

/**********************************************************************
@FUNCTION: fill string object using printf.
@INPUT: the string object.
@INPUT: the format token.
@INPUT: some variable parameters.
@RETURN: now string length in characters after filling.
***********************************************************************/
EXP_API int string_printf(string_t vs, const tchar_t* fmt, ...);

/**********************************************************************
@FUNCTION: append token to string object using printf.
@INPUT: the string object.
@INPUT: the format token.
@INPUT: some variable parameters.
@RETURN: now string length in characters after appending.
***********************************************************************/
EXP_API int string_append(string_t vs, const tchar_t* fmt, ...);

/**********************************************************************
@FUNCTION: get string object inner buffer.
@INPUT: the string object.
@RETURN: inner string buffer.
@NOTE: the buffer can used for reading, but must not write it.
***********************************************************************/
EXP_API const tchar_t* string_ptr(string_t vs);

/**********************************************************************
@FUNCTION: get string length of the string object.
@INPUT: the string object.
@RETURN: length in characters.
***********************************************************************/
EXP_API int string_len(string_t vs);

/**********************************************************************
@FUNCTION: empty string object.
@INPUT: the string object.
@RETURN: none.
***********************************************************************/
EXP_API void string_empty(string_t vs);

/**********************************************************************
@FUNCTION: test string object is empty.
@INPUT: the string object.
@RETURN: nonezero for empty string object, otherwise return zero.
***********************************************************************/
EXP_API bool_t string_is_empty(string_t vs);

/**********************************************************************
@FUNCTION: clone a new string object.
@INPUT: the string object.
@RETURN: the new string object cloned.
***********************************************************************/
EXP_API string_t string_clone(string_t vs);

/**********************************************************************
@FUNCTION: resize string inner buffer size.
@INPUT: the string object.
@INPUT: the new size in characters.
@RETURN: the string inner buffer size.
@NOTE: the inner buffer size not always equal to string token length.
***********************************************************************/
EXP_API int string_resize(string_t vs, int len);

/**********************************************************************
@FUNCTION: ensure string inner buffer size matching the need, then return the buffer fro operating. 
@INPUT: the string object.
@INPUT: the need buffer size in characters, not include terminate character.
@RETURN: inner buffer.
@NOTE: expose the inner buffer for direct writing.
***********************************************************************/
EXP_API tchar_t* string_ensure_buf(string_t vs, int len);

/**********************************************************************
@FUNCTION: get a character at position of the string object.
@INPUT: the string object.
@INPUT: the zero based position.
@RETURN: the character if position in inner length range, otherwise return zero.
***********************************************************************/
EXP_API tchar_t string_get_char(string_t vs, int pos);

/**********************************************************************
@FUNCTION: set a character at position of the string object.
@INPUT: the string object.
@INPUT: the zero based position.
@INPUT: the character to set.
@RETURN: if position in inner length range return nonzero, otherwise return zero.
***********************************************************************/
EXP_API bool_t string_set_char(string_t vs, int pos, tchar_t ch);

/**********************************************************************
@FUNCTION: get some characters from the position in string object.
@INPUT: the string object.
@INPUT: the zero based start position.
@OUTPUT: the characters buffer.
@INPUT: the characters need to read.
@RETURN: the characters copyed.
***********************************************************************/
EXP_API int string_get_chars(string_t vs, int pos, tchar_t* pch, int n);

/**********************************************************************
@FUNCTION: set some characters from the position in string object.
@INPUT: the string object.
@INPUT: the zero based start position.
@INPUT: the string token.
@INPUT: the characters need to write.
@RETURN: none.
@NOTE: the string inner buffer may be expanded.
***********************************************************************/
EXP_API void string_set_chars(string_t vs, int pos, const tchar_t* pch, int n);

/**********************************************************************
@FUNCTION: insert some characters from the position in string object.
@INPUT: the string object.
@INPUT: the zero based start position.
@INPUT: the string token.
@INPUT: the characters need to insert.
@RETURN: none.
@NOTE: the string inner buffer may be expanded.
***********************************************************************/
EXP_API void string_ins_chars(string_t vs, int pos, const tchar_t* pch, int n);

/**********************************************************************
@FUNCTION: delete some characters from the position in string object.
@INPUT: the string object.
@INPUT: the zero based start position.
@INPUT: the characters need to delete.
@RETURN: none.
@NOTE: the string inner buffer may be truncted.
***********************************************************************/
EXP_API void string_del_chars(string_t vs, int pos, int n);

/**********************************************************************
@FUNCTION: encode string object to bytes sequence.
@INPUT: the string object.
@INPUT: the encode type, eg: _GB2312, _UTF8_BOM, _UTF16LIT, _UTF16BIG.
@INPUT: the bytes buffer for encoding.
@RETURN: bytes encoded, zero for failed.
@NOTE: buffer can be NULL for testing how many bytes will be encoded.
***********************************************************************/
EXP_API dword_t string_encode(string_t vs, int encode, byte_t* buf, dword_t max);

/**********************************************************************
@FUNCTION: decode string object from bytes sequence.
@INPUT: the string object.
@INPUT: the encode type, eg: _GB2312, _UTF8_BOM, _UTF16LIT, _UTF16BIG.
@INPUT: the bytes sequence for decoding.
@RETURN: bytes decoded, zero for failed.
@NOTE: vs can be NULL for testing how many bytes will be decoded.
***********************************************************************/
EXP_API int string_decode(string_t vs, int encode, const byte_t* buf, dword_t size);


#ifdef	__cplusplus
}
#endif

#endif /*STRING_H*/
