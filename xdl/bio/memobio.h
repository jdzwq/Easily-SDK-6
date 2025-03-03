﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc memo bio document

	@module	memobio.h | interface file

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

#ifndef _MEMOBIO_H
#define _MEMOBIO_H

#include "../xdldef.h"


#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION format_memo_doc: format the memo document to string buffer.
@INPUT link_t_ptr ptr: the memo link component.
@OUTPUT tchar_t* buf: the string buffer.
@INPUT int max: the string buffer size in characters.
@RETURN int: return the characters formated.
*/
EXP_API int format_memo_doc(link_t_ptr ptr, tchar_t* buf, int max);

/*
@FUNCTION parse_memo_doc: parse the memo document from string buffer.
@INPUT link_t_ptr ptr: the memo link component.
@INPUT const tchar_t* buf: the string buffer.
@INPUT int len: the string buffer size in characters.
@RETURN int: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t parse_memo_doc(link_t_ptr ptr, const tchar_t* buf, int len);

EXP_API bool_t format_memo_doc_to_stream(link_t_ptr ptr, stream_t stm);

EXP_API bool_t parse_memo_doc_from_stream(link_t_ptr ptr, stream_t stm);

#ifdef	__cplusplus
}
#endif


#endif /*MEMOBIO_H*/