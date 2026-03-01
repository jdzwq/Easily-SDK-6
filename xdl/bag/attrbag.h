/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc attributes bag document

	@module	attrbag.h | interface file

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

#ifndef _ATTRBAG_H
#define _ATTRBAG_H

#include "../xdldef.h"


#ifdef	__cplusplus
extern "C" {
#endif

EXP_API int split_attributes_title(const tchar_t* str, int len, tchar_t* buf, int max);

EXP_API bool_t dom_node_parse_attributes(link_t_ptr nlk, const tchar_t* str, int len);

EXP_API int dom_node_format_attributes(link_t_ptr nlk, tchar_t* buf, int len);

#ifdef	__cplusplus
}
#endif


#endif //_ATTRBAG_H