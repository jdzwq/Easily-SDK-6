/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc Aho-Corasick automaton document

	@module	actable.h | interface file

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

#ifndef _ACTABLE_H
#define _ACTABLE_H

#include "../xdkdef.h"

typedef bool_t(CALLBACK *PF_ENUM_AC_TABLE)(const tchar_t* key, int len, vword_t delta, void* p);

#ifdef	__cplusplus
extern "C" {
#endif

/***********************************************************************
@FUNCTION: create ac-table.
@RETURN: the link component of ac-table or NULL if failed.
***********************************************************************/
EXP_API link_t_ptr create_ac_table(void);

/***********************************************************************
@FUNCTION: destroy ac-table.
@INPUT: the link component of actable.
@RETURN: none.
***********************************************************************/
EXP_API void destroy_ac_table(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: insert a pair of key-value into ac-table.
@INPUT: the link component of ac-table.
@INPUT: the key name.
@INPUT: the key name characters or -1 indicate zero terminated.
@INPUT: the key value.
@RETURN: none.
@NOTE: if the key name exists in ac-table then the value to be replaced,
	otherwise new key-value to be added.
***********************************************************************/
EXP_API void insert_ac_table(link_t_ptr ptr, const tchar_t* key, int len, vword_t val);

/***********************************************************************
@FUNCTION: build failure transfer table of the ac-table.
@INPUT: the link component of actable.
@RETURN: none.
***********************************************************************/
EXP_API void build_ac_table(link_t_ptr ptr);

/***********************************************************************
@FUNCTION: find the key-value pair in ac-table.
@INPUT: the link component of ac-table.
@INPUT: the key name.
@INPUT: the key name characters or -1 indicate zero terminated.
@RETURN: value of the key or zero if not find.
***********************************************************************/
EXP_API vword_t find_ac_table(link_t_ptr ptr, const tchar_t* key, int len);

/***********************************************************************
@FUNCTION: enumerate the key-value pairs in ac-table.
@INPUT: the link component of ac-table.
@INPUT: the callback function for getting one key-value per called.
@INPUT: the user-parameter trans back to callback function.
@RETURN: none.
@NOTE: return non-zero in callback function will break the enumerating.
***********************************************************************/
EXP_API void enum_ac_table(link_t_ptr ptr, PF_ENUM_AC_TABLE pf, void* pa);

#if defined (DEBUG) || defined (_DEBUG)
EXP_API void ac_table_self_test(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_ACTABLE_H*/
