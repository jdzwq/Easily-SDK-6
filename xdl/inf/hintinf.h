﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc view hintner document

	@module	hintner.h | interface file

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

#ifndef _HINTINF_H
#define _HINTINF_H

typedef enum{
	HINT_NONE,
	HINT_OBJECT,
	HINT_GROUP,
	HINT_VERT_SPLIT,
	HINT_HORZ_SPLIT,
	HINT_CROSS_SPLIT,
	HINT_DRAG_CORNER
}HINT_CODE;


typedef enum{
	_HINTNER_OPERA_STOP = 0,
	_HINTNER_OPERA_NEXT = 1
}HINTNER_OPERA;

typedef enum{
	_HINTNER_STATE_FULL = 0,
	_HINTNER_STATE_ITEM = 1,
	_HINTNER_STATE_NONE = -1,
}HINTNER_STATE;

typedef int(*PF_HINT_DESIGNER_CALLBACK)(int state, link_t_ptr xlk, link_t_ptr ylk, xrect_t* pxr, bool_t focus, bool_t drag, bool_t sizew, bool_t sizeh, void* pp);


typedef void(*PF_HINT_NEXT_ITEM)(void* param, link_t_ptr* p_xlk, link_t_ptr* p_ylk, xrect_t* p_rect, bool_t* p_focus, bool_t* p_drag, bool_t* p_sizew, bool_t* p_sizeh);
typedef void(*PF_HINT_CUR_ITEM)(void* param, link_t_ptr* p_xlk, link_t_ptr* p_ylk);

typedef struct _if_itemhint_t{
	PF_HINT_NEXT_ITEM	pf_next_item;
	PF_HINT_CUR_ITEM	pf_cur_item;
	void* param;
}if_itemhint_t;


#endif /*HINTINF_H*/