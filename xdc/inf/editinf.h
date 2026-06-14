/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc design document

	@module	editinf.h | editor interface file

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

#ifndef _EDITINF_H
#define _EDITINF_H

#include "../xdcdef.h"

typedef bool_t(*EDIT_GET_FOCUS_INFO)(widget_t wt, tchar_t* edtior, tchar_t* styles);
typedef void(*EDIT_GET_FOCUS_RECT)(widget_t wt, xrect_t* pxr);
typedef void*(*EDIT_GET_FOCUS_DATA)(widget_t wt);
typedef bool_t(*EDIT_SET_FOCUS_DATA)(widget_t wt, void* data);
typedef bool_t(*EDIT_GET_FOCUS_AUTO)(widget_t wt);
typedef bool_t(*EDIT_GET_FOCUS_CANBE)(widget_t wt);
typedef void(*EDIT_SET_FOCUS_DIRTY)(widget_t wt);
typedef int(*EDIT_SET_FOCUS_NOTI)(widget_t wt, int cmd, void* data);

typedef struct _editor_interface{
	bool_t with_char;

	EDIT_GET_FOCUS_INFO 	pf_get_obj_info;
	EDIT_GET_FOCUS_RECT 	pf_get_obj_rect;
	EDIT_GET_FOCUS_DATA		pf_get_obj_data;
	EDIT_SET_FOCUS_DATA		pf_set_obj_data;
	EDIT_GET_FOCUS_AUTO		pf_get_obj_auto;
	EDIT_GET_FOCUS_CANBE	pf_get_obj_canbe;
	EDIT_SET_FOCUS_DIRTY	pf_set_obj_dirty;
	EDIT_SET_FOCUS_NOTI		pf_set_obj_noti;
}editor_interface;

#ifdef	__cplusplus
extern "C" {
#endif

EXP_API editor_interface edit_formctrl;

EXP_API editor_interface edit_gridctrl;

EXP_API editor_interface edit_imagesctrl;

EXP_API editor_interface edit_listctrl;

EXP_API editor_interface edit_properctrl;

EXP_API editor_interface edit_statisctrl;

EXP_API editor_interface edit_tablectrl;

EXP_API editor_interface edit_treectrl;

#ifdef	__cplusplus
}
#endif


#endif /*_EDITINF_H*/