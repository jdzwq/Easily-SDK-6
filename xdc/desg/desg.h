/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc design document

	@module	desg.h | interface file

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

#ifndef _DESG_H
#define _DESG_H

#include "../xdcdef.h"

typedef void(*PF_GET_POINT_SCALE)(widget_t wt, int* pcx, int* pcy);

typedef void(*PF_GET_OBJECT_POINT)(widget_t wt, void* obj, xpoint_t* ppt);
typedef bool_t(*PF_SET_OBJECT_POINT)(widget_t wt, void* obj, const xpoint_t* ppt);
typedef void(*PF_GET_OBJECT_SIZE)(widget_t wt, void* obj, xsize_t* pxs);
typedef bool_t(*PF_SET_OBJECT_SIZE)(widget_t wt, void* obj, const xsize_t* pxs);
typedef void(*PF_GET_OBJECT_RECT)(widget_t wt, void* obj, xrect_t* pxr);
typedef bool_t(*PF_SET_OBJECT_RECT)(widget_t wt, void* obj, const xrect_t* pxr);
typedef int(*PF_GET_OBJECT_ATTRS)(widget_t wt, void* obj, tchar_t* buf, int max);
typedef bool_t(*PF_SET_OBJECT_ATTRS)(widget_t wt, void* obj, const tchar_t* buf, int len);

typedef bool_t(*PF_DEL_OBJECT)(widget_t wt, void* obj);
typedef void*(*PF_INS_OBJECT)(widget_t wt, const tchar_t* attrs, int len);
typedef bool_t(*PF_GET_OBJECT_SELECTED)(widget_t wt, void* obj);
typedef void(*PF_SET_OBJECT_SELECTED)(widget_t wt, void* obj, bool_t b);
typedef void(*PF_ALL_OBJECT_SELECTED)(widget_t wt, bool_t b);

typedef void*(*PF_GET_NEXT_GROP)(widget_t wt, void* grp);
typedef void*(*PF_GET_NEXT_OBJECT)(widget_t wt, void* grp, void* obj);

typedef dword_t(*PF_RETRIVE_DOCUMENT)(widget_t wt, byte_t* buf, dword_t max);
typedef bool_t(*PF_RESTORE_DOCUMENT)(widget_t wt, const byte_t* buf, dword_t len);
typedef void(*PF_RENDER_DOCUMENT)(widget_t wt, drawing_interface* pci);

#define WITH_SIZE_WIDTH		0x00000001
#define WITH_SIZE_HEIGHT	0x00000002
#define WITH_DRAG_FOCUSED	0x00000010
#define WITH_DRAG_SELECTED	0x00000020
#define WITH_MOUSE_GROUPED	0x00000100

typedef struct _designer_interface{
	bool_t with_ruler;
	dword_t with_opera;
	
	PF_GET_POINT_SCALE pf_get_point_scale;
	
	PF_GET_OBJECT_POINT pf_get_obj_point;
	PF_SET_OBJECT_POINT pf_set_obj_point;
	PF_GET_OBJECT_SIZE	pf_get_obj_size;
	PF_SET_OBJECT_SIZE pf_set_obj_size;
	PF_GET_OBJECT_RECT	pf_get_obj_rect;
	PF_SET_OBJECT_RECT pf_set_obj_rect;

	PF_GET_OBJECT_ATTRS pf_get_obj_attrs;
	PF_SET_OBJECT_ATTRS pf_set_obj_attrs;

	PF_GET_OBJECT_SELECTED pf_get_obj_selected;
	PF_SET_OBJECT_SELECTED pf_set_obj_selected;
	PF_ALL_OBJECT_SELECTED pf_all_obj_selected;

	PF_GET_NEXT_GROP pf_get_next_grp;
	PF_GET_NEXT_OBJECT pf_get_next_obj;

	PF_INS_OBJECT	pf_ins_obj;
	PF_DEL_OBJECT	pf_del_obj;

	PF_RETRIVE_DOCUMENT	pf_retrive_doc;
	PF_RESTORE_DOCUMENT	pf_restore_doc;
	PF_RENDER_DOCUMENT pf_render_doc;
}designer_interface;

#ifdef	__cplusplus
extern "C" {
#endif


EXP_API designer_interface desg_formctrl;

EXP_API designer_interface desg_diagramctrl;

EXP_API designer_interface desg_dialogctrl;

EXP_API designer_interface desg_gridctrl;

EXP_API designer_interface desg_statisctrl;

EXP_API designer_interface desg_topogctrl;

#ifdef	__cplusplus
}
#endif


#endif /*_DESG_H*/