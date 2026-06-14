/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc designer document

	@module	designer.h | interface file

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

#ifndef _DESIGNER_H
#define _DESIGNER_H

#include "../xdcdef.h"

typedef enum{
	HINT_NONE,
	HINT_OBJECT,
	HINT_GROUP,
	HINT_VERT_SPLIT,
	HINT_HORZ_SPLIT,
	HINT_CROSS_SPLIT,
}DESIGNER_HINT_CODE;

typedef enum{
	NC_OBJECT_DRAG = 101,
	NC_OBJECT_DROP = 102,
	NC_OBJECT_SIZING = 103,
	NC_OBJECT_SIZED = 104,
	NC_OBJECT_SELECTED = 105,
	NC_OBJECT_UNSELECT = 106,
	NC_OBJECT_CHANGING = 107,
	NC_OBJECT_CHANGED = 108,
	NC_OBJECT_LBCLICK = 109,
	NC_OBJECT_DBCLICK = 110,
	NC_OBJECT_RBCLICK = 111
}DESIGNER_NOTI_CODE;

typedef struct _NOTICE_DESIGNER{
	widget_t widget;
	unsigned int id;
	unsigned int code;
	
	void* object;
	vword_t data;

	int ret;
}NOTICE_DESIGNER;

LOC_API int designer_sub_lbutton_down(widget_t widget, const xpoint_t* pxp, uid_t sid, vword_t delta);

LOC_API int designer_sub_lbutton_up(widget_t widget, const xpoint_t* pxp, uid_t sid, vword_t delta);

LOC_API int designer_sub_lbutton_dbclick(widget_t widget, const xpoint_t* pxp, uid_t sid, vword_t delta);

LOC_API int designer_sub_mousemove(widget_t widget, dword_t mk, const xpoint_t* ppt, uid_t sid, vword_t delta);

LOC_API int designer_sub_keydown(widget_t widget, dword_t ks, int nKey, uid_t sid, vword_t delta);

LOC_API int designer_sub_paint(widget_t widget, visual_t dc, const xrect_t* pxr, uid_t sid, vword_t delta);


#ifdef	__cplusplus
extern "C" {
#endif

EXP_API void hand_designer_create(widget_t widget, const designer_interface* pdi);

EXP_API void hand_designer_destroy(widget_t widget);

EXP_API bool_t designer_get_dirty(widget_t widget);

EXP_API void designer_set_dirty(widget_t widget, bool_t b_dirty);

EXP_API void* designer_get_focused(widget_t widget);

EXP_API bool_t designer_set_focused(widget_t widget, void* obj);

#ifdef	__cplusplus
}
#endif

#endif /**/
