/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc designer document

	@module	dialogdesg.c | implement file

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

#include "../inf/desginf.h"

#include "../xdcobj.h"


#define DIALOG_LINE_FEED		(float)50
#define DIALOG_ENTITY_MIN_WIDTH	(float)10
#define DIALOG_ENTITY_MIN_HEIGHT	(float)10

/***********************************************interface********************************************************/

static void _dialogctrl_get_point_scale(widget_t wt, int* pcx, int* pcy)
{
	*pcx = *pcy = 1;
}

static void _dialogctrl_get_object_point(widget_t wt, void* obj, xpoint_t* ppt)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_dialog_item(dialog, ilk))
	{
		ppt->fx = get_dialog_item_x(ilk);
		ppt->fy = get_dialog_item_y(ilk);

		widget_point_to_pt(wt, ppt);
	}
}

static bool_t _dialogctrl_set_object_point(widget_t wt, void* obj, const xpoint_t* ppt)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;
	xpoint_t pt;

	pt.x = ppt->x;
	pt.y = ppt->y;

	widget_point_to_mm(wt, &pt);

	if (is_dialog_item(dialog, ilk))
	{
		set_dialog_item_x(ilk, pt.fx);
		set_dialog_item_y(ilk, pt.fy);

		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void _dialogctrl_get_object_size(widget_t wt, void* obj, xsize_t* pxs)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_dialog_item(dialog, ilk))
	{
		pxs->fw = get_dialog_item_width(ilk);
		pxs->fh = get_dialog_item_height(ilk);

		widget_size_to_pt(wt, pxs);
	}
}

static bool_t _dialogctrl_set_object_size(widget_t wt, void* obj, const xsize_t* pxs)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;
	xsize_t xs;

	xs.w = pxs->w;
	xs.h = pxs->h;

	widget_size_to_mm(wt, &xs);

	if (is_dialog_item(dialog, ilk))
	{
		set_dialog_item_width(ilk, xs.fw);
		set_dialog_item_height(ilk, xs.fh);

		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void _dialogctrl_get_object_rect(widget_t wt, void* obj, xrect_t* pxr)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_dialog_item(dialog, ilk))
	{
		pxr->fx = get_dialog_item_x(ilk);
		pxr->fy = get_dialog_item_y(ilk);
		pxr->fw = get_dialog_item_width(ilk);
		pxr->fh = get_dialog_item_height(ilk);

		widget_rect_to_pt(wt, pxr);
	}
}

static bool_t _dialogctrl_set_object_rect(widget_t wt, void* obj, const xrect_t* pxr)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;
	xrect_t xr;

	xr.x = pxr->x;
	xr.y = pxr->y;
	xr.w = pxr->w;
	xr.h = pxr->h;

	widget_rect_to_mm(wt, &xr);

	if (is_dialog_item(dialog, ilk))
	{
		set_dialog_item_x(ilk, xr.fx);
		set_dialog_item_y(ilk, xr.fy);
		set_dialog_item_width(ilk, xr.fw);
		set_dialog_item_height(ilk, xr.fh);

		return bool_true;
	}else
	{
		return bool_false;
	}
}

static int _dialogctrl_get_object_attrs(widget_t wt, void* obj, tchar_t* buf, int max)
{
	return dom_node_format_attributes((link_t_ptr)obj, buf, max);
}

static bool_t _dialogctrl_set_object_attrs(widget_t wt, void* obj, const tchar_t* buf, int len)
{
	tchar_t token[KEY_LEN] = {0};

	split_attributes_title(buf, len, token, KEY_LEN);

	if(!is_dialog_item_class(token)) return bool_false;

	dom_node_parse_attributes((link_t_ptr)obj, buf, len);

	return bool_true;
}

static bool_t _dialogctrl_delete_object(widget_t wt, void* obj)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_dialog_item(dialog, ilk))
	{
		delete_dialog_item(ilk);
		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void* _dialogctrl_insert_object(widget_t wt, const tchar_t* attrs, int len)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	tchar_t type[KEY_LEN] = {0};
	int klen;
	link_t_ptr ilk;

	klen = split_attributes_title(attrs, len, type, KEY_LEN);
	if(!is_dialog_item_class(type)) return NULL;
	
	ilk = insert_dialog_item(dialog, type);

	if(ilk)
	{
		dom_node_parse_attributes(ilk, attrs, len);
	}

	return (void*)ilk;
}

static bool_t _dialogctrl_get_object_selected(widget_t wt, void* obj)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_dialog_item(dialog, ilk))
		return get_dialog_item_selected(ilk);
	else
		return bool_false;
}

static void _dialogctrl_set_object_selected(widget_t wt, void* obj, bool_t b)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_dialog_item(dialog, ilk))
	{
		set_dialog_item_selected(ilk, b);
	}
}

static void _dialogctrl_all_object_selected(widget_t wt, bool_t b)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	link_t_ptr ilk;

	ilk = get_dialog_next_item(dialog, LINK_FIRST);
	while(ilk)
	{
		set_dialog_item_selected(ilk, b);
		ilk = get_dialog_next_item(dialog, ilk);
	}
}

static void* _dialogctrl_get_next_group(widget_t wt, void* grp)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);

	return (grp == LINK_FIRST)? (void*)dialog : NULL;
}

static void* _dialogctrl_get_next_object(widget_t wt, void* grp, void* obj)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	return (grp == dialog)? (void*)get_dialog_next_item(dialog, ilk) : NULL;
}

static dword_t _dialogctrl_retrive_document(widget_t wt, byte_t* buf, dword_t max)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);

#ifdef _UNICODE
	return format_dom_doc_to_bytes(dialog, buf, max, DEF_UCS);
#else
	return format_dom_doc_to_bytes(dialog, buf, max, DEF_MBS);
#endif
}

static bool_t _dialogctrl_restore_document(widget_t wt, const byte_t* buf, dword_t len)
{
	link_t_ptr dialog = dialogctrl_detach(wt);
	bool_t b;

#ifdef _UNICODE
	b = parse_dom_doc_from_bytes(dialog, buf, len, DEF_UCS);
#else
	b = parse_dom_doc_from_bytes(dialog, buf, len, DEF_MBS);
#endif

	dialogctrl_attach(wt, dialog);

	return b;
}

static void _dialogctrl_render_document(widget_t wt, drawing_interface* pci)
{
	link_t_ptr dialog = dialogctrl_fetch(wt);

	draw_dialog(pci, dialog);
}

/////////////////////////////////////////////////////////////////////////////////////

designer_interface desg_dialogctrl = {
	.with_ruler = bool_false,
	.with_opera = WITH_SIZE_WIDTH | WITH_SIZE_HEIGHT | WITH_DRAG_FOCUSED | WITH_DRAG_SELECTED | WITH_MOUSE_GROUPED,

	.pf_get_point_scale = _dialogctrl_get_point_scale,
	
	.pf_get_obj_point = _dialogctrl_get_object_point,
	.pf_set_obj_point = _dialogctrl_set_object_point,
	.pf_get_obj_size = _dialogctrl_get_object_size,
	.pf_set_obj_size = _dialogctrl_set_object_size,
	.pf_get_obj_rect = _dialogctrl_get_object_rect,
	.pf_set_obj_rect = _dialogctrl_set_object_rect,

	.pf_get_obj_attrs = _dialogctrl_get_object_attrs,
	.pf_set_obj_attrs = _dialogctrl_set_object_attrs,

	.pf_get_obj_selected = _dialogctrl_get_object_selected,
	.pf_set_obj_selected = _dialogctrl_set_object_selected,
	.pf_all_obj_selected = _dialogctrl_all_object_selected,

	.pf_get_next_grp = _dialogctrl_get_next_group,
	.pf_get_next_obj = _dialogctrl_get_next_object,

	.pf_ins_obj = _dialogctrl_insert_object,
	.pf_del_obj = _dialogctrl_delete_object,

	.pf_retrive_doc = _dialogctrl_retrive_document,
	.pf_restore_doc = _dialogctrl_restore_document,
	.pf_render_doc = _dialogctrl_render_document
};

