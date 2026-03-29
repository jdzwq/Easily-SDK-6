/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc designer document

	@module	topogdesg.c | implement file

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

#include "desg.h"

#include "../xdcobj.h"


/***********************************************interface********************************************************/

static void _topogctrl_get_point_scale(widget_t wt, int* pcx, int* pcy)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	xsize_t xs;

	xs.fw = get_topog_rx(topog);
	xs.fh = get_topog_ry(topog);

	widget_size_to_pt(wt, &xs);

	*pcx = xs.w;
	*pcy = xs.h;
}

static void _topogctrl_get_object_point(widget_t wt, void* obj, xpoint_t* ppt)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;
	xrect_t xr = {0};

	if (is_topog_spot(topog, ilk))
	{
		calc_topog_spot_rect(topog, ilk, &xr);
		ppt->fx = xr.fx;
		ppt->fy = xr.fy;

		widget_point_to_pt(wt, ppt);
	}
}

static bool_t _topogctrl_set_object_point(widget_t wt, void* obj, const xpoint_t* ppt)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;
	xpoint_t pt;
	int row, col;

	pt.x = ppt->x;
	pt.y = ppt->y;

	widget_point_to_mm(wt, &pt);

	if (is_topog_spot(topog, ilk))
	{
		col = (int)(pt.fx / get_topog_rx(topog));
		row = (int)(pt.fy / get_topog_ry(topog));

		if (col < 0 || row < 0)
			return bool_false;

		if (col >= get_topog_cols(topog) || row >= get_topog_rows(topog))
			return bool_false;

		if(col == get_topog_spot_col(ilk) && row == get_topog_spot_row(ilk))
			return bool_false;

		set_topog_spot_row(ilk, row);
		set_topog_spot_col(ilk, col);

		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void _topogctrl_get_object_size(widget_t wt, void* obj, xsize_t* pxs)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;
	xrect_t xr = {0};

	if (is_topog_spot(topog, ilk))
	{
		calc_topog_spot_rect(topog, ilk, &xr);
		pxs->fw = xr.fw;
		pxs->fh = xr.fh;

		widget_size_to_pt(wt, pxs);
	}
}

static bool_t _topogctrl_set_object_size(widget_t wt, void* obj, const xsize_t* pxs)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;
	
	return bool_false;
}

static void _topogctrl_get_object_rect(widget_t wt, void* obj, xrect_t* pxr)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_topog_spot(topog, ilk))
	{
		calc_topog_spot_rect(topog, ilk, pxr);
		
		widget_rect_to_pt(wt, pxr);
	}
}

static bool_t _topogctrl_set_object_rect(widget_t wt, void* obj, const xrect_t* pxr)
{
	link_t_ptr topog = topogctrl_fetch(wt);

	return _topogctrl_set_object_point(wt, obj, RECTPOINT(pxr));
}

static int _topogctrl_get_object_attrs(widget_t wt, void* obj, tchar_t* buf, int max)
{
	return dom_node_format_attributes((link_t_ptr)obj, buf, max);
}

static bool_t _topogctrl_set_object_attrs(widget_t wt, void* obj, const tchar_t* buf, int len)
{
	tchar_t token[KEY_LEN] = {0};

	split_attributes_title(buf, len, token, KEY_LEN);

	if(xscmp(token, DOC_TOPOG_SPOT) != 0) return bool_false;

	dom_node_parse_attributes((link_t_ptr)obj, buf, len);

	return bool_true;
}

static bool_t _topogctrl_delete_object(widget_t wt, void* obj)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_topog_spot(topog, ilk))
	{
		delete_topog_spot(ilk);
		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void* _topogctrl_insert_object(widget_t wt, const tchar_t* attrs, int len)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	tchar_t type[KEY_LEN] = {0};
	int klen;
	link_t_ptr ilk;

	klen = split_attributes_title(attrs, len, type, KEY_LEN);
	if(xscmp(type, DOC_TOPOG_SPOT) != 0) return NULL;
	
	ilk = insert_topog_spot(topog, LINK_LAST);
	if(ilk)
	{
		dom_node_parse_attributes(ilk, attrs, len);
	}

	return (void*)ilk;
}

static bool_t _topogctrl_get_object_selected(widget_t wt, void* obj)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_topog_spot(topog, ilk))
		return get_topog_spot_selected(ilk);
	else
		return bool_false;
}

static void _topogctrl_set_object_selected(widget_t wt, void* obj, bool_t b)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_topog_spot(topog, ilk))
	{
		set_topog_spot_selected(ilk, b);
	}
}

static void _topogctrl_all_object_selected(widget_t wt, bool_t b)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	link_t_ptr ilk;

	ilk = get_topog_next_spot(topog, LINK_FIRST);
	while(ilk)
	{
		set_topog_spot_selected(ilk, b);
		ilk = get_topog_next_spot(topog, ilk);
	}
}

static void* _topogctrl_get_next_group(widget_t wt, void* grp)
{
	link_t_ptr topog = topogctrl_fetch(wt);

	return (grp == LINK_FIRST)? (void*)topog : NULL;
}

static void* _topogctrl_get_next_object(widget_t wt, void* grp, void* obj)
{
	link_t_ptr topog = topogctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	return (grp == topog)? (void*)get_topog_next_spot(topog, ilk) : NULL;
}

static dword_t _topogctrl_retrive_document(widget_t wt, byte_t* buf, dword_t max)
{
	link_t_ptr topog = topogctrl_fetch(wt);

#ifdef _UNICODE
	return format_dom_doc_to_bytes(topog, buf, max, DEF_UCS);
#else
	return format_dom_doc_to_bytes(topog, buf, max, DEF_MBS);
#endif
}

static bool_t _topogctrl_restore_document(widget_t wt, const byte_t* buf, dword_t len)
{
	link_t_ptr topog = topogctrl_detach(wt);
	bool_t b;
#ifdef _UNICODE
	b = parse_dom_doc_from_bytes(topog, buf, len, DEF_UCS);
#else
	b = parse_dom_doc_from_bytes(topog, buf, len, DEF_MBS);
#endif

	topogctrl_attach(wt, topog);

	return b;
}

static void _topogctrl_render_document(widget_t wt, drawing_interface* pci)
{
	link_t_ptr topog = topogctrl_fetch(wt);

	draw_topog(pci, topog);
}

/////////////////////////////////////////////////////////////////////////////////////

designer_interface desg_topogctrl = {
	.with_ruler = bool_true,
	.with_opera = WITH_DRAG_FOCUSED | WITH_DRAG_SELECTED | WITH_MOUSE_GROUPED,

	.pf_get_point_scale = _topogctrl_get_point_scale,
	
	.pf_get_obj_point = _topogctrl_get_object_point,
	.pf_set_obj_point = _topogctrl_set_object_point,
	.pf_get_obj_size = _topogctrl_get_object_size,
	.pf_set_obj_size = _topogctrl_set_object_size,
	.pf_get_obj_rect = _topogctrl_get_object_rect,
	.pf_set_obj_rect = _topogctrl_set_object_rect,

	.pf_get_obj_attrs = _topogctrl_get_object_attrs,
	.pf_set_obj_attrs = _topogctrl_set_object_attrs,

	.pf_get_obj_selected = _topogctrl_get_object_selected,
	.pf_set_obj_selected = _topogctrl_set_object_selected,
	.pf_all_obj_selected = _topogctrl_all_object_selected,

	.pf_get_next_grp = _topogctrl_get_next_group,
	.pf_get_next_obj = _topogctrl_get_next_object,

	.pf_ins_obj = _topogctrl_insert_object,
	.pf_del_obj = _topogctrl_delete_object,

	.pf_retrive_doc = _topogctrl_retrive_document,
	.pf_restore_doc = _topogctrl_restore_document,
	.pf_render_doc = _topogctrl_render_document
};

