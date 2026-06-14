/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc designer document

	@module	statisdesg.c | implement file

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


/***********************************************interface********************************************************/

static void _statisctrl_get_point_scale(widget_t wt, int* pcx, int* pcy)
{
	*pcx = *pcy = 1;
}

static void _statisctrl_get_object_point(widget_t wt, void* obj, xpoint_t* ppt)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr nlk = (link_t_ptr)obj;
	xrect_t xr = {0};

	if(is_statis_gax(statis, nlk))
		calc_statis_gaxbar_rect(statis, nlk, &xr);
	else if(is_statis_yax(statis, nlk))
		calc_statis_coor_rect(statis, 1, NULL, nlk, &xr);
	else if(is_statis_xax(statis, nlk))
		calc_statis_coor_rect(statis, 1, nlk, NULL, &xr);

	ppt->fx = xr.fx;
	ppt->fy = xr.fy;

	widget_point_to_pt(wt, ppt);
}

static bool_t _statisctrl_set_object_point(widget_t wt, void* obj, const xpoint_t* ppt)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	xpoint_t pt;
	xrect_t xr;
	int nHint;
	LINKPTR xlk, ylk, glk;
	LINKPTR root, nlk = (LINKPTR)obj;

	pt.x = ppt->x;
	pt.y = ppt->y;

	widget_point_to_mm(wt, &pt);

	xlk = ylk = glk = NULL;
	nHint = calc_statis_hint(&pt, statis, 1, &xlk, &ylk, &glk);

	if(is_statis_gax(statis, nlk))
	{
		if (nlk == glk) return bool_false;

		root = get_dom_child_node_root(get_statis_gaxset(statis));

		if (glk)
		{
			switch_link_before(root, glk, nlk);
		}
		else
		{
			calc_statis_gaxbar_rect(statis, nlk, &xr);
			widget_rect_to_pt(wt, &xr);

			if (ppt->x < xr.x)
				switch_link_first(root, nlk);
			else
				switch_link_last(root, nlk);
		}

		return bool_true;
	}else if(is_statis_yax(statis, nlk))
	{
		if (nlk == ylk) return bool_false;

		root = get_dom_child_node_root(get_statis_yaxset(statis));

		if (ylk)
		{
			switch_link_before(root, ylk, nlk);
		}
		else
		{
			calc_statis_coor_rect(statis, 1, NULL, nlk, &xr);
			widget_rect_to_pt(wt, &xr);

			if (ppt->y < xr.y)
				switch_link_first(root, nlk);
			else
				switch_link_last(root, nlk);
		}

		return bool_true;
	}else if(is_statis_xax(statis, nlk))
	{
		if (nlk == xlk) return bool_false;

		root = get_dom_child_node_root(get_statis_xaxset(statis));

		if (xlk)
		{
			switch_link_before(root, xlk, nlk);
		}
		else
		{
			calc_statis_coor_rect(statis, 1, nlk, NULL, &xr);
			widget_rect_to_pt(wt, &xr);

			if (ppt->x < xr.x)
				switch_link_first(root, nlk);
			else
				switch_link_last(root, nlk);
		}

		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void _statisctrl_get_object_size(widget_t wt, void* obj, xsize_t* pxs)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr nlk = (link_t_ptr)obj;
	xrect_t xr;

	if(is_statis_gax(statis, nlk))
		calc_statis_gaxbar_rect(statis, nlk, &xr);
	else if(is_statis_yax(statis, nlk))
		calc_statis_coor_rect(statis, 1, NULL, nlk, &xr);
	else if(is_statis_xax(statis, nlk))
		calc_statis_coor_rect(statis, 1, nlk, NULL, &xr);

	pxs->fw = xr.fw;
	pxs->fh = xr.fh;

	widget_size_to_pt(wt, pxs);
}

static bool_t _statisctrl_set_object_size(widget_t wt, void* obj, const xsize_t* pxs)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr nlk = (link_t_ptr)obj;
	xsize_t xs;

	xs.w = pxs->w;
	xs.h = pxs->h;

	widget_size_to_mm(wt, &xs);

	if(is_statis_gax(statis, nlk))
	{
		return bool_false;
	}else if(is_statis_yax(statis, nlk))
	{
		set_statis_yaxbar_width(statis, xs.fw);
		set_statis_yaxbar_height(statis, xs.fh);
		return bool_true;
	}else if(is_statis_xax(statis, nlk))
	{
		set_statis_xaxbar_width(statis, xs.fw);
		set_statis_xaxbar_height(statis, xs.fh);
		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void _statisctrl_get_object_rect(widget_t wt, void* obj, xrect_t* pxr)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr nlk = (link_t_ptr)obj;

	if(is_statis_gax(statis, nlk))
		calc_statis_gaxbar_rect(statis, nlk, pxr);
	else if(is_statis_yax(statis, nlk))
		calc_statis_coor_rect(statis, 1, NULL, nlk, pxr);
	else if(is_statis_xax(statis, nlk))
		calc_statis_coor_rect(statis, 1, nlk, NULL, pxr);

	widget_rect_to_pt(wt, pxr);
}

static bool_t _statisctrl_set_object_rect(widget_t wt, void* obj, const xrect_t* pxr)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr nlk = (link_t_ptr)obj;
	
	return bool_false;
}

static int _statisctrl_get_object_attrs(widget_t wt, void* obj, tchar_t* buf, int max)
{
	return dom_node_format_attributes((link_t_ptr)obj, buf, max);
}

static bool_t _statisctrl_set_object_attrs(widget_t wt, void* obj, const tchar_t* buf, int len)
{
	tchar_t token[KEY_LEN] = {0};

	split_attributes_title(buf, len, token, KEY_LEN);

	if(xscmp(token, DOC_STATIS_XAX) != 0 && xscmp(token, DOC_STATIS_YAX) != 0 && xscmp(token, DOC_STATIS_GAX) != 0) 
		return bool_false;

	dom_node_parse_attributes((link_t_ptr)obj, buf, len);

	return bool_true;
}

static bool_t _statisctrl_delete_object(widget_t wt, void* obj)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr nlk = (link_t_ptr)obj;

	if(is_statis_gax(statis, nlk))
		{delete_gax(nlk);return bool_true;}
	else if(is_statis_yax(statis, nlk))
		{delete_yax(nlk);return bool_true;}
	else if(is_statis_xax(statis, nlk))
		{delete_xax(nlk);return bool_true;}
	else
		return bool_false;
}

static void* _statisctrl_insert_object(widget_t wt, const tchar_t* attrs, int len)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	tchar_t type[KEY_LEN] = {0};
	int klen;
	link_t_ptr nlk = NULL;

	klen = split_attributes_title(attrs, len, type, KEY_LEN);
	
	if(xscmp(type, DOC_STATIS_GAX) == 0)
		nlk = insert_gax(statis, LINK_LAST);
	else if(xscmp(type, DOC_STATIS_YAX) == 0)
		nlk = insert_yax(statis, LINK_LAST);
	else if(xscmp(type, DOC_STATIS_XAX) == 0)
		nlk = insert_xax(statis, LINK_LAST);
	
	if(nlk)
	{
		dom_node_parse_attributes(nlk, attrs, len);
	}

	return (void*)nlk;
}

static bool_t _statisctrl_get_object_selected(widget_t wt, void* obj)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr nlk = (link_t_ptr)obj;

	if(is_statis_yax(statis, nlk))
		return get_yax_selected(nlk);
	else
		return bool_false;
}

static void _statisctrl_set_object_selected(widget_t wt, void* obj, bool_t b)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr nlk = (link_t_ptr)obj;

	if(is_statis_yax(statis, nlk))
	{
		set_yax_selected(nlk, b);
	}
}

static void _statisctrl_all_object_selected(widget_t wt, bool_t b)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr nlk;

	nlk = get_next_yax(statis, LINK_FIRST);
	while(nlk)
	{
		set_yax_selected(nlk, b);
		nlk = get_next_yax(statis, nlk);
	}
}

static void* _statisctrl_get_next_group(widget_t wt, void* grp)
{
	link_t_ptr statis = statisctrl_fetch(wt);

	if(grp == LINK_FIRST)
		return (void*)get_statis_gaxset(statis);
	else if(is_statis_gaxset(grp))
		return (void*)get_statis_yaxset(statis);
	else if(is_statis_yaxset(grp))
		return (void*)get_statis_xaxset(statis);
	else
		return NULL;
}

static void* _statisctrl_get_next_object(widget_t wt, void* grp, void* obj)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr nlk = (link_t_ptr)obj;

	if(is_statis_gaxset(grp))
		return (void*)get_next_gax(statis, obj);
	else if(is_statis_yaxset(grp))
		return (void*)get_next_yax(statis, obj);
	else if(is_statis_xaxset(grp))
		return (void*)get_next_xax(statis, obj);
	else
		return NULL;
}

static dword_t _statisctrl_retrive_document(widget_t wt, byte_t* buf, dword_t max)
{
	link_t_ptr statis = statisctrl_fetch(wt);

#ifdef _UNICODE
	return format_dom_doc_to_bytes(statis, buf, max, DEF_UCS);
#else
	return format_dom_doc_to_bytes(statis, buf, max, DEF_MBS);
#endif
}

static bool_t _statisctrl_restore_document(widget_t wt, const byte_t* buf, dword_t len)
{
	link_t_ptr statis = statisctrl_detach(wt);
	bool_t b;

#ifdef _UNICODE
	b = parse_dom_doc_from_bytes(statis, buf, len, DEF_UCS);
#else
	b = parse_dom_doc_from_bytes(statis, buf, len, DEF_MBS);
#endif

	statisctrl_attach(wt, statis);

	return b;
}

static void _statisctrl_render_document(widget_t wt, drawing_interface* pci)
{
	link_t_ptr statis = statisctrl_fetch(wt);

	set_statis_design(statis, 1);
	draw_statis_page(pci, statis, 1);
	set_statis_design(statis, 0);
}

/////////////////////////////////////////////////////////////////////////////////////

designer_interface desg_statisctrl = {
	.with_ruler = bool_false,
	.with_opera = WITH_SIZE_WIDTH | WITH_SIZE_HEIGHT | WITH_DRAG_FOCUSED,
	
	.pf_get_point_scale = _statisctrl_get_point_scale,
	
	.pf_get_obj_point = _statisctrl_get_object_point,
	.pf_set_obj_point = _statisctrl_set_object_point,
	.pf_get_obj_size = _statisctrl_get_object_size,
	.pf_set_obj_size = _statisctrl_set_object_size,
	.pf_get_obj_rect = _statisctrl_get_object_rect,
	.pf_set_obj_rect = _statisctrl_set_object_rect,

	.pf_get_obj_attrs = _statisctrl_get_object_attrs,
	.pf_set_obj_attrs = _statisctrl_set_object_attrs,

	.pf_get_obj_selected = _statisctrl_get_object_selected,
	.pf_set_obj_selected = _statisctrl_set_object_selected,
	.pf_all_obj_selected = _statisctrl_all_object_selected,

	.pf_get_next_grp = _statisctrl_get_next_group,
	.pf_get_next_obj = _statisctrl_get_next_object,

	.pf_ins_obj = _statisctrl_insert_object,
	.pf_del_obj = _statisctrl_delete_object,

	.pf_retrive_doc = _statisctrl_retrive_document,
	.pf_restore_doc = _statisctrl_restore_document,
	.pf_render_doc = _statisctrl_render_document
};

