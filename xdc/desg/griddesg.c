/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc designer document

	@module	griddesg.c | implement file

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

static void _gridctrl_get_point_scale(widget_t wt, int* pcx, int* pcy)
{
	*pcx = *pcy = 1;
}

static void _gridctrl_get_object_point(widget_t wt, void* obj, xpoint_t* ppt)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr col = (link_t_ptr)obj;
	xrect_t xr = {0};

	if(is_grid_col(grid, col))
	{
		calc_grid_cell_rect(grid, 1, NULL, col, &xr);
	}

	ppt->fx = xr.fx;
	ppt->fy = xr.fy;

	widget_point_to_pt(wt, ppt);
}

static bool_t _gridctrl_set_object_point(widget_t wt, void* obj, const xpoint_t* ppt)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	xpoint_t pt;
	xrect_t xr;
	int nHint;
	LINKPTR rlk, clk;
	LINKPTR root, col = (LINKPTR)obj;

	pt.x = ppt->x;
	pt.y = ppt->y;

	widget_point_to_mm(wt, &pt);

	rlk = clk = NULL;
	nHint = calc_grid_hint(&pt, grid, 1, &rlk, &clk);

	if (is_grid_col(grid, col))
	{
		if (clk == col)
			return bool_false;

		root = get_dom_child_node_root(get_grid_colset(grid));

		if (clk)
		{
			switch_link_before(root, clk, col);
		}
		else
		{
			calc_grid_cell_rect(grid, 1, NULL, col, &xr);
			widget_rect_to_pt(wt, &xr);

			if (ppt->x < xr.x)
				switch_link_first(root, col);
			else
				switch_link_last(root, col);
		}
		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void _gridctrl_get_object_size(widget_t wt, void* obj, xsize_t* pxs)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr col = (link_t_ptr)obj;
	xrect_t xr = {0};

	if(is_grid_col(grid, col))
	{
		calc_grid_cell_rect(grid, 1, NULL, col, &xr);
	}

	pxs->fw = xr.fw;
	pxs->fh = xr.fh;

	widget_size_to_pt(wt, pxs);
}

static bool_t _gridctrl_set_object_size(widget_t wt, void* obj, const xsize_t* pxs)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr col = (link_t_ptr)obj;
	xsize_t xs;

	xs.w = pxs->w;
	xs.h = pxs->h;

	widget_size_to_mm(wt, &xs);

	if(is_grid_col(grid, col))
	{
		set_col_width(col, xs.fw);
	
		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void _gridctrl_get_object_rect(widget_t wt, void* obj, xrect_t* pxr)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr col = (link_t_ptr)obj;

	if(is_grid_col(grid, col))
	{
		calc_grid_cell_rect(grid, 1, NULL, col, pxr);
		widget_rect_to_pt(wt, pxr);
	}
}

static bool_t _gridctrl_set_object_rect(widget_t wt, void* obj, const xrect_t* pxr)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr col = (link_t_ptr)obj;
	
	return bool_false;
}

static int _gridctrl_get_object_attrs(widget_t wt, void* obj, tchar_t* buf, int max)
{
	return dom_node_format_attributes((link_t_ptr)obj, buf, max);
}

static bool_t _gridctrl_set_object_attrs(widget_t wt, void* obj, const tchar_t* buf, int len)
{
	tchar_t token[KEY_LEN] = {0};

	split_attributes_title(buf, len, token, KEY_LEN);

	if(xscmp(token, DOC_GRID_COL) != 0) return bool_false;

	dom_node_parse_attributes((link_t_ptr)obj, buf, len);

	return bool_true;
}

static bool_t _gridctrl_delete_object(widget_t wt, void* obj)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr col = (link_t_ptr)obj;

	if(is_grid_col(grid, col))
	{
		delete_col(col);
		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void* _gridctrl_insert_object(widget_t wt, const tchar_t* attrs, int len)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	tchar_t type[KEY_LEN] = {0};
	int klen;
	link_t_ptr clk;

	klen = split_attributes_title(attrs, len, type, KEY_LEN);
	if(xscmp(type, DOC_GRID_COL) != 0) return NULL;
	
	clk = insert_col(grid, LINK_LAST);
	if(clk)
	{
		dom_node_parse_attributes(clk, attrs, len);
	}

	return (void*)clk;
}

static bool_t _gridctrl_get_object_selected(widget_t wt, void* obj)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr col = (link_t_ptr)obj;

	if(is_grid_col(grid, col))
		return get_col_selected(col);
	else
		return bool_false;
}

static void _gridctrl_set_object_selected(widget_t wt, void* obj, bool_t b)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr col = (link_t_ptr)obj;

	if(is_grid_col(grid, col))
	{
		set_col_selected(col, b);
	}
}

static void _gridctrl_all_object_selected(widget_t wt, bool_t b)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr clk;

	clk = get_next_col(grid, LINK_FIRST);
	while(clk)
	{
		set_col_selected(clk, b);
		clk = get_next_col(grid, clk);
	}
}

static void* _gridctrl_get_next_group(widget_t wt, void* grp)
{
	link_t_ptr grid = gridctrl_fetch(wt);

	if(grp == LINK_FIRST)
		return (void*)get_grid_colset(grid);
	else
		return NULL;
}

static void* _gridctrl_get_next_object(widget_t wt, void* grp, void* obj)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr clk = (link_t_ptr)obj;

	if(is_grid_colset(grp))
		return (void*)get_next_col(grid, clk);
	else
		return NULL;
}

static dword_t _gridctrl_retrive_document(widget_t wt, byte_t* buf, dword_t max)
{
	link_t_ptr grid = gridctrl_fetch(wt);

#ifdef _UNICODE
	return format_dom_doc_to_bytes(grid, buf, max, DEF_UCS);
#else
	return format_dom_doc_to_bytes(grid, buf, max, DEF_MBS);
#endif
}

static bool_t _gridctrl_restore_document(widget_t wt, const byte_t* buf, dword_t len)
{
	link_t_ptr grid = gridctrl_detach(wt);
	bool_t b;

#ifdef _UNICODE
	b = parse_dom_doc_from_bytes(grid, buf, len, DEF_UCS);
#else
	b = parse_dom_doc_from_bytes(grid, buf, len, DEF_MBS);
#endif

	gridctrl_attach(wt, grid);

	return b;
}

static void _gridctrl_render_document(widget_t wt, drawing_interface* pci)
{
	link_t_ptr grid = gridctrl_fetch(wt);

	set_grid_design(grid, 1);
	draw_grid_page(pci, grid, 1);
	set_grid_design(grid, 0);
}

/////////////////////////////////////////////////////////////////////////////////////

designer_interface desg_gridctrl = {
	.with_ruler = bool_true,
	.with_opera = WITH_SIZE_WIDTH | WITH_DRAG_FOCUSED,
	
	.pf_get_point_scale = _gridctrl_get_point_scale,
	
	.pf_get_obj_point = _gridctrl_get_object_point,
	.pf_set_obj_point = _gridctrl_set_object_point,
	.pf_get_obj_size = _gridctrl_get_object_size,
	.pf_set_obj_size = _gridctrl_set_object_size,
	.pf_get_obj_rect = _gridctrl_get_object_rect,
	.pf_set_obj_rect = _gridctrl_set_object_rect,

	.pf_get_obj_attrs = _gridctrl_get_object_attrs,
	.pf_set_obj_attrs = _gridctrl_set_object_attrs,

	.pf_get_obj_selected = _gridctrl_get_object_selected,
	.pf_set_obj_selected = _gridctrl_set_object_selected,
	.pf_all_obj_selected = _gridctrl_all_object_selected,

	.pf_get_next_grp = _gridctrl_get_next_group,
	.pf_get_next_obj = _gridctrl_get_next_object,

	.pf_ins_obj = _gridctrl_insert_object,
	.pf_del_obj = _gridctrl_delete_object,

	.pf_retrive_doc = _gridctrl_retrive_document,
	.pf_restore_doc = _gridctrl_restore_document,
	.pf_render_doc = _gridctrl_render_document
};

