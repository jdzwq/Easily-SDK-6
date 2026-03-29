/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc designer document

	@module	diagramdesg.c | implement file

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


#define DIAGRAM_LINE_FEED		(float)50
#define DIAGRAM_ENTITY_MIN_WIDTH	(float)10
#define DIAGRAM_ENTITY_MIN_HEIGHT	(float)10

/***********************************************interface********************************************************/

static void _diagramctrl_get_point_scale(widget_t wt, int* pcx, int* pcy)
{
	*pcx = *pcy = 1;
}

static void _diagramctrl_get_object_point(widget_t wt, void* obj, xpoint_t* ppt)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_diagram_entity(diagram, ilk))
	{
		ppt->fx = get_diagram_entity_x(ilk);
		ppt->fy = get_diagram_entity_y(ilk);

		widget_point_to_pt(wt, ppt);
	}
}

static bool_t _diagramctrl_set_object_point(widget_t wt, void* obj, const xpoint_t* ppt)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;
	xpoint_t pt;

	pt.x = ppt->x;
	pt.y = ppt->y;

	widget_point_to_mm(wt, &pt);

	if (is_diagram_entity(diagram, ilk))
	{
		set_diagram_entity_x(ilk, pt.fx);
		set_diagram_entity_y(ilk, pt.fy);

		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void _diagramctrl_get_object_size(widget_t wt, void* obj, xsize_t* pxs)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_diagram_entity(diagram, ilk))
	{
		pxs->fw = get_diagram_entity_width(ilk);
		pxs->fh = get_diagram_entity_height(ilk);

		widget_size_to_pt(wt, pxs);
	}
}

static bool_t _diagramctrl_set_object_size(widget_t wt, void* obj, const xsize_t* pxs)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;
	xsize_t xs;

	xs.w = pxs->w;
	xs.h = pxs->h;

	widget_size_to_mm(wt, &xs);

	if (is_diagram_entity(diagram, ilk))
	{
		set_diagram_entity_width(ilk, xs.fw);
		set_diagram_entity_height(ilk, xs.fh);

		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void _diagramctrl_get_object_rect(widget_t wt, void* obj, xrect_t* pxr)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_diagram_entity(diagram, ilk))
	{
		pxr->fx = get_diagram_entity_x(ilk);
		pxr->fy = get_diagram_entity_y(ilk);
		pxr->fw = get_diagram_entity_width(ilk);
		pxr->fh = get_diagram_entity_height(ilk);

		widget_rect_to_pt(wt, pxr);
	}
}

static bool_t _diagramctrl_set_object_rect(widget_t wt, void* obj, const xrect_t* pxr)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;
	xrect_t xr;

	xr.x = pxr->x;
	xr.y = pxr->y;
	xr.w = pxr->w;
	xr.h = pxr->h;

	widget_rect_to_mm(wt, &xr);

	if (is_diagram_entity(diagram, ilk))
	{
		set_diagram_entity_x(ilk, xr.fx);
		set_diagram_entity_y(ilk, xr.fy);
		set_diagram_entity_width(ilk, xr.fw);
		set_diagram_entity_height(ilk, xr.fh);

		return bool_true;
	}else
	{
		return bool_false;
	}
}

static int _diagramctrl_get_object_attrs(widget_t wt, void* obj, tchar_t* buf, int max)
{
	return dom_node_format_attributes((link_t_ptr)obj, buf, max);
}

static bool_t _diagramctrl_set_object_attrs(widget_t wt, void* obj, const tchar_t* buf, int len)
{
	tchar_t token[KEY_LEN] = {0};

	split_attributes_title(buf, len, token, KEY_LEN);

	if(!is_diagram_entity_class(token)) return bool_false;

	dom_node_parse_attributes((link_t_ptr)obj, buf, len);

	return bool_true;
}

static bool_t _diagramctrl_delete_object(widget_t wt, void* obj)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_diagram_entity(diagram, ilk))
	{
		delete_diagram_entity(ilk);
		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void* _diagramctrl_insert_object(widget_t wt, const tchar_t* attrs, int len)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	tchar_t type[KEY_LEN] = {0};
	int klen;
	link_t_ptr ilk;

	klen = split_attributes_title(attrs, len, type, KEY_LEN);
	if(!is_diagram_entity_class(type)) return NULL;
	
	ilk = insert_diagram_entity(diagram, type);
	if(ilk)
	{
		dom_node_parse_attributes(ilk, attrs, len);
	}

	return (void*)ilk;
}

static bool_t _diagramctrl_get_object_selected(widget_t wt, void* obj)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_diagram_entity(diagram, ilk))
		return get_diagram_entity_selected(ilk);
	else
		return bool_false;
}

static void _diagramctrl_set_object_selected(widget_t wt, void* obj, bool_t b)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	if (is_diagram_entity(diagram, ilk))
	{
		set_diagram_entity_selected(ilk, b);
	}
}

static void _diagramctrl_all_object_selected(widget_t wt, bool_t b)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	link_t_ptr ilk;

	ilk = get_diagram_next_entity(diagram, LINK_FIRST);
	while(ilk)
	{
		set_diagram_entity_selected(ilk, b);
		ilk = get_diagram_next_entity(diagram, ilk);
	}
}

static void* _diagramctrl_get_next_group(widget_t wt, void* grp)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);

	return (grp == LINK_FIRST)? (void*)diagram : NULL;
}

static void* _diagramctrl_get_next_object(widget_t wt, void* grp, void* obj)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);
	link_t_ptr ilk = (link_t_ptr)obj;

	return (grp == diagram)? (void*)get_diagram_next_entity(diagram, ilk) : NULL;
}

static dword_t _diagramctrl_retrive_document(widget_t wt, byte_t* buf, dword_t max)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);

#ifdef _UNICODE
	return format_dom_doc_to_bytes(diagram, buf, max, DEF_UCS);
#else
	return format_dom_doc_to_bytes(diagram, buf, max, DEF_MBS);
#endif
}

static bool_t _diagramctrl_restore_document(widget_t wt, const byte_t* buf, dword_t len)
{
	link_t_ptr diagram = diagramctrl_detach(wt);
	bool_t b;
#ifdef _UNICODE
	b = parse_dom_doc_from_bytes(diagram, buf, len, DEF_UCS);
#else
	b = parse_dom_doc_from_bytes(diagram, buf, len, DEF_MBS);
#endif

	diagramctrl_attach(wt, diagram);

	return b;
}

static void _diagramctrl_render_document(widget_t wt, drawing_interface* pci)
{
	link_t_ptr diagram = diagramctrl_fetch(wt);

	draw_diagram(pci, diagram);
}

/////////////////////////////////////////////////////////////////////////////////////

designer_interface desg_diagramctrl = {
	.with_ruler = bool_true,
	.with_opera = WITH_SIZE_WIDTH | WITH_SIZE_HEIGHT | WITH_DRAG_FOCUSED | WITH_DRAG_SELECTED | WITH_MOUSE_GROUPED,

	.pf_get_point_scale = _diagramctrl_get_point_scale,
	
	.pf_get_obj_point = _diagramctrl_get_object_point,
	.pf_set_obj_point = _diagramctrl_set_object_point,
	.pf_get_obj_size = _diagramctrl_get_object_size,
	.pf_set_obj_size = _diagramctrl_set_object_size,
	.pf_get_obj_rect = _diagramctrl_get_object_rect,
	.pf_set_obj_rect = _diagramctrl_set_object_rect,

	.pf_get_obj_attrs = _diagramctrl_get_object_attrs,
	.pf_set_obj_attrs = _diagramctrl_set_object_attrs,

	.pf_get_obj_selected = _diagramctrl_get_object_selected,
	.pf_set_obj_selected = _diagramctrl_set_object_selected,
	.pf_all_obj_selected = _diagramctrl_all_object_selected,

	.pf_get_next_grp = _diagramctrl_get_next_group,
	.pf_get_next_obj = _diagramctrl_get_next_object,

	.pf_ins_obj = _diagramctrl_insert_object,
	.pf_del_obj = _diagramctrl_delete_object,

	.pf_retrive_doc = _diagramctrl_retrive_document,
	.pf_restore_doc = _diagramctrl_restore_document,
	.pf_render_doc = _diagramctrl_render_document
};

