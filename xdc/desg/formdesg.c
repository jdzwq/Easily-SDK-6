/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc designer document

	@module	formdesg.c | implement file

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


#define FIELD_MIN_WIDTH		(float)10
#define FIELD_MIN_HEIGHT	(float)10

/***********************************************interface********************************************************/

static void _formctrl_get_point_scale(widget_t wt, int* pcx, int* pcy)
{
	*pcx = *pcy = 1;
}

static void _formctrl_get_object_point(widget_t wt, void* obj, xpoint_t* ppt)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = (link_t_ptr)obj;

	if (is_form_field(form, flk))
	{
		ppt->fx = get_field_x(flk);
		ppt->fy = get_field_y(flk);

		widget_point_to_pt(wt, ppt);
	}
}

static bool_t _formctrl_set_object_point(widget_t wt, void* obj, const xpoint_t* ppt)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = (link_t_ptr)obj;
	xpoint_t pt;

	pt.x = ppt->x;
	pt.y = ppt->y;

	widget_point_to_mm(wt, &pt);

	if (is_form_field(form, flk))
	{
		set_field_x(flk, pt.fx);
		set_field_y(flk, pt.fy);

		return bool_true;
	}
	else
	{
		return bool_false;
	}
}

static void _formctrl_get_object_size(widget_t wt, void* obj, xsize_t* pxs)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = (link_t_ptr)obj;

	if (is_form_field(form, flk))
	{
		pxs->fw = get_field_width(flk);
		pxs->fh = get_field_height(flk);

		widget_size_to_pt(wt, pxs);
	}
}

static bool_t _formctrl_set_object_size(widget_t wt, void* obj, const xsize_t* pxs)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = (link_t_ptr)obj;
	xsize_t xs;

	xs.w = pxs->w;
	xs.h = pxs->h;

	widget_size_to_mm(wt, &xs);

	if (is_form_field(form, flk))
	{
		set_field_width(flk, xs.fw);
		set_field_height(flk, xs.fh);

		return bool_true;
	}
	else
	{
		return bool_false;
	}
}

static void _formctrl_get_object_rect(widget_t wt, void* obj, xrect_t* pxr)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = (link_t_ptr)obj;

	if (is_form_field(form, flk))
	{
		pxr->fx = get_field_x(flk);
		pxr->fy = get_field_y(flk);
		pxr->fw = get_field_width(flk);
		pxr->fh = get_field_height(flk);

		widget_rect_to_pt(wt, pxr);
	}
}

static bool_t _formctrl_set_object_rect(widget_t wt, void* obj, const xrect_t* pxr)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = (link_t_ptr)obj;
	xrect_t xr;

	xr.x = pxr->x;
	xr.y = pxr->y;
	xr.w = pxr->w;
	xr.h = pxr->h;

	widget_rect_to_mm(wt, &xr);

	if (is_form_field(form, flk))
	{
		set_field_x(flk, xr.fx);
		set_field_y(flk, xr.fy);
		set_field_width(flk, xr.fw);
		set_field_height(flk, xr.fh);

		return bool_true;
	}
	else
	{
		return bool_false;
	}
}

static int _formctrl_get_object_attrs(widget_t wt, void* obj, tchar_t* buf, int max)
{
	return dom_node_format_attributes((link_t_ptr)obj, buf, max);
}

static bool_t _formctrl_set_object_attrs(widget_t wt, void* obj, const tchar_t* buf, int len)
{
	tchar_t token[KEY_LEN] = {0};

	split_attributes_title(buf, len, token, KEY_LEN);

	if(!is_form_field_class(token)) return bool_false;

	dom_node_parse_attributes((link_t_ptr)obj, buf, len);

	return bool_true;
}

static bool_t _formctrl_delete_object(widget_t wt, void* obj)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = (link_t_ptr)obj;

	if (is_form_field(form, flk))
	{
		delete_field(flk);
		return bool_true;
	}else
	{
		return bool_false;
	}
}

static void* _formctrl_insert_object(widget_t wt, const tchar_t* attrs, int len)
{
	link_t_ptr form = formctrl_fetch(wt);
	tchar_t type[KEY_LEN] = {0};
	int klen;
	link_t_ptr flk;

	klen = split_attributes_title(attrs, len, type, KEY_LEN);
	if(!is_form_field_class(type)) return NULL;
	
	flk = insert_field(form, type);
	if(flk)
	{
		dom_node_parse_attributes(flk, attrs, len);
	}

	return (void*)flk;
}

static bool_t _formctrl_get_object_selected(widget_t wt, void* obj)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = (link_t_ptr)obj;

	if (is_form_field(form, flk))
		return get_field_selected(flk);
	else
		return bool_false;
}

static void _formctrl_set_object_selected(widget_t wt, void* obj, bool_t b)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = (link_t_ptr)obj;

	if (is_form_field(form, flk))
	{
		set_field_selected(flk, b);
	}
}

static void _formctrl_all_object_selected(widget_t wt, bool_t b)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk;

	flk = get_next_field(form, LINK_FIRST);
	while(flk)
	{
		set_field_selected(flk, b);
		flk = get_next_field(form, flk);
	}
}

static void* _formctrl_get_next_group(widget_t wt, void* grp)
{
	link_t_ptr form = formctrl_fetch(wt);

	return (void*)((grp == LINK_FIRST)? form : NULL);
}

static void* _formctrl_get_next_object(widget_t wt, void* grp, void* obj)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = (link_t_ptr)obj;

	return (grp == form)? (void*)get_next_field(form, flk) : NULL;
}

static void _formctrl_get_group_rect(widget_t wt, int gid, xrect_t* pxr)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk;
	float fx, fy, fw, fh;

	pxr->fx = pxr->fy = pxr->fw = pxr->fh = 0.0f;

	flk = get_next_field(form, LINK_FIRST);
	while(flk)
	{
		if(gid != get_field_group(flk))
		{
			flk = get_next_field(form, flk);
			continue;
		}

		fx = get_field_x(flk);
		fy = get_field_y(flk);
		fw = get_field_width(flk);
		fh = get_field_height(flk);

		if (fx < pxr->fx)
		{
			pxr->fw += (pxr->fx - fx);
			pxr->fx = fx;
		}
		if (fy < pxr->fy)
		{
			pxr->fh += (pxr->fy - fy);
			pxr->fy = fy;
		}
		if (fx + fw > pxr->fx + pxr->fw)
			pxr->fw = fx + fw - pxr->fx;
		if (fy + fh > pxr->fy + pxr->fh)
			pxr->fh = fy + fh - pxr->fy;

		flk = get_next_field(form, flk);
	}

	widget_rect_to_pt(wt, pxr);
}

static dword_t _formctrl_retrive_document(widget_t wt, byte_t* buf, dword_t max)
{
	link_t_ptr form = formctrl_fetch(wt);

#ifdef _UNICODE
	return format_dom_doc_to_bytes(form, buf, max, DEF_UCS);
#else
	return format_dom_doc_to_bytes(form, buf, max, DEF_MBS);
#endif
}

static bool_t _formctrl_restore_document(widget_t wt, const byte_t* buf, dword_t len)
{
	link_t_ptr form = formctrl_detach(wt);
	bool_t b;
#ifdef _UNICODE
	b = parse_dom_doc_from_bytes(form, buf, len, DEF_UCS);
#else
	b = parse_dom_doc_from_bytes(form, buf, len, DEF_MBS);
#endif

	formctrl_attach(wt, form);

	return b;
}

static void _formctrl_render_document(widget_t wt, drawing_interface* pci)
{
	link_t_ptr form = formctrl_fetch(wt);

	set_form_design(form, 1);
	draw_form_page(pci, form, 1);
	set_form_design(form, 0);
}

/////////////////////////////////////////////////////////////////////////////////////

designer_interface desg_formctrl = {
	.with_ruler = bool_true,
	.with_opera = WITH_SIZE_WIDTH | WITH_SIZE_HEIGHT | WITH_DRAG_FOCUSED | WITH_DRAG_SELECTED | WITH_MOUSE_GROUPED,
	
	.pf_get_point_scale = _formctrl_get_point_scale,
	
	.pf_get_obj_point = _formctrl_get_object_point,
	.pf_set_obj_point = _formctrl_set_object_point,
	.pf_get_obj_size = _formctrl_get_object_size,
	.pf_set_obj_size = _formctrl_set_object_size,
	.pf_get_obj_rect = _formctrl_get_object_rect,
	.pf_set_obj_rect = _formctrl_set_object_rect,

	.pf_get_obj_attrs = _formctrl_get_object_attrs,
	.pf_set_obj_attrs = _formctrl_set_object_attrs,

	.pf_get_obj_selected = _formctrl_get_object_selected,
	.pf_set_obj_selected = _formctrl_set_object_selected,
	.pf_all_obj_selected = _formctrl_all_object_selected,

	.pf_get_next_grp = _formctrl_get_next_group,
	.pf_get_next_obj = _formctrl_get_next_object,

	.pf_ins_obj = _formctrl_insert_object,
	.pf_del_obj = _formctrl_delete_object,

	.pf_retrive_doc = _formctrl_retrive_document,
	.pf_restore_doc = _formctrl_restore_document,
	.pf_render_doc = _formctrl_render_document
};

