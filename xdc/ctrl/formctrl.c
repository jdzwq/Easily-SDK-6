/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc form control document

	@module	formctrl.c | implement file

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

#include "ctrl.h"

#include "../xdcobj.h"


#define FORM_LINE_FEED		(float)50
#define FIELD_MIN_WIDTH		(float)10
#define FIELD_MIN_HEIGHT	(float)10

typedef struct _form_delta_t{
	link_t_ptr form;
	link_t_ptr field;
	link_t_ptr hover;

	bool_t b_alarm;
	bool_t b_lock;

	short cur_page;
	short max_page;

	widget_t editor;
	widget_t hsc;
	widget_t vsc;
}form_delta_t;

#define GETFORMDELTA(ph) 	(form_delta_t*)widget_get_user_delta(ph)
#define SETFORMDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/******************************************form event********************************************************/

static void _formctrl_field_rect(widget_t widget, link_t_ptr flk, xrect_t* pxr)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	calc_form_field_rect(ptd->form, flk, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _formctrl_reset_page(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	int pw, ph, vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	if(ptd->form)
	{
		if (compare_text(get_form_printing_ptr(ptd->form), -1, ATTR_PRINTING_LANDSCAPE, -1, 0) == 0)
		{
			xs.fw = get_form_height(ptd->form);
			xs.fh = get_form_width(ptd->form);
		}
		else
		{
			xs.fw = get_form_width(ptd->form);
			xs.fh = get_form_height(ptd->form);
		}

		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}else
	{
		vw = pw;
		vh = ph;
	}

	xs.fw = 10.0f;
	xs.fh = 10.0f;
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	widget_reset_paging(widget, pw, ph, vw, vh, lw, lh);

	widget_reset_scroll(widget, 1);

	widget_reset_scroll(widget, 0);
}

static void _formctrl_ensure_visible(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	xrect_t xr = { 0 };

	if (!ptd->field)
		return;

	_formctrl_field_rect(widget, ptd->field, &xr);

	widget_ensure_visible(widget, &xr, 1);
}

static void _formctrl_reset_group(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	LINKPTR flk;
	int gid;
	const tchar_t* sz_text;

	XDK_ASSERT(ptd->field);

	gid = get_field_group(ptd->field);
	if (!gid)
		return;

	sz_text = get_field_text_ptr(ptd->field);
	
	flk = get_next_visible_field(ptd->form, LINK_FIRST);
	while (flk)
	{
		if (flk == ptd->field)
		{
			flk = get_next_visible_field(ptd->form, flk);
			continue;
		}

		if (compare_text(get_field_class_ptr(flk), -1, DOC_FORM_CHECK, -1, 0) != 0)
		{
			flk = get_next_visible_field(ptd->form, flk);
			continue;
		}

		if (get_field_group(flk) != gid)
		{
			flk = get_next_visible_field(ptd->form, flk);
			continue;
		}

		set_field_text(flk, sz_text, -1);

		formctrl_redraw_field(widget, flk, 0);

		flk = get_next_visible_field(ptd->form, flk);
	}
}

/*********************************************************************************************************/

int noti_form_owner(widget_t widget, unsigned int code, link_t_ptr form, link_t_ptr flk, void* data)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	NOTICE_FORM nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;

	nf.data = data;	
	nf.ret = 0;

	nf.form = form;
	nf.field = flk;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);
	return nf.ret;
}

bool_t noti_form_field_changing(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->field);

	if (noti_form_owner(widget, NC_FIELDUNFOCUS, ptd->form, ptd->field, NULL))
		return (bool_t)0;

	ptd->b_alarm = (bool_t)0;

	_formctrl_field_rect(widget, ptd->field, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	ptd->field = NULL;

	widget_erase(widget, &xr);

	return (bool_t)1;
}

void noti_form_field_changed(widget_t widget, link_t_ptr flk)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(flk);
	XDK_ASSERT(!ptd->field);

	ptd->field = flk;

	_formctrl_field_rect(widget, ptd->field, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);

	noti_form_owner(widget, NC_FIELDFOCUSED, ptd->form, flk, NULL);
}

void noti_form_field_enter(widget_t widget, link_t_ptr flk)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(flk);
	XDK_ASSERT(!ptd->hover);

	ptd->hover = flk;

	if (widget_is_hotvoer(widget))
	{
		//widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
	}
}

void noti_form_field_leave(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	ptd->hover = NULL;

	if (widget_is_hotvoer(widget))
	{
		//widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
	}
}

void noti_form_field_hover(widget_t widget, int x, int y)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	xpoint_t xp;

	XDK_ASSERT(ptd->hover != NULL);

	xp.x = x;
	xp.y = y;
	noti_form_owner(widget, NC_FIELDHOVER, ptd->form, ptd->hover, (void*)&xp);
}

void noti_form_begin_edit(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	const tchar_t* fclass;
	const tchar_t* editor;
	const tchar_t* text;
	bool_t checked;
	link_t_ptr data;

	xrect_t xr;

	EDITDELTA fd = { 0 };

	color_mod_t ob = { 0 };
	xfont_t xf = { 0 };
	xface_t xa = { 0 };

	XDK_ASSERT(ptd->field);

	if (widget_is_valid(ptd->editor))
		return;

	if (!get_field_focusable(ptd->field))
	{
		return;
	}

	fclass = get_field_class_ptr(ptd->field);

	if (compare_text(fclass, -1, DOC_FORM_TEXT, -1, 0) == 0)
	{
		editor = get_field_editor_ptr(ptd->field);
	}
	else if (compare_text(fclass, -1, DOC_FORM_CHECK, -1, 0) == 0)
	{
		editor = ATTR_EDITOR_FIRECHECK;
	}
	else if (compare_text(fclass, -1, DOC_FORM_RICH, -1, 0) == 0)
	{
		editor = ATTR_EDITOR_RICHBOX;
	}
	else if (compare_text(fclass, -1, DOC_FORM_TAG, -1, 0) == 0)
	{
		editor = ATTR_EDITOR_TAGBOX;
	}
	else if (compare_text(fclass, -1, DOC_FORM_TABLE, -1, 0) == 0)
	{
		editor = ATTR_EDITOR_TABLEBOX;
	}
	else if (compare_text(fclass, -1, DOC_FORM_MEMO, -1, 0) == 0)
	{
		editor = ATTR_EDITOR_MEMOBOX;
	}
	else if (compare_text(fclass, -1, DOC_FORM_GRID, -1, 0) == 0)
	{
		editor = ATTR_EDITOR_GRIDBOX;
	}
	else if (compare_text(fclass, -1, DOC_FORM_STATIS, -1, 0) == 0)
	{
		editor = ATTR_EDITOR_STATISBOX;
	}
	else if (compare_text(fclass, -1, DOC_FORM_FORM, -1, 0) == 0)
	{
		editor = ATTR_EDITOR_FORMBOX;
	}
	else
	{
		return;
	}

	default_xfont(&xf);
	parse_xfont_from_style(&xf, get_field_style_ptr(ptd->field));
	default_xface(&xa);
	parse_xface_from_style(&xa, get_field_style_ptr(ptd->field));
	widget_get_color_mode(widget, &ob);

	_formctrl_field_rect(widget, ptd->field, &xr);
	pt_expand_rect(&xr, DEF_INNER_FEED, DEF_INNER_FEED);

	if (compare_text(editor, -1, ATTR_EDITOR_FIREEDIT, -1, 0) == 0)
	{
		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, NULL))
			return;

		ptd->editor = fireedit_create(widget, &xr);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIREEDIT);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);

		text = get_field_text_ptr(ptd->field);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIRECHECK, -1, 0) == 0)
	{
		if (is_null(get_field_value_ptr(ptd->field)))
			return;

		checked = (compare_text(get_field_text_ptr(ptd->field), -1, get_field_value_ptr(ptd->field), -1, 0) == 0) ? 1 : 0;
		if (checked)
			formctrl_set_field_text(widget, ptd->field, NULL);
		else
			formctrl_set_field_text(widget, ptd->field, get_field_value_ptr(ptd->field));

		_formctrl_reset_group(widget);
		return;
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIRENUM, -1, 0) == 0)
	{
		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, NULL))
			return;

		ptd->editor = firenum_create(widget, &xr);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIRENUM);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);
		editbox_set_xfont(ptd->editor, &xf);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
		
		text = get_field_text_ptr(ptd->field);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIREDATE, -1, 0) == 0)
	{
		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, NULL))
			return;

		ptd->editor = firedate_create(widget, &xr);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIREDATE);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);
		editbox_set_xfont(ptd->editor, &xf);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);

		text = get_field_text_ptr(ptd->field);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIRETIME, -1, 0) == 0)
	{
		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, NULL))
			return;

		ptd->editor = firetime_create(widget, &xr);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIRETIME);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);
		editbox_set_xfont(ptd->editor, &xf);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);

		text = get_field_text_ptr(ptd->field);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIRELIST, -1, 0) == 0)
	{
		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, NULL))
			return;
		
		data = get_field_options_table(ptd->field);
		if (!data)
			return;

		ptd->editor = firelist_create(widget, &xr, data);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIRELIST);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);
		editbox_set_xfont(ptd->editor, &xf);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);

		text = get_field_text_ptr(ptd->field);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIREWORDS, -1, 0) == 0)
	{
		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, (void*)&fd))
			return;

		data = (link_t_ptr)fd.data;
		ptd->editor = firewords_create(widget, &xr, data);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIREWORDS);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);
		editbox_set_xfont(ptd->editor, &xf);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);

		text = get_field_text_ptr(ptd->field);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIREGRID, -1, 0) == 0)
	{
		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, (void*)&fd))
			return;

		data = (link_t_ptr)fd.data;
		if (!data)
			return;

		ptd->editor = firegrid_create(widget, &xr, data);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIREGRID);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);
		editbox_set_xfont(ptd->editor, &xf);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_TABLEBOX, -1, 0) == 0)
	{
		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, &fd))
			return;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
		{
			ptd->editor = tablectrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, widget);
		}
		else
		{
			ptd->editor = tablectrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_VSCROLL, &xr, widget);
		}

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_TABLEBOX);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		tablectrl_set_lock(ptd->editor, 0);
		tablectrl_auto_insert(ptd->editor, 1);

		text = get_field_text_ptr(ptd->field);
		data = create_string_table(0);
		string_table_parse_options(data, text, -1, OPT_ITEMFEED, OPT_LINEFEED);

		tablectrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_GRIDBOX, -1, 0) == 0)
	{
		data = get_field_embed_grid(ptd->field);
		if (!data)
			return;

		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, &fd))
			return;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
		{
			ptd->editor = gridctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, widget);
		}
		else
		{
			ptd->editor = gridctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, widget);
		}

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_GRIDBOX);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		set_grid_width(data, get_field_width(ptd->field));
		set_grid_height(data, get_field_height(ptd->field));

		gridctrl_set_lock(ptd->editor, 0);
		gridctrl_auto_insert(ptd->editor, 1);

		gridctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_STATISBOX, -1, 0) == 0)
	{
		data = get_field_embed_statis(ptd->field);
		if (!data)
			return;

		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, &fd))
			return;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
			ptd->editor = statisctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, widget);
		else
			ptd->editor = statisctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, widget);

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_STATISBOX);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		statisctrl_set_lock(ptd->editor, 0);
		statisctrl_auto_insert(ptd->editor, 1);

		set_statis_width(data, get_field_width(ptd->field));
		set_statis_height(data, get_field_height(ptd->field));

		statisctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FORMBOX, -1, 0) == 0)
	{
		data = get_field_embed_form(ptd->field);
		if (!data)
			return;

		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, &fd))
			return;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
			ptd->editor = formctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, widget);
		else
			ptd->editor = formctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, widget);

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FORMBOX);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		formctrl_set_lock(ptd->editor, 0);

		set_form_width(data, get_field_width(ptd->field));
		set_form_height(data, get_field_height(ptd->field));

		formctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_TAGBOX, -1, 0) == 0)
	{
		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, &fd))
			return;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
			ptd->editor = tagctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, widget);
		else
			ptd->editor = tagctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, widget);

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_TAGBOX);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		tagctrl_set_lock(ptd->editor, 0);

		text = get_field_text_ptr(ptd->field);
		data = create_tag_doc();
		parse_tag_doc(data, text, -1);

		tagctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_MEMOBOX, -1, 0) == 0)
	{
		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, &fd))
			return;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
			ptd->editor = memoctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, widget);
		else
			ptd->editor = memoctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, widget);

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_MEMOBOX);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		memoctrl_set_lock(ptd->editor, 0);

		text = get_field_text_ptr(ptd->field);
		data = create_memo_doc();
		parse_memo_doc(data, text, -1);

		set_memo_width(data, get_field_width(ptd->field));
		set_memo_height(data, get_field_height(ptd->field));
		memoctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_RICHBOX, -1, 0) == 0)
	{
		data = get_field_embed_rich(ptd->field);
		if (!data)
			return;

		if (noti_form_owner(widget, NC_FIELDEDITING, ptd->form, ptd->field, &fd))
			return;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
			ptd->editor = richctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, widget);
		else
			ptd->editor = richctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, widget);

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_RICHBOX);
		widget_set_owner(ptd->editor, widget);

		widget_set_color_mode(ptd->editor, &ob);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		richctrl_set_lock(ptd->editor, 0);

		set_rich_width(data, get_field_width(ptd->field));
		set_rich_height(data, get_field_height(ptd->field));
		richctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}

	if (!widget_is_valid(ptd->editor))
		return;

	set_field_visible(ptd->field, 0);
}

void noti_form_commit_edit(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	widget_t editctrl;
	dword_t uid;
	tchar_t* text;
	int len;
	link_t_ptr item, data;
	bool_t dirty;
	bool_t b_accept = 0;

	EDITDELTA fd = { 0 };

	if (!widget_is_valid(ptd->editor))
		return;

	XDK_ASSERT(ptd->field);

	set_field_visible(ptd->field, 1);

	uid = widget_get_user_id(ptd->editor);

	if (uid == IDC_FIREEDIT)
	{
		text = (tchar_t*)editbox_get_text_ptr(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)text) == 0) ? 1 : 0;
		if (b_accept)
		{
			formctrl_set_field_text(widget, ptd->field, text);
		}
	}
	else if (uid == IDC_FIRELIST)
	{
		text = (tchar_t*)editbox_get_text_ptr(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)text) == 0) ? 1 : 0;
		if (b_accept)
		{
			formctrl_set_field_text(widget, ptd->field, text);
		}
	}
	else if (uid == IDC_FIRENUM)
	{
		text = (tchar_t*)editbox_get_text_ptr(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)text) == 0) ? 1 : 0;
		if (b_accept)
		{
			formctrl_set_field_text(widget, ptd->field, text);
		}
	}
	else if (uid == IDC_FIREDATE)
	{
		text = (tchar_t*)editbox_get_text_ptr(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)text) == 0) ? 1 : 0;
		if (b_accept)
		{
			formctrl_set_field_text(widget, ptd->field, text);
		}
	}
	else if (uid == IDC_FIRETIME)
	{
		text = (tchar_t*)editbox_get_text_ptr(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)text) == 0) ? 1 : 0;
		if (b_accept)
		{
			formctrl_set_field_text(widget, ptd->field, text);
		}
	}
	else if (uid == IDC_FIREWORDS)
	{
		fd.data = firewords_get_data(ptd->editor);
		item = firewords_get_item(ptd->editor);
		if (item)
		{
			editbox_set_text(ptd->editor, get_words_item_text_ptr(item));
		}

		fd.text = editbox_get_text_ptr(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)&fd) == 0) ? 1 : 0;
		if (b_accept)
		{
			formctrl_set_field_text(widget, ptd->field, fd.text);
		}
	}
	else if (uid == IDC_FIREGRID)
	{
		fd.data = firegrid_get_data(ptd->editor);
		fd.item = firegrid_get_item(ptd->editor);

		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)&fd) == 0) ? 1 : 0;
	}
	else if (uid == IDC_TABLEBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		tablectrl_accept(ptd->editor, 1);
		dirty = (get_field_editable(ptd->field)) ? tablectrl_is_update(ptd->editor) : 0;

		data = tablectrl_detach(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)&fd) == 0) ? 1 : 0;
		if (b_accept)
		{
			if (dirty)
			{
				len = string_table_format_options(data, NULL, MAX_LONG, OPT_ITEMFEED, OPT_LINEFEED);
				text = xsalloc(len + 1);
				string_table_format_options(data, text, len, OPT_ITEMFEED, OPT_LINEFEED);

				set_field_text(ptd->field, text, len);
				xsfree(text);

				set_field_dirty(ptd->field, 1);

				noti_form_owner(widget, NC_FIELDUPDATE, ptd->form, ptd->field, NULL);
			}
		}

		destroy_string_table(data);
	}
	else if (uid == IDC_GRIDBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		gridctrl_accept(ptd->editor, 1);
		dirty = (get_field_editable(ptd->field)) ? gridctrl_is_update(ptd->editor) : 0;

		ptd->cur_page = gridctrl_get_cur_page(ptd->editor);

		data = gridctrl_detach(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)&fd) == 0) ? 1 : 0;
		if (b_accept)
		{
			if (dirty)
			{
				set_field_dirty(ptd->field, 1);
				noti_form_owner(widget, NC_FIELDUPDATE, ptd->form, ptd->field, NULL);
			}
		}
	}
	else if (uid == IDC_STATISBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		statisctrl_accept(ptd->editor, 1);
		dirty = (get_field_editable(ptd->field)) ? statisctrl_is_update(ptd->editor) : 0;

		ptd->cur_page = statisctrl_get_cur_page(ptd->editor);

		data = statisctrl_detach(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)&fd) == 0) ? 1 : 0;
		if (b_accept)
		{
			if (dirty)
			{
				set_field_dirty(ptd->field, 1);
				noti_form_owner(widget, NC_FIELDUPDATE, ptd->form, ptd->field, NULL);
			}
		}
	}
	else if (uid == IDC_FORMBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		formctrl_accept(ptd->editor, 1);
		dirty = (get_field_editable(ptd->field)) ? formctrl_is_update(ptd->editor) : 0;

		data = formctrl_detach(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)&fd) == 0) ? 1 : 0;
		if (b_accept)
		{
			if (dirty)
			{
				set_field_dirty(ptd->field, 1);
				noti_form_owner(widget, NC_FIELDUPDATE, ptd->form, ptd->field, NULL);
			}
		}
	}
	else if (uid == IDC_TAGBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		dirty = (get_field_editable(ptd->field)) ? tagctrl_get_dirty(ptd->editor) : 0;

		data = tagctrl_detach(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)&fd) == 0) ? 1 : 0;
		if (b_accept)
		{
			if (dirty)
			{
				len = format_tag_doc(data, NULL, MAX_LONG);
				text = xsalloc(len + 1);
				format_tag_doc(data, text, len);

				set_field_text(ptd->field, text, len);
				xsfree(text);

				set_field_dirty(ptd->field, 1);

				noti_form_owner(widget, NC_FIELDUPDATE, ptd->form, ptd->field, NULL);
			}
		}

		destroy_tag_doc(data);
	}
	else if (uid == IDC_MEMOBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		dirty = (get_field_editable(ptd->field)) ? memoctrl_get_dirty(ptd->editor) : 0;

		ptd->cur_page = memoctrl_get_cur_page(ptd->editor);

		data = memoctrl_detach(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)&fd) == 0) ? 1 : 0;
		if (b_accept)
		{
			if (dirty)
			{
				len = format_memo_doc(data, NULL, MAX_LONG);
				text = xsalloc(len + 1);
				format_memo_doc(data, text, len);

				set_field_text(ptd->field, text, len);
				xsfree(text);

				set_field_dirty(ptd->field, 1);

				noti_form_owner(widget, NC_FIELDUPDATE, ptd->form, ptd->field, NULL);
			}
		}

		destroy_memo_doc(data);
	}
	else if (uid == IDC_RICHBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		dirty = (get_field_editable(ptd->field)) ? richctrl_get_dirty(ptd->editor) : 0;

		ptd->cur_page = richctrl_get_cur_page(ptd->editor);

		data = richctrl_detach(ptd->editor);
		b_accept = (noti_form_owner(widget, NC_FIELDCOMMIT, ptd->form, ptd->field, (void*)&fd) == 0) ? 1 : 0;
		if (b_accept)
		{
			if (dirty)
			{
				set_field_dirty(ptd->field, 1);

				noti_form_owner(widget, NC_FIELDUPDATE, ptd->form, ptd->field, NULL);
			}
		}
	}

	editctrl = ptd->editor;
	ptd->editor = (widget_t)0;

	widget_destroy(editctrl);
	widget_set_focus(widget);

	if (!b_accept)
		return;

	if (IS_DATA_FIELD(get_field_class_ptr(ptd->field)))
	{
		widget_post_key(widget, KEY_TAB);
	}
}

void noti_form_rollback_edit(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	dword_t uid;
	link_t_ptr data;
	widget_t editctrl;

	EDITDELTA fd = { 0 };

	if (!widget_is_valid(ptd->editor))
		return;

	XDK_ASSERT(ptd->field);

	set_field_visible(ptd->field, 1);

	uid = widget_get_user_id(ptd->editor);

	if (uid == IDC_FIREWORDS)
	{
		fd.data = firewords_get_data(ptd->editor);
		fd.text = NULL;
		noti_form_owner(widget, NC_FIELDROLLBACK, ptd->form, ptd->field, (void*)&fd);
	}
	else if (uid == IDC_FIREGRID)
	{
		fd.data = firegrid_get_data(ptd->editor);
		fd.item = NULL;
		noti_form_owner(widget, NC_FIELDROLLBACK, ptd->form, ptd->field, (void*)&fd);
	}
	else if (uid == IDC_TABLEBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		tablectrl_accept(ptd->editor, 0);

		data = tablectrl_detach(ptd->editor);

		noti_form_owner(widget, NC_FIELDROLLBACK, ptd->form, ptd->field, (void*)&fd);

		destroy_string_table(data);
	}
	else if (uid == IDC_GRIDBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		gridctrl_accept(ptd->editor, 0);
		ptd->cur_page = gridctrl_get_cur_page(ptd->editor);
		noti_form_owner(widget, NC_FIELDROLLBACK, ptd->form, ptd->field, (void*)&fd);
	}
	else if (uid == IDC_STATISBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		statisctrl_accept(ptd->editor, 0);
		ptd->cur_page = statisctrl_get_cur_page(ptd->editor);
		noti_form_owner(widget, NC_FIELDROLLBACK, ptd->form, ptd->field, (void*)&fd);
	}
	else if (uid == IDC_FORMBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		formctrl_accept(ptd->editor, 0);
		noti_form_owner(widget, NC_FIELDROLLBACK, ptd->form, ptd->field, (void*)&fd);
	}
	else if (uid == IDC_MEMOBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		ptd->cur_page = memoctrl_get_cur_page(ptd->editor);

		data = memoctrl_detach(ptd->editor);

		noti_form_owner(widget, NC_FIELDROLLBACK, ptd->form, ptd->field, (void*)&fd);

		destroy_memo_doc(data);
	}
	else if (uid == IDC_TAGBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		data = tagctrl_detach(ptd->editor);

		noti_form_owner(widget, NC_FIELDROLLBACK, ptd->form, ptd->field, (void*)&fd);

		destroy_tag_doc(data);
	}
	else if (uid == IDC_RICHBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		ptd->cur_page = richctrl_get_cur_page(ptd->editor);
		noti_form_owner(widget, NC_FIELDROLLBACK, ptd->form, ptd->field, (void*)&fd);
	}
	else
	{
		noti_form_owner(widget, NC_FIELDROLLBACK, ptd->form, ptd->field, NULL);
	}

	editctrl = ptd->editor;
	ptd->editor = (widget_t)0;

	widget_destroy(editctrl);
	widget_set_focus(widget);
}

void noti_form_reset_editor(widget_t widget, bool_t bCommit)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	if (!widget_is_valid(ptd->editor))
		return;

	if (bCommit)
		noti_form_commit_edit(widget);
	else
		noti_form_rollback_edit(widget);
}

void noti_form_reset_scroll(widget_t widget, bool_t bUpdate)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	if (widget_is_valid(ptd->vsc))
	{
		if (bUpdate)
			widget_erase(ptd->vsc, NULL);
		else
			widget_destroy(ptd->vsc);
	}

	if (widget_is_valid(ptd->hsc))
	{
		if (bUpdate)
			widget_erase(ptd->hsc, NULL);
		else
			widget_destroy(ptd->hsc);
	}
}

/*******************************************************************************/
int hand_form_create(widget_t widget, void* data)
{
	form_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (form_delta_t*)xmem_alloc(sizeof(form_delta_t));
	xmem_zero((void*)ptd, sizeof(form_delta_t));

	SETFORMDELTA(widget, ptd);

	ptd->b_lock = 1;

	return 0;
}

void hand_form_destroy(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (widget_is_valid(ptd->hsc))
		widget_destroy(ptd->hsc);

	if (widget_is_valid(ptd->vsc))
		widget_destroy(ptd->vsc);

	xmem_free(ptd);

	SETFORMDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_form_size(widget_t widget, int code, const xsize_t* prs)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	switch(code)
	{
	case WS_SIZE_FULLSCREEN:
		break;
	case WS_SIZE_MAXIMIZED:
		break;
	case WS_SIZE_MINIMIZED:
		break;
	case WS_SIZE_MAXSHOW:
		break;
	case WS_SIZE_RESTORE:
		break;
	case WS_SIZE_LAYOUT:
		break;
	}

	_formctrl_reset_page(widget);
}

void hand_form_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	xrect_t xr;

	if (!ptd->form)
		return;

	if (widget_is_valid(ptd->editor))
	{
		if (!IS_AUTO_FIELD(get_field_class_ptr(ptd->field)))
		{
			noti_form_reset_editor(widget, 1);
		}
	}

	if (!widget_hand_scroll(widget, bHorz, nLine))
		return;

	if (widget_is_valid(ptd->editor))
	{
		_formctrl_field_rect(widget, ptd->field, &xr);
		widget_move(ptd->editor, RECTPOINT(&xr));
	}
}

void hand_form_wheel(widget_t widget, bool_t bHorz, int nDelta)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	scroll_t scr = { 0 };
	int nLine;
	widget_t win;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return;

	widget_get_scroll_info(widget, bHorz, &scr);

	if (bHorz)
		nLine = (nDelta > 0) ? scr.min : -scr.min;
	else
		nLine = (nDelta < 0) ? scr.min : -scr.min;

	if (widget_hand_scroll(widget, bHorz, nLine))
	{
		if (!bHorz && !(widget_get_style(widget) & WD_STYLE_VSCROLL))
		{
			if (!widget_is_valid(ptd->vsc))
			{
				ptd->vsc = show_vertbox(widget);
			}
			else
			{
				widget_erase(ptd->vsc, NULL);
			}
		}

		if (bHorz && !(widget_get_style(widget) & WD_STYLE_HSCROLL))
		{
			if (!widget_is_valid(ptd->hsc))
			{
				ptd->hsc = show_horzbox(widget);
			}
			else
			{
				widget_erase(ptd->hsc, NULL);
			}
		}

		return;
	}

	win = widget_get_parent(widget);

	if (widget_is_valid(win))
	{
		widget_scroll(win, bHorz, nLine);
	}
}

void hand_form_mouse_hover(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	if (!ptd->form)
		return;

	if (ptd->hover)
		noti_form_field_hover(widget, pxp->x, pxp->y);
}

void hand_form_mouse_leave(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	if (!ptd->form)
		return;

	if (ptd->hover)
		noti_form_field_leave(widget);
}

void hand_form_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	
	if (!ptd->form)
		return;

	noti_form_reset_editor(widget, 1);

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}
}

void hand_form_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	//int nHint;
	link_t_ptr flk;
	bool_t bRe = 0, bAuto = 0;
	xpoint_t pt;

	if (!ptd->form)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	flk = NULL;
	calc_form_hint(&pt, ptd->form, &flk);

	bRe = (flk == ptd->field) ? 1 : 0;

	if (!ptd->b_lock && bRe && flk && get_field_editable(flk))
	{
		widget_post_key(widget, KEY_ENTER);
		return;
	}

	if (ptd->field && !bRe)
	{
		if (!noti_form_field_changing(widget))
			bRe = 1;
	}

	if (flk && !get_field_focusable(flk))
		flk = NULL;

	if (flk && !bRe)
	{
		noti_form_field_changed(widget, flk);

		if (IS_AUTO_FIELD(get_field_class_ptr(flk)))
			bAuto = 1;
	}

	noti_form_owner(widget, NC_FORMLBCLK, ptd->form, ptd->field, (void*)pxp);

	if (!ptd->b_lock && bAuto && flk && get_field_editable(flk))
	{
		widget_post_key(widget, KEY_ENTER);
	}
}

void hand_form_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	if (!ptd->form)
		return;

	noti_form_reset_editor(widget, 1);

	noti_form_owner(widget, NC_FORMDBCLK, ptd->form, ptd->field, (void*)pxp);
}

void hand_form_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	if (!ptd->form)
		return;

	noti_form_reset_editor(widget, 1);
}

void hand_form_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	if (!ptd->form)
		return;

	noti_form_owner(widget, NC_FORMRBCLK, ptd->form, ptd->field, (void*)pxp);
}

void hand_form_keydown(widget_t widget, dword_t ks, int nKey)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	if (!ptd->form)
		return;

	if (nKey == KEY_ENTER && ptd->field)
	{
		if (widget_can_focus(widget) && !ptd->b_lock)
		{
			noti_form_begin_edit(widget);
		}
	}
	else if (nKey == KEY_TAB)
	{
		formctrl_tabskip(widget, TABORDER_RIGHT);
	}
	else if (nKey == KEY_LEFT || nKey == KEY_UP) // KEY_LEFT KEY_UP
	{
		formctrl_tabskip(widget, TABORDER_LEFT);
	}
	else if (nKey == KEY_RIGHT || nKey == KEY_DOWN) // KEY_RIGHT KEY_DOWN
	{
		formctrl_tabskip(widget, TABORDER_RIGHT);
	}
	else if (nKey == KEY_END) // vk_end
	{
		formctrl_move_last_page(widget);
	}
	else if (nKey == KEY_HOME) // vk_home
	{
		formctrl_move_first_page(widget);
	}
	else if (nKey == KEY_PAGEUP) // PAGEUP
	{
		formctrl_move_prev_page(widget);
	}
	else if (nKey == KEY_PAGEDOWN) // PAGEDOWN
	{
		formctrl_move_next_page(widget);
	}
}

void hand_form_wchar(widget_t widget, wchar_t nChar)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	if (!ptd->form)
		return;

	if (IS_VISIBLE_CHAR(nChar) && !widget_is_valid(ptd->editor))
	{
		hand_form_keydown(widget, 0, KEY_ENTER);
	}

	if (IS_VISIBLE_CHAR(nChar) && widget_is_valid(ptd->editor))
	{
		widget_post_wchar(ptd->editor, nChar);
	}
}

void hand_form_child_command(widget_t widget, int code, vword_t data)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	switch (code)
	{
	case COMMAND_COMMIT:
		noti_form_commit_edit(widget);
		break;
	case COMMAND_ROLLBACK:
		noti_form_rollback_edit(widget);
		break;
	}
}

void hand_form_menu_command(widget_t widget, int code, int cid, vword_t data)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	if (ptd->form)
	{
		if (cid == IDC_EDITMENU)
		{
			if (widget_is_valid((widget_t)data))
			{
				widget_close((widget_t)data, 1);
			}
		}
	}
	else
	{
		if (!widget_is_valid(ptd->editor))
			return;

		if (widget_get_user_id(ptd->editor) == cid && code)
		{
			widget_post_command(widget_get_owner(widget), code, IDC_CHILD, (vword_t)ptd->editor);
		}
	}
}

void hand_form_notice(widget_t widget, NOTICE* pnt)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	if (!ptd->form)
		return;

	if (pnt->user == IDC_GRIDBOX)
	{
		noti_form_owner(widget, NC_FIELDGRID, ptd->form, ptd->field, (void*)pnt);
	}
	else if (pnt->user == IDC_STATISBOX)
	{
		noti_form_owner(widget, NC_FIELDSTATIS, ptd->form, ptd->field, (void*)pnt);
	}
	else if (pnt->user == IDC_IMAGESBOX)
	{
		noti_form_owner(widget, NC_FIELDIMAGES, ptd->form, ptd->field, (void*)pnt);
	}
	else if (pnt->user == IDC_FORMBOX)
	{
		noti_form_owner(widget, NC_FIELDFORM, ptd->form, ptd->field, (void*)pnt);
	}
	else if (pnt->user == IDC_PHOTOBOX)
	{
		noti_form_owner(widget, NC_FIELDPHOTO, ptd->form, ptd->field, (void*)pnt);
	}
	else if (pnt->user == IDC_RICHBOX)
	{
		noti_form_owner(widget, NC_FIELDRICH, ptd->form, ptd->field, (void*)pnt);
	}else if (pnt->user == IDC_RICHBOX)
	{
		noti_form_owner(widget, NC_FIELDRICH, ptd->form, ptd->field, (void*)pnt);
	}
	else if (pnt->user == IDC_TAGBOX)
	{
		noti_form_owner(widget, NC_FIELDTAG, ptd->form, ptd->field, (void*)pnt);
	}
	else if (pnt->user == IDC_MEMOBOX)
	{
		noti_form_owner(widget, NC_FIELDMEMO, ptd->form, ptd->field, (void*)pnt);
	}
}

void hand_form_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	xrect_t xr = { 0 };
	xsize_t xs = { 0 };
	visual_t rdc;
	link_t_ptr flk;

	canvas_t canv;
	drawing_interface ifc = {0};
	drawing_interface ifv = {0};

	const color_mod_t *pclrs;
	xbrush_t xb;
	xpen_t xp;
	xcolor_t xc;

	if (!ptd->form) return;

	pclrs = widget_get_color_mode_ptr(widget);
	default_xbrush(&xb);
	format_xcolor(&(pclrs->clr_bkg), xb.color);
	default_xpen(&xp);
	format_xcolor(&(pclrs->clr_frg), xp.color);

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);
	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
	
	get_visual_interface(rdc, &ifv);
	widget_get_view_rect(widget, (viewbox_t*)&(ifv.rect));

	get_canvas_interface(canv, &ifc);
	widget_get_canv_rect(widget, (canvbox_t*)&(ifc.rect));
	ifc.pclrs = pclrs;

	//(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	if (widget_can_paging(widget))
	{
		/*if (!b_design)
		{
			xmem_copy((void*)&xr, (void*)&cb, sizeof(xrect_t));
			ft_expand_rect(&xr, 4.0, 4.0);

			draw_shape(canv, &xp, NULL, &xr, ATTR_SHAPE_RECT);
		}*/

		xmem_copy((void*)&xc, (void*)&(pclrs->clr_frg), sizeof(xcolor_t));
		draw_corner(&ifc, &xc, (const xrect_t*)&(ifc.rect));
	}

	set_form_design(ptd->form, 1);
	draw_form_page(&ifc, ptd->form, ptd->cur_page);
	set_form_design(ptd->form, 0);

	//draw focus
	if (ptd->field)
	{
		_formctrl_field_rect(widget, ptd->field, &xr);

		if (ptd->b_alarm)
		{
			parse_xcolor(&xc, DEF_ALARM_COLOR);

			draw_focus_raw(&ifv, &xc, &xr, ALPHA_SOLID);
		}
		else
		{
			if (get_field_editable(ptd->field))
				parse_xcolor(&xc, DEF_ENABLE_COLOR);
			else
				parse_xcolor(&xc, DEF_DISABLE_COLOR);

			draw_feed_raw(&ifv, &xc, &xr, ALPHA_SOLID);
		}
	}

	end_canvas_paint(canv, dc, pxr);
	
}

/***********************************************function********************************************************/

widget_t formctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_form_create)
		EVENT_ON_DESTROY(hand_form_destroy)

		EVENT_ON_PAINT(hand_form_paint)

		EVENT_ON_SIZE(hand_form_size)

		EVENT_ON_SCROLL(hand_form_scroll)
		EVENT_ON_WHEEL(hand_form_wheel)

		EVENT_ON_KEYDOWN(hand_form_keydown)
		EVENT_ON_WCHAR(hand_form_wchar)

		EVENT_ON_MOUSE_HOVER(hand_form_mouse_hover)
		EVENT_ON_MOUSE_LEAVE(hand_form_mouse_leave)

		EVENT_ON_LBUTTON_DBCLICK(hand_form_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_form_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_form_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_form_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_form_rbutton_up)

		EVENT_ON_NOTICE(hand_form_notice)
		EVENT_ON_CHILD_COMMAND(hand_form_child_command)
		EVENT_ON_MENU_COMMAND(hand_form_menu_command)

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void formctrl_attach(widget_t widget, link_t_ptr ptr)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(ptr && is_form_doc(ptr));

	noti_form_reset_editor(widget, 0);

	ptd->form = ptr;
	ptd->field = NULL;
	ptd->cur_page = 1;

	formctrl_redraw(widget, 1);
}

link_t_ptr formctrl_detach(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	link_t_ptr data;

	XDK_ASSERT(ptd != NULL);

	noti_form_reset_editor(widget, 0);

	data = ptd->form;
	ptd->form = NULL;
	ptd->field = NULL;
	ptd->cur_page = 0;

	widget_erase(widget, NULL);

	return data;
}

link_t_ptr formctrl_fetch(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->form;
}

widget_t formctrl_get_editor(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	return ptd->editor;
}

bool_t formctrl_verify(widget_t widget, bool_t bAlarm)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	link_t_ptr flk;
	int code;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return 1;

	noti_form_reset_editor(widget, (bool_t)0);

	code = verify_form_doc(ptd->form, &flk);
	if (veValid != code)
	{
		ptd->b_alarm = (bool_t)1;

		formctrl_set_focus_field(widget, flk);
		
		return (bool_t)0;
	}
	else
		return (bool_t)1;
}

void formctrl_accept(widget_t widget, bool_t bAccept)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return;

	noti_form_reset_editor(widget, bAccept);
}

void formctrl_redraw(widget_t widget, bool_t bCalc)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	link_t_ptr flk;
	bool_t b_valid;
	drawing_interface ifc = {0};

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return;

	noti_form_reset_editor(widget, 0);

	if (bCalc)
	{
		calc_form_doc(ptd->form);
	}

	b_valid = 0;
	flk = get_next_field(ptd->form, LINK_FIRST);
	while (flk)
	{
		if (flk == ptd->field)
			b_valid = 1;

		noti_form_owner(widget, NC_FIELDCALCED, ptd->form, flk, NULL);

		flk = get_next_field(ptd->form, flk);
	}
	
	noti_form_owner(widget, NC_FORMCALCED, ptd->form, NULL, NULL);

	if (!b_valid)
	{
		ptd->field = NULL;
	}
	ptd->hover = NULL;

	_formctrl_reset_page(widget);

	if (bCalc)
	{
		get_canvas_interface(widget_get_canvas(widget), &ifc);

		ptd->max_page = calc_form_pages(&ifc, ptd->form);
	}
	
	widget_erase(widget, NULL);
}

void formctrl_redraw_field(widget_t widget, link_t_ptr flk, bool_t bCalc)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	xrect_t xr;
	drawing_interface ifc = {0};

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return;

#ifdef _DEBUG
	if(!is_form_field(ptd->form, flk))
		return;
#endif

	if (bCalc)
	{
		calc_form_field(ptd->form, flk);

		get_canvas_interface(widget_get_canvas(widget), &ifc);

		ptd->max_page = (short)calc_form_pages(&ifc, ptd->form);
	}
	
	noti_form_owner(widget, NC_FIELDCALCED, ptd->form, flk, NULL);

	_formctrl_field_rect(widget, flk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

void formctrl_tabskip(widget_t widget, int nSkip)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	link_t_ptr flk = NULL;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return;

	noti_form_reset_editor(widget, (bool_t)1);

	switch (nSkip)
	{
	case TABORDER_LEFT:
	case TABORDER_UP:
		if (ptd->field == NULL)
			flk = get_prev_focusable_field(ptd->form, LINK_LAST);
		else
			flk = get_prev_focusable_field(ptd->form, ptd->field);
		break;
	case TABORDER_RIGHT:
	case TABORDER_DOWN:
		if (ptd->field == NULL)
			flk = get_next_focusable_field(ptd->form, LINK_FIRST);
		else
			flk = get_next_focusable_field(ptd->form, ptd->field);
		break;
	case TABORDER_HOME:
		flk = get_next_focusable_field(ptd->form, LINK_FIRST);
		break;
	case TABORDER_END:
		flk = get_prev_focusable_field(ptd->form, LINK_LAST);
		break;
	}

	formctrl_set_focus_field(widget, flk);
}

bool_t formctrl_set_focus_field(widget_t widget, link_t_ptr flk)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	bool_t bRe;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return 0;

	if (flk == LINK_FIRST)
		flk = get_next_focusable_field(ptd->form, LINK_FIRST);
	else if (flk == LINK_LAST)
		flk = get_prev_focusable_field(ptd->form, LINK_LAST);

	bRe = (flk == ptd->field) ? (bool_t)1 : (bool_t)0;
	if (bRe)
		return (bool_t)1;

	if (ptd->field && !bRe)
	{
		if (!noti_form_field_changing(widget))
			return (bool_t)0;
	}

	if (flk && !bRe)
	{
		noti_form_field_changed(widget, flk);

		_formctrl_ensure_visible(widget);
	}

	return (bool_t)1;
}

link_t_ptr formctrl_get_focus_field(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return NULL;

	return ptd->field;
}

void formctrl_move_first_page(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return;

	if (ptd->cur_page != 1)
	{
		noti_form_reset_editor(widget, (bool_t)1);

		ptd->cur_page = 1;

		widget_erase(widget, NULL);
	}
}

void formctrl_move_last_page(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return;

	if (ptd->cur_page != ptd->max_page)
	{
		noti_form_reset_editor(widget, (bool_t)1);

		ptd->cur_page = ptd->max_page;
		widget_erase(widget, NULL);
	}
}

void formctrl_move_next_page(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return;

	if (ptd->cur_page < ptd->max_page)
	{
		noti_form_reset_editor(widget, (bool_t)1);

		ptd->cur_page++;

		widget_erase(widget, NULL);
	}
}

void formctrl_move_prev_page(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return;

	if (ptd->cur_page > 1)
	{
		noti_form_reset_editor(widget, (bool_t)1);

		ptd->cur_page--;

		widget_erase(widget, NULL);
	}
}

int formctrl_get_cur_page(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return 0;

	return ptd->cur_page;
}

int formctrl_get_max_page(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	drawing_interface ifc = {0};

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return 0;

	get_canvas_interface(widget_get_canvas(widget), &ifc);

	return calc_form_pages(&ifc, ptd->form);
}

void formctrl_move_to_page(widget_t widget, int page)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return;

	if (page > ptd->max_page || page < 1)
		return;

	noti_form_reset_editor(widget, (bool_t)1);

	ptd->cur_page = page;

	widget_erase(widget, NULL);
}

bool_t formctrl_set_field_text(widget_t widget, link_t_ptr flk, const tchar_t* szText)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	xrect_t xr;
	const tchar_t* text;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return 0;

#ifdef _DEBUG
	XDK_ASSERT(is_form_field(ptd->form, flk));
#endif

	if (!IS_DATA_FIELD(get_field_class_ptr(flk)))
		return 0;

	text = get_field_text_ptr(flk);
	if (compare_data(szText, text, get_field_data_type_ptr(flk)) == 0)
		return 1;

	if (veValid != verify_text(szText, get_field_data_type_ptr(flk), get_field_nullable(flk), get_field_data_len(flk), get_field_data_min_ptr(flk), get_field_data_max_ptr(flk)))
		return 0;

	set_field_text(flk, szText, -1);
	set_field_dirty(flk, 1);

	noti_form_owner(widget, NC_FIELDUPDATE, ptd->form, flk, NULL);

	formctrl_get_field_rect(widget, flk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);
	widget_erase(widget, &xr);

	if (get_field_fireable(flk))
	{
		if (calc_form_doc(ptd->form))
		{
			widget_erase(widget, NULL);
		}
	}

	return 1;
}

bool_t formctrl_is_update(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return get_update_field_count(ptd->form) ? 1 : 0;
}

void formctrl_get_field_rect(widget_t widget, link_t_ptr flk, xrect_t* pxr)
{
	form_delta_t* ptd = GETFORMDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	if (!ptd->form)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_form_field(ptd->form, flk));
#endif

	_formctrl_field_rect(widget, flk, pxr);
}

bool_t formctrl_get_lock(widget_t widget)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->b_lock;
}

void formctrl_set_lock(widget_t widget, bool_t bLock)
{
	form_delta_t* ptd = GETFORMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_lock = bLock;
}

bool_t formctrl_get_dirty(widget_t widget)
{
	return 0;
}

void formctrl_set_dirty(widget_t widget, bool_t b_dirty)
{
	NOP;
}
