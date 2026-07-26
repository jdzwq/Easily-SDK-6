/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc editor document

	@module	editor.c | implement file

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

#include "editor.h"

#include "../xdcobj.h"


typedef struct _editor_context{
	widget_t widget;
	widget_t editor;
	editor_interface editif;
}editor_context;

/***********************************************************************/

static int _editor_noti_begin_edit(editor_context* ptd)
{
	editor_interface* pdi = &(ptd->editif);

	tchar_t editor[KEY_LEN + 1] = {0};
	tchar_t styles[META_LEN + 1] = {0};
	xrect_t xr = {0};

	xfont_t xf;
	xface_t xa;
	color_mod_t clrs;

	const tchar_t* text;
	link_t_ptr data;
	EDITDELTA fd = { 0 };

	if(!(*pdi->pf_get_obj_info)(ptd->widget, editor, styles))
		return 1;

	(*pdi->pf_get_obj_rect)(ptd->widget, &xr);

	default_textor_xfont(&xf);
	if(!xsisnil(styles)){parse_xfont_from_style(&xf, styles);}
	default_textor_xface(&xa);
	if(!xsisnil(styles)){parse_xface_from_style(&xa, styles);}

	widget_get_color_mode(ptd->widget, &clrs);
	format_xcolor(&(clrs.clr_txt), xa.text_color);

	pt_expand_rect(&xr, DEF_INNER_FEED, DEF_INNER_FEED);

	if (compare_text(editor, -1, ATTR_EDITOR_FIREEDIT, -1, 0) == 0)
	{
		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, NULL))
			return 0;

		ptd->editor = fireedit_create(ptd->widget, &xr);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIREEDIT);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);

		text = (const tchar_t*)(*pdi->pf_get_obj_data)(ptd->widget);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIRECHECK, -1, 0) == 0)
	{
		/*if (xsisnil(get_field_value_ptr(ptd->field)))
			return 0;

		checked = (compare_text(get_field_text_ptr(ptd->field), -1, get_field_value_ptr(ptd->field), -1, 0) == 0) ? 1 : 0;
		if (checked)
			formctrl_set_field_text(ptd->widget, ptd->field, NULL);
		else
			formctrl_set_field_text(ptd->widget, ptd->field, get_field_value_ptr(ptd->field));

		_formctrl_reset_group(ptd->widget);*/
		return 1;
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIRENUM, -1, 0) == 0)
	{
		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, NULL))
			return 0;

		ptd->editor = firenum_create(ptd->widget, &xr);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIRENUM);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
		
		text = (const tchar_t*)(*pdi->pf_get_obj_data)(ptd->widget);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIREDATE, -1, 0) == 0)
	{
		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, NULL))
			return 0;

		ptd->editor = firedate_create(ptd->widget, &xr);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIREDATE);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);

		text = (const tchar_t*)(*pdi->pf_get_obj_data)(ptd->widget);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIRETIME, -1, 0) == 0)
	{
		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, NULL))
			return 0;

		ptd->editor = firetime_create(ptd->widget, &xr);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIRETIME);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);

		text = (const tchar_t*)(*pdi->pf_get_obj_data)(ptd->widget);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIRELIST, -1, 0) == 0)
	{
		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, NULL))
			return 0;
		
		data = (link_t_ptr)(*pdi->pf_get_obj_data)(ptd->widget);
		if (!data) return 0;

		ptd->editor = firelist_create(ptd->widget, &xr, data);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIRELIST);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);

		text = (const tchar_t*)(*pdi->pf_get_obj_data)(ptd->widget);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIREWORDS, -1, 0) == 0)
	{
		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, (void*)&fd))
			return 0;

		data = (link_t_ptr)fd.data;
		if (!data) return 0;

		ptd->editor = firewords_create(ptd->widget, &xr, data);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIREWORDS);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);

		text = (const tchar_t*)(*pdi->pf_get_obj_data)(ptd->widget);
		editbox_set_text(ptd->editor, text);
		editbox_selectall(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FIREGRID, -1, 0) == 0)
	{
		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, (void*)&fd))
			return 0;

		data = (link_t_ptr)fd.data;
		if (!data) return 0;

		ptd->editor = firegrid_create(ptd->widget, &xr, data);
		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FIREGRID);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_TABLEBOX, -1, 0) == 0)
	{
		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, (void*)&fd))
			return 0;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
		{
			ptd->editor = tablectrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, ptd->widget);
		}
		else
		{
			ptd->editor = tablectrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_VSCROLL, &xr, ptd->widget);
		}

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_TABLEBOX);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		tablectrl_set_lock(ptd->editor, 0);
		tablectrl_auto_insert(ptd->editor, 1);

		text = (const tchar_t*)(*pdi->pf_get_obj_data)(ptd->widget);
		data = create_string_table(0);
		string_table_parse_options(data, text, -1, OPT_ITEMFEED, OPT_LINEFEED);

		tablectrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_GRIDBOX, -1, 0) == 0)
	{
		data = (link_t_ptr)(*pdi->pf_get_obj_data)(ptd->widget);
		if (!data) return 0;

		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, (void*)&fd))
			return 0;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
		{
			ptd->editor = gridctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, ptd->widget);
		}
		else
		{
			ptd->editor = gridctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, ptd->widget);
		}

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_GRIDBOX);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		widget_rect_to_mm(ptd->widget, &xr);
		ft_expand_rect(&xr, -DEF_EDGE_FEED, -DEF_EDGE_FEED);
		set_grid_width(data, xr.fw);
		set_grid_height(data, xr.fh);

		gridctrl_set_lock(ptd->editor, 0);
		gridctrl_auto_insert(ptd->editor, 1);

		gridctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_STATISBOX, -1, 0) == 0)
	{
		data = (link_t_ptr)(*pdi->pf_get_obj_data)(ptd->widget);
		if (!data) return 0;

		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, (void*)&fd))
			return 0;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
			ptd->editor = statisctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, ptd->widget);
		else
			ptd->editor = statisctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, ptd->widget);

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_STATISBOX);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		statisctrl_set_lock(ptd->editor, 0);
		statisctrl_auto_insert(ptd->editor, 1);

		widget_rect_to_mm(ptd->widget, &xr);
		ft_expand_rect(&xr, -DEF_EDGE_FEED, -DEF_EDGE_FEED);
		set_statis_width(data, xr.fw);
		set_statis_height(data, xr.fh);

		statisctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_FORMBOX, -1, 0) == 0)
	{
		data = (link_t_ptr)(*pdi->pf_get_obj_data)(ptd->widget);
		if (!data) return 0;

		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, (void*)&fd))
			return 0;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
			ptd->editor = formctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, ptd->widget);
		else
			ptd->editor = formctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, ptd->widget);

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_FORMBOX);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		formctrl_set_lock(ptd->editor, 0);

		widget_rect_to_mm(ptd->widget, &xr);
		ft_expand_rect(&xr, -DEF_EDGE_FEED, -DEF_EDGE_FEED);
		set_form_width(data, xr.fw);
		set_form_height(data, xr.fh);

		formctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_TAGBOX, -1, 0) == 0)
	{
		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, (void*)&fd))
			return 0;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
			ptd->editor = tagctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, ptd->widget);
		else
			ptd->editor = tagctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, ptd->widget);

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_TAGBOX);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		tagctrl_set_lock(ptd->editor, 0);

		text = (const tchar_t*)(*pdi->pf_get_obj_data)(ptd->widget);
		data = create_tag_doc();
		parse_tag_doc(data, text, -1);

		tagctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_MEMOBOX, -1, 0) == 0)
	{
		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, (void*)&fd))
			return 0;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
			ptd->editor = memoctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, ptd->widget);
		else
			ptd->editor = memoctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, ptd->widget);

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_MEMOBOX);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		memoctrl_set_lock(ptd->editor, 0);

		text = (const tchar_t*)(*pdi->pf_get_obj_data)(ptd->widget);
		data = create_memo_doc();
		parse_memo_doc(data, text, -1);

		widget_rect_to_mm(ptd->widget, &xr);
		ft_expand_rect(&xr, -DEF_EDGE_FEED, -DEF_EDGE_FEED);
		set_memo_width(data, xr.fw);
		set_memo_height(data, xr.fh);
		memoctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}
	else if (compare_text(editor, -1, ATTR_EDITOR_RICHBOX, -1, 0) == 0)
	{
		data = (link_t_ptr)(*pdi->pf_get_obj_data)(ptd->widget);
		if (!data) return 0;

		if ((*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_EDITING, (void*)&fd))
			return 0;

		pt_expand_rect(&xr, -DEF_INNER_FEED, -DEF_INNER_FEED);

		if (fd.menu)
			ptd->editor = richctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL | WD_STYLE_MENUBAR, &xr, ptd->widget);
		else
			ptd->editor = richctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_HSCROLL | WD_STYLE_VSCROLL, &xr, ptd->widget);

		XDK_ASSERT(ptd->editor);
		widget_set_user_id(ptd->editor, IDC_RICHBOX);
		widget_set_owner(ptd->editor, ptd->widget);

		widget_set_color_mode(ptd->editor, &clrs);
		editbox_set_xfont(ptd->editor, &xf);
		editbox_set_xface(ptd->editor, &xa);

		if (fd.menu)
		{
			widget_attach_menu(ptd->editor, fd.menu);
		}

		richctrl_set_lock(ptd->editor, 0);

		widget_rect_to_mm(ptd->widget, &xr);
		ft_expand_rect(&xr, -DEF_EDGE_FEED, -DEF_EDGE_FEED);
		set_rich_width(data, xr.fw);
		set_rich_height(data, xr.fh);
		richctrl_attach(ptd->editor, data);

		widget_show(ptd->editor, WS_SHOW_NORMAL);
		widget_set_focus(ptd->editor);
	}

	return 1;
}

void _editor_noti_commit_edit(editor_context* ptd)
{
	editor_interface* pdi = &(ptd->editif);

	widget_t editctrl;
	dword_t uid;
	tchar_t* text;
	int len;
	link_t_ptr item, data;
	bool_t b_auto, b_dirty = 0;
	int n_accept = 0;

	EDITDELTA fd = { 0 };

	XDK_ASSERT(widget_is_valid(ptd->editor));

	uid = widget_get_user_id(ptd->editor);

	if (uid == IDC_FIREEDIT)
	{
		text = (tchar_t*)editbox_get_text_ptr(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)text);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			b_dirty = (*pdi->pf_set_obj_data)(ptd->widget, (void*)text);
		}
	}
	else if (uid == IDC_FIRELIST)
	{
		text = (tchar_t*)editbox_get_text_ptr(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)text);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			b_dirty = (*pdi->pf_set_obj_data)(ptd->widget, (void*)text);
		}
	}
	else if (uid == IDC_FIRENUM)
	{
		text = (tchar_t*)editbox_get_text_ptr(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)text);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			b_dirty = (*pdi->pf_set_obj_data)(ptd->widget, (void*)text);
		}
	}
	else if (uid == IDC_FIREDATE)
	{
		text = (tchar_t*)editbox_get_text_ptr(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)text);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			b_dirty = (*pdi->pf_set_obj_data)(ptd->widget, (void*)text);
		}
	}
	else if (uid == IDC_FIRETIME)
	{
		text = (tchar_t*)editbox_get_text_ptr(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)text);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			b_dirty = (*pdi->pf_set_obj_data)(ptd->widget, (void*)text);
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
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)&fd);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			b_dirty = (*pdi->pf_set_obj_data)(ptd->widget, (void*)fd.text);
		}
	}
	else if (uid == IDC_FIREGRID)
	{
		fd.data = firegrid_get_data(ptd->editor);
		fd.item = firegrid_get_item(ptd->editor);

		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)&fd);
		b_dirty = bool_true;
	}
	else if (uid == IDC_TABLEBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		tablectrl_accept(ptd->editor, 1);
		b_dirty = tablectrl_is_update(ptd->editor);

		data = tablectrl_detach(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)&fd);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			if (b_dirty)
			{
				len = string_table_format_options(data, NULL, MAX_LONG, OPT_ITEMFEED, OPT_LINEFEED);
				text = xsalloc(len + 1);
				string_table_format_options(data, text, len, OPT_ITEMFEED, OPT_LINEFEED);

				b_dirty = (*pdi->pf_set_obj_data)(ptd->widget, (void*)text);
				xsfree(text);
			}
		}

		destroy_string_table(data);
	}
	else if (uid == IDC_GRIDBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		gridctrl_accept(ptd->editor, 1);
		b_dirty = gridctrl_is_update(ptd->editor);

		data = gridctrl_detach(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)&fd);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			if (b_dirty)
			{
				(*pdi->pf_set_obj_dirty)(ptd->widget);
			}
		}
	}
	else if (uid == IDC_STATISBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		statisctrl_accept(ptd->editor, 1);
		b_dirty = statisctrl_is_update(ptd->editor);

		data = statisctrl_detach(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)&fd);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			if (b_dirty)
			{
				(*pdi->pf_set_obj_dirty)(ptd->widget);
			}
		}
	}
	else if (uid == IDC_FORMBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		formctrl_accept(ptd->editor, 1);
		b_dirty = formctrl_is_update(ptd->editor);

		data = formctrl_detach(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)&fd);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			if (b_dirty)
			{
				(*pdi->pf_set_obj_dirty)(ptd->widget);
			}
		}
	}
	else if (uid == IDC_TAGBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		b_dirty = tagctrl_get_dirty(ptd->editor);

		data = tagctrl_detach(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)&fd);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			if (b_dirty)
			{
				len = format_tag_doc(data, NULL, MAX_LONG);
				text = xsalloc(len + 1);
				format_tag_doc(data, text, len);

				b_dirty = (*pdi->pf_set_obj_data)(ptd->widget, (void*)text);
				xsfree(text);
			}
		}

		destroy_tag_doc(data);
	}
	else if (uid == IDC_MEMOBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		b_dirty = memoctrl_get_dirty(ptd->editor);

		data = memoctrl_detach(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)&fd);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			if (b_dirty)
			{
				len = format_memo_doc(data, NULL, MAX_LONG);
				text = xsalloc(len + 1);
				format_memo_doc(data, text, len);

				b_dirty = (*pdi->pf_set_obj_data)(ptd->widget, (void*)text);
				xsfree(text);
			}
		}

		destroy_memo_doc(data);
	}
	else if (uid == IDC_RICHBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		b_dirty = richctrl_get_dirty(ptd->editor);

		data = richctrl_detach(ptd->editor);
		n_accept = (*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_COMMIT, (void*)&fd);
		if (n_accept == RET_NOTICE_ACCEPT)
		{
			if (b_dirty)
			{
				(*pdi->pf_set_obj_dirty)(ptd->widget);
			}
		}
	}

	editctrl = ptd->editor;
	ptd->editor = (widget_t)0;

	widget_destroy(editctrl);
	widget_set_focus(ptd->widget);

	switch(n_accept)
	{
	case RET_NOTICE_ACCEPT:
		if (b_dirty)
		{
			(*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_UPDATE, NULL);
		}
		b_auto = (*pdi->pf_get_obj_auto)(ptd->widget);
		if (!b_auto)
		{
			widget_post_key(ptd->widget, KEY_TAB);
		}
		return;
	case RET_NOTICE_REJECT:
		return;
	case RET_NOTICE_DELETE:
		widget_post_key(ptd->widget, KEY_DELETE);
		return;
	}
}

void _editor_noti_rollback_edit(editor_context* ptd)
{
	editor_interface* pdi = &(ptd->editif);

	dword_t uid;
	link_t_ptr data;
	widget_t editctrl;

	EDITDELTA fd = { 0 };

	XDK_ASSERT(widget_is_valid(ptd->editor));

	uid = widget_get_user_id(ptd->editor);

	if (uid == IDC_FIREWORDS)
	{
		fd.data = firewords_get_data(ptd->editor);
		fd.text = NULL;
		(*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_ROLLBACK, (void*)&fd);
	}
	else if (uid == IDC_FIREGRID)
	{
		fd.data = firegrid_get_data(ptd->editor);
		fd.item = NULL;
		(*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_ROLLBACK, (void*)&fd);
	}
	else if (uid == IDC_TABLEBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		tablectrl_accept(ptd->editor, 0);

		data = tablectrl_detach(ptd->editor);

		(*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_ROLLBACK, (void*)&fd);

		destroy_string_table(data);
	}
	else if (uid == IDC_GRIDBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		gridctrl_accept(ptd->editor, 0);
		(*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_ROLLBACK, (void*)&fd);
	}
	else if (uid == IDC_STATISBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		statisctrl_accept(ptd->editor, 0);
		(*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_ROLLBACK, (void*)&fd);
	}
	else if (uid == IDC_FORMBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		formctrl_accept(ptd->editor, 0);
		(*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_ROLLBACK, (void*)&fd);
	}
	else if (uid == IDC_MEMOBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);
		data = memoctrl_detach(ptd->editor);

		(*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_ROLLBACK, (void*)&fd);

		destroy_memo_doc(data);
	}
	else if (uid == IDC_TAGBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		data = tagctrl_detach(ptd->editor);

		(*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_ROLLBACK, (void*)&fd);

		destroy_tag_doc(data);
	}
	else if (uid == IDC_RICHBOX)
	{
		fd.menu = widget_detach_menu(ptd->editor);

		(*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_ROLLBACK, (void*)&fd);
	}
	else
	{
		(*pdi->pf_set_obj_noti)(ptd->widget, COMMAND_ROLLBACK, NULL);
	}

	editctrl = ptd->editor;
	ptd->editor = (widget_t)0;
	widget_destroy(editctrl);

	widget_set_focus(ptd->widget);
}

/***********************************************************************/

int editor_sub_scroll(widget_t widget, bool_t bHorz, int nLine, uid_t sid, vword_t delta)
{
	editor_context* ptd = (editor_context*)delta;
	editor_interface* pdi = &(ptd->editif);

	bool_t b_auto;
	xrect_t xr;

	XDK_ASSERT(sid == IDS_EDITOR && ptd);

	if (!widget_hand_scroll(widget, bHorz, nLine))
		return 1;

	if(!widget_is_valid(ptd->editor)) return 1;

	b_auto = (*pdi->pf_get_obj_auto)(ptd->widget);
	if(b_auto)
	{
		(*pdi->pf_get_obj_rect)(ptd->widget, &xr);
		widget_move(ptd->editor, RECTPOINT(&xr));
	}else
	{
		_editor_noti_commit_edit(ptd);
	}

	return 1;
}

int editor_sub_wheel(widget_t widget, bool_t bHorz, int nDelta, uid_t sid, vword_t delta)
{
	editor_context* ptd = (editor_context*)delta;
	editor_interface* pdi = &(ptd->editif);

	bool_t b_auto;
	xrect_t xr;

	XDK_ASSERT(sid == IDS_EDITOR && ptd);

	widget_hand_wheel(widget, bHorz, nDelta);

	if(!widget_is_valid(ptd->editor)) return 1;

	b_auto = (*pdi->pf_get_obj_auto)(ptd->widget);
	if(b_auto)
	{
		(*pdi->pf_get_obj_rect)(ptd->widget, &xr);
		widget_move(ptd->editor, RECTPOINT(&xr));
	}else
	{
		_editor_noti_commit_edit(ptd);
	}

	return 1;
}

int editor_sub_child_command(widget_t widget, int code, vword_t data, uid_t sid, vword_t delta)
{
	editor_context* ptd = (editor_context*)delta;
	editor_interface* pdi = &(ptd->editif);

	XDK_ASSERT(sid == IDS_EDITOR && ptd);

	switch (code)
	{
	case COMMAND_EDITING:
		if(!widget_is_valid(ptd->editor))
		{
			_editor_noti_begin_edit(ptd);
		}
		return 1;
	case COMMAND_COMMIT:
		if(widget_is_valid(ptd->editor))
		{
			_editor_noti_commit_edit(ptd);
		}
		return 1;
	case COMMAND_ROLLBACK:
		if(widget_is_valid(ptd->editor))
		{
			_editor_noti_rollback_edit(ptd);
		}
		return 1;
	}

	return 0;
}

int editor_sub_keydown(widget_t widget, dword_t ks, int nKey, uid_t sid, vword_t delta)
{
	editor_context* ptd = (editor_context*)delta;
	editor_interface* pdi = &(ptd->editif);

	XDK_ASSERT(sid == IDS_EDITOR && ptd);

	if (nKey == KEY_ENTER)
	{
		if ((*pdi->pf_get_obj_canbe)(ptd->widget))
		{
			_editor_noti_begin_edit(ptd);
		}
		return 1;
	}

	return 0;
}

int editor_sub_wchar(widget_t widget, wchar_t nChar, uid_t sid, vword_t delta)
{
	editor_context* ptd = (editor_context*)delta;
	editor_interface* pdi = &(ptd->editif);

	XDK_ASSERT(sid == IDS_EDITOR && ptd);

	if(!pdi->with_char) return 0;

	if (!(*pdi->pf_get_obj_canbe)(ptd->widget)) return 0;
	
	if (IS_VISIBLE_CHAR(nChar) && !widget_is_valid(ptd->editor))
	{
		_editor_noti_begin_edit(ptd);
	}

	if (IS_VISIBLE_CHAR(nChar) && widget_is_valid(ptd->editor))
	{
		widget_post_wchar(ptd->editor, nChar);
	}

	return 1;
}

/*******************************************************************************/

void hand_editor_create(widget_t widget, const editor_interface* pdi)
{
	if_subproc_t sub = {0};
	editor_context* ptd;

	SUBPROC_BEGIN_DISPATH(&sub)

	SUBPROC_ON_EDITOR_IMPLEMENT

	SUBPROC_END_DISPATH

	if(widget_set_subproc(widget, IDS_EDITOR, &sub))
	{
		ptd = (editor_context*)xmem_alloc(sizeof(editor_context));
		ptd->widget = widget;
		xmem_copy((void*)&(ptd->editif), (void*)pdi, sizeof(editor_interface));
		widget_set_subproc_delta(widget, IDS_EDITOR, (vword_t)ptd);
	}
}

void hand_editor_destroy(widget_t widget)
{
	editor_context* ptd;

	ptd = (editor_context*)widget_get_subproc_delta(widget, IDS_EDITOR);
	if(ptd)
	{
		xmem_free(ptd);
	}
}

