/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc fire date control document

	@module	firedate.c | implement file

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

#include "firor.h"

#include "../xdcobj.h"



static int sub_editbox_keydown(widget_t widget, dword_t ks, int nKey, uid_t subid, vword_t delta)
{
	if (subid != IDS_EDITBOX)
		return 0;

	switch (nKey)
	{
	case KEY_TAB:
		widget_post_command(widget_get_owner(widget), COMMAND_COMMIT, IDC_CHILD, (vword_t)NULL);
		return 1;
	case KEY_ENTER:
		widget_post_command(widget_get_owner(widget), COMMAND_COMMIT, IDC_CHILD, (vword_t)NULL);
		return 1;
	case KEY_ESC:
		widget_post_command(widget_get_owner(widget), COMMAND_ROLLBACK, IDC_CHILD, (vword_t)NULL);
		return 1;
	case KEY_SPACE:
		editbox_set_text(widget, NULL);
		widget_post_command(widget_get_owner(widget), COMMAND_COMMIT, IDC_CHILD, (vword_t)NULL);
		return 1;
	}

	return 0;
}

static int sub_editbox_self_command(widget_t widget, int code, vword_t data, uid_t subid, vword_t delta)
{
	widget_t datebox;
	xdate_t dt;
	const tchar_t* text;

	if (subid != IDS_EDITBOX)
		return 0;

	datebox = (widget_t)delta;

	switch (code)
	{
	case COMMAND_UPDATE:
		if (widget_is_valid(datebox))
		{
			text = editbox_get_text_ptr(widget);
			if (is_null(text))
				get_loc_date(&dt);
			else
				parse_date(&dt, text);

			datebox_set_date(datebox, &dt);
		}
		return 1;
	case COMMAND_COLOR:
		if (widget_is_valid(datebox))
		{
			widget_set_color_mode(datebox, (color_mod_t*)data);
		}
		return 1;
	case COMMAND_COMMIT:
		widget_post_command(widget_get_owner(widget), COMMAND_COMMIT, IDC_CHILD, (vword_t)NULL);
		return 1;
	case COMMAND_ROLLBACK:
		widget_post_command(widget_get_owner(widget), COMMAND_ROLLBACK, IDC_CHILD, (vword_t)NULL);
		return 1;
	}

	return 0;
}

static int sub_editbox_show(widget_t widget, bool_t show, uid_t subid, vword_t delta)
{
	widget_t datebox;

	if (subid != IDS_EDITBOX)
		return 0;

	datebox = (widget_t)delta;

	if (widget_is_valid(datebox))
	{
		if (show)
			widget_show(datebox, WS_SHOW_NORMAL);
		else
			widget_show(datebox, WS_SHOW_HIDE);
	}

	return 1;
}

static void sub_editbox_unsubbing(widget_t widget, uid_t subid, vword_t delta)
{
	widget_t datebox;

	if (subid != IDS_EDITBOX)
		return;

	datebox = (widget_t)delta;
	if (widget_is_valid(datebox))
	{
		widget_destroy(datebox);
	}
}

/////////////////////////////////////////////////////////////////////////////
static int sub_datebox_self_command(widget_t widget, int code, vword_t data, uid_t subid, vword_t delta)
{
	widget_t editbox;
	tchar_t token[DATE_LEN + 1] = { 0 };
	xdate_t dt = { 0 };

	if (subid != IDS_DATEBOX)
		return 0;

	editbox = (widget_t)delta;

	switch (code)
	{
	case COMMAND_UPDATE:
		if (widget_is_valid(editbox))
		{
			datebox_get_date(widget, &dt);

			format_date(&dt, token);
			editbox_set_text(editbox, token);
		}
		return 1;
	case COMMAND_CHANGE:
		if (widget_is_valid(editbox))
		{
			widget_post_key(editbox, KEY_ENTER);
		}
		break;
	}

	return 0;
}

/*************************************************************************************/
widget_t firedate_create(widget_t widget, const xrect_t* pxr)
{
	widget_t editor, datebox;
	xrect_t xr_ed, xr = { 0 };
	xsize_t xs;

	if_subproc_t ev = { 0 };

	ev.sub_on_keydown = sub_editbox_keydown;
	ev.sub_on_unsubbed = sub_editbox_unsubbing;
	ev.sub_on_self_command = sub_editbox_self_command;
	ev.sub_on_show = sub_editbox_show;

	editor = editbox_create(widget, WD_STYLE_CONTROL | WD_STYLE_EDITOR, pxr);

	widget_set_user_id(editor, IDC_EDITBOX);
	widget_set_subproc(editor, IDS_EDITBOX, &ev);

	widget_get_window_rect(editor, &xr_ed);

	xr.x = xr_ed.x;
	xr.y = xr_ed.y + xr_ed.h;
	datebox = datebox_create(widget, WD_STYLE_POPUP | WD_STYLE_BORDER | WD_STYLE_NOACTIVE, &xr);

	widget_set_subproc_delta(editor, IDS_EDITBOX, (vword_t)datebox);

	widget_set_user_id(datebox, IDC_DATEBOX);
	widget_set_owner(datebox, editor);

	xmem_zero((void*)&ev, sizeof(if_subproc_t));

	ev.sub_on_self_command = sub_datebox_self_command;

	widget_set_subproc(datebox, IDS_DATEBOX, &ev);
	widget_set_subproc_delta(datebox, IDS_DATEBOX, (vword_t)editor);

	widget_get_window_rect(datebox, &xr);
	datebox_popup_size(datebox, RECTSIZE(&xr));

	get_screen_size(&xs);

	if (xr.x + xr.w > xs.w)
	{
		xr.x = xs.w - xr.w;
	}

	if (xr.y + xr.h > xs.h)
	{
		xr.y = xr_ed.y - xr.h;
	}

	widget_move(datebox, RECTPOINT(&xr));
	widget_size(datebox, RECTSIZE(&xr));

	return editor;
}
