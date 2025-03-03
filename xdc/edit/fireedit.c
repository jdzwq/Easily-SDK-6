﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc fire edit control document

	@module	fireedit.c | implement file

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

#include "../xdcimp.h"
#include "../xdcinit.h"


static int sub_editbox_keydown(res_win_t widget, dword_t ks, int nKey, uid_t subid, vword_t delta)
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
	}

	return 0;
}

static int sub_editbox_self_command(res_win_t widget, int code, vword_t data, uid_t subid, vword_t delta)
{
	//res_win_t keybox;

	if (subid != IDS_EDITBOX)
		return 0;

	switch (code)
	{
	case COMMAND_COLOR:
		/*keybox = editbox_get_keybox(widget);
		if (widget_is_valid(keybox))
		{
			widget_set_color_mode(keybox, (clr_mod_t*)data,);
			widget_update_window(keybox);
			widget_update_client(keybox);
		}*/
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

static int sub_editbox_show(res_win_t widget, bool_t show, uid_t subid, vword_t delta)
{
	//res_win_t keybox;

	if (subid != IDS_EDITBOX)
		return 0;

	/*keybox = editbox_get_keybox(widget);

	if (widget_is_valid(keybox))
	{
		if (show)
			widget_show(keybox, WS_SHOW_NORMAL);
		else
			widget_show(keybox, WS_SHOW_HIDE);
	}*/

	return 1;
}

static void sub_editbox_unsubbing(res_win_t widget, uid_t subid, vword_t delta)
{
	if (subid != IDS_EDITBOX)
		return;

	widget_del_subproc(widget, IDS_EDITBOX);
}

/*************************************************************************************/

res_win_t fireedit_create(res_win_t widget, const xrect_t* pxr)
{
	res_win_t editor = NULL;
	if_subproc_t ev = { 0 };
	xface_t xa = { 0 };

	/*if (widget_get_touch_mode(widget))
	{
		editor = editbox_create_keybox(widget, WD_STYLE_CONTROL | WD_STYLE_EDITOR, pxr);
	}
	else*/
	{
		editor = editbox_create(widget, WD_STYLE_CONTROL | WD_STYLE_EDITOR, pxr);
	}

	widget_set_user_id(editor, IDC_EDITBOX);

	widget_get_xface(editor, &xa);
	xscpy(xa.text_wrap, NULL);
	widget_set_xface(editor, &xa);

	ev.sub_on_keydown = sub_editbox_keydown;
	ev.sub_on_unsubbing = sub_editbox_unsubbing;
	ev.sub_on_self_command = sub_editbox_self_command;
	ev.sub_on_show = sub_editbox_show;

	widget_set_subproc(editor, IDS_EDITBOX, &ev);

	return editor;
}
