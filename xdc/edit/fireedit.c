/***********************************************************************
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
	}

	return 0;
}

static int sub_editbox_self_command(widget_t widget, int code, vword_t data, uid_t subid, vword_t delta)
{
	//widget_t keybox;

	if (subid != IDS_EDITBOX)
		return 0;

	switch (code)
	{
	case COMMAND_COLOR:
		/*keybox = editbox_get_keybox(widget);
		if (widget_is_valid(keybox))
		{
			widget_set_color_mode(keybox, (color_mod_t*)data,);
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

static int sub_editbox_show(widget_t widget, bool_t show, uid_t subid, vword_t delta)
{
	//widget_t keybox;

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

/*************************************************************************************/

widget_t fireedit_create(widget_t widget, const xrect_t* pxr)
{
	widget_t editor = (widget_t)0;
	if_subproc_t ev = { 0 };

	/*if (widget_get_touch_mode(widget))
	{
		editor = editbox_create_keybox(widget, WD_STYLE_CONTROL | WD_STYLE_EDITOR, pxr);
	}
	else*/
	{
		editor = editbox_create(widget, WD_STYLE_CONTROL | WD_STYLE_EDITOR, pxr);
	}

	widget_set_user_id(editor, IDC_EDITBOX);

	ev.sub_on_keydown = sub_editbox_keydown;
	ev.sub_on_self_command = sub_editbox_self_command;
	ev.sub_on_show = sub_editbox_show;

	widget_set_subproc(editor, IDS_EDITBOX, &ev);

	return editor;
}
