﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc fire check control document

	@module	firecheck.c | implement file

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


static int sub_checkbox_keydown(res_win_t widget, dword_t ks, int nKey, uid_t subid, vword_t delta)
{
	if (subid != IDS_CHECKBOX)
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

static void sub_checkbox_unsubbing(res_win_t widget, uid_t subid, vword_t delta)
{
	if (subid != IDS_CHECKBOX)
		return ;

	widget_del_subproc(widget, IDS_CHECKBOX);
}

/*************************************************************************************/

res_win_t firecheck_create(res_win_t widget, const xrect_t* pxr)
{
	res_win_t editor;
	if_subproc_t ev = { 0 };
	xface_t xa = { 0 };

	ev.sub_on_keydown = sub_checkbox_keydown;
	ev.sub_on_unsubbing = sub_checkbox_unsubbing;

	editor = checkbox_create(widget, WD_STYLE_CONTROL | WD_STYLE_EDITOR, pxr);
	widget_set_user_id(editor, IDC_CHECKBOX);
	widget_set_subproc(editor, IDS_CHECKBOX, &ev);

	widget_get_xface(editor, &xa);
	xscpy(xa.text_wrap, NULL);
	widget_set_xface(editor, &xa);

	return editor;
}
