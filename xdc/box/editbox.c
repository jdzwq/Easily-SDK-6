﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc edit control document

	@module	editbox.c | implement file

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

#include "box.h"

#include "../xdcimp.h"
#include "../xdcinit.h"

typedef struct _editbox_delta_t{
	textor_context textor;

	int chs;
	tchar_t pch[CHS_LEN + 1];

	bool_t b_lock;
	bool_t b_auto;
}editbox_delta_t;

#define GETEDITBOXDELTA(ph) 	(editbox_delta_t*)widget_get_user_delta(ph)
#define SETEDITBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

int _editbox_get_text(void* data, tchar_t* buf, int max)
{
	string_t vs = (string_t)data;
	int len;

	len = string_len(vs);
	len = (len < max) ? len : max;

	if (buf)
		xsncpy(buf, string_ptr(vs), len);

	return len;
}

void _editbox_set_text(void* data, const tchar_t* buf, int len)
{
	string_t vs = (string_t)data;

	string_cpy(vs, buf, len);
}

static bool_t _editbox_get_paging(res_win_t widget, xsize_t* pse)
{
	xrect_t xr;

	widget_get_client_rect(widget, &xr);

	pse->w = xr.w;
	pse->h = xr.h;

	return 0;
}

void _editbox_auto_resize(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	string_t vs;
	xsize_t xs;
	xrect_t xr;
	int cx;
	const xfont_t* pxf;
	drawing_interface ifv = {0};

	XDK_ASSERT(ptd != NULL);

	pxf = widget_get_xfont_ptr(widget);

	widget_get_window_rect(widget, &xr);

	vs = (string_t)ptd->textor.data;

	get_visual_interface(ptd->textor.cdc, &ifv);

	(*ifv.pf_text_metric)(ifv.ctx, pxf, &xs);
	cx = xs.w;
	(*ifv.pf_text_size)(ifv.ctx, pxf, string_ptr(vs), string_len(vs), &xs);

	if (xs.w + cx > xr.w)
	{
		xs.w += (cx + 4) / 2;
		xs.h = xr.h;

		widget_size(widget, &xs);
		widget_update(widget);
	}
}

/*****************************************************************************/
void noti_editbox_command(res_win_t widget, int code, vword_t data)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	if (widget_has_subproc(widget))
		widget_send_command(widget, code, IDC_SELF, data);
	else
		widget_post_command(widget_get_owner(widget), code, widget_get_user_id(widget), data);
}

/**********************************************************************************/
int hand_editbox_create(res_win_t widget, void* data)
{
	editbox_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (editbox_delta_t*)xmem_alloc(sizeof(editbox_delta_t));
	xmem_zero((void*)ptd, sizeof(editbox_delta_t));

	ptd->textor.widget = widget;
	ptd->textor.cdc = widget_client_ctx(widget);
	ptd->textor.data = (void*)string_alloc();
	ptd->textor.pf_scan_text = (PF_SCAN_TEXT)scan_var_text;
	ptd->textor.pf_get_text = _editbox_get_text;
	ptd->textor.pf_set_text = _editbox_set_text;
	ptd->textor.pf_get_paging = _editbox_get_paging;
	ptd->textor.max_undo = 1024;
	ptd->textor.page = 1;

	SETEDITBOXDELTA(widget, ptd);

	return 0;
}

void hand_editbox_destroy(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	res_win_t keybox;

	XDK_ASSERT(ptd != NULL);

	hand_textor_clean(&ptd->textor);

	widget_release_ctx(widget, ptd->textor.cdc);
	string_free((string_t)ptd->textor.data);

	xmem_free(ptd);

	SETEDITBOXDELTA(widget, 0);

	widget_hand_destroy(widget);

	keybox = (res_win_t)widget_get_user_prop(widget, XDCKEYBOX);

	if (widget_is_valid(keybox))
		widget_destroy(keybox);
}


void hand_editbox_copy(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_copy(&ptd->textor);
}

void hand_editbox_cut(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	if (ptd->b_lock)
		return;

	if (_TEXTOR_PRESS_ACCEPT == hand_textor_cut(&ptd->textor))
	{
		noti_editbox_command(widget, COMMAND_UPDATE, (vword_t)NULL);

		if (ptd->b_auto)
		{
			_editbox_auto_resize(widget);
		}
	}
}

void hand_editbox_paste(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	if (ptd->b_lock)
		return;

	if (_TEXTOR_PRESS_ACCEPT == hand_textor_paste(&ptd->textor))
	{
		noti_editbox_command(widget, COMMAND_UPDATE, (vword_t)NULL);

		if (ptd->b_auto)
		{
			_editbox_auto_resize(widget);
		}
	}
}

void hand_editbox_undo(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	if (ptd->b_lock)
		return;

	if (_TEXTOR_PRESS_ACCEPT == hand_textor_undo(&ptd->textor))
	{
		noti_editbox_command(widget, COMMAND_UPDATE, (vword_t)NULL);

		if (ptd->b_auto)
		{
			_editbox_auto_resize(widget);
		}
	}
}

void hand_editbox_set_focus(res_win_t widget, res_win_t wt)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_set_focus(&ptd->textor, wt);
}

void hand_editbox_kill_focus(res_win_t widget, res_win_t wt)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_kill_focus(&ptd->textor, wt);

	if (widget_is_editor(widget))
	{
		noti_editbox_command(widget, COMMAND_COMMIT, (vword_t)NULL);
	}
}

void hand_editbox_keydown(res_win_t widget, dword_t ks, int key)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	const xface_t* pxa;

	switch (key)
	{
	case KEY_BACK:
		if (ptd->b_lock)
			break;
		if (_TEXTOR_PRESS_ACCEPT == hand_textor_back(&ptd->textor))
		{
			noti_editbox_command(widget, COMMAND_UPDATE, (vword_t)NULL);
		}
		break;
	case KEY_DELETE:
		if (ptd->b_lock)
			break;
		if (_TEXTOR_PRESS_ACCEPT == hand_textor_delete(&ptd->textor))
		{
			noti_editbox_command(widget, COMMAND_UPDATE, (vword_t)NULL);
		}
		break;
	case KEY_TAB:
		break;
	case KEY_ENTER:
		if (widget_is_editor(widget))
		{
			pxa = widget_get_xface_ptr(widget);
			if (is_null(pxa->text_wrap))
			{
				noti_editbox_command(widget, COMMAND_COMMIT, (vword_t)NULL);
			}
		}
		break;
	case KEY_ESC:
		if (ptd->b_lock)
			break;
		hand_textor_escape(&ptd->textor);
		break;
	case KEY_LEFT:
		hand_textor_left(&ptd->textor);
		break;
	case KEY_RIGHT:
		hand_textor_right(&ptd->textor);
		break;
	case KEY_UP:
		hand_textor_up(&ptd->textor);

		if (widget_is_editor(widget))
		{
			pxa = widget_get_xface_ptr(widget);
			if (is_null(pxa->text_wrap))
			{
				noti_editbox_command(widget, COMMAND_TABORDER, (vword_t)TABORDER_UP);
			}
		}
		break;
	case KEY_DOWN:
		hand_textor_down(&ptd->textor);

		if (widget_is_editor(widget))
		{
			pxa = widget_get_xface_ptr(widget);
			if (is_null(pxa->text_wrap))
			{
				noti_editbox_command(widget, COMMAND_TABORDER, (vword_t)TABORDER_DOWN);
			}
		}
		break;
	case _T('c'):
	case _T('C'):
		if (widget_key_state(widget, KEY_CONTROL))
		{
			hand_editbox_copy(widget);
		}
		break;
	case _T('x'):
	case _T('X'):
		if (widget_key_state(widget, KEY_CONTROL))
		{
			hand_editbox_cut(widget);
		}
		break;
	case _T('v'):
	case _T('V'):
		if (widget_key_state(widget, KEY_CONTROL))
		{
			hand_editbox_paste(widget);
		}
		break;
	case _T('z'):
	case _T('Z'):
		if (widget_key_state(widget, KEY_CONTROL))
		{
			hand_editbox_undo(widget);
		}
		break;
	}
}

void hand_editbox_char(res_win_t widget, tchar_t ch)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	if (ptd->b_lock)
		return;

	if (ch == KEY_BACK)
		return;

	if (ch != KEY_ENTER && ch != KEY_TAB && ch > 0 && ch < 32)
		return;

	if (!ptd->chs)
	{
		ptd->chs = xschs(&ch);

		xsncpy(ptd->pch, &ch, 1);
		ptd->chs--;

		if (ptd->chs)
			return;
	}
	else
	{
		xsncat(ptd->pch, &ch, 1);
		ptd->chs--;

		if (ptd->chs)
			return;
	}

	if (_TEXTOR_PRESS_ACCEPT == hand_textor_word(&ptd->textor, ptd->pch))
	{
		noti_editbox_command(widget, COMMAND_UPDATE, (vword_t)NULL);

		if (ptd->b_auto)
		{
			_editbox_auto_resize(widget);
		}
	}
}

void hand_editbox_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_lbutton_down(&ptd->textor, pxp);
}

void hand_editbox_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_lbutton_up(&ptd->textor, pxp);
}

void hand_editbox_rbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

}

void hand_editbox_lbutton_dbclick(res_win_t widget, const xpoint_t* pxp)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	if (editbox_is_multiline(widget))
		hand_textor_selectline(&ptd->textor);
	else
		hand_textor_selectall(&ptd->textor);
}

void hand_editbox_rbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	xpoint_t xp;

	xp.x = pxp->x;
	xp.y = pxp->y;
	widget_client_to_screen(widget, &xp);

	textor_menu(widget, &xp, WS_LAYOUT_LEFTBOTTOM);
}

void hand_editbox_mousemove(res_win_t widget, dword_t mk, const xpoint_t* ppt)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_mousemove(&ptd->textor, mk, ppt);
}

void hand_editbox_size(res_win_t widget, int code, const xsize_t* prs)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_size(&ptd->textor, code, prs);
}

void hand_editbox_scroll(res_win_t widget, bool_t bHorz, int nLine)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_scroll(&ptd->textor, bHorz, nLine);
}

void hand_editbox_menu_command(res_win_t widget, int code, int cid, vword_t data)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	if (cid == IDC_EDITMENU)
	{
		switch (code)
		{
		case COMMAND_COPY:
			hand_editbox_copy(widget);
			break;
		case COMMAND_CUT:
			hand_editbox_cut(widget);
			break;
		case COMMAND_PASTE:
			hand_editbox_paste(widget);
			break;
		case COMMAND_UNDO:
			hand_editbox_undo(widget);
			break;
		}

		widget_close((res_win_t)data, 1);
	}
}

void hand_editbox_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	xrect_t xr;
	xcolor_t xc;
	drawing_interface ifv = {0};

	hand_textor_paint(&ptd->textor, dc, pxr);

	if (ptd->b_auto)
	{
		get_visual_interface(dc, &ifv);
		widget_get_view_rect(widget, (viewbox_t*)(&ifv.rect));

		widget_get_client_rect(widget, &xr);

		parse_xcolor(&xc, DEF_DISABLE_COLOR);
		draw_feed_raw(&ifv, &xc, &xr, ALPHA_SOLID);
	}
}

/************************************************************************************************/

res_win_t editbox_create(res_win_t widget, dword_t style, const xrect_t* pxr)
{
	if_event_t ev = { 0 };
	res_win_t wt;

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_editbox_create)
		EVENT_ON_DESTROY(hand_editbox_destroy)

		EVENT_ON_PAINT(hand_editbox_paint)

		EVENT_ON_SIZE(hand_editbox_size)
		EVENT_ON_SCROLL(hand_editbox_scroll)

		EVENT_ON_KEYDOWN(hand_editbox_keydown)
		EVENT_ON_CHAR(hand_editbox_char)

		EVENT_ON_MOUSE_MOVE(hand_editbox_mousemove)
		EVENT_ON_LBUTTON_DBCLICK(hand_editbox_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_editbox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_editbox_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_editbox_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_editbox_rbutton_up)

		EVENT_ON_MENU_COMMAND(hand_editbox_menu_command)

		EVENT_ON_SET_FOCUS(hand_editbox_set_focus)
		EVENT_ON_KILL_FOCUS(hand_editbox_kill_focus)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	wt = widget_create(NULL, style, pxr, widget, &ev);
	if (!wt)
		return NULL;

	/*widget_get_xface(wt, &xa);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_LINEBREAK);
	widget_set_xface(wt, &xa);*/

	return wt;
}

void editbox_redraw(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	hand_textor_redraw(&ptd->textor);
}

void editbox_selectall(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	hand_textor_selectall(&ptd->textor);
}

void editbox_set_text(res_win_t widget, const tchar_t* text)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	string_cpy((string_t)ptd->textor.data, text, -1);

	if (ptd->b_auto)
	{
		_editbox_auto_resize(widget);
		hand_textor_end(&ptd->textor);
	}
	else
	{
		hand_textor_end(&ptd->textor);
		editbox_redraw(widget);
	}

	noti_editbox_command(widget, COMMAND_UPDATE, (vword_t)NULL);
}

int editbox_get_text(res_win_t widget, tchar_t* buf, int max)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	string_t vs;
	int len;

	XDK_ASSERT(ptd != NULL);

	vs = (string_t)ptd->textor.data;

	len = string_len(vs);
	if (buf)
	{
		len = (len < max) ? len : max;
		xsncpy(buf, string_ptr(vs), len);
	}

	return len;
}

const tchar_t* editbox_get_text_ptr(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	string_t vs;

	XDK_ASSERT(ptd != NULL);

	vs = (string_t)ptd->textor.data;

	return string_ptr(vs);
}

bool_t editbox_is_select(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	return textor_is_select(&ptd->textor);
}

bool_t editbox_is_multiline(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	xface_t xa = { 0 };

	XDK_ASSERT(ptd != NULL);

	widget_get_xface(widget, &xa);

	return is_null(xa.text_wrap) ? 0 : 1;
}

void editbox_auto_size(res_win_t widget, bool_t bSize)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_auto = bSize;

	if (bSize)
	{
		_editbox_auto_resize(widget);
	}
}

void editbox_set_lock(res_win_t widget, bool_t bLock)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_lock = bLock;
}

bool_t editbox_get_lock(res_win_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->b_lock;
}

res_win_t editbox_create_keybox(res_win_t widget, dword_t style, const xrect_t* pxr)
{
	res_win_t editbox, keybox;
	xrect_t xr = { 0 };

	editbox = editbox_create(widget, style, pxr);

	widget_get_window_rect(editbox, &xr);
	xr.y += xr.h;

	keybox = keybox_create(editbox, WD_STYLE_POPUP | WD_STYLE_NOACTIVE, &xr);

	keybox_popup_size(keybox, RECTSIZE(&xr));

	widget_size(keybox, RECTSIZE(&xr));
	widget_take(keybox, (int)WS_TAKE_TOP);
	widget_update(keybox);
	widget_show(keybox, WS_SHOW_NORMAL);

	widget_set_user_prop(editbox, XDCKEYBOX, (vword_t)keybox);

	return editbox;
}

res_win_t editbox_get_keybox(res_win_t widget)
{
	return (res_win_t)widget_get_user_prop(widget, XDCKEYBOX);
}

