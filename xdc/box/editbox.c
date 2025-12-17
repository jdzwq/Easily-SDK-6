/***********************************************************************
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

#include "../xdcobj.h"


typedef struct _editbox_delta_t{
	textor_context textor;

	int chs;
	tchar_t pch[CHS_LEN + 1];

	bool_t b_lock;
	bool_t b_auto;

	xface_t xa;
	xfont_t xf;
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

static bool_t _editbox_get_paging(widget_t widget, xsize_t* pse)
{
	xrect_t xr;

	widget_get_client_rect(widget, &xr);

	pse->w = xr.w;
	pse->h = xr.h;

	return 0;
}

static const xfont_t* _editbox_get_xfont_ptr(widget_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	return &(ptd->xf);
}

static const xface_t* _editbox_get_xface_ptr(widget_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	return &(ptd->xa);
}

void _editbox_auto_resize(widget_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	string_t vs;
	xsize_t xs;
	xrect_t xr;
	int cx;
	drawing_interface ifv = {0};

	XDK_ASSERT(ptd != NULL);

	widget_get_window_rect(widget, &xr);

	vs = (string_t)ptd->textor.data;

	get_visual_interface(ptd->textor.cdc, &ifv);

	(*ifv.pf_font_size)(ifv.ctx, &xs);
	cx = xs.w;
	(*ifv.pf_text_size)(ifv.ctx, string_ptr(vs), string_len(vs), &xs);

	if (xs.w + cx > xr.w)
	{
		xs.w += (cx + 4) / 2;
		xs.h = xr.h;

		widget_size(widget, &xs);
	}
}

/*****************************************************************************/
void noti_editbox_command(widget_t widget, int code, vword_t data)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	if (widget_has_subproc(widget))
		widget_send_command(widget, code, IDC_SELF, data);
	else
		widget_post_command(widget_get_owner(widget), code, widget_get_user_id(widget), data);
}

/**********************************************************************************/
int hand_editbox_create(widget_t widget, void* data)
{
	editbox_delta_t* ptd;
	color_mod_t clrs;

	widget_hand_create(widget);

	ptd = (editbox_delta_t*)xmem_alloc(sizeof(editbox_delta_t));
	xmem_zero((void*)ptd, sizeof(editbox_delta_t));

	ptd->textor.widget = widget;
	ptd->textor.cdc = widget_client_context(widget);
	ptd->textor.data = (void*)string_alloc();
	ptd->textor.pf_scan_text = (PF_SCAN_TEXT)scan_var_text;
	ptd->textor.pf_get_text = _editbox_get_text;
	ptd->textor.pf_set_text = _editbox_set_text;
	ptd->textor.pf_get_paging = _editbox_get_paging;
	ptd->textor.pf_get_xfont_ptr = _editbox_get_xfont_ptr;
	ptd->textor.pf_get_xface_ptr = _editbox_get_xface_ptr;
	ptd->textor.max_undo = 1024;
	ptd->textor.page = 1;

	widget_get_color_mode(widget, &clrs);
	default_textor_xface(&ptd->xa);
	format_xcolor(&(clrs.clr_txt), ptd->xa.text_color);
	default_textor_xfont(&ptd->xf);

	SETEDITBOXDELTA(widget, ptd);

	return 0;
}

void hand_editbox_destroy(widget_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	widget_t keybox;

	XDK_ASSERT(ptd != NULL);

	hand_textor_clean(&ptd->textor);

	widget_release_context(widget, ptd->textor.cdc);
	string_free((string_t)ptd->textor.data);

	xmem_free(ptd);

	SETEDITBOXDELTA(widget, 0);

	widget_hand_destroy(widget);

	keybox = (widget_t)widget_get_user_prop(widget, XDCKEYBOX);

	if (widget_is_valid(keybox))
		widget_destroy(keybox);
}

void hand_editbox_copy(widget_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_copy(&ptd->textor);
}

void hand_editbox_cut(widget_t widget)
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

void hand_editbox_paste(widget_t widget)
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

void hand_editbox_undo(widget_t widget)
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

void hand_editbox_set_focus(widget_t widget, widget_t wt)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_set_focus(&ptd->textor, wt);
}

void hand_editbox_kill_focus(widget_t widget, widget_t wt)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_kill_focus(&ptd->textor, wt);

	if (widget_is_editor(widget))
	{
		noti_editbox_command(widget, COMMAND_COMMIT, (vword_t)NULL);
	}
}

void hand_editbox_keydown(widget_t widget, dword_t ks, int key)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

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
			if (is_null(ptd->xa.text_wrap))
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
			if (is_null(ptd->xa.text_wrap))
			{
				noti_editbox_command(widget, COMMAND_TABORDER, (vword_t)TABORDER_UP);
			}
		}
		break;
	case KEY_DOWN:
		hand_textor_down(&ptd->textor);

		if (widget_is_editor(widget))
		{
			if (is_null(ptd->xa.text_wrap))
			{
				noti_editbox_command(widget, COMMAND_TABORDER, (vword_t)TABORDER_DOWN);
			}
		}
		break;
	case KEY_COPY:
		hand_editbox_copy(widget);
		break;
	case KEY_CUT:
		hand_editbox_cut(widget);
		break;
	case KEY_PASTE:
		hand_editbox_paste(widget);
		break;
	case KEY_UNDO:
		hand_editbox_undo(widget);
		break;
	}
}

void hand_editbox_wchar(widget_t widget, wchar_t ch)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	if (ptd->b_lock)
		return;

	if (ch == KEY_BACK)
		return;

	if (ch != KEY_ENTER && ch != KEY_TAB && ch > 0 && ch < 32)
		return;

#if defined(_UNICODE) || defined(UNICODE)
	ptd->pch[0] = ch;
	ptd->chs = 1;
	ptd->pch[ptd->chs] = L'\0';
#else
	ucs_byte_to_mbs(ch, ptd->pch);
	ptd->chs = xschs(ptd->pch);
	ptd->pch[ptd->chs] = '\0';
#endif

	if (_TEXTOR_PRESS_ACCEPT == hand_textor_word(&ptd->textor, ptd->pch))
	{
		noti_editbox_command(widget, COMMAND_UPDATE, (vword_t)NULL);

		if (ptd->b_auto)
		{
			_editbox_auto_resize(widget);
		}
	}
}

void hand_editbox_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_lbutton_down(&ptd->textor, pxp);
}

void hand_editbox_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_lbutton_up(&ptd->textor, pxp);
}

void hand_editbox_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

}

void hand_editbox_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	if (editbox_is_multiline(widget))
		hand_textor_selectline(&ptd->textor);
	else
		hand_textor_selectall(&ptd->textor);
}

void hand_editbox_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	xpoint_t xp;

	xp.x = pxp->x;
	xp.y = pxp->y;
	widget_client_to_screen(widget, &xp);

	textor_menu(widget, &xp, WS_LAYOUT_LEFTBOTTOM);
}

void hand_editbox_mousemove(widget_t widget, dword_t mk, const xpoint_t* ppt)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_mousemove(&ptd->textor, mk, ppt);
}

void hand_editbox_size(widget_t widget, int code, const xsize_t* prs)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_size(&ptd->textor, code, prs);
}

void hand_editbox_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	hand_textor_scroll(&ptd->textor, bHorz, nLine);
}

void hand_editbox_menu_command(widget_t widget, int code, int cid, vword_t data)
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

		widget_close((widget_t)data, 1);
	}
}

void hand_editbox_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
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

widget_t editbox_create(widget_t widget, dword_t style, const xrect_t* pxr)
{
	if_dispatch_t ev = { 0 };
	widget_t wt;

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_editbox_create)
		EVENT_ON_DESTROY(hand_editbox_destroy)

		EVENT_ON_PAINT(hand_editbox_paint)

		EVENT_ON_SIZE(hand_editbox_size)
		EVENT_ON_SCROLL(hand_editbox_scroll)

		EVENT_ON_KEYDOWN(hand_editbox_keydown)
		EVENT_ON_WCHAR(hand_editbox_wchar)

		EVENT_ON_MOUSE_MOVE(hand_editbox_mousemove)
		EVENT_ON_LBUTTON_DBCLICK(hand_editbox_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_editbox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_editbox_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_editbox_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_editbox_rbutton_up)

		EVENT_ON_MENU_COMMAND(hand_editbox_menu_command)

		EVENT_ON_SET_FOCUS(hand_editbox_set_focus)
		EVENT_ON_KILL_FOCUS(hand_editbox_kill_focus)

	EVENT_END_DISPATH

	wt = widget_create(NULL, style, pxr, widget, &ev);
	if (!wt) return (widget_t)0;

	return wt;
}

void editbox_redraw(widget_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	hand_textor_redraw(&ptd->textor);
}

void editbox_selectall(widget_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	hand_textor_selectall(&ptd->textor);
}

void editbox_set_text(widget_t widget, const tchar_t* text)
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

int editbox_get_text(widget_t widget, tchar_t* buf, int max)
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

const tchar_t* editbox_get_text_ptr(widget_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);
	string_t vs;

	XDK_ASSERT(ptd != NULL);

	vs = (string_t)ptd->textor.data;

	return string_ptr(vs);
}

bool_t editbox_is_select(widget_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	return textor_is_select(&ptd->textor);
}

bool_t editbox_is_multiline(widget_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return is_null(ptd->xa.text_wrap) ? 0 : 1;
}

void editbox_auto_size(widget_t widget, bool_t bSize)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_auto = bSize;

	if (bSize)
	{
		_editbox_auto_resize(widget);
	}
}

void editbox_set_xface(widget_t widget, const xface_t* pxa)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_copy((void*)(&ptd->xa), (void*)pxa, sizeof(xface_t));

	editbox_redraw(widget);
}

void editbox_get_xface(widget_t widget, xface_t* pxa)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_copy((void*)pxa, (void*)(&ptd->xa), sizeof(xface_t));
}

void editbox_set_xfont(widget_t widget, const xfont_t* pxf)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_copy((void*)(&ptd->xf), (void*)pxf, sizeof(xfont_t));

	editbox_redraw(widget);
}

void editbox_get_xfont(widget_t widget, xfont_t* pxf)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_copy((void*)pxf, (void*)(&ptd->xf), sizeof(xfont_t));
}

void editbox_set_lock(widget_t widget, bool_t bLock)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_lock = bLock;
}

bool_t editbox_get_lock(widget_t widget)
{
	editbox_delta_t* ptd = GETEDITBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->b_lock;
}

widget_t editbox_create_keybox(widget_t widget, dword_t style, const xrect_t* pxr)
{
	widget_t editbox, keybox;
	xrect_t xr = { 0 };

	editbox = editbox_create(widget, style, pxr);

	widget_get_window_rect(editbox, &xr);
	xr.y += xr.h;

	keybox = keybox_create(editbox, WD_STYLE_POPUP | WD_STYLE_NOACTIVE, &xr);

	keybox_popup_size(keybox, RECTSIZE(&xr));

	widget_size(keybox, RECTSIZE(&xr));
	widget_take(keybox, (int)WS_TAKE_TOP);
	widget_show(keybox, WS_SHOW_NORMAL);

	widget_set_user_prop(editbox, XDCKEYBOX, (vword_t)keybox);

	return editbox;
}

widget_t editbox_get_keybox(widget_t widget)
{
	return (widget_t)widget_get_user_prop(widget, XDCKEYBOX);
}
