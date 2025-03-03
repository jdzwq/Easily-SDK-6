﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc msgdlg control document

	@module	msgdlg.c | implement file

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

#include "dlg.h"

#include "../xdcimp.h"
#include "../xdcinit.h"

#define IDC_PUSHBOX_CLOSE		10
#define IDC_PUSHBOX_OK			11
#define IDC_PUSHBOX_CANCEL		12
#define IDC_PUSHBOX_YES			13
#define IDC_PUSHBOX_NO			14
#define IDC_PUSHBOX_KNOWN		15

#define MSGDLG_TITLE_HEIGHT		(float)10 //TM
#define MSGDLG_TITLE_WIDTH		(float)100 //TM
#define MSGDLG_BUTTON_HEIGHT	(float)6 //tm
#define MSGDLG_BUTTON_WIDTH_MAXI	(float)30 //tm
#define MSGDLG_BUTTON_WIDTH_MIDD	(float)12 //tm
#define MSGDLG_BUTTON_WIDTH_MINI	(float)6 //tm

#define MSGDLG_EDGE_FEED		(int)4 //PT

typedef struct _msgdlg_delta_t{
	dword_t btn;
	const tchar_t* text;
}msgdlg_delta_t;

typedef struct _MSGDLGDATA{
	dword_t btn;
	const tchar_t* text;
}MSGDLGDATA;

#define GETMSGDLGDELTA(ph) 	(msgdlg_delta_t*)widget_get_user_delta(ph)
#define SETMSGDLGDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/**********************************************************************************/
int hand_msgdlg_create(res_win_t widget, void* data)
{
	msgdlg_delta_t* ptd = GETMSGDLGDELTA(widget);
	MSGDLGDATA* pm = (MSGDLGDATA*)data;

	xrect_t xr, xr_btn;
	xsize_t xs;
	res_win_t pushbox;

	XDK_ASSERT(pm != NULL);

	widget_hand_create(widget);

	ptd = (msgdlg_delta_t*)xmem_alloc(sizeof(msgdlg_delta_t));
	xmem_zero((void*)ptd, sizeof(msgdlg_delta_t));

	ptd->btn = pm->btn;
	ptd->text = pm->text;

	xs.fw = MSGDLG_TITLE_WIDTH;
	xs.fh = MSGDLG_TITLE_HEIGHT;
	widget_size_to_pt(widget, &xs);

	widget_get_client_rect(widget, &xr);
	xr.x += MSGDLG_EDGE_FEED;
	xr.w -= 2 * MSGDLG_EDGE_FEED;
	xr.y = xr.y + xr.h - xs.h;
	xr.h = xs.h;

	if (!(ptd->btn & 0x0000FFFF))
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MIDD;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x + xr.w - xs.w;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = pushbox_create(widget, WD_STYLE_CONTROL | WD_PUSHBOX_TEXT, &xr_btn);
		widget_set_user_id(pushbox, IDC_PUSHBOX_CLOSE);
		widget_set_owner(pushbox, widget);
		pushbox_set_text(pushbox, MSGDLG_PUSHBOX_CLOSE, -1);
		widget_show(pushbox, WS_SHOW_NORMAL);

		xr.w -= (xr_btn.w + MSGDLG_EDGE_FEED);
	}

	if (ptd->btn & MSGBTN_NO)
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MINI;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x + xr.w - xs.w;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = pushbox_create(widget, WD_STYLE_CONTROL | WD_PUSHBOX_TEXT, &xr_btn);
		widget_set_user_id(pushbox, IDC_PUSHBOX_NO);
		widget_set_owner(pushbox, widget);
		pushbox_set_text(pushbox, MSGDLG_PUSHBOX_NO, -1);
		widget_show(pushbox, WS_SHOW_NORMAL);

		xr.w -= (xr_btn.w + MSGDLG_EDGE_FEED);
	}

	if (ptd->btn & MSGBTN_YES)
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MINI;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x + xr.w - xs.w;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = pushbox_create(widget, WD_STYLE_CONTROL | WD_PUSHBOX_TEXT, &xr_btn);
		widget_set_user_id(pushbox, IDC_PUSHBOX_YES);
		widget_set_owner(pushbox, widget);
		pushbox_set_text(pushbox, MSGDLG_PUSHBOX_YES, -1);
		widget_show(pushbox, WS_SHOW_NORMAL);

		xr.w -= (xr_btn.w + MSGDLG_EDGE_FEED);
	}

	if (ptd->btn & MSGBTN_CANCEL)
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MIDD;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x + xr.w - xs.w;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = pushbox_create(widget, WD_STYLE_CONTROL | WD_PUSHBOX_TEXT, &xr_btn);
		widget_set_user_id(pushbox, IDC_PUSHBOX_CANCEL);
		widget_set_owner(pushbox, widget);
		pushbox_set_text(pushbox, MSGDLG_PUSHBOX_CANCEL, -1);
		widget_show(pushbox, WS_SHOW_NORMAL);

		xr.w -= (xr_btn.w + MSGDLG_EDGE_FEED);
	}

	if (ptd->btn & MSGBTN_OK)
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MIDD;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x + xr.w - xs.w;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = pushbox_create(widget, WD_STYLE_CONTROL | WD_PUSHBOX_TEXT, &xr_btn);
		widget_set_user_id(pushbox, IDC_PUSHBOX_OK);
		widget_set_owner(pushbox, widget);
		pushbox_set_text(pushbox, MSGDLG_PUSHBOX_OK, -1);
		widget_show(pushbox, WS_SHOW_NORMAL);

		xr.w -= (xr_btn.w + MSGDLG_EDGE_FEED);
	}

	if (ptd->btn & MSGBTN_KNOWN)
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MAXI;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = pushbox_create(widget, WD_STYLE_CONTROL | WD_PUSHBOX_CHECK, &xr_btn);
		widget_set_user_id(pushbox, IDC_PUSHBOX_KNOWN);
		widget_set_owner(pushbox, widget);
		pushbox_set_text(pushbox, MSGDLG_PUSHBOX_KNOWN, -1);
		widget_show(pushbox, WS_SHOW_NORMAL);
	}

	SETMSGDLGDELTA(widget, ptd);

	return 0;
}

void hand_msgdlg_destroy(res_win_t widget)
{
	msgdlg_delta_t* ptd = GETMSGDLGDELTA(widget);
	res_win_t pushbox;

	XDK_ASSERT(ptd != NULL);

	pushbox = widget_get_child(widget, IDC_PUSHBOX_CLOSE);
	if (pushbox)
		widget_destroy(pushbox);

	pushbox = widget_get_child(widget, IDC_PUSHBOX_NO);
	if (pushbox)
		widget_destroy(pushbox);

	pushbox = widget_get_child(widget, IDC_PUSHBOX_YES);
	if (pushbox)
		widget_destroy(pushbox);

	pushbox = widget_get_child(widget, IDC_PUSHBOX_CANCEL);
	if (pushbox)
		widget_destroy(pushbox);

	pushbox = widget_get_child(widget, IDC_PUSHBOX_OK);
	if (pushbox)
		widget_destroy(pushbox);

	pushbox = widget_get_child(widget, IDC_PUSHBOX_KNOWN);
	if (pushbox)
		widget_destroy(pushbox);

	xmem_free(ptd);

	SETMSGDLGDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_msgdlg_menu_command(res_win_t widget, int code, int cid, vword_t data)
{
	msgdlg_delta_t* ptd = GETMSGDLGDELTA(widget);

	res_win_t pushbox;
	dword_t ret;

	if (!ptd)
		return;

	if (cid == IDC_PUSHBOX_CLOSE)
	{
		ret = 0;
		pushbox = widget_get_child(widget, IDC_PUSHBOX_KNOWN);
		if (pushbox)
		{
			if (pushbox_get_state(pushbox))
				ret |= MSGBTN_KNOWN;
		}
		widget_close(widget, ret);
	}
	else if (cid == IDC_PUSHBOX_NO)
	{
		ret = MSGBTN_NO;
		pushbox = widget_get_child(widget, IDC_PUSHBOX_KNOWN);
		if (pushbox)
		{
			if (pushbox_get_state(pushbox))
				ret |= MSGBTN_KNOWN;
		}
		widget_close(widget, ret);
	}
	else if (cid == IDC_PUSHBOX_YES)
	{
		ret = MSGBTN_YES;
		pushbox = widget_get_child(widget, IDC_PUSHBOX_KNOWN);
		if (pushbox)
		{
			if (pushbox_get_state(pushbox))
				ret |= MSGBTN_KNOWN;
		}
		widget_close(widget, ret);
	}
	else if (cid == IDC_PUSHBOX_CANCEL)
	{
		ret = MSGBTN_CANCEL;
		pushbox = widget_get_child(widget, IDC_PUSHBOX_KNOWN);
		if (pushbox)
		{
			if (pushbox_get_state(pushbox))
				ret |= MSGBTN_KNOWN;
		}
		widget_close(widget, ret);
	}
	else if (cid == IDC_PUSHBOX_OK)
	{
		ret = MSGBTN_OK;
		pushbox = widget_get_child(widget, IDC_PUSHBOX_KNOWN);
		if (pushbox)
		{
			if (pushbox_get_state(pushbox))
				ret |= MSGBTN_KNOWN;
		}
		widget_close(widget, ret);
	}
}

void hand_msgdlg_size(res_win_t widget, int code, const xsize_t* prs)
{
	msgdlg_delta_t* ptd = GETMSGDLGDELTA(widget);
	xsize_t xs;
	xrect_t xr, xr_btn;
	res_win_t pushbox;
	canvas_t canv;
	
	canv = widget_get_canvas(widget);

	xs.fw = MSGDLG_TITLE_WIDTH;
	xs.fh = MSGDLG_TITLE_HEIGHT;
	widget_size_to_pt(widget, &xs);

	widget_get_client_rect(widget, &xr);
	xr.x += MSGDLG_EDGE_FEED;
	xr.w -= 2 * MSGDLG_EDGE_FEED;
	xr.y = xr.y + xr.h - xs.h;
	xr.h = xs.h;

	if (!(ptd->btn & 0x0000FFFF))
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MIDD;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x + xr.w - xs.w;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = widget_get_child(widget, IDC_PUSHBOX_CLOSE);
		widget_move(pushbox, RECTPOINT(&xr_btn));

		xr.w -= (xr_btn.w + MSGDLG_EDGE_FEED);
	}

	if (ptd->btn & MSGBTN_NO)
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MINI;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x + xr.w - xs.w;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = widget_get_child(widget, IDC_PUSHBOX_NO);
		widget_move(pushbox, RECTPOINT(&xr_btn));

		xr.w -= (xr_btn.w + MSGDLG_EDGE_FEED);
	}

	if (ptd->btn & MSGBTN_YES)
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MINI;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x + xr.w - xs.w;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = widget_get_child(widget, IDC_PUSHBOX_YES);
		widget_move(pushbox, RECTPOINT(&xr_btn));

		xr.w -= (xr_btn.w + MSGDLG_EDGE_FEED);
	}

	if (ptd->btn & MSGBTN_CANCEL)
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MIDD;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x + xr.w - xs.w;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = widget_get_child(widget, IDC_PUSHBOX_CANCEL);
		widget_move(pushbox, RECTPOINT(&xr_btn));

		xr.w -= (xr_btn.w + MSGDLG_EDGE_FEED);
	}

	if (ptd->btn & MSGBTN_OK)
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MIDD;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x + xr.w - xs.w;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = widget_get_child(widget, IDC_PUSHBOX_OK);
		widget_move(pushbox, RECTPOINT(&xr_btn));

		xr.w -= (xr_btn.w + MSGDLG_EDGE_FEED);
	}

	if (ptd->btn & MSGBTN_KNOWN)
	{
		xs.fw = MSGDLG_BUTTON_WIDTH_MAXI;
		xs.fh = MSGDLG_BUTTON_HEIGHT;
		widget_size_to_pt(widget, &xs);

		xr_btn.x = xr.x;
		xr_btn.y = xr.y + xr.h / 2 - xs.h / 2;
		xr_btn.w = xs.w;
		xr_btn.h = xs.h;

		pushbox = widget_get_child(widget, IDC_PUSHBOX_KNOWN);
		widget_move(pushbox, RECTPOINT(&xr_btn));
	}

	widget_erase(widget, NULL);
}

void hand_msgdlg_keydown(res_win_t widget, dword_t ks, int key)
{
	msgdlg_delta_t* ptd = GETMSGDLGDELTA(widget);

	switch (key)
	{
	case KEY_ENTER:
		widget_close(widget, MSGBTN_KNOWN);
		break;
	case KEY_ESC:
		widget_close(widget, 0);
		break;
	}
}

void hand_msgdlg_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	msgdlg_delta_t* ptd = GETMSGDLGDELTA(widget);
	
	xfont_t xf = { 0 };
	xface_t xa = { 0 };
	xpen_t xp = { 0 };
	xbrush_t xb = { 0 };
	xrect_t xr,xr_txt,xr_bar;
	xsize_t xs;
	xpoint_t pt1, pt2;

	visual_t rdc;
	canvas_t canv;
	drawing_interface ifv = {0};

	widget_get_xfont(widget, &xf);
	widget_get_xface(widget, &xa);

	widget_get_xbrush(widget, &xb);
	widget_get_xpen(widget, &xp);

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	xs.fw = MSGDLG_TITLE_HEIGHT;
	xs.fh = MSGDLG_TITLE_HEIGHT;
	widget_size_to_pt(widget, &xs);

	xr.h -= xs.h;
	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);
	xr.h += xs.h;

	xr_bar.x = xr.x;
	xr_bar.y = xr.y + xr.h - xs.h;
	xr_bar.w = xr.w;
	xr_bar.h = xs.h;

	lighten_xbrush(&xb, DEF_MIDD_DARKEN);
	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr_bar);

	pt1.x = xr.x;
	pt1.y = xr.y + xr.h - xs.h;
	pt2.x = xr.x + xr.w;
	pt2.y = xr.y + xr.h - xs.h;

	(*ifv.pf_draw_line)(ifv.ctx, &xp, &pt1, &pt2);

	xr_txt.x = xr.x + xs.w;
	xr_txt.y = xr.y;
	xr_txt.w = xr.w - 2 * xs.w;
	xr_txt.h = xr.h - xs.h;

	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);

	(*ifv.pf_draw_text)(ifv.ctx, &xf, &xa, &xr_txt, ptd->text, -1);

	end_canvas_paint(canv, dc, pxr);
}

/***************************************************************************************/
res_win_t msgdlg_create(const tchar_t* text, dword_t button, res_win_t owner)
{
	MSGDLGDATA md = { 0 };
	if_event_t ev = { 0 };
	xrect_t xr = { 0 };
	clr_mod_t clr = { 0 };
	res_win_t dlg;

	md.btn = button;
	md.text = text;

	ev.param = (void*)&md;

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_msgdlg_create)
		EVENT_ON_DESTROY(hand_msgdlg_destroy)

		EVENT_ON_PAINT(hand_msgdlg_paint)

		EVENT_ON_SIZE(hand_msgdlg_size)

		EVENT_ON_KEYDOWN(hand_msgdlg_keydown)

		EVENT_ON_MENU_COMMAND(hand_msgdlg_menu_command)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	dlg = widget_create(NULL, WD_STYLE_DIALOG, &xr, owner, &ev);

	if (button & MSGICO_ERR)
	{
		widget_set_title(dlg, MSGDLG_TITLE_ERR);
	}
	else if (button & MSGICO_WRN)
	{
		widget_set_title(dlg, MSGDLG_TITLE_WRN);
	}
	else
	{
		widget_set_title(dlg, MSGDLG_TITLE_TIP);
	}

	msgdlg_popup_size(dlg, RECTSIZE(&xr));
	widget_size(dlg, RECTSIZE(&xr));
	widget_update(dlg);
	widget_center_window(dlg, owner);

	if (widget_is_valid(owner))
	{
		widget_get_color_mode(owner, &clr);
		widget_set_color_mode(dlg, &clr);
	}

	return dlg;
}

void msgdlg_popup_size(res_win_t widget, xsize_t* pxs)
{
	msgdlg_delta_t* ptd = GETMSGDLGDELTA(widget);

	pxs->fw = MSGDLG_TITLE_HEIGHT * 8;
	pxs->fh = MSGDLG_TITLE_HEIGHT * 4;

	widget_size_to_pt(widget, pxs);

	widget_adjust_size(widget_get_style(widget), pxs);
}

