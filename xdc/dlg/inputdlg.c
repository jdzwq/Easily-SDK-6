﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc inputdlg control document

	@module	inputdlg.c | implement file

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

#define IDC_INPUTDLG_PUSHBOX_CLOSE		10

typedef struct _inputdlg_delta_t{
	tchar_t* buf;
	int max;
	res_win_t editor;
	res_win_t button;
}inputdlg_delta_t;

typedef struct _INPUTPARAM{
	tchar_t* buf;
	int max;
}INPUTPARAM;


#define GETINPUTDLGDELTA(ph) 	(inputdlg_delta_t*)widget_get_user_delta(ph)
#define SETINPUTDLGDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)
/*********************************************************************************/
void noti_inputdlg_commit_edit(res_win_t widget)
{
	inputdlg_delta_t* ptd = GETINPUTDLGDELTA(widget);
	
	if (ptd->buf)
	{
		editbox_get_text(ptd->editor, ptd->buf, ptd->max);
	}

	widget_close(widget, 1);
}

void noti_inputdlg_rollback_edit(res_win_t widget)
{
	inputdlg_delta_t* ptd = GETINPUTDLGDELTA(widget);

	if (ptd->buf)
	{
		xscpy(ptd->buf, _T(""));
	}

	widget_close(widget, 0);
}
/**********************************************************************************/
int hand_inputdlg_create(res_win_t widget, void* data)
{
	inputdlg_delta_t* ptd = GETINPUTDLGDELTA(widget);

	xrect_t xr;
	xfont_t xf = { 0 };
	clr_mod_t ob = { 0 };
	INPUTPARAM* pim = (INPUTPARAM*)data;

	widget_hand_create(widget);

	ptd = (inputdlg_delta_t*)xmem_alloc(sizeof(inputdlg_delta_t));
	xmem_zero((void*)ptd, sizeof(inputdlg_delta_t));

	SETINPUTDLGDELTA(widget, ptd);

	if (pim)
	{
		ptd->buf = pim->buf;
		ptd->max = pim->max;
	}
	
	widget_get_color_mode(widget, &ob);
	widget_get_xfont(widget, &xf);

	widget_get_client_rect(widget, &xr);
	xr.x = xr.w - xr.h;
	xr.w = xr.h;
	ptd->button = pushbox_create(widget, WD_STYLE_CONTROL | WD_PUSHBOX_ICON, &xr);
	widget_set_user_id(ptd->button, IDC_INPUTDLG_PUSHBOX_CLOSE);
	widget_set_owner(ptd->button, widget);
	pushbox_set_text(ptd->button, GDI_ATTR_GIZMO_CLOSE, -1);
	widget_show(ptd->button, WS_SHOW_NORMAL);

	widget_get_client_rect(widget, &xr);
	xr.w -= xr.h;
	ptd->editor = fireedit_create(widget, &xr);
	widget_set_user_id(ptd->editor, IDC_FIREEDIT);
	widget_set_owner(ptd->editor, widget);
	
	widget_set_xfont(ptd->editor, &xf);
	widget_set_color_mode(ptd->editor, &ob);

	widget_show(ptd->editor, WS_SHOW_NORMAL);
	widget_set_focus(ptd->editor);

	if (ptd->buf)
	{
		editbox_set_text(ptd->editor, ptd->buf);
		editbox_selectall(ptd->editor);
	}

	return 0;
}

void hand_inputdlg_destroy(res_win_t widget)
{
	inputdlg_delta_t* ptd = GETINPUTDLGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (ptd->editor)
		widget_destroy(ptd->editor);

	if (ptd->button)
		widget_destroy(ptd->button);

	xmem_free(ptd);

	SETINPUTDLGDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_inputdlg_child_command(res_win_t widget, int code, vword_t data)
{
	inputdlg_delta_t* ptd = GETINPUTDLGDELTA(widget);

	switch (code)
	{
	case COMMAND_COMMIT:
		noti_inputdlg_commit_edit(widget);
		break;
	case COMMAND_ROLLBACK:
		noti_inputdlg_rollback_edit(widget);
		break;
	}
}

void hand_inputdlg_menu_command(res_win_t widget, int code, int cid, vword_t data)
{
	inputdlg_delta_t* ptd = GETINPUTDLGDELTA(widget);

	if (cid == IDC_INPUTDLG_PUSHBOX_CLOSE)
	{
		noti_inputdlg_rollback_edit(widget);
	}
}

void hand_inputdlg_size(res_win_t widget, int code, const xsize_t* prs)
{
	inputdlg_delta_t* ptd = GETINPUTDLGDELTA(widget);
	xrect_t xr;

	if (ptd->button)
	{
		widget_get_client_rect(widget, &xr);
		xr.x = xr.w - xr.h;
		xr.w = xr.h;
		widget_move(ptd->button, RECTPOINT(&xr));
		widget_size(ptd->button, RECTSIZE(&xr));
		widget_update(ptd->button);
	}

	if (ptd->editor)
	{
		widget_get_client_rect(widget, &xr);
		xr.w -= xr.h;
		widget_size(ptd->editor, RECTSIZE(&xr));
		widget_update(ptd->editor);
	}

	widget_erase(widget, NULL);
}

void hand_inputdlg_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	inputdlg_delta_t* ptd = GETINPUTDLGDELTA(widget);
	visual_t rdc;
	xfont_t xf = { 0 };
	xface_t xa = { 0 };
	xpen_t xp = { 0 };
	xbrush_t xb = { 0 };
	xrect_t xr;

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

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	

	end_canvas_paint(canv, dc, pxr);
}

/***************************************************************************************/
res_win_t inputdlg_create(const tchar_t* title, tchar_t* buf, int max, res_win_t owner)
{
	if_event_t ev = { 0 };
	INPUTPARAM pm = { 0 };
	clr_mod_t clr = { 0 };
	xrect_t xr = { 0 };
	res_win_t dlg;

	pm.buf = buf;
	pm.max = max;

	ev.param = (void*)&pm;

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_inputdlg_create)
		EVENT_ON_DESTROY(hand_inputdlg_destroy)

		EVENT_ON_PAINT(hand_inputdlg_paint)

		EVENT_ON_SIZE(hand_inputdlg_size)

		EVENT_ON_CHILD_COMMAND(hand_inputdlg_child_command)

		EVENT_ON_MENU_COMMAND(hand_inputdlg_menu_command)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH
	
	dlg = widget_create(NULL, WD_STYLE_POPUP | WD_STYLE_BORDER, &xr, owner, &ev);

	widget_set_title(dlg, title);

	inputdlg_popup_size(dlg, RECTSIZE(&xr));
	widget_size(dlg, RECTSIZE(&xr));
	widget_update(dlg);

	widget_center_window(dlg, owner);

	if (widget_is_valid(owner) && widget_has_struct(owner))
	{
		widget_get_color_mode(owner, &clr);
		widget_set_color_mode(dlg, &clr);
	}

	return dlg;
}

void inputdlg_popup_size(res_win_t widget, xsize_t* pxs)
{
	inputdlg_delta_t* ptd = GETINPUTDLGDELTA(widget);

	xfont_t xf = { 0 };
	xsize_t xs;
	float pm;

	widget_get_xfont(widget, &xf);

	font_metric_by_pt(xstof(xf.size), &pm, NULL);
	xs.fw = pm;
	xs.fh = pm;
	widget_size_to_pt(widget, &xs);

	xs.h = (int)((float)xs.h * 1.25);
	xs.w = 15 * xs.w;

	widget_adjust_size(widget_get_style(widget), &xs);

	pxs->w = xs.w;
	pxs->h = xs.h;
}


