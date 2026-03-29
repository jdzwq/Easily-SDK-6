/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc notes control documilk

	@module	notesctrl.c | implement file

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


typedef struct _notes_delta_t{
	link_t_ptr arch;
	link_t_ptr item;
	link_t_ptr hover;

	widget_t vsc;
	bool_t b_delete;
}notes_delta_t;

#define GETNOTESDELTA(ph) 	(notes_delta_t*)widget_get_user_delta(ph)
#define SETNOTESDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/***************************************************************************************/

static int _notesctrl_calc_width(widget_t widget)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	canvas_t canv;
	measure_interface im = { 0 };
	const xfont_t *pxf;
	xsize_t xs;

	pxf = widget_get_xfont_ptr(widget);
	canv = widget_get_canvas(widget);
	get_canvas_measure(canv, &im);
	widget_get_canv_rect(widget, (canvbox_t*)&(im.rect));

	xs.fw = calc_notes_width(&im, pxf, ptd->arch);
	xs.fh = 0;

	widget_size_to_pt(widget, &xs);

	return xs.w;
}

static int _notesctrl_calc_height(widget_t widget)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	canvas_t canv;
	measure_interface im = { 0 };
	const xfont_t *pxf;
	xsize_t xs;

	pxf = widget_get_xfont_ptr(widget);
	canv = widget_get_canvas(widget);
	get_canvas_measure(canv, &im);
	widget_get_canv_rect(widget, (canvbox_t*)&(im.rect));

	xs.fw = 0;
	xs.fh = calc_notes_height(&im, pxf, ptd->arch);

	widget_size_to_pt(widget, &xs);

	return xs.h;
}

static int _notesctrl_calc_hint(widget_t widget, const xpoint_t* ppt, link_t_ptr* pplk)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	canvas_t canv;
	measure_interface im = { 0 };
	const xfont_t *pxf;
	xpoint_t pt;
	int hint;

	pxf = widget_get_xfont_ptr(widget);
	canv = widget_get_canvas(widget);
	get_canvas_measure(canv, &im);
	widget_get_canv_rect(widget, (canvbox_t*)&(im.rect));

	pt.x = ppt->x;
	pt.y = ppt->y;
	widget_point_to_mm(widget, &pt);

	*pplk = NULL;
	hint = calc_notes_hint(&im, pxf, &pt, ptd->arch, pplk);

	return hint;
}

static void _notesctrl_item_rect(widget_t widget, link_t_ptr plk, xrect_t* pxr)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	canvas_t canv;
	measure_interface im = { 0 };
	const xfont_t *pxf;
	xrect_t xr;
	int hint;

	pxf = widget_get_xfont_ptr(widget);
	canv = widget_get_canvas(widget);
	get_canvas_measure(canv, &im);
	widget_get_canv_rect(widget, (canvbox_t*)&(im.rect));

	calc_notes_item_rect(&im, pxf, ptd->arch, plk, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _notesctrl_reset_page(widget_t widget)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	xrect_t xr;
	int mh;

	widget_get_client_rect(widget, &xr);

	if(ptd->arch)
		mh = _notesctrl_calc_height(widget);
	else
		mh = xr.h;

	widget_reset_paging(widget, xr.w, xr.h, xr.w, mh, 0, 0);
}

static void _notesctrl_ensure_visible(widget_t widget)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	xrect_t xr;

	if (!ptd->item)
		return;

	_notesctrl_item_rect(widget, ptd->item, &xr);

	widget_ensure_visible(widget, &xr, 1);
}

/*************************************************************************/

int noti_notes_owner(widget_t widget, unsigned int code, link_t_ptr arch, link_t_ptr item, void* data)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	NOTICE_NOTES nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;
	nf.data = data;
	nf.ret = 0;

	nf.arch = arch;
	nf.item = item;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);
	return nf.ret;
}

bool_t noti_notes_item_changing(widget_t widget)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->item);

	if (noti_notes_owner(widget, NC_NOTESITEMCHANGING, ptd->arch, ptd->item, NULL))
		return 0;

	_notesctrl_item_rect(widget,ptd->item, &xr);

	ptd->item = NULL;

	widget_erase(widget, &xr);

	return 1;
}

void noti_notes_item_changed(widget_t widget, link_t_ptr elk)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(!ptd->item);

	ptd->item = elk;

	_notesctrl_item_rect(widget, ptd->item, &xr);
	
	widget_erase(widget, &xr);
}

bool_t noti_notes_item_delete(widget_t widget, link_t_ptr ilk)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	if (noti_notes_owner(widget, NC_NOTESITEMDELETE, ptd->arch, ilk, NULL))
		return 0;

	return 1;
}

void noti_notes_item_enter(widget_t widget, link_t_ptr plk)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	XDK_ASSERT(plk);
	XDK_ASSERT(!ptd->hover);

	ptd->hover = plk;

	if (widget_is_hotvoer(widget))
	{
		//widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
	}
}

void noti_notes_item_leave(widget_t widget)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	ptd->hover = NULL;

	if (widget_is_hotvoer(widget))
	{
		//widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
	}
}

void noti_notes_item_hover(widget_t widget, int x, int y)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	xpoint_t xp;

	XDK_ASSERT(ptd->hover != NULL);

	xp.x = x;
	xp.y = y;
	noti_notes_owner(widget, NC_NOTESITEMHOVER, ptd->arch, ptd->hover, (void*)&xp);
}

void noti_notes_reset_scroll(widget_t widget, bool_t bUpdate)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	if (widget_is_valid(ptd->vsc))
	{
		if (bUpdate)
			widget_erase(ptd->vsc, NULL);
		else
			widget_close(ptd->vsc, 0);
	}
}

/********************************************************************************************/

int hand_notes_create(widget_t widget, void* data)
{
	notes_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (notes_delta_t*)xmem_alloc(sizeof(notes_delta_t));

	SETNOTESDELTA(widget, ptd);

	return 0;
}

void hand_notes_destroy(widget_t widget)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (widget_is_valid(ptd->vsc))
		widget_destroy(ptd->vsc);

	xmem_free(ptd);

	SETNOTESDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_notes_keydown(widget_t widget, dword_t ks, int key)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	if (!ptd->arch)
		return;

	switch (key)
	{
	case KEY_ENTER:
		break;
	case KEY_SPACE:
		break;
	case KEY_LEFT:
		notesctrl_tabskip(widget,TABORDER_LEFT);
		break;
	case KEY_RIGHT:
		notesctrl_tabskip(widget,TABORDER_RIGHT);
		break;
	case KEY_HOME:
		notesctrl_tabskip(widget,TABORDER_HOME);
		break;
	case KEY_END:
		notesctrl_tabskip(widget,TABORDER_END);
		break;
	}
}

void hand_notes_mouse_move(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	link_t_ptr plk = NULL;
	int hint;

	if (!ptd->arch)
		return;

	hint = _notesctrl_calc_hint(widget, pxp, &plk);

	if (!ptd->hover && plk)
	{
		noti_notes_item_enter(widget, plk);
	}
	else if (ptd->hover && ptd->hover != plk)
	{
		noti_notes_item_leave(widget);
	}
}

void hand_notes_mouse_hover(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	if (!ptd->arch)
		return;

	if (ptd->hover)
		noti_notes_item_hover(widget, pxp->x, pxp->y);
}

void hand_notes_mouse_leave(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	if (!ptd->arch)
		return;

	if (ptd->hover)
		noti_notes_item_leave(widget);
}

void hand_notes_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	if (!ptd->arch)
		return;

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}
}

void hand_notes_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	link_t_ptr ilk = NULL;
	int hint;
	bool_t bRe;

	if (!ptd->arch)
		return;

	hint = _notesctrl_calc_hint(widget, pxp, &ilk);

	if (ptd->b_delete && hint == _NOTES_HINT_CLOSE)
	{
		if (noti_notes_item_delete(widget, ilk))
		{
			delete_arch_item(ilk);

			notesctrl_redraw(widget);
			return;
		}
	}

	bRe = (ilk == ptd->item) ? 1 : 0;

	if (!bRe && ptd->item)
	{
		if (!noti_notes_item_changing(widget))
			bRe = 1;
	}

	if (ilk && !bRe)
	{
		noti_notes_item_changed(widget, ilk);
	}

	noti_notes_owner(widget, NC_NOTESLBCLK, ptd->arch, ptd->item, (void*)pxp);
}

void hand_notes_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	if (!ptd->arch)
		return;

	noti_notes_owner(widget, NC_NOTESDBCLK, ptd->arch, ptd->item, (void*)pxp);
}

void hand_notes_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	if (!ptd->arch)
		return;
}

void hand_notes_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	if (!ptd->arch)
		return;

	noti_notes_owner(widget, NC_NOTESRBCLK, ptd->arch, ptd->item, (void*)pxp);
}

void hand_notes_size(widget_t widget, int code, const xsize_t* prs)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

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

	_notesctrl_reset_page(widget);
}

void hand_notes_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	if (!ptd->arch)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_notes_wheel(widget_t widget, bool_t bHorz, int nDelta)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	scroll_t scr = { 0 };
	int nLine;
	widget_t win;

	if (!ptd->arch)
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

		return;
	}

	win = widget_get_parent(widget);

	if (widget_is_valid(win))
	{
		widget_scroll(win, bHorz, nLine);
	}
}

void hand_notes_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	visual_t rdc;
	canvas_t canv;
	drawing_interface ifc = {0};
	drawing_interface ifv = {0};
	xrect_t xr;

	const color_mod_t *pclrs;
	const xfont_t *pxf;
	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };
	xcolor_t xc = { 0 };

	if (!ptd->arch) return;

	pxf = widget_get_xfont_ptr(widget);
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

	(*ifv.drw->pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	draw_notes(&ifc, pxf, &xp, &xb, ptd->arch, ptd->item);

	end_canvas_paint(canv, dc, pxr);
}

/************************************************************************************************/
widget_t notesctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_notes_create)
		EVENT_ON_DESTROY(hand_notes_destroy)

		EVENT_ON_PAINT(hand_notes_paint)

		EVENT_ON_SIZE(hand_notes_size)

		EVENT_ON_SCROLL(hand_notes_scroll)
		EVENT_ON_WHEEL(hand_notes_wheel)

		EVENT_ON_KEYDOWN(hand_notes_keydown)

		EVENT_ON_MOUSE_MOVE(hand_notes_mouse_move)
		EVENT_ON_MOUSE_HOVER(hand_notes_mouse_hover)
		EVENT_ON_MOUSE_LEAVE(hand_notes_mouse_leave)

		EVENT_ON_LBUTTON_DOWN(hand_notes_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_notes_lbutton_up)
		EVENT_ON_LBUTTON_DBCLICK(hand_notes_lbutton_dbclick)
		EVENT_ON_RBUTTON_DOWN(hand_notes_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_notes_rbutton_up)

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void notesctrl_attach(widget_t widget, link_t_ptr ptr)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(ptr && is_arch_doc(ptr));

	ptd->arch = ptr;

	notesctrl_redraw(widget);
}

link_t_ptr notesctrl_detach(widget_t widget)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	link_t_ptr data;

	XDK_ASSERT(ptd != NULL);

	data = ptd->arch;
	ptd->arch = NULL;

	notesctrl_redraw(widget);

	return data;
}

link_t_ptr notesctrl_fetch(widget_t widget)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->arch;
}

void notesctrl_enable_delete(widget_t widget, bool_t bDelete)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_delete = bDelete;
}

void notesctrl_redraw(widget_t widget)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	link_t_ptr ilk, doc;
	bool_t b_valid;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->arch)
		return;

	b_valid = 0;
	ilk = get_arch_first_child_item(ptd->arch);
	while (ilk)
	{
		doc = fetch_arch_document(ilk);

		if (ilk == ptd->item)
			b_valid = 1;

		noti_notes_owner(widget, NC_NOTESITEMCALCED, ptd->arch, ilk, NULL);

		ilk = get_arch_next_sibling_item(ilk);
	}

	noti_notes_owner(widget, NC_NOTESCALCED, ptd->arch, NULL, NULL);

	if (!b_valid)
	{
		ptd->item = NULL;
	}

	_notesctrl_reset_page(widget);
	widget_erase(widget, NULL);
}

void notesctrl_redraw_item(widget_t widget, link_t_ptr ilk)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->arch)
		return;

	noti_notes_owner(widget, NC_NOTESITEMCALCED, ptd->arch, ilk, NULL);

	_notesctrl_item_rect(widget, ilk, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

bool_t notesctrl_set_focus_item(widget_t widget, link_t_ptr ilk)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	bool_t bRe;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->arch)
		return 0;

	if (ilk)
	{
#ifdef _DEBUG
		XDK_ASSERT(is_arch_document(ptd->arch, ilk) || is_arch_catalog(ptd->arch, ilk));
#endif
	}

	bRe = (ilk == ptd->item) ? 1 : 0;

	if (!bRe && ptd->item)
	{
		if (!noti_notes_item_changing(widget))
			return 0;
	}

	if (!bRe && ilk)
	{
		noti_notes_item_changed(widget, ilk);

		_notesctrl_ensure_visible(widget);
	}

	return 1;
}

link_t_ptr notesctrl_get_focus_item(widget_t widget)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->arch)
		return NULL;

	return ptd->item;
}

void notesctrl_get_item_rect(widget_t widget, link_t_ptr elk, xrect_t* prt)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->arch)
		return;

	_notesctrl_item_rect(widget, elk, prt);
}

void notesctrl_tabskip(widget_t widget, int nSkip)
{
	notes_delta_t* ptd = GETNOTESDELTA(widget);
	link_t_ptr plk = NULL;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->arch)
		return;

	switch (nSkip)
	{
	case TABORDER_RIGHT:
	case TABORDER_DOWN:
		if (ptd->item)
			plk = get_arch_next_sibling_item(ptd->item);
		else
			plk = get_arch_first_child_item(ptd->arch);

		if (plk)
			notesctrl_set_focus_item(widget, plk);
		break;
	case TABORDER_LEFT:
	case TABORDER_UP:
		if (ptd->item)
			plk = get_arch_prev_sibling_item(ptd->item);
		else
			plk = get_arch_last_child_item(ptd->arch);

		if (plk)
			notesctrl_set_focus_item(widget, plk);
		break;
	case TABORDER_HOME:
		plk = get_arch_first_child_item(ptd->arch);

		if (plk)
			notesctrl_set_focus_item(widget, plk);
		break;
	case TABORDER_END:
		plk = get_arch_last_child_item(ptd->arch);

		if (plk)
			notesctrl_set_focus_item(widget, plk);
		break;
	}
}
