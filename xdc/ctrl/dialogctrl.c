/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc dialog control document

	@module	dialogctrl.c | implement file

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


#define DIALOG_LINE_FEED		(float)50
#define DIALOG_ITEM_MIN_WIDTH	(float)10
#define DIALOG_ITEM_MIN_HEIGHT	(float)10

typedef struct _dialog_delta_t{
	link_t_ptr dialog;
	link_t_ptr item;
	link_t_ptr hover;
}dialog_delta_t;

#define GETDIALOGDELTA(ph) 	(dialog_delta_t*)widget_get_user_delta(ph)
#define SETDIALOGDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/******************************************dialog event********************************************************/

static void _dialogctrl_item_rect(widget_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	calc_dialog_item_rect(ptd->dialog, ilk, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _dialogctrl_reset_page(widget_t widget)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	int pw, ph, vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	if(ptd->dialog)
	{
		xs.fw = get_dialog_width(ptd->dialog);
		xs.fh = get_dialog_height(ptd->dialog);

		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}else{
		vw = pw;
		vh = ph;
	}

	xs.fw = (float)10;
	xs.fh = (float)10;
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	widget_reset_paging(widget, pw, ph, vw, vh, lw, lh);

	widget_reset_scroll(widget, 1);

	widget_reset_scroll(widget, 0);
}

static void _dialogctrl_ensure_visible(widget_t widget)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	xrect_t xr = { 0 };

	if (!ptd->item)
		return;

	_dialogctrl_item_rect(widget, ptd->item, &xr);

	widget_ensure_visible(widget, &xr, 1);
}
/*********************************************************************************************************/
int noti_dialog_owner(widget_t widget, unsigned int code, link_t_ptr ptr, link_t_ptr ilk, void* data)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	NOTICE_DIALOG nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;

	nf.data = data;

	nf.dialog = ptr;
	nf.item = ilk;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);
	return nf.ret;
}

bool_t noti_dialog_item_changing(widget_t widget)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->item);

	if (noti_dialog_owner(widget, NC_DIALOGITEMKILLFOCUS, ptd->dialog, ptd->item, NULL))
		return (bool_t)0;

	_dialogctrl_item_rect(widget, ptd->item, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	ptd->item = NULL;

	widget_erase(widget, &xr);

	return (bool_t)1;
}

void noti_dialog_item_changed(widget_t widget, link_t_ptr ilk)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ilk);
	XDK_ASSERT(!ptd->item);

	ptd->item = ilk;

	_dialogctrl_item_rect(widget, ptd->item, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);

	noti_dialog_owner(widget, NC_DIALOGITEMSETFOCUS, ptd->dialog, ilk, NULL);
}

void noti_dialog_item_enter(widget_t widget, link_t_ptr ilk)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	XDK_ASSERT(ilk);
	XDK_ASSERT(!ptd->hover);

	ptd->hover = ilk;

	//widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
}

void noti_dialog_item_leave(widget_t widget)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	ptd->hover = NULL;

	//widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
}

void noti_dialog_item_hover(widget_t widget, int x, int y)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	xpoint_t pt;

	XDK_ASSERT(ptd->hover != NULL);

	pt.x = x;
	pt.y = y;
	noti_dialog_owner(widget, NC_DIALOGITEMHOVER, ptd->dialog, ptd->hover, (void*)&pt);
}

void noti_dialog_calc(widget_t widget)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
}

/*******************************************************************************/
int hand_dialog_create(widget_t widget, void* data)
{
	dialog_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (dialog_delta_t*)xmem_alloc(sizeof(dialog_delta_t));
	xmem_zero((void*)ptd, sizeof(dialog_delta_t));

	SETDIALOGDELTA(widget, ptd);

	return 0;
}

void hand_dialog_destroy(widget_t widget)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETDIALOGDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_dialog_size(widget_t widget, int code, const xsize_t* prs)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

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

	_dialogctrl_reset_page(widget);
}

void hand_dialog_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	if (!ptd->dialog)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_dialog_mouse_move(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	link_t_ptr ilk;
	xpoint_t pt;

	if (!ptd->dialog)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	ilk = NULL;
	calc_dialog_hint(&pt, ptd->dialog, &ilk);

	if (widget_is_hotvoer(widget))
	{
		if (!ptd->hover && ilk)
		{
			noti_dialog_item_enter(widget, ilk);
			return;
		}

		if (ptd->hover && ptd->hover != ilk)
		{
			noti_dialog_item_leave(widget);
			return;
		}

		if (ptd->hover)
		{
			noti_dialog_item_leave(widget);
		}
	}
}

void hand_dialog_mouse_hover(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	if (!ptd->dialog)
		return;

	if (ptd->hover)
		noti_dialog_item_hover(widget, pxp->x, pxp->y);
}

void hand_dialog_mouse_leave(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	if (!ptd->dialog)
		return;

	if (ptd->hover)
		noti_dialog_item_leave(widget);
}

void hand_dialog_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	int nHint;
	link_t_ptr ilk;
	bool_t bRe;
	xpoint_t pt;

	if (!ptd->dialog)
		return;

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}
}

void hand_dialog_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	link_t_ptr ilk;
	bool_t bRe;
	xpoint_t pt;

	if (!ptd->dialog)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	ilk = NULL;
	calc_dialog_hint(&pt, ptd->dialog, &ilk);

	bRe = (ilk == ptd->item) ? 1 : 0;

	if (ptd->item && !bRe)
	{
		if (!noti_dialog_item_changing(widget))
			bRe = 1;
	}

	if (ilk && !bRe)
	{
		noti_dialog_item_changed(widget, ilk);
	}

	noti_dialog_owner(widget, NC_DIALOGLBCLK, ptd->dialog, ptd->item, (void*)pxp);
}

void hand_dialog_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	if (!ptd->dialog)
		return;

	noti_dialog_owner(widget, NC_DIALOGDBCLK, ptd->dialog, ptd->item, (void*)pxp);
}

void hand_dialog_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	if (!ptd->dialog)
		return;
}

void hand_dialog_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	if (!ptd->dialog)
		return;

	noti_dialog_owner(widget, NC_DIALOGRBCLK, ptd->dialog, ptd->item, (void*)pxp);
}

void hand_dialog_keydown(widget_t widget, dword_t ks, int nKey)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	if (!ptd->dialog)
		return;
}

void hand_dialog_notice(widget_t widget, NOTICE* pnt)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	if (!ptd->dialog)
		return;
}

void hand_dialog_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	xrect_t xr = { 0 };
	visual_t rdc;
	link_t_ptr ilk;

	canvas_t canv;
	drawing_interface ifc = {0};
	drawing_interface ifv = {0};

	const color_mod_t *pclrs;
	xbrush_t xb;
	xpen_t xp;
	xcolor_t xc;

	if (!ptd->dialog) return;

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

	draw_dialog(&ifc, ptd->dialog);
	
	//draw focus
	if (ptd->item)
	{
		_dialogctrl_item_rect(widget, ptd->item, &xr);

		parse_xcolor(&xc, DEF_ENABLE_COLOR);

		draw_focus_raw(&ifv, &xc, &xr, ALPHA_SOLID);
	}

	end_canvas_paint(canv, dc, pxr);
	
}

/***********************************************function********************************************************/

widget_t dialogctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_dialog_create)
		EVENT_ON_DESTROY(hand_dialog_destroy)

		EVENT_ON_PAINT(hand_dialog_paint)

		EVENT_ON_SIZE(hand_dialog_size)

		EVENT_ON_SCROLL(hand_dialog_scroll)

		EVENT_ON_KEYDOWN(hand_dialog_keydown)

		EVENT_ON_MOUSE_MOVE(hand_dialog_mouse_move)
		EVENT_ON_MOUSE_HOVER(hand_dialog_mouse_hover)
		EVENT_ON_MOUSE_LEAVE(hand_dialog_mouse_leave)

		EVENT_ON_LBUTTON_DBCLICK(hand_dialog_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_dialog_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_dialog_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_dialog_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_dialog_rbutton_up)

		EVENT_ON_NOTICE(hand_dialog_notice)

		

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void dialogctrl_attach(widget_t widget, link_t_ptr ptr)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(ptr && is_dialog_doc(ptr));

	ptd->dialog = ptr;
	ptd->item = NULL;

	dialogctrl_redraw(widget);
}

link_t_ptr dialogctrl_detach(widget_t widget)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	link_t_ptr data;

	XDK_ASSERT(ptd != NULL);

	data = ptd->dialog;
	ptd->dialog = NULL;
	ptd->item = NULL;

	widget_erase(widget, NULL);

	return data;
}

link_t_ptr dialogctrl_fetch(widget_t widget)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->dialog;
}

void dialogctrl_redraw(widget_t widget)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	link_t_ptr ilk;
	bool_t b_valid;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->dialog)
		return;

	b_valid = 0;
	ilk = get_dialog_next_item(ptd->dialog, LINK_FIRST);
	while (ilk)
	{
		if (ilk == ptd->item)
			b_valid = 1;

		noti_dialog_owner(widget, NC_DIALOGITEMCALCED, ptd->dialog, ilk, NULL);

		ilk = get_dialog_next_item(ptd->dialog, ilk);
	}
	
	noti_dialog_owner(widget, NC_DIALOGCALCED, ptd->dialog, NULL, NULL);

	if (!b_valid)
	{
		ptd->item = NULL;
	}
	ptd->hover = NULL;

	_dialogctrl_reset_page(widget);
	widget_erase(widget, NULL);
}

void dialogctrl_redraw_item(widget_t widget, link_t_ptr ilk)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->dialog)
		return;

#ifdef _DEBUG
	if(!is_dialog_item(ptd->dialog, ilk))
		return;
#endif

	noti_dialog_owner(widget, NC_DIALOGITEMCALCED, ptd->dialog, ilk, NULL);

	_dialogctrl_item_rect(widget, ilk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

void dialogctrl_tabskip(widget_t widget, int nSkip)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	link_t_ptr ilk = NULL;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->dialog)
		return;

	switch (nSkip)
	{
	case TABORDER_LEFT:
	case TABORDER_UP:
		if (ptd->item == NULL)
			ilk = get_dialog_prev_item(ptd->dialog, LINK_LAST);
		else
			ilk = get_dialog_prev_item(ptd->dialog, ptd->item);
		break;
	case TABORDER_RIGHT:
	case TABORDER_DOWN:
		if (ptd->item == NULL)
			ilk = get_dialog_next_item(ptd->dialog, LINK_FIRST);
		else
			ilk = get_dialog_next_item(ptd->dialog, ptd->item);
		break;
	case TABORDER_HOME:
		ilk = get_dialog_next_item(ptd->dialog, LINK_FIRST);
		break;
	case TABORDER_END:
		ilk = get_dialog_prev_item(ptd->dialog, LINK_LAST);
		break;
	}

	dialogctrl_set_focus_item(widget, ilk);
}

bool_t dialogctrl_set_focus_item(widget_t widget, link_t_ptr ilk)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	bool_t bRe;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->dialog)
		return 0;

	if (ilk)
	{
#ifdef _DEBUG
		XDK_ASSERT(is_dialog_item(ptd->dialog, ilk));
#endif
	}

	bRe = (ilk == ptd->item) ? (bool_t)1 : (bool_t)0;
	if (bRe)
		return (bool_t)1;

	if (ptd->item && !bRe)
	{
		if (!noti_dialog_item_changing(widget))
			return (bool_t)0;
	}

	if (ilk && !bRe)
	{
		noti_dialog_item_changed(widget, ilk);

		_dialogctrl_ensure_visible(widget);
	}

	return (bool_t)1;
}

link_t_ptr dialogctrl_get_focus_item(widget_t widget)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->dialog)
		return NULL;

	return ptd->item;
}

void dialogctrl_get_dialog_item_rect(widget_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	if (!ptd->dialog)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_dialog_item(ptd->dialog, ilk));
#endif

	_dialogctrl_item_rect(widget, ilk, pxr);
}

bool_t dialogctrl_get_dirty(widget_t widget)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->dialog)
		return 0;

	return 0;
}

void dialogctrl_set_dirty(widget_t widget, bool_t bDirty)
{
	dialog_delta_t* ptd = GETDIALOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->dialog)
		return;
}
