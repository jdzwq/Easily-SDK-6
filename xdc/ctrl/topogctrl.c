/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc topog control document

	@module	topogctrl.c | implement file

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


typedef struct _topog_delta_t{
	link_t_ptr topog;
	link_t_ptr spot;
	link_t_ptr hover;

	widget_t hsc;
	widget_t vsc;

	int org_x, org_y;
	int row, col;

	ximage_t img;
}topog_delta_t;


#define GETTOPOGDELTA(ph) 	(topog_delta_t*)widget_get_user_delta(ph)
#define SETTOPOGDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/***********************************************************************/

static void _topogctrl_spot_rect(widget_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	calc_topog_spot_rect(ptd->topog, ilk, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _topogctrl_ensure_visible(widget_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xrect_t xr = { 0 };

	if (!ptd->spot)
		return;

	_topogctrl_spot_rect(widget, ptd->spot, &xr);

	widget_ensure_visible(widget, &xr, 1);
}

static void _topogctrl_reset_matrix(widget_t widget, int row, int col)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	int rows, cols;
	matrix_t mt = NULL;
	bool_t b;
	tchar_t* buf;
	void* tmp;
	int len;

	if (!ptd->topog)
		return;

	rows = get_topog_rows(ptd->topog);
	cols = get_topog_cols(ptd->topog);

	if (row < 0 || row >= rows)
		return;

	if (col < 0 || col >= cols)
		return;

	mt = matrix_alloc(rows, cols);
	tmp = xmem_alloc(matrix_need_size(rows, cols));
	matrix_attach(mt, tmp);

	matrix_parse(mt, get_topog_matrix_ptr(ptd->topog), -1);

	b = ((int)matrix_get_value(mt, row, col)) ? 0 : 1;
	matrix_set_value(mt, row, col, (double)b);

	len = matrix_format(mt, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	len = matrix_format(mt, buf, len);

	tmp = matrix_detach(mt);
	xmem_free(tmp);
	matrix_free(mt);

	set_topog_matrix(ptd->topog, buf, len);
	xsfree(buf);

	widget_erase(widget, NULL);
}

static void _topogctrl_reset_page(widget_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	int pw, ph, vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	if (ptd->topog)
	{
		widget_rect_to_mm(widget, &xr);
		set_topog_width(ptd->topog, xr.fw);
		set_topog_height(ptd->topog, xr.fh);

		xs.fw = get_topog_cols(ptd->topog) * get_topog_rx(ptd->topog);
		xs.fh = get_topog_rows(ptd->topog) * get_topog_ry(ptd->topog);
		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}
	else
	{
		vw = pw;
		vh = ph;
	}

	xs.fw = 10.0f;
	xs.fh = 10.0f;
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	widget_reset_paging(widget, pw, ph, vw, vh, lw, lh);

	widget_reset_scroll(widget, 1);

	widget_reset_scroll(widget, 0);
}

/***********************************************************************/

int noti_topog_owner(widget_t widget, unsigned int code, link_t_ptr topog, link_t_ptr spot, int row, int col, void* data)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	NOTICE_TOPOG nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;
	nf.data = data;
	nf.ret = 0;

	nf.topog = topog;
	nf.spot = spot;
	nf.row = row;
	nf.col = col;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);
	return nf.ret;
}

void noti_topog_reset_select(widget_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	link_t_ptr ilk;
	int count = 0;

	ilk = get_topog_next_spot(ptd->topog, LINK_FIRST);
	while (ilk)
	{
		if (get_topog_spot_selected(ilk))
		{
			set_topog_spot_selected(ilk, 0);
			noti_topog_owner(widget, NC_TOPOGSPOTSELECTED, ptd->topog, ilk, get_topog_spot_row(ilk), get_topog_spot_col(ilk), NULL);

			count++;
		}

		ilk = get_topog_next_spot(ptd->topog, ilk);
	}

	if (count)
	{
		widget_erase(widget, NULL);
	}
}

void noti_topog_spot_selected(widget_t widget, link_t_ptr ilk)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xrect_t xr;
	bool_t b_check;

	b_check = get_topog_spot_selected(ilk);

	if (b_check)
		set_topog_spot_selected(ilk, 0);
	else
		set_topog_spot_selected(ilk, 1);

	noti_topog_owner(widget, NC_TOPOGSPOTSELECTED, ptd->topog, ilk, get_topog_spot_row(ilk), get_topog_spot_col(ilk), NULL);

	_topogctrl_spot_rect(widget, ilk, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

bool_t noti_topog_spot_changing(widget_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->spot);

	if (noti_topog_owner(widget, NC_TOPOGSPOTCHANGING, ptd->topog, ptd->spot, ptd->row, ptd->col, NULL))
		return (bool_t)0;

	_topogctrl_spot_rect(widget, ptd->spot, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	ptd->spot = NULL;
	ptd->row = -1;
	ptd->col = -1;

	widget_erase(widget, &xr);

	return (bool_t)1;
}

void noti_topog_spot_changed(widget_t widget, link_t_ptr ilk)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ilk);
	XDK_ASSERT(!ptd->spot);

	ptd->spot = ilk;
	ptd->row = get_topog_spot_row(ilk);
	ptd->col = get_topog_spot_col(ilk);

	_topogctrl_spot_rect(widget, ptd->spot, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);

	noti_topog_owner(widget, NC_TOPOGSPOTCHANGED, ptd->topog, ptd->spot, ptd->row, ptd->col, NULL);
}

void noti_topog_spot_enter(widget_t widget, link_t_ptr ilk)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ilk);
	XDK_ASSERT(!ptd->hover);

	ptd->hover = ilk;

	if (widget_is_hotvoer(widget))
	{
		//widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
	}
}

void noti_topog_spot_leave(widget_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	ptd->hover = NULL;

	if (widget_is_hotvoer(widget))
	{
		//widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
	}
}

void noti_topog_spot_hover(widget_t widget, int x, int y)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xpoint_t xp;

	XDK_ASSERT(ptd->hover != NULL);

	xp.x = x;
	xp.y = y;
	noti_topog_owner(widget, NC_TOPOGSPOTHOVER, ptd->topog, ptd->hover, get_topog_spot_row(ptd->hover), get_topog_spot_col(ptd->hover), (void*)&xp);
}

void noti_topog_reset_scroll(widget_t widget, bool_t bUpdate)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (widget_is_valid(ptd->vsc))
	{
		if (bUpdate)
			widget_erase(ptd->vsc, NULL);
		else
			widget_close(ptd->vsc, 0);
	}

	if (widget_is_valid(ptd->hsc))
	{
		if (bUpdate)
			widget_erase(ptd->hsc, NULL);
		else
			widget_close(ptd->hsc, 0);
	}
}

/***********************************************************************/

int hand_topogctrl_create(widget_t widget, void* data)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	widget_hand_create(widget);

	ptd = (topog_delta_t*)xmem_alloc(sizeof(topog_delta_t));
	xmem_zero((void*)ptd, sizeof(topog_delta_t));

	xmem_zero((void*)&ptd->img, sizeof(ximage_t));

	SETTOPOGDELTA(widget, ptd);

	return 0;
}

void hand_topogctrl_destroy(widget_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (widget_is_valid(ptd->hsc))
		widget_destroy(ptd->hsc);

	if (widget_is_valid(ptd->vsc))
		widget_destroy(ptd->vsc);

	if (ptd->img.source)
		xsfree(ptd->img.source);

	xmem_free(ptd);

	SETTOPOGDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_topogctrl_mouse_move(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	int nHint;
	link_t_ptr ilk;
	xpoint_t pt;
	int row, col;

	if (!ptd->topog)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	ilk = NULL;
	row = col = -1;
	nHint = calc_topog_hint(&pt, ptd->topog, &ilk, &row, &col);

	if (nHint == TOPOG_HINT_SPOT && !ptd->hover && ilk)
	{
		noti_topog_spot_enter(widget, ilk);
	}
	else if (nHint == TOPOG_HINT_SPOT && ptd->hover && ptd->hover != ilk)
	{
		noti_topog_spot_leave(widget);
	}
	else if (nHint != TOPOG_HINT_SPOT && ptd->hover)
	{
		noti_topog_spot_leave(widget);
	}
}

void hand_topogctrl_mouse_hover(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	if (ptd->hover)
		noti_topog_spot_hover(widget, pxp->x, pxp->y);
}

void hand_topogctrl_mouse_leave(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	if (ptd->hover)
		noti_topog_spot_leave(widget);
}

void hand_topogctrl_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	int nHint;
	link_t_ptr ilk;
	bool_t bRe;
	xpoint_t pt;
	int row, col;

	if (!ptd->topog)
		return;

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}
}

void hand_topogctrl_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	int nHint;
	link_t_ptr ilk;
	bool_t bRe;
	xpoint_t pt;
	int row, col;

	if (!ptd->topog)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	ilk = NULL;
	row = col = -1;
	nHint = calc_topog_hint(&pt, ptd->topog, &ilk, &row, &col);

	bRe = (ilk == ptd->spot) ? 1 : 0;

	if (ptd->spot && !bRe)
	{
		if (!noti_topog_spot_changing(widget))
			bRe = 1;
	}

	if (ilk && !bRe)
	{
		noti_topog_spot_changed(widget, ilk);
	}

	ptd->row = row;
	ptd->col = col;

	noti_topog_owner(widget, NC_TOPOGLBCLK, ptd->topog, ptd->spot, ptd->row, ptd->col, (void*)pxp);
}

void hand_topogctrl_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	noti_topog_owner(widget, NC_TOPOGDBCLK, ptd->topog, ptd->spot, ptd->row, ptd->col, (void*)pxp);
}

void hand_topogctrl_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;
}

void hand_topogctrl_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	noti_topog_owner(widget, NC_TOPOGRBCLK, ptd->topog, ptd->spot, ptd->row, ptd->col, (void*)pxp);
}

void hand_topogctrl_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_topogctrl_wheel(widget_t widget, bool_t bHorz, int nDelta)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	scroll_t scr = { 0 };
	int nLine;
	widget_t win;

	if (!ptd->topog)
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

		if (bHorz && !(widget_get_style(widget) & WD_STYLE_HSCROLL))
		{
			if (!widget_is_valid(ptd->hsc))
			{
				ptd->hsc = show_horzbox(widget);
			}
			else
			{
				widget_erase(ptd->hsc, NULL);
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

void hand_topogctrl_keydown(widget_t widget, dword_t ks, int nKey)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	if (nKey == KEY_TAB)
	{
		topogctrl_tabskip(widget, TABORDER_RIGHT);
	}
	else if (nKey == KEY_LEFT || nKey == KEY_UP) // KEY_LEFT KEY_UP
	{
		topogctrl_tabskip(widget, TABORDER_LEFT);
	}
	else if (nKey == KEY_RIGHT || nKey == KEY_DOWN) // KEY_RIGHT KEY_DOWN
	{
		topogctrl_tabskip(widget, TABORDER_RIGHT);
	}
}

void hand_topogctrl_size(widget_t widget, int code, const xsize_t* prs)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

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

	_topogctrl_reset_page(widget);
}

void hand_topogctrl_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	visual_t rdc;
	xrect_t xr;

	canvas_t canv;
	drawing_interface ifc = {0};
	drawing_interface ifv = {0};

	const color_mod_t *pclrs;
	xbrush_t xb;
	xcolor_t xc;

	pclrs = widget_get_color_mode_ptr(widget);
	default_xbrush(&xb);
	format_xcolor(&(pclrs->clr_bkg), xb.color);
	xmem_copy((void*)&xc, (void*)&(pclrs->clr_bkg), sizeof(xcolor_t));

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);
	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
	
	get_visual_interface(rdc, &ifv);
	widget_get_view_rect(widget, (viewbox_t*)&(ifv.rect));

	get_canvas_interface(canv, &ifc);
	widget_get_canv_rect(widget, (canvbox_t*)&(ifc.rect));
	ifc.pclrs = pclrs;
	
	(*ifv.drw->pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	if (ptd->img.source)
	{
		format_xcolor(&(pclrs->clr_msk), ptd->img.color);

		(ifc.drw->pf_draw_image)(ifc.ctx, &(ptd->img), (xrect_t*)&(ifc.rect));
	}

	if (ptd->topog)
	{
		draw_topog(&ifc, ptd->topog);
	}

	end_canvas_paint(canv, dc, pxr);
}

/***********************************************************************/

widget_t topogctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_topogctrl_create)
		EVENT_ON_DESTROY(hand_topogctrl_destroy)

		EVENT_ON_PAINT(hand_topogctrl_paint)

		EVENT_ON_SIZE(hand_topogctrl_size)

		EVENT_ON_SCROLL(hand_topogctrl_scroll)
		EVENT_ON_WHEEL(hand_topogctrl_wheel)

		EVENT_ON_KEYDOWN(hand_topogctrl_keydown)

		EVENT_ON_MOUSE_MOVE(hand_topogctrl_mouse_move)
		EVENT_ON_MOUSE_HOVER(hand_topogctrl_mouse_hover)
		EVENT_ON_MOUSE_LEAVE(hand_topogctrl_mouse_leave)

		EVENT_ON_LBUTTON_DBCLICK(hand_topogctrl_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_topogctrl_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_topogctrl_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_topogctrl_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_topogctrl_rbutton_up)

		

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void topogctrl_attach(widget_t widget, link_t_ptr data)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(data && is_topog_doc(data));

	ptd->topog = data;
	ptd->spot = NULL;
	ptd->row = -1;
	ptd->col = -1;

	widget_get_client_rect(widget, &xr);
	widget_rect_to_mm(widget, &xr);

	set_topog_width(ptd->topog, xr.fw);
	set_topog_height(ptd->topog, xr.fh);

	topogctrl_redraw(widget);
}

link_t_ptr topogctrl_detach(widget_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	link_t_ptr data;

	XDK_ASSERT(ptd != NULL);

	data = ptd->topog;
	ptd->topog = NULL;
	ptd->spot = NULL;
	ptd->row = -1;
	ptd->col = -1;

	widget_erase(widget, NULL);

	return data;
}

link_t_ptr topogctrl_fetch(widget_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->topog;
}

void topogctrl_redraw(widget_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	link_t_ptr ilk;
	bool_t b_valid;


	XDK_ASSERT(ptd != NULL);

	if (!ptd->topog)
		return;

	b_valid = 0;
	ilk = get_topog_next_spot(ptd->topog, LINK_FIRST);
	while (ilk)
	{
		if (ilk == ptd->spot)
			b_valid = 1;

		noti_topog_owner(widget, NC_TOPOGSPOTCALCED, ptd->topog, ilk, get_topog_spot_row(ilk), get_topog_spot_col(ilk), NULL);

		ilk = get_topog_next_spot(ptd->topog, ilk);
	}

	noti_topog_owner(widget, NC_TOPOGCALCED, ptd->topog,  NULL, -1, -1,NULL);

	if (!b_valid)
	{
		ptd->spot = NULL;
		ptd->row = -1;
		ptd->col = -1;
	}
	ptd->hover = NULL;

	_topogctrl_reset_page(widget);
	widget_erase(widget, NULL);
}

void topogctrl_tabskip(widget_t widget, int nSkip)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	link_t_ptr plk = ptd->spot;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->topog)
		return;

	switch (nSkip)
	{
	case TABORDER_RIGHT:
	case TABORDER_DOWN:
		if (plk == NULL)
			plk = get_topog_next_spot(ptd->topog, LINK_FIRST);
		else
			plk = get_topog_next_spot(ptd->topog, plk);

		if (plk)
			topogctrl_set_focus_spot(widget, plk);
		break;
	case TABORDER_LEFT:
	case TABORDER_UP:
		if (plk == NULL)
			plk = get_topog_prev_spot(ptd->topog, LINK_LAST);
		else
			plk = get_topog_prev_spot(ptd->topog, plk);

		if (plk)
			topogctrl_set_focus_spot(widget, plk);
		break;
	}
}

void topogctrl_redraw_spot(widget_t widget, link_t_ptr plk)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->topog)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_topog_spot(ptd->topog, plk));
#endif

	noti_topog_owner(widget, NC_TOPOGSPOTCALCED, ptd->topog, plk, get_topog_spot_row(plk), get_topog_spot_col(plk), NULL);

	_topogctrl_spot_rect(widget, plk, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

bool_t topogctrl_set_focus_spot(widget_t widget, link_t_ptr ilk)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	bool_t bRe;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->topog)
		return 0;

	if (ilk == LINK_FIRST)
		ilk = get_topog_next_spot(ptd->topog, LINK_FIRST);
	else if (ilk == LINK_LAST)
		ilk = get_topog_prev_spot(ptd->topog, LINK_LAST);

	bRe = (ilk == ptd->spot) ? 1 : 0;
	if (bRe)
		return 1;

	if (ptd->spot && !bRe)
	{
		if (!noti_topog_spot_changing(widget))
			return 0;
	}

	if (ilk && !bRe)
	{
		noti_topog_spot_changed(widget, ilk);

		_topogctrl_ensure_visible(widget);
	}

	return 1;
}

link_t_ptr topogctrl_get_focus_spot(widget_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->spot;
}

void topogctrl_get_spot_rect(widget_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->topog)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_topog_spot(ptd->topog, ilk));
#endif

	_topogctrl_spot_rect(widget, ilk, pxr);
}

void topogctrl_get_focus_dot(widget_t widget, int* prow, int* pcol)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	*prow = ptd->row;
	*pcol = ptd->col;
}

bool_t topogctrl_get_dirty(widget_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->topog)
		return 0;

	return 0;
}

void topogctrl_set_dirty(widget_t widget, bool_t bDirty)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->topog)
		return;
}

bool_t topogctrl_set_bitmap(widget_t widget, bitmap_t bmp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	bool_t rt;
	visual_t rdc;

	XDK_ASSERT(ptd != NULL);

	rdc = widget_client_context(widget);

	if (ptd->img.source)
		xsfree(ptd->img.source);

	xmem_zero((void*)&ptd->img, sizeof(ximage_t));

	if (bmp)
		rt = save_bitmap_to_ximage(rdc, bmp, &ptd->img);
	else
		rt = 1;

	widget_release_context(widget, rdc);

	topogctrl_redraw(widget);

	return rt;
}
