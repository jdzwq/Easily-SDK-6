﻿/***********************************************************************
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

#include "../xdcimp.h"
#include "../xdcinit.h"

typedef struct _topog_delta_t{
	link_t_ptr topog;
	link_t_ptr spot;
	link_t_ptr hover;

	res_win_t hsc;
	res_win_t vsc;

	bool_t b_drag;
	int org_x, org_y;
	int row, col;

	ximage_t img;

	link_t_ptr stack;
}topog_delta_t;


#define GETTOPOGDELTA(ph) 	(topog_delta_t*)widget_get_user_delta(ph)
#define SETTOPOGDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/*****************************************************************************/
static void _topogctrl_done(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	byte_t* buf;
	dword_t len;

	XDK_ASSERT(ptd && ptd->topog);

#ifdef _UNICODE
	len = format_dom_doc_to_bytes(ptd->topog, NULL, MAX_LONG, DEF_UCS);
#else
	len = format_dom_doc_to_bytes(ptd->topog, NULL, MAX_LONG, DEF_MBS);
#endif

	buf = (byte_t*)xmem_alloc(len + sizeof(tchar_t));

#ifdef _UNICODE
	format_dom_doc_to_bytes(ptd->topog, buf, len, DEF_UCS);
#else
	format_dom_doc_to_bytes(ptd->topog, buf, len, DEF_MBS);
#endif

	push_stack_node(ptd->stack, (void*)buf);
}

static void _topogctrl_undo(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	void* p;
	int len;

	XDK_ASSERT(ptd && ptd->topog);

	p = pop_stack_node(ptd->stack);
	if (p)
	{
		clear_topog_doc(ptd->topog);

		len = xslen((tchar_t*)p);

#ifdef _UNICODE
		parse_dom_doc_from_bytes(ptd->topog, (byte_t*)p, len * sizeof(tchar_t), DEF_UCS);
#else
		parse_dom_doc_from_bytes(ptd->topog, (byte_t*)p, len * sizeof(tchar_t), DEF_MBS);
#endif

		xmem_free(p);

		topogctrl_redraw(widget);
	}
}

static void _topogctrl_discard(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	void* p;

	XDK_ASSERT(ptd && ptd->stack);

	p = pop_stack_node(ptd->stack);
	if (p)
	{
		xmem_free(p);
	}
}

static void _topogctrl_clean(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	void* p;

	XDK_ASSERT(ptd && ptd->stack);

	while (p = pop_stack_node(ptd->stack))
	{
		xmem_free(p);
	}
}

static bool_t _topogctrl_copy(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	dword_t len;
	byte_t* buf;
	link_t_ptr dom, nlk, ilk;

	XDK_ASSERT(ptd && ptd->topog);

	if (!get_topog_spot_selected_count(ptd->topog))
		return 0;

	dom = create_topog_doc();
	ilk = get_topog_next_spot(ptd->topog, LINK_FIRST);
	while (ilk)
	{
		if (get_topog_spot_selected(ilk))
		{
			nlk = insert_topog_spot(dom, LINK_LAST);
			copy_dom_node(nlk, ilk);
		}

		ilk = get_topog_next_spot(ptd->topog, ilk);
	}

#ifdef _UNICODE
	len = format_dom_doc_to_bytes(dom, NULL, MAX_LONG, DEF_UCS);
#else
	len = format_dom_doc_to_bytes(dom, NULL, MAX_LONG, DEF_MBS);
#endif

	buf = (byte_t*)xmem_alloc(len);

#ifdef _UNICODE
	format_dom_doc_to_bytes(dom, buf, len, DEF_UCS);
#else
	format_dom_doc_to_bytes(dom, buf, len, DEF_MBS);
#endif

	if (!clipboard_put(widget, DEF_CB_FORMAT, buf, len))
	{
		xmem_free(buf);

		destroy_topog_doc(dom);

		return 0;
	}

	xmem_free(buf);

	destroy_topog_doc(dom);
	return 1;
}

static bool_t _topogctrl_cut(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	link_t_ptr nxt, ilk;

	XDK_ASSERT(ptd && ptd->topog);

	if (!_topogctrl_copy(widget))
		return 0;

	ilk = get_topog_next_spot(ptd->topog, LINK_FIRST);
	while (ilk)
	{
		nxt = get_topog_next_spot(ptd->topog, ilk);

		if (get_topog_spot_selected(ilk))
		{
			delete_topog_spot(ilk);
		}
		ilk = nxt;
	}

	topogctrl_redraw(widget);

	return 1;
}

static bool_t _topogctrl_paste(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	dword_t len;
	byte_t* buf;
	link_t_ptr dom, nlk;

	int row, col;
	tchar_t sz_name[RES_LEN + 1] = { 0 };

	XDK_ASSERT(ptd && ptd->topog);

	len = clipboard_get(widget, DEF_CB_FORMAT, NULL, MAX_LONG);
	if (!len)
	{
		return 0;
	}

	buf = (byte_t*)xmem_alloc(len);
	len = clipboard_get(widget, DEF_CB_FORMAT, buf, len);

	dom = create_dom_doc();
#ifdef _UNICODE
	if (!parse_dom_doc_from_bytes(dom, buf, len, DEF_UCS))
#else
	if (!parse_dom_doc_from_bytes(dom, buf, len, DEF_MBS))
#endif
	{
		xmem_free(buf);

		destroy_dom_doc(dom);
		return 0;
	}

	xmem_free(buf);

	if (!is_topog_doc(dom))
	{
		destroy_dom_doc(dom);
		return 0;
	}

	while (nlk = get_topog_next_spot(dom, LINK_FIRST))
	{
		nlk = detach_dom_node(get_topog_spotset(dom), nlk);
		attach_dom_node(get_topog_spotset(ptd->topog), LINK_LAST, nlk);

		xsprintf(sz_name, _T("spot%d"), get_topog_spot_count(ptd->topog));
		set_topog_spot_name(nlk, sz_name);

		col = get_topog_spot_col(nlk);
		row = get_topog_spot_row(nlk) + 2;

		set_topog_spot_col(nlk, col);
		set_topog_spot_row(nlk, row);
	}

	destroy_dom_doc(dom);
	return 1;
}

static void _topogctrl_spot_rect(res_win_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	calc_topog_spot_rect(ptd->topog, ilk, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _topogctrl_ensure_visible(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xrect_t xr = { 0 };

	if (!ptd->spot)
		return;

	_topogctrl_spot_rect(widget, ptd->spot, &xr);

	widget_ensure_visible(widget, &xr, 1);
}

static void _topogctrl_reset_matrix(res_win_t widget, int row, int col)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	int rows, cols;
	matrix_t mt = NULL;
	bool_t b;
	tchar_t* buf;
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

	matrix_parse(mt, get_topog_matrix_ptr(ptd->topog), -1);

	b = ((int)matrix_get_value(mt, row, col)) ? 0 : 1;
	matrix_set_value(mt, row, col, (double)b);

	len = matrix_format(mt, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	len = matrix_format(mt, buf, len);

	matrix_free(mt);

	set_topog_matrix(ptd->topog, buf, len);
	xsfree(buf);

	widget_erase(widget, NULL);
}

static void _topogctrl_reset_page(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	int pw, ph, fw, fh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	xs.fw = get_topog_cols(ptd->topog) * get_topog_rx(ptd->topog);
	xs.fh = get_topog_rows(ptd->topog) * get_topog_ry(ptd->topog);
	widget_size_to_pt(widget, &xs);
	fw = xs.w;
	fh = xs.h;

	xs.fw = (float)10;
	xs.fh = (float)10;
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	widget_reset_paging(widget, pw, ph, fw, fh, lw, lh);

	widget_reset_scroll(widget, 1);

	widget_reset_scroll(widget, 0);
}


/*****************************************************************************/
int noti_topog_owner(res_win_t widget, unsigned int code, link_t_ptr topog, link_t_ptr spot, int row, int col, void* data)
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

void noti_topog_reset_select(res_win_t widget)
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

void noti_topog_spot_selected(res_win_t widget, link_t_ptr ilk)
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

bool_t noti_topog_spot_changing(res_win_t widget)
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

void noti_topog_spot_changed(res_win_t widget, link_t_ptr ilk)
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

void noti_topog_spot_enter(res_win_t widget, link_t_ptr ilk)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ilk);
	XDK_ASSERT(!ptd->hover);

	ptd->hover = ilk;

	if (widget_is_hotvoer(widget))
	{
		widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
	}
}

void noti_topog_spot_leave(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	ptd->hover = NULL;

	if (widget_is_hotvoer(widget))
	{
		widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
	}
}

void noti_topog_spot_hover(res_win_t widget, int x, int y)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xpoint_t xp;

	XDK_ASSERT(ptd->hover != NULL);

	xp.x = x;
	xp.y = y;
	noti_topog_owner(widget, NC_TOPOGSPOTHOVER, ptd->topog, ptd->hover, get_topog_spot_row(ptd->hover), get_topog_spot_col(ptd->hover), (void*)&xp);
}

void noti_topog_spot_drag(res_win_t widget, int x, int y)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xpoint_t pt;

	XDK_ASSERT(ptd->spot);

	ptd->b_drag = (bool_t)1;
	ptd->org_x = x;
	ptd->org_y = y;

	if (widget_can_focus(widget))
	{
		widget_set_capture(widget, 1);
	}
	widget_set_cursor(widget, CURSOR_HAND);

	pt.x = x;
	pt.y = y;
	noti_topog_owner(widget, NC_TOPOGSPOTDRAG, ptd->topog, ptd->spot, ptd->row, ptd->col, (void*)&pt);
}

void noti_topog_spot_drop(res_win_t widget, int x, int y)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xpoint_t pt;
	xsize_t xs;
	int cx, cy;

	XDK_ASSERT(ptd->spot);

	ptd->b_drag = (bool_t)0;

	if (widget_can_focus(widget))
	{
		widget_set_capture(widget, 0);
	}
	widget_set_cursor(widget, CURSOR_ARROW);

	xs.fw = get_topog_rx(ptd->topog);
	xs.fh = get_topog_ry(ptd->topog);

	widget_size_to_pt(widget, &xs);

	if (!xs.w || !xs.h)
		return;

	cx = x - ptd->org_x;
	cy = y - ptd->org_y;

	cx /= xs.w;
	cy /= xs.h;

	if (!cx && !cy)
		return;

	cx += get_topog_spot_col(ptd->spot);
	cy += get_topog_spot_row(ptd->spot);

	if (cx < 0 || cy < 0)
		return;

	if (cx >= get_topog_cols(ptd->topog) || cy >= get_topog_rows(ptd->topog))
		return;

	_topogctrl_done(widget);

	set_topog_spot_col(ptd->spot, cx);
	set_topog_spot_row(ptd->spot, cy);
	ptd->row = cy;
	ptd->col = cx;

	widget_erase(widget, NULL);

	pt.x = x;
	pt.y = y;
	noti_topog_owner(widget, NC_TOPOGSPOTDROP, ptd->topog, ptd->spot, ptd->row, ptd->col, (void*)&pt);
}

void noti_topog_reset_scroll(res_win_t widget, bool_t bUpdate)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (widget_is_valid(ptd->vsc))
	{
		if (bUpdate)
			widget_update(ptd->vsc);
		else
			widget_close(ptd->vsc, 0);
	}

	if (widget_is_valid(ptd->hsc))
	{
		if (bUpdate)
			widget_update(ptd->hsc);
		else
			widget_close(ptd->hsc, 0);
	}
}
/*****************************************************************************/
int hand_topogctrl_create(res_win_t widget, void* data)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	widget_hand_create(widget);

	ptd = (topog_delta_t*)xmem_alloc(sizeof(topog_delta_t));
	xmem_zero((void*)ptd, sizeof(topog_delta_t));

	xmem_zero((void*)&ptd->img, sizeof(ximage_t));

	ptd->stack = create_stack_table();

	SETTOPOGDELTA(widget, ptd);

	return 0;
}

void hand_topogctrl_destroy(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (widget_is_valid(ptd->hsc))
		widget_destroy(ptd->hsc);

	if (widget_is_valid(ptd->vsc))
		widget_destroy(ptd->vsc);

	_topogctrl_clean(widget);
	destroy_stack_table(ptd->stack);

	if (ptd->img.source)
		xsfree(ptd->img.source);

	xmem_free(ptd);

	SETTOPOGDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_topogctrl_mouse_move(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	int nHint;
	link_t_ptr ilk;
	xpoint_t pt;
	int row, col;

	if (!ptd->topog)
		return;

	if (ptd->b_drag)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(widget, &pt);

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

	if (topog_is_design(ptd->topog) && nHint == TOPOG_HINT_SPOT && ilk == ptd->spot && (dw & MS_WITH_LBUTTON) && !(dw & KS_WITH_CONTROL))
	{
		noti_topog_spot_drag(widget, pxp->x, pxp->y);
	}
}

void hand_topogctrl_mouse_hover(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	if (ptd->hover)
		noti_topog_spot_hover(widget, pxp->x, pxp->y);
}

void hand_topogctrl_mouse_leave(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	if (ptd->hover)
		noti_topog_spot_leave(widget);
}

void hand_topogctrl_lbutton_down(res_win_t widget, const xpoint_t* pxp)
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

	if (!topog_is_design(ptd->topog))
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(widget, &pt);

	ilk = NULL;
	row = col = -1;
	nHint = calc_topog_hint(&pt, ptd->topog, &ilk, &row, &col);
	bRe = (ilk == ptd->spot) ? 1 : 0;

	if (nHint == TOPOG_HINT_SPOT)
	{
		if (widget_key_state(widget, KEY_CONTROL))
		{
			noti_topog_spot_selected(widget, ilk);
		}
	}
	else if (nHint == TOPOG_HINT_NONE)
	{
		if (!widget_key_state(widget, KEY_CONTROL))
		{
			noti_topog_reset_select(widget);
		}
	}
}

void hand_topogctrl_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	int nHint;
	link_t_ptr ilk;
	bool_t bRe;
	xpoint_t pt;
	int row, col;

	if (!ptd->topog)
		return;

	if (ptd->b_drag)
	{
		noti_topog_spot_drop(widget, pxp->x, pxp->y);
		return;
	}

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(widget, &pt);

	ilk = NULL;
	row = col = -1;
	nHint = calc_topog_hint(&pt, ptd->topog, &ilk, &row, &col);

	if (topog_is_design(ptd->topog))
	{
		bRe = (row == ptd->row && ptd->col == col) ? 1 : 0;

		if (widget_key_state(widget, KEY_CONTROL))
		{
			_topogctrl_reset_matrix(widget, row, col);
			return;
		}
	}

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

void hand_topogctrl_lbutton_dbclick(res_win_t widget, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	noti_topog_owner(widget, NC_TOPOGDBCLK, ptd->topog, ptd->spot, ptd->row, ptd->col, (void*)pxp);
}

void hand_topogctrl_rbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;
}

void hand_topogctrl_rbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	noti_topog_owner(widget, NC_TOPOGRBCLK, ptd->topog, ptd->spot, ptd->row, ptd->col, (void*)pxp);
}

void hand_topogctrl_scroll(res_win_t widget, bool_t bHorz, int nLine)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_topogctrl_wheel(res_win_t widget, bool_t bHorz, int nDelta)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	scroll_t scr = { 0 };
	int nLine;
	res_win_t win;

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
				widget_update(ptd->vsc);
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
				widget_update(ptd->hsc);
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

void hand_topogctrl_keydown(res_win_t widget, dword_t ks, int nKey)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	int row, col, m;
	int rows, cols;
	bool_t b_design;
	link_t_ptr slk;

	if (!ptd->topog)
		return;

	b_design = topog_is_design(ptd->topog);

	if (b_design)
	{
		if (ptd->spot && (nKey == KEY_UP || nKey == KEY_DOWN || nKey == KEY_LEFT || nKey == KEY_RIGHT))
		{
			m = 1;

			noti_topog_owner(widget, NC_FIELDDRAG, ptd->topog, ptd->spot, ptd->row, ptd->col, NULL);

			_topogctrl_done(widget);

			rows = get_topog_rows(ptd->topog);
			cols = get_topog_cols(ptd->topog);

			slk = get_topog_next_spot(ptd->topog, LINK_FIRST);
			while (slk)
			{
				if (slk != ptd->spot && !get_topog_spot_selected(slk))
				{
					slk = get_topog_next_spot(ptd->topog, slk);
					continue;
				}

				col = get_topog_spot_col(slk);
				row = get_topog_spot_row(slk);

				switch (nKey)
				{
				case KEY_DOWN:
					row = (row + m < rows) ? row + m : row;
					break;
				case KEY_UP:
					row = (row - m < 0) ? row : row - m;
					break;
				case KEY_LEFT:
					col = (col - m < 0) ? col : col - m;
					break;
				case KEY_RIGHT:
					col = (col + m < cols)? col + m : col;
					break;
				}

				set_topog_spot_col(slk, col);
				set_topog_spot_row(slk, row);
				ptd->row = row;
				ptd->col = col;

				slk = get_topog_next_spot(ptd->spot, slk);
			}

			widget_erase(widget, NULL);

			noti_topog_owner(widget, NC_TOPOGSPOTDROP, ptd->topog, ptd->spot, ptd->row, ptd->col, NULL);
		}
		else if ((nKey == _T('z') || nKey == _T('Z')) && widget_key_state(widget, KEY_CONTROL))
		{
			_topogctrl_undo(widget);
		}
		else if ((nKey == _T('c') || nKey == _T('C')) && widget_key_state(widget, KEY_CONTROL))
		{
			_topogctrl_copy(widget);
		}
		else if ((nKey == _T('x') || nKey == _T('X')) && widget_key_state(widget, KEY_CONTROL))
		{
			_topogctrl_done(widget);

			if (!_topogctrl_cut(widget))
			{
				_topogctrl_discard(widget);
			}
		}
		else if ((nKey == _T('v') || nKey == _T('V')) && widget_key_state(widget, KEY_CONTROL))
		{
			_topogctrl_done(widget);

			if (!_topogctrl_paste(widget))
			{
				_topogctrl_discard(widget);
			}
		}
	}
	else
	{
		if (nKey == KEY_TAB)
		{
			topogctrl_tabskip(widget,TABORDER_RIGHT);
		}
		else if (nKey == KEY_LEFT || nKey == KEY_UP) //KEY_LEFT KEY_UP
		{
			topogctrl_tabskip(widget,TABORDER_LEFT);
		}
		else if (nKey == KEY_RIGHT || nKey == KEY_DOWN) //KEY_RIGHT KEY_DOWN
		{
			topogctrl_tabskip(widget,TABORDER_RIGHT);
		}
	}
}

void hand_topogctrl_copy(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	if (!ptd->topog)
		return;

	
}

void hand_topogctrl_size(res_win_t widget, int code, const xsize_t* prs)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	xrect_t xr;

	if (!ptd->topog)
		return;

	noti_topog_reset_scroll(widget, 0);

	widget_get_client_rect(widget, &xr);
	widget_rect_to_tm(widget, &xr);

	set_topog_width(ptd->topog, xr.fw);
	set_topog_height(ptd->topog, xr.fh);

	topogctrl_redraw(widget);
}

void hand_topogctrl_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	visual_t rdc;
	xfont_t xf = { 0 };
	xface_t xa = { 0 };
	xpen_t xp = { 0 };
	xbrush_t xb = { 0 };
	xcolor_t xc = { 0 };
	xrect_t xr;

	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	widget_get_xfont(widget, &xf);
	widget_get_xface(widget, &xa);

	widget_get_xbrush(widget, &xb);
	widget_get_xpen(widget, &xp);

	canv = widget_get_canvas(widget);

	pif = widget_get_canvas_interface(widget);
	
	widget_get_client_rect(widget, &xr);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
			
	get_visual_interface(rdc, &ifv);
	
	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	if (ptd->img.source)
	{
		format_xcolor(&(pif->mode.clr_msk), ptd->img.color);

		(pif->pf_draw_image)(pif->ctx, &(ptd->img), (xrect_t*)&(pif->rect));
	}

	if (ptd->topog)
	{
		draw_topog(pif, ptd->topog);

		if (topog_is_design(ptd->topog) && ptd->spot)
		{
			widget_get_view_rect(widget, (viewbox_t*)(&ifv.rect));

			_topogctrl_spot_rect(widget, ptd->spot, &xr);

			pt_expand_rect(&xr, DEF_INNER_FEED, DEF_INNER_FEED);

			if (get_topog_spot_selected(ptd->spot))
			{
				parse_xcolor(&xc, DEF_ALPHA_COLOR);
				(*ifv.pf_alphablend_rect)(ifv.ctx, &xc, &xr, ALPHA_TRANS);
			}
			else
			{
				parse_xcolor(&xc, DEF_ENABLE_COLOR);
				draw_focus_raw(&ifv, &xc, &xr, ALPHA_TRANS);
			}
		}
	}
			
	

	end_canvas_paint(canv, dc, pxr);
	
}

/***************************************************************************************/
res_win_t topogctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, res_win_t wparent)
{
	if_event_t ev = { 0 };

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

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void topogctrl_attach(res_win_t widget, link_t_ptr data)
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
	widget_rect_to_tm(widget, &xr);

	set_topog_width(ptd->topog, xr.fw);
	set_topog_height(ptd->topog, xr.fh);

	topogctrl_redraw(widget);
}

link_t_ptr topogctrl_detach(res_win_t widget)
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

link_t_ptr topogctrl_fetch(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->topog;
}

void topogctrl_redraw(res_win_t widget)
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

	widget_update(widget);
}

void topogctrl_tabskip(res_win_t widget, int nSkip)
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

void topogctrl_redraw_spot(res_win_t widget, link_t_ptr plk)
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

bool_t topogctrl_set_focus_spot(res_win_t widget, link_t_ptr ilk)
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

link_t_ptr topogctrl_get_focus_spot(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->spot;
}

void topogctrl_get_spot_rect(res_win_t widget, link_t_ptr ilk, xrect_t* pxr)
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

void topogctrl_get_focus_dot(res_win_t widget, int* prow, int* pcol)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	*prow = ptd->row;
	*pcol = ptd->col;
}

bool_t topogctrl_get_dirty(res_win_t widget)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->topog)
		return 0;

	if (!topog_is_design(ptd->topog))
		return 0;

	return (peek_stack_node(ptd->stack, -1)) ? 1 : 0;
}

void topogctrl_set_dirty(res_win_t widget, bool_t bDirty)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->topog)
		return;

	if (!topog_is_design(ptd->topog))
		return;

	if (bDirty)
		_topogctrl_done(widget);
	else
		_topogctrl_clean(widget);
}

bool_t topogctrl_set_bitmap(res_win_t widget, bitmap_t bmp)
{
	topog_delta_t* ptd = GETTOPOGDELTA(widget);
	bool_t rt;
	visual_t rdc;

	XDK_ASSERT(ptd != NULL);

	rdc = widget_client_ctx(widget);

	if (ptd->img.source)
		xsfree(ptd->img.source);

	xmem_zero((void*)&ptd->img, sizeof(ximage_t));

	if (bmp)
		rt = save_bitmap_to_ximage(rdc, bmp, &ptd->img);
	else
		rt = 1;

	widget_release_ctx(widget, rdc);

	topogctrl_redraw(widget);

	return rt;
}
