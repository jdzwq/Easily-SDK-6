/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc grid control document

	@module	gridctrl.c | implement file

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


typedef struct _grid_delta_t{
	link_t_ptr grid;
	link_t_ptr row;
	link_t_ptr col;
	link_t_ptr hover;
	link_t_ptr fix;

	int org_x, org_y;
	int cur_x, cur_y;
	short cur_page;

	bool_t b_size_row, b_size_col;
	bool_t b_alarm;
	bool_t b_auto;
	bool_t b_lock;
}grid_delta_t;

#define GETGRIDDELTA(ph) 	(grid_delta_t*)widget_get_user_delta(ph)
#define SETGRIDDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/**********************************************************************************************/
static void _gridctrl_rowbar_rect(widget_t widget, link_t_ptr rlk, xrect_t* pxr)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	calc_grid_cell_rect(ptd->grid, ptd->cur_page, rlk, NULL, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _gridctrl_row_rect(widget_t widget, link_t_ptr rlk, xrect_t* pxr)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	calc_grid_cell_rect(ptd->grid, ptd->cur_page, rlk, NULL, pxr);
	pxr->fw = calc_grid_row_width(ptd->grid);

	widget_rect_to_pt(widget, pxr);
}

static void _gridctrl_colbar_rect(widget_t widget, link_t_ptr clk, xrect_t* pxr)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	calc_grid_cell_rect(ptd->grid, ptd->cur_page, NULL, clk, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _gridctrl_col_rect(widget_t widget, link_t_ptr clk, xrect_t* pxr)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	calc_grid_cell_rect(ptd->grid, ptd->cur_page, NULL, clk, pxr);
	pxr->fh = calc_grid_col_height(ptd->grid, ptd->cur_page);

	widget_rect_to_pt(widget, pxr);
}

static void _gridctrl_cell_rect(widget_t widget, link_t_ptr rlk, link_t_ptr clk, xrect_t* pxr)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	calc_grid_cell_rect(ptd->grid, ptd->cur_page, rlk, clk, pxr);

	widget_rect_to_pt(widget, pxr);
}

float _gridctrl_page_width(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr clk;
	float w;

	w = get_grid_rowbar_width(ptd->grid);

	clk = get_prev_col(ptd->grid, LINK_LAST);
	while (clk)
	{
		if (!get_col_visible(clk))
			clk = get_prev_col(ptd->grid, clk);
		else
			break;
	}

	while (clk)
	{
		w += get_col_width(clk);
		clk = get_prev_col(ptd->grid, clk);
	}

	return w;
}

static void _gridctrl_reset_page(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	int pw, ph, vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	if (ptd->grid)
	{
		if (compare_text(get_grid_printing_ptr(ptd->grid), -1, ATTR_PRINTING_LANDSCAPE, -1, 0) == 0)
		{
			xs.fw = _gridctrl_page_width(widget);

			if (xs.fw < get_grid_height(ptd->grid))
			{
				xs.fw = get_grid_height(ptd->grid);
			}
			xs.fh = get_grid_width(ptd->grid);
		}
		else
		{
			xs.fw = _gridctrl_page_width(widget);

			if (xs.fw < get_grid_width(ptd->grid))
			{
				xs.fw = get_grid_width(ptd->grid);
			}
			xs.fh = get_grid_height(ptd->grid);
		}

		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}else
	{
		vw = pw;
		vh = ph;
	}

	if (ptd->grid)
	{
		xs.fw = get_grid_rowbar_height(ptd->grid);
		xs.fh = get_grid_rowbar_height(ptd->grid);
	}
	else
	{
		xs.fw = 10.0f;
		xs.fh = 10.0f;
	}
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	widget_reset_paging(widget, pw, ph, vw, vh, lw, lh);

	widget_reset_scroll(widget, 1);

	widget_reset_scroll(widget, 0);
}

void _gridctrl_ensure_visible(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	int page;
	xrect_t xr = { 0 };

	if (ptd->row)
	{
		page = calc_grid_row_page(ptd->grid,ptd->row);
		if (page && page != ptd->cur_page)
		{
			ptd->cur_page = page;
			widget_erase(widget, NULL);
		}
	}

	_gridctrl_cell_rect(widget, ptd->row, ptd->col, &xr);
	widget_ensure_visible(widget, &xr, 1);
}

/*************************************************************************************************/

int noti_grid_owner(widget_t widget, unsigned int code, link_t_ptr grid, link_t_ptr rlk, link_t_ptr clk, void* data)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	NOTICE_GRID nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;
	nf.data = data;
	nf.ret = 0;

	nf.grid = grid;
	nf.row = rlk;
	nf.col = clk;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);
	return nf.ret;
}

void noti_grid_reset_check(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr rlk;
	int count = 0;
	bool_t b;

	b = get_rowset_checked(ptd->grid);

	rlk = get_next_row(ptd->grid, LINK_FIRST);
	while (rlk)
	{
		set_row_checked(rlk, b);
		noti_grid_owner(widget, NC_ROWCHECKED, ptd->grid, rlk, NULL, NULL);

		rlk = get_next_row(ptd->grid, rlk);
	}

	widget_erase(widget, NULL);
}

void noti_grid_reset_select(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr clk;
	int count = 0;

	clk = get_next_col(ptd->grid, LINK_FIRST);
	while (clk)
	{
		if (get_col_selected(clk))
		{
			set_col_selected(clk, 0);
			noti_grid_owner(widget, NC_COLSELECTED, ptd->grid, NULL, clk, NULL);

			count++;
		}
		clk = get_next_col(ptd->grid, clk);
	}

	if (!count)
		return;

	widget_erase(widget, NULL);
}

void noti_grid_col_sizing(widget_t widget, int x, int y)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	ptd->b_size_col = 1;
	ptd->org_x = x;
	ptd->org_y = y;

	widget_set_capture(widget, 1);
	widget_set_cursor(widget, CURSOR_SIZEWE);
}

void noti_grid_col_sized(widget_t widget, int x, int y)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	float mw;
	xrect_t xrCol, xrCli;
	xsize_t xs = { 0 };

	widget_set_capture(widget, 0);
	widget_set_cursor(widget, CURSOR_ARROW);

	xs.w = x - ptd->org_x;
	if (!xs.w)
		return;

	widget_size_to_mm(widget, &xs);

	mw = get_col_width(ptd->col);
	mw += xs.fw;
	mw = (float)(int)mw;
	if (mw < 2 * DEF_SPLIT_FEED)
		mw = 2 * DEF_SPLIT_FEED;

	mw = (float)(int)mw;

	if (ptd->col)
	{
		set_col_width(ptd->col, mw);

		_gridctrl_col_rect(widget, ptd->col, &xrCol);

		widget_get_client_rect(widget, &xrCli);
		xrCli.x = xrCol.x;
		xrCli.w -= xrCol.x;
		xrCli.y = xrCli.y;
		xrCli.h = xrCol.h;
	}
	else
	{
		set_grid_rowbar_width(ptd->grid, mw);

		widget_get_client_rect(widget, &xrCli);
	}

	widget_erase(widget, &xrCli);

	ptd->b_size_col = 0;
}

void noti_grid_row_sizing(widget_t widget, int x, int y)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	ptd->b_size_row = 1;
	ptd->org_x = x;
	ptd->org_y = y;

	widget_set_capture(widget, 1);
	widget_set_cursor(widget,CURSOR_SIZENS);
}

void noti_grid_row_sized(widget_t widget, int x, int y)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	float mh;
	xsize_t xs = { 0 };

	widget_set_capture(widget, 0);
	widget_set_cursor(widget, CURSOR_ARROW);

	xs.h = y - ptd->org_y;
	if (!xs.h)
		return;

	widget_size_to_mm(widget, &xs);

	mh = get_grid_rowbar_height(ptd->grid);
	mh += xs.fh;
	mh = (float)(int)mh;
	if (mh < 2 * DEF_SPLIT_FEED)
		mh = 2 * DEF_SPLIT_FEED;

	mh = (float)(int)mh;
	set_grid_rowbar_height(ptd->grid, mh);

	widget_erase(widget, NULL);

	ptd->b_size_row = 0;
}

void noti_grid_row_checked(widget_t widget, link_t_ptr rlk)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	xrect_t xr;

	if (!get_grid_showcheck(ptd->grid))
		return;

	XDK_ASSERT(rlk);

	set_row_checked(rlk, ((get_row_checked(rlk)) ? 0 : 1));

	noti_grid_owner(widget, NC_ROWCHECKED, ptd->grid, rlk, NULL, NULL);

	_gridctrl_rowbar_rect(widget, rlk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

void noti_grid_col_selected(widget_t widget, link_t_ptr clk)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	xrect_t xr;

	if (!grid_is_design(ptd->grid))
		return;

	XDK_ASSERT(clk);

	set_col_selected(clk, ((get_col_selected(clk)) ? 0 : 1));

	noti_grid_owner(widget, NC_COLSELECTED, ptd->grid, NULL, clk, NULL);

	_gridctrl_colbar_rect(widget, clk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

bool_t noti_grid_row_insert(widget_t widget, link_t_ptr rlk)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(rlk);

	if (noti_grid_owner(widget, NC_ROWINSERT, ptd->grid, rlk, NULL, NULL))
		return 0;

	return 1;
}

bool_t noti_grid_row_delete(widget_t widget, link_t_ptr rlk)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(rlk);

	if (noti_grid_owner(widget, NC_ROWDELETE, ptd->grid, rlk, NULL, NULL))
		return 0;

	return 1;
}

bool_t noti_grid_row_changing(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->row);

	if (noti_grid_owner(widget, NC_ROWCHANGING, ptd->grid, ptd->row, NULL, NULL))
		return 0;

	_gridctrl_row_rect(widget, ptd->row, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	ptd->row = NULL;

	widget_erase(widget, &xr);

	return 1;
}

void noti_grid_row_changed(widget_t widget, link_t_ptr rlk)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(rlk && !ptd->row);

	_gridctrl_row_rect(widget, rlk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	ptd->b_alarm = 0;

	ptd->row = rlk;

	widget_erase(widget, &xr);

	noti_grid_owner(widget, NC_ROWCHANGED, ptd->grid, ptd->row, NULL, NULL);
}

void noti_grid_col_changing(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->col);

	_gridctrl_col_rect(widget, ptd->col, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	ptd->col = NULL;

	widget_erase(widget, &xr);
}

void noti_grid_col_changed(widget_t widget, link_t_ptr clk)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(clk && !ptd->col);

	_gridctrl_col_rect(widget, clk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	ptd->b_alarm = 0;

	ptd->col = clk;

	widget_erase(widget, &xr);
}

void noti_grid_col_enter(widget_t widget, link_t_ptr clk)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(clk);
	XDK_ASSERT(!ptd->hover);

	ptd->hover = clk;

	widget_enable_hover(widget, bool_true);
}

void noti_grid_col_leave(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	ptd->hover = NULL;

	widget_enable_hover(widget, bool_false);
}

void noti_grid_col_hover(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	noti_grid_owner(widget, NC_COLHOVER, ptd->grid, NULL, ptd->hover, NULL);
}

void noti_grid_reset_editor(widget_t widget, bool_t bCommit)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	if (bCommit)
		widget_post_command(widget, COMMAND_COMMIT, IDC_CHILD, (vword_t)0);
	else
		widget_post_command(widget, COMMAND_ROLLBACK, IDC_CHILD, (vword_t)0);
}

/*******************************************************************************************/

int hand_grid_create(widget_t widget, void* data)
{
	grid_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (grid_delta_t*)xmem_alloc(sizeof(grid_delta_t));

	SETGRIDDELTA(widget, ptd);

	return 0;
}

void hand_grid_destroy(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	noti_grid_reset_editor(widget, 0);

	xmem_free(ptd);

	SETGRIDDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_grid_size(widget_t widget, int code, const xsize_t* prs)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

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

	_gridctrl_reset_page(widget);
}

void hand_grid_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 1);

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_grid_wheel(widget_t widget, bool_t bHorz, int nDelta)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 1);

	widget_hand_wheel(widget, bHorz, nDelta);
}

void hand_grid_mouse_move(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr row, col;
	int nHint;
	xpoint_t pt;

	if (!ptd->grid)
		return;

	if (ptd->b_size_row)
	{
		widget_set_cursor(widget, CURSOR_SIZENS);

		ptd->cur_x = pxp->x;
		ptd->cur_y = pxp->y;
		return;
	}
	else if (ptd->b_size_col)
	{
		widget_set_cursor(widget, CURSOR_SIZEWE);

		ptd->cur_x = pxp->x;
		ptd->cur_y = pxp->y;
		return;
	}

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	nHint = calc_grid_hint(&pt, ptd->grid, ptd->cur_page, &row, &col);

	if (nHint == GRID_HINT_HORZ_SPLIT && row == ptd->row && !(dw & KS_WITH_CONTROL))
	{
		if (dw & MS_WITH_LBUTTON)
		{
			noti_grid_row_sizing(widget, pxp->x, pxp->y);
			return;
		}
	}
	else if (nHint == GRID_HINT_VERT_SPLIT && col == ptd->col && !(dw & KS_WITH_CONTROL))
	{
		if (dw & MS_WITH_LBUTTON)
		{
			noti_grid_col_sizing(widget, pxp->x, pxp->y);
			return;
		}	
	}
	else if (nHint == GRID_HINT_NONE)
	{
		widget_set_cursor(widget, CURSOR_ARROW);
	}
}

void hand_grid_mouse_hover(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	if (!ptd->grid)
		return;

	if (ptd->hover)
		noti_grid_col_hover(widget);
}

void hand_grid_mouse_leave(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	if (!ptd->grid)
		return;

	if (ptd->hover)
		noti_grid_col_leave(widget);
}

void hand_grid_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 1);

	if (!grid_is_design(ptd->grid))
	{
		if (!ptd->row && ptd->col && get_col_sortable(ptd->col))
		{
			sort_grid_col(ptd->grid, ptd->col);

			widget_erase(widget, NULL);
		}
	}

	noti_grid_owner(widget, NC_GRIDDBCLK, ptd->grid, ptd->row, ptd->col, (void*)pxp);
}

void hand_grid_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr rlk, clk;
	int nHint;
	bool_t bReCol, bReRow;
	xpoint_t pt;

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 1);

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	nHint = calc_grid_hint(&pt, ptd->grid, ptd->cur_page, &rlk, &clk);

	bReRow = (rlk == ptd->row) ? 1 : 0;
	bReCol = (clk == ptd->col) ? 1 : 0;

	if (nHint == GRID_HINT_NULBAR)
	{
		if (get_grid_showcheck(ptd->grid))
		{
			if (get_rowset_checked(ptd->grid))
				set_rowset_checked(ptd->grid, 0);
			else
				set_rowset_checked(ptd->grid, 1);

			noti_grid_reset_check(widget);
		}
	}
	else if (nHint == GRID_HINT_ROWBAR)
	{
		noti_grid_row_checked(widget, rlk);
	}
	else if (nHint == GRID_HINT_COLBAR)
	{
		if (widget_key_state(widget, KS_WITH_CONTROL))
		{
			if (grid_is_design(ptd->grid))
				noti_grid_col_selected(widget, clk);
			else
				ptd->fix = ptd->col;
		}
	}
	else if (nHint == GRID_HINT_NONE)
	{
		if (!widget_key_state(widget, KS_WITH_CONTROL))
		{
			if(grid_is_design(ptd->grid))
				noti_grid_reset_select(widget);
		}
	}else if (nHint == GRID_HINT_HORZ_SPLIT)
	{
		widget_set_cursor(widget, CURSOR_SIZENS);
	}
	else if (nHint == GRID_HINT_VERT_SPLIT)
	{
		widget_set_cursor(widget, CURSOR_SIZEWE);
	}
}

void hand_grid_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr rlk, clk;
	int nHint;
	bool_t bReCol, bReRow;
	xpoint_t pt;

	if (!ptd->grid)
		return;

	if (ptd->b_size_row)
	{
		noti_grid_row_sized(widget, pxp->x, pxp->y);
		return;
	}

	if (ptd->b_size_col)
	{
		noti_grid_col_sized(widget, pxp->x, pxp->y);
		return;
	}

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	nHint = calc_grid_hint(&pt, ptd->grid, ptd->cur_page, &rlk, &clk);

	if (nHint == GRID_HINT_NULBAR || nHint == GRID_HINT_ROWBAR)
	{
		return;
	}

	bReRow = (rlk == ptd->row) ? 1 : 0;
	bReCol = (clk == ptd->col) ? 1 : 0;

	if (bReRow && bReCol)
	{
		if (ptd->row && ptd->col && !ptd->b_lock && !grid_is_design(ptd->grid) && get_col_editable(ptd->col) && !get_row_locked(ptd->row))
		{
			widget_post_key(widget, KEY_ENTER);
		}
		return;
	}

	if (!bReRow && ptd->row)
	{
		if (!noti_grid_row_changing(widget))
			bReRow = 1;
	}

	if (!bReCol && ptd->col)
	{
		noti_grid_col_changing(widget);
	}

	if (!bReCol && clk)
		noti_grid_col_changed(widget, clk);

	if (!bReRow && rlk)
		noti_grid_row_changed(widget, rlk);

	if (!bReRow || !bReCol)
	{
		if (ptd->row && ptd->col)
		{
			_gridctrl_ensure_visible(widget);
			noti_grid_owner(widget, NC_CELLSETFOCUS, ptd->grid, ptd->row, ptd->col, NULL);
		}
	}

	noti_grid_owner(widget, NC_GRIDLBCLK, ptd->grid, ptd->row, ptd->col, (void*)pxp);
}

void hand_grid_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 1);
}

void hand_grid_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	if (!ptd->grid)
		return;

	noti_grid_owner(widget, NC_GRIDRBCLK, ptd->grid, ptd->row, ptd->col, (void*)pxp);
}

void hand_grid_keydown(widget_t widget, dword_t ks, int nKey)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	if (!ptd->grid)
		return;

	switch (nKey)
	{
	case KEY_SPACE:
		if (ptd->row)
		{
			noti_grid_row_checked(widget, ptd->row);
		}
		break;
	case KEY_DELETE:
		if (ptd->row)
		{
			gridctrl_delete_row(widget, ptd->row);
		}
		break;
	case KEY_TAB:
		gridctrl_tabskip(widget, TABORDER_ANY);
		break;
	case KEY_LEFT:
		gridctrl_tabskip(widget, TABORDER_LEFT);
		break;
	case KEY_RIGHT:
		gridctrl_tabskip(widget, TABORDER_RIGHT);
		break;
	case KEY_UP:
		gridctrl_tabskip(widget, TABORDER_UP);
		break;
	case KEY_DOWN:
		gridctrl_tabskip(widget, TABORDER_DOWN);
		break;
	case KEY_END:
		gridctrl_tabskip(widget, TABORDER_END);
		break;
	case KEY_HOME:
		gridctrl_tabskip(widget, TABORDER_HOME);
		break;
	case KEY_PAGEUP:
		gridctrl_tabskip(widget, TABORDER_PAGEUP);
		break;
	case KEY_PAGEDOWN:
		gridctrl_tabskip(widget, TABORDER_PAGEDOWN);
		break;
	}
}

void hand_grid_menu_command(widget_t widget, int code, int cid, vword_t data)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	if (!ptd->grid)
		return;
}

void hand_grid_notice(widget_t widget, NOTICE* pnt)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	if (!ptd->grid)
		return;
}

void hand_grid_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	visual_t rdc;
	xrect_t xr;
	link_t_ptr clk;

	canvas_t canv;
	drawing_interface ifc = {0};
	drawing_interface ifv = {0};

	const color_mod_t *pclrs;
	xbrush_t xb;
	xcolor_t xc;

	if (!ptd->grid) return;

	pclrs = widget_get_color_mode_ptr(widget);
	default_xbrush(&xb);
	format_xcolor(&(pclrs->clr_bkg), xb.color);
	xmem_copy((void*)&xc,(void*)&(pclrs->clr_frg), sizeof(xcolor_t));

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);
	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
	
	get_visual_interface(rdc, &ifv);
	widget_get_view_rect(widget, (viewbox_t*)&(ifv.rect));

	get_canvas_interface(canv, &ifc);
	widget_get_canv_rect(widget, (canvbox_t*)&(ifc.rect));
	ifc.pclrs = pclrs;

	(*ifv.drw->pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);
	
	if (widget_can_paging(widget))
	{
		draw_corner(&ifc, &xc, (const xrect_t*)&(ifc.rect));
	}

	draw_grid_page(&ifc, ptd->grid, ptd->cur_page);

	// draw focus
	if (ptd->b_lock && ptd->row)
	{
		_gridctrl_row_rect(widget, ptd->row, &xr);

		parse_xcolor(&xc, DEF_ALPHA_COLOR);
		(*ifv.drw->pf_alphablend_rect)(ifv.ctx, &xc, &xr, ALPHA_SOFT);
	}
	else if (ptd->row && ptd->col)
	{
		_gridctrl_cell_rect(widget, ptd->row, ptd->col, &xr);

		if (ptd->b_alarm)
		{
			parse_xcolor(&xc, DEF_ALARM_COLOR);
		}
		else
		{
			if (get_col_editable(ptd->col))
				parse_xcolor(&xc, DEF_ENABLE_COLOR);
			else
				parse_xcolor(&xc, DEF_DISABLE_COLOR);
		}

		draw_focus_raw(&ifv, &xc, &xr, ALPHA_SOFT);
	}

	end_canvas_paint(canv, dc, pxr);
}

/******************************************************************************************/
widget_t gridctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_grid_create)
		EVENT_ON_DESTROY(hand_grid_destroy)

		EVENT_ON_PAINT(hand_grid_paint)

		EVENT_ON_SIZE(hand_grid_size)

		EVENT_ON_SCROLL(hand_grid_scroll)
		EVENT_ON_WHEEL(hand_grid_wheel)

		EVENT_ON_KEYDOWN(hand_grid_keydown)

		EVENT_ON_MOUSE_MOVE(hand_grid_mouse_move)
		EVENT_ON_MOUSE_HOVER(hand_grid_mouse_hover)
		EVENT_ON_MOUSE_LEAVE(hand_grid_mouse_leave)

		EVENT_ON_LBUTTON_DBCLICK(hand_grid_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_grid_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_grid_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_grid_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_grid_rbutton_up)

		EVENT_ON_NOTICE(hand_grid_notice)
		EVENT_ON_MENU_COMMAND(hand_grid_menu_command)

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void gridctrl_attach(widget_t widget, link_t_ptr ptr)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(ptr && is_grid_doc(ptr));

	ptd->grid = ptr;
	ptd->row = NULL;
	ptd->col = NULL;

	ptd->cur_page = 1;

	gridctrl_redraw(widget, 1);

	if (!ptd->b_lock && ptd->b_auto && !get_next_visible_row(ptr, LINK_FIRST))
	{
		gridctrl_insert_row(widget, LINK_LAST);
	}
}

link_t_ptr gridctrl_detach(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr data;

	XDK_ASSERT(ptd != NULL);

	noti_grid_reset_editor(widget, 0);

	data = ptd->grid;
	ptd->grid = NULL;

	ptd->cur_page = 0;

	widget_erase(widget, NULL);

	return data;
}

link_t_ptr gridctrl_fetch(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->grid;
}

void gridctrl_redraw(widget_t widget, bool_t bCalc)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr rlk, clk;
	bool_t bValid;
	int bSum, sumcols;
	bool_t b;
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 0);

	bValid = 0;
	rlk = get_next_visible_row(ptd->grid, LINK_FIRST);
	while (rlk)
	{
		if (rlk == ptd->row)
			bValid = 1;

		if (bCalc)
		{
			calc_grid_row(ptd->grid, rlk);
		}
			
		noti_grid_owner(widget, NC_ROWCALCED,ptd->grid, rlk, NULL, NULL);

		rlk = get_next_visible_row(ptd->grid, rlk);
	}

	if (!bValid)
		ptd->row = NULL;

	bValid = 0;
	bSum = get_grid_showsum(ptd->grid);
	sumcols = 0;
	clk = get_next_visible_col(ptd->grid, LINK_FIRST);
	while (clk)
	{
		if (clk == ptd->col)
			bValid = 1;

		if (bSum && get_col_sum_mode_ptr(clk))
		{
			sum_grid_col(ptd->grid, clk);
			sumcols++;
		}

		noti_grid_owner(widget, NC_COLCALCED, ptd->grid, NULL, clk, NULL);

		clk = get_next_visible_col(ptd->grid, clk);
	}

	if (!bValid)
		ptd->col = NULL;

	ptd->hover = NULL;

	noti_grid_owner(widget, NC_GRIDCALCED,ptd->grid, NULL, NULL, NULL);

	b = (widget_get_style(widget) & WD_STYLE_PAGING) ? 1 : 0;
	if (!b)
	{
		widget_get_client_rect(widget, &xr);
		widget_rect_to_mm(widget, &xr);
		set_grid_height(ptd->grid, xr.fh);
	}

	_gridctrl_reset_page(widget);
	widget_erase(widget, NULL);
}

void gridctrl_tabskip(widget_t widget, int dir)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr rlk, clk;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 1);

	rlk = ptd->row;
	clk = ptd->col;

	switch (dir)
	{
	case TABORDER_ANY:
		if ((ptd->row == get_prev_visible_row(ptd->grid, LINK_LAST)) && (ptd->col == ptd->fix || ptd->col == get_prev_focusable_col(ptd->grid, LINK_LAST)))
		{
			gridctrl_insert_row(widget, LINK_LAST);
		}
		else
		{
			if (ptd->col == ptd->fix)
			{
				rlk = get_next_visible_row(ptd->grid, rlk);
				if (rlk)
				{
					gridctrl_set_focus_cell(widget, rlk, clk);
				}
			}
			else if (ptd->col == get_prev_focusable_col(ptd->grid, LINK_LAST))
			{
				rlk = get_next_visible_row(ptd->grid, ptd->row);
				if (rlk)
				{
					gridctrl_set_focus_cell(widget, rlk, get_next_focusable_col(ptd->grid, LINK_FIRST));
				}
			}
			else
			{
				clk = get_next_focusable_col(ptd->grid, clk);
				if (clk)
				{
					gridctrl_set_focus_cell(widget, rlk, clk);
				}
			}
		}
		break;
	case TABORDER_LEFT:
		if (clk == NULL)
			clk = get_prev_focusable_col(ptd->grid, LINK_LAST);
		else
			clk = get_prev_focusable_col(ptd->grid, clk);

		if (clk)
		{
			gridctrl_set_focus_cell(widget, rlk, clk);
		}
		break;
	case TABORDER_RIGHT:
		if (clk == NULL)
			clk = get_next_focusable_col(ptd->grid, LINK_FIRST);
		else
			clk = get_next_focusable_col(ptd->grid, clk);

		if (clk)
		{
			gridctrl_set_focus_cell(widget, rlk, clk);
		}
		break;
	case TABORDER_UP:
		if (rlk)
		{
			rlk = get_prev_visible_row(ptd->grid, rlk);

			if (rlk)
			{
				gridctrl_set_focus_cell(widget, rlk, clk);
			}
		}
		break;
	case TABORDER_DOWN:
		if (rlk == NULL)
			rlk = get_next_visible_row(ptd->grid, LINK_FIRST);
		else
			rlk = get_next_visible_row(ptd->grid, rlk);

		if (rlk)
		{
			gridctrl_set_focus_cell(widget, rlk, clk);
		}
		break;
	case TABORDER_HOME:
		gridctrl_move_first_page(widget);
		break;
	case TABORDER_END:
		gridctrl_move_last_page(widget);
		break;
	case TABORDER_PAGEUP:
		gridctrl_move_prev_page(widget);
		break;
	case TABORDER_PAGEDOWN:
		gridctrl_move_next_page(widget);
		break;
	}
}

bool_t gridctrl_set_cell_text(widget_t widget, link_t_ptr rlk, link_t_ptr clk, const tchar_t* szText)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	const tchar_t* text;
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return 0;

#ifdef _DEBUG
	XDK_ASSERT(is_grid_row(ptd->grid, rlk));
	XDK_ASSERT(is_grid_col(ptd->grid, clk));
#endif

	text = get_cell_text_ptr(rlk,clk);
	if (compare_data(szText, text, get_col_data_type_ptr(clk)) == 0)
		return 1;

	if (veValid != verify_text(szText, get_col_data_type_ptr(clk), get_col_nullable(clk), get_col_data_len(clk), get_col_data_min_ptr(clk), get_col_data_max_ptr(clk)))
		return 0;

	set_cell_text(rlk, clk, szText, -1);
	set_cell_dirty(rlk, clk, 1);
	set_row_dirty(rlk);

	if (get_col_fireable(clk))
	{
		if (calc_grid_row(ptd->grid, rlk))
		{
			widget_erase(widget, NULL);
		}
	}

	_gridctrl_row_rect(widget, rlk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);
	widget_erase(widget, &xr);

	return 1;
}

bool_t gridctrl_delete_row(widget_t widget, link_t_ptr rlk)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr nlk;

	XDK_ASSERT(ptd != NULL);
	
	if (!ptd->grid)
		return 0;

	noti_grid_reset_editor(widget, 0);

	if (ptd->b_lock)
		return 0;

#ifdef _DEBUG
	XDK_ASSERT(is_grid_row(ptd->grid, rlk));
#endif

	if (!noti_grid_row_delete(widget, rlk))
		return 0;

	if (rlk == ptd->row)
	{
		noti_grid_row_changing(widget);
	}

	nlk = get_next_visible_row(ptd->grid, rlk);
	if (!nlk)
		nlk = get_prev_visible_row(ptd->grid, rlk);

	set_row_delete(rlk);

	gridctrl_redraw(widget, 1);

	if (nlk)
		gridctrl_set_focus_cell(widget, nlk, ptd->col);

	return 1;
}

link_t_ptr gridctrl_insert_row(widget_t widget, link_t_ptr pre)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr rlk;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return NULL;

	noti_grid_reset_editor(widget, 0);

	if (ptd->b_lock)
		return NULL;

	if (pre == LINK_FIRST)
		pre = get_next_visible_row(ptd->grid, LINK_FIRST);
	else if (pre == LINK_LAST)
		pre = get_prev_visible_row(ptd->grid, LINK_LAST);
	else
	{
#ifdef _DEBUG
		XDK_ASSERT(is_grid_row(ptd->grid, pre));
#endif
	}

	if (!pre) pre = LINK_FIRST;

	rlk = insert_row(ptd->grid, pre);
	set_row_state(rlk, dsNewClean);

	if (!noti_grid_row_insert(widget, rlk))
	{
		delete_row(rlk);
		return NULL;
	}

	gridctrl_redraw_row(widget, rlk, 0);

	gridctrl_set_focus_cell(widget, rlk, LINK_FIRST);

	return rlk;
}

bool_t gridctrl_copy_row(widget_t widget, link_t_ptr srcGrid, link_t_ptr srcRow)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr destGrid = ptd->grid;
	link_t_ptr destRow;
	link_t_ptr clk_dest, clk_src;
	const tchar_t* cname;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return 0;

	destRow = ptd->row;

	if (!destRow)
		return 0;

	if (get_row_locked(destRow))
		return 0;

	clk_dest = get_next_col(destGrid, LINK_FIRST);
	while (clk_dest)
	{
		cname = get_col_name_ptr(clk_dest);
		clk_src = get_col(srcGrid, cname);
		if (clk_src)
		{
			set_cell_text(destRow, clk_dest, get_cell_text_ptr(srcRow, clk_src), -1);
			set_cell_dirty(destRow, clk_dest, 1);
			set_row_dirty(destRow);

			sum_grid_col(ptd->grid, clk_dest);
		}

		clk_dest = get_next_col(destGrid, clk_dest);
	}
	set_row_dirty(destRow);

	gridctrl_redraw_row(widget, destRow, 1);

	return 1;
}

void gridctrl_redraw_row(widget_t widget, link_t_ptr rlk, bool_t bCalc)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	xrect_t xr, xrCli;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_grid_row(ptd->grid, rlk));
#endif

	if (bCalc)
	{
		calc_grid_row(ptd->grid, rlk);
	}
		
	noti_grid_owner(widget, NC_ROWCALCED,ptd->grid, rlk, NULL, NULL);

	_gridctrl_row_rect(widget, rlk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_get_client_rect(widget, &xrCli);
	xrCli.y = xr.y;
	xrCli.h -= xr.y;

	widget_erase(widget, &xrCli);
}

void gridctrl_redraw_col(widget_t widget, link_t_ptr clk, bool_t bCalc)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	xrect_t xr,xrCli;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_grid_col(ptd->grid, clk));
#endif

	if (bCalc && get_grid_showsum(ptd->grid) && get_col_sum_mode_ptr(clk))
	{
		sum_grid_col(ptd->grid, clk);
	}

	noti_grid_owner(widget, NC_COLCALCED, ptd->grid, NULL, clk, NULL);

	_gridctrl_col_rect(widget, clk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_get_client_rect(widget, &xrCli);
	xrCli.x = xr.x;
	xrCli.w -= xr.x;

	widget_erase(widget, &xr);
}

bool_t gridctrl_set_focus_cell(widget_t widget, link_t_ptr rlk, link_t_ptr clk)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	bool_t bReRow, bReCol;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return 0;

	if (rlk == LINK_FIRST)
		rlk = get_next_visible_row(ptd->grid, LINK_FIRST);
	else if (rlk == LINK_LAST)
		rlk = get_prev_visible_row(ptd->grid, LINK_LAST);

	if (clk == LINK_FIRST)
		clk = get_next_focusable_col(ptd->grid, LINK_FIRST);
	else if (clk == LINK_LAST)
		clk = get_prev_focusable_col(ptd->grid, LINK_LAST);

	bReRow = (rlk == ptd->row) ? 1 : 0;
	bReCol = (clk == ptd->col) ? 1 : 0;

	if (bReRow && bReCol)
	{
		return 1;
	}

	if (!bReRow && ptd->row)
	{
		if (!noti_grid_row_changing(widget))
			return 0;
	}

	if (!bReCol && ptd->col)
	{
		noti_grid_col_changing(widget);
	}

	if (!bReRow || !bReCol)
	{
		if (ptd->row && ptd->col)
			noti_grid_owner(widget, NC_CELLKILLFOCUS,ptd->grid, ptd->row, ptd->col, NULL);
	}

	if (!bReCol && clk)
		noti_grid_col_changed(widget, clk);

	if (!bReRow && rlk)
		noti_grid_row_changed(widget, rlk);

	if (!bReRow || !bReCol)
	{
		if (ptd->row && ptd->col)
			noti_grid_owner(widget, NC_CELLSETFOCUS,ptd->grid, ptd->row, ptd->col, NULL);
	}

	_gridctrl_ensure_visible(widget);

	return 1;
}

link_t_ptr gridctrl_get_focus_col(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return NULL;

	return ptd->col;
}

link_t_ptr gridctrl_get_focus_row(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return NULL;

	return ptd->row;
}

void gridctrl_auto_insert(widget_t widget, bool_t bAuto)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_auto = bAuto;
}

void gridctrl_set_fixed(widget_t widget, link_t_ptr clk)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->fix = clk;
}

link_t_ptr	gridctrl_get_fixed(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->fix;
}

bool_t gridctrl_verify(widget_t widget, bool_t bAlarm)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr rlk, clk;
	int code;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return 1;

	noti_grid_reset_editor(widget, 0);

	code = verify_grid_doc(ptd->grid, &rlk, &clk);
	if (veValid != code)
	{
		gridctrl_set_focus_cell(widget, rlk, clk);
		ptd->b_alarm = 1;
		return 0;
	}
	else
		return 1;
}

void gridctrl_accept(widget_t widget, bool_t bAccept)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr nxt, rlk;
	int rs;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	if(bAccept)
		noti_grid_reset_editor(widget, 1);
	else
		noti_grid_reset_editor(widget, 0);

	rlk = get_next_row(ptd->grid, LINK_FIRST);
	while (rlk)
	{
		nxt = get_next_row(ptd->grid, rlk);

		rs = get_row_state(rlk);
		if (rs == dsNewClean)
			delete_row(rlk);

		rlk = nxt;
	}

	gridctrl_redraw(widget, 0);
}

bool_t gridctrl_is_update(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return 0;

	return (get_update_row_count(ptd->grid)) ? 1 : 0;
}

void gridctrl_move_first_page(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	int nCurPage;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 1);

	nCurPage = ptd->cur_page;

	if (nCurPage != 1)
	{
		nCurPage = 1;
		ptd->cur_page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void gridctrl_move_prev_page(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	int nCurPage;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 1);

	nCurPage = ptd->cur_page;

	if (nCurPage > 1)
	{
		nCurPage--;
		ptd->cur_page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void gridctrl_move_next_page(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	int nCurPage, nMaxPage;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 1);

	nCurPage = ptd->cur_page;
	nMaxPage = calc_grid_pages(ptd->grid);

	if (nCurPage < nMaxPage)
	{
		nCurPage++;
		ptd->cur_page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void gridctrl_move_last_page(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	int nCurPage, nMaxPage;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 1);

	nCurPage = ptd->cur_page;
	nMaxPage = calc_grid_pages(ptd->grid);

	if (nCurPage != nMaxPage)
	{
		nCurPage = nMaxPage;
		ptd->cur_page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void gridctrl_move_to_page(widget_t widget, int page)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	int nCurPage, nMaxPage;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 1);

	nCurPage = ptd->cur_page;
	nMaxPage = calc_grid_pages(ptd->grid);

	if (page > 0 && page != nCurPage && page <= nMaxPage)
	{
		nCurPage = page;
		ptd->cur_page = nCurPage;

		widget_erase(widget, NULL);
	}
}

int gridctrl_get_max_page(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return 0;

	return calc_grid_pages(ptd->grid);
}

int gridctrl_get_cur_page(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return 0;

	return ptd->cur_page;
}

void gridctrl_find(widget_t widget, const tchar_t* token)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	link_t_ptr clk,rlk;
	int tlen;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 0);

	clk = get_next_visible_col(ptd->grid, LINK_FIRST);
	if (!clk)
		return;

	tlen = xslen(token);

	
	if (tlen)
		rlk = (ptd->row) ? get_next_visible_row(ptd->grid, ptd->row) : get_next_visible_row(ptd->grid, LINK_FIRST);
	else
		rlk = NULL;
	
	while (rlk)
	{
		if (xsnicmp(get_cell_text_ptr(rlk, clk), token, tlen) == 0)
			break;

		rlk = get_next_visible_row(ptd->grid, rlk);
	}

	if (rlk)
		gridctrl_set_focus_cell(widget, rlk, clk);
	else
		gridctrl_set_focus_cell(widget, NULL, NULL);
}

void gridctrl_filter(widget_t widget, const tchar_t* token)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	link_t_ptr rlk,clk;
	int tlen;
	const tchar_t* text;
	bool_t b_redraw, b_hidden;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	noti_grid_reset_editor(widget, 0);

	gridctrl_set_focus_cell(widget, NULL, NULL);

	clk = get_next_visible_col(ptd->grid, LINK_FIRST);
	if (!clk)
		return;

	tlen = xslen(token);

	b_redraw = 0;
	rlk = get_next_row(ptd->grid, LINK_FIRST);
	while (rlk)
	{
		b_hidden = 1;

		if (xsisnil(token))
		{
			b_hidden = 0;
		}
		else
		{
			text = get_cell_text_ptr(rlk,clk);

			if (xsnicmp(text, token, tlen) == 0)
				b_hidden = 0;
		}

		if (b_hidden != get_row_hidden(rlk))
		{
			set_row_hidden(rlk, b_hidden);
			b_redraw = 1;
		}

		rlk = get_next_row(ptd->grid, rlk);
	}

	if (b_redraw)
		gridctrl_redraw(widget, 1);
}

void gridctrl_popup_size(widget_t widget, xsize_t* pse)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	int count;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	count = get_visible_row_count(ptd->grid);
	if (count < 5)
		count = 5;
	if (count > 7)
		count = 7;

	pse->fw = _gridctrl_page_width(widget);
	pse->fh = get_grid_rowbar_height(ptd->grid) * count;

	widget_size_to_pt(widget, pse);

	adjust_widget_size(widget_get_style(widget), pse);
}

void gridctrl_get_cell_rect(widget_t widget, link_t_ptr rlk, link_t_ptr clk, xrect_t* pxr)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	_gridctrl_cell_rect(widget, rlk, clk, pxr);
}

bool_t gridctrl_get_lock(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->b_lock;
}

void gridctrl_set_lock(widget_t widget, bool_t bLock)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_lock = bLock;
}

bool_t gridctrl_get_dirty(widget_t widget)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return 0;

	if (!grid_is_design(ptd->grid))
		return 0;

	return 0;
}

void gridctrl_set_dirty(widget_t widget, bool_t bDirty)
{
	grid_delta_t* ptd = GETGRIDDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->grid)
		return;

	if (!grid_is_design(ptd->grid))
		return;
}
