﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc grid document

	@module	griddoc.c | implement file

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
#include "gridview.h"

#include "../xdlgdi.h"
#include "../xdldoc.h"



#define GRIDITEM_INDICATOR_NEXT_GRID	0
#define GRIDITEM_INDICATOR_NEXT_ITEM	1

typedef struct _GRIDITEMOPERATOR{
	int ind;

	int page;
	link_t_ptr grid;
	link_t_ptr rlk;
	link_t_ptr clk;
}GRIDITEMOPERATOR;

void call_grid_next_item(void* param, link_t_ptr* p_xlk, link_t_ptr* p_ylk, xrect_t* p_rect, bool_t* p_focus, bool_t* p_drag, bool_t* p_sizew, bool_t* p_sizeh)
{
	GRIDITEMOPERATOR* poo = (GRIDITEMOPERATOR*)param;

	XDK_ASSERT(poo && poo->grid);

	switch (poo->ind)
	{
	case GRIDITEM_INDICATOR_NEXT_GRID:
		poo->clk = NULL;
		poo->rlk = NULL;

		*p_xlk = NULL;
		*p_ylk = NULL;
		calc_grid_cell_rect(poo->grid, poo->page, poo->rlk, poo->clk, p_rect);

		*p_focus = 1;
		*p_drag = 0;
		*p_sizew = 1;
		*p_sizeh = 0;

		poo->ind = GRIDITEM_INDICATOR_NEXT_ITEM;
		break;
	case GRIDITEM_INDICATOR_NEXT_ITEM:
		poo->clk = (poo->clk == NULL) ? get_next_visible_col(poo->grid, LINK_FIRST) : get_next_visible_col(poo->grid, poo->clk);
		if (poo->clk == NULL)
		{
			poo->rlk = (poo->rlk == NULL) ? get_next_visible_row(poo->grid, LINK_FIRST) : get_next_visible_row(poo->grid, poo->rlk);
		}

		if (!poo->rlk && !poo->clk)
		{
			*p_xlk = LINK_LAST;
			*p_ylk = LINK_LAST;
			xmem_zero((void*)p_rect, sizeof(xrect_t));

			*p_focus = 1;
			*p_drag = 0;
			*p_sizew = 0;
			*p_sizeh = 0;
		}
		else
		{
			*p_xlk = poo->rlk;
			*p_ylk = poo->clk;
			calc_grid_cell_rect(poo->grid, poo->page, poo->rlk, poo->clk, p_rect);

			*p_focus = 1;
			*p_drag = 0;
			*p_sizew = 1;
			*p_sizeh = 0;
		}
		poo->ind = (poo->rlk == LINK_LAST && poo->clk == LINK_LAST) ? GRIDITEM_INDICATOR_NEXT_GRID : GRIDITEM_INDICATOR_NEXT_ITEM;
		break;
	}
}

void call_grid_cur_item(void* param, link_t_ptr* p_xlk, link_t_ptr* p_ylk)
{
	GRIDITEMOPERATOR* poo = (GRIDITEMOPERATOR*)param;

	XDK_ASSERT(poo && poo->grid);

	*p_xlk = poo->rlk;
	*p_ylk = poo->clk;
}


void hint_grid_item(link_t_ptr ptr, int page, PF_HINT_DESIGNER_CALLBACK pf, void* pp)
{
	GRIDITEMOPERATOR ro = { 0 };
	if_itemhint_t it = { 0 };

	ro.grid = ptr;
	ro.page = page;

	it.param = (void*)&ro;
	it.pf_next_item = call_grid_next_item;
	it.pf_cur_item = call_grid_cur_item;
	
	hint_object_item(&it, pf, pp);
}

/******************************************************************************************************************************************/
static int _grid_rows_persubfield(link_t_ptr ptr)
{
	int rowsperpage;
	float fh, ch, rh, th;
	bool_t b_sum;

	fh = get_grid_height(ptr);
	th = get_grid_title_height(ptr);
	ch = get_grid_colbar_height(ptr);
	rh = get_grid_rowbar_height(ptr);
	b_sum = get_grid_showsum(ptr);

	if (b_sum)
		th += rh;

	rowsperpage = (int)((fh - th - ch) / rh);
	if (rowsperpage <= 0)
		rowsperpage = 0;

	return rowsperpage;
}

static int _grid_rows_perpage(link_t_ptr ptr)
{
	int rowsperpage;
	float fh, ch, rh, th;
	bool_t b_sum;
	int ns;

	fh = get_grid_height(ptr);
	th = get_grid_title_height(ptr);
	ch = get_grid_colbar_height(ptr);
	rh = get_grid_rowbar_height(ptr);
	ns = get_grid_subfield(ptr);
	b_sum = get_grid_showsum(ptr);

	if (b_sum)
		th += rh;

	rowsperpage = (int)((fh - th - ch) / rh);
	if (rowsperpage <= 0)
		rowsperpage = 0;

	return rowsperpage * ns;
}

static float _grid_width_persubfield(link_t_ptr ptr)
{
	link_t_ptr clk;
	float rw;

	rw = get_grid_rowbar_width(ptr);

	clk = get_next_visible_col(ptr, LINK_FIRST);
	while (clk)
	{
		rw += get_col_width(clk);

		clk = get_next_visible_col(ptr, clk);
	}

	return rw;
}

int calc_grid_row_scope(link_t_ptr ptr, int page, link_t_ptr* pfirst, link_t_ptr* plast)
{
	int rowsperpage, rows;
	link_t_ptr rlk;

	if (page <= 0)
		return 0;

	*pfirst = *plast = NULL;

	rowsperpage = _grid_rows_perpage(ptr);
	if (rowsperpage <= 0)
		return 0;

	*pfirst = get_visible_row_at(ptr, (page - 1) * rowsperpage);
	if (*pfirst == NULL)
		return 0;

	rows = 0;
	rlk = *pfirst;
	while (rlk && rowsperpage--)
	{
		*plast = rlk;
		rows++;
		rlk = get_next_visible_row(ptr, rlk);
	}

	return rows;
}

int calc_grid_row_page(link_t_ptr ptr, link_t_ptr rlk)
{
	link_t_ptr plk;
	int rowsperpage, count, page;

	if (rlk == NULL)
		return 0;

	if (!get_row_visible(rlk))
		return 0;

	rowsperpage = _grid_rows_perpage(ptr);
	if (rowsperpage <= 0)
		return 0;

	page = 1;
	count = rowsperpage;
	plk = get_next_visible_row(ptr, LINK_FIRST);
	while (plk && plk != rlk)
	{
		count--;
		if (count == 0)
		{
			page++;
			count = rowsperpage;
		}
		plk = get_next_visible_row(ptr, plk);
	}
	return page;
}

int calc_grid_pages(link_t_ptr ptr)
{
	int rowsperpage, rows;

	rowsperpage = _grid_rows_perpage(ptr);
	if (rowsperpage <= 0)
		return 1;

	rows = get_visible_row_count(ptr);	/*calcing use visible row*/
	if (rows == 0)
		return 1;
	if (rows % rowsperpage == 0)
		return rows / rowsperpage;
	else
		return rows / rowsperpage + 1;
}

float calc_grid_page_width(link_t_ptr ptr)
{
	int ns;

	ns = get_grid_subfield(ptr);

	return ns * _grid_width_persubfield(ptr);
}

float calc_grid_page_height(link_t_ptr ptr, int page)
{
	link_t_ptr rlk, rlk_first, rlk_last;
	float th, ch, rh;
	int ns, pages;

	th = get_grid_title_height(ptr);
	ch = get_grid_colbar_height(ptr);
	rh = get_grid_rowbar_height(ptr);

	pages = calc_grid_pages(ptr);

	if (get_grid_showsum(ptr) && page == pages)
		th += rh;

	ns = _grid_rows_persubfield(ptr);

	if (page < pages)
		return ns * rh + th + ch;

	rlk_first = rlk_last = NULL;
	calc_grid_row_scope(ptr, page, &rlk_first, &rlk_last);

	th += ch;
	rlk = rlk_first;
	while (rlk && ns)
	{
		if (get_row_visible(rlk))
		{
			th += rh;
			ns--;
		}

		if (rlk == rlk_last)
			break;

		rlk = get_next_row(ptr, rlk);
	}

	return th;
}

int calc_grid_cell_rect(link_t_ptr ptr, int page, link_t_ptr rlk, link_t_ptr clk, xrect_t* pxr)
{
	link_t_ptr row, col;
	link_t_ptr rlk_first, rlk_last;
	float th, rw, ch, rh;
	float xm, ym;
	int i, sub, ns;

	xmem_zero((void*)pxr, sizeof(xrect_t));

	ch = get_grid_colbar_height(ptr);
	rh = get_grid_rowbar_height(ptr);
	rw = get_grid_rowbar_width(ptr);
	th = get_grid_title_height(ptr);

	if (rlk && !get_row_visible(rlk))
		return 0;

	if (!rlk)
		ym = th;
	else
		ym = th + ch;

	if (!clk)
		xm = 0;
	else
		xm = rw;

	if (!rlk && !clk)
	{
		pxr->fx = xm;
		pxr->fw = rw;
		pxr->fy = ym;
		pxr->fh = ch;
		return 1;
	}

	ns = _grid_rows_persubfield(ptr);

	sub = 0;

	if (rlk)
	{
		rlk_first = rlk_last = NULL;
		calc_grid_row_scope(ptr, page, &rlk_first, &rlk_last);

		i = 0;
		row = rlk_first;
		while (row)
		{
			if (i == ns)
			{
				ym = th + ch;
				i = 0;
				sub++;
			}

			if (row == rlk)
				break;

			ym += rh;
			i++;

			if (row == rlk_last)
				break;
			else
				row = get_next_visible_row(ptr, row);
		}

		pxr->fy = ym;
		pxr->fh = rh;
	}
	else
	{
		row = NULL;
		pxr->fy = ym;
		pxr->fh = ch;
	}
	
	if (clk)
	{
		xm = rw + sub * _grid_width_persubfield(ptr);

		col = get_next_visible_col(ptr, LINK_FIRST);
		while (col && col != clk)
		{
			xm += get_col_width(col);

			col = get_next_visible_col(ptr, col);
		}

		pxr->fx = xm;
		pxr->fw = (col)? get_col_width(col) : 0;
	}
	else
	{
		col = NULL;
		pxr->fx = sub * _grid_width_persubfield(ptr);
		pxr->fw = rw;
	}

	if (row != rlk || col != clk)
	{
		xmem_zero((void*)pxr, sizeof(xrect_t));
		return 0;
	}

	return 1;
}

int calc_grid_row_rect(link_t_ptr ptr, int page, link_t_ptr rlk, xrect_t* pxr)
{
	link_t_ptr clk;

	clk = get_next_visible_col(ptr, LINK_FIRST);

	if (!calc_grid_cell_rect(ptr, page, rlk, clk, pxr))
		return 0;

	pxr->fx -= get_grid_rowbar_width(ptr);
	pxr->fw = _grid_width_persubfield(ptr);

	return 1;
}

int calc_grid_col_rect(link_t_ptr ptr, int page, link_t_ptr rlk, link_t_ptr clk, xrect_t* pxr)
{
	if (!calc_grid_cell_rect(ptr, page, rlk, clk, pxr))
		return 0;

	pxr->fy = get_grid_title_height(ptr);
	pxr->fh = calc_grid_page_height(ptr, page) - get_grid_title_height(ptr);

	return 1;
}

int calc_grid_hint(const xpoint_t* ppt, link_t_ptr ptr, int page, link_t_ptr* prlk, link_t_ptr* pclk)
{
	link_t_ptr row, col;
	link_t_ptr rlk_first, rlk_last;
	float th, rw, cw, ch, rh, gw;
	float mx, my, w, h;
	int i, sub, ns;
	int hint;

	ch = get_grid_colbar_height(ptr);
	rh = get_grid_rowbar_height(ptr);
	rw = get_grid_rowbar_width(ptr);
	th = get_grid_title_height(ptr);

	mx = ppt->fx;
	my = ppt->fy;

	hint = GRID_HINT_NONE;
	*prlk = NULL;
	*pclk = NULL;

	if (mx <= 0 && my <= 0)
	{
		return hint;
	}

	if (mx < rw && my < th)
	{
		hint = GRID_HINT_MENU;
		return hint;
	}

	if (mx >= rw && my < th)
	{
		hint = GRID_HINT_TITLE;
		return hint;
	}

	if (mx < rw - DEF_SPLIT_FEED && my < th + ch - DEF_SPLIT_FEED)
	{
		hint = GRID_HINT_NULBAR;
		return hint;
	}

	ns = _grid_rows_persubfield(ptr);
	gw = _grid_width_persubfield(ptr);

	h = th + ch;
	w = 0;

	rlk_first = rlk_last = NULL;
	calc_grid_row_scope(ptr, page, &rlk_first, &rlk_last);

	i = 0;
	row = rlk_first;
	while (row)
	{
		if (i == ns)
		{
			i = 0;
			h = th + ch;
			w += gw;
		}

		if (mx > w && mx < w + gw && my > h + DEF_SPLIT_FEED && my < h + rh - DEF_SPLIT_FEED)
		{
			*prlk = row;

			if (mx < w + rw - DEF_SPLIT_FEED)
				hint = GRID_HINT_ROWBAR;
			else if (mx < w + gw)
				hint = GRID_HINT_CELL;

			break;
		}
		else if (mx > w && mx < w + gw && my >= h + rh - DEF_SPLIT_FEED && my <= h + rh + DEF_SPLIT_FEED && mx < w + rw - DEF_SPLIT_FEED)
		{
			*prlk = row;
			hint = GRID_HINT_HORZ_SPLIT;

			break;
		}

		h += rh;
		i++;

		if (row == rlk_last)
			break;
		else
			row = get_next_visible_row(ptr, row);
	}

	sub = get_grid_subfield(ptr);

	for (i = 0; i < sub; i++)
	{
		h = th;
		w = rw + i * gw;

		col = get_next_visible_col(ptr, LINK_FIRST);
		while (col)
		{
			cw = get_col_width(col);

			if (mx > w + DEF_SPLIT_FEED && mx < w + cw - DEF_SPLIT_FEED)
			{
				*pclk = col;
				if (!(*prlk))
				{
					hint = GRID_HINT_COLBAR;
					return hint;
				}
			}
			else if (mx >= w + cw - DEF_SPLIT_FEED && mx <= w + cw + DEF_SPLIT_FEED)
			{
				*pclk = col;
				if (!(*prlk))
				{
					hint = GRID_HINT_VERT_SPLIT;
					return hint;
				}
			}
			else if (mx < w + cw)
			{
				break;
			}

			w += cw;
			col = get_next_visible_col(ptr, col);
		}
	}

	return hint;
}

void draw_grid_page(const drawing_interface* pif, link_t_ptr ptr, int page)
{
	link_t_ptr clk, rlk;
	link_t_ptr rlk_first, rlk_last;
	float th, rw, ch, rh;
	bool_t b_design, b_print;
	bool_t b_lastpage, b_sumrow, b_showcheck, b_tag = 0;
	int n_stepdraw = 0;

	const tchar_t *token, *shape, *style, *rstyle, *type, *colfmt;
	bool_t zeronull, wrapable;

	xfont_t xf = { 0 };
	xface_t xa = { 0 };
	xpen_t xp = { 0 };
	xbrush_t xb_step, xb_bar, xb = { 0 };
	ximage_t xi = { 0 };
	xrect_t xrCell, xrBar, xrCheck;
	xcolor_t xc, xc_check;
	float px, py, pw, ph, gw, cw, tw;
	int i, ns, rs;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	px = pbox->fx;
	py = pbox->fy;
	pw = pbox->fw;
	ph = pbox->fh;

	rlk_first = rlk_last = NULL;
	calc_grid_row_scope(ptr, page, &rlk_first, &rlk_last);

	if (rlk_last)
		b_lastpage = (get_next_visible_row(ptr, rlk_last)) ? 0 : 1;
	else
		b_lastpage = 0;

	shape = get_grid_shape_ptr(ptr);

	b_design = grid_is_design(ptr);

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;

	default_xpen(&xp);
	default_xbrush(&xb);
	default_xfont(&xf);
	default_xface(&xa);

	style = get_grid_style_ptr(ptr);

	parse_xbrush_from_style(&xb, style);
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_bkg, xb.color);
	}

	/*parse_xpen_from_style(&xp, style);
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_frg, xp.color);
	}*/

	xscpy(xp.color, xb.color);
	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

	parse_xface_from_style(&xa, style);

	parse_xfont_from_style(&xf, style);
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_msk, xi.color);
	}

	xmem_copy((void*)&xb_bar, (void*)&xb, sizeof(xbrush_t));
	lighten_xbrush(&xb_bar, DEF_MIDD_DARKEN);

	xmem_copy((void*)&xb_step, (void*)&xb, sizeof(xbrush_t));
	lighten_xbrush(&xb_step, DEF_SOFT_DARKEN);

	parse_xcolor(&xc_check, xp.color);

	b_sumrow = get_grid_showsum(ptr);
	b_showcheck = get_grid_showcheck(ptr);

	if (compare_text(get_grid_stepdraw_ptr(ptr), -1, ATTR_LAYER_HORZ, -1, 0) == 0)
		n_stepdraw = 1;
	else if (compare_text(get_grid_stepdraw_ptr(ptr), -1, ATTR_LAYER_VERT, -1, 0) == 0)
		n_stepdraw = 2;
	else
		n_stepdraw = 0;

	th = get_grid_title_height(ptr);
	rw = get_grid_rowbar_width(ptr);
	ch = get_grid_colbar_height(ptr);
	rh = get_grid_rowbar_height(ptr);

	gw = _grid_width_persubfield(ptr);
	ns = get_grid_subfield(ptr);
	rs = _grid_rows_persubfield(ptr);

	//draw title bar
	if (th)
	{
		xrBar.fx = px + rw;
		xrBar.fy = py;
		xrBar.fw = pw - rw;
		xrBar.fh = th;

		(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xrBar, get_grid_title_ptr(ptr), -1);
	}

	//draw null bar
	if (rw && ch)
	{
		xrBar.fx = px;
		xrBar.fw = rw;
		xrBar.fy = th + py;
		xrBar.fh = ch;

		draw_shape(pif, &xp, &xb_bar, &xrBar, shape);

		if (b_showcheck && get_rowset_checked(ptr))
		{
			xmem_copy((void*)&xrCheck, (void*)&xrBar, sizeof(xrect_t));
			ft_center_rect(&xrCheck, DEF_SMALL_ICON, DEF_SMALL_ICON);
			draw_gizmo(pif, &xc_check, &xrCheck, GDI_ATTR_GIZMO_CHECKED);
		}
	}

	//draw col bar
	if (ch)
	{
		for (i = 0; i < ns; i++)
		{
			xrBar.fx = i * gw + rw + px;
			xrBar.fy = th + py;
			xrBar.fh = ch;

			clk = get_next_visible_col(ptr, LINK_FIRST);
			while (clk)
			{
				default_xfont(&xf);
				default_xface(&xa);

				style = get_col_style_ptr(clk);

				parse_xface_from_style(&xa, style);

				parse_xfont_from_style(&xf, style);
				if (!b_print)
				{
					format_xcolor(&pif->mode.clr_txt, xf.color);
				}

				xrBar.fw = get_col_width(clk);

				draw_shape(pif, &xp, &xb_bar, &xrBar, shape);

				token = get_col_title_ptr(clk);
				(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xrBar, token, -1);

				xrBar.fx += xrBar.fw;
				clk = get_next_visible_col(ptr, clk);
			}
		}
	}

	//draw row bar
	if (rw)
	{
		xrBar.fx = px;
		xrBar.fw = rw;
		xrBar.fy = th + ch + py;
		xrBar.fh = rh;

		i = 0;
		rlk = rlk_first;
		while (rlk)
		{
			if (i == rs)
			{
				xrBar.fx += gw;
				xrBar.fy = th + ch + py;
				i = 0;
			}
			i++;

			draw_shape(pif, &xp, &xb_bar, &xrBar, shape);

			if (b_showcheck && get_row_checked(rlk))
			{
				xmem_copy((void*)&xrCheck, (void*)&xrBar, sizeof(xrect_t));
				ft_center_rect(&xrCheck, DEF_SMALL_ICON, DEF_SMALL_ICON);
				draw_gizmo(pif, &xc_check, &xrCheck, GDI_ATTR_GIZMO_CHECKED);
			}

			if (rlk_last == rlk)
				break;

			xrBar.fy += xrBar.fh;
			rlk = get_next_visible_row(ptr, rlk);
		}
	}

	//draw sum bar
	if (rw && b_sumrow && b_lastpage)
	{
		xrBar.fy += xrBar.fh;

		draw_shape(pif, &xp, &xb_bar, &xrBar, shape);

		xmem_copy((void*)&xrCheck, (void*)&xrBar, sizeof(xrect_t));
		ft_center_rect(&xrCheck, DEF_SMALL_ICON, DEF_SMALL_ICON);
		draw_gizmo(pif, &xc_check, &xrCheck, GDI_ATTR_GIZMO_SUM);
	}

	//draw cell
	b_tag = 1;
	tw = rw;
	clk = get_next_visible_col(ptr, LINK_FIRST);
	while (clk)
	{
		default_xface(&xa);

		style = get_col_style_ptr(clk);

		parse_xface_from_style(&xa, style);
		xscpy(xa.text_align, get_col_alignment_ptr(clk));

		type = get_col_data_type_ptr(clk);
		colfmt = get_col_format_ptr(clk);
		zeronull = get_col_zeronull(clk);
		wrapable = get_col_wrapable(clk);

		cw = get_col_width(clk);

		xrCell.fx = tw + px;
		xrCell.fy = th + ch + py;
		xrCell.fw = cw;
		xrCell.fh = rh;

		i = 0;
		if (n_stepdraw == 1)
			b_tag = 0;
		else
			b_tag = (b_tag) ? 0 : 1;

		rlk = rlk_first;
		while (rlk)
		{
			default_xfont(&xf);
			parse_xfont_from_style(&xf, style);
			if (!b_print)
			{
				format_xcolor(&pif->mode.clr_txt, xf.color);
			}

			rstyle = get_row_style_ptr(rlk);
			if (!is_null(rstyle))
			{
				parse_xfont_from_style(&xf, rstyle);
			}
			
			if (i == rs)
			{
				xrCell.fx += gw;
				xrCell.fy = th + ch + py;

				i = 0;
				if (n_stepdraw == 1)
					b_tag = 0;
			}
			i++;

			if (n_stepdraw && b_tag)
			{
				draw_shape(pif, &xp, &xb_step, &xrCell, shape);
				if (n_stepdraw == 1)
					b_tag = 0;
			}
			else
			{
				draw_shape(pif, &xp, NULL, &xrCell, shape);
				if (n_stepdraw == 1)
					b_tag = 1;
			}

			if (get_col_password(clk))
			{
				draw_pass(pif, &xf, &xa, &xrCell, get_cell_text_ptr(rlk, clk), -1);
			}
			else if (compare_text(type, -1, ATTR_DATA_TYPE_BINARY, -1, 0) == 0)
			{
				parse_ximage_from_source(&xi, get_cell_text_ptr(rlk,clk));

				(*pif->pf_draw_image)(pif->ctx, &xi, &xrCell);
			}
			else
			{
				token = get_cell_options_text_ptr(rlk, clk);
				draw_data(pif, &xf, &xa, &xrCell, token, -1, get_col_data_dig(clk), type, colfmt, zeronull, wrapable);
			}

			if (rlk_last == rlk)
				break;

			xrCell.fy += xrCell.fh;
			rlk = get_next_visible_row(ptr, rlk);
		}

		if (b_sumrow && b_lastpage)
		{
			xrCell.fy += xrCell.fh;

			draw_shape(pif, &xp, &xb_bar, &xrCell, shape);

			token = get_col_sum_text_ptr(clk);

			draw_data(pif, &xf, &xa, &xrCell, token, -1, get_col_data_dig(clk), type, colfmt, zeronull, wrapable);
		}

		tw += cw;
		clk = get_next_visible_col(ptr, clk);
	}
}
