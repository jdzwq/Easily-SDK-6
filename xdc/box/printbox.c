/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc print control document

	@module	printbox.c | implement file

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



#define SVG_LINE_FEED		(int)100

typedef struct _print_delta_t{
	link_t_ptr sheet;

	int pages, page;

	widget_t hsc;
	widget_t vsc;
}print_delta_t;

#define GETPRINTDELTA(ph) 		(print_delta_t*)widget_get_user_delta(ph)
#define SETPRINTDELTA(ph,ptd)	widget_set_user_delta(ph,(vword_t)ptd)

/************************************************************************************************/
static int _printbox_calc_pages(widget_t widget)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	xrect_t xr;
	int pages = 0;
	xface_t xa = {0};

	canvas_t canv;
	const drawing_interface* pif = NULL;

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);

	if (is_form_doc(ptd->sheet))
	{
		pages = calc_form_pages(pif, ptd->sheet);
	}
	else if (is_grid_doc(ptd->sheet))
	{
		pages = calc_grid_pages(ptd->sheet);
	}
	else if (is_statis_doc(ptd->sheet))
	{
		pages = calc_statis_pages(ptd->sheet);
	}
	else if (is_rich_doc(ptd->sheet))
	{
		default_xface(&xa);
		xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);
		pages = calc_rich_pages(pif, &xa, &xr, ptd->sheet);
	}
	else if (is_memo_doc(ptd->sheet))
	{
		default_xface(&xa);
		xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);
		pages = calc_rich_pages(pif, &xa, &xr, ptd->sheet);
	}

	return pages;
}

static void _printbox_reset_page(widget_t widget)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);
	int pw, ph, vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	if (ptd->sheet && is_form_doc(ptd->sheet))
	{
		xs.fw = get_form_width(ptd->sheet);
		xs.fh = get_form_height(ptd->sheet);

		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}
	else if (ptd->sheet && is_grid_doc(ptd->sheet))
	{
		xs.fw = get_grid_width(ptd->sheet);
		xs.fh = get_grid_height(ptd->sheet);

		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}
	else if (ptd->sheet && is_statis_doc(ptd->sheet))
	{
		xs.fw = get_statis_width(ptd->sheet);
		xs.fh = get_statis_height(ptd->sheet);

		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}
	else if (ptd->sheet && is_rich_doc(ptd->sheet))
	{
		xs.fw = get_rich_width(ptd->sheet);
		xs.fh = get_rich_height(ptd->sheet);

		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}
	else if (ptd->sheet && is_memo_doc(ptd->sheet))
	{
		xs.fw = get_memo_width(ptd->sheet);
		xs.fh = get_memo_height(ptd->sheet);

		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}else
	{
		vw = pw;
		vh = ph;
	}

	xs.fw = 5.0f;
	xs.fh = 5.0f;
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	widget_reset_paging(widget, pw, ph, vw, vh, lw, lh);

	widget_reset_scroll(widget, 1);

	widget_reset_scroll(widget, 0);
}

/********************************************************************************************/

int hand_print_create(widget_t widget, void* data)
{
	print_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (print_delta_t*)xmem_alloc(sizeof(print_delta_t));
	xmem_zero((void*)ptd, sizeof(print_delta_t));

	SETPRINTDELTA(widget, ptd);

	return 0;
}

void hand_print_destroy(widget_t widget)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (widget_is_valid(ptd->hsc))
		widget_destroy(ptd->hsc);

	if (widget_is_valid(ptd->vsc))
		widget_destroy(ptd->vsc);

	xmem_free(ptd);

	SETPRINTDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_print_size(widget_t widget, int code, const xsize_t* pxs)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	switch(code)
	{
	case WS_SIZE_FULLSCREEN:
		break;
	case WS_SIZE_MAXIMIZED:
		break;
	case WS_SIZE_MINIMIZED:
		break;
	case WS_SIZE_LAYOUT:
		_printbox_reset_page(widget);
		break;
	}
}

void hand_print_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	if (!ptd->sheet)
		return;

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}
}

void hand_print_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	if (!ptd->sheet)
		return;
}

void hand_print_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	if (!ptd->sheet)
		return;

}

void hand_print_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	if (!ptd->sheet)
		return;

}

void hand_print_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	if (!ptd->sheet)
		return;

}

void hand_print_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	if (!ptd->sheet)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_print_wheel(widget_t widget, bool_t bHorz, int nDelta)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);
	scroll_t scr = { 0 };
	int nLine;
	widget_t win;

	if (!ptd->sheet)
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
		}

		if (bHorz && !(widget_get_style(widget) & WD_STYLE_HSCROLL))
		{
			if (!widget_is_valid(ptd->hsc))
			{
				ptd->hsc = show_horzbox(widget);
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

void hand_print_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);
	visual_t rdc;

	xrect_t xr = { 0 };

	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	color_mod_t clrs;
	xbrush_t xb;
	xcolor_t xc;
	xface_t xa;

	if (!ptd->sheet) return;

	widget_get_color_mode(widget, &clrs);
	default_xbrush(&xb);
	format_xcolor(&clrs.clr_bkg, xb.color);
	xmem_copy((void*)&xc, (void*)&clrs.clr_frg, sizeof(xcolor_t));

	default_xface(&xa);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);

	canv = widget_get_canvas(widget);

	pif = widget_get_canvas_interface(widget);

	widget_get_client_rect(widget, &xr);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	if (widget_can_paging(widget))
	{
		lighten_xcolor(&xc, DEF_HARD_DARKEN);

		draw_corner(pif, &xc, (const xrect_t*)&(pif->rect));
	}

	if (ptd->sheet)
	{
		if (is_form_doc(ptd->sheet))
		{
			draw_form_page(pif, ptd->sheet, ptd->page);
		}
		else if (is_grid_doc(ptd->sheet))
		{
			draw_grid_page(pif, ptd->sheet, ptd->page);
		}
		else if (is_statis_doc(ptd->sheet))
		{
			draw_statis_page(pif, ptd->sheet, ptd->page);
		}
		else if (is_rich_doc(ptd->sheet))
		{
			draw_rich_text(pif, &xa, (xrect_t*)&(pif->rect), ptd->sheet, ptd->page);
		}
		else if (is_memo_doc(ptd->sheet))
		{
			draw_memo_text(pif, &xa, (xrect_t*)&(pif->rect), ptd->sheet, ptd->page);
		}
	}

	end_canvas_paint(canv, dc, pxr);
}

/*****************************************************************************************************/

widget_t printbox_create(widget_t widget, dword_t style, const xrect_t* pxr)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_print_create)
		EVENT_ON_DESTROY(hand_print_destroy)

		EVENT_ON_PAINT(hand_print_paint)

		EVENT_ON_SIZE(hand_print_size)

		EVENT_ON_SCROLL(hand_print_scroll)
		EVENT_ON_WHEEL(hand_print_wheel)

		EVENT_ON_LBUTTON_DBCLICK(hand_print_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_print_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_print_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_print_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_print_rbutton_up)

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void printbox_set_data(widget_t widget, link_t_ptr ptr)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->sheet = ptr;

	ptd->page = 1;

	printbox_redraw(widget);
}

link_t_ptr printbox_get_data(widget_t widget)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->sheet;
}

void printbox_redraw(widget_t widget)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);
	int pages;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->sheet)
		return;

	pages = _printbox_calc_pages(widget);
	if (ptd->page > pages)
		ptd->page = pages;

	_printbox_reset_page(widget);
}

void printbox_move_prev_page(widget_t widget)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);
	int nCurPage;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->sheet)
		return;

	nCurPage = ptd->page;

	if (nCurPage > 1)
	{
		nCurPage--;
		ptd->page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void printbox_move_next_page(widget_t widget)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);
	int nCurPage, nMaxPage;
	xsize_t xs;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->sheet)
		return;

	widget_get_canv_size(widget, &xs);

	nCurPage = ptd->page;
	nMaxPage = _printbox_calc_pages(widget);

	if (nCurPage < nMaxPage)
	{
		nCurPage++;
		ptd->page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void printbox_move_first_page(widget_t widget)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);
	int nCurPage;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->sheet)
		return;

	nCurPage = ptd->page;

	if (nCurPage != 1)
	{
		nCurPage = 1;
		ptd->page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void printbox_move_last_page(widget_t widget)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);
	int nCurPage, nMaxPage;
	xsize_t xs;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->sheet)
		return;

	widget_get_canv_size(widget, &xs);

	nCurPage = ptd->page;
	nMaxPage = _printbox_calc_pages(widget);

	if (nCurPage != nMaxPage)
	{
		nCurPage = nMaxPage;
		ptd->page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void printbox_move_to_page(widget_t widget, int page)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);
	int nCurPage, nMaxPage;
	xsize_t xs;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->sheet)
		return;

	widget_get_canv_size(widget, &xs);

	nCurPage = ptd->page;
	nMaxPage = _printbox_calc_pages(widget);

	if (page > 0 && page != nCurPage && page <= nMaxPage)
	{
		nCurPage = page;
		ptd->page = nCurPage;

		widget_erase(widget, NULL);
	}
}

int printbox_get_max_page(widget_t widget)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);
	xsize_t xs;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->sheet)
		return 0;

	widget_get_canv_size(widget, &xs);

	return _printbox_calc_pages(widget);
}

int printbox_get_page(widget_t widget)
{
	print_delta_t* ptd = GETPRINTDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->sheet)
		return 0;

	return ptd->page;
}


