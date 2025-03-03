﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc words control document

	@module	wordsbox.c | implement file

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

#include "../xdcimp.h"
#include "../xdcinit.h"

typedef struct _words_delta_t{
	link_t_ptr words;
	link_t_ptr item;
	int bw, bh;
	int page;
}words_delta_t;

#define GETWORDSDELTA(ph) 	(words_delta_t*)widget_get_user_delta(ph)
#define SETWORDSDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)


#define WORDSBOX_MAX_ITEMS		9
#define WORDSBOX_GUID_SPAN		(float)6

/***************************************************************************************/
void _wordsbox_item_rect(res_win_t widget, link_t_ptr plk, xrect_t* pxr)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	canvas_t canv;
	measure_interface im = { 0 };
	xfont_t xf = { 0 };

	widget_get_xfont(widget, &xf);

	canv = widget_get_canvas(widget);
	get_canvas_measure(canv, &im);
	widget_get_canv_rect(widget, (canvbox_t*)&(im.rect));

	calc_wordsbox_item_rect(&im, &xf, ptd->words, ptd->page, plk, pxr);
	widget_rect_to_pt(widget, pxr);
}

void _wordsbox_reset_page(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	measure_interface im = { 0 };
	xfont_t xf = { 0 };
	xrect_t xr;
	xsize_t xs;

	widget_get_xfont(widget, &xf);

	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_wordsbox_size(&im, &xf, ptd->words, &xs);
	widget_size_to_pt(widget, &xs);

	widget_get_client_rect(widget, &xr);

	widget_reset_paging(widget, xr.w, xr.h, xs.w, xs.h, 0, 0);
}

void _wordsbox_ensure_visible(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	xrect_t xr;

	if (!ptd->item)
		return;

	_wordsbox_item_rect(widget, ptd->item, &xr);

	widget_ensure_visible(widget, &xr, 1);
}

/*************************************************************************/

void noti_wordsbox_command(res_win_t widget, int code, vword_t data)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	if (widget_has_subproc(widget))
		widget_post_command(widget, code, IDC_SELF, data);
	else
		widget_post_command(widget_get_owner(widget), code, widget_get_user_id(widget), data);
}

void wordsbox_on_item_changing(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->item);

	_wordsbox_item_rect(widget,ptd->item, &xr);

	ptd->item = NULL;

	widget_erase(widget, &xr);
}

void wordsbox_on_item_changed(res_win_t widget, link_t_ptr elk)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(!ptd->item);

	ptd->item = elk;

	_wordsbox_item_rect(widget, ptd->item, &xr);
	
	widget_erase(widget, &xr);

	noti_wordsbox_command(widget, COMMAND_UPDATE, (vword_t)NULL);
}

/********************************************************************************************/
int hand_words_create(res_win_t widget, void* data)
{
	words_delta_t* ptd;

	xfont_t xf = { 0 };
	float pm = 0;
	xsize_t xs;

	ptd = (words_delta_t*)xmem_alloc(sizeof(words_delta_t));

	widget_get_xfont(widget, &xf);

	font_metric_by_pt(xstof(xf.size), &pm, NULL);
	xs.fw = pm;
	xs.fh = pm;

	widget_size_to_pt(widget, &xs);

	ptd->bw = xs.w;
	ptd->bh = xs.h;

	ptd->page = 0;

	SETWORDSDELTA(widget, ptd);

	return 0;
}

void hand_words_destroy(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETWORDSDELTA(widget, 0);
}

void hand_words_keydown(res_win_t widget, dword_t ks, int key)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	if (!ptd->words)
		return;

	switch (key)
	{
	case KEY_LEFT:
		wordsbox_tabskip(widget,TABORDER_LEFT);
		break;
	case KEY_RIGHT:
		wordsbox_tabskip(widget,TABORDER_RIGHT);
		break;
	case KEY_UP:
		wordsbox_tabskip(widget,TABORDER_UP);
		break;
	case KEY_DOWN:
		wordsbox_tabskip(widget,TABORDER_DOWN);
		break;
	case KEY_HOME:
		wordsbox_tabskip(widget,TABORDER_HOME);
		break;
	case KEY_END:
		wordsbox_tabskip(widget,TABORDER_END);
		break;
	case KEY_PAGEUP:
		wordsbox_tabskip(widget,TABORDER_PAGEUP);
		break;
	case KEY_PAGEDOWN:
		wordsbox_tabskip(widget,TABORDER_PAGEDOWN);
		break;
	}
}


void hand_words_mouse_move(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	if (!ptd->words)
		return;
}

void hand_words_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	if (!ptd->words)
		return;
}

void hand_words_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	measure_interface im = { 0 };
	xfont_t xf = { 0 };

	link_t_ptr ilk = NULL;
	xpoint_t pt;

	if (!ptd->words)
		return;

	widget_get_xfont(widget, &xf);

	get_canvas_measure(widget_get_canvas(widget), &im);

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(widget, &pt);

	calc_wordsbox_hint(&im, &xf, &pt, ptd->words, ptd->page, &ilk);

	if (ilk != ptd->item)
	{
		if (ptd->item)
			wordsbox_on_item_changing(widget);

		if (ilk)
			wordsbox_on_item_changed(widget, ilk);
	}

	noti_wordsbox_command(widget, COMMAND_CHANGE, (vword_t)NULL);
}

void hand_words_size(res_win_t widget, int code, const xsize_t* prs)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	if (!ptd->words)
		return;

	wordsbox_redraw(widget);
}

void hand_words_scroll(res_win_t widget, bool_t bHorz, int nLine)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	if (!ptd->words)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_words_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	visual_t rdc;
	xrect_t xr;
	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	xfont_t xf;
	xbrush_t xb;
	xpen_t xp;
	xcolor_t xc;

	widget_get_xfont(widget, &xf);
	widget_get_xbrush(widget, &xb);
	widget_get_xpen(widget, &xp);

	canv = widget_get_canvas(widget);

	pif = widget_get_canvas_interface(widget);

	widget_get_client_rect(widget, &xr);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
		
	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	draw_wordsbox(pif, &xf, ptd->words, ptd->page);

	if (ptd->item)
	{
		widget_get_view_rect(widget, (viewbox_t*)(&ifv.rect));

		_wordsbox_item_rect(widget, ptd->item, &xr);

		pt_expand_rect(&xr, DEF_INNER_FEED, DEF_INNER_FEED);

		parse_xcolor(&xc, DEF_ENABLE_COLOR);
		draw_focus_raw(&ifv, &xc, &xr, ALPHA_SOLID);

	}

	end_canvas_paint(canv, dc, pxr);	
}

/************************************************************************************************/
res_win_t wordsbox_create(res_win_t widget, dword_t style, const xrect_t* pxr)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_words_create)
		EVENT_ON_DESTROY(hand_words_destroy)
		EVENT_ON_PAINT(hand_words_paint)
		EVENT_ON_SIZE(hand_words_size)
		EVENT_ON_SCROLL(hand_words_scroll)
		EVENT_ON_KEYDOWN(hand_words_keydown)
		EVENT_ON_MOUSE_MOVE(hand_words_mouse_move)
		EVENT_ON_LBUTTON_DOWN(hand_words_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_words_lbutton_up)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void wordsbox_set_data(res_win_t widget, link_t_ptr ptr)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->words = ptr;
	ptd->item = NULL;

	ptd->page = 1;

	wordsbox_redraw(widget);
}

link_t_ptr wordsbox_get_data(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->words;
}

void wordsbox_redraw(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	link_t_ptr ilk;
	bool_t b_valid;
	int pages;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return;

	b_valid = 0;
	ilk = get_words_next_visible_item(ptd->words, LINK_FIRST);
	while (ilk)
	{
		if (ilk == ptd->item)
			b_valid = 1;

		ilk = get_words_next_visible_item(ptd->words, ilk);
	}

	if (!b_valid)
	{
		ptd->item = NULL;
	}

	pages = calc_wordsbox_pages(ptd->words);
	if (ptd->page > pages)
		ptd->page = pages;

	_wordsbox_reset_page(widget);

	widget_update(widget);
}

bool_t wordsbox_set_focus_item(res_win_t widget, link_t_ptr ent)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	bool_t bRe;
	int page;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return 0;

	if (ent == LINK_FIRST)
		ent = get_words_next_visible_item(ptd->words, LINK_FIRST);
	else if (ent == LINK_LAST)
		ent = get_words_prev_visible_item(ptd->words, LINK_LAST);

	bRe = (ent == ptd->item) ? 1 : 0;

	if (!bRe && ptd->item)
	{
		wordsbox_on_item_changing(widget);
	}

	if (!bRe && ent)
	{
		wordsbox_on_item_changed(widget, ent);

		_wordsbox_ensure_visible(widget);
	}

	if (ptd->item)
	{
		page = calc_wordsbox_item_page(ptd->words, ptd->item);
		if (page != ptd->page)
		{
			wordsbox_move_to_page(widget, page);
		}
	}

	return 1;
}

link_t_ptr wordsbox_get_focus_item(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return NULL;

	return ptd->item;
}

void wordsbox_get_item_rect(res_win_t widget, link_t_ptr elk, xrect_t* prt)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_words_item(ptd->words, elk));
#endif

	_wordsbox_item_rect(widget, elk, prt);
}

void wordsbox_tabskip(res_win_t widget, int nSkip)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	link_t_ptr plk = NULL;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return;

	switch (nSkip)
	{
	case TABORDER_RIGHT:
	case TABORDER_DOWN:
		if (ptd->item)
			plk = get_words_next_visible_item(ptd->words, ptd->item);
		else
			plk = get_words_next_visible_item(ptd->words, LINK_FIRST);

		if (plk)
			wordsbox_set_focus_item(widget, plk);
		break;
	case TABORDER_LEFT:
	case TABORDER_UP:
		if (ptd->item)
			plk = get_words_prev_visible_item(ptd->words, ptd->item);
		else
			plk = get_words_prev_visible_item(ptd->words, LINK_LAST);

		if (plk)
			wordsbox_set_focus_item(widget, plk);
		break;
	case TABORDER_HOME:
		wordsbox_move_first_page(widget);
		break;
	case TABORDER_END:
		wordsbox_move_last_page(widget);
		break;
	case TABORDER_PAGEUP:
		wordsbox_move_prev_page(widget);
		break;
	case TABORDER_PAGEDOWN:
		wordsbox_move_next_page(widget);
		break;
	}
}

void wordsbox_move_prev_page(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	int nCurPage;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return;

	nCurPage = ptd->page;

	if (nCurPage > 1)
	{
		nCurPage--;
		ptd->page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void wordsbox_move_next_page(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	int nCurPage, nMaxPage;
	xsize_t xs;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return;

	widget_get_canv_size(widget, &xs);

	nCurPage = ptd->page;
	nMaxPage = calc_wordsbox_pages(ptd->words);

	if (nCurPage < nMaxPage)
	{
		nCurPage++;
		ptd->page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void wordsbox_move_first_page(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	int nCurPage;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return;

	nCurPage = ptd->page;

	if (nCurPage != 1)
	{
		nCurPage = 1;
		ptd->page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void wordsbox_move_last_page(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	int nCurPage, nMaxPage;
	xsize_t xs;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return;

	widget_get_canv_size(widget, &xs);

	nCurPage = ptd->page;
	nMaxPage = calc_wordsbox_pages(ptd->words);

	if (nCurPage != nMaxPage)
	{
		nCurPage = nMaxPage;
		ptd->page = nCurPage;

		widget_erase(widget, NULL);
	}
}

void wordsbox_move_to_page(res_win_t widget, int page)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	int nCurPage, nMaxPage;
	xsize_t xs;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return;

	widget_get_canv_size(widget, &xs);

	nCurPage = ptd->page;
	nMaxPage = calc_wordsbox_pages(ptd->words);

	if (page > 0 && page != nCurPage && page <= nMaxPage)
	{
		nCurPage = page;
		ptd->page = nCurPage;

		widget_erase(widget, NULL);
	}
}

int wordsbox_get_max_page(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	xsize_t xs;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return 0;

	widget_get_canv_size(widget, &xs);

	return calc_wordsbox_pages(ptd->words);
}

int wordsbox_get_page(res_win_t widget)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return 0;

	return ptd->page;
}

void wordsbox_find(res_win_t widget, link_t_ptr pos, const tchar_t* token)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	link_t_ptr elk;
	int tlen;
	const tchar_t* text;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return;

	if (is_null(token))
	{
		wordsbox_set_focus_item(widget, NULL);
		return;
	}

	tlen = xslen(token);

	if (pos == LINK_FIRST)
		elk = get_words_next_visible_item(ptd->words, LINK_FIRST);
	if (pos == LINK_LAST)
		elk = NULL;
	else
		elk = get_words_next_visible_item(ptd->words, pos);

	while (elk)
	{
		text = get_words_item_text_ptr(elk);

		if (xsnicmp(text, token, tlen) == 0)
			break;

		elk = get_words_next_visible_item(ptd->words, elk);
	}

	wordsbox_set_focus_item(widget, elk);
}

void wordsbox_filter(res_win_t widget, const tchar_t* token)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	link_t_ptr elk;
	int tlen;
	const tchar_t* text;

	bool_t b_redraw, b_hidden;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return;

	wordsbox_set_focus_item(widget, NULL);

	tlen = xslen(token);

	b_redraw = 0;
	elk = get_words_next_item(ptd->words, LINK_FIRST);
	while (elk)
	{
		b_hidden = 1;

		if (is_null(token))
		{
			b_hidden = 0;
		}
		else
		{
			text = get_words_item_text_ptr(elk);

			if (xsnicmp(text, token, tlen) == 0)
				b_hidden = 0;
		}

		if (b_hidden != get_words_item_hidden(elk))
		{
			set_words_item_hidden(elk, b_hidden);
			b_redraw = 1;
		}

		elk = get_words_next_item(ptd->words, elk);
	}

	if (b_redraw)
		wordsbox_redraw(widget);
}

link_t_ptr wordsbox_seek(res_win_t widget, int index)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	link_t_ptr elk;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->words)
		return NULL;

	elk = calc_wordsbox_item(ptd->words, ptd->page, index);

	wordsbox_set_focus_item(widget, elk);

	return elk;
}

void wordsbox_popup_size(res_win_t widget, xsize_t* pxs)
{
	words_delta_t* ptd = GETWORDSDELTA(widget);
	measure_interface im = { 0 };
	xfont_t xf = { 0 };

	XDK_ASSERT(ptd != NULL);

	widget_get_xfont(widget, &xf);

	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_wordsbox_size(&im, &xf, ptd->words, pxs);

	widget_size_to_pt(widget, pxs);

	widget_adjust_size(widget_get_style(widget), pxs);
}

