﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc windows nc document

	@module	widgetnc.c | implement file

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

#include "widgetnc.h"

#include "../xdcimp.h"
#include "../xdcinit.h"


#ifdef XDU_SUPPORT_WIDGET_NC

static void _WidgetDrawLogo(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt)
{
	xpen_t xp;
	xbrush_t xb;
	xrect_t rt, xr;

	drawing_interface ifv = {0};

	get_visual_interface(rdc, &ifv);

	default_xpen(&xp);
	format_xcolor(pxc, xp.color);

	default_xbrush(&xb);
	format_xcolor(pxc, xb.color);

	rt.x = prt->x;
	rt.y = prt->y;

	if (prt->w > 24 && prt->h > 24)
	{
		xscpy(xp.size, _T("3"));
		rt.w = 36;
		rt.h = 36;
	}
	else if (prt->w > 16 && prt->h > 16)
	{
		xscpy(xp.size, _T("2"));
		rt.w = 24;
		rt.h = 24;
	}
	else
	{
		xscpy(xp.size, _T("1"));
		rt.w = 16;
		rt.h = 16;
	}

	prt = &rt;

	xr.x = prt->x;
	xr.y = prt->y;
	xr.w = prt->w / 2 - 2;
	xr.h = prt->h / 2 - 2;

	(*ifv.pf_draw_round)(ifv.ctx, &xp, &xb, &xr, NULL);

	xr.x = prt->x + prt->w / 2 + 1;
	xr.y = prt->y;
	xr.w = prt->w / 2 - 2;
	xr.h = prt->h / 2 - 2;
	(*ifv.pf_draw_rect)(ifv.ctx, &xp, &xb, &xr);

	xr.x = prt->x;
	xr.y = prt->y + prt->h / 2 + 1;
	xr.w = prt->w / 2 - 2;
	xr.h = prt->h / 2 - 2;
	(*ifv.pf_draw_rect)(ifv.ctx, &xp, &xb, &xr);

	xr.x = prt->x + prt->w / 2 + 1;
	xr.y = prt->y + prt->h / 2 + 1;
	xr.w = prt->w / 2 - 2;
	xr.h = prt->h / 2 - 2;
	(*ifv.pf_draw_round)(ifv.ctx, &xp, &xb, &xr, NULL);
}

static void _WidgetDrawEdge(res_win_t wt, visual_t rdc)
{
	border_t bd = { 0 };
	dword_t ws;
	xbrush_t xb;
	xrect_t rtWnd, rtScr;

	drawing_interface ifv = {0};

	ws = widget_get_style(wt);
	widget_calc_border(ws, &bd);

	if (!bd.edge)
		return;

	get_visual_interface(rdc, &ifv);

	widget_get_client_rect(wt, &rtScr);
	widget_client_to_window(wt, RECTPOINT(&rtScr));

	(*ifv.pf_exclude_rect)(ifv.ctx, &rtScr);

	widget_get_window_rect(wt, &rtWnd);
	rtWnd.x = rtWnd.y = 0;

	widget_get_xbrush(wt, &xb);
	lighten_xbrush(&xb, DEF_HARD_DARKEN);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &rtWnd);
}

static void _WidgetDrawHScroll(res_win_t wt, visual_t rdc)
{
	border_t bd = { 0 };
	xrect_t rtWnd, rtScr;
	scroll_t sl = { 0 };
	int ind;

	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };

	drawing_interface ifv = {0};

	widget_calc_border(widget_get_style(wt), &bd);

	if (!bd.hscroll)
		return;

	get_visual_interface(rdc, &ifv);

	widget_get_scroll_info(wt, 1, &sl);

	widget_get_window_rect(wt, &rtWnd);
	rtWnd.x = rtWnd.y = 0;

	widget_get_xbrush(wt, &xb);
	widget_get_xpen(wt, &xp);

	rtScr.x = rtWnd.x + bd.edge;
	rtScr.w = rtWnd.w - 2 * bd.edge - bd.vscroll;
	rtScr.y = rtWnd.y + rtWnd.h - bd.edge - bd.hscroll;
	rtScr.h = bd.hscroll;

	lighten_xbrush(&xb, DEF_SOFT_DARKEN);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &rtScr);

	if (sl.max + sl.page / 2 > sl.min)
	{
		lighten_xbrush(&xb, DEF_HARD_DARKEN);
		xscpy(xp.color, xb.color);

		rtScr.x = rtWnd.x + bd.edge;
		rtScr.w = bd.hscroll;
		rtScr.y = rtWnd.y + rtWnd.h - bd.edge - bd.hscroll;
		rtScr.h = bd.hscroll;
		pt_expand_rect(&rtScr, -3, -3);

		(*ifv.pf_draw_round)(ifv.ctx, &xp, &xb, &rtScr, NULL);

		rtScr.x = rtWnd.x + rtWnd.w - bd.edge - bd.vscroll - bd.hscroll;
		rtScr.w = bd.hscroll;
		rtScr.y = rtWnd.y + rtWnd.h - bd.edge - bd.hscroll;
		rtScr.h = bd.hscroll;
		pt_expand_rect(&rtScr, -3, -3);

		(*ifv.pf_draw_round)(ifv.ctx, &xp, &xb, &rtScr, NULL);

		if (!sl.pos)
		{
			rtScr.x = rtWnd.x + bd.edge;
			rtScr.w = bd.hscroll;
			rtScr.y = rtWnd.y + rtWnd.h - bd.edge - bd.hscroll;
			rtScr.h = bd.hscroll;
		}
		else if (sl.pos == sl.max)
		{
			rtScr.x = rtWnd.x + rtWnd.w - bd.edge - bd.vscroll - bd.hscroll;
			rtScr.w = bd.hscroll;
			rtScr.y = rtWnd.y + rtWnd.h - bd.edge - bd.hscroll;
			rtScr.h = bd.hscroll;
		}
		else
		{
			ind = (int)((float)sl.pos / (float)sl.max * (float)(rtWnd.w - 2 * bd.edge - bd.vscroll - bd.hscroll));
			rtScr.x = rtWnd.x + bd.edge + ind;
			rtScr.w = bd.hscroll;
			rtScr.y = rtWnd.y + rtWnd.h - bd.edge - bd.hscroll;
			rtScr.h = bd.hscroll;
		}
		pt_expand_rect(&rtScr, -4, -4);

		lighten_xpen(&xp, DEF_SOFT_LIGHTEN);
		lighten_xbrush(&xb, DEF_SOFT_LIGHTEN);
		(*ifv.pf_draw_ellipse)(ifv.ctx, &xp, &xb, &rtScr);
	}

	
}

static void _WidgetDrawVScroll(res_win_t wt, visual_t rdc)
{
	border_t bd = { 0 };
	xrect_t rtWnd, rtScr;
	scroll_t sl = { 0 };
	int ind;

	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };

	drawing_interface ifv = {0};

	widget_calc_border(widget_get_style(wt), &bd);

	if (!bd.vscroll)
		return;

	get_visual_interface(rdc, &ifv);

	widget_get_scroll_info(wt, 0, &sl);

	widget_get_window_rect(wt, &rtWnd);
	rtWnd.x = rtWnd.y = 0;

	widget_get_xbrush(wt, &xb);
	widget_get_xpen(wt, &xp);

	rtScr.x = rtWnd.x + rtWnd.w - bd.edge - bd.vscroll;
	rtScr.w = bd.vscroll;
	rtScr.y = rtWnd.y + bd.edge + bd.title + bd.menu;
	rtScr.h = rtWnd.h - bd.title - bd.menu - 2 * bd.edge;

	lighten_xbrush(&xb, DEF_SOFT_DARKEN);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &rtScr);

	lighten_xbrush(&xb, DEF_HARD_DARKEN);
	xscpy(xp.color, xb.color);

	//up page button
	rtScr.x = rtWnd.x + rtWnd.w - bd.vscroll;
	rtScr.y = rtWnd.y + bd.edge + bd.title + bd.menu;
	rtScr.w = bd.vscroll;
	rtScr.h = bd.vscroll;
	pt_expand_rect(&rtScr, -4, -6);

	(*ifv.pf_draw_triangle)(ifv.ctx, &xp, &xb, &rtScr, GDI_ATTR_ORIENT_TOP);

	//down page button
	rtScr.x = rtWnd.x + rtWnd.w - bd.edge - bd.vscroll;
	rtScr.y = rtWnd.y + rtWnd.h - bd.edge - bd.vscroll;
	rtScr.w = bd.vscroll;
	rtScr.h = bd.vscroll;
	pt_expand_rect(&rtScr, -4, -6);

	(*ifv.pf_draw_triangle)(ifv.ctx, &xp, &xb, &rtScr, GDI_ATTR_ORIENT_BOTTOM);

	if (sl.max + sl.page / 2 > sl.min)
	{
		//up line button
		rtScr.x = rtWnd.x + rtWnd.w - bd.edge - bd.vscroll;
		rtScr.y = rtWnd.y + bd.edge + bd.title + bd.menu + bd.vscroll;
		rtScr.w = bd.vscroll;
		rtScr.h = bd.vscroll;
		pt_expand_rect(&rtScr, -3, -3);

		(*ifv.pf_draw_round)(ifv.ctx, &xp, &xb, &rtScr, NULL);

		//down line button
		rtScr.x = rtWnd.x + rtWnd.w - bd.edge - bd.vscroll;
		rtScr.y = rtWnd.y + rtWnd.h - bd.edge - 2 * bd.vscroll;
		rtScr.w = bd.vscroll;
		rtScr.h = bd.vscroll;
		pt_expand_rect(&rtScr, -3, -3);

		(*ifv.pf_draw_round)(ifv.ctx, &xp, &xb, &rtScr, NULL);

		if (!sl.pos)
		{
			rtScr.x = rtWnd.x + rtWnd.w - bd.edge - bd.vscroll;
			rtScr.y = rtWnd.y + bd.edge + bd.title + bd.menu + bd.vscroll;
			rtScr.w = bd.vscroll;
			rtScr.h = bd.vscroll;
		}
		else if (sl.pos == sl.max)
		{
			rtScr.x = rtWnd.x + rtWnd.w - bd.edge - bd.vscroll;
			rtScr.y = rtWnd.y + rtWnd.h - bd.edge - 2 * bd.vscroll;
			rtScr.w = bd.vscroll;
			rtScr.h = bd.vscroll;
		}
		else
		{
			ind = (int)((float)sl.pos / (float)sl.max * (float)(rtWnd.h - bd.title - bd.menu - 2 * bd.edge - 3 * bd.vscroll));

			rtScr.x = rtWnd.x + rtWnd.w - bd.edge - bd.vscroll;
			rtScr.y = rtWnd.y + bd.edge + bd.title + bd.menu + bd.vscroll + ind;
			rtScr.w = bd.vscroll;
			rtScr.h = bd.vscroll;
		}

		pt_expand_rect(&rtScr, -4, -4);

		lighten_xpen(&xp, DEF_SOFT_LIGHTEN);
		lighten_xbrush(&xb, DEF_SOFT_LIGHTEN);
		(*ifv.pf_draw_ellipse)(ifv.ctx, &xp, &xb, &rtScr);
	}

	
}

static void _WidgetDrawTitleBar(res_win_t wt, visual_t rdc)
{
	int edge, title, hscr, vscr, menu, icon;
	border_t bd = { 0 };
	xrect_t rtWnd, rtScr;
	xpoint_t pt1, pt2;
	dword_t ws;

	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };
	xcolor_t xc = { 0 };
	xfont_t xf = { 0 };
	xface_t xa = { 0 };

	tchar_t txt[RES_LEN + 1] = { 0 };
	int len;

	xbrush_t xb_shadow = { 0 };
	xpen_t xp_shadow = { 0 };
	tchar_t aa[8] = { 0 };
	xpoint_t pa[15] = { 0 };

	int i = 0;
	int n = 0;
	int feed = 5;

	drawing_interface ifv = {0};

	ws = widget_get_style(wt);

	widget_calc_border(ws, &bd);

	edge = bd.edge;
	title = bd.title;
	hscr = bd.hscroll;
	vscr = bd.vscroll;
	menu = bd.menu;
	icon = bd.icon;

	if (!title)
		return;

	get_visual_interface(rdc, &ifv);

	widget_get_window_rect(wt, &rtWnd);
	rtWnd.x = rtWnd.y = 0;

	rtScr.x = rtWnd.x + edge;
	rtScr.y = rtWnd.y + edge;
	rtScr.w = rtWnd.w - 2 * edge;
	rtScr.h = title;

	widget_get_xbrush(wt, &xb);
	widget_get_xpen(wt, &xp);
	widget_get_xfont(wt, &xf);
	widget_get_xface(wt, &xa);

	rtScr.x = rtWnd.x + edge;
	rtScr.y = rtWnd.y + edge;
	rtScr.w = rtWnd.w - 2 * edge;
	rtScr.h = title - feed;

	aa[i] = _T('M');
	pa[n].x = rtScr.x;
	pa[n].y = rtScr.y;
	i++;
	n++;

	aa[i] = _T('L');
	pa[n].x = rtScr.x + rtScr.w;
	pa[n].y = rtScr.y;
	i++;
	n++;

	aa[i] = _T('L');
	pa[n].x = rtScr.x + rtScr.w;
	pa[n].y = rtScr.y + rtScr.h - 2 * feed;
	i++;
	n++;

	aa[i] = _T('A');
	pa[n].x = 1;
	pa[n].y = 0;
	pa[n+1].x = feed;
	pa[n+1].y = feed;
	pa[n+2].x = rtScr.x + rtScr.w - feed;
	pa[n+2].y = rtScr.y + rtScr.h - feed;
	i++;
	n += 3;

	aa[i] = _T('C');
	pa[n].x = rtScr.x + rtScr.w / 8 * 7;
	pa[n].y = rtScr.y + rtScr.h - 2 * feed;
	pa[n+1].x = rtScr.x + rtScr.w / 4 * 3;
	pa[n+1].y = rtScr.y + rtScr.h - feed;
	pa[n+2].x = rtScr.x + rtScr.w / 2;
	pa[n+2].y = rtScr.y + rtScr.h;
	i++;
	n += 3;

	aa[i] = _T('S');
	pa[n].x = rtScr.x + rtScr.w / 4;
	pa[n].y = rtScr.y + rtScr.h;
	pa[n + 1].x = rtScr.x + feed;
	pa[n + 1].y = rtScr.y + rtScr.h;
	i++;
	n += 2;

	aa[i] = _T('A');
	pa[n].x = 1;
	pa[n].y = 0;
	pa[n+1].x = feed;
	pa[n+1].y = feed;
	pa[n+2].x = rtScr.x;
	pa[n+2].y = rtScr.y + rtScr.h - feed;
	i++;
	n += 3;

	aa[i] = _T('Z');
	i++;

	xmem_copy((void*)&xb_shadow, (void*)&xb, sizeof(xbrush_t));
	lighten_xbrush(&xb_shadow, DEF_SOFT_DARKEN);
	xmem_copy((void*)&xp_shadow, (void*)&xp, sizeof(xpen_t));
	xscpy(xp_shadow.color, xb_shadow.color);

	//xb_shadow.shadow.offx = feed;
	//xb_shadow.shadow.offy = feed;
	xp_shadow.adorn.feed = 2;
	xp_shadow.adorn.size = 2;

	(*ifv.pf_draw_path)(ifv.ctx, &xp_shadow, &xb_shadow, aa, pa, n);

	rtScr.x = rtWnd.x + edge;
	rtScr.y = rtWnd.y + edge;
	rtScr.w = title;
	rtScr.h = title;

	pt_center_rect(&rtScr, 16, 16);
	parse_xcolor(&xc, xp.color);

	_WidgetDrawLogo(rdc, &xc, &rtScr);

	/*caption*/
	len = widget_get_title(wt, txt, RES_LEN);
	if (len)
	{
		rtScr.x = rtWnd.x + edge + title;
		rtScr.w = rtWnd.w - 2 * edge - 2 * title;
		rtScr.y = rtWnd.y + edge;
		rtScr.h = title;

		(*ifv.pf_draw_text)(ifv.ctx, &xf, &xa, &rtScr, txt, len);
	}

	if (ws & WD_STYLE_SIZEBOX)
	{
		xscpy(xp.size, _T("2"));

		/*mini box*/
		rtScr.x = rtWnd.x + rtWnd.w - edge - (title / 2 * 3);
		rtScr.w = title / 2;
		rtScr.y = rtWnd.y + edge;
		rtScr.h = title * 2 / 3;
		pt_center_rect(&rtScr, icon, icon);

		rtScr.y += rtScr.h / 2;
		rtScr.h /= 2;
		(*ifv.pf_draw_rect)(ifv.ctx, &xp, &xb, &rtScr);

		/*zoom box*/
		rtScr.x = rtWnd.x + rtWnd.w - edge - title;
		rtScr.w = title / 2;
		rtScr.y = rtWnd.y + edge;
		rtScr.h = title * 2 / 3;
		pt_center_rect(&rtScr, icon, icon);

		(*ifv.pf_draw_round)(ifv.ctx, &xp, &xb, &rtScr, NULL);

		if (widget_is_maximized(wt))
		{
			pt_expand_rect(&rtScr, -3, -3);
			(*ifv.pf_draw_rect)(ifv.ctx, &xp, &xb, &rtScr);
		}
	}

	if (ws & WD_STYLE_CLOSEBOX)
	{
		rtScr.x = rtWnd.x + rtWnd.w - edge - (title / 2);
		rtScr.w = title / 2;
		rtScr.y = rtWnd.y + edge;
		rtScr.h = title * 2 / 3;
		pt_center_rect(&rtScr, icon, icon);

		xscpy(xp.size, _T("2"));

		pt1.x = rtScr.x;
		pt1.y = rtScr.y;
		pt2.x = rtScr.x + rtScr.w;
		pt2.y = rtScr.y + rtScr.h;
		(*ifv.pf_draw_line)(ifv.ctx, &xp, &pt1, &pt2);
		
		pt1.x = rtScr.x;
		pt1.y = rtScr.y + rtScr.h;
		pt2.x = rtScr.x + rtScr.w;
		pt2.y = rtScr.y;
		(*ifv.pf_draw_line)(ifv.ctx, &xp, &pt1, &pt2);
	}
}

static void _WidgetDrawMenuBar(res_win_t wt, visual_t rdc)
{
	int edge, title, vscr, hscr, menu;
	dword_t ws;
	border_t bd = { 0 };
	scroll_t sc = { 0 };
	xrect_t rtWnd, rtMenu, rtImage;
	xsize_t xs = { 0 };

	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };
	xfont_t xf = { 0 };
	xface_t xa = { 0 };
	xcolor_t xc = { 0 };

	link_t_ptr ptr, ilk;
	const tchar_t* text;

	drawing_interface ifv = {0};

	ws = widget_get_style(wt);
	widget_calc_border(ws, &bd);

	edge = bd.edge;
	title = bd.title;
	hscr = bd.hscroll;
	vscr = bd.vscroll;
	menu = bd.menu;

	if (!menu)
		return;

	get_visual_interface(rdc, &ifv);

	widget_get_window_rect(wt, &rtWnd);
	rtWnd.x = rtWnd.y = 0;

	widget_get_xbrush(wt, &xb);
	lighten_xbrush(&xb, DEF_SOFT_DARKEN);
	widget_get_xpen(wt, &xp);
	widget_get_xfont(wt, &xf);
	widget_get_xface(wt, &xa);
	widget_get_iconic(wt, &xc);

	if (!is_null(xf.size))
	{
		ltoxs(xstol(xf.size) - 1, xf.size, INT_LEN);
	}

	lighten_xbrush(&xb, DEF_SOFT_DARKEN);

	rtMenu.x = rtWnd.x + edge;
	rtMenu.w = rtWnd.w - 2 * edge;
	rtMenu.y = rtWnd.y + edge + title;
	rtMenu.h = menu;

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &rtMenu);

	ptr = widget_get_menu(wt);

	rtImage.x = rtWnd.x + edge;
	rtImage.w = 0;
	rtImage.y = rtWnd.y + edge + title;
	rtImage.h = menu;

	ilk = (ptr)? get_menu_next_item(ptr, LINK_FIRST) : NULL;
	while (ilk)
	{
		rtImage.x += rtImage.w;
		rtImage.w = menu;

		pt_center_rect(&rtImage, 16, 16);

		text = get_menu_item_title_ptr(ilk);
		if (!is_null(text))
		{
			(*ifv.pf_text_size)(ifv.ctx, &xf, text, -1, &xs);

			rtImage.x += menu;
			rtImage.w = xs.w;

			(*ifv.pf_draw_text)(ifv.ctx, &xf, &xa, &rtImage, text, -1);
		}

		ilk = get_menu_next_item(ptr, ilk);
	}
}
/**************************************************************************************************/

void widgetnc_on_paint(res_win_t wt, visual_t dc)
{
	border_t bd = { 0 };

	widget_calc_border(widget_get_style(wt), &bd);

	if (bd.edge)
	{
		_WidgetDrawEdge(wt, dc);
	}

	if (bd.title)
	{
		_WidgetDrawTitleBar(wt, dc);
	}

	if (bd.menu)
	{
		_WidgetDrawMenuBar(wt, dc);
	}

	if (bd.hscroll)
	{
		_WidgetDrawHScroll(wt, dc);
	}

	if (bd.vscroll)
	{
		_WidgetDrawVScroll(wt, dc);
	}
}

void widgetnc_on_calcsize(res_win_t wt, border_t* pbd)
{
	widget_calc_border(widget_get_style(wt), pbd);
}

int widgetnc_on_hittest(res_win_t wt, const xpoint_t* pxp)
{
	int edge, title, vscr, hscr, menu;
	border_t bd = { 0 };
	dword_t ws;
	xrect_t xr, rt;
	xpoint_t pt;

	ws = widget_get_style(wt);

	widget_calc_border(ws, &bd);

	edge = bd.edge;
	title = bd.title;
	hscr = bd.hscroll;
	vscr = bd.vscroll;
	menu = bd.menu;

	if (!edge && !title && !vscr && !hscr && !menu)
		return HINT_CLIENT;

	widget_get_window_rect(wt, &xr);

	pt.x = pxp->x;
	pt.y = pxp->y;

	if (menu)
	{
		rt.x = xr.x + edge;
		rt.w = xr.w - 2 * edge;
		rt.y = xr.y + edge + title;
		rt.h = menu;

		if (pt_in_rect(pxp, &rt))
			return HINT_MENUBAR;
	}

	if (hscr)
	{
		rt.x = xr.x + edge;
		rt.w = hscr;
		rt.y = xr.y + xr.h - edge - hscr;
		rt.h = hscr;

		if (pt_in_rect(pxp, &rt))
			return HINT_LINELEFT;

		rt.x = xr.x + edge + hscr;
		rt.w = xr.w - 2 * edge - vscr - 2 * hscr;
		rt.y = xr.y + xr.h - edge - hscr;
		rt.h = hscr;

		if (pt_in_rect(pxp, &rt))
			return HINT_HSCROLL;

		rt.x = xr.x + xr.w - edge - vscr - hscr;
		rt.w = hscr;
		rt.y = xr.y + xr.h - edge - hscr;
		rt.h = hscr;

		if (pt_in_rect(pxp, &rt))
			return HINT_LINERIGHT;
	}

	if (vscr)
	{
		rt.x = xr.x + xr.w - edge - vscr;
		rt.w = vscr;
		rt.y = xr.y + edge + title + menu;
		rt.h = vscr;

		if (pt_in_rect(pxp, &rt))
			return HINT_PAGEUP;

		rt.x = xr.x + xr.w - edge - vscr;
		rt.w = vscr;
		rt.y = xr.y + edge + title + menu + vscr;
		rt.h = vscr;

		if (pt_in_rect(pxp, &rt))
			return HINT_LINEUP;

		rt.x = xr.x + xr.w - edge - vscr;
		rt.w = vscr;
		rt.y = xr.y + edge + title + menu + 2 * vscr;
		rt.h = xr.h - 2 * edge - title - menu - 4 * vscr;

		if (pt_in_rect(pxp, &rt))
			return HINT_VSCROLL;

		rt.x = xr.x + xr.w - edge - vscr;
		rt.w = vscr;
		rt.y = xr.y + xr.h - edge - 2 * vscr;
		rt.h = vscr;

		if (pt_in_rect(pxp, &rt))
			return HINT_LINEDOWN;

		rt.x = xr.x + xr.w - edge - vscr;
		rt.w = vscr;
		rt.y = xr.y + xr.h - edge - vscr;
		rt.h = vscr;

		if (pt_in_rect(pxp, &rt))
			return HINT_PAGEDOWN;
	}

	if (title)
	{
		rt.x = xr.x + edge;
		rt.w = title;
		rt.y = xr.y + edge;
		rt.h = title;
		if (pt_in_rect(pxp, &rt))
		{
			return HINT_ICON;
		}

		rt.x = xr.x + xr.w - edge - (title / 2 * 3);
		rt.w = title / 2;
		rt.y = xr.y + edge;
		rt.h = title;
		if (pt_in_rect(pxp, &rt))
		{
			if (ws & WD_STYLE_SIZEBOX)
				return HINT_MINIMIZE;
			else
				return HINT_TITLE;
		}

		rt.x = xr.x + xr.w - edge - title;
		rt.w = title / 2;
		rt.y = xr.y + edge;
		rt.h = title;
		if (pt_in_rect(pxp, &rt))
		{
			if (ws & WD_STYLE_SIZEBOX)
			{
				if (widget_is_maximized(wt))
					return HINT_RESTORE;
				else
					return HINT_MAXIMIZE;
			}
			else
				return HINT_TITLE;
		}

		rt.x = xr.x + xr.w - edge - (title / 2);
		rt.w = title / 2;
		rt.y = xr.y + edge;
		rt.h = title;
		if (pt_in_rect(pxp, &rt))
		{
			if (ws & WD_STYLE_CLOSEBOX)
				return HINT_CLOSE;
			else
				return HINT_TITLE;
		}

		rt.x = xr.x + edge;
		rt.w = xr.w - 2 * edge;
		rt.y = xr.y + edge;
		rt.h = title;

		if (pt_in_rect(pxp, &rt))
			return HINT_TITLE;
	}

	if (edge)
	{
		rt.x = xr.x;
		rt.w = edge;
		rt.y = xr.y;
		rt.h = edge;
		if (pt_in_rect(pxp, &rt))
		{
			return HINT_TOPLEFT;
		}

		rt.x = xr.x + edge;
		rt.w = xr.w - 2 * edge;
		rt.y = xr.y;
		rt.h = edge;
		if (pt_in_rect(pxp, &rt))
		{
			return HINT_TOP;
		}

		rt.x = xr.x + xr.w - edge;
		rt.w = edge;
		rt.y = xr.y;
		rt.h = edge;
		if (pt_in_rect(pxp, &rt))
		{
			return HINT_TOPRIGHT;
		}

		rt.x = xr.x;
		rt.w = edge;
		rt.y = xr.y + edge;
		rt.h = xr.h - 2 * edge;
		if (pt_in_rect(pxp, &rt))
		{
			return HINT_LEFT;
		}

		rt.x = xr.x + xr.w - edge;
		rt.w = edge;
		rt.y = xr.y + edge;
		rt.h = xr.h - 2 * edge;
		if (pt_in_rect(pxp, &rt))
		{
			return HINT_RIGHT;
		}

		rt.x = xr.x + xr.w - edge;
		rt.w = edge;
		rt.y = xr.y + xr.h - edge;
		rt.h = edge;
		if (pt_in_rect(pxp, &rt))
		{
			return HINT_RIGHTBOTTOM;
		}

		rt.x = xr.x + edge;
		rt.w = xr.w - 2 * edge;
		rt.y = xr.y + xr.h - edge;
		rt.h = edge;
		if (pt_in_rect(pxp, &rt))
		{
			return HINT_BOTTOM;
		}

		rt.x = xr.x;
		rt.w = edge;
		rt.y = xr.y + xr.h - edge;
		rt.h = edge;
		if (pt_in_rect(pxp, &rt))
		{
			return HINT_LEFTBOTTOM;
		}
	}

	rt.x = xr.x + edge;
	rt.w = xr.w - 2 * edge - vscr;
	rt.y = xr.y + edge + title + menu;
	rt.h = xr.h - 2 * edge - title - menu - hscr;
	if (pt_in_rect(pxp, &rt))
	{
		return HINT_CLIENT;
	}

	return HINT_NOWHERE;
}

int widgetnc_on_calcscroll(res_win_t wt, bool_t horz, const xpoint_t* pxp)
{
	int edge, title, hscr, vscr, menu;
	border_t bd = { 0 };
	int pos;
	xrect_t xr;
	scroll_t sc = { 0 };

	widget_calc_border(widget_get_style(wt), &bd);

	edge = bd.edge;
	title = bd.title;
	hscr = bd.hscroll;
	vscr = bd.vscroll;
	menu = bd.menu;

	if (horz && !hscr)
		return 0;
	else if (!horz && !vscr)
		return 0;

	widget_get_window_rect(wt, &xr);
	xr.x = xr.y = 0;

	if (horz)
	{
		widget_get_scroll_info(wt, 1, &sc);

		if (!sc.pos &&  pxp->x < edge + hscr)
		{
			return -sc.min;
		}
		else if (sc.pos == sc.max && pxp->x > xr.w - edge - vscr - hscr)
		{
			return sc.max + sc.min;
		}

		if (sc.max > 0)
		{
			pos = (int)((float)(pxp->x - edge) / (float)(xr.w - 2 * edge - hscr - vscr) * (float)sc.max);
			if (pos < 0)
				pos = 0;
			else if (pos > sc.max)
				pos = sc.max;
		}
		else
		{
			pos = 0;
		}
	}
	else
	{
		widget_get_scroll_info(wt, 0, &sc);

		if (!sc.pos && pxp->y < edge + title + menu + 2 * vscr)
		{
			return -sc.min;
		}
		else if (sc.pos == sc.max && pxp->y > xr.h - edge - 2 * vscr)
		{
			return sc.max + sc.min;
		}

		if (sc.max > 0)
		{
			pos = (int)((float)(pxp->y - edge - title - menu - vscr) / (float)(xr.h - 2 * edge - title - menu - 2 * vscr) * (float)sc.max);
			if (pos < 0)
				pos = 0;
			else if (pos > sc.max)
				pos = sc.max;
		}
		else
		{
			pos = 0;
		}
	}

	return pos;
}

void widget_draw_scroll(res_win_t wt, bool_t horz)
{
	visual_t dc;

	dc = widget_window_ctx(wt);

	if (horz)
		_WidgetDrawHScroll(wt, dc);
	else
		_WidgetDrawVScroll(wt, dc);

	widget_release_ctx(wt, dc);
}

#endif