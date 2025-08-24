/***********************************************************************
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

#include "xdunc.h"

#include "xduloc.h"


#ifdef XDU_SUPPORT_WIDGET_NC

static void _WidgetDrawLogo(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt)
{
	xpen_t xp;
	xbrush_t xb;
	xrect_t rt, xr;

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

	_gdi_draw_round(rdc, &xp, &xb, &xr, NULL);

	xr.x = prt->x + prt->w / 2 + 1;
	xr.y = prt->y;
	xr.w = prt->w / 2 - 2;
	xr.h = prt->h / 2 - 2;
	_gdi_draw_rect(rdc, &xp, &xb, &xr);

	xr.x = prt->x;
	xr.y = prt->y + prt->h / 2 + 1;
	xr.w = prt->w / 2 - 2;
	xr.h = prt->h / 2 - 2;
	_gdi_draw_rect(rdc, &xp, &xb, &xr);

	xr.x = prt->x + prt->w / 2 + 1;
	xr.y = prt->y + prt->h / 2 + 1;
	xr.w = prt->w / 2 - 2;
	xr.h = prt->h / 2 - 2;
	_gdi_draw_round(rdc, &xp, &xb, &xr, NULL);
}

static void _WidgetDrawEdge(widget_t wt, visual_t rdc, const xrect_t* prt)
{
	border_t bd = { 0 };
	dword_t ws;
	xpen_t xp;
	xbrush_t xb;
	color_mod_t clrs;
	xrect_t rtScr;

	ws = _widget_get_style(wt);
	_calc_widget_border(ws, &bd);

	if (!bd.edge && !bd.title)
		return;

	rtScr.x = prt->x + bd.edge;
	rtScr.y = prt->y + bd.title;
	rtScr.w = prt->w - bd.edge * 2;
	rtScr.h = prt->h - bd.title - bd.edge;
	_gdi_exclude_rect(rdc, &rtScr);

	_widget_get_color_mode(wt, &clrs);
	default_xpen(&xp);
	format_xcolor(&clrs.clr_bkg, xp.color);
	default_xbrush(&xb);
	format_xcolor(&clrs.clr_bkg, xb.color);

	_gdi_draw_rect(rdc, &xp, &xb, prt);
}

static void _WidgetDrawHScroll(widget_t wt, visual_t rdc, const xrect_t* prt)
{
	border_t bd = { 0 };
	xrect_t rtScr;
	scroll_t sl = { 0 };
	int ind;

	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };
	color_mod_t clrs;

	dword_t wstyle = _widget_get_style(wt);

	_calc_widget_border(wstyle, &bd);

	if (!bd.scrh)
		return;

	_widget_get_scroll_info(wt, 1, &sl);

	_widget_get_color_mode(wt, &clrs);
	default_xbrush(&xb);
	format_xcolor(&clrs.clr_bkg, xb.color);
	default_xpen(&xp);
	format_xcolor(&clrs.clr_frg, xp.color);

	rtScr.x = prt->x + bd.edge;
	rtScr.w = prt->w - 2 * bd.edge - bd.scrw;
	rtScr.y = prt->y + prt->h - bd.edge - bd.scrh;
	rtScr.h = bd.scrh;

	lighten_xbrush(&xb, DEF_SOFT_DARKEN);

	_gdi_draw_rect(rdc, NULL, &xb, &rtScr);

	if (sl.max + sl.page / 2 > sl.min)
	{
		lighten_xbrush(&xb, DEF_HARD_DARKEN);
		xscpy(xp.color, xb.color);

		rtScr.x = prt->x + bd.edge;
		rtScr.w = bd.scrh;
		rtScr.y = prt->y + prt->h - bd.edge - bd.scrh;
		rtScr.h = bd.scrh;
		pt_expand_rect(&rtScr, -3, -3);

		_gdi_draw_round(rdc, &xp, &xb, &rtScr, NULL);

		rtScr.x = prt->x + prt->w - bd.edge - bd.scrw - bd.scrh;
		rtScr.w = bd.scrh;
		rtScr.y = prt->y + prt->h - bd.edge - bd.scrh;
		rtScr.h = bd.scrh;
		pt_expand_rect(&rtScr, -3, -3);

		_gdi_draw_round(rdc, &xp, &xb, &rtScr, NULL);

		if (!sl.pos)
		{
			rtScr.x = prt->x + bd.edge;
			rtScr.w = bd.scrh;
			rtScr.y = prt->y + prt->h - bd.edge - bd.scrh;
			rtScr.h = bd.scrh;
		}
		else if (sl.pos == sl.max)
		{
			rtScr.x = prt->x + prt->w - bd.edge - bd.scrw - bd.scrh;
			rtScr.w = bd.scrh;
			rtScr.y = prt->y + prt->h - bd.edge - bd.scrh;
			rtScr.h = bd.scrh;
		}
		else
		{
			ind = (int)((float)sl.pos / (float)sl.max * (float)(prt->w - 2 * bd.edge - bd.scrw - bd.scrh));
			rtScr.x = prt->x + bd.edge + ind;
			rtScr.w = bd.scrh;
			rtScr.y = prt->y + prt->h - bd.edge - bd.scrh;
			rtScr.h = bd.scrh;
		}
		pt_expand_rect(&rtScr, -4, -4);

		lighten_xpen(&xp, DEF_SOFT_LIGHTEN);
		lighten_xbrush(&xb, DEF_SOFT_LIGHTEN);
		_gdi_draw_ellipse(rdc, &xp, &xb, &rtScr);
	}
}

static void _WidgetDrawVScroll(widget_t wt, visual_t rdc, const xrect_t* prt)
{
	border_t bd = { 0 };
	xrect_t rtScr;
	scroll_t sl = { 0 };
	int ind;

	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };
	color_mod_t clrs;

	dword_t ws = _widget_get_style(wt);
	_calc_widget_border(ws, &bd);

	if (!bd.scrw)
		return;

	_widget_get_scroll_info(wt, 0, &sl);

	_widget_get_color_mode(wt, &clrs);
	default_xbrush(&xb);
	format_xcolor(&clrs.clr_bkg, xb.color);
	default_xpen(&xp);
	format_xcolor(&clrs.clr_frg, xp.color);

	rtScr.x = prt->x + prt->w - bd.edge - bd.scrw;
	rtScr.w = bd.scrw;
	rtScr.y = prt->y + bd.edge + bd.title;
	rtScr.h = prt->h - bd.title - 2 * bd.edge;

	lighten_xbrush(&xb, DEF_SOFT_DARKEN);

	_gdi_draw_rect(rdc, NULL, &xb, &rtScr);

	lighten_xbrush(&xb, DEF_HARD_DARKEN);
	xscpy(xp.color, xb.color);

	//up page button
	rtScr.x = prt->x + prt->w - bd.scrw;
	rtScr.y = prt->y + bd.edge + bd.title;
	rtScr.w = bd.scrw;
	rtScr.h = bd.scrw;
	pt_expand_rect(&rtScr, -4, -6);

	//_gdi_draw_triangle(rdc, &xp, &xb, &rtScr, GDI_ATTR_ORIENT_TOP);

	//down page button
	rtScr.x = prt->x + prt->w - bd.edge - bd.scrw;
	rtScr.y = prt->y + prt->h - bd.edge - bd.scrw;
	rtScr.w = bd.scrw;
	rtScr.h = bd.scrw;
	pt_expand_rect(&rtScr, -4, -6);

	//_gdi_draw_triangle(rdc, &xp, &xb, &rtScr, GDI_ATTR_ORIENT_BOTTOM);

	if (sl.max + sl.page / 2 > sl.min)
	{
		//up line button
		rtScr.x = prt->x + prt->w - bd.edge - bd.scrw;
		rtScr.y = prt->y + bd.edge + bd.title + bd.scrw;
		rtScr.w = bd.scrw;
		rtScr.h = bd.scrw;
		pt_expand_rect(&rtScr, -3, -3);

		_gdi_draw_round(rdc, &xp, &xb, &rtScr, NULL);

		//down line button
		rtScr.x = prt->x + prt->w - bd.edge - bd.scrw;
		rtScr.y = prt->y + prt->h - bd.edge - 2 * bd.scrw;
		rtScr.w = bd.scrw;
		rtScr.h = bd.scrw;
		pt_expand_rect(&rtScr, -3, -3);

		_gdi_draw_round(rdc, &xp, &xb, &rtScr, NULL);

		if (!sl.pos)
		{
			rtScr.x = prt->x + prt->w - bd.edge - bd.scrw;
			rtScr.y = prt->y + bd.edge + bd.title + bd.scrw;
			rtScr.w = bd.scrw;
			rtScr.h = bd.scrw;
		}
		else if (sl.pos == sl.max)
		{
			rtScr.x = prt->x + prt->w - bd.edge - bd.scrw;
			rtScr.y = prt->y + prt->h - bd.edge - 2 * bd.scrw;
			rtScr.w = bd.scrw;
			rtScr.h = bd.scrw;
		}
		else
		{
			ind = (int)((float)sl.pos / (float)sl.max * (float)(prt->h - bd.title - 2 * bd.edge - 3 * bd.scrw));

			rtScr.x = prt->x + prt->w - bd.edge - bd.scrw;
			rtScr.y = prt->y + bd.edge + bd.title + bd.scrw + ind;
			rtScr.w = bd.scrw;
			rtScr.h = bd.scrw;
		}

		pt_expand_rect(&rtScr, -4, -4);

		lighten_xpen(&xp, DEF_SOFT_LIGHTEN);
		lighten_xbrush(&xb, DEF_SOFT_LIGHTEN);
		_gdi_draw_ellipse(rdc, &xp, &xb, &rtScr);
	}
}

static void _WidgetDrawTitleBar(widget_t wt, visual_t rdc, const xrect_t* prt)
{
	int edge, title, hscr, vscr;
	border_t bd = { 0 };
	xrect_t rtScr;
	xpoint_t pt1, pt2;
	dword_t ws;

	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };
	xcolor_t xc = { 0 };
	xfont_t xf = { 0 };
	xface_t xa = { 0 };

	tchar_t txt[RES_LEN + 1] = { 0 };
	int len;

	color_mod_t clrs;
	xbrush_t xb_shadow = { 0 };
	xpen_t xp_shadow = { 0 };
	tchar_t aa[8] = { 0 };
	xpoint_t pa[15] = { 0 };

	int i = 0;
	int n = 0;
	int feed = 5;

	ws = _widget_get_style(wt);
	_calc_widget_border(ws, &bd);

	edge = bd.edge;
	title = bd.title;
	hscr = bd.scrh;
	vscr = bd.scrw;

	if (!title)
		return;

	rtScr.x = prt->x + edge;
	rtScr.y = prt->y + edge;
	rtScr.w = prt->w - 2 * edge;
	rtScr.h = title;

	_widget_get_color_mode(wt, &clrs);
	default_xbrush(&xb);
	format_xcolor(&clrs.clr_bkg, xb.color);
	default_xpen(&xp);
	format_xcolor(&clrs.clr_frg, xp.color);
	default_xfont(&xf);
	format_xcolor(&clrs.clr_txt, xf.color);
	default_xface(&xa);

	rtScr.x = prt->x + edge;
	rtScr.y = prt->y + edge;
	rtScr.w = prt->w - 2 * edge;
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

	_gdi_draw_path(rdc, &xp_shadow, &xb_shadow, aa, pa, n);

	rtScr.x = prt->x + edge;
	rtScr.y = prt->y + edge;
	rtScr.w = title;
	rtScr.h = title;

	pt_center_rect(&rtScr, 16, 16);
	parse_xcolor(&xc, xp.color);

	_WidgetDrawLogo(rdc, &xc, &rtScr);

	/*caption*/
	len = _widget_get_title(wt, txt, RES_LEN);
	if (len)
	{
		rtScr.x = prt->x + edge + title;
		rtScr.w = prt->w - 2 * edge - 2 * title;
		rtScr.y = prt->y + edge;
		rtScr.h = title;

		_gdi_draw_text(rdc, &xf, &xa, &rtScr, txt, len);
	}

	if (ws & WD_STYLE_SIZEBOX)
	{
		xscpy(xp.size, _T("2"));

		/*mini box*/
		rtScr.x = prt->x + prt->w - edge - (title / 2 * 3);
		rtScr.w = title / 2;
		rtScr.y = prt->y + edge;
		rtScr.h = title * 2 / 3;
		pt_center_rect(&rtScr, FRAME_ICON_DOTS, FRAME_ICON_DOTS);

		rtScr.y += rtScr.h / 2;
		rtScr.h /= 2;
		_gdi_draw_rect(rdc, &xp, &xb, &rtScr);

		/*zoom box*/
		rtScr.x = prt->x + prt->w - edge - title;
		rtScr.w = title / 2;
		rtScr.y = prt->y + edge;
		rtScr.h = title * 2 / 3;
		pt_center_rect(&rtScr, FRAME_ICON_DOTS, FRAME_ICON_DOTS);

		_gdi_draw_round(rdc, &xp, &xb, &rtScr, NULL);

		if (_widget_is_maximized(wt))
		{
			pt_expand_rect(&rtScr, -3, -3);
			_gdi_draw_rect(rdc, &xp, &xb, &rtScr);
		}
	}

	if (ws & WD_STYLE_CLOSEBOX)
	{
		rtScr.x = prt->x + prt->w - edge - (title / 2);
		rtScr.w = title / 2;
		rtScr.y = prt->y + edge;
		rtScr.h = title * 2 / 3;
		pt_center_rect(&rtScr, FRAME_ICON_DOTS, FRAME_ICON_DOTS);

		xscpy(xp.size, _T("2"));

		pt1.x = rtScr.x;
		pt1.y = rtScr.y;
		pt2.x = rtScr.x + rtScr.w;
		pt2.y = rtScr.y + rtScr.h;
		_gdi_draw_line(rdc, &xp, &pt1, &pt2);
		
		pt1.x = rtScr.x;
		pt1.y = rtScr.y + rtScr.h;
		pt2.x = rtScr.x + rtScr.w;
		pt2.y = rtScr.y;
		_gdi_draw_line(rdc, &xp, &pt1, &pt2);
	}
}

/**************************************************************************************************/

void _widget_nc_draw_frame(widget_t wt, visual_t dc, const xrect_t* prt)
{
	border_t bd = { 0 };
	dword_t ws;

	ws = _widget_get_style(wt);
	_calc_widget_border(ws, &bd);

	if (bd.edge)
	{
		_WidgetDrawEdge(wt, dc, prt);
	}

	if (bd.title)
	{
		_WidgetDrawTitleBar(wt, dc, prt);
	}

	if (bd.scrh)
	{
		_WidgetDrawHScroll(wt, dc, prt);
	}

	if (bd.scrw)
	{
		_WidgetDrawVScroll(wt, dc, prt);
	}
}

void _widget_nc_draw_scroll(widget_t wt, visual_t dc, bool_t horz, const xrect_t* prt)
{
	
	if (horz)
		_WidgetDrawHScroll(wt, dc, prt);
	else
		_WidgetDrawVScroll(wt, dc, prt);
}

int _widget_nc_hint_test(widget_t wt, const xpoint_t* pxp)
{
	int edge, title, vscr, hscr;
	border_t bd = { 0 };
	dword_t ws;
	xrect_t xr, rt;
	xpoint_t pt;

	ws = _widget_get_style(wt);
	_calc_widget_border(ws, &bd);

	edge = bd.edge;
	title = bd.title;
	hscr = bd.scrh;
	vscr = bd.scrw;

	if (!edge && !title && !vscr && !hscr)
		return HINT_CLIENT;

	_widget_get_window_rect(wt, &xr);

	pt.x = pxp->x;
	pt.y = pxp->y;

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
		rt.y = xr.y + edge + title;
		rt.h = vscr;

		if (pt_in_rect(pxp, &rt))
			return HINT_PAGEUP;

		rt.x = xr.x + xr.w - edge - vscr;
		rt.w = vscr;
		rt.y = xr.y + edge + title + vscr;
		rt.h = vscr;

		if (pt_in_rect(pxp, &rt))
			return HINT_LINEUP;

		rt.x = xr.x + xr.w - edge - vscr;
		rt.w = vscr;
		rt.y = xr.y + edge + title + 2 * vscr;
		rt.h = xr.h - 2 * edge - title - 4 * vscr;

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
				if (_widget_is_maximized(wt))
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
	rt.y = xr.y + edge + title;
	rt.h = xr.h - 2 * edge - title - hscr;
	if (pt_in_rect(pxp, &rt))
	{
		return HINT_CLIENT;
	}

	return HINT_NOWHERE;
}

int _widget_nc_calc_scroll(widget_t wt, bool_t horz, const xpoint_t* pxp)
{
	int edge, title, hscr, vscr;
	border_t bd = { 0 };
	int pos;
	xrect_t xr;
	scroll_t sc = { 0 };

	dword_t ws = _widget_get_style(wt);
	_calc_widget_border(ws, &bd);

	edge = bd.edge;
	title = bd.title;
	hscr = bd.scrh;
	vscr = bd.scrw;

	if (horz && !hscr)
		return 0;
	else if (!horz && !vscr)
		return 0;

	_widget_get_window_rect(wt, &xr);
	xr.x = xr.y = 0;

	if (horz)
	{
		_widget_get_scroll_info(wt, 1, &sc);

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
		_widget_get_scroll_info(wt, 0, &sc);

		if (!sc.pos && pxp->y < edge + title + 2 * vscr)
		{
			return -sc.min;
		}
		else if (sc.pos == sc.max && pxp->y > xr.h - edge - 2 * vscr)
		{
			return sc.max + sc.min;
		}

		if (sc.max > 0)
		{
			pos = (int)((float)(pxp->y - edge - title - vscr) / (float)(xr.h - 2 * edge - title - 2 * vscr) * (float)sc.max);
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

#endif