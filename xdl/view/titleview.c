﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc title view

	@module	titleview.c | implement file

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
#include "titleview.h"

#include "../xdlgdi.h"
#include "../xdldoc.h"


#define TITLE_EDGE_DARK	 1.0f
#define	TITLE_EDGE_LIGHT 2.0f
#define TITLE_EDGE_ARC	 1.0f
/*********************************************************************************************/
float calc_title_width(link_t_ptr ptr)
{
	link_t_ptr plk;
	bool_t b_vert;
	float fw, fh, iw, w = 0;

	fw = get_title_width(ptr);
	fh = get_title_height(ptr);

	b_vert = (compare_text(get_title_oritation_ptr(ptr), -1, ATTR_ORITATION_LEFT, -1, 0) == 0 || compare_text(get_title_oritation_ptr(ptr), -1, ATTR_ORITATION_RIGHT, -1, 0) == 0) ? 1 : 0;
	if (b_vert)
		return fw;

	iw = get_title_item_width(ptr);

	plk = get_title_next_item(ptr, LINK_FIRST);
	while (plk)
	{
		w += iw;
		plk = get_title_next_item(ptr, plk);
	}

	return w;
}

float calc_title_height(link_t_ptr ptr)
{
	link_t_ptr plk;
	bool_t b_vert;
	float fw, fh, ih, h = 0;

	fw = get_title_width(ptr);
	fh = get_title_height(ptr);

	b_vert = (compare_text(get_title_oritation_ptr(ptr), -1, ATTR_ORITATION_LEFT, -1, 0) == 0 || compare_text(get_title_oritation_ptr(ptr), -1, ATTR_ORITATION_RIGHT, -1, 0) == 0) ? 1 : 0;
	if (!b_vert)
		return fh;

	ih = get_title_item_height(ptr);

	plk = get_title_next_item(ptr, LINK_FIRST);
	while (plk)
	{
		h += ih;
		plk = get_title_next_item(ptr, plk);
	}

	return h;
}

void calc_title_item_rect(link_t_ptr ptr, link_t_ptr ilk, xrect_t* pxr)
{
	link_t_ptr plk;
	float pw, ph, iw, ih, hw = 0;
	bool_t lay_vert;
	xrect_t xr;

	lay_vert = (compare_text(get_title_oritation_ptr(ptr), -1, ATTR_ORITATION_LEFT, -1, 0) == 0 || compare_text(get_title_oritation_ptr(ptr), -1, ATTR_ORITATION_RIGHT, -1, 0) == 0) ? 1 : 0;
	
	pw = get_title_width(ptr);
	ph = get_title_height(ptr);
	iw = get_title_item_width(ptr);
	ih = get_title_item_height(ptr);

	plk = get_title_next_item(ptr, LINK_FIRST);
	while (plk)
	{
		if (lay_vert)
		{
			xr.fx = 0;
			xr.fy = hw;
			xr.fw = pw;
			xr.fh = ih;
		}
		else
		{
			xr.fx = hw;
			xr.fy = 0;
			xr.fw = iw;
			xr.fh = ph;
		}

		if (plk == ilk)
		{
			xmem_copy((void*)pxr, (void*)&xr, sizeof(xrect_t));
			return;
		}

		if (lay_vert)
		{
			hw += ih;
		}
		else
		{
			hw += iw;
		}

		plk = get_title_next_item(ptr, plk);
	}

	xmem_zero((void*)pxr, sizeof(xrect_t));
}

int calc_title_hint(const xpoint_t* ppt, link_t_ptr ptr, link_t_ptr plk_focus, link_t_ptr* pilk)
{
	link_t_ptr plk;
	float pw, ph, iw, ih, ic, hw = 0;
	float xm, ym;
	bool_t lay_vert;
	int nHint;
	xrect_t xr;

	nHint = TITLE_HINT_NONE;
	*pilk = NULL;

	xm = ppt->fx;
	ym = ppt->fy;

	lay_vert = (compare_text(get_title_oritation_ptr(ptr), -1, ATTR_ORITATION_LEFT, -1, 0) == 0 || compare_text(get_title_oritation_ptr(ptr), -1, ATTR_ORITATION_RIGHT, -1, 0) == 0) ? 1 : 0;
	
	pw = get_title_width(ptr);
	ph = get_title_height(ptr);
	iw = get_title_item_width(ptr);
	ih = get_title_item_height(ptr);
	ic = get_title_icon_span(ptr);

	plk = get_title_next_item(ptr, LINK_FIRST);
	while (plk)
	{
		if (lay_vert)
		{
			xr.fx = 0;
			xr.fy = hw;
			xr.fw = pw;
			xr.fh = ih;
		}
		else
		{
			xr.fx = hw;
			xr.fy = 0;
			xr.fw = iw;
			xr.fh = ph;
		}

		if (ft_inside(xm, ym, xr.fx + 1, xr.fy + 1, xr.fx + xr.fw - 1, xr.fy + xr.fh - 1))
		{
			nHint = TITLE_HINT_ITEM;
			*pilk = plk;

			if (lay_vert)
			{
				if(plk == plk_focus && ft_inside(xm, ym, xr.fx + (xr.fw - ic) / 2 - TITLE_EDGE_DARK / 2, xr.fy, xr.fx + (xr.fw + ic) / 2 - TITLE_EDGE_DARK / 2, xr.fy + ic))
					nHint = TITLE_HINT_CLOSE;
			}
			else
			{
				if (plk == plk_focus && ft_inside(xm, ym, xr.fx, xr.fy + (xr.fh - ic) / 2 - TITLE_EDGE_DARK / 2, xr.fx + ic, xr.fy + (xr.fh + ic) / 2 - TITLE_EDGE_DARK / 2))
					nHint = TITLE_HINT_CLOSE;
			}

			break;
		}

		if (lay_vert)
		{
			hw += ih;
		}
		else
		{
			hw += iw;
		}

		plk = get_title_next_item(ptr, plk);
	}

	return nHint;
}

void draw_title(const drawing_interface* pif, link_t_ptr ptr, link_t_ptr plk_focus)
{
	link_t_ptr plk;
	bool_t lay_vert;
	float iw, ih, ic, hw = 0;
	xrect_t xr_image, xr_text, xr = { 0 };
	xpoint_t pt_arc = { 0 };
	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };
	xfont_t xf_focus, xf = { 0 };
	xface_t xa = { 0 };
	xcolor_t xc = { 0 };
	ximage_t xi = { 0 };
	const tchar_t *style, *orita, *icon;
	bool_t b_print;
	float px, py, pw, ph;

	tchar_t ta[11] = { 0 };
	xpoint_t pa[15] = { 0 };

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	px = pbox->fx;
	py = pbox->fy;
	pw = pbox->fw;
	ph = pbox->fh;

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;

	default_xpen(&xp);
	default_xbrush(&xb);
	default_xfont(&xf);
	default_xface(&xa);

	style = get_title_style_ptr(ptr);
	orita = get_title_oritation_ptr(ptr);

	parse_xface_from_style(&xa, style);

	parse_xfont_from_style(&xf, style);
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

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
	lighten_xpen(&xp, DEF_MIDD_DARKEN);

	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_msk, xi.color);
	}

	if (!b_print)
	{
		xmem_copy((void*)&xc, (void*)&pif->mode.clr_ico, sizeof(xcolor_t));
	}
	else
	{
		parse_xcolor(&xc, xf.color);
	}

	xmem_copy((void*)&xf_focus, (void*)&xf, sizeof(xfont_t));
	xscpy(xf_focus.decorate, GDI_ATTR_FONT_DECORATE_UNDERLINE);
	xscpy(xf_focus.weight, GDI_ATTR_FONT_WEIGHT_BOLD);

	lay_vert = (compare_text(orita, -1, ATTR_ORITATION_LEFT, -1, 0) == 0 || compare_text(orita, -1, ATTR_ORITATION_RIGHT, -1, 0) == 0) ? 1 : 0;
	
	if (lay_vert)
		xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);
	else
		xscpy(xa.text_wrap, _T(""));

	iw = get_title_item_width(ptr);
	ih = get_title_item_height(ptr);
	ic = get_title_icon_span(ptr);;

	plk = get_title_next_item(ptr, LINK_FIRST);
	while (plk)
	{
		if (lay_vert)
		{
			xr.fx = px;
			xr.fy = hw + py;
			xr.fw = pw;
			xr.fh = ih;
		}
		else
		{
			xr.fx = hw + px;
			xr.fy = py;
			xr.fw = iw;
			xr.fh = ph;
		}

		icon = get_title_item_icon_ptr(plk);

		if (plk == plk_focus)
		{
			if (compare_text(orita, -1, ATTR_ORITATION_LEFT, -1, 0) == 0)
			{
				ta[0] = _T('M');
				pa[0].fx = xr.fx;
				pa[0].fy = py - 0.5f;

				ta[1] = _T('L');
				pa[1].fx = xr.fx + TITLE_EDGE_LIGHT;
				pa[1].fy = py - 0.5f;

				ta[2] = _T('L');
				pa[2].fx = xr.fx + TITLE_EDGE_LIGHT;
				pa[2].fy = xr.fy;

				ta[3] = _T('L');
				pa[3].fx = xr.fx + xr.fw - TITLE_EDGE_DARK - TITLE_EDGE_ARC;
				pa[3].fy = xr.fy;

				ta[4] = _T('A');
				pa[4].fx = 1;
				pa[4].fy = 0;
				pa[5].fx = TITLE_EDGE_ARC;
				pa[5].fy = TITLE_EDGE_ARC;
				pa[6].fx = xr.fx + xr.fw - TITLE_EDGE_DARK;
				pa[6].fy = xr.fy + TITLE_EDGE_ARC;

				ta[5] = _T('L');
				pa[7].fx = xr.fx + xr.fw - TITLE_EDGE_DARK;
				pa[7].fy = xr.fy + xr.fh - TITLE_EDGE_ARC;

				ta[6] = _T('A');
				pa[8].fx = 1;
				pa[8].fy = 0;
				pa[9].fx = TITLE_EDGE_ARC;
				pa[9].fy = TITLE_EDGE_ARC;
				pa[10].fx = xr.fx + xr.fw - TITLE_EDGE_DARK - TITLE_EDGE_ARC;
				pa[10].fy = xr.fy + xr.fh;

				ta[7] = _T('L');
				pa[11].fx = xr.fx + TITLE_EDGE_LIGHT;
				pa[11].fy = xr.fy + xr.fh;

				ta[8] = _T('L');
				pa[12].fx = xr.fx + TITLE_EDGE_LIGHT;
				pa[12].fy = ph + 0.5f;

				ta[9] = _T('L');
				pa[13].fx = xr.fx;
				pa[13].fy = ph + 0.5f;

				(*pif->pf_draw_path)(pif->ctx, &xp, &xb, ta, pa, 14);

				xr_image.fx = xr.fx + (xr.fw - ic) / 2 - TITLE_EDGE_DARK / 2;
				xr_image.fy = xr.fy;
				xr_image.fw = ic;
				xr_image.fh = ic;

				ft_center_rect(&xr_image, DEF_SMALL_ICON, DEF_SMALL_ICON);

				if (get_title_item_locked(plk))
				{
					draw_gizmo(pif, &xc, &xr_image, icon);
				}
				else
				{
					draw_gizmo(pif, &xc, &xr_image, GDI_ATTR_GIZMO_CLOSE);
				}

				xr_text.fx = xr.fx;
				xr_text.fy = xr.fy + ic;
				xr_text.fw = xr.fw - TITLE_EDGE_DARK;
				xr_text.fh = xr.fh - ic;

				(*pif->pf_draw_text)(pif->ctx, &xf_focus, &xa, &xr_text, get_title_item_title_ptr(plk), -1);
			}
			else if (compare_text(orita, -1, ATTR_ORITATION_RIGHT, -1, 0) == 0)
			{
				ta[0] = _T('M');
				pa[0].fx = xr.fx + xr.fw;
				pa[0].fy = py - 0.5f;

				ta[1] = _T('L');
				pa[1].fx = xr.fx + xr.fw - TITLE_EDGE_LIGHT;
				pa[1].fy = py - 0.5f;

				ta[2] = _T('L');
				pa[2].fx = xr.fx + xr.fw - TITLE_EDGE_LIGHT;
				pa[2].fy = xr.fy;

				ta[3] = _T('L');
				pa[3].fx = xr.fx + TITLE_EDGE_DARK + TITLE_EDGE_ARC;
				pa[3].fy = xr.fy;

				ta[4] = _T('A');
				pa[4].fx = 0;
				pa[4].fy = 0;
				pa[5].fx = TITLE_EDGE_ARC;
				pa[5].fy = TITLE_EDGE_ARC;
				pa[6].fx = xr.fx + TITLE_EDGE_DARK;
				pa[6].fy = xr.fy + TITLE_EDGE_ARC;

				ta[5] = _T('L');
				pa[7].fx = xr.fx + TITLE_EDGE_DARK;
				pa[7].fy = xr.fy + xr.fh - TITLE_EDGE_ARC;

				ta[6] = _T('A');
				pa[8].fx = 0;
				pa[8].fy = 0;
				pa[9].fx = TITLE_EDGE_ARC;
				pa[9].fy = TITLE_EDGE_ARC;
				pa[10].fx = xr.fx + TITLE_EDGE_DARK + TITLE_EDGE_ARC;
				pa[10].fy = xr.fy + xr.fh;

				ta[7] = _T('L');
				pa[11].fx = xr.fx + xr.fw - TITLE_EDGE_LIGHT;
				pa[11].fy = xr.fy + xr.fh;

				ta[8] = _T('L');
				pa[12].fx = xr.fx + xr.fw - TITLE_EDGE_LIGHT;
				pa[12].fy = ph + 0.5f;

				ta[9] = _T('L');
				pa[13].fx = xr.fx + xr.fw;
				pa[13].fy = ph + 0.5f;

				(*pif->pf_draw_path)(pif->ctx, &xp, &xb, ta, pa, 14);

				xr_image.fx = xr.fx + (xr.fw - ic) / 2 + TITLE_EDGE_DARK / 2;
				xr_image.fy = xr.fy;
				xr_image.fw = ic;
				xr_image.fh = ic;

				ft_center_rect(&xr_image, DEF_SMALL_ICON, DEF_SMALL_ICON);

				if (get_title_item_locked(plk))
				{
					draw_gizmo(pif, &xc, &xr_image, icon);
				}
				else
				{
					draw_gizmo(pif, &xc, &xr_image, GDI_ATTR_GIZMO_CLOSE);
				}

				xr_text.fx = xr.fx + TITLE_EDGE_DARK;
				xr_text.fy = xr.fy + ic;
				xr_text.fw = xr.fw - TITLE_EDGE_DARK;
				xr_text.fh = xr.fh - ic;

				(*pif->pf_draw_text)(pif->ctx, &xf_focus, &xa, &xr_text, get_title_item_title_ptr(plk), -1);
			}
			else if (compare_text(orita, -1, ATTR_ORITATION_TOP, -1, 0) == 0)
			{
				ta[0] = _T('M');
				pa[0].fx = px - 0.5f;
				pa[0].fy = xr.fy;

				ta[1] = _T('L');
				pa[1].fx = px - 0.5f;
				pa[1].fy = xr.fy + TITLE_EDGE_LIGHT;

				ta[2] = _T('L');
				pa[2].fx = xr.fx;
				pa[2].fy = xr.fy + TITLE_EDGE_LIGHT;

				ta[3] = _T('L');
				pa[3].fx = xr.fx;
				pa[3].fy = xr.fy + xr.fh - TITLE_EDGE_DARK - TITLE_EDGE_ARC;

				ta[4] = _T('A');
				pa[4].fx = 0;
				pa[4].fy = 0;
				pa[5].fx = TITLE_EDGE_ARC;
				pa[5].fy = TITLE_EDGE_ARC;
				pa[6].fx = xr.fx + TITLE_EDGE_ARC;
				pa[6].fy = xr.fy + xr.fh - TITLE_EDGE_DARK;

				ta[5] = _T('L');
				pa[7].fx = xr.fx + xr.fw - TITLE_EDGE_ARC;
				pa[7].fy = xr.fy + xr.fh - TITLE_EDGE_DARK;

				ta[6] = _T('A');
				pa[8].fx = 0;
				pa[8].fy = 0;
				pa[9].fx = TITLE_EDGE_ARC;
				pa[9].fy = TITLE_EDGE_ARC;
				pa[10].fx = xr.fx + xr.fw;
				pa[10].fy = xr.fy + xr.fh - TITLE_EDGE_DARK - TITLE_EDGE_ARC;

				ta[7] = _T('L');
				pa[11].fx = xr.fx + xr.fw;
				pa[11].fy = xr.fy + TITLE_EDGE_LIGHT;

				ta[8] = _T('L');
				pa[12].fx = pw + 0.5f;
				pa[12].fy = xr.fy + TITLE_EDGE_LIGHT;

				ta[9] = _T('L');
				pa[13].fx = pw + 0.5f;
				pa[13].fy = xr.fy;

				(*pif->pf_draw_path)(pif->ctx, &xp, &xb, ta, pa, 14);

				xr_image.fx = xr.fx;
				xr_image.fy = xr.fy + (xr.fh - ic) / 2 - TITLE_EDGE_DARK / 2;
				xr_image.fw = ic;
				xr_image.fh = ic;

				ft_center_rect(&xr_image, DEF_SMALL_ICON, DEF_SMALL_ICON);

				if (get_title_item_locked(plk))
				{
					draw_gizmo(pif, &xc, &xr_image, icon);
				}
				else
				{
					draw_gizmo(pif, &xc, &xr_image, GDI_ATTR_GIZMO_CLOSE);
				}

				xr_text.fx = xr.fx + ic;
				xr_text.fy = xr.fy;
				xr_text.fw = xr.fw - ic;
				xr_text.fh = xr.fh - TITLE_EDGE_DARK;

				(*pif->pf_draw_text)(pif->ctx, &xf_focus, &xa, &xr_text, get_title_item_title_ptr(plk), -1);
			}
			else if (compare_text(orita, -1, ATTR_ORITATION_BOTTOM, -1, 0) == 0)
			{
				ta[0] = _T('M');
				pa[0].fx = px -0.5f;
				pa[0].fy = xr.fy + xr.fh;

				ta[1] = _T('L');
				pa[1].fx = px -0.5f;
				pa[1].fy = xr.fy + xr.fh - TITLE_EDGE_LIGHT;

				ta[2] = _T('L');
				pa[2].fx = xr.fx;
				pa[2].fy = xr.fy + xr.fh - TITLE_EDGE_LIGHT;

				ta[3] = _T('L');
				pa[3].fx = xr.fx;
				pa[3].fy = xr.fy + TITLE_EDGE_DARK + TITLE_EDGE_ARC;

				ta[4] = _T('A');
				pa[4].fx = 1;
				pa[4].fy = 0;
				pa[5].fx = TITLE_EDGE_ARC;
				pa[5].fy = TITLE_EDGE_ARC;
				pa[6].fx = xr.fx + TITLE_EDGE_ARC;
				pa[6].fy = xr.fy + TITLE_EDGE_DARK;

				ta[5] = _T('L');
				pa[7].fx = xr.fx + xr.fw - TITLE_EDGE_ARC;
				pa[7].fy = xr.fy + TITLE_EDGE_DARK;

				ta[6] = _T('A');
				pa[8].fx = 1;
				pa[8].fy = 0;
				pa[9].fx = TITLE_EDGE_ARC;;
				pa[9].fy = TITLE_EDGE_ARC;
				pa[10].fx = xr.fx + xr.fw;
				pa[10].fy = xr.fy + TITLE_EDGE_DARK + TITLE_EDGE_ARC;

				ta[7] = _T('L');
				pa[11].fx = xr.fx + xr.fw;
				pa[11].fy = xr.fy + xr.fh - TITLE_EDGE_LIGHT;

				ta[8] = _T('L');
				pa[12].fx = pw +0.5f;
				pa[12].fy = xr.fy + xr.fh - TITLE_EDGE_LIGHT;

				ta[9] = _T('L');
				pa[13].fx = pw +0.5f;
				pa[13].fy = xr.fy + xr.fh;

				ta[10] = _T('Z');

				(*pif->pf_draw_path)(pif->ctx, &xp, &xb, ta, pa, 14);

				xr_image.fx = xr.fx;
				xr_image.fy = xr.fy + (xr.fh - ic) / 2 + TITLE_EDGE_DARK / 2;
				xr_image.fw = ic;
				xr_image.fh = ic;

				ft_center_rect(&xr_image, DEF_SMALL_ICON, DEF_SMALL_ICON);

				if (get_title_item_locked(plk))
				{
					draw_gizmo(pif, &xc, &xr_image, icon);
				}
				else
				{
					draw_gizmo(pif, &xc, &xr_image, GDI_ATTR_GIZMO_CLOSE);
				}

				xr_text.fx = xr.fx + ic;
				xr_text.fy = xr.fy + TITLE_EDGE_DARK;
				xr_text.fw = xr.fw - ic;
				xr_text.fh = xr.fh - TITLE_EDGE_DARK;

				(*pif->pf_draw_text)(pif->ctx, &xf_focus, &xa, &xr_text, get_title_item_title_ptr(plk), -1);
			}
		}
		else
		{
			if (compare_text(orita, -1, ATTR_ORITATION_LEFT, -1, 0) == 0)
			{
				xr_image.fx = xr.fx + (xr.fw - ic) / 2 + TITLE_EDGE_DARK / 2;
				xr_image.fy = xr.fy;
				xr_image.fw = ic;
				xr_image.fh = ic;

				ft_center_rect(&xr_image, DEF_SMALL_ICON, DEF_SMALL_ICON);

				draw_gizmo(pif, &xc, &xr_image, icon);

				xr_text.fx = xr.fx + TITLE_EDGE_LIGHT;
				xr_text.fy = xr.fy + ic;
				xr_text.fw = xr.fw - TITLE_EDGE_LIGHT;
				xr_text.fh = xr.fh - ic;

				(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr_text, get_title_item_title_ptr(plk), -1);
			}
			else if (compare_text(orita, -1, ATTR_ORITATION_RIGHT, -1, 0) == 0)
			{
				xr_image.fx = xr.fx + (xr.fw - ic) / 2 - TITLE_EDGE_DARK / 2;
				xr_image.fy = xr.fy;
				xr_image.fw = ic;
				xr_image.fh = ic;

				ft_center_rect(&xr_image, DEF_SMALL_ICON, DEF_SMALL_ICON);

				draw_gizmo(pif, &xc, &xr_image, icon);

				xr_text.fx = xr.fx;
				xr_text.fy = xr.fy + ic;
				xr_text.fw = xr.fw - TITLE_EDGE_LIGHT;
				xr_text.fh = xr.fh - ic;

				(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr_text, get_title_item_title_ptr(plk), -1);
			}
			else if (compare_text(orita, -1, ATTR_ORITATION_TOP, -1, 0) == 0)
			{
				xr_image.fx = xr.fx;
				xr_image.fy = xr.fy + (xr.fh - ic) / 2 + TITLE_EDGE_DARK / 2;
				xr_image.fw = ic;
				xr_image.fh = ic;

				ft_center_rect(&xr_image, DEF_SMALL_ICON, DEF_SMALL_ICON);

				draw_gizmo(pif, &xc, &xr_image, icon);

				xr_text.fx = xr.fx + ic;
				xr_text.fy = xr.fy + TITLE_EDGE_LIGHT;
				xr_text.fw = xr.fw - ic;
				xr_text.fh = xr.fh - TITLE_EDGE_LIGHT;

				(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr_text, get_title_item_title_ptr(plk), -1);
			}
			else if (compare_text(orita, -1, ATTR_ORITATION_BOTTOM, -1, 0) == 0)
			{
				xr_image.fx = xr.fx;
				xr_image.fy = xr.fy + (xr.fh - ic) / 2 - TITLE_EDGE_DARK / 2;
				xr_image.fw = ic;
				xr_image.fh = ic;

				ft_center_rect(&xr_image, DEF_SMALL_ICON, DEF_SMALL_ICON);

				draw_gizmo(pif, &xc, &xr_image, icon);

				xr_text.fx = xr.fx + ic;
				xr_text.fy = xr.fy;
				xr_text.fw = xr.fw - ic;
				xr_text.fh = xr.fh - TITLE_EDGE_LIGHT;

				(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr_text, get_title_item_title_ptr(plk), -1);
			}
		}

		if (lay_vert)
		{
			hw += ih;
		}
		else
		{
			hw += iw;
		}

		plk = get_title_next_item(ptr, plk);
	}
}
