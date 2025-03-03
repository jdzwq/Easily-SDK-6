﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc property view

	@module	properview.c | implement file

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
#include "properview.h"

#include "../xdlgdi.h"
#include "../xdldoc.h"



float calc_proper_height(link_t_ptr ptr)
{
	link_t_ptr slk, elk;
	float th,total = 0;

	th = get_proper_item_height(ptr);

	slk = get_next_section(ptr, LINK_FIRST);
	while (slk)
	{
		total += th;

		if (!get_section_collapsed(slk))
		{
			elk = get_next_entity(slk, LINK_FIRST);
			while (elk)
			{
				total += th;
				elk = get_next_entity(slk, elk);
			}
		}

		slk = get_next_section(ptr, slk);
	}

	return total;
}

float calc_proper_width(link_t_ptr ptr)
{
	float iw;

	iw = get_proper_item_span(ptr);

	return iw * 2;
}

void calc_proper_section_rect(link_t_ptr ptr, link_t_ptr sec, xrect_t* pxr)
{
	link_t_ptr slk, elk;
	float pw, iw, th, total = 0;

	pw = get_proper_width(ptr);
	iw = get_proper_item_span(ptr);

	if (pw < 2 * iw)
	{
		pw = iw * 2;
	}

	xmem_zero((void*)pxr, sizeof(xrect_t));

	pw = get_proper_width(ptr);
	th = get_proper_item_height(ptr);

	slk = get_next_section(ptr, LINK_FIRST);
	while (slk && slk != sec)
	{
		total += th;

		if (!get_section_collapsed(slk))
		{
			elk = get_next_entity(slk, LINK_FIRST);
			while (elk)
			{
				total += th;

				elk = get_next_entity(slk, elk);
			}
		}

		slk = get_next_section(ptr, slk);
	}

	pxr->fx =0;
	pxr->fw = pw;
	pxr->fy = total;
	pxr->fh = th;
}

void calc_proper_entity_rect(link_t_ptr ptr, link_t_ptr ent, xrect_t* pxr)
{
	link_t_ptr slk, elk = NULL;
	float pw, iw, th, total = 0;

	xmem_zero((void*)pxr, sizeof(xrect_t));

	pw = get_proper_width(ptr);
	th = get_proper_item_height(ptr);
	iw = get_proper_item_span(ptr);
	if (pw < 2 * iw)
	{
		pw = iw * 2;
	}

	slk = get_next_section(ptr, LINK_FIRST);
	while (slk)
	{
		total += th;
		if (!get_section_collapsed(slk))
		{
			elk = get_next_entity(slk, LINK_FIRST);
			while (elk && elk != ent)
			{
				total += th;
				elk = get_next_entity(slk, elk);
			}
			if (elk)
				break;
		}
		slk = get_next_section(ptr, slk);
	}

	if (elk == ent)
	{
		pxr->fx = 0;
		pxr->fw = pw;
		pxr->fy = total;
		pxr->fh = th;
	}
}

void calc_proper_entity_text_rect(link_t_ptr ptr, link_t_ptr ent, xrect_t* pxr)
{
	float ew;

	ew = get_proper_item_span(ptr);
	calc_proper_entity_rect(ptr,ent, pxr);
	pxr->fx += ew;
	pxr->fw -= ew;
}

int calc_proper_hint(const xpoint_t* ppt, link_t_ptr ptr, link_t_ptr* psec, link_t_ptr* pent)
{
	int hint, b_find = 0;
	float x1, y1, x2, y2, xp, yp;
	float pw, th, ew;
	link_t_ptr slk, elk;

	xp = ppt->fx;
	yp = ppt->fy;

	*psec = NULL;
	*pent = NULL;
	hint = PROPER_HINT_NONE;

	pw = get_proper_width(ptr);
	th = get_proper_item_height(ptr);
	ew = get_proper_item_span(ptr);
	if (pw < 2 * ew)
	{
		pw = ew * 2;
	}

	x1 = 0;
	x2 = pw;
	y2 = 0;

	slk = get_next_section(ptr, LINK_FIRST);
	while (slk)
	{
		y1 = y2;
		y2 = y1 + th;
		if (ft_inside(xp, yp, x1, y1, x2, y2))
		{
			*psec = slk;
			hint = PROPER_HINT_SECTION;
			break;
		}

		y1 = y2;
		if (!get_section_collapsed(slk))
		{
			b_find = 0;
			elk = get_next_entity(slk, LINK_FIRST);
			while (elk)
			{
				y2 = y1 + th;
				if (ft_inside(xp, yp, x1, y1, x2, y2))
				{
					*pent = elk;
					if (xp >= x1 + ew - 5 && xp <= x1 + ew + 5)
						hint = PROPER_HINT_VERT_SPLIT;
					else
						hint = PROPER_HINT_ENTITY;

					b_find = 1;
					break;
				}
				y1 = y2;
				elk = get_next_entity(slk, elk);
			}
		}

		if (b_find)
			break;

		slk = get_next_section(ptr, slk);
	}

	return hint;
}

void draw_proper(const drawing_interface* pif, link_t_ptr ptr)
{
	link_t_ptr sec, ent;
	xrect_t xr, xr_draw;
	xpen_t xp = { 0 };
	xbrush_t xb_bar, xb = { 0 };
	xfont_t xf = { 0 };
	xface_t xa = { 0 };
	ximage_t xi = { 0 };
	xcolor_t xc = { 0 };
	float ic, iw, ih;
	const tchar_t *style, *shape;
	bool_t b_print;
	float px, py, pw, ph;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	XDK_ASSERT(pif);

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;

	ih = get_proper_item_height(ptr);
	iw = get_proper_item_span(ptr);
	ic = get_proper_icon_span(ptr);

	px = pbox->fx;
	py = pbox->fy;
	pw = pbox->fw;
	ph = pbox->fh;

	default_xpen(&xp);
	default_xbrush(&xb);
	default_xfont(&xf);
	default_xface(&xa);

	style = get_proper_style_ptr(ptr);

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

	xmem_copy((void*)&xb_bar, (void*)&xb, sizeof(xbrush_t));
	lighten_xbrush(&xb_bar, DEF_SOFT_DARKEN);
	xscpy(xb_bar.gradient, GDI_ATTR_GRADIENT_HORZ);

	shape = get_proper_shape_ptr(ptr);

	xr.fx = px;
	xr.fy = py;
	xr.fw = pw;
	xr.fh = 0;

	sec = get_next_section(ptr, LINK_FIRST);
	while (sec)
	{
		xr_draw.fx = xr.fx;
		xr_draw.fy = xr.fy;
		xr_draw.fw = xr.fw;
		xr_draw.fh = ih;

		if (is_null(shape))
		{
			(*pif->pf_draw_rect)(pif->ctx, NULL, &xb_bar, &xr_draw);
		}
		else
		{
			(*pif->pf_draw_rect)(pif->ctx, &xp, &xb_bar, &xr_draw);
		}

		xr_draw.fx = xr.fx;
		xr_draw.fw = ic;
		xr_draw.fy = xr.fy;
		xr_draw.fh = ih;

		ft_center_rect(&xr_draw, DEF_SMALL_ICON, DEF_SMALL_ICON);

		draw_gizmo(pif, &xc, &xr_draw, get_section_icon_ptr(sec));

		xr_draw.fx = xr.fx + xr.fw - ic;
		xr_draw.fw = ic;
		xr_draw.fy = xr.fy;
		xr_draw.fh = ih;
		ft_center_rect(&xr_draw, DEF_SMALL_ICON, DEF_SMALL_ICON);

		if (!get_section_collapsed(sec))
		{
			draw_gizmo(pif, &xc, &xr_draw, GDI_ATTR_GIZMO_EXPAND);
		}
		else
		{
			draw_gizmo(pif, &xc, &xr_draw, GDI_ATTR_GIZMO_COLLAPSE);
		}

		xr_draw.fx = xr.fx + ic;
		xr_draw.fw = xr.fw - ic;
		xr_draw.fy = xr.fy;
		xr_draw.fh = ih;

		(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr_draw, get_section_name_ptr(sec), -1);

		xr.fy += ih;

		if (get_section_collapsed(sec))
		{
			sec = get_next_section(ptr, sec);
			continue;
		}

		ent = get_next_entity(sec, LINK_FIRST);
		while (ent)
		{
			//key shape
			xr_draw.fx = xr.fx;
			xr_draw.fw = iw;
			xr_draw.fy = xr.fy;
			xr_draw.fh = ih;

			if (!is_null(shape))
			{
				draw_shape(pif, &xp, NULL, &xr_draw, shape);
			}

			//val shape
			xr_draw.fx = xr.fx + iw;
			xr_draw.fw = pw - iw;
			xr_draw.fy = xr.fy;
			xr_draw.fh = ih;

			if (!is_null(shape))
			{
				draw_shape(pif, &xp, NULL, &xr_draw, shape);
			}

			//key image
			xr_draw.fx = xr.fx;
			xr_draw.fw = ic;
			xr_draw.fy = xr.fy;
			xr_draw.fh = ih;

			ft_center_rect(&xr_draw, DEF_SMALL_ICON, DEF_SMALL_ICON);

			draw_gizmo(pif, &xc, &xr_draw, get_entity_icon_ptr(ent));

			//key text
			xr_draw.fx = xr.fx + ic;
			xr_draw.fw = iw - ic;
			xr_draw.fy = xr.fy;
			xr_draw.fh = ih;

			(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr_draw, get_entity_name_ptr(ent), -1);

			//val text
			xr_draw.fx = xr.fx + iw;
			xr_draw.fw = pw - iw;
			xr_draw.fy = xr.fy;
			xr_draw.fh = ih;

			(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr_draw, get_entity_options_text_ptr(ent), -1);

			xr.fy += ih;
			ent = get_next_entity(sec, ent);
		}

		sec = get_next_section(ptr, sec);
	}
}
