﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc boxing document

	@module	boxingview.c | implement file

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
#include "boxview.h"

#include "../xdlgdi.h"


void calc_datebox_size(const measure_interface* pim, const xfont_t* pxf, xsize_t* pxs)
{
	xsize_t xs;
	float fx, fy;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	fx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	fy = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxs->fw = fx * CALENDAR_COL;
	pxs->fh = fy * (CALENDAR_ROW + 2);
}

void calc_datebox_day_rect(const measure_interface* pim, const xfont_t* pxf, const xdate_t* pdt, xrect_t* pxr)
{
	int i, j;
	xsize_t xs;
	float fx, fy;
	calendar_t ca = { 0 };

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	fx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	fy = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxr->fx = 0;
	pxr->fy = 0;
	pxr->fw = 0;
	pxr->fh = 0;

#ifdef XDK_SUPPORT_DATE
	fill_calendar(&ca, pdt);
#endif

	for (i = 0; i < CALENDAR_ROW; i++)
	{
		for (j = 0; j < CALENDAR_COL; j++)
		{
			pxr->fx = j * fx;
			pxr->fy = (i + 2) * fy;

			if (ca.calen_days[i][j] == pdt->day)
			{
				pxr->fw = fx;
				pxr->fh = fy;

				return;
			}
		}
	}
}

int	calc_datebox_hint(const measure_interface* pim, const xfont_t* pxf, const xpoint_t* ppt, const xdate_t* pdt, int* pday)
{
	xrect_t xr;
	int i, j;
	xsize_t xs;
	float fx, fy;
	calendar_t ca = { 0 };

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	fx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	fy = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	*pday = 0;

	xr.fx = 0;
	xr.fy = 0;
	xr.fw = fx;
	xr.fh = fy;
	if (ft_in_rect(ppt, &xr))
	{
		return DATEBOX_HINT_PREV;
	}

	xr.fx = fx * (CALENDAR_COL - 1);
	xr.fy = 0;
	xr.fw = fx;
	xr.fh = fy;
	if (ft_in_rect(ppt, &xr))
	{
		return DATEBOX_HINT_NEXT;
	}

	xr.fw = fx;
	xr.fh = fy;

#ifdef XDK_SUPPORT_DATE
	fill_calendar(&ca, pdt);
#endif

	for (i = 0; i < CALENDAR_ROW; i++)
	{
		for (j = 0; j < CALENDAR_COL; j++)
		{
			xr.fx = j * fx;
			xr.fy = (i + 2) * fy;

			if (ft_in_rect(ppt, &xr))
			{
				if (ca.calen_days[i][j])
				{
					*pday = ca.calen_days[i][j];

					return DATEBOX_HINT_DAYS;
				}
				else
				{
					return DATEBOX_HINT_NONE;
				}
			}
		}
	}

	return DATEBOX_HINT_NONE;
}

void draw_datebox(const drawing_interface* pif, const xfont_t* pxf, const xdate_t* pdt)
{
	xface_t xa;
	xpen_t xp;
	xfont_t xf;
	xcolor_t xc;
	xrect_t xr;
	tchar_t token[RES_LEN + 1];
	int i, j;
	bool_t b_print;

	xsize_t xs;
	float mx, my;
	calendar_t ca = { 0 };

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	(*pif->pf_text_metric)(pif->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xface(&xa);
	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);

	default_xpen(&xp);
	xscpy(xp.color, xf.color);

	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

	xr.fx = pbox->fx;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, _T("<"), -1);

	xr.fx = pbox->fx + mx;
	xr.fw = mx * (CALENDAR_COL - 2);
	xr.fy = pbox->fy;
	xr.fh = my;
	xsprintf(token, CB_FORMAT_YEARMONTH, pdt->year, pdt->mon);
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);

	xr.fx = pbox->fx + mx * (CALENDAR_COL -1);
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, _T(">"), -1);

#ifdef XDK_SUPPORT_DATE
	fill_calendar(&ca, pdt);
#endif

	for (i = 0; i < CALENDAR_COL; i++)
	{
		xr.fx = pbox->fx + i * mx;
		xr.fw = mx;
		xr.fy = pbox->fy + my;
		xr.fh = my;

		(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, ca.calen_week[i], -1);
	}

	for (i = 0; i < CALENDAR_ROW; i++)
	{
		for (j = 0; j < CALENDAR_COL; j++)
		{
			xr.fx = pbox->fx + j * mx;
			xr.fy = pbox->fy + (i + 2) * my;
			xr.fw = mx;
			xr.fh = my;

			if (ca.calen_days[i][j])
			{
				xsprintf(token, _T("%d"), ca.calen_days[i][j]);
				(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);
			}

			if (pdt->day && pdt->day == ca.calen_days[i][j])
			{
				ft_expand_rect(&xr, -1, -1);
				(*pif->pf_draw_rect)(pif->ctx, &xp, NULL, &xr);
			}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
void calc_timebox_size(const measure_interface* pim, const xfont_t* pxf, xsize_t* pxs)
{
	xsize_t xs;
	float fx, fy;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	fx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	fy = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxs->fw = (float)(fx * 4.5);
	pxs->fh = (float)(fy * 3);
}

int	calc_timebox_hint(const measure_interface* pim, const xfont_t* pxf, const xpoint_t* ppt)
{
	xrect_t xr;
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = mx;
	xr.fy = 0;
	xr.fw = mx / 2;
	xr.fh = my / 2;
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_YEAR_UP;
	}

	xr.fx = mx;
	xr.fy = my / 2;
	xr.fw = mx / 2;
	xr.fh = my / 2;
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_YEAR_DOWN;
	}

	xr.fx = (float)(mx * 2.5);
	xr.fy = 0;
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_MON_UP;
	}

	xr.fx = (float)(mx * 2.5);
	xr.fy = (float)(my / 2);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_MON_DOWN;
	}

	xr.fx = (float)(mx * 4);
	xr.fy = 0;
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_DAY_UP;
	}

	xr.fx = (float)(mx * 4);
	xr.fy = (float)(my / 2);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_DAY_DOWN;
	}

	xr.fx = mx;
	xr.fy = my;
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_HOUR_UP;
	}

	xr.fx = mx;
	xr.fy = (float)(my * 1.5);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_HOUR_DOWN;
	}

	xr.fx = mx;
	xr.fy = (float)(my * 2);
	xr.fw = (float)(mx / 2);
	xr.fh = my;
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_HOUR_ZERO;
	}

	xr.fx = (float)(mx * 2.5);
	xr.fy = my;
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_MIN_UP;
	}

	xr.fx = (float)(mx * 2.5);
	xr.fy = (float)(my * 1.5);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_MIN_DOWN;
	}

	xr.fx = (float)(mx * 2.5);
	xr.fy = (float)(my * 2);
	xr.fw = (float)(mx / 2);
	xr.fh = my;
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_MIN_ZERO;
	}

	xr.fx = (float)(mx * 4);
	xr.fy = my;
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_SEC_UP;
	}

	xr.fx = (float)(mx * 4);
	xr.fy = (float)(my * 1.5);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_SEC_DOWN;
	}

	xr.fx = (float)(mx * 4);
	xr.fy = (float)(my * 2);
	xr.fw = (float)(mx / 2);
	xr.fh = my;
	if (ft_in_rect(ppt, &xr))
	{
		return TIMEBOX_HINT_SEC_ZERO;
	}

	return TIMEBOX_HINT_NONE;
}

void draw_timebox(const drawing_interface* pif, const xfont_t* pxf, const xdate_t* ptt)
{
	xfont_t xf;
	xface_t xa;
	xpen_t xp;
	xcolor_t xc;
	xrect_t xr;
	bool_t b_print;

	tchar_t token[INT_LEN + 1];

	xsize_t xs;
	float mx, my;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	default_xface(&xa);
	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xpen(&xp);
	xscpy(xp.color, xf.color);

	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

	(*pif->pf_text_metric)(pif->ctx, &xf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = pbox->fx;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	xsprintf(token, _T("%02d"), ptt->year - 2000);
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);

	xr.fx = pbox->fx;
	xr.fy = pbox->fy + my;
	xr.fw = mx;
	xr.fh = my;
	xsprintf(token, _T("%02d"), ptt->hour);
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);

	xr.fx = pbox->fx;
	xr.fy = (float)(pbox->fy + my * 2);
	xr.fw = mx;
	xr.fh = my;
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, _T("时"), -1);

	xr.fx = (float)(pbox->fx + mx * 1.5);
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	xsprintf(token, _T("%02d"), ptt->mon);
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);

	xr.fx = (float)(pbox->fx + mx * 1.5);
	xr.fy = pbox->fy + my;
	xr.fw = mx;
	xr.fh = my;
	xsprintf(token, _T("%02d"), ptt->min);
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);

	xr.fx = (float)(pbox->fx + mx * 1.5);
	xr.fy = (float)(pbox->fy + my * 2);
	xr.fw = mx;
	xr.fh = my;
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, _T("分"), -1);

	xr.fx = (float)(pbox->fx + mx * 3);
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	xsprintf(token, _T("%02d"), ptt->day);
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);

	xr.fx = (float)(pbox->fx + mx * 3);
	xr.fy = (float)(pbox->fy + my);
	xr.fw = mx;
	xr.fh = my;
	xsprintf(token, _T("%02d"), ptt->sec);
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);

	xr.fx = (float)(pbox->fx + mx * 3);
	xr.fy = (float)(pbox->fy + my * 2);
	xr.fw = mx;
	xr.fh = my;
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, _T("秒"), -1);

	xr.fx = (float)(pbox->fx + mx);
	xr.fy = pbox->fy;
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_UP);

	xr.fx = (float)(pbox->fx + mx);
	xr.fy = (float)(pbox->fy + my / 2);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_DOWN);

	xr.fx = (float)(pbox->fx + mx);
	xr.fy = (float)(pbox->fy + my);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_UP);

	xr.fx = (float)(pbox->fx + mx);
	xr.fy = (float)(pbox->fy + my * 1.5);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_DOWN);

	xr.fx = (float)(pbox->fx + mx);
	xr.fy = (float)(pbox->fy + my * 2);
	xr.fw = (float)(mx / 2);
	xr.fh = my;
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	(*pif->pf_draw_rect)(pif->ctx, &xp, NULL, &xr);

	xr.fx = (float)(pbox->fx + mx * 2.5);
	xr.fy = pbox->fy;
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_UP);

	xr.fx = (float)(pbox->fx + mx * 2.5);
	xr.fy = (float)(pbox->fy + my / 2);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_DOWN);

	xr.fx = (float)(pbox->fx + mx * 2.5);
	xr.fy = (float)(pbox->fy + my);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_UP);

	xr.fx = (float)(pbox->fx + mx * 2.5);
	xr.fy = (float)(pbox->fy + my * 1.5);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_DOWN);

	xr.fx = (float)(pbox->fx + mx * 2.5);
	xr.fy = (float)(pbox->fy + my * 2);
	xr.fw = (float)(mx / 2);
	xr.fh = my;
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	(*pif->pf_draw_rect)(pif->ctx, &xp, NULL, &xr);

	xr.fx = (float)(pbox->fx + mx * 4);
	xr.fy = pbox->fy;
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_UP);

	xr.fx = (float)(pbox->fx + mx * 4);
	xr.fy = (float)(pbox->fy + my / 2);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_DOWN);

	xr.fx = (float)(pbox->fx + mx * 4);
	xr.fy = (float)(pbox->fy + my);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_UP);

	xr.fx = (float)(pbox->fx + mx * 4);
	xr.fy = (float)(pbox->fy + my * 1.5);
	xr.fw = (float)(mx / 2);
	xr.fh = (float)(my / 2);
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_DOWN);

	xr.fx = (float)(pbox->fx + mx * 4);
	xr.fy = (float)(pbox->fy + my * 2);
	xr.fw = (float)mx / 2;
	xr.fh = my;
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	(*pif->pf_draw_rect)(pif->ctx, &xp, NULL, &xr);
}
/////////////////////////////////////////////////////////////////////////////////////////////////////
void calc_listbox_size(const measure_interface* pim, const xfont_t* pxf, link_t_ptr ptr, xsize_t* pxs)
{
	link_t_ptr ent;

	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxs->fh = 0;
	pxs->fw = mx;
	ent = get_string_next_entity(ptr, LINK_FIRST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_next_entity(ptr, ent);
			continue;
		}

		(*pim->pf_measure_size)(pim->ctx, pxf, get_string_entity_val_ptr(ent), -1, &xs);

		if (pxs->fw < xs.fw)
			pxs->fw = xs.fw;

		pxs->fh += my;

		ent = get_string_next_entity(ptr, ent);
	}
}

int calc_listbox_hint(const measure_interface* pim, const xfont_t* pxf, const xpoint_t* ppt, link_t_ptr ptr, link_t_ptr* pilk)
{
	link_t_ptr ent;
	xrect_t xr;
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = 0;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	ent = get_string_next_entity(ptr, LINK_FIRST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_next_entity(ptr, ent);
			continue;
		}

		(*pim->pf_measure_size)(pim->ctx, pxf, get_string_entity_val_ptr(ent), -1, &xs);

		if (xr.fw < xs.fw)
			xr.fw = xs.fw;

		if (ft_in_rect(ppt, &xr))
		{
			if (pilk)
				*pilk = ent;

			return LISTBOX_HINT_ITEM;
		}

		xr.fy += my;
		ent = get_string_next_entity(ptr, ent);
	}

	return LISTBOX_HINT_NONE;
}

void calc_listbox_item_rect(const measure_interface* pim, const xfont_t* pxf, link_t_ptr ptr, link_t_ptr ilk, xrect_t* pxr)
{
	link_t_ptr ent;
	xrect_t xr;
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = 0;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	ent = get_string_next_entity(ptr, LINK_FIRST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_next_entity(ptr, ent);
			continue;
		}

		(*pim->pf_measure_size)(pim->ctx, pxf, get_string_entity_val_ptr(ent), -1, &xs);

		if (xr.fw < xs.fw)
			xr.fw = xs.fw;

		if (ent == ilk)
		{
			xmem_copy((void*)pxr, (void*)&xr, sizeof(xrect_t));
			return;
		}

		xr.fy += my;
		ent = get_string_next_entity(ptr, ent);
	}

	xmem_zero((void*)pxr, sizeof(xrect_t));
}

void draw_listbox(const drawing_interface* pif, const xfont_t* pxf, link_t_ptr ptr)
{
	link_t_ptr ent;
	xface_t xa;
	xfont_t xf;
	xrect_t xr;
	bool_t b_print;

	xsize_t xs;
	float mx, my;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	(*pif->pf_text_metric)(pif->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xface(&xa);
	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_NEAR);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);

	xr.fx = pbox->fx;
	xr.fy = pbox->fy;
	xr.fw = pbox->fw;
	xr.fh = my;

	ent = get_string_next_entity(ptr, LINK_FIRST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_next_entity(ptr, ent);
			continue;
		}

		(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, get_string_entity_val_ptr(ent), -1);

		xr.fy += my;
		ent = get_string_next_entity(ptr, ent);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
void calc_dropbox_size(const measure_interface* pim, const xfont_t* pxf, link_t_ptr ptr, xsize_t* pxs)
{
	link_t_ptr ent;
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxs->fh = 0;
	pxs->fw = 0;

	ent = get_string_next_entity(ptr, LINK_FIRST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_next_entity(ptr, ent);
			continue;
		}

		(*pim->pf_measure_size)(pim->ctx, pxf, get_string_entity_val_ptr(ent), -1, &xs);

		if (pxs->fw < xs.fw)
			pxs->fw = xs.fw;

		pxs->fh += my;

		ent = get_string_next_entity(ptr, ent);
	}

	pxs->fw += mx;
}

int calc_dropbox_hint(const measure_interface* pim, const xfont_t* pxf, const xpoint_t* ppt, link_t_ptr ptr, link_t_ptr* pilk)
{
	link_t_ptr ent;
	xrect_t xr;
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = 0;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	ent = get_string_next_entity(ptr, LINK_FIRST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_next_entity(ptr, ent);
			continue;
		}

		(*pim->pf_measure_size)(pim->ctx, pxf, get_string_entity_val_ptr(ent), -1, &xs);

		if (xr.fw < xs.fw)
			xr.fw = xs.fw;

		if (ft_in_rect(ppt, &xr))
		{
			if (pilk)
				*pilk = ent;

			return DROPBOX_HINT_ITEM;
		}

		xr.fy += my;
		ent = get_string_next_entity(ptr, ent);
	}

	return DROPBOX_HINT_NONE;
}

void calc_dropbox_item_rect(const measure_interface* pim, const xfont_t* pxf, link_t_ptr ptr, link_t_ptr ilk, xrect_t* pxr)
{
	link_t_ptr ent;
	xrect_t xr;
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = 0;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	ent = get_string_next_entity(ptr, LINK_FIRST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_next_entity(ptr, ent);
			continue;
		}

		(*pim->pf_measure_size)(pim->ctx, pxf, get_string_entity_val_ptr(ent), -1, &xs);

		if (xr.fw < xs.fw)
			xr.fw = xs.fw;

		if (ent == ilk)
		{
			xmem_copy((void*)pxr, (void*)&xr, sizeof(xrect_t));
			return;
		}

		xr.fy += my;
		ent = get_string_next_entity(ptr, ent);
	}

	xmem_zero((void*)pxr, sizeof(xrect_t));
}

void draw_dropbox(const drawing_interface* pif, const xfont_t* pxf, link_t_ptr ptr)
{
	link_t_ptr ent;
	xface_t xa;
	xfont_t xf;
	xrect_t xr;
	bool_t b_print;

	xsize_t xs;
	float mx, my;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	(*pif->pf_text_metric)(pif->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xface(&xa);
	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_NEAR);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);

	xr.fx = pbox->fx;
	xr.fy = pbox->fy;
	xr.fw = pbox->fw;
	xr.fh = my;

	ent = get_string_next_entity(ptr, LINK_FIRST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_next_entity(ptr, ent);
			continue;
		}

		(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, get_string_entity_val_ptr(ent), -1);

		xr.fy += my;
		ent = get_string_next_entity(ptr, ent);
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
void draw_pushbox(const drawing_interface* pif, const xfont_t* pxf, const tchar_t* text)
{
	xface_t xa;
	xfont_t xf;
	xpen_t xp;
	xcolor_t xc;
	xrect_t xr;
	bool_t b_print;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xface(&xa);
	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);

	default_xpen(&xp);
	xscpy(xp.color, xf.color);

	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

	xr.fx = pbox->fx;
	xr.fy = pbox->fy;
	xr.fw = pbox->fw;
	xr.fh = pbox->fh;

	xp.adorn.feed = 2;
	xp.adorn.size = 2;
	(*pif->pf_draw_rect)(pif->ctx, &xp, NULL, &xr);

	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, text, -1);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
void calc_radiobox_size(const measure_interface* pim, const xfont_t* pxf, xsize_t* pxs)
{
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxs->fw = mx * 2;
	pxs->fh = my;
}

int calc_radiobox_hint(const measure_interface* pim, const xfont_t* pxf, const xpoint_t* ppt)
{
	xrect_t xr;
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = 0;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return RADIOBOX_HINT_OFF;

	xr.fx = mx;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;
	
	if (ft_in_rect(ppt, &xr))
		return RADIOBOX_HINT_ON;

	return RADIOBOX_HINT_NONE;
}

void draw_radiobox(const drawing_interface* pif, const xfont_t* pxf, bool_t b_on)
{
	xface_t xa;
	xfont_t xf;
	xpen_t xp;
	xbrush_t xb, xb_on;
	xcolor_t xc;
	xrect_t xr;
	bool_t b_print;

	xsize_t xs;
	float mx, my;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xface(&xa);
	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);

	default_xbrush(&xb);
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_bkg, xb.color);
	}

	default_xpen(&xp);
	xscpy(xp.color, xf.color);

	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

	xmem_copy((void*)&xb_on, (void*)&xb, sizeof(xbrush_t));

	lighten_xbrush(&xb, DEF_SOFT_DARKEN);
	lighten_xbrush(&xb_on, DEF_HARD_DARKEN);

	(*pif->pf_text_metric)(pif->ctx, &xf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	if (b_on)
	{
		xr.fx = pbox->fx + mx / 2;
		xr.fy = pbox->fy;
		xr.fw = mx;
		xr.fh = my;
		(*pif->pf_draw_rect)(pif->ctx, NULL, &xb_on, &xr);

		xr.fx = pbox->fx;
		xr.fy = pbox->fy;
		xr.fw = mx;
		xr.fh = my;
		(*pif->pf_draw_ellipse)(pif->ctx, NULL, &xb_on, &xr);

		xr.fx = pbox->fx + mx;
		xr.fy = pbox->fy;
		xr.fw = mx;
		xr.fh = my;
		(*pif->pf_draw_ellipse)(pif->ctx, &xp, &xb, &xr);

		(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, _T("开"), -1);
	}
	else
	{
		xr.fx = pbox->fx + mx / 2;
		xr.fy = pbox->fy;
		xr.fw = mx;
		xr.fh = my;
		(*pif->pf_draw_rect)(pif->ctx, NULL, &xb, &xr);

		xr.fx = pbox->fx + mx;
		xr.fy = pbox->fy;
		xr.fw = mx;
		xr.fh = my;
		(*pif->pf_draw_ellipse)(pif->ctx, NULL, &xb, &xr);

		xr.fx = pbox->fx;
		xr.fy = pbox->fy;
		xr.fw = mx;
		xr.fh = my;
		(*pif->pf_draw_ellipse)(pif->ctx, &xp, &xb, &xr);

		(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, _T("关"), -1);
	}
}

/////////////////////////////////////////////////////////////////////////////////////////
void calc_checkbox_size(const measure_interface* pim, const xfont_t* pxf, xsize_t* pxs)
{
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxs->fw = mx;
	pxs->fh = my;
}

void draw_checkbox(const drawing_interface* pif, const xfont_t* pxf, bool_t b_on)
{
	xface_t xa;
	xfont_t xf;
	xpen_t xp;
	xbrush_t xb;
	xcolor_t xc;
	xrect_t xr;
	bool_t b_print;

	xsize_t xs;
	float mx, my;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xface(&xa);
	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);

	default_xbrush(&xb);
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_bkg, xb.color);
	}

	default_xpen(&xp);
	xscpy(xp.color, xf.color);

	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

	(*pif->pf_text_metric)(pif->ctx, &xf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = pbox->fx;
	xr.fy = pbox->fy;
	xr.fw = pbox->fw;
	xr.fh = pbox->fh;
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);

	(*pif->pf_draw_rect)(pif->ctx, &xp, NULL, &xr);

	if (b_on)
	{
		draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_CHECKED);
	}
}

//////////////////////////////////////////////////////////////////////////////////////////
void calc_slidebox_size(const measure_interface* pim, const xfont_t* pxf, xsize_t* pxs)
{
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxs->fw = mx * 10;
	pxs->fh = my;
}

int calc_slidebox_hint(const measure_interface* pim, const xfont_t* pxf, const xpoint_t* ppt)
{
	xsize_t xs;
	float mx, my;
	int pos;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pos = (int)(ppt->fx / (mx * 10) * 100);

	if (pos < 0)
		pos = 0;
	if (pos > 100)
		pos = 100;

	return pos;
}

void calc_slidebox_button_rect(const measure_interface* pim, const xfont_t* pxf, int pos, xrect_t* pxr)
{
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxr->fx = (float)((float)pos / 100.0 * mx * 10 - mx / 2);
	pxr->fy = 0;
	pxr->fw = mx;
	pxr->fh = my;
}

void draw_slidebox(const drawing_interface* pif, const xfont_t* pxf, int pos)
{
	xface_t xa;
	xfont_t xf;
	xpen_t xp;
	xbrush_t xb;
	xcolor_t xc;
	xrect_t xr;
	bool_t b_print;
	tchar_t token[INT_LEN + 1];

	xsize_t xs;
	float mx, my, cur;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	default_xface(&xa);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xpen(&xp);
	xscpy(xp.color, xf.color);

	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

	default_xbrush(&xb);
	xscpy(xb.color, xp.color);

	(*pif->pf_text_metric)(pif->ctx, &xf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	cur = (float)pos / 100 * (mx * 10);

	xr.fx = pbox->fx;
	xr.fy = pbox->fy + my / 2 - 2;
	xr.fw = mx * 10;
	xr.fh = 2;
	(*pif->pf_draw_rect)(pif->ctx, &xp, NULL, &xr);

	xscpy(xf.size, _T("8"));

	if (pos > 0 && pos < 100)
	{
		xr.fx = pbox->fx;
		xr.fy = pbox->fy + my / 2 - 2;
		xr.fw = cur;
		xr.fh = 2;
		(*pif->pf_draw_rect)(pif->ctx, &xp, &xb, &xr);

		xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
		ltoxs(pos, token, INT_LEN);
		xr.fx = pbox->fx + cur - mx / 2;
		xr.fy = pbox->fy;
		xr.fw = mx;
		xr.fh = my / 2;
		(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);
	}

	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_NEAR);
	ltoxs(0, token, INT_LEN);
	xr.fx = pbox->fx;
	xr.fy = pbox->fy + my / 2;
	xr.fw = mx;
	xr.fh = my / 2;
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);

	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_FAR);
	ltoxs(100, token, INT_LEN);
	xr.fx = pbox->fx + mx * 9;
	xr.fy = pbox->fy + my / 2;
	xr.fw = mx;
	xr.fh = my / 2;
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);

	xr.fx = pbox->fx + cur - mx / 4;
	xr.fy = pbox->fy + my / 2;
	xr.fw = mx / 2;
	xr.fh = my / 2;
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_UP);
}

//////////////////////////////////////////////////////////////////////////////////////
void calc_spinbox_size(const measure_interface* pim, const xfont_t* pxf, xsize_t* pxs)
{
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxs->fw = (float)(mx * 1.5);
	pxs->fh = my;
}

int calc_spinbox_hint(const measure_interface* pim, const xfont_t* pxf, const xpoint_t* ppt)
{
	xsize_t xs;
	float mx, my;
	xrect_t xr;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = mx;
	xr.fy = 0;
	xr.fw = mx / 2;
	xr.fh = my / 2;

	if (ft_in_rect(ppt, &xr))
		return SPINBOX_HINT_PLUS;

	xr.fx = mx;
	xr.fy = my / 2;
	xr.fw = mx / 2;
	xr.fh = my / 2;

	if (ft_in_rect(ppt, &xr))
		return SPINBOX_HINT_MINUS;

	return SPINBOX_HINT_NONE;
}

void draw_spinbox(const drawing_interface* pif, const xfont_t* pxf, int cur)
{
	xfont_t xf;
	xface_t xa;
	xpen_t xp;
	xcolor_t xc;
	xrect_t xr;
	bool_t b_print;

	xsize_t xs;
	float mx, my;
	tchar_t token[INT_LEN + 1];

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xface(&xa);
	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);

	default_xpen(&xp);
	xscpy(xp.color, xf.color);

	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

	(*pif->pf_text_metric)(pif->ctx, &xf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = pbox->fx;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	ltoxs(cur, token, INT_LEN);
	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);

	xr.fx = pbox->fx + mx;
	xr.fy = pbox->fy;
	xr.fw = mx / 2;
	xr.fh = my / 2;
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_UP);

	xr.fx = pbox->fx + mx;
	xr.fy = pbox->fy + my / 2;
	xr.fw = mx / 2;
	xr.fh = my / 2;
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_DOWN);
}

////////////////////////////////////////////////////////////////////////////////////////
void calc_navibox_size(const measure_interface* pim, const xfont_t* pxf, xsize_t* pxs)
{
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxs->fw = mx * 6;
	pxs->fh = my;
}

int calc_navibox_hint(const measure_interface* pim, const xfont_t* pxf, const xpoint_t* ppt)
{
	xsize_t xs = { 0 };
	xrect_t xr = { 0 };
	float mx = 0;
	float my = 0;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = 0;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return NAVIBOX_HINT_HOME;

	xr.fx = mx;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return NAVIBOX_HINT_PREV;

	xr.fx = mx * 2;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return NAVIBOX_HINT_NEXT;

	xr.fx = mx * 3;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return NAVIBOX_HINT_END;

	xr.fx = mx * 4;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return NAVIBOX_HINT_KEYBOARD;

	return NAVIBOX_HINT_NONE;
}

void draw_navibox(const drawing_interface* pif, const xfont_t* pxf, const NAVISTATE* pns)
{
	xfont_t xf;
	xpen_t xp;
	xcolor_t xc;
	xrect_t xr;
	bool_t b_print;

	xsize_t xs;
	float mx, my;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xpen(&xp);
	xscpy(xp.color, xf.color);

	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

	(*pif->pf_text_metric)(pif->ctx, &xf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = pbox->fx;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_FIRST);

	xr.fx = pbox->fx + mx;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_PREV);

	xr.fx = pbox->fx + mx * 2;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_NEXT);

	xr.fx = pbox->fx + mx * 3;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_LAST);

	xr.fx = pbox->fx + mx * 4;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
	if (pns && pns->keyboxed)
		draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_KEYBOXED);
	else
		draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_KEYBOX);
}

////////////////////////////////////////////////////////////////////////////////////////
void calc_vertbox_size(const measure_interface* pim, const xfont_t* pxf, xsize_t* pxs)
{
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxs->fw = mx;
	pxs->fh = my * 4;
}

int calc_vertbox_hint(const measure_interface* pim, const xfont_t* pxf, const xpoint_t* ppt)
{
	xsize_t xs = { 0 };
	xrect_t xr = { 0 };
	float mx = 0;
	float my = 0;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = 0;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return VERTBOX_HINT_PAGEUP;

	xr.fx = 0;
	xr.fy = my;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return VERTBOX_HINT_LINEUP;

	xr.fx = 0;
	xr.fy = 2 * my;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return VERTBOX_HINT_LINEDOWN;

	xr.fx = 0;
	xr.fy = 3 * my;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return VERTBOX_HINT_PAGEDOWN;

	return VERTBOX_HINT_NONE;
}

void draw_vertbox(const drawing_interface* pif, const xfont_t* pxf)
{
	xfont_t xf;
	xpen_t xp;
	xcolor_t xc;
	xrect_t xr;
	bool_t b_print;

	xsize_t xs;
	float mx, my;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xpen(&xp);
	xscpy(xp.color, xf.color);

	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

	(*pif->pf_text_metric)(pif->ctx, &xf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = pbox->fx;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_MIDD_ICON, DEF_MIDD_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_BEGIN);

	xr.fx = pbox->fx;
	xr.fy = pbox->fy + my;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_MIDD_ICON, DEF_MIDD_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_UP);

	xr.fx = pbox->fx;
	xr.fy = pbox->fy + my * 2;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_MIDD_ICON, DEF_MIDD_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_DOWN);

	xr.fx = pbox->fx;
	xr.fy = pbox->fy + my * 3;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_MIDD_ICON, DEF_MIDD_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_END);
}

////////////////////////////////////////////////////////////////////////////////////////
void calc_horzbox_size(const measure_interface* pim, const xfont_t* pxf, xsize_t* pxs)
{
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	pxs->fw = mx * 4;
	pxs->fh = my;
}

int calc_horzbox_hint(const measure_interface* pim, const xfont_t* pxf, const xpoint_t* ppt)
{
	xsize_t xs = { 0 };
	xrect_t xr = { 0 };
	float mx = 0;
	float my = 0;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = 0;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return HORZBOX_HINT_PAGELEFT;

	xr.fx = mx;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return HORZBOX_HINT_LINELEFT;

	xr.fx = 2 * mx;
	xr.fy = 0;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return HORZBOX_HINT_LINERIGHT;

	xr.fx = 0;
	xr.fy = 3 * my;
	xr.fw = mx;
	xr.fh = my;

	if (ft_in_rect(ppt, &xr))
		return HORZBOX_HINT_PAGERIGHT;

	return HORZBOX_HINT_NONE;
}

void draw_horzbox(const drawing_interface* pif, const xfont_t* pxf)
{
	xfont_t xf;
	xpen_t xp;
	xcolor_t xc;
	xrect_t xr;
	bool_t b_print;

	xsize_t xs;
	float mx, my;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xpen(&xp);
	xscpy(xp.color, xf.color);

	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

	(*pif->pf_text_metric)(pif->ctx, &xf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fx = pbox->fx;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_MIDD_ICON, DEF_MIDD_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_FIRST);

	xr.fx = pbox->fx + mx;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_MIDD_ICON, DEF_MIDD_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_PREV);

	xr.fx = pbox->fx + mx * 2;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_MIDD_ICON, DEF_MIDD_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_NEXT);

	xr.fx = pbox->fx+ mx * 3;
	xr.fy = pbox->fy;
	xr.fw = mx;
	xr.fh = my;
	ft_center_rect(&xr, DEF_MIDD_ICON, DEF_MIDD_ICON);
	draw_gizmo(pif, &xc, &xr, GDI_ATTR_GIZMO_LAST);
}

////////////////////////////////////////////////////////////////////////////////////////
void calc_iconbox_size(const measure_interface* pim, const xfont_t* pxf, const tchar_t* layer, const tchar_t* align, link_t_ptr str, xsize_t* pxs)
{
	xsize_t xs;
	float mx, my;
	int n;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	n = get_string_entity_count(str);

	if (compare_text(layer, -1, ATTR_LAYER_VERT, -1, 1) == 0)
	{
		pxs->fw = mx;
		pxs->fh = my * n;
	}
	else
	{
		pxs->fw = mx * n;
		pxs->fh = my;
	}
}

void calc_iconbox_item_rect(const measure_interface* pim, const xfont_t* pxf, const tchar_t* layer, const tchar_t* align, const xsize_t* pxs, link_t_ptr str, link_t_ptr ilk, xrect_t* pxr)
{
	xsize_t xs;
	float mx, my, span;
	xrect_t xr;
	link_t_ptr ent;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	if (compare_text(layer, -1, ATTR_LAYER_VERT, -1, 1) == 0)
	{
		if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
		{
			span = pxs->fh;
		}
		else
		{
			span = 0;
		}
	}
	else
	{
		if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
		{
			span = pxs->fw;
		}
		else
		{
			span = 0;
		}
	}

	xr.fw = mx;
	xr.fh = my;

	ent = get_string_next_entity(str, LINK_FIRST);
	while (ent)
	{
		if (compare_text(layer, -1, ATTR_LAYER_VERT, -1, 1) == 0)
		{
			if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
			{
				xr.fx = 0;
				xr.fy = span - my;

				span -= my;
			}
			else
			{
				xr.fx = 0;
				xr.fy = span;

				span += my;
			}
		}
		else
		{
			if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
			{
				xr.fx = span - mx;
				xr.fy = 0;

				span -= mx;
			}
			else
			{
				xr.fx = span;
				xr.fy = 0;

				span += mx;
			}
		}

		if (ent == ilk)
		{
			xmem_copy((void*)pxr, (void*)&xr, sizeof(xrect_t));
			return;
		}

		ent = get_string_next_entity(str, ent);
	}

	xmem_zero((void*)pxr, sizeof(xrect_t));
}

int calc_iconbox_hint(const measure_interface* pim, const xfont_t* pxf, const tchar_t* layer, const tchar_t* align, const xsize_t* pxs, const xpoint_t* ppt, link_t_ptr str, link_t_ptr* pilk)
{
	xsize_t xs;
	float mx, my, span;
	xrect_t xr;
	link_t_ptr ent;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	if (compare_text(layer, -1, ATTR_LAYER_VERT, -1, 1) == 0)
	{
		if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
		{
			span = pxs->fh;
		}
		else
		{
			span = 0;
		}
	}
	else
	{
		if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
		{
			span = pxs->fw;
		}
		else
		{
			span = 0;
		}
	}

	xr.fw = mx;
	xr.fh = my;

	ent = get_string_next_entity(str, LINK_FIRST);
	while (ent)
	{
		if (compare_text(layer, -1, ATTR_LAYER_VERT, -1, 1) == 0)
		{
			if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
			{
				xr.fx = 0;
				xr.fy = span - my;

				span -= my;
			}
			else
			{
				xr.fx = 0;
				xr.fy = span;

				span += my;
			}
		}
		else
		{
			if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
			{
				xr.fx = span - mx;
				xr.fy = 0;

				span -= mx;
			}
			else
			{
				xr.fx = span;
				xr.fy = 0;

				span += mx;
			}
		}

		if (ft_in_rect(ppt, &xr))
		{
			*pilk = ent;
			return ICONBOX_HINT_ITEM;
		}

		ent = get_string_next_entity(str, ent);
	}

	*pilk = NULL;
	return ICONBOX_HINT_NONE;
}

void draw_iconbox(const drawing_interface* pif, const xfont_t* pxf, const tchar_t* layer, const tchar_t* align, link_t_ptr str)
{
	xfont_t xf;
	xpen_t xp;
	xcolor_t xc;
	xrect_t xr;
	bool_t b_print;

	xsize_t xs;
	float mx, my, span;

	link_t_ptr ent;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xpen(&xp);
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_frg, xp.color);
	}
	parse_xcolor(&xc, xp.color);

	(*pif->pf_text_metric)(pif->ctx, &xf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	if (compare_text(layer, -1, ATTR_LAYER_VERT, -1, 1) == 0)
	{
		if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
		{
			span = pbox->fh;
		}
		else
		{
			span = 0;
		}
	}
	else
	{
		if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
		{
			span = pbox->fw;
		}
		else
		{
			span = 0;
		}
	}

	ent = get_string_next_entity(str, LINK_FIRST);
	while (ent)
	{
		if (compare_text(layer, -1, ATTR_LAYER_VERT, -1, 1) == 0)
		{
			if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
			{
				xr.fx = pbox->fx;
				xr.fy = pbox->fy + span - my;
				xr.fw = mx;
				xr.fh = my;

				span -= my;
			}
			else
			{
				xr.fx = pbox->fx;
				xr.fy = pbox->fy + span;
				xr.fw = mx;
				xr.fh = my;

				span += my;
			}
		}
		else
		{
			if (compare_text(align, -1, ATTR_ALIGNMENT_FAR, -1, 1) == 0)
			{
				xr.fx = pbox->fx + span - mx;
				xr.fy = pbox->fy;
				xr.fw = mx;
				xr.fh = my;

				span -= mx;
			}
			else
			{
				xr.fx = pbox->fx + span;
				xr.fy = pbox->fy;
				xr.fw = mx;
				xr.fh = my;

				span += mx;
			}
		}

		ft_center_rect(&xr, DEF_SMALL_ICON, DEF_SMALL_ICON);
		draw_gizmo(pif, &xc, &xr, get_string_entity_val_ptr(ent));
		
		ent = get_string_next_entity(str, ent);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////
#define WORDSBOX_MAX_ITEMS		9

int calc_wordsbox_pages(link_t_ptr ptr)
{
	int count;

	count = get_words_visible_item_count(ptr);

	if (!count)
		return 1;

	if (count % WORDSBOX_MAX_ITEMS)
		return count / WORDSBOX_MAX_ITEMS + 1;
	else
		return count / WORDSBOX_MAX_ITEMS;
}

void calc_wordsbox_item_scope(link_t_ptr ptr, int page, link_t_ptr* pfirst, link_t_ptr* plast)
{
	link_t_ptr ilk;
	int pages, index = 1;
	int count = 1;

	*pfirst = *plast = NULL;

	pages = calc_wordsbox_pages(ptr);
	if (page < 1 || page > pages)
		return;

	ilk = get_words_next_visible_item(ptr, LINK_FIRST);
	while (index < page)
	{
		if (count == WORDSBOX_MAX_ITEMS)
		{
			count = 1;
			index++;
		}

		count++;
		ilk = get_words_next_visible_item(ptr, ilk);
	}

	*pfirst = ilk;
	count = 1;

	while (ilk)
	{
		if (is_last_link(ilk) || count == WORDSBOX_MAX_ITEMS)
		{
			*plast = ilk;
			break;
		}

		count++;
		ilk = get_words_next_visible_item(ptr, ilk);
	}
}

int calc_wordsbox_item_page(link_t_ptr ptr, link_t_ptr plk)
{
	link_t_ptr ilk;
	int index = 1;
	int count = 0;

	ilk = get_words_next_visible_item(ptr, LINK_FIRST);
	while (ilk)
	{
		if (count == WORDSBOX_MAX_ITEMS)
		{
			count = 0;
			index++;
		}

		if (ilk == plk)
			return index;

		count++;
		ilk = get_words_next_visible_item(ptr, ilk);
	}

	return 0;
}

link_t_ptr calc_wordsbox_item(link_t_ptr ptr, int page, int index)
{
	link_t_ptr ilk, filk, lilk;

	calc_wordsbox_item_scope(ptr, page, &filk, &lilk);
	ilk = filk;
	while (ilk && index)
	{
		if (ilk == lilk)
			break;

		index--;
		ilk = get_words_next_visible_item(ptr, ilk);
	}

	return (index) ? NULL : ilk;
}

void calc_wordsbox_size(const measure_interface* pim, const xfont_t* pxf, link_t_ptr ptr, xsize_t* pxs)
{
	xsize_t xs;
	float mx, my, mw = 0;
	int n = 0;
	link_t_ptr ilk;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	ilk = get_words_next_visible_item(ptr, LINK_FIRST);
	while (ilk)
	{
		(*pim->pf_measure_size)(pim->ctx, pxf, get_words_item_text_ptr(ilk), -1, &xs);

		if (mw < xs.fw)
			mw = xs.fw;

		n++;
		ilk = get_words_next_visible_item(ptr, ilk);
	}

	if (n > WORDSBOX_MAX_ITEMS)
		n = WORDSBOX_MAX_ITEMS;

	pxs->fw = mw + 2 * mx;
	pxs->fh = n * my;
}

void calc_wordsbox_item_rect(const measure_interface* pim, const xfont_t* pxf, link_t_ptr ptr, int page, link_t_ptr plk, xrect_t* pxr)
{
	link_t_ptr ilk, filk, lilk;
	xrect_t xr;
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fy = 0;
	xr.fh = my;

	calc_wordsbox_item_scope(ptr, page, &filk, &lilk);

	ilk = filk;
	while (ilk)
	{
		(*pim->pf_measure_size)(pim->ctx, pxf, get_words_item_text_ptr(ilk), -1, &xs);
		xr.fx = 0;
		xr.fw = (mx > xs.fw) ? (mx * 2) : (xs.fw + mx);

		if (ilk == plk)
		{
			xmem_copy((void*)pxr, (void*)&xr, sizeof(xrect_t));
			return;
		}

		if (ilk == lilk)
			break;

		xr.fy += my;
		ilk = get_words_next_visible_item(ptr, ilk);
	}

	xmem_zero((void*)pxr, sizeof(xrect_t));
}

int calc_wordsbox_hint(const measure_interface* pim, const xfont_t* pxf, const xpoint_t* ppt, link_t_ptr ptr, int page, link_t_ptr* pilk)
{
	link_t_ptr ilk, filk, lilk;
	xrect_t xr;
	xsize_t xs;
	float mx, my;

	(*pim->pf_measure_font)(pim->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xr.fy = 0;
	xr.fh = my;

	calc_wordsbox_item_scope(ptr, page, &filk, &lilk);

	ilk = filk;
	while (ilk)
	{
		(*pim->pf_measure_size)(pim->ctx, pxf, get_words_item_text_ptr(ilk), -1, &xs);
		xr.fx = 0;
		xr.fw = (mx > xs.fw) ? (mx * 2) : (xs.fw + mx);

		if (ft_in_rect(ppt, &xr))
		{
			*pilk = ilk;
			return WORDSBOX_HINT_ITEM;
		}

		if (ilk == lilk)
			break;

		xr.fy += my;
		ilk = get_words_next_visible_item(ptr, ilk);
	}

	*pilk = NULL;
	return WORDSBOX_HINT_NONE;
}

void draw_wordsbox(const drawing_interface* pif, const xfont_t* pxf, link_t_ptr ptr, int page)
{
	xface_t xa;
	xfont_t xf;
	xrect_t xr;
	bool_t b_print;

	tchar_t token[INT_LEN + 1];
	link_t_ptr ilk, filk, lilk;
	int index;

	xsize_t xs;
	float mx, my;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	(*pif->pf_text_metric)(pif->ctx, pxf, &xs);

	mx = (xs.fw > DEF_TOUCH_SPAN) ? xs.fw : DEF_TOUCH_SPAN;
	my = (xs.fh > DEF_TOUCH_SPAN) ? xs.fh : DEF_TOUCH_SPAN;

	xmem_copy((void*)&xf, (void*)pxf, sizeof(xfont_t));

	b_print = (pif->tag == _CANVAS_PRINTER) ? 1 : 0;
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	default_xface(&xa);
	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_NEAR);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);

	xr.fy = pbox->fy;
	xr.fh = my;

	calc_wordsbox_item_scope(ptr, page, &filk, &lilk);

	index = 0;
	ilk = filk;
	while (ilk)
	{
		xr.fx = pbox->fx;
		xr.fw = mx;
		xsprintf(token, _T("%d. "), ++index);

		(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, token, -1);

		xr.fx = pbox->fx + mx;
		xr.fw = pbox->fw - mx;

		(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, get_words_item_text_ptr(ilk), -1);

		if (ilk == lilk)
			break;

		xr.fy += my;
		ilk = get_words_next_visible_item(ptr, ilk);
	}

}
