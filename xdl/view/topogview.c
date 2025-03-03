﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc topog document

	@module	topogview.c | implement file

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

#include "topogview.h"

#include "../xdlgdi.h"
#include "../xdldoc.h"


void calc_topog_spot_rect(link_t_ptr ptr, link_t_ptr ilk, xrect_t* pxr)
{
	pxr->fx = get_topog_spot_col(ilk) * get_topog_rx(ptr);
	pxr->fy = get_topog_spot_row(ilk) * get_topog_ry(ptr);
	pxr->fw = get_topog_rx(ptr);
	pxr->fh = get_topog_ry(ptr);
}

int calc_topog_hint(const xpoint_t* ppt, link_t_ptr ptr, link_t_ptr* pilk, int* prow, int* pcol)
{
	link_t_ptr ilk;
	int nHit;
	float xm, ym;
	xrect_t di;

	xm = ppt->fx;
	ym = ppt->fy;

	nHit = TOPOG_HINT_NONE;
	*pilk = NULL;

	*prow = (int)(ym / get_topog_ry(ptr));
	*pcol = (int)(xm / get_topog_rx(ptr));

	if (*prow < 0 || *prow >= get_topog_rows(ptr))
	{
		*prow = -1;
	}

	if (*pcol < 0 || *pcol >= get_topog_cols(ptr))
	{
		*pcol = -1;
	}

	ilk = get_topog_prev_spot(ptr, LINK_LAST);
	while (ilk)
	{
		calc_topog_spot_rect(ptr, ilk, &di);

		if (ft_inside(xm, ym, di.fx, di.fy, di.fx + di.fw, di.fy + di.fh))
		{
			nHit = TOPOG_HINT_SPOT;
			*pilk = ilk;

			break;
		}
		ilk = get_topog_prev_spot(ptr, ilk);
	}

	return nHit;
}

void draw_topog(const drawing_interface* pif, link_t_ptr ptr)
{
	link_t_ptr ilk;
	xrect_t xr;
	xsize_t xs;
	xbrush_t xb_dot, xb = { 0 };
	xpen_t xp = { 0 };
	xfont_t xf = { 0 };
	xface_t xa = { 0 };
	xcolor_t xc = { 0 };
	ximage_t xi = { 0 };

	bool_t b_design, b_print;
	const tchar_t *style;
	const tchar_t *type;

	matrix_t mt = NULL;
	int rows,cols, i, j;
	float rx, ry;
	int dark;

	const canvbox_t* pbox = (canvbox_t*)(&pif->rect);

	string_t vs = NULL;

	b_print = (pif->tag == _CANVAS_PRINTER)? 1 : 0;
	b_design = topog_is_design(ptr);

	default_xpen(&xp);
	default_xbrush(&xb);

	style = get_topog_style_ptr(ptr);
	
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

	xmem_copy((void*)&xb_dot, (void*)&xb, sizeof(xbrush_t));
	lighten_xbrush(&xb_dot, DEF_SOFT_LIGHTEN);

	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_msk, xi.color);
	}
	else
	{
		xscpy(xi.color, _T(""));
	}

	rows = get_topog_rows(ptr);
	cols = get_topog_cols(ptr);

	mt = matrix_alloc(rows, cols);

	matrix_parse(mt, get_topog_matrix_ptr(ptr), -1);

	rx = get_topog_rx(ptr);
	ry = get_topog_ry(ptr);

	for (i = 0; i < rows; i++)
	{
		for (j = 0; j < cols; j++)
		{
			xr.fx = pbox->fx + j * rx;
			xr.fy = pbox->fy + i * ry;
			xr.fw = rx;
			xr.fh = ry;

			ft_expand_rect(&xr, -0.5, -0.5);

			dark = (int)matrix_get_value(mt, i, j);
			if (dark)
			{
				xmem_copy((void*)&xb_dot, (void*)&xb, sizeof(xbrush_t));
				lighten_xbrush(&xb_dot, dark + DEF_SOFT_LIGHTEN);
				(*pif->pf_draw_rect)(pif->ctx, ((b_design)? &xp : NULL), &xb_dot, &xr);
			}
			else if (b_design)
			{
				(*pif->pf_draw_rect)(pif->ctx, &xp, NULL, &xr);
			}
		}
	}

	matrix_free(mt);

	vs = string_alloc();

	ilk = get_topog_next_spot(ptr, LINK_FIRST);
	while (ilk)
	{
		style = get_topog_spot_style_ptr(ilk);
		type = get_topog_spot_type_ptr(ilk);

		default_xfont(&xf);
		parse_xfont_from_style(&xf, style);

		default_xface(&xa);
		parse_xface_from_style(&xa, style);

		(*pif->pf_text_metric)(pif->ctx, &xf, &xs);

		calc_topog_spot_rect(ptr, ilk, &xr);
		xr.fw = xs.fw;
		xr.fh = xs.fh;
		ft_offset_rect(&xr, pbox->fx, pbox->fy);

		if (compare_text(type, -1, ATTR_SPOT_TYPE_COLORBAR, -1, 0) == 0)
		{
			(*pif->pf_color_out)(pif->ctx, &xr, 1, get_topog_spot_title_ptr(ilk), -1);
		}
		else if (compare_text(type, -1, ATTR_SPOT_TYPE_ICON, -1, 0) == 0)
		{
			parse_xcolor(&xc, xf.color);
			draw_gizmo(pif, &xc, &xr, get_topog_spot_title_ptr(ilk));
		}
		else if (compare_text(type, -1, ATTR_SPOT_TYPE_IMAGE, -1, 0) == 0)
		{
			parse_ximage_from_source(&xi, get_topog_spot_title_ptr(ilk));
			(*pif->pf_draw_image)(pif->ctx, &xi, &xr);
			xi.source = NULL;
		}
		else if (compare_text(type, -1, ATTR_SPOT_TYPE_TEXT, -1, 0) == 0)
		{
			string_cpy(vs, get_topog_spot_title_ptr(ilk), -1);
			draw_var_text(pif, &xf, &xa, &xr, vs);
		}

		ilk = get_topog_next_spot(ptr, ilk);
	}

	string_free(vs);
}

