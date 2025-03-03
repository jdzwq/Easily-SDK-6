﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc tree view

	@module	treeview.c | implement file

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
#include "treeview.h"

#include "../xdlgdi.h"
#include "../xdldoc.h"



float _calc_tree_child_height(link_t_ptr ptr, link_t_ptr plk)
{
	link_t_ptr ilk;
	link_t_ptr st = NULL;
	float ih,th = 0;

	th = get_tree_title_height(ptr);
	ih = get_tree_item_height(ptr);

	ilk = get_tree_first_child_item(plk);
	while (ilk)
	{
		th += ih;

		if (!get_tree_item_collapsed(ilk) && get_tree_first_child_item(ilk))
		{
			if (!st)
				st = create_stack_table();

			push_stack_node(st, (void*)ilk);

			ilk = get_tree_first_child_item(ilk);
			continue;

		}

		while (ilk)
		{
			ilk = get_tree_next_sibling_item(ilk);
			if (ilk)
				break;
			ilk = (st) ? (link_t_ptr)pop_stack_node(st) : NULL;
		}
	}

	if (st)
		destroy_stack_table(st);

	return th;
}

float calc_tree_height(link_t_ptr ptr)
{
	return _calc_tree_child_height(ptr, ptr);
}

float calc_tree_width(const measure_interface* pif, link_t_ptr ptr)
{
	link_t_ptr ilk;
	link_t_ptr st = NULL;
	float ic,iw,mw = 0;
	const tchar_t* token;
	xfont_t xf;
	xsize_t xs;

	ic = get_tree_icon_span(ptr);
	iw = ic;

	default_xfont(&xf);
	parse_xfont_from_style(&xf, get_tree_style_ptr(ptr));

	ilk = get_tree_first_child_item(ptr);
	while (ilk)
	{
		token = get_tree_item_title_ptr(ilk);

		(*pif->pf_measure_size)(pif->ctx, &xf, token, -1, &xs);

		if (get_tree_item_showcheck(ilk))
			xs.fw += ic;
		
		if (mw < iw + xs.fw)
			mw = iw + xs.fw;

		if (!get_tree_item_collapsed(ilk) && get_tree_first_child_item(ilk))
		{
			if (!st)
				st = create_stack_table();

			push_stack_node(st, (void*)ilk);

			iw += ic / 2;
			ilk = get_tree_first_child_item(ilk);
			continue;

		}

		while (ilk)
		{
			ilk = get_tree_next_sibling_item(ilk);
			if (ilk)
				break;
			ilk = (st) ? (link_t_ptr)pop_stack_node(st) : NULL;
			iw -= ic / 2;
		}
	}

	if (st)
		destroy_stack_table(st);

	return mw;
}

bool_t calc_tree_item_rect(link_t_ptr ptr, link_t_ptr cur, xrect_t* pxr)
{
	link_t_ptr ilk;
	float fw, fh, th, ic, ih;
	link_t_ptr st = NULL;
	bool_t b_find = 0;

	fw = get_tree_width(ptr);
	fh = get_tree_height(ptr);
	th = get_tree_title_height(ptr);
	ih = get_tree_item_height(ptr);
	ic = get_tree_icon_span(ptr);

	pxr->fx = ic;
	pxr->fw = fw - ic;
	pxr->fy = th;
	pxr->fh = 0;

	ilk = get_tree_first_child_item(ptr);
	while (ilk)
	{
		pxr->fh = ih;

		if (ilk == cur)
		{
			b_find = 1;
			break;
		}

		pxr->fy += pxr->fh;

		if (!get_tree_item_collapsed(ilk) && get_tree_first_child_item(ilk))
		{
			pxr->fx += ic / 2;
			pxr->fw -= ic / 2;

			if (!st)
				st = create_stack_table();

			push_stack_node(st, (void*)ilk);

			ilk = get_tree_first_child_item(ilk);
			continue;

		}

		while (ilk)
		{
			ilk = get_tree_next_sibling_item(ilk);
			if (ilk)
				break;
			ilk = (st) ? (link_t_ptr)pop_stack_node(st) : NULL;
			pxr->fx -= ic / 2;
			pxr->fw += ic / 2;
		}
	}

	if (st)
		destroy_stack_table(st);

	if (!b_find)
	{
		xmem_zero((void*)pxr, sizeof(xrect_t));
	}

	return b_find;
}

bool_t calc_tree_item_text_rect(link_t_ptr ptr, link_t_ptr cur, xrect_t* pxr)
{
	float ic;

	if (!calc_tree_item_rect(ptr, cur, pxr))
		return 0;

	if (get_tree_item_showcheck(cur))
	{
		ic = get_tree_icon_span(ptr);
		pxr->fx += ic;
		pxr->fw -= ic;
	}

	return 1;
}

bool_t calc_tree_item_entity_rect(link_t_ptr ptr, link_t_ptr cur, xrect_t* pxr)
{
	if (!calc_tree_item_rect(ptr, cur, pxr))
		return 0;

	pxr->fx = 0;
	pxr->fw = get_tree_width(ptr);

	return 1;
}

bool_t calc_tree_item_expand_rect(link_t_ptr ptr, link_t_ptr cur, xrect_t* pxr)
{
	float ih;

	if (!calc_tree_item_rect(ptr, cur, pxr))
		return 0;

	ih = _calc_tree_child_height(ptr, cur);

	pxr->fh += ih;
	pxr->fx = 0;
	pxr->fw = get_tree_width(ptr);

	return 1;
}

int calc_tree_hint(const xpoint_t* ppt, link_t_ptr ptr, link_t_ptr* pilk)
{
	link_t_ptr ilk;
	link_t_ptr st = NULL;
	float x, y, ic, ih, th;
	float total_h, total_i;
	bool_t b_showcheck;
	int hint;

	*pilk = NULL;
	hint = TREE_HINT_NONE;

	x = ppt->fx;
	y = ppt->fy;

	th = get_tree_title_height(ptr);
	ih = get_tree_item_height(ptr);
	ic = get_tree_icon_span(ptr);

	total_h = th;
	total_i = 0;

	if (y < total_h)
	{
		*pilk = NULL;
		hint = TREE_HINT_TITLE;
		return hint;
	}

	ilk = get_tree_first_child_item(ptr);
	while (ilk)
	{
		b_showcheck = get_tree_item_showcheck(ilk);

		if (y < total_h + ih)
		{
			*pilk = ilk;

			if (x < total_i)
			{
				hint = TREE_HINT_ITEM;
			}
			else if (x < total_i + ic)
			{
				hint = TREE_HINT_EXPAND;
			}
			else if (x < total_i + 2 * ic)
			{
				if (b_showcheck)
					hint = TREE_HINT_CHECK;
				else
					hint = TREE_HINT_ITEM;
			}
			else
			{
				hint = TREE_HINT_ITEM;
			}

			break;
		}

		total_h += ih;

		if (!get_tree_item_collapsed(ilk))
		{
			if (!st)
				st = create_stack_table();

			push_stack_node(st, (void*)ilk);

			ilk = get_tree_first_child_item(ilk);
			total_i += ic / 2;
		}
		else
		{
			ilk = get_tree_next_sibling_item(ilk);
		}

		while (!ilk)
		{
			ilk = (st) ? (link_t_ptr)pop_stack_node(st) : NULL;
			if (ilk)
			{
				ilk = get_tree_next_sibling_item(ilk);

			}
			else
			{
				break;
			}

			total_i -= ic / 2;
		}
	}

	if (st)
		destroy_stack_table(st);

	return hint;
}

void draw_tree(const drawing_interface* pif, link_t_ptr ptr)
{
	link_t_ptr ilk;
	link_t_ptr st = NULL;
	float ic, ih, th, total_indent, total_height;
	bool_t b_checkbox;
	xrect_t xr_check, xr_text, xr_image;
	xbrush_t xb_bar,xb = { 0 };
	xpen_t xp = { 0 };
	xfont_t xf = { 0 };
	xface_t xa = { 0 };
	ximage_t xi = { 0 };
	xcolor_t xc, xc_check = { 0 };
	const tchar_t *style, *icon;
	bool_t b_print;
	float px, py, pw, ph;

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

	style = get_tree_style_ptr(ptr);

	parse_xface_from_style(&xa, style);

	parse_xfont_from_style(&xf, style);
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_txt, xf.color);
	}

	/*parse_xpen_from_style(&xp, style);
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_frg, xp.color);
	}*/

	parse_xbrush_from_style(&xb, style);
	if (!b_print)
	{
		format_xcolor(&pif->mode.clr_bkg, xb.color);
	}

	xscpy(xp.color, xb.color);
	parse_xcolor(&xc, xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);

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

	parse_xcolor(&xc_check, xp.color);

	th = get_tree_title_height(ptr);
	ih = get_tree_item_height(ptr);
	ic = get_tree_icon_span(ptr);;

	total_indent = px;
	total_height = py;

	xr_text.fx = total_indent;
	xr_text.fw = pw;
	xr_text.fy = total_height;
	xr_text.fh = th;

	xmem_copy((void*)&xb_bar, (void*)&xb, sizeof(xbrush_t));

	lighten_xbrush(&xb_bar, DEF_MIDD_DARKEN);
	xscpy(xb_bar.linear, xb.color);
	xscpy(xb_bar.style, GDI_ATTR_FILL_STYLE_GRADIENT);
	xscpy(xb_bar.gradient, GDI_ATTR_GRADIENT_HORZ);

	(*pif->pf_draw_rect)(pif->ctx, NULL, &xb_bar, &xr_text);

	xr_image.fx = total_indent;
	xr_image.fw = ic;
	xr_image.fy = total_height;
	xr_image.fh = th;

	ft_center_rect(&xr_image, DEF_SMALL_ICON, DEF_SMALL_ICON);
	draw_gizmo(pif, &xc, &xr_image, get_tree_title_icon_ptr(ptr));

	xr_text.fx = total_indent + ic;
	xr_text.fw = pw - ic;
	xr_text.fy = total_height;
	xr_text.fh = th;

	(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr_text, get_tree_title_ptr(ptr), -1);

	total_height += th;

	ilk = get_tree_first_child_item(ptr);
	while (ilk)
	{
		xr_image.fx = total_indent;
		xr_image.fw = ic;
		xr_image.fy = total_height;
		xr_image.fh = ih;

		icon = get_tree_item_icon_ptr(ilk);
		if ( !is_null(icon))
		{
			ft_center_rect(&xr_image, DEF_SMALL_ICON, DEF_SMALL_ICON);
			draw_gizmo(pif, &xc, &xr_image, get_tree_item_icon_ptr(ilk));
		}
		else
		{
			ft_center_rect(&xr_image, DEF_SMALL_ICON, DEF_SMALL_ICON);

			if (!get_tree_item_collapsed(ilk))
			{
				draw_gizmo(pif, &xc_check, &xr_image, GDI_ATTR_GIZMO_MINUS);
			}
			else
			{
				draw_gizmo(pif, &xc_check, &xr_image, GDI_ATTR_GIZMO_PLUS);
			}
		}

		b_checkbox = get_tree_item_showcheck(ilk);

		if (b_checkbox)
		{
			xr_check.fx = total_indent + ic;
			xr_check.fw = ic;
			xr_check.fy = total_height;
			xr_check.fh = ih;

			ft_center_rect(&xr_check, DEF_SMALL_ICON, DEF_SMALL_ICON);
			
			if (get_tree_item_checked(ilk))
			{
				draw_gizmo(pif, &xc_check, &xr_check, GDI_ATTR_GIZMO_CHECKED);
			}
			else
			{
				draw_gizmo(pif, &xc_check, &xr_check, GDI_ATTR_GIZMO_CHECKBOX);
			}

			xr_text.fx = total_indent + ic * 2;
			xr_text.fw = pw - xr_text.fx;
			xr_text.fy = total_height;
			xr_text.fh = ih;
		}
		else
		{
			xr_text.fx = total_indent + ic;
			xr_text.fw = pw - xr_text.fx;
			xr_text.fy = total_height;
			xr_text.fh = ih;
		}

		(*pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr_text, get_tree_item_title_ptr(ilk), -1);

		total_height += ih;
		if (!get_tree_item_collapsed(ilk) && get_tree_first_child_item(ilk))
		{
			total_indent += ic / 2;

			if (!st)
				st = create_stack_table();

			push_stack_node(st, (void*)ilk);

			ilk = get_tree_first_child_item(ilk);
			continue;

		}

		while (ilk)
		{
			ilk = get_tree_next_sibling_item(ilk);
			if (ilk)
				break;
			ilk = (st) ? (link_t_ptr)pop_stack_node(st) : NULL;
			total_indent -= ic / 2;
		}
	}

	if (st)
		destroy_stack_table(st);
}
