/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc notes document

	@module	notesview.c | implement file

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
#include "notesview.h"

#include "../xdlsdi.h"
#include "../xdldoc.h"

#define NOTESVIEW_SPAN_PLUS		10

float calc_notes_height(const measure_interface* pmc, const xfont_t* pxf, link_t_ptr ptr)
{
	float ph = 0.0f;
	xsize_t xs;
	xrect_t xr;
	link_t_ptr doc, ilk;
	float tw, th;
	xface_t xa;

	default_xface(&xa);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);

	(*pmc->mea->pf_measure_font)(pmc->ctx, pxf, &xs);
	tw = (float)(xs.fw * 8);
	th = (float)(xs.fh * xstof(xa.line_height));

	ph = 0;
	ilk = get_arch_first_child_item(ptr);
	while (ilk)
	{
		doc = fetch_arch_document(ilk);

		XDK_ASSERT(is_notes_doc(doc));

		if (compare_text(get_notes_type_ptr(doc), -1, ATTR_NOTES_TEXT, -1, 0) == 0)
		{
			xr.fx = xr.fy = 0;
			xr.fw = pmc->rect.fw - tw;
			xr.fh = th;
			(*pmc->mea->pf_measure_rect)(pmc->ctx, pxf, &xa, get_notes_text_ptr(doc), -1, &xr);

			ph += xr.fh;
		}
		else
		{
			ph += NOTESVIEW_SPAN_PLUS * th;
		}

		ilk = get_arch_next_sibling_item(ilk);
	}

	return ph;
}

float calc_notes_width(const measure_interface* pmc, const xfont_t* pxf, link_t_ptr ptr)
{
	float pw = 0.0f;
	xsize_t xs;
	link_t_ptr doc, ilk;
	float tw, th;
	xface_t xa;

	default_xface(&xa);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);

	(*pmc->mea->pf_measure_font)(pmc->ctx, pxf, &xs);
	tw = (float)(xs.fw * 8);
	th = (float)(xs.fh * xstof(xa.line_height));

	ilk = get_arch_first_child_item(ptr);
	while (ilk)
	{
		doc = fetch_arch_document(ilk);

		XDK_ASSERT(is_notes_doc(doc));

		if (compare_text(get_notes_type_ptr(doc),-1,ATTR_NOTES_TEXT,-1,0) == 0)
		{
			(*pmc->mea->pf_measure_size)(pmc->ctx, pxf, get_notes_text_ptr(doc), -1, &xs);
			if (pw < xs.w)
				pw = xs.w;
		}
		else
		{
			pw = NOTESVIEW_SPAN_PLUS * tw;
		}

		ilk = get_arch_next_sibling_item(ilk);
	}

	return pw;
}

void calc_notes_item_rect(const measure_interface* pmc, const xfont_t* pxf, link_t_ptr ptr, link_t_ptr plk, xrect_t* pxr)
{
	xsize_t xs;
	xrect_t xr;
	link_t_ptr doc, ilk;
	float tw, th, ph = 0;
	xface_t xa;

	default_xface(&xa);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);

	(*pmc->mea->pf_measure_font)(pmc->ctx, pxf, &xs);
	tw = (float)(xs.fw * 8);
	th = (float)(xs.fh * xstof(xa.line_height));

	ilk = get_arch_first_child_item(ptr);
	while (ilk)
	{
		doc = fetch_arch_document(ilk);

		XDK_ASSERT(is_notes_doc(doc));

		if (compare_text(get_notes_type_ptr(doc), -1, ATTR_NOTES_TEXT, -1, 0) == 0)
		{
			xr.fx = xr.fy = 0;
			xr.fw = pmc->rect.fw - tw;
			xr.fh = th;
			(*pmc->mea->pf_measure_rect)(pmc->ctx, pxf, &xa, get_notes_text_ptr(doc), -1, &xr);

			ph += xr.fh;
		}
		else
		{
			ph += NOTESVIEW_SPAN_PLUS * th;
		}

		if (ilk == plk)
		{
			pxr->fx = xr.fx;
			pxr->fy = xr.fh + ph;
			pxr->fw = xr.fw;
			pxr->fh = ph;
			break;
		}

		ilk = get_arch_next_sibling_item(ilk);
	}
}

int	calc_notes_hint(const measure_interface* pmc, const xfont_t* pxf, const xpoint_t* ppt, link_t_ptr ptr, link_t_ptr* pplk)
{
	xrect_t xr;
	xsize_t xs;
	float tw, th, ph = 0;
	link_t_ptr doc, ilk;
	int hint;
	xface_t xa;

	default_xface(&xa);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);

	*pplk = NULL;
	hint = _NOTES_HINT_NONE;

	(*pmc->mea->pf_measure_font)(pmc->ctx, pxf, &xs);
	tw = (float)(xs.fw * 8);
	th = (float)(xs.fh * xstof(xa.line_height));

	ilk = get_arch_first_child_item(ptr);
	while (ilk)
	{
		doc = fetch_arch_document(ilk);

		XDK_ASSERT(is_notes_doc(doc));

		xr.fx = pmc->rect.fx + pmc->rect.fw - th;
		xr.fy = pmc->rect.fy + ph;
		xr.fw = th;
		xr.fh = th;
		if (ft_in_rect(ppt, &xr))
		{
			*pplk = ilk;
			hint = _NOTES_HINT_CLOSE;
			break;
		}

		xr.fx = pmc->rect.fx;
		xr.fy = pmc->rect.fy + ph;
		xr.fw = tw;
		xr.fh = th;
		if (ft_in_rect(ppt, &xr))
		{
			*pplk = ilk;
			hint = _NOTES_HINT_TIME;
			break;
		}

		xr.fx = pmc->rect.fx + tw;
		xr.fy = pmc->rect.fy + ph;
		xr.fw = pmc->rect.fw - tw;
		xr.fh = th;
		if (ft_in_rect(ppt, &xr))
		{
			*pplk = ilk;
			hint = _NOTES_HINT_TITLE;
			break;
		}

		if (compare_text(get_notes_type_ptr(doc), -1, ATTR_NOTES_TEXT, -1, 0) == 0)
		{
			xr.fx = xr.fy = 0;
			xr.fw = pmc->rect.fw - tw;
			xr.fh = th;
			(*pmc->mea->pf_measure_rect)(pmc->ctx, pxf, &xa, get_notes_text_ptr(doc), -1, &xr);

			ph += xr.fh;
		}
		else
		{
			xr.fh = NOTESVIEW_SPAN_PLUS * th;
			ph += xr.fh;
		}

		xr.fx = pmc->rect.fx + tw;
		xr.fy = pmc->rect.fy + ph + th;
		xr.fw = pmc->rect.fw - tw;
		if (pt_in_rect(ppt, &xr))
		{
			*pplk = ilk;
			hint = _NOTES_HINT_ITEM;
			break;
		}

		ilk = get_arch_next_sibling_item(ilk);
	}

	return hint;
}

void draw_notes(const drawing_interface* pci, const xfont_t* pxf, const xpen_t* pxp, const xbrush_t* pxb, link_t_ptr ptr, link_t_ptr plk)
{
	const canvbox_t* pbox = (canvbox_t*)(&pci->rect);
	xcolor_t xc;
	xrect_t xr, xr_btn, xr_txt;
	xsize_t xs;
	xpoint_t pt_cur, pt_org;
	float tw, th, ph = 0;
	xdate_t dt;
	link_t_ptr ilk, doc;
	tchar_t token[DATE_LEN + 1];
	xface_t xa;

	default_xface(&xa);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);

	xr.fx = pci->rect.fx;
	xr.fy = pci->rect.fy;
	xr.fw = pci->rect.fw;

	get_loc_date(&dt);

	parse_xcolor(&xc, pxp->color);
	lighten_xcolor(&xc, DEF_SOFT_DARKEN);

	(*pci->drw->pf_font_size)(pci->ctx, &xs);
	tw = ((float)xs.w * 8);
	th = ((float)xs.h * xstof(xa.line_height));

	ilk = get_arch_first_child_item(ptr);
	while (ilk)
	{
		doc = fetch_arch_document(ilk);

		xr_btn.fx = xr.fx;
		xr_btn.fy = xr.fy;
		xr_btn.fw = pci->rect.fw;
		xr_btn.fh = th;

		//(*pci->drw->pf_draw_rect)(pci->ctx, NULL, &xb_bar, &xr_btn);

		xr_btn.fx = xr.fx;
		xr_btn.fy = xr.fy;
		xr_btn.fw = th;
		xr_btn.fh = th;

		if (ilk == plk)
		{
			ft_center_rect(&xr_btn, 5, 5);
			draw_gizmo(pci, &xc, &xr_btn, GDI_ATTR_GIZMO_GUIDER);
		}
		else
		{
			ft_center_rect(&xr_btn, 5, 5);
			draw_gizmo(pci, &xc, &xr_btn, GDI_ATTR_GIZMO_NEXT);
		}

		if (!xsisnil(get_notes_time_ptr(doc)))
		{
			parse_datetime(&dt, get_notes_time_ptr(doc));
			if (compare_date(&dt, &dt) == 0)
			{
				xsprintf(token, _T("今天 %02d:%02d"), dt.hour, dt.min);
			}
			else
			{
				xsprintf(token, _T("%d/%d %02d:%02d"), dt.day,dt.mon,dt.hour, dt.min);
			}

			(*pci->drw->pf_text_size)(pci->ctx, token, -1, &xs);

			xr_txt.fx = xr.fx + 2 * th;
			xr_txt.fy = xr.fy;
			xr_txt.fw = pci->rect.fw - 4 * th;
			xr_txt.fh = th;

			(*pci->drw->pf_draw_text)(pci->ctx, &xa, &xr_txt, token, -1);
		}
		else
		{
			xsprintf(token, _T("今天 %02d:%02d"), dt.hour, dt.min);
			(*pci->drw->pf_text_size)(pci->ctx, token, -1, &xs);
		}

		if (compare_text(get_notes_type_ptr(doc), -1, ATTR_NOTES_TEXT, -1, 0) == 0)
		{
			xr_txt.fx = xr.fx + xs.fw + 2 * th;
			xr_txt.fy = xr.fy;
			xr_txt.fw = pci->rect.fw - xs.fw - 3 * th;
			xr_txt.fh = th;

			(*pci->drw->pf_draw_text)(pci->ctx, &xa, &xr_txt, get_notes_text_ptr(doc), -1);
		}
		else
		{
			xr_btn.fx = xr.fx + th;
			xr_btn.fy = xr.fy + th;
			xr_btn.fw = tw - th;
			xr_btn.fh = NOTESVIEW_SPAN_PLUS * tw;

			ft_center_rect(&xr_btn, 2.5, 2.5);
			draw_gizmo(pci, &xc, &xr_btn, GDI_ATTR_GIZMO_FIXED);
		}

		pt_cur.fx = xr.fx + th / 2;
		pt_cur.fy = xr.fy + th / 2;

		if (!is_first_link(ilk))
		{
			(*pci->drw->pf_draw_line)(pci->ctx, pxp, &pt_cur, &pt_org);
		}

		if (compare_text(get_notes_type_ptr(doc), -1, ATTR_NOTES_TEXT, -1, 0) == 0)
		{
			xr_txt.fx = 0;
			xr_txt.fy = 0;
			xr_txt.fw = pci->rect.fw - tw;
			xr_txt.fh = tw;
			(*pci->drw->pf_text_rect)(pci->ctx, &xa, token, -1, &xr_txt);

			ph += xr.fh;
		}
		else
		{
			xr.fh = NOTESVIEW_SPAN_PLUS * th;
			ph += xr.fh;
		}

		xr_txt.fx = xr.fx + tw;
		xr_txt.fy = xr.fy + ph;
		xr_txt.fw = pci->rect.fw - th;
		xr_txt.fh = xr.fh;
		(*pci->drw->pf_draw_text)(pci->ctx, &xa, &xr_txt, get_notes_text_ptr(doc), -1);

		pt_org.fx = pt_cur.fx;
		pt_org.fy = pt_cur.fy;

		ilk = get_arch_next_sibling_item(ilk);
	}
}
