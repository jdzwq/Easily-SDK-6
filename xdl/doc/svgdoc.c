﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc svg document

	@module	svgdoc.c | implement file

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

#include "svgdoc.h"

#include "../xdldoc.h"


link_t_ptr create_svg_doc()
{
	link_t_ptr ptr;

	ptr = create_dom_doc();
	set_dom_node_name(ptr,DOC_SVG,-1);
	set_dom_node_xmlns(ptr, XMLNS, -1, XMLNS_SVG_INSTANCE,-1);
	set_dom_node_xmlns(ptr, XMLNS_XLINK, -1, XMLNS_XLINK_INSTANCE, -1);

	set_dom_node_attr(ptr, XML_ATTR_VERSION, -1, _T("1.1"), -1);

	set_svg_width(ptr, DEF_PAPER_WIDTH);
	set_svg_height(ptr, DEF_PAPER_HEIGHT);

	return ptr;
}

void destroy_svg_doc(link_t_ptr ptr)
{
	destroy_dom_doc(ptr);
}

void clear_svg_doc(link_t_ptr ptr)
{
	delete_dom_child_nodes(ptr);
}

bool_t is_svg_doc(link_t_ptr ptr)
{
	return (compare_text(get_dom_node_name_ptr(ptr), -1, DOC_SVG, -1, 0) == 0) ? 1 : 0;
}

bool_t is_svg_node(link_t_ptr ptr, link_t_ptr ilk)
{
	return is_dom_child_node(ptr, ilk);
}

link_t_ptr insert_svg_node(link_t_ptr nlk)
{
	return insert_dom_node(nlk,LINK_LAST);
}

void delete_svg_node(link_t_ptr nlk)
{
	delete_dom_node(nlk);
}

link_t_ptr get_svg_first_child_node(link_t_ptr nlk)
{
	return get_dom_first_child_node(nlk);
}

link_t_ptr get_svg_last_child_node(link_t_ptr nlk)
{
	return get_dom_last_child_node(nlk);
}

link_t_ptr get_svg_parent_node(link_t_ptr nlk)
{
	return get_dom_parent_node(nlk);
}

link_t_ptr get_svg_next_sibling_node(link_t_ptr nlk)
{
	return get_dom_next_sibling_node(nlk);
}

link_t_ptr get_svg_prev_sibling_node(link_t_ptr nlk)
{
	return get_dom_prev_sibling_node(nlk);
}

link_t_ptr svg_doc_from_node(link_t_ptr nlk)
{
	while (nlk)
	{
		if (compare_text(get_dom_node_name_ptr(nlk), -1, DOC_SVG, -1, 1) == 0)
			return nlk;

		nlk = get_dom_parent_node(nlk);
	}

	return nlk;
}

link_t_ptr get_svg_defs_node(link_t_ptr ptr, bool_t b_add, int* pn)
{
	link_t_ptr nlk;

	if (pn) *pn = 0;

	nlk = get_svg_first_child_node(ptr);
	while (nlk)
	{
		if (compare_text(get_svg_node_name_ptr(nlk), -1, SVG_NODE_DEFS, -1, 1) == 0)
			break;

		nlk = get_svg_next_sibling_node(nlk);
	}

	if (!nlk && b_add)
	{
		nlk = insert_dom_node(ptr, LINK_FIRST);
		set_dom_node_name(nlk, SVG_NODE_DEFS, -1);
	}

	if (pn)
		*pn = get_dom_child_node_count(nlk);

	return nlk;
}

/******************************************************************************************************/

void set_svg_width(link_t_ptr ptr, float width)
{
	tchar_t token[NUM_LEN + 1] = { 0 };

	//xsprintf(token, _T("%.1fmm"), width);

	xsprintf(token, _T("%d"), (int)(width * PTPERMM));

	set_dom_node_attr(ptr, SVG_ATTR_WIDTH, -1, token, -1);
}

float get_svg_width(link_t_ptr ptr)
{
	return (float)(get_dom_node_attr_numeric(ptr, SVG_ATTR_WIDTH) / PTPERMM);
}

void set_svg_height(link_t_ptr ptr, float height)
{
	tchar_t token[NUM_LEN + 1] = { 0 };

	//xsprintf(token, _T("%.1fmm"), height);

	xsprintf(token, _T("%d"), (int)(height * PTPERMM));

	set_dom_node_attr(ptr, SVG_ATTR_HEIGHT, -1, token, -1);
}

float get_svg_height(link_t_ptr ptr)
{
	return (float)(get_dom_node_attr_numeric(ptr, SVG_ATTR_HEIGHT) / PTPERMM);
}

void set_svg_viewbox(link_t_ptr ptr, const xrect_t* pbox)
{
	tchar_t token[NUM_LEN * 4] = { 0 };

	xsprintf(token, _T("%d %d %d %d"), pbox->x, pbox->y, pbox->w, pbox->h);

	set_dom_node_attr(ptr, SVG_ATTR_VIEWBOX, -1, token, -1);
}

void get_svg_viewbox(link_t_ptr ptr, xrect_t* pbox)
{
	const tchar_t* str;
	tchar_t* key;
	int klen;
	int n, total = 0;

	xmem_zero((void*)pbox, sizeof(xrect_t));

	str = get_dom_node_attr_ptr(ptr, SVG_ATTR_VIEWBOX, -1);
	if (is_null(str))
		return;

	n = parse_string_token((str + total), -1, _T(' '), &key, &klen);
	total += n;
	if (n)
	{
		pbox->x = xsntol(key, klen);
	}
	else
		return;

	n = parse_string_token((str + total), -1, _T(' '), &key, &klen);
	total += n;
	if (n)
	{
		pbox->y = xsntol(key, klen);
	}
	else
		return;

	n = parse_string_token((str + total), -1, _T(' '), &key, &klen);
	total += n;
	if (n)
	{
		pbox->w = xsntol(key, klen);
	}
	else
		return;

	n = parse_string_token((str + total), -1, _T(' '), &key, &klen);
	total += n;
	if (n)
	{
		pbox->h = xsntol(key, klen);
	}
}

void reset_svg_viewbox(link_t_ptr ptr)
{
	xrect_t vb = { 0 };
	float htpermm, vtpermm;

	htpermm = PTPERMM;
	vtpermm = PTPERMM;

	vb.x = 0;
	vb.y = 0;
	vb.w = (int)(get_svg_width(ptr) * htpermm);
	vb.h = (int)(get_svg_height(ptr) * vtpermm);

	set_svg_viewbox(ptr, &vb);
}

void write_xpen_to_svg_node(link_t_ptr nlk, const xpen_t* pxp)
{
	tchar_t token[RES_LEN + 1] = { 0 };

	if (is_null_xpen(pxp))
		return;

	if (!is_null(pxp->color))
	{
		set_dom_node_attr(nlk, SVG_ATTR_STROKE_COLOR, -1, pxp->color, -1);
	}

	if (!is_null(pxp->opacity))
	{
		xsprintf(token, _T("%.2f"), xstonum(pxp->opacity) / 255.0);
		set_dom_node_attr(nlk, SVG_ATTR_STROKE_OPACITY, -1, token, -1);
	}

	if (!is_null(pxp->size))
	{
		set_dom_node_attr(nlk, SVG_ATTR_STROKE_WIDTH, -1, pxp->size, -1);
	}

	if (compare_text(pxp->style, -1, GDI_ATTR_STROKE_STYLE_DASH, -1, 1) == 0)
	{
		xsprintf(token, _T("%d,%d"), xstol(pxp->size), xstol(pxp->size));
		set_dom_node_attr(nlk, SVG_ATTR_STROKE_DASHARRAY, -1, token, -1);
	}
	else if (compare_text(pxp->style, -1, GDI_ATTR_STROKE_STYLE_DASHDASH, -1, 1) == 0)
	{
		xsprintf(token, _T("%d,%d"), 2 * xstol(pxp->size), xstol(pxp->size));
		set_dom_node_attr(nlk, SVG_ATTR_STROKE_DASHARRAY, -1, token, -1);
	}
}

void read_xpen_from_svg_node(link_t_ptr nlk, xpen_t* pxp)
{
	const tchar_t* token;

	token = get_dom_node_attr_ptr(nlk, SVG_ATTR_STROKE_COLOR, -1);
	if (!is_null(token))
	{
		xscpy(pxp->color, token);
	}

	token = get_dom_node_attr_ptr(nlk, SVG_ATTR_STROKE_OPACITY, -1);
	if (!is_null(token))
	{
		xsprintf(pxp->opacity, _T("%d"), (int)(xstof(token) * 255.0));
	}

	token = get_dom_node_attr_ptr(nlk, SVG_ATTR_STROKE_WIDTH, -1);
	if (!is_null(token))
	{
		xscpy(pxp->size, token);
	}

	token = get_dom_node_attr_ptr(nlk, SVG_ATTR_STROKE_DASHARRAY, -1);
	if (!is_null(token))
	{
		if (xstol(pxp->size) == xstol(token))
			xscpy(pxp->style, GDI_ATTR_STROKE_STYLE_DASH);
		else
			xscpy(pxp->style, GDI_ATTR_STROKE_STYLE_DASHDASH);
	}
}

void write_xbrush_to_svg_node(link_t_ptr nlk, const xbrush_t* pxb)
{
	tchar_t token[RES_LEN + 1] = { 0 };
	tchar_t gid[RES_LEN + 1] = { 0 };
	link_t_ptr ptr, nlk_defs, nlk_objs, nlk_sub;
	xcolor_t xc = { 0 };
	tchar_t clr[CLR_LEN + 1] = { 0 };
	int n = 0;

	if (is_null_xbrush(pxb))
	{
		set_dom_node_attr(nlk, SVG_ATTR_FILL_COLOR, -1, GDI_ATTR_RGB_WHITE, -1);
		return;
	}

	if (compare_text(pxb->style, -1, GDI_ATTR_FILL_STYLE_GRADIENT, -1, 0) == 0)
	{
		ptr = svg_doc_from_node(nlk);
		nlk_defs = get_svg_defs_node(ptr, 1, &n);

		xsprintf(gid, _T("gradient%d"), (n + 1));
		xsprintf(token, _T("url(#%s)"), gid);
		set_dom_node_attr(nlk, SVG_ATTR_FILL_COLOR, -1, token, -1);

		nlk_objs = insert_dom_node(nlk_defs, LINK_LAST);
		if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_HORZ, -1, 0) == 0 || compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_VERT, -1, 0) == 0)
		{
			set_dom_node_name(nlk_objs, SVG_NODE_LINEARGRADIENT, -1);
		}
		else
		{
			set_dom_node_name(nlk_objs, SVG_NODE_RADIALGRADIENT, -1);
		}
		set_dom_node_attr(nlk_objs, _T("id"), -1, gid, -1);

		if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_HORZ, -1, 0) == 0)
		{
			set_dom_node_attr(nlk_objs, _T("x1"), -1, _T("0%"), -1);
			set_dom_node_attr(nlk_objs, _T("y1"), -1, _T("50%"), -1);
			set_dom_node_attr(nlk_objs, _T("x2"), -1, _T("0%"), -1);
			set_dom_node_attr(nlk_objs, _T("y2"), -1, _T("100%"), -1);
		}
		else if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_VERT, -1, 0) == 0)
		{
			set_dom_node_attr(nlk_objs, _T("x1"), -1, _T("0%"), -1);
			set_dom_node_attr(nlk_objs, _T("y1"), -1, _T("50%"), -1);
			set_dom_node_attr(nlk_objs, _T("x2"), -1, _T("100%"), -1);
			set_dom_node_attr(nlk_objs, _T("y2"), -1, _T("100%"), -1);
		}
		else
		{
			set_dom_node_attr(nlk_objs, _T("cx"), -1, _T("50%"), -1);
			set_dom_node_attr(nlk_objs, _T("cy"), -1, _T("50%"), -1);
			set_dom_node_attr(nlk_objs, _T("rx"), -1, _T("50%"), -1);
			set_dom_node_attr(nlk_objs, _T("ry"), -1, _T("50%"), -1);
		}

		nlk_sub = insert_dom_node(nlk_objs, LINK_LAST);
		set_dom_node_name(nlk_sub, SVG_NODE_STOP, -1);
		set_dom_node_attr(nlk_sub, _T("offset"), -1, _T("0%"), -1);
		if (is_null(pxb->color))
		{
			parse_xcolor(&xc, pxb->color);
			lighten_xcolor(&xc, -20);
			format_xcolor(&xc, clr);
			xsprintf(token, _T("stop-color:%s"), clr);
		}
		else
			xsprintf(token, _T("stop-color:%s"), pxb->color);
		set_dom_node_attr(nlk_sub, _T("style"), -1, token, -1);

		nlk_sub = insert_dom_node(nlk_objs, LINK_LAST);
		set_dom_node_name(nlk_sub, SVG_NODE_STOP, -1);
		set_dom_node_attr(nlk_sub, _T("offset"), -1, _T("100%"), -1);
		if (is_null(pxb->linear))
		{
			parse_xcolor(&xc, pxb->color);
			lighten_xcolor(&xc, 20);
			format_xcolor(&xc, clr);
			xsprintf(token, _T("stop-color:%s"), clr);
		}
		else
			xsprintf(token, _T("stop-color:%s"), pxb->linear);
		set_dom_node_attr(nlk_sub, _T("style"), -1, token, -1);
	}
	else
	{
		if (!is_null(pxb->color))
		{
			set_dom_node_attr(nlk, SVG_ATTR_FILL_COLOR, -1, pxb->color, -1);
		}
	}

	if (pxb->shadow.offx || pxb->shadow.offy)
	{
		ptr = svg_doc_from_node(nlk);
		nlk_defs = get_svg_defs_node(ptr, 1, &n);

		xsprintf(gid, _T("filter%d"), (n + 1));
		xsprintf(token, _T("url(#%s)"), gid);
		set_dom_node_attr(nlk, _T("filter"), -1, token, -1);

		nlk_objs = insert_dom_node(nlk_defs, LINK_LAST);
		set_dom_node_name(nlk_objs, _T("filter"), -1);
		set_dom_node_attr(nlk_objs, _T("id"), -1, gid, -1);
		set_dom_node_attr(nlk_objs, _T("x"), -1, _T("0"), -1);
		set_dom_node_attr(nlk_objs, _T("y"), -1, _T("0"), -1);
		set_dom_node_attr(nlk_objs, _T("width"), -1, _T("200%"), -1);
		set_dom_node_attr(nlk_objs, _T("height"), -1, _T("200%"), -1);

		nlk_sub = insert_dom_node(nlk_objs, LINK_LAST);
		set_dom_node_name(nlk_sub, _T("feOffset"), -1);
		set_dom_node_attr(nlk_sub, _T("result"), -1, _T("offOut"), -1);
		set_dom_node_attr(nlk_sub, _T("in"), -1, _T("SourceAlpha"), -1);
		xsprintf(token, _T("%d"), pxb->shadow.offx);
		set_dom_node_attr(nlk_sub, _T("dx"), -1, token, -1);
		xsprintf(token, _T("%d"), pxb->shadow.offy);
		set_dom_node_attr(nlk_sub, _T("dy"), -1, token, -1);

		nlk_sub = insert_dom_node(nlk_objs, LINK_LAST);
		set_dom_node_name(nlk_sub, _T("feGaussianBlur"), -1);
		set_dom_node_attr(nlk_sub, _T("result"), -1, _T("blurOut"), -1);
		set_dom_node_attr(nlk_sub, _T("in"), -1, _T("offOut"), -1);
		set_dom_node_attr(nlk_sub, _T("stdDeviation"), -1, _T("5"), -1);

		nlk_sub = insert_dom_node(nlk_objs, LINK_LAST);
		set_dom_node_name(nlk_sub, _T("feBlend"), -1);
		set_dom_node_attr(nlk_sub, _T("in"), -1, _T("SourceGraphic"), -1);
		set_dom_node_attr(nlk_sub, _T("in2"), -1, _T("blurOut"), -1);
		set_dom_node_attr(nlk_sub, _T("mode"), -1, _T("normal"), -1);
	}

	if (!is_null(pxb->opacity))
	{
		xsprintf(token, _T("%.2f"), xstof(pxb->opacity) / 255.0);
		set_dom_node_attr(nlk, SVG_ATTR_FILL_OPACITY, -1, token, -1);
	}
}

void read_xbrush_from_svg_node(link_t_ptr nlk, xbrush_t* pxb)
{
	tchar_t token[RES_LEN + 1] = { 0 };
	tchar_t gid[RES_LEN + 1] = { 0 };
	link_t_ptr ptr, nlk_defs, nlk_objs, nlk_sub;

	get_dom_node_attr(nlk, SVG_ATTR_FILL_COLOR, -1, token, RES_LEN);

	if (compare_text(token, 5, _T("url(#"), 5, 1) == 0)
	{
		xsncpy(gid, (token + 5), xslen(token) - 6);

		xscpy(pxb->style, GDI_ATTR_FILL_STYLE_GRADIENT);

		ptr = svg_doc_from_node(nlk);
		nlk_defs = get_svg_defs_node(ptr, 0, NULL);
		if (nlk_defs)
		{
			nlk_objs = get_svg_first_child_node(nlk_defs);
			while (nlk_objs)
			{
				if (compare_text(get_dom_node_attr_ptr(nlk_objs, _T("id"), -1), -1, gid, -1, 1) == 0)
				{
					break;
				}

				nlk_objs = get_svg_first_child_node(nlk_objs);
			}

			if (nlk_objs)
			{
				if (compare_text(get_dom_node_name_ptr(nlk_objs), -1, SVG_NODE_LINEARGRADIENT, -1, 1) == 0)
				{
					xscpy(pxb->gradient, GDI_ATTR_GRADIENT_HORZ);
				}
				else
				{
					xscpy(pxb->gradient, GDI_ATTR_GRADIENT_RADIAL);
				}

				nlk_sub = get_svg_first_child_node(nlk_objs);
				while (nlk_sub)
				{
					if (compare_text(get_dom_node_name_ptr(nlk_sub), -1, SVG_NODE_STOP, -1, 1) == 0 && compare_text(get_dom_node_attr_ptr(nlk_sub, _T("offset"), -1), -1, _T("0%"), -1, 0) == 0)
					{
						get_dom_node_attr(nlk_sub, _T("style"), -1, token, RES_LEN);
						xscpy(pxb->color, (token + 11)); //stop-color:
					}
					else if (compare_text(get_dom_node_name_ptr(nlk_sub), -1, SVG_NODE_STOP, -1, 1) == 0)
					{
						get_dom_node_attr(nlk_sub, _T("style"), -1, token, RES_LEN);
						xscpy(pxb->linear, (token + 11)); //stop-color:
					}

					nlk_sub = get_svg_next_sibling_node(nlk_sub);
				}
			}
		}
	}
	else if (!is_null(token))
	{
		xscpy(pxb->color, token);
	}
	
	get_dom_node_attr(nlk, SVG_ATTR_FILL_OPACITY, -1, token, RES_LEN);
	if (!is_null(token))
	{
		xsprintf(pxb->opacity, _T("%d"), (int)(xstof(token) * 255.0));
	}
}

void write_xfont_to_svg_node(link_t_ptr nlk, const xfont_t* pxf)
{
	if (is_null_xfont(pxf))
		return;

	if (!is_null(pxf->size))
	{
		set_dom_node_attr(nlk, SVG_ATTR_FONT_SIZE, -1, pxf->size, -1);
	}

	if (!is_null(pxf->family))
	{
		set_dom_node_attr(nlk, SVG_ATTR_FONT_FAMILY, -1, pxf->family, -1);
	}

	if (!is_null(pxf->color))
	{
		set_dom_node_attr(nlk, SVG_ATTR_TEXT_COLOR, -1, pxf->color, -1);
	}
}

void read_xfont_from_svg_node(link_t_ptr nlk, xfont_t* pxf)
{
	const tchar_t* token;

	token = get_dom_node_attr_ptr(nlk, SVG_ATTR_FONT_SIZE, -1);
	if (!is_null(token))
	{
		xscpy(pxf->size, token);
	}

	token = get_dom_node_attr_ptr(nlk, SVG_ATTR_FONT_FAMILY, -1);
	if (!is_null(token))
	{
		xscpy(pxf->family, token);
	}

	token = get_dom_node_attr_ptr(nlk, SVG_ATTR_TEXT_COLOR, -1);
	if (!is_null(token))
	{
		xscpy(pxf->color, token);
	}
}

void write_xface_to_svg_node(link_t_ptr nlk, const xface_t* pxa)
{
	tchar_t token[RES_LEN + 1] = { 0 };

	if (is_null_xface(pxa))
		return;

	if (!is_null(pxa->text_align))
	{
		if (compare_text(pxa->text_align, -1, GDI_ATTR_TEXT_ALIGN_FAR, -1, 1) == 0)
			xscpy(token, SVG_ATTR_TEXT_ALIGN_FAR);
		else if (compare_text(pxa->text_align, -1, GDI_ATTR_TEXT_ALIGN_CENTER, -1, 1) == 0)
			xscpy(token, SVG_ATTR_TEXT_ALIGN_CENTER);
		else
			xscpy(token, SVG_ATTR_TEXT_ALIGN_NEAR);

		set_dom_node_attr(nlk, SVG_ATTR_TEXT_ALIGN, -1, token, -1);
	}
}

void read_xface_from_svg_node(link_t_ptr nlk, xface_t* pxa)
{
	const tchar_t* token;

	token = get_dom_node_attr_ptr(nlk, SVG_ATTR_TEXT_ALIGN, -1);
	if (!is_null(token))
	{
		if (compare_text(token, -1, SVG_ATTR_TEXT_ALIGN_FAR, -1, 1) == 0)
			xscpy(pxa->text_align, GDI_ATTR_TEXT_ALIGN_FAR);
		else if (compare_text(token, -1, SVG_ATTR_TEXT_ALIGN_CENTER, -1, 1) == 0)
			xscpy(pxa->text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
	}
}

void write_ximage_to_svg_node(link_t_ptr glk, const ximage_t* pxi, const xrect_t* prt)
{
	tchar_t token[NUM_LEN + 1];
	
	tchar_t* data;
	int len;

	set_dom_node_name(glk, SVG_NODE_IMAGE, -1);

	xsprintf(token, _T("%d"), prt->x);
	set_dom_node_attr(glk, SVG_ATTR_X, -1, token, -1);

	xsprintf(token, _T("%d"), prt->y);
	set_dom_node_attr(glk, SVG_ATTR_Y, -1, token, -1);

	xsprintf(token, _T("%d"), prt->w);
	set_dom_node_attr(glk, SVG_ATTR_WIDTH, -1, token, -1);

	xsprintf(token, _T("%d"), prt->h);
	set_dom_node_attr(glk, SVG_ATTR_HEIGHT, -1, token, -1);

	if (pxi)
	{
		if (compare_text(pxi->type, -1, GDI_ATTR_IMAGE_TYPE_URL, -1, 1) == 0)
		{
			set_dom_node_attr(glk, SVG_ATTR_IMAGE_HREF, -1, pxi->source, -1);
		}
		else
		{
			len = format_ximage_to_source(pxi, NULL, MAX_LONG);
			data = xsalloc(len + 1);
			format_ximage_to_source(pxi, data, len);
			attach_dom_node_attr(glk, SVG_ATTR_IMAGE_HREF, data);
		}
	}
}

void read_ximage_from_svg_node(link_t_ptr glk, ximage_t* pxi, xrect_t* prt)
{
	if (xsicmp(get_dom_node_name_ptr(glk), SVG_NODE_IMAGE) != 0)
		return;

	prt->x = (get_dom_node_attr_integer(glk, SVG_ATTR_X));
	prt->y = (get_dom_node_attr_integer(glk, SVG_ATTR_Y));
	prt->w = (get_dom_node_attr_integer(glk, SVG_ATTR_WIDTH));
	prt->h = (get_dom_node_attr_integer(glk, SVG_ATTR_HEIGHT));

	parse_ximage_from_source(pxi, get_dom_node_attr_ptr(glk, SVG_ATTR_IMAGE_HREF, -1));
}

void write_line_to_svg_node(link_t_ptr glk, const xpen_t* pxp, const xpoint_t* ppt1,const xpoint_t* ppt2)
{
	tchar_t token[NUM_LEN + 1];

	set_dom_node_name(glk,SVG_NODE_LINE,-1);

	xsprintf(token,_T("%d"),ppt1->x);
	set_dom_node_attr(glk,SVG_ATTR_X1,-1,token,-1);

	xsprintf(token,_T("%d"),ppt1->y);
	set_dom_node_attr(glk,SVG_ATTR_Y1,-1,token,-1);

	xsprintf(token,_T("%d"),ppt2->x);
	set_dom_node_attr(glk,SVG_ATTR_X2,-1,token,-1);

	xsprintf(token,_T("%d"),ppt2->y);
	set_dom_node_attr(glk,SVG_ATTR_Y2,-1,token,-1);

	write_xpen_to_svg_node(glk, pxp);
}

void read_line_from_svg_node(link_t_ptr glk,xpen_t* pxp,xpoint_t* ppt1,xpoint_t* ppt2)
{
	if(xsicmp(get_dom_node_name_ptr(glk),SVG_NODE_LINE) != 0)
		return;

	ppt1->x = (get_dom_node_attr_integer(glk, SVG_ATTR_X1));
	ppt1->y = (get_dom_node_attr_integer(glk, SVG_ATTR_Y1));
	ppt2->x = (get_dom_node_attr_integer(glk, SVG_ATTR_X2));
	ppt2->y = (get_dom_node_attr_integer(glk, SVG_ATTR_Y2));

	if (pxp)
		read_xpen_from_svg_node(glk, pxp);
}

void write_polyline_to_svg_node(link_t_ptr glk,const xpen_t* pxp, const xpoint_t* ppt,int n)
{
	tchar_t token[2 * NUM_LEN + 1];
	tchar_t* str;
	int i;

	set_dom_node_name(glk,SVG_NODE_POLYLINE,-1);

	str = xsalloc(NUM_LEN * 2 * n);
	for(i=0;i<n;i++)
	{
		xsprintf(token,_T("%d,%d "),ppt[i].x,ppt[i].y);
		xscat(str,token);
	}
	set_dom_node_attr(glk,SVG_ATTR_POINTS,-1,str,-1);
	xsfree(str);

	write_xpen_to_svg_node(glk, pxp);

	set_dom_node_attr(glk, SVG_ATTR_FILL_COLOR, -1, _T("none"), -1);

	if (is_null(pxp->color))
	{
		set_dom_node_attr(glk, SVG_ATTR_STROKE_COLOR, -1, GDI_ATTR_RGB_BLACK, -1);
	}
}

int read_polyline_from_svg_node(link_t_ptr glk,xpen_t* pxp,xpoint_t* ppt,int n)
{
	const tchar_t* str;
	tchar_t* token;
	tchar_t* xpt;
	tchar_t* ypt;
	int len,xptlen,yptlen,count = 0;

	if(xsicmp(get_dom_node_name_ptr(glk),SVG_NODE_POLYLINE) != 0)
		return 0;

	str = get_dom_node_attr_ptr(glk,SVG_ATTR_POINTS,-1);
	if(is_null(str))
		return 0;

	len = xslen(str);

	token = (tchar_t*)str;
	while(*token && len)
	{
		xpt = token;
		while(*token != _T(',') && *token != _T('\0'))
		{
			token ++;
			len --;
		}
		xptlen = (int)(token - xpt);

		if(token == _T('\0'))
			break;

		token ++; //skip item feed
		len --;
		
		ypt = token;
		while(*token != _T(' ') && *token != _T('\0'))
		{
			token ++;
			len --;
		}
		yptlen = (int)(token - ypt);

		if(ppt && count < n)
		{
			ppt[count].x = xsntol(xpt, xptlen);
			ppt[count].y = xsntol(ypt, yptlen);
		}

		count ++;

		if(*token == _T('\0'))
			break;

		token ++; //kip line feed
		len --;
	}

	if (pxp)
		read_xpen_from_svg_node(glk, pxp);

	return count;
}

void write_polygon_to_svg_node(link_t_ptr glk,const xpen_t* pxp, const xbrush_t* pxb,const xpoint_t* ppt,int n)
{
	tchar_t token[2 * NUM_LEN + 1];
	tchar_t* str;
	int i;

	set_dom_node_name(glk,SVG_NODE_POLYGON,-1);

	str = xsalloc(NUM_LEN * 2 * n);
	for(i=0;i<n;i++)
	{
		xsprintf(token,_T("%d,%d "),ppt[i].x,ppt[i].y);
		xscat(str,token);
	}
	set_dom_node_attr(glk,SVG_ATTR_POINTS,-1,str,-1);
	xsfree(str);

	write_xpen_to_svg_node(glk, pxp);

	write_xbrush_to_svg_node(glk, pxb);
}

int read_polygon_from_svg_node(link_t_ptr glk,xpen_t* pxp,xbrush_t* pxb,xpoint_t* ppt,int n)
{
	const tchar_t* str;
	tchar_t* token;
	tchar_t* xpt;
	tchar_t* ypt;
	int len,xptlen,yptlen,count = 0;

	if(xsicmp(get_dom_node_name_ptr(glk),SVG_NODE_POLYGON) != 0)
		return 0;

	str = get_dom_node_attr_ptr(glk,SVG_ATTR_POINTS,-1);
	if(is_null(str))
		return 0;

	len = xslen(str);

	token = (tchar_t*)str;
	while(*token && len)
	{
		xpt = token;
		while(*token != _T(',') && *token != _T('\0'))
		{
			token ++;
			len --;
		}
		xptlen = (int)(token - xpt);

		if(token == _T('\0'))
			break;

		token ++; //skip item feed
		len --;
		
		ypt = token;
		while(*token != _T(' ') && *token != _T('\0'))
		{
			token ++;
			len --;
		}
		yptlen = (int)(token - ypt);

		if(ppt && count < n)
		{
			ppt[count].x = xsntol(xpt, xptlen);
			ppt[count].y = xsntol(ypt, yptlen);
		}

		count ++;

		if(*token == _T('\0'))
			break;

		token ++; //kip line feed
		len --;
	}

	if (pxp)
		read_xpen_from_svg_node(glk, pxp);

	if (pxb)
		read_xbrush_from_svg_node(glk, pxb);

	return count;
}

void write_bezier_to_svg_node(link_t_ptr glk, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
	tchar_t token[2 * 4 * NUM_LEN + 1];

	set_dom_node_name(glk, SVG_NODE_PATH, -1);

	xsprintf(token, _T("M%d,%d C%d,%d %d,%d %d,%d"), ppt1->x, ppt1->y, ppt2->x, ppt2->y, ppt3->x, ppt3->y, ppt4->x, ppt4->y);

	set_dom_node_attr(glk, SVG_ATTR_D, -1, token, -1);
	set_dom_node_attr(glk, SVG_ATTR_FILL_COLOR, -1, _T("none"), -1);

	write_xpen_to_svg_node(glk, pxp);
}

void write_curve_to_svg_node(link_t_ptr glk, const xpen_t* pxp, const xpoint_t* ppt, int n)
{
	tchar_t* token;
	int i = 0;

	set_dom_node_name(glk, SVG_NODE_PATH, -1);

	token = xsalloc(2 * NUM_LEN * n);

	xsprintf(token, _T("M%d,%d "), ppt[i].x, ppt[i].y);
	i++;

	for (i = 1; i < n; i++)
	{
		xsappend(token, _T("S%d,%d %d,%d "), (ppt[i - 1].x + ppt[i].x) / 2, (ppt[i - 1].y + ppt[i].y) / 2, ppt[i].x, ppt[i].y);
	}

	set_dom_node_attr(glk, SVG_ATTR_D, -1, token, -1);
	set_dom_node_attr(glk, SVG_ATTR_FILL_COLOR, -1, _T("none"), -1);

	xsfree(token);

	write_xpen_to_svg_node(glk, pxp);
}

void write_ellipse_to_svg_node(link_t_ptr glk, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt)
{
	tchar_t token[NUM_LEN + 1];

	set_dom_node_name(glk, SVG_NODE_ELLIPSE, -1);

	xsprintf(token,_T("%d"),(prt->x + prt->w / 2));
	set_dom_node_attr(glk,SVG_ATTR_CX,-1,token,-1);

	xsprintf(token,_T("%d"),(prt->y + prt->h / 2));
	set_dom_node_attr(glk,SVG_ATTR_CY,-1,token,-1);

	xsprintf(token,_T("%d"),(prt->w / 2));
	set_dom_node_attr(glk,SVG_ATTR_RX,-1,token,-1);

	xsprintf(token,_T("%d"),(prt->h / 2));
	set_dom_node_attr(glk,SVG_ATTR_RY,-1,token,-1);

	write_xpen_to_svg_node(glk, pxp);

	write_xbrush_to_svg_node(glk, pxb);
}

void read_ellipse_from_svg_node(link_t_ptr glk,xpen_t* pxp,xbrush_t* pxb,xrect_t* prt)
{
	if (xsicmp(get_dom_node_name_ptr(glk), SVG_NODE_ELLIPSE) != 0)
		return;

	prt->x = (get_dom_node_attr_integer(glk, SVG_ATTR_CX) - get_dom_node_attr_integer(glk, SVG_ATTR_RX));
	prt->y = (get_dom_node_attr_integer(glk, SVG_ATTR_CY) - get_dom_node_attr_integer(glk, SVG_ATTR_RY));
	prt->w = (get_dom_node_attr_integer(glk, SVG_ATTR_RX) * 2);
	prt->h = (get_dom_node_attr_integer(glk, SVG_ATTR_RY) * 2);

	if (pxp)
		read_xpen_from_svg_node(glk, pxp);

	if (pxb)
		read_xbrush_from_svg_node(glk, pxb);
}

void write_rect_to_svg_node(link_t_ptr glk,const xpen_t* pxp, const xbrush_t* pxb,const xrect_t* prt)
{
	tchar_t token[NUM_LEN + 1];

	set_dom_node_name(glk,SVG_NODE_RECT,-1);

	xsprintf(token,_T("%d"),prt->x);
	set_dom_node_attr(glk,SVG_ATTR_X,-1,token,-1);

	xsprintf(token,_T("%d"),prt->y);
	set_dom_node_attr(glk,SVG_ATTR_Y,-1,token,-1);

	xsprintf(token,_T("%d"),prt->w);
	set_dom_node_attr(glk,SVG_ATTR_WIDTH,-1,token,-1);

	xsprintf(token,_T("%d"),prt->h);
	set_dom_node_attr(glk,SVG_ATTR_HEIGHT,-1,token,-1);

	write_xpen_to_svg_node(glk, pxp);

	write_xbrush_to_svg_node(glk, pxb);
}

void read_rect_from_svg_node(link_t_ptr glk,xpen_t* pxp,xbrush_t* pxb,xrect_t* prt)
{
	if(xsicmp(get_dom_node_name_ptr(glk),SVG_NODE_RECT) != 0)
		return;

	prt->x = (get_dom_node_attr_integer(glk, SVG_ATTR_X));
	prt->y = (get_dom_node_attr_integer(glk, SVG_ATTR_Y));
	prt->w = (get_dom_node_attr_integer(glk, SVG_ATTR_WIDTH));
	prt->h = (get_dom_node_attr_integer(glk, SVG_ATTR_HEIGHT));

	if (pxp)
		read_xpen_from_svg_node(glk, pxp);

	if (pxb)
		read_xbrush_from_svg_node(glk, pxb);
}

bool_t svg_node_is_round(link_t_ptr glk)
{
	return (compare_text(get_dom_node_name_ptr(glk),-1,SVG_NODE_RECT,-1,1) == 0 && is_dom_node_attr(glk, SVG_ATTR_RX, -1) && is_dom_node_attr(glk, SVG_ATTR_RY, -1));
}

void write_round_to_svg_node(link_t_ptr glk, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt, int rx, int ry)
{
	tchar_t token[NUM_LEN + 1];

	set_dom_node_name(glk, SVG_NODE_RECT, -1);

	xsprintf(token, _T("%d"), prt->x);
	set_dom_node_attr(glk, SVG_ATTR_X, -1, token, -1);

	xsprintf(token, _T("%d"), prt->y);
	set_dom_node_attr(glk, SVG_ATTR_Y, -1, token, -1);

	xsprintf(token, _T("%d"), prt->w);
	set_dom_node_attr(glk, SVG_ATTR_WIDTH, -1, token, -1);

	xsprintf(token, _T("%d"), prt->h);
	set_dom_node_attr(glk, SVG_ATTR_HEIGHT, -1, token, -1);

	xsprintf(token, _T("%d"), rx);
	set_dom_node_attr(glk, SVG_ATTR_RX, -1, token, -1);

	xsprintf(token, _T("%d"), ry);
	set_dom_node_attr(glk, SVG_ATTR_RY, -1, token, -1);

	write_xpen_to_svg_node(glk, pxp);

	write_xbrush_to_svg_node(glk, pxb);
}

void read_round_from_svg_node(link_t_ptr glk, xpen_t* pxp, xbrush_t* pxb, xrect_t* prt, int* prx, int* pry)
{
	if (xsicmp(get_dom_node_name_ptr(glk), SVG_NODE_RECT) != 0)
		return;

	prt->x = (get_dom_node_attr_integer(glk, SVG_ATTR_X));
	prt->y = (get_dom_node_attr_integer(glk, SVG_ATTR_Y));
	prt->w = (get_dom_node_attr_integer(glk, SVG_ATTR_WIDTH));
	prt->h = (get_dom_node_attr_integer(glk, SVG_ATTR_HEIGHT));

	*prx = (get_dom_node_attr_integer(glk, SVG_ATTR_RX));
	*pry = (get_dom_node_attr_integer(glk, SVG_ATTR_RY));

	if (pxp)
		read_xpen_from_svg_node(glk, pxp);

	if (pxb)
		read_xbrush_from_svg_node(glk, pxb);
}

void write_text_to_svg_node(link_t_ptr glk, const xfont_t* pxf, const xface_t* pxa, const xrect_t* prt,const tchar_t* text,int len)
{
	tchar_t token[NUM_LEN + 1];

	set_dom_node_name(glk,SVG_NODE_TEXT,-1);

	if (compare_text(pxa->text_align,-1,GDI_ATTR_TEXT_ALIGN_CENTER,-1,1) == 0)
		xsprintf(token,_T("%d"),(prt->x + prt->w / 2));
	else if (compare_text(pxa->text_align, -1, GDI_ATTR_TEXT_ALIGN_FAR, -1, 1) == 0)
		xsprintf(token, _T("%d"), (prt->x + prt->w));
	else
		xsprintf(token, _T("%d"), (prt->x));
	set_dom_node_attr(glk,SVG_ATTR_X,-1,token,-1);

	if (compare_text(pxa->line_align, -1, GDI_ATTR_TEXT_ALIGN_NEAR, -1, 1) == 0)
		xsprintf(token,_T("%d"),(prt->y));
	else if (compare_text(pxa->line_align, -1, GDI_ATTR_TEXT_ALIGN_FAR, -1, 1) == 0)
		xsprintf(token, _T("%d"), (prt->y + prt->h));
	else
		xsprintf(token, _T("%d"), (prt->y + prt->h / 2));
	set_dom_node_attr(glk,SVG_ATTR_Y,-1,token,-1);

	if (prt->w)
	{
		xsprintf(token, _T("%d"), prt->w);
		set_dom_node_attr(glk, SVG_ATTR_WIDTH, -1, token, -1);
	}

	if (prt->h)
	{
		xsprintf(token, _T("%d"), prt->h);
		set_dom_node_attr(glk, SVG_ATTR_HEIGHT, -1, token, -1);
	}

	if (!is_null(pxf->size))
	{
		xsprintf(token, _T("%spt"), pxf->size);
		set_dom_node_attr(glk, SVG_ATTR_FONT_SIZE, -1, token, -1);
	}

	if (!is_null(pxf->family))
	{
		set_dom_node_attr(glk, SVG_ATTR_FONT_FAMILY, -1, pxf->family, -1);
	}

	if (!is_null(pxf->color))
	{
		set_dom_node_attr(glk, SVG_ATTR_TEXT_COLOR, -1, pxf->color, -1);
	}

	if (prt->w && prt->h)
	{
		if (compare_text(pxa->text_align, -1, GDI_ATTR_TEXT_ALIGN_FAR, -1, 1) == 0)
			xscpy(token, SVG_ATTR_TEXT_ALIGN_FAR);
		else if (compare_text(pxa->text_align, -1, GDI_ATTR_TEXT_ALIGN_CENTER, -1, 1) == 0)
			xscpy(token, SVG_ATTR_TEXT_ALIGN_CENTER);
		else
			xscpy(token, SVG_ATTR_TEXT_ALIGN_NEAR);

		set_dom_node_attr(glk, SVG_ATTR_TEXT_ALIGN, -1, token, -1);

		if (compare_text(pxa->line_align, -1, GDI_ATTR_TEXT_ALIGN_FAR, -1, 1) == 0)
			xscpy(token, SVG_ATTR_TEXT_ALIGN_FAR);
		else if (compare_text(pxa->line_align, -1, GDI_ATTR_TEXT_ALIGN_NEAR, -1, 1) == 0)
			xscpy(token, SVG_ATTR_TEXT_ALIGN_NEAR);
		else
			xscpy(token, SVG_ATTR_TEXT_ALIGN_CENTER);

		set_dom_node_attr(glk, SVG_ATTR_LINE_ALIGN, -1, token, -1);
	}

	set_dom_node_text(glk,text,len);
}

const tchar_t* read_text_from_svg_node(link_t_ptr glk,xfont_t* pxf, xface_t* pxa, xrect_t* prt)
{
	const tchar_t* token;
	
	if(xsicmp(get_dom_node_name_ptr(glk),SVG_NODE_TEXT) != 0)
		return NULL;

	prt->x = (get_dom_node_attr_integer(glk, SVG_ATTR_X));
	prt->y = (get_dom_node_attr_integer(glk, SVG_ATTR_Y));
	prt->w = (get_dom_node_attr_integer(glk, SVG_ATTR_WIDTH));
	prt->h = (get_dom_node_attr_integer(glk, SVG_ATTR_HEIGHT));

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_TEXT_ALIGN, -1);
	if (!is_null(token))
	{
		if (compare_text(token, -1, SVG_ATTR_TEXT_ALIGN_CENTER, -1, 1) == 0)
			prt->x -= prt->w / 2;
		else if (compare_text(token, -1, SVG_ATTR_TEXT_ALIGN_FAR, -1, 1) == 0)
			prt->x -= prt->w;
	}

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_LINE_ALIGN, -1);
	if (!is_null(token))
	{
		if (compare_text(token, -1, SVG_ATTR_TEXT_ALIGN_NEAR, -1, 1) == 0)
			prt->y -= prt->h / 2;
		else if (compare_text(token, -1, SVG_ATTR_TEXT_ALIGN_CENTER, -1, 1) == 0)
			prt->y -= prt->h / 2;
		else
			prt->y -= prt->h;
	}

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_FONT_SIZE, -1);
	if (!is_null(token))
	{
		xscpy(pxf->size, token);
	}

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_FONT_FAMILY, -1);
	if (!is_null(token))
	{
		xscpy(pxf->family, token);
	}

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_TEXT_COLOR, -1);
	if (!is_null(token))
	{
		xscpy(pxf->color, token);
	}

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_TEXT_ALIGN, -1);
	if (!is_null(token))
	{
		if (compare_text(token, -1, SVG_ATTR_TEXT_ALIGN_FAR, -1, 1) == 0)
			xscpy(pxa->text_align, GDI_ATTR_TEXT_ALIGN_FAR);
		else if (compare_text(token, -1, SVG_ATTR_TEXT_ALIGN_CENTER, -1, 1) == 0)
			xscpy(pxa->text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
		else
			xscpy(pxa->text_align, GDI_ATTR_TEXT_ALIGN_NEAR);
	}

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_LINE_ALIGN, -1);
	if (!is_null(token))
	{
		if (compare_text(token, -1, SVG_ATTR_TEXT_ALIGN_FAR, -1, 1) == 0)
			xscpy(pxa->line_align, GDI_ATTR_TEXT_ALIGN_FAR);
		else if (compare_text(token, -1, SVG_ATTR_TEXT_ALIGN_CENTER, -1, 1) == 0)
			xscpy(pxa->line_align, GDI_ATTR_TEXT_ALIGN_CENTER);
		else
			xscpy(pxa->line_align, GDI_ATTR_TEXT_ALIGN_NEAR);
	}

	return get_dom_node_text_ptr(glk);
}

void write_shape_to_svg_node(link_t_ptr glk,const xpen_t* pxp, const xrect_t* prt,const tchar_t* shape)
{
	xpoint_t pt[4] = { 0 };

	if(xsicmp(shape,ATTR_SHAPE_RECT) == 0)
	{
		write_rect_to_svg_node(glk, pxp, NULL, prt);
	}else if(xsicmp(shape,ATTR_SHAPE_ELLIPSE) == 0)
	{
		write_ellipse_to_svg_node(glk, pxp, NULL, prt);
	}else if(xsicmp(shape,ATTR_SHAPE_ROUND) == 0)
	{
		write_round_to_svg_node(glk, pxp, NULL, prt, prt->w / 10, prt->h / 10);
	}else if(xsicmp(shape,ATTR_SHAPE_LEFTLINE) == 0)
	{
		pt[0].x = prt->x;
		pt[0].y = prt->y;
		pt[1].x = prt->x;
		pt[1].y = prt->y + prt->h;
		
		write_line_to_svg_node(glk, pxp, &pt[0], &pt[1]);
	}else if(xsicmp(shape,ATTR_SHAPE_TOPLINE) == 0)
	{
		pt[0].x = prt->x;
		pt[0].y = prt->y;
		pt[1].x = prt->x + prt->w;
		pt[1].y = prt->y;
		
		write_line_to_svg_node(glk, pxp, &pt[0], &pt[1]);
	}else if(xsicmp(shape,ATTR_SHAPE_RIGHTLINE) == 0)
	{
		pt[0].x = prt->x + prt->w;
		pt[0].y = prt->y;
		pt[1].x = prt->x + prt->w;
		pt[1].y = prt->y + prt->h;
		
		write_line_to_svg_node(glk, pxp, &pt[0], &pt[1]);
	}else if(xsicmp(shape,ATTR_SHAPE_BOTTOMLINE) == 0)
	{
		pt[0].x = prt->x;
		pt[0].y = prt->y + prt->h;
		pt[1].x = prt->x + prt->w;
		pt[1].y = prt->y + prt->h;
		
		write_line_to_svg_node(glk, pxp, &pt[0], &pt[1]);
	}
	else if (xsicmp(shape, ATTR_SHAPE_TOPTRIANGLE) == 0)
	{
		pt[0].x = prt->x + prt->w / 2;
		pt[0].y = prt->y;
		pt[1].x = prt->x + prt->w;
		pt[1].y = prt->y + prt->h;
		pt[2].x = prt->x;
		pt[2].y = prt->y + prt->h;
		pt[3].x = prt->x + prt->w / 2;
		pt[3].y = prt->y;

		write_polyline_to_svg_node(glk, pxp, pt, 4);
	}
	else if (xsicmp(shape, ATTR_SHAPE_BOTTOMTRIANGLE) == 0)
	{
		pt[0].x = prt->x + prt->w / 2;
		pt[0].y = prt->y + prt->h;
		pt[1].x = prt->x;
		pt[1].y = prt->y;
		pt[2].x = prt->x + prt->w;
		pt[2].y = prt->y;
		pt[3].x = prt->x + prt->w / 2;
		pt[3].y = prt->y + prt->h;

		write_polyline_to_svg_node(glk, pxp, pt, 4);
	}
	else if (xsicmp(shape, ATTR_SHAPE_LEFTTRIANGLE) == 0)
	{
		pt[0].x = prt->x;
		pt[0].y = prt->y + prt->h / 2;
		pt[1].x = prt->x + prt->w;
		pt[1].y = prt->y;
		pt[2].x = prt->x + prt->w;
		pt[2].y = prt->y + prt->h;
		pt[3].x = prt->x;
		pt[3].y = prt->y + prt->h / 2;

		write_polyline_to_svg_node(glk, pxp, pt, 4);
	}
	else if (xsicmp(shape, ATTR_SHAPE_RIGHTTRIANGLE) == 0)
	{
		pt[0].x = prt->x + prt->w;
		pt[0].y = prt->y + prt->h / 2;
		pt[1].x = prt->x;
		pt[1].y = prt->y + prt->h;
		pt[2].x = prt->x;
		pt[2].y = prt->y;
		pt[3].x = prt->x + prt->w;
		pt[3].y = prt->y + prt->h / 2;

		write_polyline_to_svg_node(glk, pxp, pt, 4);
	}
}

static const tchar_t* _path_skip_num(const tchar_t* token)
{
	while (IS_SVG_NUM_CHAR(*token) || IS_SVG_SPACE_CHAR(*token))
		token++;

	return token;
}

bool_t svg_node_is_pie(link_t_ptr glk)
{
	const tchar_t* token;

	if (xsicmp(get_dom_node_name_ptr(glk), SVG_NODE_PATH) != 0)
		return 0;

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_D, -1);
	if (is_null(token))
		return 0;

	if (*token != _T('M'))
		return 0;

	token = _path_skip_num(token);

	if (*token != _T('L'))
		return 0;

	token = _path_skip_num(token);

	if (*token != _T('A'))
		return 0;

	token = _path_skip_num(token);

	if (*token != _T('Z'))
		return 0;

	return 1;
}

void write_pie_to_svg_node(link_t_ptr glk, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt, double fang, double tang)
{
	xpoint_t pt1, pt2;
	int tag = 0;
	double rx, ry;
	float x0, y0;
	tchar_t token[10 * INT_LEN + 1];

	set_dom_node_name(glk, SVG_NODE_PATH, -1);

	rx = (float)prt->w / 2.0f;
	ry = (float)prt->h / 2.0f;

	x0 = (float)prt->x + (float)prt->w / 2.0f;
	y0 = (float)prt->y + (float)prt->h / 2.0f;

	pt1.x = (int)((float)rx * cos(fang) + x0);
	pt1.y = (int)((float)ry * sin(fang) + y0);

	pt2.x = (int)((float)rx * cos(tang) + x0);
	pt2.y = (int)((float)ry * sin(tang) + y0);

	if (tang - fang >= XPI)
		tag = 1;

	xsprintf(token, _T("M%d %d L%d %d A%d %d 0 %d 1 %d %d Z"), (int)x0, (int)y0, pt1.x, pt1.y, (int)rx, (int)ry, tag, pt2.x, pt2.y);
	
	set_dom_node_attr(glk, SVG_ATTR_D, -1, token, -1);

	write_xpen_to_svg_node(glk, pxp);

	write_xbrush_to_svg_node(glk, pxb);
}

void read_pie_from_svg_node(link_t_ptr glk, xpen_t* pxp, xbrush_t* pxb, xrect_t* prt, double* pfang, double* ptang)
{
	const tchar_t* token;
	int x1, y1, x2, y2, x3, y3, rx, ry;
	int tan, lar, ccw;

	if (xsicmp(get_dom_node_name_ptr(glk), SVG_NODE_PATH) != 0)
		return;

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_D, -1);
	if (is_null(token))
		return;

	xsscanf(token, _T("M%d %d L%d %d A%d %d %d %d %d %d %d Z"), &x1, &y1, &x2, &y2, &rx, &ry, &tan, &lar, &ccw, &x3, &y3);

	prt->x = x1 - rx;
	prt->y = y1 - ry;
	prt->w = 2 * rx;
	prt->h = 2 * ry;

	*pfang = acos((float)(x2 - x1) / (float)rx);
	if (y1 < y2)
		*pfang = 2 * XPI - *pfang;

	*ptang = acos((float)(x3 - x1) / (float)rx);
	if (y1 <= y3)
		*ptang = 2 * XPI - *ptang;

	if (pxp)
		read_xpen_from_svg_node(glk, pxp);

	if (pxb)
		read_xbrush_from_svg_node(glk, pxb);
}

bool_t svg_node_is_fan(link_t_ptr glk)
{
	const tchar_t* token;

	if (xsicmp(get_dom_node_name_ptr(glk), SVG_NODE_PATH) != 0)
		return 0;

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_D, -1);
	if (is_null(token))
		return 0;

	if (*token != _T('M'))
		return 0;

	token = _path_skip_num(token);
	if (*token != _T('A'))
		return 0;

	token = _path_skip_num(token);
	if (*token != _T('L'))
		return 0;

	token = _path_skip_num(token);
	if (*token != _T('A'))
		return 0;

	token = _path_skip_num(token);
	if (*token != _T('Z'))
		return 0;

	return 1;
}

void write_sector_to_svg_node(link_t_ptr glk, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* prl, const xspan_t* prs, double fang, double sang)
{
	xpoint_t pa[4] = { 0 };
	int r1, r2;
	tchar_t token[12 * INT_LEN + 1];

	set_dom_node_name(glk, SVG_NODE_PATH, -1);

	r1 = prl->s;
	r2 = prs->s;

	pa[0].x = ppt->x + (int)((float)(r1) * cos(fang));
	pa[0].y = ppt->y + (int)((float)(r1) * sin(fang));

	pa[1].x = ppt->x + (int)((float)(r1) * cos(fang + sang));
	pa[1].y = ppt->y + (int)((float)(r1)* sin(fang + sang));

	pa[2].x = ppt->x + (int)((float)(r2)* cos(fang + sang));
	pa[2].y = ppt->y + (int)((float)(r2)* sin(fang + sang));

	pa[3].x = ppt->x + (int)((float)(r2) * cos(fang));
	pa[3].y = ppt->y + (int)((float)(r2) * sin(fang));

	xsprintf(token, _T("M%d %d A%d %d 0 0 1 %d %d L%d %d A%d %d 0 0 0 %d %d Z"), pa[0].x, pa[0].y, r1, r1, pa[1].x, pa[1].y, pa[2].x, pa[2].y, r2, r2, pa[3].x, pa[3].y);

	set_dom_node_attr(glk, SVG_ATTR_D, -1, token, -1);

	write_xpen_to_svg_node(glk, pxp);

	write_xbrush_to_svg_node(glk, pxb);
}

void read_sector_from_svg_node(link_t_ptr glk, xpen_t* pxp, xbrush_t* pxb, xpoint_t* ppt, xspan_t* prl, xspan_t* prs, double* pfang, double* psang)
{
	const tchar_t* token;
	int x1, y1, x2, y2, x3, y3, r, s;
	int tan, lar, ccw;

	if (xsicmp(get_dom_node_name_ptr(glk), SVG_NODE_PATH) != 0)
		return;

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_D, -1);
	if (is_null(token))
		return;

	xsscanf(token, _T("M%d %d A%d %d %d %d %d %d %d L%d %d A%d %d"), &x1, &y1, &r, &r, &tan, &lar, &ccw, &x2, &y2, &x3, &y3, &s, &s);

	prl->s = r;
	prs->s = s;

	*pfang = acos((float)(x2 - x1) / (float)r);
	if (y1 < y2)
		*pfang = 2 * XPI - *pfang;

	*psang = acos((float)(x3 - x1) / (float)r);
	*psang -= *pfang;
	if (y1 <= y3)
		*psang = 2 * XPI - *psang;

	if (pxp)
		read_xpen_from_svg_node(glk, pxp);

	if (pxb)
		read_xbrush_from_svg_node(glk, pxb);
}

bool_t svg_node_is_arc(link_t_ptr glk)
{
	const tchar_t* token;

	if (xsicmp(get_dom_node_name_ptr(glk), SVG_NODE_PATH) != 0)
		return 0;

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_D, -1);
	if (is_null(token))
		return 0;

	if (*token != _T('M'))
		return 0;

	token = _path_skip_num(token);

	if (*token != _T('A'))
		return 0;

	token = _path_skip_num(token);

	if (*token != _T('\0'))
		return 0;

	return 1;
}

void write_arc_to_svg_node(link_t_ptr glk, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t sflag, bool_t lflag)
{
	tchar_t token[10 * INT_LEN + 1];

	set_dom_node_name(glk, SVG_NODE_PATH, -1);

	xsprintf(token, _T("M%d %d A%d %d 0 %d %d %d %d"), ppt1->x, ppt1->y, pxs->w, pxs->h, (int)lflag, (int)sflag, ppt2->x, ppt2->y);

	set_dom_node_attr(glk, SVG_ATTR_D, -1, token, -1);
	set_dom_node_attr(glk, SVG_ATTR_FILL_COLOR, -1, _T("none"), -1);

	write_xpen_to_svg_node(glk, pxp);
}

void read_arc_from_svg_node(link_t_ptr glk, xpen_t* pxp, xpoint_t* ppt1, xpoint_t* ppt2, xsize_t* pxs, bool_t* psflag, bool_t* plflag)
{
	const tchar_t* token;
	int x1, y1, x2, y2, rx, ry;
	int tan, lar, ccw;

	if (xsicmp(get_dom_node_name_ptr(glk), SVG_NODE_PATH) != 0)
		return;

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_D, -1);
	if (is_null(token))
		return;

	xsscanf(token, _T("M%d %d A%d %d %d %d %d %d %d"), &x1, &y1, &rx, &ry, &tan, &lar, &ccw, &x2, &y2);

	ppt1->x = x1;
	ppt1->y = y1;
	ppt2->x = x2;
	ppt2->y = y2;

	pxs->w = rx;
	pxs->h = ry;

	*psflag = ccw;
	*plflag = lar;

	if (pxp)
		read_xpen_from_svg_node(glk, pxp);
}


static int _svg_format_path(const tchar_t* aa, int an, const xpoint_t* pp, int pn, tchar_t* buf, int max)
{
	int a, p = 0, n, total = 0;
	int r, l, s;

	if (an < 0) an = xslen(aa);

	for (a = 0; (a < an && p < pn); a++)
	{
		switch (aa[a])
		{
		case _T('M'):
			n = xsprintf(((buf) ? (buf + total) : NULL), _T("M%d,%d "), pp[p].x, pp[p].y);
			if (total + n > max)
				return total;
			total += n;
			p++;
			break;
		case _T('L'):
			n = xsprintf(((buf) ? (buf + total) : NULL), _T("L%d,%d "), pp[p].x, pp[p].y);
			if (total + n > max)
				return total;
			total += n;
			p++;
			break;
		case _T('H'):
			break;
		case _T('V'):
			break;
		case _T('C'):
			n = xsprintf(((buf) ? (buf + total) : NULL), _T("C%d,%d %d,%d %d,%d "), pp[p].x, pp[p].y, pp[p + 1].x, pp[p + 1].y, pp[p + 2].x, pp[p + 2].y);
			if (total + n > max)
				return total;
			total += n;
			p += 3;
			break;
		case _T('S'):
			n = xsprintf(((buf) ? (buf + total) : NULL), _T("S%d,%d %d,%d "), pp[p].x, pp[p].y, pp[p + 1].x, pp[p + 1].y);
			if (total + n > max)
				return total;
			total += n;
			p += 2;
			break;
		case _T('Q'):
			n = xsprintf(((buf) ? (buf + total) : NULL), _T("Q%d,%d %d,%d "), pp[p].x, pp[p].y, pp[p + 1].x, pp[p + 1].y);
			if (total + n > max)
				return total;
			total += n;
			p += 2;
			break;
		case _T('T'):
			n = xsprintf(((buf) ? (buf + total) : NULL), _T("L%d,%d "), pp[p].x, pp[p].y);
			if (total + n > max)
				return total;
			total += n;
			p++;
			break;
		case _T('A'):
			r = 0;
			s = (pp[p].x) ? 1 : 0;
			l = (pp[p].y) ? 1 : 0;

			n = xsprintf(((buf) ? (buf + total) : NULL), _T("A%d,%d %d %d,%d %d,%d "), pp[p+1].x, pp[p+1].y, r, l, s, pp[p + 2].x, pp[p + 2].y);
			if (total + n > max)
				return total;
			total += n;
			p += 3;

			break;
		case _T('Z'):
			if (buf)
			{
				buf[total] = _T('Z');
			}
			total++;

			a = an;
			break;
		}
	}

	return total;
}

void write_path_to_svg_node(link_t_ptr glk, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, int len, const xpoint_t* pa, int pn)
{
	tchar_t* buf;
	int n;

	n = _svg_format_path(aa, len, pa, pn, NULL, MAX_LONG);
	buf = xsalloc(n + 1);
	_svg_format_path(aa, len, pa, pn, buf, n);

	set_dom_node_name(glk, SVG_NODE_PATH, -1);

	set_dom_node_attr(glk, SVG_ATTR_D, -1, buf, n);

	xsfree(buf);

	write_xpen_to_svg_node(glk, pxp);

	write_xbrush_to_svg_node(glk, pxb);
}

static void _svg_parse_path(const tchar_t* token, int len, tchar_t* aa, int* an, xpoint_t* pp, int* pn)
{
	const tchar_t* str = token;
	int a = 0, p = 0, n = 0;
	int r, l, s;

	if (len < 0) len = xslen(token);

	while (str && n < len)
	{
		while (!IS_SVG_PATH_CHAR(*str))
		{
			str++;
			n++;
		}

		switch (*str)
		{
		case _T('M'):
			if (aa)
			{
				aa[a] = *str;
			}
			a++;

			str++;
			n++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//one point
			p++;

			break;
		case _T('L'):
			if (aa)
			{
				aa[a] = *str;
			}
			a++;

			str++;
			n++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//one point
			p++;

			break;
		case _T('H'):
			if (aa)
			{
				aa[a] = _T('L');
			}
			a++;

			str++;
			n++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
				pp[p].y = (p) ? pp[p - 1].y : 0;
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//one point
			p++;

			break;
		case _T('V'):
			if (aa)
			{
				aa[a] = _T('L');
			}
			a++;

			str++;
			n++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = (p) ? pp[p - 1].x : 0;
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//one point
			p++;

			break;
		case _T('C'):
			if (aa)
			{
				aa[a] = *str;
			}
			a++;

			str++;
			n++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//one point
			p++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//two point
			p++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//three point
			p++;

			break;
		case _T('S'):
			if (aa)
			{
				aa[a] = *str;
			}
			a++;

			str++;
			n++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//one point
			p++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//two point
			p++;

			break;
		case _T('Q'):
			if (aa)
			{
				aa[a] = *str;
			}
			a++;

			str++;
			n++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//one point
			p++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//two point
			p++;

			break;
		case _T('T'):
			if (aa)
			{
				aa[a] = *str;
			}
			a++;

			str++;
			n++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//one point
			p++;
			break;
		case _T('A'):
			if (aa)
			{
				aa[a] = *str;
			}
			a++;

			str++;
			n++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//rx, ry
			p++;

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			r = xstol(str);

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			l = xstol(str);

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			s = xstol(str);

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].x = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			while (IS_SVG_SPACE_CHAR(*str))
			{
				str++;
				n++;
			}

			if (pp)
			{
				pp[p].y = xstol(str);
			}

			while (IS_SVG_NUM_CHAR(*str))
			{
				str++;
				n++;
			}

			//point
			p++;

			if (s && pp)
			{
				pp[p - 2].x = 0 - pp[p - 2].x;
				pp[p - 2].y = 0 - pp[p - 2].y;
			}

			break;
		case _T('Z'):
			n = len;
			break;
		}
	}

	if (an) *an = a;
	if (pn) *pn = p;
}

void read_path_from_svg_node(link_t_ptr glk, xpen_t* pxp, xbrush_t* pxb, tchar_t* aa, int* an, xpoint_t* pa, int* pn)
{
	const tchar_t* token;
	
	if (xsicmp(get_dom_node_name_ptr(glk), SVG_NODE_PATH) != 0)
		return;

	token = get_dom_node_attr_ptr(glk, SVG_ATTR_D, -1);
	if (is_null(token))
		return;

	_svg_parse_path(token, -1, aa, an, pa, pn);
	
	if (pxp)
		read_xpen_from_svg_node(glk, pxp);

	if (pxb)
		read_xbrush_from_svg_node(glk, pxb);
}

