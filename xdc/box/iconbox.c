/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc icon control document

	@module	iconbox.c | implement file

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

#include "../xdcobj.h"


typedef struct _iconbox_delta_t{
	link_t_ptr string;

	tchar_t layer[RES_LEN + 1];
	tchar_t align[RES_LEN + 1];
}iconbox_delta_t;

#define GETICONBOXDELTA(ph) 	(iconbox_delta_t*)widget_get_user_delta(ph)
#define SETICONBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/*********************************************************************************/
void _iconbox_item_rect(widget_t widget, link_t_ptr ent, xrect_t* pxr)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);
	measure_interface im = { 0 };
	xsize_t xs;
	canvbox_t cb;

	get_canvas_measure(widget_get_canvas(widget), &im);

	widget_get_canv_rect(widget, &cb);
	xs.fw = cb.fw;
	xs.fh = cb.fh;

	calc_iconbox_item_rect(&im, ptd->layer, ptd->align, &xs, ptd->string, ent, pxr);
	widget_rect_to_mm(widget, pxr);
}

static void _iconbox_reset_page(widget_t widget)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);
	int pw, ph, vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	canvas_t canv;
	const drawing_interface* pif = NULL;
	measure_interface im = { 0 };

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);

	(pif->pf_get_measure)(pif->ctx, &im);
	(pif->pf_font_size)(pif->ctx, &xs);

	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	if (ptd->string)
	{
		calc_iconbox_size(&im, ptd->layer, ptd->align, ptd->string, &xs);
		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}
	else
	{
		vw = pw;
		vh = ph;
	}

	widget_reset_paging(widget, pw, ph, vw, vh, lw, lh);

	widget_reset_scroll(widget, 0);
}
/*********************************************************************************/
void noti_iconbox_command(widget_t widget, int code, vword_t data)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);

	if (widget_has_subproc(widget))
		widget_post_command(widget, code, IDC_SELF, data);
	else
		widget_post_command(widget_get_owner(widget), code, widget_get_user_id(widget), data);
}

void iconbox_on_click_item(widget_t widget, link_t_ptr ent)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);

	widget_erase(widget, NULL);

	noti_iconbox_command(widget, xstol(get_string_entity_key_ptr(ent)), (vword_t)NULL);
}

/*********************************************************************************/
int hand_iconbox_create(widget_t widget, void* data)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);

	ptd = (iconbox_delta_t*)xmem_alloc(sizeof(iconbox_delta_t));
	xmem_zero((void*)ptd, sizeof(iconbox_delta_t));

	ptd->string = create_string_table(0);
	
	SETICONBOXDELTA(widget, ptd);

	return 0;
}

void hand_iconbox_destroy(widget_t widget)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (ptd->string)
		destroy_string_table(ptd->string);

	xmem_free(ptd);

	SETICONBOXDELTA(widget, 0);
}

void hand_iconbox_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);
	
}

void hand_iconbox_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);
	measure_interface im = { 0 };
	xpoint_t pt;
	xsize_t xs;
	canvbox_t cb;

	link_t_ptr ilk = NULL;
	int hint;

	pt.x = pxp->x;
	pt.y = pxp->y;

	widget_point_to_mm(widget, &pt);

	get_canvas_measure(widget_get_canvas(widget), &im);

	widget_get_canv_rect(widget, &cb);
	xs.fw = cb.fw;
	xs.fh = cb.fh;

	hint = calc_iconbox_hint(&im, ptd->layer, ptd->align, &xs, &pt, ptd->string, &ilk);

	if (hint == ICONBOX_HINT_ITEM)
	{
		iconbox_on_click_item(widget, ilk);
	}
}

void hand_iconbox_size(widget_t widget, int code, const xsize_t* prs)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	switch(code)
	{
	case WS_SIZE_FULLSCREEN:
		break;
	case WS_SIZE_MAXIMIZED:
		break;
	case WS_SIZE_MINIMIZED:
		break;
	case WS_SIZE_LAYOUT:
		_iconbox_reset_page(widget);
		break;
	}
}

void hand_iconbox_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);
	visual_t rdc;
	xrect_t xr;
	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	color_mod_t clrs;
	xbrush_t xb;

	widget_get_color_mode(widget, &clrs);
	default_xbrush(&xb);
	format_xcolor(&clrs.clr_bkg, xb.color);

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);

	widget_get_client_rect(widget, &xr);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	draw_iconbox(pif, ptd->layer, ptd->align, ptd->string);

	end_canvas_paint(canv, dc, pxr);
}

/***************************************************************************************/
widget_t iconbox_create(widget_t widget, dword_t style, const xrect_t* pxr)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_iconbox_create)
		EVENT_ON_DESTROY(hand_iconbox_destroy)

		EVENT_ON_PAINT(hand_iconbox_paint)

		EVENT_ON_SIZE(hand_iconbox_size)

		EVENT_ON_LBUTTON_DOWN(hand_iconbox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_iconbox_lbutton_up)

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void iconbox_set_options(widget_t widget, const tchar_t* opt, int len)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	string_table_parse_options(ptd->string, opt, len, OPT_ITEMFEED, OPT_LINEFEED);

	widget_erase(widget, NULL);
}

void iconbox_set_layer(widget_t widget, const tchar_t* layer)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xsncpy(ptd->layer, layer, RES_LEN);
}

void iconbox_set_alignment(widget_t widget, const tchar_t* align)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xsncpy(ptd->align, align, RES_LEN);
}

void iconbox_get_item_rect(widget_t widget, const tchar_t* key, xrect_t* pxr)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);
	link_t_ptr ent;

	XDK_ASSERT(ptd != NULL);

	ent = get_string_entity(ptd->string, key, -1);
	if (ent)
	{
		_iconbox_item_rect(widget, ent, pxr);
	}
	else
	{
		xmem_zero((void*)pxr, sizeof(xrect_t));
	}
}

void iconbox_popup_size(widget_t widget, xsize_t* pxs)
{
	iconbox_delta_t* ptd = GETICONBOXDELTA(widget);
	measure_interface im = { 0 };

	XDK_ASSERT(ptd != NULL);

	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_iconbox_size(&im, ptd->layer, ptd->align, ptd->string, pxs);

	widget_size_to_pt(widget, pxs);

	adjust_widget_size(widget_get_style(widget), pxs);
}
