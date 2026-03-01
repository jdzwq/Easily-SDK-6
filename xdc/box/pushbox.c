/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc push control document

	@module	pushbox.c | implement file

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


#define PUSHBOX_ATTR_BUTTON_SPAN	(float)5 //TM

typedef struct _pushbox_delta_t{
	tchar_t* sz_text;
	bool_t b_check;

}pushbox_delta_t;

#define GETPUSHBOXDELTA(ph) 	(pushbox_delta_t*)widget_get_user_delta(ph)
#define SETPUSHBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/********************************************************************************/
static void _pushbox_reset_page(widget_t widget)
{
	pushbox_delta_t* ptd = GETPUSHBOXDELTA(widget);
	xrect_t xr;

	widget_get_client_rect(widget, &xr);

	widget_reset_paging(widget, xr.w, xr.h, xr.w, xr.h, 0, 0);
}

/**********************************************************************************/
int hand_pushbox_create(widget_t widget, void* data)
{
	pushbox_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (pushbox_delta_t*)xmem_alloc(sizeof(pushbox_delta_t));
	xmem_zero((void*)ptd, sizeof(pushbox_delta_t));

	SETPUSHBOXDELTA(widget, ptd);

	return 0;
}

void hand_pushbox_destroy(widget_t widget)
{
	pushbox_delta_t* ptd = GETPUSHBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (ptd->sz_text)
		xsfree(ptd->sz_text);

	xmem_free(ptd);

	SETPUSHBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_pushbox_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	pushbox_delta_t* ptd = GETPUSHBOXDELTA(widget);
	dword_t ws;

	ws = widget_get_style(widget);
	
	if (widget_can_focus(widget))
	{
		widget_set_capture(widget, 1);
	}

	if (!(ws & WD_PUSHBOX_CHECK))
	{
		ptd->b_check = 1;
		widget_erase(widget, NULL);
	}
}

void hand_pushbox_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	pushbox_delta_t* ptd = GETPUSHBOXDELTA(widget);
	dword_t ws;

	ws = widget_get_style(widget);

	if (widget_can_focus(widget))
	{
		widget_set_capture(widget, 0);
	}

	if (ws & WD_PUSHBOX_CHECK)
	{
		if (ptd->b_check)
			ptd->b_check = 0;
		else
			ptd->b_check = 1;
	}
	else
	{
		ptd->b_check = 0;
	}

	widget_erase(widget, NULL);

	widget_send_command(widget_get_owner(widget), ptd->b_check, widget_get_user_id(widget), (vword_t)widget);
}

void hand_pushbox_size(widget_t widget, int code, const xsize_t* prs)
{
	pushbox_delta_t* ptd = GETPUSHBOXDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	switch(code)
	{
	case WS_SIZE_FULLSCREEN:
		break;
	case WS_SIZE_MAXIMIZED:
		break;
	case WS_SIZE_MINIMIZED:
		break;
	case WS_SIZE_MAXSHOW:
		break;
	case WS_SIZE_RESTORE:
		break;
	case WS_SIZE_LAYOUT:
		break;
	}

	_pushbox_reset_page(widget);
}

void hand_pushbox_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	pushbox_delta_t* ptd = GETPUSHBOXDELTA(widget);
	visual_t rdc;

	dword_t ws;
	xrect_t xr,xr_box;

	const color_mod_t *pclrs;
	xcolor_t xc;
	xfont_t xf;
	xface_t xa;
	xbrush_t xb;
	xpen_t xp;
	ximage_t xi;

	canvas_t canv;
	drawing_interface ifc = {0};
	drawing_interface ifv = {0};

	pclrs = widget_get_color_mode_ptr(widget);
	default_xpen(&xp);
	format_xcolor(&(pclrs->clr_bkg), xp.color);
	lighten_xpen(&xp, DEF_HARD_DARKEN);
	default_xbrush(&xb);
	format_xcolor(&(pclrs->clr_bkg), xb.color);

	xmem_copy((void*)&xc, (void*)&(pclrs->clr_ico), sizeof(xcolor_t));
	default_xface(&xa);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);
	format_xcolor(&(pclrs->clr_txt), xa.text_color);

	default_xfont(&xf);
	xscpy(xf.size, GDI_ATTR_FONT_SIZE_FOOTER);

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);
	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
	
	get_visual_interface(rdc, &ifv);
	widget_get_view_rect(widget, (viewbox_t*)&(ifv.rect));

	get_canvas_interface(canv, &ifc);
	widget_get_canv_rect(widget, (canvbox_t*)&(ifc.rect));
	ifc.pclrs = pclrs;

	(*ifv.pf_set_xfont)(ifv.ctx, &xf);
	
	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	ws = widget_get_style(widget);

	if (ws & WD_PUSHBOX_CHECK)
	{
		xr_box.fx = ifc.rect.fx;
		xr_box.fy = ifc.rect.fy;
		xr_box.fw = DEF_SMALL_ICON;
		xr_box.fh = ifc.rect.fh;
		ft_center_rect(&xr_box, DEF_SMALL_ICON, DEF_SMALL_ICON);

		if (ptd->b_check)
			draw_gizmo(&ifc, &xc, &xr_box, GDI_ATTR_GIZMO_CHECKED);
		else
			draw_gizmo(&ifc, &xc, &xr_box, GDI_ATTR_GIZMO_CHECKBOX);

		xr_box.fx = ifc.rect.fx + DEF_SMALL_ICON;
		xr_box.fy = ifc.rect.fy;
		xr_box.fw = ifc.rect.fw - DEF_SMALL_ICON;
		xr_box.fh = ifc.rect.fh;

		xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_NEAR);
		(ifc.pf_draw_text)(ifc.ctx, &xa, &xr_box, ptd->sz_text, -1);
	}
	else if (ws & WD_PUSHBOX_ICON)
	{
		xr_box.fx = ifc.rect.fx;
		xr_box.fy = ifc.rect.fy;
		xr_box.fw = ifc.rect.fw;
		xr_box.fh = ifc.rect.fh;
		ft_expand_rect(&xr_box, -0.5, -0.5);

		if (ptd->b_check)
		{
			format_xcolor(&(pclrs->clr_frg), xp.color);
			(ifc.pf_draw_rect)(ifc.ctx, &xp, NULL, &xr_box);
		}
		else
		{
			(ifc.pf_draw_rect)(ifc.ctx, &xp, NULL, &xr_box);
		}

		xr_box.fx = ifc.rect.fx;
		xr_box.fy = ifc.rect.fy;
		xr_box.fw = ifc.rect.fw;
		xr_box.fh = ifc.rect.fh;

		ft_center_rect(&xr_box, DEF_SMALL_ICON, DEF_SMALL_ICON);
		draw_gizmo(&ifc, &xc, &xr_box, ptd->sz_text);
	}
	else if (ws & WD_PUSHBOX_IMAGE)
	{
		xr_box.fx = ifc.rect.fx;
		xr_box.fy = ifc.rect.fy;
		xr_box.fw = ifc.rect.fw;
		xr_box.fh = ifc.rect.fh;
		ft_expand_rect(&xr_box, -0.5, -0.5);

		if (ptd->b_check)
		{
			format_xcolor(&(pclrs->clr_frg), xp.color);
			(ifc.pf_draw_rect)(ifc.ctx, &xp, NULL, &xr_box);
		}
		else
		{
			(ifc.pf_draw_rect)(ifc.ctx, &xp, NULL, &xr_box);
		}

		xr_box.fx = ifc.rect.fx;
		xr_box.fy = ifc.rect.fy;
		xr_box.fw = ifc.rect.fw;
		xr_box.fh = ifc.rect.fh;

		parse_ximage_from_source(&xi, ptd->sz_text);
		(ifc.pf_draw_image)(ifc.ctx, &xi, &xr_box);
	}
	else
	{
		xr_box.fx = ifc.rect.fx;
		xr_box.fy = ifc.rect.fy;
		xr_box.fw = ifc.rect.fw;
		xr_box.fh = ifc.rect.fh;
		ft_expand_rect(&xr_box, -0.5, -0.5);

		if (ptd->b_check)
		{
			format_xcolor(&(pclrs->clr_frg), xp.color);
			(ifc.pf_draw_rect)(ifc.ctx, &xp, NULL, &xr_box);
		}
		else
		{
			(ifc.pf_draw_rect)(ifc.ctx, &xp, NULL, &xr_box);
		}

		xr_box.fx = ifc.rect.fx;
		xr_box.fy = ifc.rect.fy;
		xr_box.fw = ifc.rect.fw;
		xr_box.fh = ifc.rect.fh;

		xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
		(ifc.pf_draw_text)(ifc.ctx, &xa, &xr_box, ptd->sz_text, -1);
	}

	end_canvas_paint(canv, dc, pxr);
}

/***************************************************************************************/
widget_t pushbox_create(widget_t widget, dword_t style, const xrect_t* pxr)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_pushbox_create)
		EVENT_ON_DESTROY(hand_pushbox_destroy)

		EVENT_ON_PAINT(hand_pushbox_paint)

		EVENT_ON_SIZE(hand_pushbox_size)

		EVENT_ON_LBUTTON_DOWN(hand_pushbox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_pushbox_lbutton_up)

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void pushbox_set_state(widget_t widget, bool_t bChecked)
{
	pushbox_delta_t* ptd = GETPUSHBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_check = bChecked;
}

bool_t pushbox_get_state(widget_t widget)
{
	pushbox_delta_t* ptd = GETPUSHBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->b_check;
}

void pushbox_set_text(widget_t widget, const tchar_t* text, int len)
{
	pushbox_delta_t* ptd = GETPUSHBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (ptd->sz_text)
		xsfree(ptd->sz_text);

	if (len < 0)
		len = xslen(text);

	ptd->sz_text = xsalloc(len + 1);
	xsncpy(ptd->sz_text, text, len);

	widget_erase(widget, NULL);
}

void pushbox_popup_size(widget_t widget, xsize_t* pxs)
{
	pushbox_delta_t* ptd = GETPUSHBOXDELTA(widget);
	xsize_t xs;
	drawing_interface ifc = {0};

	XDK_ASSERT(ptd != NULL);

	get_canvas_interface(widget_get_canvas(widget), &ifc);

	(ifc.pf_text_size)(ifc.ctx, ptd->sz_text, -1, &xs);

	if (xs.fw < xs.fh)
		xs.fw = xs.fh;

	widget_size_to_pt(widget, pxs);

	adjust_widget_size(widget_get_style(widget), pxs);
}
