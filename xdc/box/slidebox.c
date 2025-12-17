/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc slide control document

	@module	slidebox.c | implement file

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


typedef struct _slidebox_delta_t{
	int n_pos;
	bool_t b_move;

}slidebox_delta_t;

#define GETSLIDEBOXDELTA(ph) 	(slidebox_delta_t*)widget_get_user_delta(ph)
#define SETSLIDEBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/*********************************************************************************/
void noti_slidebox_command(widget_t widget, int code, vword_t data)
{
	slidebox_delta_t* ptd = GETSLIDEBOXDELTA(widget);

	if (widget_has_subproc(widget))
		widget_post_command(widget, code, IDC_SELF, data);
	else
		widget_post_command(widget_get_owner(widget), code, widget_get_user_id(widget), data);
}

void slidebox_on_moving(widget_t widget, const xpoint_t* pxp)
{
	slidebox_delta_t* ptd = GETSLIDEBOXDELTA(widget);

	ptd->b_move = 1;

	if (widget_can_focus(widget))
	{
		widget_set_capture(widget, 1);
	}
	widget_set_cursor(widget, CURSOR_HAND);
}

void slidebox_on_moved(widget_t widget, const xpoint_t* pxp)
{
	slidebox_delta_t* ptd = GETSLIDEBOXDELTA(widget);
	measure_interface im = { 0 };

	xpoint_t pt;
	int hint;

	ptd->b_move = 0;
	if (widget_can_focus(widget))
	{
		widget_set_capture(widget, 0);
	}
	widget_set_cursor(widget, CURSOR_HAND);

	pt.x = pxp->x;
	pt.y = pxp->y;

	widget_point_to_mm(widget, &pt);

	get_canvas_measure(widget_get_canvas(widget), &im);

	hint = calc_slidebox_hint(&im, &pt);
	if (hint == ptd->n_pos)
		return;

	ptd->n_pos = hint;

	widget_erase(widget, NULL);

	noti_slidebox_command(widget, COMMAND_UPDATE, (vword_t)NULL);
}
/*********************************************************************************/
int hand_slidebox_create(widget_t widget, void* data)
{
	slidebox_delta_t* ptd ;

	widget_hand_create(widget);

	ptd = (slidebox_delta_t*)xmem_alloc(sizeof(slidebox_delta_t));
	xmem_zero((void*)ptd, sizeof(slidebox_delta_t));

	SETSLIDEBOXDELTA(widget, ptd);

	return 0;
}

void hand_slidebox_destroy(widget_t widget)
{
	slidebox_delta_t* ptd = GETSLIDEBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETSLIDEBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_slidebox_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	slidebox_delta_t* ptd = GETSLIDEBOXDELTA(widget);
	
	slidebox_on_moving(widget, pxp);
}

void hand_slidebox_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	slidebox_delta_t* ptd = GETSLIDEBOXDELTA(widget);
	
	slidebox_on_moved(widget, pxp);
}

void hand_slidebox_size(widget_t widget, int code, const xsize_t* prs)
{
	slidebox_delta_t* ptd = GETSLIDEBOXDELTA(widget);
	
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
		break;
	}
}

void hand_slidebox_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	slidebox_delta_t* ptd = GETSLIDEBOXDELTA(widget);
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

	draw_slidebox(pif, ptd->n_pos);

	end_canvas_paint(canv, dc, pxr);
}

/***************************************************************************************/
widget_t slidebox_create(widget_t widget, dword_t style, const xrect_t* pxr)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_slidebox_create)
		EVENT_ON_DESTROY(hand_slidebox_destroy)

		EVENT_ON_PAINT(hand_slidebox_paint)

		EVENT_ON_SIZE(hand_slidebox_size)

		EVENT_ON_LBUTTON_DOWN(hand_slidebox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_slidebox_lbutton_up)

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void slidebox_popup_size(widget_t widget, xsize_t* pxs)
{
	slidebox_delta_t* ptd = GETSLIDEBOXDELTA(widget);
	measure_interface im = { 0 };

	XDK_ASSERT(ptd != NULL);

	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_slidebox_size(&im, pxs);

	widget_size_to_pt(widget, pxs);

	adjust_widget_size(widget_get_style(widget), pxs);
}

void slidebox_set_slide(widget_t widget, int pos)
{
	slidebox_delta_t* ptd = GETSLIDEBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->n_pos = pos;

	widget_erase(widget, NULL);
}

int slidebox_get_slide(widget_t widget)
{
	slidebox_delta_t* ptd = GETSLIDEBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->n_pos;
}
