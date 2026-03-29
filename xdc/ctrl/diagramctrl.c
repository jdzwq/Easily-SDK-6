/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc diagram control document

	@module	diagramctrl.c | implement file

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

#include "ctrl.h"

#include "../xdcobj.h"


typedef struct _diagram_delta_t{
	link_t_ptr diagram;
	link_t_ptr entity;
	link_t_ptr hover;

	widget_t hsc;
	widget_t vsc;
}diagram_delta_t;

#define GETDIAGRAMDELTA(ph) 	(diagram_delta_t*)widget_get_user_delta(ph)
#define SETDIAGRAMDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/******************************************diagram event********************************************************/

static void _diagramctrl_entity_rect(widget_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	calc_diagram_entity_rect(ptd->diagram, ilk, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _diagramctrl_reset_page(widget_t widget)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	int pw, ph, vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	if(ptd->diagram)
	{
		if (compare_text(get_diagram_printing_ptr(ptd->diagram), -1, ATTR_PRINTING_LANDSCAPE, -1, 0) == 0)
		{
			xs.fw = get_diagram_height(ptd->diagram);
			xs.fh = get_diagram_width(ptd->diagram);
		}
		else
		{
			xs.fw = get_diagram_width(ptd->diagram);
			xs.fh = get_diagram_height(ptd->diagram);
		}

		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}else
	{
		vw = pw;
		vh = ph;
	}

	xs.fw = (float)10;
	xs.fh = (float)10;
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	widget_reset_paging(widget, pw, ph, vw, vh, lw, lh);

	widget_reset_scroll(widget, 1);

	widget_reset_scroll(widget, 0);
}

static void _diagramctrl_ensure_visible(widget_t widget)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	xrect_t xr = { 0 };

	if (!ptd->entity)
		return;

	_diagramctrl_entity_rect(widget, ptd->entity, &xr);

	widget_ensure_visible(widget, &xr, 1);
}
/*********************************************************************************************************/
int noti_diagram_owner(widget_t widget, unsigned int code, link_t_ptr ptr, link_t_ptr ilk, void* data)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	NOTICE_DIAGRAM nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;

	nf.data = data;

	nf.diagram = ptr;
	nf.entity = ilk;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);
	return nf.ret;
}

bool_t noti_diagram_entity_changing(widget_t widget)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->entity);

	if (noti_diagram_owner(widget, NC_DIAGRAMENTITYKILLFOCUS, ptd->diagram, ptd->entity, NULL))
		return (bool_t)0;

	_diagramctrl_entity_rect(widget, ptd->entity, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	ptd->entity = NULL;

	widget_erase(widget, &xr);

	return (bool_t)1;
}

void noti_diagram_entity_changed(widget_t widget, link_t_ptr ilk)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ilk);
	XDK_ASSERT(!ptd->entity);

	ptd->entity = ilk;

	_diagramctrl_entity_rect(widget, ptd->entity, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);

	noti_diagram_owner(widget, NC_DIAGRAMENTITYSETFOCUS, ptd->diagram, ilk, NULL);
}

void noti_diagram_entity_enter(widget_t widget, link_t_ptr ilk)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	XDK_ASSERT(ilk);
	XDK_ASSERT(!ptd->hover);

	ptd->hover = ilk;

	//widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
}

void noti_diagram_entity_leave(widget_t widget)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	ptd->hover = NULL;

	//widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
}

void noti_diagram_entity_hover(widget_t widget, int x, int y)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	xpoint_t pt;

	XDK_ASSERT(ptd->hover != NULL);

	pt.x = x;
	pt.y = y;
	noti_diagram_owner(widget, NC_DIAGRAMENTITYHOVER, ptd->diagram, ptd->hover, (void*)&pt);
}

void noti_diagram_calc(widget_t widget)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
}

void noti_diagram_reset_scroll(widget_t widget, bool_t bUpdate)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	if (widget_is_valid(ptd->vsc))
	{
		if (bUpdate)
			widget_erase(ptd->vsc, NULL);
		else
			widget_destroy(ptd->vsc);
	}

	if (widget_is_valid(ptd->hsc))
	{
		if (bUpdate)
			widget_erase(ptd->hsc, NULL);
		else
			widget_destroy(ptd->hsc);
	}
}

/*******************************************************************************/
int hand_diagram_create(widget_t widget, void* data)
{
	diagram_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (diagram_delta_t*)xmem_alloc(sizeof(diagram_delta_t));
	xmem_zero((void*)ptd, sizeof(diagram_delta_t));

	SETDIAGRAMDELTA(widget, ptd);

	return 0;
}

void hand_diagram_destroy(widget_t widget)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (widget_is_valid(ptd->hsc))
		widget_destroy(ptd->hsc);

	if (widget_is_valid(ptd->vsc))
		widget_destroy(ptd->vsc);

	xmem_free(ptd);

	SETDIAGRAMDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_diagram_size(widget_t widget, int code, const xsize_t* prs)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

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

	_diagramctrl_reset_page(widget);
}

void hand_diagram_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	if (!ptd->diagram)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_diagram_wheel(widget_t widget, bool_t bHorz, int nDelta)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	scroll_t scr = { 0 };
	int nLine;
	widget_t win;

	if (!ptd->diagram)
		return;

	widget_get_scroll_info(widget, bHorz, &scr);

	if (bHorz)
		nLine = (nDelta > 0) ? scr.min : -scr.min;
	else
		nLine = (nDelta < 0) ? scr.min : -scr.min;

	if (widget_hand_scroll(widget, bHorz, nLine))
	{
		if (!bHorz && !(widget_get_style(widget) & WD_STYLE_VSCROLL))
		{
			if (!widget_is_valid(ptd->vsc))
			{
				ptd->vsc = show_vertbox(widget);
			}
			else
			{
				widget_erase(ptd->vsc, NULL);
			}
		}

		if (bHorz && !(widget_get_style(widget) & WD_STYLE_HSCROLL))
		{
			if (!widget_is_valid(ptd->hsc))
			{
				ptd->hsc = show_horzbox(widget);
			}
			else
			{
				widget_erase(ptd->hsc, NULL);
			}
		}

		return;
	}

	win = widget_get_parent(widget);

	if (widget_is_valid(win))
	{
		widget_scroll(win, bHorz, nLine);
	}
}

void hand_diagram_mouse_move(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	link_t_ptr ilk;
	xpoint_t pt;

	if (!ptd->diagram)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	ilk = NULL;
	calc_diagram_hint(&pt, ptd->diagram, &ilk);

	if (widget_is_hotvoer(widget))
	{
		if (!ptd->hover && ilk)
		{
			noti_diagram_entity_enter(widget, ilk);
			return;
		}

		if (ptd->hover && ptd->hover != ilk)
		{
			noti_diagram_entity_leave(widget);
			return;
		}

		if (ptd->hover)
		{
			noti_diagram_entity_leave(widget);
		}
	}
}

void hand_diagram_mouse_hover(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	if (!ptd->diagram)
		return;

	if (ptd->hover)
		noti_diagram_entity_hover(widget, pxp->x, pxp->y);
}

void hand_diagram_mouse_leave(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	if (!ptd->diagram)
		return;

	if (ptd->hover)
		noti_diagram_entity_leave(widget);
}

void hand_diagram_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	if (!ptd->diagram)
		return;

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}
}

void hand_diagram_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	link_t_ptr ilk;
	bool_t bRe;
	xpoint_t pt;

	if (!ptd->diagram)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	ilk = NULL;
	calc_diagram_hint(&pt, ptd->diagram, &ilk);

	noti_diagram_owner(widget, NC_DIAGRAMLBCLK, ptd->diagram, ilk, (void*)pxp);

	bRe = (ilk == ptd->entity) ? 1 : 0;

	if (ptd->entity && !bRe)
	{
		if (!noti_diagram_entity_changing(widget))
			return;
	}

	if (ilk && !bRe)
	{
		noti_diagram_entity_changed(widget, ilk);
	}
}

void hand_diagram_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	if (!ptd->diagram)
		return;

	noti_diagram_owner(widget, NC_DIAGRAMDBCLK, ptd->diagram, ptd->entity, (void*)pxp);
}

void hand_diagram_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	if (!ptd->diagram)
		return;
}

void hand_diagram_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	if (!ptd->diagram)
		return;

	noti_diagram_owner(widget, NC_DIAGRAMRBCLK, ptd->diagram, ptd->entity, (void*)pxp);
}

void hand_diagram_keydown(widget_t widget, dword_t ks, int nKey)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	if (!ptd->diagram)
		return;
}

void hand_diagram_notice(widget_t widget, NOTICE* pnt)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	if (!ptd->diagram)
		return;
}

void hand_diagram_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	xrect_t xr = { 0 };
	visual_t rdc;
	link_t_ptr ilk;

	canvas_t canv;
	drawing_interface ifc = {0};
	drawing_interface ifv = {0};

	const color_mod_t *pclrs;
	xbrush_t xb;
	xpen_t xp;
	xcolor_t xc;

	if (!ptd->diagram) return;

	pclrs = widget_get_color_mode_ptr(widget);
	default_xbrush(&xb);
	format_xcolor(&(pclrs->clr_bkg), xb.color);
	default_xpen(&xp);
	format_xcolor(&(pclrs->clr_frg), xp.color);

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);
	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
	
	get_visual_interface(rdc, &ifv);
	widget_get_view_rect(widget, (viewbox_t*)&(ifv.rect));

	get_canvas_interface(canv, &ifc);
	widget_get_canv_rect(widget, (canvbox_t*)&(ifc.rect));
	ifc.pclrs = pclrs;

	(*ifv.drw->pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	draw_diagram(&ifc, ptd->diagram);
	
	//draw focus
	if (ptd->entity)
	{
		_diagramctrl_entity_rect(widget, ptd->entity, &xr);

		parse_xcolor(&xc, DEF_ENABLE_COLOR);

		draw_focus_raw(&ifv, &xc, &xr, ALPHA_SOLID);
	}

	end_canvas_paint(canv, dc, pxr);
}

/***********************************************function********************************************************/

widget_t diagramctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_diagram_create)
		EVENT_ON_DESTROY(hand_diagram_destroy)

		EVENT_ON_PAINT(hand_diagram_paint)

		EVENT_ON_SIZE(hand_diagram_size)

		EVENT_ON_SCROLL(hand_diagram_scroll)
		EVENT_ON_WHEEL(hand_diagram_wheel)

		EVENT_ON_KEYDOWN(hand_diagram_keydown)

		EVENT_ON_MOUSE_MOVE(hand_diagram_mouse_move)
		EVENT_ON_MOUSE_HOVER(hand_diagram_mouse_hover)
		EVENT_ON_MOUSE_LEAVE(hand_diagram_mouse_leave)

		EVENT_ON_LBUTTON_DBCLICK(hand_diagram_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_diagram_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_diagram_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_diagram_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_diagram_rbutton_up)

		EVENT_ON_NOTICE(hand_diagram_notice)

		

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void diagramctrl_attach(widget_t widget, link_t_ptr ptr)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(ptr && is_diagram_doc(ptr));

	ptd->diagram = ptr;
	ptd->entity = NULL;

	diagramctrl_redraw(widget);
}

link_t_ptr diagramctrl_detach(widget_t widget)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	link_t_ptr data;

	XDK_ASSERT(ptd != NULL);

	data = ptd->diagram;
	ptd->diagram = NULL;
	ptd->entity = NULL;

	widget_erase(widget, NULL);

	return data;
}

link_t_ptr diagramctrl_fetch(widget_t widget)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->diagram;
}

void diagramctrl_redraw(widget_t widget)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	link_t_ptr ilk;
	bool_t b_valid;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->diagram)
		return;

	b_valid = 0;
	ilk = get_diagram_next_entity(ptd->diagram, LINK_FIRST);
	while (ilk)
	{
		if (ilk == ptd->entity)
			b_valid = 1;

		noti_diagram_owner(widget, NC_DIAGRAMENTITYCALCED, ptd->diagram, ilk, NULL);

		ilk = get_diagram_next_entity(ptd->diagram, ilk);
	}
	
	noti_diagram_owner(widget, NC_DIAGRAMCALCED, ptd->diagram, NULL, NULL);

	if (!b_valid)
	{
		ptd->entity = NULL;
	}
	ptd->hover = NULL;

	_diagramctrl_reset_page(widget);
	widget_erase(widget, NULL);
}

void diagramctrl_redraw_entity(widget_t widget, link_t_ptr ilk)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->diagram)
		return;

#ifdef _DEBUG
	if(!is_diagram_entity(ptd->diagram, ilk))
		return;
#endif

	noti_diagram_owner(widget, NC_DIAGRAMENTITYCALCED, ptd->diagram, ilk, NULL);

	_diagramctrl_entity_rect(widget, ilk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

void diagramctrl_tabskip(widget_t widget, int nSkip)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	link_t_ptr ilk = NULL;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->diagram)
		return;

	switch (nSkip)
	{
	case TABORDER_LEFT:
	case TABORDER_UP:
		if (ptd->entity == NULL)
			ilk = get_diagram_prev_entity(ptd->diagram, LINK_LAST);
		else
			ilk = get_diagram_prev_entity(ptd->diagram, ptd->entity);
		break;
	case TABORDER_RIGHT:
	case TABORDER_DOWN:
		if (ptd->entity == NULL)
			ilk = get_diagram_next_entity(ptd->diagram, LINK_FIRST);
		else
			ilk = get_diagram_next_entity(ptd->diagram, ptd->entity);
		break;
	case TABORDER_HOME:
		ilk = get_diagram_next_entity(ptd->diagram, LINK_FIRST);
		break;
	case TABORDER_END:
		ilk = get_diagram_prev_entity(ptd->diagram, LINK_LAST);
		break;
	}

	diagramctrl_set_focus_entity(widget, ilk);
}

bool_t diagramctrl_set_focus_entity(widget_t widget, link_t_ptr ilk)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	bool_t bRe;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->diagram)
		return 0;

	if (ilk == LINK_FIRST)
		ilk = get_diagram_next_entity(ptd->diagram, LINK_FIRST);
	else if (ilk == LINK_LAST)
		ilk = get_diagram_prev_entity(ptd->diagram, LINK_LAST);

	bRe = (ilk == ptd->entity) ? (bool_t)1 : (bool_t)0;
	if (bRe)
		return (bool_t)1;

	if (ptd->entity && !bRe)
	{
		if (!noti_diagram_entity_changing(widget))
			return (bool_t)0;
	}

	if (ilk && !bRe)
	{
		noti_diagram_entity_changed(widget, ilk);

		_diagramctrl_ensure_visible(widget);
	}

	return (bool_t)1;
}

link_t_ptr diagramctrl_get_focus_entity(widget_t widget)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->diagram)
		return NULL;

	return ptd->entity;
}

void diagramctrl_get_diagram_entity_rect(widget_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	if (!ptd->diagram)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_diagram_entity(ptd->diagram, ilk));
#endif

	_diagramctrl_entity_rect(widget, ilk, pxr);
}

bool_t diagramctrl_get_dirty(widget_t widget)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->diagram)
		return 0;

	return 0;
}

void diagramctrl_set_dirty(widget_t widget, bool_t bDirty)
{
	diagram_delta_t* ptd = GETDIAGRAMDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->diagram)
		return;
}
