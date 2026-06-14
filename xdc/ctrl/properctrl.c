/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc proper control document

	@module	properctrl.c | implement file

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


typedef struct _proper_delta_t{
	link_t_ptr proper;
	link_t_ptr entity;
	link_t_ptr hover;

	int org_x, org_y;

	bool_t b_size;
	bool_t b_lock;
}proper_delta_t;

#define GETPROPERDELTA(ph) 	(proper_delta_t*)widget_get_user_delta(ph)
#define SETPROPERDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/***********************************************************************/

static void _properctrl_section_rect(widget_t widget, link_t_ptr sec, xrect_t* pxr)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	calc_proper_section_rect(ptd->proper,sec, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _properctrl_entity_rect(widget_t widget, link_t_ptr ent, xrect_t* pxr)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	calc_proper_entity_rect(ptd->proper, ent, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _properctrl_entity_text_rect(widget_t widget, link_t_ptr ent, xrect_t* pxr)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	calc_proper_entity_text_rect(ptd->proper, ent, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _properctrl_reset_page(widget_t widget)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	int pw, ph, vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	if (ptd->proper)
	{
		widget_size_to_mm(widget, RECTSIZE(&xr));
		set_proper_width(ptd->proper, xr.fw);
		set_proper_height(ptd->proper, xr.fh);

		xs.fw = calc_proper_width(ptd->proper);
		xs.fh = calc_proper_height(ptd->proper);

		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		if (vw < pw)
			vw = pw;
		vh = xs.h;
	}
	else
	{
		vw = pw;
		vh = ph;
	}

	if (ptd->proper)
	{
		xs.fw = get_proper_item_height(ptd->proper);
		xs.fh = get_proper_item_height(ptd->proper);
	}
	else
	{
		xs.fw = 50.f;
		xs.fh = 5.0f;
	}
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	widget_reset_paging(widget, pw, ph, vw, vh, lw, lh);

	widget_reset_scroll(widget, 1);
	widget_reset_scroll(widget, 0);
}

static void _properctrl_ensure_visible(widget_t widget)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	xrect_t xr = { 0 };

	if (!ptd->entity)
		return;

	_properctrl_entity_rect(widget, ptd->entity, &xr);

	widget_ensure_visible(widget, &xr, 1);
}

/***********************************************************************/

int noti_proper_owner(widget_t widget, unsigned int code, link_t_ptr proper, link_t_ptr slk, link_t_ptr elk, void* data)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	NOTICE_PROPER nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;
	nf.data = data;
	nf.ret = 0;

	nf.proper = proper;
	nf.section = slk;
	nf.entity = elk;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);

	return nf.ret;
}

void noti_proper_begin_size(widget_t widget, int x, int y)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	ptd->org_x = x;
	ptd->org_y = y;
	ptd->b_size = 1;

	if (widget_can_focus(widget))
	{
		widget_set_capture(widget, 1);
	}
	widget_set_cursor(widget,CURSOR_SIZEWE);
}

void noti_proper_end_size(widget_t widget, int x, int y)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	float pw, iw, ew;
	xsize_t xs = { 0 };

	ptd->b_size = 0;

	if (widget_can_focus(widget))
	{
		widget_set_capture(widget, 0);
	}
	widget_set_cursor(widget, CURSOR_ARROW);

	pw = get_proper_width(ptd->proper);
	ew = get_proper_item_span(ptd->proper);
	iw = get_proper_icon_span(ptd->proper);

	xs.w = x - ptd->org_x;
	widget_size_to_mm(widget, &xs);

	ew += xs.fw;
	if (ew < iw)
		ew = iw;
	else if (ew > pw)
		ew = pw;

	set_proper_item_span(ptd->proper, ew);

	widget_erase(widget, NULL);
}

bool_t noti_proper_entity_changing(widget_t widget)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->entity);

	if (noti_proper_owner(widget, NC_ENTITYCHANGING, ptd->proper, section_from_entity(ptd->entity), ptd->entity, NULL))
		return 0;

	_properctrl_entity_rect(widget, ptd->entity, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	ptd->entity = NULL;

	widget_erase(widget, &xr);

	return 1;
}

void noti_proper_entity_changed(widget_t widget, link_t_ptr elk)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(!ptd->entity);

	ptd->entity = elk;

	_properctrl_entity_rect(widget, ptd->entity, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);

	noti_proper_owner(widget, NC_ENTITYCHANGED, ptd->proper, section_from_entity(ptd->entity), ptd->entity, NULL);
}

void noti_proper_entity_enter(widget_t widget, link_t_ptr plk)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	XDK_ASSERT(plk);
	XDK_ASSERT(!ptd->hover);

	ptd->hover = plk;

	widget_enable_hover(widget, bool_true);
}

void noti_proper_entity_leave(widget_t widget)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	ptd->hover = NULL;

	widget_enable_hover(widget, bool_false);
}

void noti_proper_entity_hover(widget_t widget, int x, int y)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	xpoint_t xp;

	XDK_ASSERT(ptd->hover != NULL);

	xp.x = x;
	xp.y = y;
	noti_proper_owner(widget, NC_ENTITYHOVER, ptd->proper, NULL, ptd->hover, (void*)&xp);
}

void noti_proper_section_expand(widget_t widget, link_t_ptr slk)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	xrect_t xr_sec, xr;

	if (get_section_collapsed(slk))
	{
		set_section_collapsed(slk, 0);
	}
	else
	{
		set_section_collapsed(slk, 1);
	}

	_properctrl_section_rect(widget, slk, &xr_sec);
	widget_get_client_rect(widget, &xr);

	pt_inter_rect(&xr, &xr_sec);
	widget_erase(widget, &xr);
}

void noti_proper_reset_editor(widget_t widget, bool_t bCommit)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	if (bCommit)
		widget_post_command(widget, COMMAND_COMMIT, IDC_CHILD, (vword_t)0);
	else
		widget_post_command(widget, COMMAND_ROLLBACK, IDC_CHILD, (vword_t)0);
}

/***********************************************************************/

int hand_proper_create(widget_t widget, void* data)
{
	proper_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (proper_delta_t*)xmem_alloc(sizeof(proper_delta_t));

	SETPROPERDELTA(widget, ptd);

	return 0;
}

void hand_proper_destroy(widget_t widget)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETPROPERDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_proper_size(widget_t widget, int code, const xsize_t* prs)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	XDK_ASSERT(ptd != NULL);
	
	_properctrl_reset_page(widget);

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
		widget_erase(widget, NULL);
		break;
	}
}

void hand_proper_notice(widget_t widget, NOTICE* pnt)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	if (!ptd->proper)
		return;
}

void hand_proper_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	if (!ptd->proper)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_proper_wheel(widget_t widget, bool_t bHorz, int nDelta)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	if (!ptd->proper)
		return;

	widget_hand_wheel(widget, bHorz, nDelta);
}

void hand_proper_mouse_move(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	link_t_ptr slk, elk;
	int nHint;
	xpoint_t pt;

	if (!ptd->proper)
		return;

	if (ptd->b_size)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	slk = elk = NULL;
	nHint = calc_proper_hint(&pt, ptd->proper, &slk, &elk);

	if (nHint == PROPER_HINT_VERT_SPLIT && !(dw & KS_WITH_CONTROL))
	{
		if (dw & MS_WITH_LBUTTON)
		{
			noti_proper_begin_size(widget, pxp->x, pxp->y);
			return;
		}else
			widget_set_cursor(widget, CURSOR_SIZEWE);
	}

	if (nHint == PROPER_HINT_ENTITY && !ptd->hover && elk)
	{
		noti_proper_entity_enter(widget, elk);
	}
	else if (nHint == PROPER_HINT_ENTITY && ptd->hover && ptd->hover != elk)
	{
		noti_proper_entity_leave(widget);
	}
	else if (nHint != PROPER_HINT_ENTITY && ptd->hover)
	{
		noti_proper_entity_leave(widget);
	}
}

void hand_proper_mouse_hover(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	if (!ptd->proper)
		return;

	if (ptd->hover)
	{
		noti_proper_entity_hover(widget, pxp->x, pxp->y);
	}
}

void hand_proper_mouse_leave(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	if (!ptd->proper)
		return;

	if (ptd->hover)
		noti_proper_entity_leave(widget);
}

void hand_proper_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->proper)
		return;

	noti_proper_owner(widget, NC_PROPERDBCLK, ptd->proper, ((ptd->entity) ? section_from_entity(ptd->entity) : NULL), ptd->entity, (void*)pxp);
}

void hand_proper_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	link_t_ptr slk, elk;
	int nHint;
	xpoint_t pt;

	if (!ptd->proper)
		return;

	noti_proper_reset_editor(widget, 1);

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	slk = elk = NULL;
	nHint = calc_proper_hint(&pt, ptd->proper, &slk, &elk);

	if (nHint == PROPER_HINT_SECTION)
	{
		noti_proper_section_expand(widget, slk);
		return;
	}
}

void hand_proper_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	link_t_ptr slk, elk;
	xpoint_t pt;
	int nHint;
	bool_t bRe;

	if (!ptd->proper)
		return;

	if (ptd->b_size)
	{
		noti_proper_end_size(widget, pxp->x, pxp->y);
		return;
	}

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	slk = elk = NULL;
	nHint = calc_proper_hint(&pt, ptd->proper, &slk, &elk);

	bRe = (elk == ptd->entity) ? 1 : 0;

	if (bRe && !ptd->b_lock && ptd->entity && get_entity_editable(ptd->entity))
	{
		widget_post_key(widget, KEY_ENTER);
		return;
	}

	if (!bRe && ptd->entity)
	{
		if (!noti_proper_entity_changing(widget))
			bRe = 1;
	}

	if (!bRe && elk)
	{
		noti_proper_entity_changed(widget, elk);
	}

	noti_proper_owner(widget, NC_PROPERLBCLK, ptd->proper, ((ptd->entity) ? section_from_entity(ptd->entity) : NULL), ptd->entity, (void*)pxp);
}

void hand_proper_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	if (!ptd->proper)
		return;

	noti_proper_reset_editor(widget, 1);
}

void hand_proper_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	if (!ptd->proper)
		return;

	noti_proper_owner(widget, NC_PROPERRBCLK, ptd->proper, ((ptd->entity)? section_from_entity(ptd->entity) : NULL), ptd->entity, (void*)pxp);
}

void hand_proper_keydown(widget_t widget, dword_t ks, int nKey)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	if (!ptd->proper)
		return;

	switch (nKey)
	{
	case KEY_LEFT:
		properctrl_tabskip(widget,TABORDER_LEFT);
		break;
	case KEY_RIGHT:
		properctrl_tabskip(widget,TABORDER_RIGHT);
		break;
	case KEY_UP:
		properctrl_tabskip(widget,TABORDER_UP);
		break;
	case KEY_DOWN:
		properctrl_tabskip(widget,TABORDER_DOWN);
		break;
	case KEY_END:
		properctrl_tabskip(widget,TABORDER_END);
		break;
	case KEY_HOME:
		properctrl_tabskip(widget,TABORDER_HOME);
		break;
	case KEY_PAGEUP:
		properctrl_tabskip(widget,TABORDER_PAGEUP);
		break;
	case KEY_PAGEDOWN:
		properctrl_tabskip(widget,TABORDER_PAGEDOWN);
		break;
	}
}

void hand_proper_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	visual_t rdc;
	xpen_t xp = { 0 };
	xrect_t xr = { 0 };

	canvas_t canv;
	drawing_interface ifc = {0};
	drawing_interface ifv = {0};

	const color_mod_t *pclrs;
	xbrush_t xb = { 0 };
	xcolor_t xc = { 0 };

	if (!ptd->proper) return;

	pclrs = widget_get_color_mode_ptr(widget);
	default_xbrush(&xb);
	format_xcolor(&(pclrs->clr_bkg), xb.color);
	xmem_copy((void*)&xc, (void*)&(pclrs->clr_frg), sizeof(xcolor_t));

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);
	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
	
	get_visual_interface(rdc, &ifv);
	widget_get_view_rect(widget, (viewbox_t*)&(ifv.rect));

	get_canvas_interface(canv, &ifc);
	widget_get_canv_rect(widget, (canvbox_t*)&(ifc.rect));
	ifc.pclrs = pclrs;

	(*ifv.drw->pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	draw_proper(&ifc, ptd->proper);

	//draw focus
	if (ptd->entity)
	{
		_properctrl_entity_rect(widget, ptd->entity, &xr);
		pt_expand_rect(&xr, DEF_INNER_FEED, DEF_INNER_FEED);

		parse_xcolor(&xc, DEF_ALPHA_COLOR);
		(*ifv.drw->pf_alphablend_rect)(ifv.ctx, &xc, &xr, ALPHA_TRANS);
	}

	end_canvas_paint(canv, dc, pxr);
}

/***********************************************************************/

widget_t properctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_proper_create)
		EVENT_ON_DESTROY(hand_proper_destroy)

		EVENT_ON_PAINT(hand_proper_paint)

		EVENT_ON_SIZE(hand_proper_size)

		EVENT_ON_SCROLL(hand_proper_scroll)
		EVENT_ON_WHEEL(hand_proper_wheel)

		EVENT_ON_KEYDOWN(hand_proper_keydown)

		EVENT_ON_MOUSE_MOVE(hand_proper_mouse_move)
		EVENT_ON_MOUSE_HOVER(hand_proper_mouse_hover)
		EVENT_ON_MOUSE_LEAVE(hand_proper_mouse_leave)

		EVENT_ON_LBUTTON_DBCLICK(hand_proper_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_proper_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_proper_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_proper_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_proper_rbutton_up)

		EVENT_ON_NOTICE(hand_proper_notice)	

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void properctrl_attach(widget_t widget, link_t_ptr ptr)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(ptr && is_proper_doc(ptr));

	ptd->proper = ptr;

	widget_get_client_rect(widget, &xr);
	widget_rect_to_mm(widget, &xr);

	set_proper_width(ptd->proper, xr.fw);
	set_proper_height(ptd->proper, xr.fh);

	properctrl_redraw(widget);
}

link_t_ptr properctrl_detach(widget_t widget)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	link_t_ptr data;

	XDK_ASSERT(ptd != NULL);

	if (ptd->proper == NULL)
		return NULL;

	noti_proper_reset_editor(widget, 0);

	data = ptd->proper;
	ptd->proper = NULL;

	widget_erase(widget, NULL);

	return data;
}

link_t_ptr properctrl_fetch(widget_t widget)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->proper;
}

void properctrl_accept(widget_t widget, bool_t bAccept)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->proper)
		return;

	if(bAccept)
		noti_proper_reset_editor(widget, 1);
	else
		noti_proper_reset_editor(widget, 0);
}

void properctrl_redraw(widget_t widget)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	link_t_ptr sec, ent;
	bool_t b_valid;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->proper)
		return;

	noti_proper_reset_editor(widget, 0);

	b_valid = 0;
	sec = get_next_section(ptd->proper, LINK_FIRST);
	while (sec)
	{
		noti_proper_owner(widget, NC_SECTIONCALCED, ptd->proper, sec, NULL, NULL);

		ent = get_next_entity(sec, LINK_FIRST);
		while (ent)
		{
			if (ent == ptd->entity)
				b_valid = 1;

			noti_proper_owner(widget, NC_ENTITYCALCED, ptd->proper, sec, ent, NULL);

			ent = get_next_entity(sec, ent);
		}

		sec = get_next_section(ptd->proper, sec);
	}

	noti_proper_owner(widget, NC_PROPERCALCED, ptd->proper, NULL, NULL, NULL);

	if (!b_valid)
	{
		ptd->entity = NULL;
	}
	ptd->hover = NULL;

	_properctrl_reset_page(widget);
	widget_erase(widget, NULL);
}

void properctrl_redraw_entity(widget_t widget, link_t_ptr elk)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->proper)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_proper_entity(ptd->proper, elk));
#endif

	noti_proper_owner(widget, NC_ENTITYCALCED, ptd->proper, section_from_entity(elk), elk, NULL);

	_properctrl_entity_rect(widget, ptd->entity, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

void properctrl_redraw_section(widget_t widget, link_t_ptr slk)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	xrect_t xr;
	link_t_ptr ent;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->proper)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_proper_section(ptd->proper, slk));
#endif

	ent = get_next_entity(slk, LINK_FIRST);
	while (ent)
	{
		noti_proper_owner(widget, NC_ENTITYCALCED, ptd->proper, slk, ent, NULL);
		ent = get_next_entity(slk, ent);
	}

	noti_proper_owner(widget, NC_SECTIONCALCED, ptd->proper, slk, NULL, NULL);

	_properctrl_section_rect(widget, slk, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

bool_t properctrl_set_focus_entity(widget_t widget, link_t_ptr elk)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	bool_t bRe;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->proper)
		return 0;

	if (elk)
	{
#ifdef _DEBUG
		XDK_ASSERT(is_proper_entity(ptd->proper, elk));
#endif
	}

	bRe = (elk == ptd->entity) ? 1 : 0;

	if (bRe)
		return 1;

	if (ptd->entity && !bRe)
	{
		if (!noti_proper_entity_changing(widget))
			return 0;
	}

	if (elk && !bRe)
	{
		noti_proper_entity_changed(widget, elk);

		_properctrl_ensure_visible(widget);
	}

	return 1;
}

link_t_ptr properctrl_get_focus_entity(widget_t widget)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->proper)
		return NULL;

	return ptd->entity;
}

void properctrl_tabskip(widget_t widget, int dir)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	link_t_ptr slk, elk;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->proper)
		return;

	switch (dir)
	{
	case TABORDER_DOWN:
	case TABORDER_RIGHT:
		if (ptd->entity)
		{
			slk = section_from_entity(ptd->entity);
			elk = get_next_entity(slk, ptd->entity);
			if (!elk)
			{
				slk = get_next_section(ptd->proper, slk);
				if (!slk)
					break;
				elk = get_next_entity(slk, LINK_FIRST);
				if (!elk)
					break;
			}

			if (get_section_collapsed(slk))
				noti_proper_section_expand(widget, slk);

			if (elk)
				properctrl_set_focus_entity(widget, elk);
		}
		else
		{
			slk = get_next_section(ptd->proper, LINK_FIRST);
			if (!slk)
				break;

			elk = get_next_entity(slk, LINK_FIRST);
			if (!elk)
				break;

			if (get_section_collapsed(slk))
				noti_proper_section_expand(widget, slk);

			if (elk)
				properctrl_set_focus_entity(widget, elk);
		}
		break;
	case TABORDER_UP:
	case TABORDER_LEFT:
		if (ptd->entity)
		{
			slk = section_from_entity(ptd->entity);
			elk = get_prev_entity(slk, ptd->entity);
			if (!elk)
			{
				slk = get_prev_section(ptd->proper, slk);
				if (!slk)
					break;
				elk = get_prev_entity(slk, LINK_LAST);
				if (!elk)
					break;
			}

			if (get_section_collapsed(slk))
				noti_proper_section_expand(widget, slk);

			if (elk)
				properctrl_set_focus_entity(widget, elk);
		}
		else
		{
			slk = get_prev_section(ptd->proper, LINK_LAST);
			if (!slk)
				break;

			elk = get_prev_entity(slk, LINK_LAST);
			if (!elk)
				break;

			if (get_section_collapsed(slk))
				noti_proper_section_expand(widget, slk);

			if (elk)
				properctrl_set_focus_entity(widget, elk);
		}
		break;
	}
}

bool_t	properctrl_set_entity_value(widget_t widget, link_t_ptr elk, const tchar_t* token)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->proper)
		return 0;

#ifdef _DEBUG
	XDK_ASSERT(is_proper_entity(ptd->proper, elk));
#endif

	if (compare_text(get_entity_value_ptr(elk), -1, token, -1, 0) == 0)
		return 0;

	set_entity_value(elk, token, -1);

	properctrl_redraw_entity(widget, elk);

	return 1;
}

void properctrl_get_entity_rect(widget_t widget, link_t_ptr ent, bool_t edit, xrect_t* pxr)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	if (!ptd->proper)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_proper_entity(ptd->proper, ent));
#endif

	if(edit)
		_properctrl_entity_text_rect(widget, ent, pxr);
	else
		_properctrl_entity_rect(widget, ent, pxr);
}

void properctrl_set_lock(widget_t widget, bool_t bLock)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_lock = bLock;
}

bool_t properctrl_get_lock(widget_t widget)
{
	proper_delta_t* ptd = GETPROPERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->b_lock;
}
