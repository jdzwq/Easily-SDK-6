/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc tree control document

	@module	treectrl.c | implement file

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


typedef struct _tree_delta_t{
	link_t_ptr tree;
	link_t_ptr item;
	link_t_ptr hover;

	int org_x, org_y, cur_x, cur_y;

	bool_t b_drag;
	bool_t b_lock;
}tree_delta_t;

typedef struct _tree_redraw_param{
	widget_t wt;
	bool_t calc;
	bool_t valid;
}tree_redraw_param;

#define GETTREEDELTA(ph) 		(tree_delta_t*)widget_get_user_delta(ph)
#define SETTREEDELTA(ph,ptd)	widget_set_user_delta(ph,(vword_t)ptd)

/***********************************************************************/

static void _treectrl_item_rect(widget_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	
	calc_tree_item_entity_rect(ptd->tree, ilk, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _treectrl_item_text_rect(widget_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	calc_tree_item_text_rect(ptd->tree, ilk, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _treectrl_item_expand_rect(widget_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	calc_tree_item_expand_rect(ptd->tree, ilk, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _treectrl_reset_page(widget_t widget)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	int pw, ph, vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;
	canvas_t canv;
	measure_interface im = { 0 };

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	if (ptd->tree)
	{
		widget_rect_to_mm(widget, &xr);
		set_tree_width(ptd->tree, xr.fw);
		set_tree_height(ptd->tree, xr.fh);

		canv = widget_get_canvas(widget);
		get_canvas_measure(canv, &im);
		widget_get_canv_rect(widget, (canvbox_t *)&(im.rect));

		xs.fw = calc_tree_width(&im, ptd->tree);
		xs.fh = calc_tree_height(ptd->tree);

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

	if(ptd->tree)
	{
		xs.fw = 5.0f;
		if(ptd->tree)
			xs.fh = get_tree_item_height(ptd->tree);
		else
			xs.fh = 5.0f;
	}else
	{
		xs.fw = 5.0f;
		xs.fh = 5.0f;
	}
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	widget_reset_paging(widget, pw, ph, vw, vh, lw, lh);

	widget_reset_scroll(widget, 1);
	widget_reset_scroll(widget, 0);
}

static void _treectrl_ensure_visible(widget_t widget)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	bool_t b_tag = 0;
	xrect_t xr;
	link_t_ptr parent;

	if (!ptd->item)
	{
		return;
	}

	parent = get_tree_parent_item(ptd->item);
	while (parent)
	{
		if (get_tree_item_collapsed(parent))
		{
			set_tree_item_collapsed(parent, 0);
			b_tag = 1;
		}
		parent = get_tree_parent_item(parent);
	}

	if (b_tag)
	{
		_treectrl_reset_page(widget);
	}

	_treectrl_item_rect(widget, ptd->item, &xr);
	widget_ensure_visible(widget, &xr, 1);
}

/***********************************************************************/

int noti_tree_owner(widget_t widget, unsigned int code, link_t_ptr tree, link_t_ptr ilk, void* data)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	NOTICE_TREE nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;
	nf.data = data;
	nf.ret = 0;

	nf.tree = tree;
	nf.item = ilk;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);
	return nf.ret;
}

void noti_tree_item_enter(widget_t widget, link_t_ptr plk)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	XDK_ASSERT(plk);
	XDK_ASSERT(!ptd->hover);

	ptd->hover = plk;

	widget_enable_hover(widget, bool_true);
}

void noti_tree_item_leave(widget_t widget)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	ptd->hover = NULL;

	widget_enable_hover(widget, bool_false);
}

void noti_tree_item_hover(widget_t widget, int x, int y)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	xpoint_t xp;

	XDK_ASSERT(ptd->hover != NULL);

	xp.x = x;
	xp.y = y;
	noti_tree_owner(widget, NC_TREEITEMHOVER, ptd->tree, ptd->hover, (void*)&xp);
}

bool_t noti_tree_item_changing(widget_t widget)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	link_t_ptr tlk;
	xrect_t xr;

	XDK_ASSERT(ptd->item != NULL);

	if (noti_tree_owner(widget, NC_TREEITEMCHANGING, ptd->tree, ptd->item, NULL))
		return 0;

	tlk = ptd->item;
	ptd->item = NULL;

	_treectrl_item_rect(widget, tlk, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);

	return 1;
}

void noti_tree_item_changed(widget_t widget, link_t_ptr ilk)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(NULL == ptd->item);

	ptd->item = ilk;
	_treectrl_item_rect(widget, ptd->item, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);

	noti_tree_owner(widget, NC_TREEITEMCHANGED, ptd->tree, ptd->item, NULL);
}

void noti_tree_item_checked(widget_t widget, link_t_ptr ilk)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	bool_t bCheck;
	xrect_t xr;
	link_t_ptr tlk;

	XDK_ASSERT(ilk != NULL);

	bCheck = get_tree_item_checked(ilk);

	set_tree_item_checked(ilk, ((bCheck) ? 0 : 1));

	noti_tree_owner(widget, NC_TREEITEMCHECKED, ptd->tree, ilk, NULL);

	tlk = get_tree_first_child_item(ilk);
	while (tlk)
	{
		if (get_tree_item_showcheck(tlk))
		{
			set_tree_item_checked(tlk, ((bCheck) ? 0 : 1));

			noti_tree_owner(widget, NC_TREEITEMCHECKED, ptd->tree, tlk, NULL);
		}

		tlk = get_tree_next_sibling_item(tlk);
	}

	_treectrl_item_expand_rect(widget, ilk, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

void noti_tree_item_expand(widget_t widget, link_t_ptr ilk)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	XDK_ASSERT(ilk != NULL);

	set_tree_item_collapsed(ilk, 0);

	noti_tree_owner(widget, NC_TREEITEMEXPAND, ptd->tree, ilk, NULL);

	treectrl_redraw(widget);
}

void noti_tree_item_collapse(widget_t widget, link_t_ptr ilk)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	XDK_ASSERT(ilk != NULL);

	set_tree_item_collapsed(ilk, 1);

	noti_tree_owner(widget, NC_TREEITEMCOLLAPSE, ptd->tree, ilk, NULL);

	treectrl_redraw(widget);
}

void noti_tree_item_drag(widget_t widget, int x, int y)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	xpoint_t pt;

	XDK_ASSERT(ptd->item != NULL);

	if (widget_can_focus(widget))
	{
		widget_set_capture(widget, 1);
	}

	widget_set_cursor(widget, CURSOR_HAND);

	ptd->b_drag = 1;
	pt.x = x;
	pt.y = y;
	noti_tree_owner(widget, NC_TREEITEMDRAG, ptd->tree, ptd->item, (void*)&pt);
}

void noti_tree_item_drop(widget_t widget, int x, int y)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	xpoint_t pt;

	XDK_ASSERT(ptd->item != NULL);

	widget_set_cursor(widget, CURSOR_ARROW);

	if (widget_can_focus(widget))
	{
		widget_set_capture(widget, 0);
	}

	ptd->b_drag = 0;
	pt.x = x;
	pt.y = y;
	noti_tree_owner(widget, NC_TREEITEMDROP, ptd->tree, ptd->item, (void*)&pt);
}

void noti_tree_reset_editor(widget_t widget, bool_t bCommit)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	if (bCommit)
		widget_post_command(widget, COMMAND_COMMIT, IDC_CHILD, (vword_t)0);
	else
		widget_post_command(widget, COMMAND_ROLLBACK, IDC_CHILD, (vword_t)0);
}

/***********************************************************************/

int hand_tree_create(widget_t widget, void* data)
{
	tree_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (tree_delta_t*)xmem_alloc(sizeof(tree_delta_t));
	xmem_zero((void*)ptd, sizeof(tree_delta_t));

	SETTREEDELTA(widget, ptd);

	ptd->b_lock = 1;

	return 0;
}

void hand_tree_destroy(widget_t widget)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	noti_tree_reset_editor(widget, 0);

	xmem_free(ptd);

	SETTREEDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_tree_size(widget_t widget, int code, const xsize_t* pxs)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	_treectrl_reset_page(widget);
	
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

void hand_tree_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	link_t_ptr tlk;
	int nHint;
	bool_t bRe;
	xpoint_t pt;

	if (!ptd->tree)
		return;

	noti_tree_reset_editor(widget, 1);

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	tlk = NULL;
	nHint = calc_tree_hint(&pt, ptd->tree, &tlk);

	bRe = (tlk == ptd->item) ? 1 : 0;

	if (nHint == TREE_HINT_EXPAND)
	{
		if (get_tree_item_collapsed(tlk))
			noti_tree_item_expand(widget, tlk);
		else
			noti_tree_item_collapse(widget, tlk);
		return;
	}

	if (nHint == TREE_HINT_CHECK)
	{
		noti_tree_item_checked(widget, tlk);
		return;
	}
}

void hand_tree_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	link_t_ptr tlk;
	int nHint;
	bool_t bRe;
	xpoint_t pt;

	if (!ptd->tree)
		return;

	if (ptd->b_drag)
	{
		noti_tree_item_drop(widget, pxp->x, pxp->y);
		return;
	}

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	tlk = NULL;
	nHint = calc_tree_hint(&pt, ptd->tree, &tlk);

	if (nHint == TREE_HINT_EXPAND || nHint == TREE_HINT_CHECK)
	{
		return;
	}

	bRe = (tlk == ptd->item) ? 1 : 0;

	if (bRe && ptd->item && !ptd->b_lock && !get_tree_item_locked(ptd->item))
	{
		widget_post_key(widget, KEY_ENTER);
		return;
	}

	if (!bRe && ptd->item)
	{
		if (!noti_tree_item_changing(widget))
			bRe = 1;
	}

	if (!bRe && tlk)
	{
		noti_tree_item_changed(widget, tlk);
	}

	if (!bRe && ptd->item)
	{
		_treectrl_ensure_visible(widget);
	}

	noti_tree_owner(widget, NC_TREELBCLK, ptd->tree, ptd->item, (void*)pxp);
}

void hand_tree_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	if (!ptd->tree)
		return;

	noti_tree_reset_editor(widget, 1);

	noti_tree_owner(widget, NC_TREEDBCLK, ptd->tree, ptd->item, (void*)pxp);
}

void hand_tree_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	if (!ptd->tree)
		return;

	noti_tree_reset_editor(widget, 1);
}

void hand_tree_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	if (!ptd->tree)
		return;

	noti_tree_owner(widget, NC_TREERBCLK, ptd->tree, ptd->item, (void*)pxp);
}

void hand_tree_mouse_move(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	link_t_ptr tlk;
	int nHint;
	xpoint_t pt;

	if (!ptd->tree)
		return;

	if (ptd->b_drag)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	tlk = NULL;
	nHint = calc_tree_hint(&pt, ptd->tree, &tlk);

	if (nHint == TREE_HINT_ITEM && tlk == ptd->item && !(dw & KS_WITH_CONTROL))
	{
		if (dw & MS_WITH_LBUTTON)
		{
			noti_tree_item_drag(widget, pxp->x, pxp->y);
			return;
		}
	}

	if (nHint == TREE_HINT_ITEM && !ptd->hover && tlk)
	{
		noti_tree_item_enter(widget, tlk);
	}
	else if (nHint == TREE_HINT_ITEM && ptd->hover && ptd->hover != tlk)
	{
		noti_tree_item_leave(widget);
	}
	else if (nHint != TREE_HINT_ITEM && ptd->hover)
	{
		noti_tree_item_leave(widget);
	}
}

void hand_tree_mouse_hover(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	if (!ptd->tree)
		return;

	if (ptd->hover)
		noti_tree_item_hover(widget, pxp->x, pxp->y);
}

void hand_tree_mouse_leave(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	if (!ptd->tree)
		return;

	if (ptd->hover)
		noti_tree_item_leave(widget);
}

void hand_tree_keydown(widget_t widget, dword_t ks, int nKey)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	if (!ptd->tree)
		return;

	switch (nKey)
	{
	case KEY_SPACE:
		if (ptd->item && get_tree_item_showcheck(ptd->item))
		{
			noti_tree_item_checked(widget, ptd->item);
		}
		break;
	case KEY_DOWN:
		treectrl_tabskip(widget,TABORDER_DOWN);
		break;
	case KEY_RIGHT:
		treectrl_tabskip(widget,TABORDER_RIGHT);
		break;
		break;
	case KEY_UP:
		treectrl_tabskip(widget,TABORDER_UP);
		break;
	case KEY_LEFT:
		treectrl_tabskip(widget,TABORDER_LEFT);
		break;
	}
}

void hand_tree_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	if (!ptd->tree)
		return;

	noti_tree_reset_editor(widget, 1);

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_tree_wheel(widget_t widget, bool_t bHorz, int nDelta)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	scroll_t scr = { 0 };
	int nLine;
	widget_t win;

	if (!ptd->tree)
		return;

	noti_tree_reset_editor(widget, 1);

	widget_hand_wheel(widget, bHorz, nDelta);
}

void hand_tree_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	visual_t rdc;
	xrect_t xr = { 0 };

	canvas_t canv;
	drawing_interface ifc = {0};
	drawing_interface ifv = {0};

	const color_mod_t* pclrs;
	xbrush_t xb;
	xcolor_t xc;

	if (!ptd->tree) return;

	pclrs = widget_get_color_mode_ptr(widget);
	default_xbrush(&xb);
	format_xcolor(&(pclrs->clr_bkg), xb.color);
	xmem_copy((void*)&xc, (void*)&(pclrs->clr_bkg), sizeof(xcolor_t));

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);
	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
	
	get_visual_interface(rdc, &ifv);
	widget_get_view_rect(widget, (viewbox_t*)&(ifv.rect));

	get_canvas_interface(canv, &ifc);
	widget_get_canv_rect(widget, (canvbox_t*)&(ifc.rect));
	ifc.pclrs = pclrs;

	(*ifv.drw->pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	draw_tree(&ifc, ptd->tree);

	//draw focus
	if (ptd->item)
	{
		widget_get_view_rect(widget, (viewbox_t*)(&ifv.rect));

		_treectrl_item_rect(widget, ptd->item, &xr);
		pt_expand_rect(&xr, DEF_INNER_FEED, 0);

		parse_xcolor(&xc, xb.color);
		lighten_xcolor(&xc, DEF_HARD_DARKEN);

		draw_focus_raw(&ifv, &xc, &xr, ALPHA_SOFT);
	}

	end_canvas_paint(canv, dc, pxr);
}

/***********************************************************************/

widget_t treectrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_tree_create)
		EVENT_ON_DESTROY(hand_tree_destroy)

		EVENT_ON_PAINT(hand_tree_paint)

		EVENT_ON_SIZE(hand_tree_size)

		EVENT_ON_SCROLL(hand_tree_scroll)
		EVENT_ON_WHEEL(hand_tree_wheel)

		EVENT_ON_KEYDOWN(hand_tree_keydown)

		EVENT_ON_MOUSE_MOVE(hand_tree_mouse_move)
		EVENT_ON_MOUSE_HOVER(hand_tree_mouse_hover)
		EVENT_ON_MOUSE_LEAVE(hand_tree_mouse_leave)

		EVENT_ON_LBUTTON_DBCLICK(hand_tree_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_tree_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_tree_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_tree_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_tree_rbutton_up)

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void treectrl_attach(widget_t widget, link_t_ptr ptr)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(ptr && is_tree_doc(ptr));

	noti_tree_reset_editor(widget, 0);

	ptd->tree = ptr;
	ptd->item = NULL;

	widget_get_client_rect(widget, &xr);
	widget_rect_to_mm(widget, &xr);

	set_tree_width(ptd->tree, xr.fw);
	set_tree_height(ptd->tree, xr.fh);

	treectrl_redraw(widget);
}

link_t_ptr treectrl_detach(widget_t widget)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	link_t_ptr ptr;

	XDK_ASSERT(ptd != NULL);

	noti_tree_reset_editor(widget, 0);

	ptr = ptd->tree;
	ptd->tree = NULL;

	widget_erase(widget, NULL);
	return ptr;
}

link_t_ptr treectrl_fetch(widget_t widget)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->tree;
}

void treectrl_accept(widget_t widget, bool_t bAccept)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->tree)
		return;

	noti_tree_reset_editor(widget, bAccept);
}

bool_t CALLBACK _redraw_tree_node(link_t_ptr plk, void* pv)
{
	tree_redraw_param* ptp = (tree_redraw_param*)pv;

	tree_delta_t* ptd = GETTREEDELTA(ptp->wt);

	if (plk == ptd->item)
		ptp->valid = 1;

	if (ptp->calc)
		noti_tree_owner(ptp->wt, NC_TREEITEMCALCED, ptd->tree, plk, NULL);

	return 1;
}

void treectrl_redraw(widget_t widget)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	tree_redraw_param tp = { 0 };

	XDK_ASSERT(ptd != NULL);

	if (!ptd->tree)
		return;

	noti_tree_reset_editor(widget, 0);

	tp.wt = widget;
	tp.calc = 1;
	tp.valid = 0;

	enum_dom_node(ptd->tree, _redraw_tree_node, (void*)&tp);

	noti_tree_owner(widget, NC_TREECALCED, ptd->tree, NULL, NULL);

	if (!tp.valid)
	{
		ptd->item = NULL;
	}
	ptd->hover = NULL;

	_treectrl_reset_page(widget);
	widget_erase(widget, NULL);
}

void treectrl_redraw_item(widget_t widget, link_t_ptr ilk)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->tree)
		return;

	noti_tree_reset_editor(widget, 0);

#ifdef _DEBUG
	XDK_ASSERT(is_tree_item(ptd->tree, ilk));
#endif

	noti_tree_owner(widget, NC_TREEITEMCALCED, ptd->tree, ilk, NULL);

	_treectrl_item_rect(widget, ilk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

bool_t treectrl_set_focus_item(widget_t widget, link_t_ptr ilk)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	bool_t bRe;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->tree)
		return 0;

	noti_tree_reset_editor(widget, 0);

	if (ilk)
	{
#ifdef _DEBUG
		XDK_ASSERT(is_tree_item(ptd->tree, ilk));
#endif
	}

	bRe = (ilk == ptd->item) ? 1 : 0;
	if (bRe)
		return 1;

	if (ptd->item && !bRe)
	{
		if (!noti_tree_item_changing(widget))
			return 0;
	}

	if (ilk && !bRe)
	{
		noti_tree_item_changed(widget, ilk);

		_treectrl_ensure_visible(widget);
	}

	return 1;
}

link_t_ptr treectrl_get_focus_item(widget_t widget)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->tree)
		return NULL;

	return ptd->item;
}

bool_t treectrl_set_item_title(widget_t widget, link_t_ptr ilk, const tchar_t* szText)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	const tchar_t* text;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->tree)
		return 0;

#ifdef _DEBUG
	XDK_ASSERT(is_tree_item(ptd->tree, ilk));
#endif

	text = get_tree_item_title_ptr(ilk);
	if (compare_text(szText, -1, text, -1, 0) != 0)
	{
		set_tree_item_title(ilk, szText);

		noti_tree_owner(widget, NC_TREEITEMUPDATE, ptd->tree, ilk, NULL);

		treectrl_redraw_item(widget, ilk);
	}

	return 1;
}

void treectrl_tabskip(widget_t widget, int nSkip)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	link_t_ptr plk = NULL;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->tree)
		return;

	noti_tree_reset_editor(widget, 1);

	switch (nSkip)
	{
	case TABORDER_RIGHT:
		if (ptd->item && get_tree_child_item_count(ptd->item))
		{
			if (get_tree_item_collapsed(ptd->item))
			{
				noti_tree_item_expand(widget, ptd->item);
			}
			plk = get_tree_first_child_item(ptd->item);
		}
		else
		{
			plk = ptd->item;
		}
		break;
	case TABORDER_DOWN:
		if (ptd->item)
		{
			plk = get_tree_next_visible_item(ptd->tree, ptd->item);
		}
		else
		{
			plk = get_tree_first_child_item(ptd->tree);
		}
		break;
	case TABORDER_LEFT:
		if (ptd->item && get_tree_parent_item(ptd->item))
		{
			plk = get_tree_parent_item(ptd->item);
			if (!get_tree_item_collapsed(plk))
			{
				noti_tree_item_expand(widget, plk);
			}
		}
		else
		{
			plk = ptd->item;
		}
		break;
	case TABORDER_UP:
		if (ptd->item)
		{
			plk = get_tree_prev_visible_item(ptd->tree, ptd->item);
		}
		else
		{
			plk = get_tree_last_child_item(ptd->tree);
		}
		break;
	case TABORDER_HOME:
		plk = get_tree_first_child_item(ptd->tree);
		break;
	case TABORDER_END:
		plk = get_tree_last_child_item(ptd->tree);
		break;
	}

	if (plk && is_tree_doc(plk))
		plk = NULL;

	if (plk)
		treectrl_set_focus_item(widget, plk);
}

void treectrl_get_item_rect(widget_t widget, link_t_ptr ilk, bool_t text, xrect_t* prt)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	if (!ptd->tree)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_tree_item(ptd->tree, ilk));
#endif

	if(text)
		_treectrl_item_text_rect(widget, ilk, prt);
	else
		_treectrl_item_rect(widget, ilk, prt);
}

void treectrl_find(widget_t widget, const tchar_t* token)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	link_t_ptr elk;
	int tlen;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->tree)
		return;

	noti_tree_reset_editor(widget, 0);

	tlen = xslen(token);

	if (tlen)
	{
		elk = (ptd->item) ? get_tree_next_sibling_item(ptd->item) : get_tree_first_child_item(ptd->tree);

		while (elk)
		{
			if (xsnicmp(get_tree_item_title_ptr(elk), token, tlen) == 0)
				break;

			elk = get_tree_next_sibling_item(elk);
		}
	}
	else
	{
		elk = NULL;
	}

	if (elk)
		treectrl_set_focus_item(widget, elk);
	else
		treectrl_set_focus_item(widget, NULL);
}

void treectrl_popup_size(widget_t widget, xsize_t* pse)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);
	int count;
	canvas_t canv;
	measure_interface im = { 0 };

	XDK_ASSERT(ptd != NULL);

	if (!ptd->tree)
		return;

	count = get_tree_child_item_count(ptd->tree);
	if (count > 7)
	{
		count = 7;
	}

	canv = widget_get_canvas(widget);
	get_canvas_measure(canv, &im);
	widget_get_canv_rect(widget, (canvbox_t*)&(im.rect));

	pse->fw = calc_tree_width(&im, ptd->tree);
	pse->fh = count * get_tree_item_height(ptd->tree);

	widget_size_to_pt(widget, pse);

	adjust_widget_size(widget_get_style(widget), pse);
}

void treectrl_set_lock(widget_t widget, bool_t bLock)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_lock = bLock;
}

bool_t treectrl_get_lock(widget_t widget)
{
	tree_delta_t* ptd = GETTREEDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->b_lock;
}
