/***********************************************************************
	Easily xdl v5.5

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc widget document

	@module	impwin.c | implement file

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

#include "impwidget.h"

#include "../xduinf.h"
#include "../xduimp.h"
#include "../xduinit.h"

#ifdef XDU_SUPPORT_WIDGET


bool_t	widget_is_maximized(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_is_maximized)(wt);
}

bool_t	widget_is_minimized(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_is_minimized)(wt);
}

bool_t	widget_enum_child(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_enum_child)(wt, pf, pv);
}

const if_dispatch_t* widget_get_dispatch(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_dispatch)(wt);
}

widget_t widget_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, if_dispatch_t* pev)
{
	if_widget_t* pif;
	
	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_create)(wname, wstyle, pxr, wparent, pev);
}

void widget_set_style(widget_t wt, dword_t ws)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_style)(wt, ws);
}

dword_t widget_get_style(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_style)(wt);
}

void widget_set_owner(widget_t wt, widget_t owner)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_owner)(wt, owner);
}

widget_t widget_get_owner(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_owner)(wt);
}

void widget_set_accel(widget_t wt, const accel_table_t* pacl, int n)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_accel)(wt, pacl, n);
}

void widget_set_core_delta(widget_t wt, vword_t pd)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_core_delta)(wt, pd);
}

vword_t widget_get_core_delta(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_core_delta)(wt);
}

void widget_set_user_delta(widget_t wt, vword_t pd)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;
	
	(pif->pf_widget_set_user_delta)(wt, pd);
}

vword_t widget_get_user_delta(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_user_delta)(wt);
}

void widget_set_user_id(widget_t wt, dword_t uid)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_user_id)(wt, uid);
}

dword_t widget_get_user_id(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_user_id)(wt);
}

widget_t widget_get_child(widget_t wt, dword_t uid)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_child)(wt, uid);
}

widget_t widget_get_parent(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_parent)(wt);
}

void widget_set_user_prop(widget_t wt, const tchar_t* pname,vword_t pval)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_user_prop)(wt, pname, pval);
}

vword_t widget_get_user_prop(widget_t wt, const tchar_t* pname)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_user_prop)(wt, pname);
}

int widget_get_return(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_user_result)(wt);
}

vword_t widget_del_user_prop(widget_t wt, const tchar_t* pname)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_del_user_prop)(wt, pname);
}

visual_t widget_client_ctx(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_client_ctx)(wt);
}

visual_t widget_window_ctx(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_window_ctx)(wt);
}

void widget_release_ctx(widget_t wt, visual_t dc)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_release_ctx)(wt, dc);
}

void widget_get_client_rect(widget_t wt, xrect_t* prt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_get_client_rect)(wt, prt);
}

void widget_get_window_rect(widget_t wt, xrect_t* prt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_get_window_rect)(wt, prt);
}

void widget_get_border(widget_t wt, border_t* pbd)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_get_border)(wt, pbd);
}

void widget_get_menu_rect(widget_t wt, xrect_t* prt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_get_menu_rect)(wt, prt);
}

void widget_get_window_edge(widget_t wt, xsize_t* pxs)
{
	xrect_t xr1, xr2;
	xpoint_t xp1, xp2;

	widget_get_window_rect(wt, &xr1);
	widget_get_client_rect(wt, &xr2);

	xp1.x = xr2.x;
	xp1.y = xr2.y;
	widget_client_to_screen(wt, &xp1);

	xp2.x = xr2.x + xr2.w;
	xp2.y = xr2.y + xr2.h;
	widget_client_to_screen(wt, &xp2);

	xr2.x = xp1.x;
	xr2.y = xp1.y;
	xr2.w = xp2.x - xp1.x;
	xr2.h = xp2.y - xp1.y;

	pxs->w = xr1.w - xr2.w;
	pxs->h = xr1.h - xr2.h;
}

void widget_client_to_screen(widget_t wt, xpoint_t* ppt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_client_to_screen)(wt, ppt);
}

void widget_screen_to_client(widget_t wt, xpoint_t* ppt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_screen_to_client)(wt, ppt);
}

void widget_client_to_window(widget_t wt, xpoint_t* ppt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_client_to_window)(wt, ppt);
}

void widget_window_to_client(widget_t wt, xpoint_t* ppt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_window_to_client)(wt, ppt);
}

void widget_center_window(widget_t wt, widget_t owner)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_center_window)(wt, owner);
}

void widget_set_cursor(widget_t wt, int curs)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_cursor)(wt, curs);
}

void widget_set_capture(widget_t wt, bool_t b)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_capture)(wt, b);
}

void widget_create_caret(widget_t wt, int w, int h)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_create_caret)(wt, w, h);
}

void widget_destroy_caret(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_destroy_caret)(wt);
}

void widget_show_caret(widget_t wt, int x, int y)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_show_caret)(wt, x, y);
}

void widget_set_focus(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_focus)(wt);
}

bool_t widget_key_state(widget_t wt, byte_t key)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_key_state)(wt, key);
}

bool_t widget_is_hotvoer(widget_t wt)
{
	return (widget_get_style(wt) & WD_STYLE_HOTOVER) ? 1 : 0;
}

bool_t widget_is_editor(widget_t wt)
{
	return (widget_get_style(wt) & WD_STYLE_EDITOR) ? 1 : 0;
}

bool_t	widget_is_valid(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_is_valid)(wt);
}

bool_t	widget_is_child(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_is_child)(wt);
}

bool_t	widget_is_focus(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_is_focus)(wt);
}

bool_t	widget_can_focus(widget_t wt)
{
	if_widget_t* pif;
	dword_t dw;

	pif = PROCESS_WIDGET_INTERFACE;

	dw = (pif->pf_widget_get_style)(wt);

	return (dw & WD_STYLE_NOACTIVE) ? 0 : 1;
}

bool_t	widget_can_paging(widget_t wt)
{
	if_widget_t* pif;
	dword_t dw;

	pif = PROCESS_WIDGET_INTERFACE;

	dw = (pif->pf_widget_get_style)(wt);

	return (dw & WD_STYLE_PAGING) ? 1 : 0;
}

bool_t widget_has_close(widget_t wt)
{
	if_widget_t* pif;
	dword_t dw;

	pif = PROCESS_WIDGET_INTERFACE;

	dw = (pif->pf_widget_get_style)(wt);

	return (dw & WD_STYLE_CLOSEBOX) ? 1 : 0;
}

bool_t widget_has_size(widget_t wt)
{
	if_widget_t* pif;
	dword_t dw;

	pif = PROCESS_WIDGET_INTERFACE;

	dw = (pif->pf_widget_get_style)(wt);

	return (dw & WD_STYLE_SIZEBOX) ? 1 : 0;
}

bool_t widget_has_border(widget_t wt)
{
	if_widget_t* pif;
	dword_t dw;

	pif = PROCESS_WIDGET_INTERFACE;

	dw = (pif->pf_widget_get_style)(wt);

	return (dw & WD_STYLE_BORDER) ? 1 : 0;
}

void widget_get_scroll_info(widget_t wt, bool_t horz, scroll_t* psc)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_get_scroll_info)(wt, horz, psc);
}

void widget_set_scroll_info(widget_t wt, bool_t horz, const scroll_t* psc)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_scroll_info)(wt, horz, psc);
}

void widget_scroll(widget_t wt, bool_t horz, int line)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_scroll)(wt, horz, line);
}

void widget_post_wchar(widget_t wt, wchar_t ch)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_post_wchar)(wt, ch);
}

void widget_post_key(widget_t wt, int key)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_post_key)(wt, key);
}

void widget_post_notice(widget_t wt, NOTICE* pnt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_post_notice)(wt, pnt);
}

int widget_send_notice(widget_t wt, NOTICE* pnt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_send_notice)(wt, pnt);
}

void widget_post_command(widget_t wt, int code, int cid, vword_t data)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_post_command)(wt, code, cid, data);
}

int widget_send_command(widget_t wt, int code, int cid, vword_t data)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_send_command)(wt, code, cid, data);
}

void widget_size(widget_t wt, const xsize_t* pxs)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_size)(wt, pxs);
}

void widget_move(widget_t wt, const xpoint_t* ppt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_move)(wt, ppt);
}

void widget_take(widget_t wt, int zor)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_take)(wt, zor);
}

void widget_show(widget_t wt, dword_t sw)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_show)(wt, sw);
}

void widget_layout(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_layout)(wt);
}

void widget_paint(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_paint)(wt);
}

void widget_erase(widget_t wt, const xrect_t* prt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_erase)(wt, prt);
}

void widget_enable(widget_t wt, bool_t b)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_enable)(wt, b);
}

void widget_active(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_active)(wt);
}

void widget_close(widget_t wt, int ret)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_close)(wt, ret);
}

void widget_destroy(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_destroy)(wt);
}

void widget_set_title(widget_t wt, const tchar_t* token)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_title)(wt, token);
}

int	widget_get_title(widget_t wt, tchar_t* buf, int max)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_title)(wt, buf, max);
}

bool_t	widget_set_subproc(widget_t wt, dword_t sid, if_subproc_t* sub)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_set_subproc)(wt, sid, sub);
}

void widget_del_subproc(widget_t wt, dword_t sid)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_del_subproc)(wt, sid);
}

vword_t widget_get_subproc_delta(widget_t wt, dword_t sid)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_subproc_delta)(wt, sid);
}

bool_t widget_set_subproc_delta(widget_t wt, dword_t sid, vword_t delta)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_set_subproc_delta)(wt, sid, delta);
}

bool_t widget_has_subproc(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_has_subproc)(wt);
}

vword_t widget_set_timer(widget_t wt, int ms)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_set_timer)(wt, ms);
}

void widget_kill_timer(widget_t wt, vword_t tid)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_kill_timer)(wt, tid);
}

void  widget_noti_xfont(widget_t wt, const xfont_t* pxf)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_noti_xfont)(wt, pxf);
}

void widget_noti_xface(widget_t wt, const xface_t* pxa)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_noti_xface)(wt, pxa);
}

void  widget_noti_xbrush(widget_t wt, const xbrush_t* pxb)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_noti_xbrush)(wt, pxb);
}

void  widget_noti_xpen(widget_t wt, const xpen_t* pxp)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_noti_xpen)(wt, pxp);
}

void  widget_set_point(widget_t wt, const xpoint_t* ppt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_point)(wt, ppt);
}

void  widget_get_point(widget_t wt, xpoint_t* ppt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_get_point)(wt, ppt);
}

void widget_set_color_mode(widget_t wt, const color_mod_t* pclr)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_color_mode)(wt, pclr);
}

void widget_get_color_mode(widget_t wt, color_mod_t* pclr)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_get_color_mode)(wt, pclr);
}

void widget_set_diaph(widget_t wt, float b)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_set_diaph)(wt, b);
}

float widget_get_diaph(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_diaph)(wt);
}

int widget_do_main(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_do_main)(wt);
}

int widget_do_modal(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_do_modal)(wt);
}

void widget_do_track(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_widget_do_track)(wt);
}

void message_quit(int ret)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_message_quit)(ret);
}

void message_position(xpoint_t* pxp)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_message_position)(pxp);
}

void calc_widget_border(dword_t ws, border_t* pbd)
{
	xsize_t xs;

	pbd->edge = pbd->title = pbd->hscroll = pbd->vscroll = pbd->menu = pbd->icon = 0;

	if (ws & WD_STYLE_TITLE)
	{
		xs.fw = ZERO_WIDTH;
		xs.fh = WIDGET_TITLE_SPAN;
		screen_size_to_pt(&xs);

		pbd->title = xs.h;
	}

	if (ws & WD_STYLE_BORDER)
	{
		xs.fw = ZERO_WIDTH;
		if (ws & WD_STYLE_CHILD)
			xs.fh = WIDGET_CHILD_EDGE;
		else
			xs.fh = WIDGET_FRAME_EDGE;
		screen_size_to_pt(&xs);

		pbd->edge = xs.h;
	}

	if (ws & WD_STYLE_HSCROLL)
	{
		xs.fw = ZERO_WIDTH;
		xs.fh = WIDGET_SCROLL_SPAN;
		screen_size_to_pt(&xs);

		pbd->hscroll = xs.h;
	}

	if (ws & WD_STYLE_VSCROLL)
	{
		xs.fw = WIDGET_SCROLL_SPAN;
		xs.fh = ZERO_HEIGHT;
		screen_size_to_pt(&xs);

		pbd->vscroll = xs.w;
	}

	if (ws & WD_STYLE_MENUBAR)
	{
		xs.fw = ZERO_WIDTH;
		xs.fh = WIDGET_MENU_SPAN;
		screen_size_to_pt(&xs);

		pbd->menu = xs.h;
	}

	xs.fw = ZERO_WIDTH;
	xs.fh = WIDGET_ICON_SPAN;
	screen_size_to_pt(&xs);
	pbd->icon = xs.h;
}

void adjust_widget_size(dword_t ws, xsize_t* pxs)
{
	if_widget_t* pif;
	border_t bd;

	pif = PROCESS_WIDGET_INTERFACE;

	if (ws & WD_STYLE_OWNERNC)
	{
		calc_widget_border(ws, &bd);

		pxs->w += (2 * bd.edge + bd.vscroll);
		pxs->h += (2 * bd.edge + bd.title + bd.menu + bd.hscroll);
	}
	else
	{
		(pif->pf_adjust_widget_size)(ws, pxs);
	}
}

void get_screen_size(xsize_t* pxs)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_get_screen_size)(pxs);
}

void get_desktop_size(xsize_t* pxs)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_get_desktop_size)(pxs);
}

void screen_size_to_pt(xsize_t* pxs)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_screen_size_to_pt)(pxs);
}

void screen_size_to_mm(xsize_t* pxs)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	(pif->pf_screen_size_to_mm)(pxs);
}

#ifdef XDU_SUPPORT_CONTEXT_OPENGL
res_glc_t widget_get_glctx(widget_t wt)
{
	if_widget_t* pif;

	pif = PROCESS_WIDGET_INTERFACE;

	return (pif->pf_widget_get_glctx)(wt);
}
#endif

#endif /*XDU_SUPPORT_WIDGET*/
