/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc widget document

	@module	if_widget.c | linux implement file

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

#include "../xduloc.h"
#include "../xduutil.h"

#if defined(_X11)
#include "X11/_if_X11.h"
#elif defined(_WAYLAND)
#include "wayland/_if_wayland.h"
#endif

#ifdef XDU_SUPPORT_WIDGET


void _widget_startup(int ver)
{
#if defined(_X11)
	xlWidgetStartup(ver);
#elif defined(_WAYLAND)
	wlWidgetStartup(ver);
#endif
}

void _widget_cleanup()
{
#if defined(_X11)
	xlWidgetCleanup();
#elif defined(_WAYLAND)
	wlWidgetCleanup();
#endif
}

widget_t _widget_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev)
{
#if defined(_X11)
	return xlWidgetCreate(wname, wstyle, pxr, wparent, pev);
#elif defined(_WAYLAND)
	return wlWidgetCreate(wname, wstyle, pxr, wparent, pev);
#endif
}

void _widget_destroy(widget_t wt)
{
#if defined(_X11)
	xlWidgetDestroy(wt);
#elif defined(_WAYLAND)
	wlWidgetDestroy(wt);
#endif
}

void _widget_close(widget_t wt, int ret)
{
#if defined(_X11)
	xlWidgetClose(wt, ret);
#elif defined(_WAYLAND)
	wlWidgetClose(wt, ret);
#endif
}

const if_subproc_t* _widget_get_subproc(widget_t wt, uid_t sid)
{
#if defined(_X11)
	return xlWidgetGetSubproc(wt, sid);
#elif defined(_WAYLAND)
	return wlWidgetGetSubproc(wt, sid);
#endif
}

bool_t _widget_set_subproc(widget_t wt, uid_t sid, if_subproc_t* sub)
{
#if defined(_X11)
	return xlWidgetSetSubproc(wt, sid, sub);
#elif defined(_WAYLAND)
	return wlWidgetSetSubproc(wt, sid, sub);
#endif
}

void _widget_del_subproc(widget_t wt, uid_t sid)
{
#if defined(_X11)
	xlWidgetDelSubproc(wt, sid);
#elif defined(_WAYLAND)
	wlWidgetDelSubproc(wt, sid);
#endif
}

bool_t _widget_set_subproc_delta(widget_t wt, uid_t sid, vword_t delta)
{
#if defined(_X11)
	return xlWidgetSetSubprocDelta(wt, sid, delta);
#elif defined(_WAYLAND)
	return wlWidgetSetSubprocDelta(wt, sid, delta);
#endif
}

vword_t _widget_get_subproc_delta(widget_t wt, uid_t sid)
{
#if defined(_X11)
	return xlWidgetGetSubprocDelta(wt, sid);
#elif defined(_WAYLAND)
	return wlWidgetGetSubprocDelta(wt, sid);
#endif
}

bool_t _widget_has_subproc(widget_t wt, uid_t sid)
{
#if defined(_X11)
	return xlWidgetHasSubproc(wt, sid);
#elif defined(_WAYLAND)
	return wlWidgetHasSubproc(wt, sid);
#endif
}

void _widget_set_core_delta(widget_t wt, vword_t pd)
{
#if defined(_X11)
	xlWidgetSetCoreDelta(wt, pd);
#elif defined(_WAYLAND)
	wlWidgetSetCoreDelta(wt, pd);
#endif
}

vword_t _widget_get_core_delta(widget_t wt)
{
#if defined(_X11)
	return xlWidgetGetCoreDelta(wt);
#elif defined(_WAYLAND)
	return wlWidgetGetCoreDelta(wt);
#endif
}

void _widget_set_user_delta(widget_t wt, vword_t pd)
{
#if defined(_X11)
	xlWidgetSetUserDelta(wt, pd);
#elif defined(_WAYLAND)
	wlWidgetSetUserDelta(wt, pd);
#endif
}

vword_t _widget_get_user_delta(widget_t wt)
{
#if defined(_X11)
	return xlWidgetGetUserDelta(wt);
#elif defined(_WAYLAND)
	return wlWidgetGetUserDelta(wt);
#endif
}

void _widget_set_style(widget_t wt, dword_t ws)
{
#if defined(_X11)
	xlWidgetSetStyle(wt, ws);
#elif defined(_WAYLAND)
	wlWidgetSetStyle(wt, ws);
#endif
}

dword_t _widget_get_style(widget_t wt)
{
#if defined(_X11)
	return xlWidgetGetStyle(wt);
#elif defined(_WAYLAND)
	return wlWidgetGetStyle(wt);
#endif
}

void _widget_set_accel(widget_t wt, const accel_table_t* pacl, int n)
{
#if defined(_X11)
	xlWidgetSetAccel(wt, pacl, n);
#elif defined(_WAYLAND)
	wlWidgetSetAccel(wt, pacl, n);
#endif
}

void _widget_set_owner(widget_t wt, widget_t owner)
{
#if defined(_X11)
	xlWidgetSetOwner(wt, owner);
#elif defined(_WAYLAND)
	wlWidgetSetOwner(wt, owner);
#endif
}

widget_t _widget_get_owner(widget_t wt)
{
#if defined(_X11)
	return xlWidgetGetOwner(wt);
#elif defined(_WAYLAND)
	return wlWidgetGetOwner(wt);
#endif
}

void _widget_set_user_id(widget_t wt, uid_t uid)
{
#if defined(_X11)
	xlWidgetSetUserId(wt, uid);
#elif defined(_WAYLAND)
	wlWidgetSetUserId(wt, uid);
#endif
}

uid_t _widget_get_user_id(widget_t wt)
{
#if defined(_X11)
	return xlWidgetGetUserId(wt);
#elif defined(_WAYLAND)
	return wlWidgetGetUserId(wt);
#endif
}

void _widget_set_user_result(widget_t wt, int rt)
{
#if defined(_X11)
	xlWidgetSetUserResult(wt, rt);
#elif defined(_WAYLAND)
	wlWidgetSetUserResult(wt, rt);
#endif
}

int _widget_get_user_result(widget_t wt)
{
#if defined(_X11)
	return xlWidgetGetUserResult(wt);
#elif defined(_WAYLAND)
	return wlWidgetGetUserResult(wt);
#endif
}

widget_t _widget_get_child(widget_t wt, uid_t uid)
{
#if defined(_X11)
	return xlWidgetGetChild(wt, uid);
#elif defined(_WAYLAND)
	return wlWidgetGetChild(wt, uid);
#endif
}

widget_t _widget_get_parent(widget_t wt)
{
#if defined(_X11)
	return xlWidgetGetParent(wt);
#elif defined(_WAYLAND)
	return wlWidgetGetParent(wt);
#endif
}

void _widget_set_user_prop(widget_t wt, const tchar_t* pname,vword_t val)
{
#if defined(_X11)
	xlWidgetSetUserProp(wt, pname, val);
#elif defined(_WAYLAND)
	wlWidgetSetUserProp(wt, pname, val);
#endif
}

vword_t _widget_get_user_prop(widget_t wt, const tchar_t* pname)
{
#if defined(_X11)
	return xlWidgetGetUserProp(wt, pname);
#elif defined(_WAYLAND)
	return wlWidgetGetUserProp(wt, pname);
#endif
}

vword_t _widget_del_user_prop(widget_t wt, const tchar_t* pname)
{
#if defined(_X11)
	return xlWidgetDelUserProp(wt, pname);
#elif defined(_WAYLAND)
	return wlWidgetDelUserProp(wt, pname);
#endif
}

const if_dispatch_t* _widget_get_dispatch(widget_t wt)
{
#if defined(_X11)
	return xlWidgetGetDispatch(wt);
#elif defined(_WAYLAND)
	return wlWidgetGetDispatch(wt);
#endif
}

bool_t _widget_is_maximized(widget_t wt)
{
#if defined(_X11)
	return xlWidgetIsMaximized(wt);
#elif defined(_WAYLAND)
	return wlWidgetIsMaximized(wt);
#endif
}

bool_t _widget_is_minimized(widget_t wt)
{
#if defined(_X11)
	return xlWidgetIsMinimized(wt);
#elif defined(_WAYLAND)
	return wlWidgetIsMinimized(wt);
#endif
}

bool_t _widget_enum_child(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv)
{
#if defined(_X11)
	return xlWidgetEnumChild(wt, pf, pv);
#elif defined(_WAYLAND)
	return wlWidgetEnumChild(wt, pf, pv);
#endif
}

visual_t _widget_client_context(widget_t wt)
{
#if defined(_X11)
	return xlWidgetClientContext(wt);
#elif defined(_WAYLAND)
	return wlWidgetClientContext(wt);
#endif
}

visual_t _widget_window_context(widget_t wt)
{
#if defined(_X11)
	return xlWidgetWindowContext(wt);
#elif defined(_WAYLAND)
	return wlWidgetWindowContext(wt);
#endif
}

void _widget_release_context(widget_t wt, visual_t dc)
{
#if defined(_X11)
	xlWidgetReleaseContext(wt, dc);
#elif defined(_WAYLAND)
	wlWidgetReleaseContext(wt, dc);
#endif
}

void _widget_get_client_rect(widget_t wt, xrect_t* prt)
{
#if defined(_X11)
	xlWidgetGetClientRect(wt, prt);
#elif defined(_WAYLAND)
	wlWidgetGetClientRect(wt, prt);
#endif
}

void _widget_get_window_rect(widget_t wt, xrect_t* prt)
{
#if defined(_X11)
	xlWidgetGetWindowRect(wt, prt);
#elif defined(_WAYLAND)
	wlWidgetGetWindowRect(wt, prt);
#endif
}

void _widget_client_to_screen(widget_t wt, xpoint_t* ppt)
{
#if defined(_X11)
	xlWidgetClientToScreen(wt, ppt);
#elif defined(_WAYLAND)
	wlWidgetClientToScreen(wt, ppt);
#endif
}

void _widget_screen_to_client(widget_t wt, xpoint_t* ppt)
{
#if defined(_X11)
	xlWidgetScreenToClient(wt, ppt);
#elif defined(_WAYLAND)
	wlWidgetScreenToClient(wt, ppt);
#endif
}

void _widget_client_to_window(widget_t wt, xpoint_t* ppt)
{
#if defined(_X11)
	xlWidgetClientToWindow(wt, ppt);
#elif defined(_WAYLAND)
	wlWidgetClientToWindow(wt, ppt);
#endif
}

void _widget_window_to_client(widget_t wt, xpoint_t* ppt)
{
#if defined(_X11)
	xlWidgetWindowToClient(wt, ppt);
#elif defined(_WAYLAND)
	wlWidgetWindowToClient(wt, ppt);
#endif
}

void _widget_center_window(widget_t wt, widget_t owner)
{
#if defined(_X11)
	xlWidgetCenterWindow(wt, owner);
#elif defined(_WAYLAND)
	wlWidgetCenterWindow(wt, owner);
#endif
}

void _widget_set_cursor(widget_t wt, int ci)
{
#if defined(_X11)
	xlWidgetSetCursor(wt, ci);
#elif defined(_WAYLAND)
	wlWidgetSetCursor(wt, ci);
#endif
}

void _widget_set_capture(widget_t wt, bool_t b)
{
#if defined(_X11)
	xlWidgetSetCapture(wt, b);
#elif defined(_WAYLAND)
	wlWidgetSetCapture(wt, b);
#endif
}

vword_t _widget_set_timer(widget_t wt, int ms)
{
#if defined(_X11)
	return xlWidgetSetTimer(wt, ms);
#elif defined(_WAYLAND)
	return wlWidgetSetTimer(wt, ms);
#endif
}

void _widget_kill_timer(widget_t wt, vword_t tid)
{
#if defined(_X11)
	xlWidgetKillTimer(wt, tid);
#elif defined(_WAYLAND)
	wlWidgetKillTimer(wt, tid);
#endif
}

void _widget_create_caret(widget_t wt, int w, int h)
{
#if defined(_X11)
	xlWidgetCreateCaret(wt, w, h);
#elif defined(_WAYLAND)
	wlWidgetCreateCaret(wt, w, h);
#endif
}

void _widget_destroy_caret(widget_t wt)
{
#if defined(_X11)
	xlWidgetDestroyCaret(wt);
#elif defined(_WAYLAND)
	wlWidgetDestroyCaret(wt);
#endif
}

void _widget_show_caret(widget_t wt, int x, int y)
{
#if defined(_X11)
	xlWidgetShowCaret(wt, x, y);
#elif defined(_WAYLAND)
	wlWidgetShowCaret(wt, x, y);
#endif
}

void _widget_set_focus(widget_t wt)
{
#if defined(_X11)
	xlWidgetSetFocus(wt);
#elif defined(_WAYLAND)
	wlWidgetSetFocus(wt);
#endif
}

bool_t _widget_key_state(widget_t wt, int ks)
{
#if defined(_X11)
	return xlWidgetKeyState(wt, ks);
#elif defined(_WAYLAND)
	return wlWidgetKeyState(wt, ks);
#endif
}

bool_t _widget_is_valid(widget_t wt)
{
#if defined(_X11)
	return xlWidgetIsValid(wt);
#elif defined(_WAYLAND)
	return wlWidgetIsValid(wt);
#endif
}

bool_t _widget_is_focus(widget_t wt)
{
#if defined(_X11)
	return xlWidgetIsFocus(wt);
#elif defined(_WAYLAND)
	return wlWidgetIsFocus(wt);
#endif
}

bool_t _widget_is_child(widget_t wt)
{
#if defined(_X11)
	return xlWidgetIsChild(wt);
#elif defined(_WAYLAND)
	return wlWidgetIsChild(wt);
#endif
}

bool_t _widget_is_ownc(widget_t wt)
{
#if defined(_X11)
	return xlWidgetIsOwnerNc(wt);
#elif defined(_WAYLAND)
	return wlWidgetIsOwnerNc(wt);
#endif
}

void _widget_move(widget_t wt, const xpoint_t* ppt)
{
#if defined(_X11)
	xlWidgetMove(wt, ppt);
#elif defined(_WAYLAND)
	wlWidgetMove(wt, ppt);
#endif
}

void _widget_size(widget_t wt, const xsize_t* pxs)
{
#if defined(_X11)
	xlWidgetSize(wt, pxs);
#elif defined(_WAYLAND)
	wlWidgetSize(wt, pxs);
#endif
}

void _widget_take(widget_t wt, int zor)
{
#if defined(_X11)
	xlWidgetTake(wt, zor);
#elif defined(_WAYLAND)
	wlWidgetTake(wt, zor);
#endif
}

void _widget_show(widget_t wt, dword_t sw)
{
#if defined(_X11)
	xlWidgetShow(wt, sw);
#elif defined(_WAYLAND)
	wlWidgetShow(wt, sw);
#endif
}

void _widget_layout(widget_t wt)
{
#if defined(_X11)
	xlWidgetLayout(wt);
#elif defined(_WAYLAND)
	wlWidgetLayout(wt);
#endif
}

void _widget_erase(widget_t wt, const xrect_t* prt)
{
#if defined(_X11)
	xlWidgetErase(wt, prt);
#elif defined(_WAYLAND)
	wlWidgetErase(wt, prt);
#endif
}

void _widget_enable(widget_t wt, bool_t b)
{
#if defined(_X11)
	xlWidgetEnable(wt, b);
#elif defined(_WAYLAND)
	wlWidgetEnable(wt, b);
#endif
}

void _widget_enable_hover(widget_t wt, bool_t b)
{
#if defined(_X11)
	xlWidgetEnableHover(wt, b);
#elif defined(_WAYLAND)
	wlWidgetEnableHover(wt, b);
#endif
}

void _widget_post_notice(widget_t wt, NOTICE* pnt)
{
#if defined(_X11)
	xlWidgetPostNotice(wt, pnt);
#elif defined(_WAYLAND)
	wlWidgetPostNotice(wt, pnt);
#endif
}

int _widget_send_notice(widget_t wt, NOTICE* pnt)
{
#if defined(_X11)
	return xlWidgetSendNotice(wt, pnt);
#elif defined(_WAYLAND)
	return wlWidgetSendNotice(wt, pnt);
#endif
}

void _widget_post_command(widget_t wt, int code, uid_t cid, vword_t data)
{
#if defined(_X11)
	xlWidgetPostCommand(wt, code, cid, data);
#elif defined(_WAYLAND)
	wlWidgetPostCommand(wt, code, cid, data);
#endif
}

int _widget_send_command(widget_t wt, int code, uid_t cid, vword_t data)
{
#if defined(_X11)
	return xlWidgetSendCommand(wt, code, cid, data);
#elif defined(_WAYLAND)
	return wlWidgetSendCommand(wt, code, cid, data);
#endif
}

void _widget_post_wchar(widget_t wt, wchar_t ch)
{
#if defined(_X11)
	xlWidgetPostWChar(wt, ch);
#elif defined(_WAYLAND)
	wlWidgetPostWChar(wt, ch);
#endif
}

void _widget_post_key(widget_t wt, int key)
{
#if defined(_X11)
	xlWidgetPostKey(wt, key);
#elif defined(_WAYLAND)
	wlWidgetPostKey(wt, key);
#endif
}

void _widget_set_title(widget_t wt, const tchar_t* token)
{
#if defined(_X11)
	xlWidgetSetTitle(wt, token);
#elif defined(_WAYLAND)
	wlWidgetSetTitle(wt, token);
#endif
}

int _widget_get_title(widget_t wt, tchar_t* buf, int max)
{
#if defined(_X11)
	return xlWidgetGetTitle(wt, buf, max);
#elif defined(_WAYLAND)
	return wlWidgetGetTitle(wt, buf, max);
#endif
}

void _widget_active(widget_t wt)
{
#if defined(_X11)
	xlWidgetActive(wt);
#elif defined(_WAYLAND)
	wlWidgetActive(wt);
#endif
}

void _widget_scroll(widget_t wt, bool_t horz, int line)
{
#if defined(_X11)
	xlWidgetScroll(wt, horz, line);
#elif defined(_WAYLAND)
	wlWidgetScroll(wt, horz, line);
#endif
}

void _widget_get_scroll_info(widget_t wt, bool_t horz, scroll_t* psl)
{
#if defined(_X11)
	xlWidgetGetScrollInfo(wt, horz, psl);
#elif defined(_WAYLAND)
	wlWidgetGetScrollInfo(wt, horz, psl);
#endif
}

void _widget_set_scroll_info(widget_t wt, bool_t horz, const scroll_t* psl)
{
#if defined(_X11)
	xlWidgetSetScrollInfo(wt, horz, psl);
#elif defined(_WAYLAND)
	wlWidgetSetScrollInfo(wt, horz, psl);
#endif
}

void _widget_set_color_mode(widget_t wt, const color_mod_t* pclr)
{
#if defined(_X11)
	xlWidgetSetColorMode(wt, pclr);
#elif defined(_WAYLAND)
	wlWidgetSetColorMode(wt, pclr);
#endif
}

void _widget_get_color_mode(widget_t wt, color_mod_t* pclr)
{
#if defined(_X11)
	xlWidgetGetColorMode(wt, pclr);
#elif defined(_WAYLAND)
	wlWidgetGetColorMode(wt, pclr);
#endif
}

const color_mod_t* _widget_get_color_mode_ptr(widget_t wt)
{
#if defined(_X11)
	return xlWidgetGetColorModePtr(wt);
#elif defined(_WAYLAND)
	return wlWidgetGetColorModePtr(wt);
#endif
}

void _widget_set_diaph(widget_t wt, float f)
{
#if defined(_X11)
	xlWidgetSetDiaph(wt, f);
#elif defined(_WAYLAND)
	wlWidgetSetDiaph(wt, f);
#endif
}

float _widget_get_diaph(widget_t wt)
{
#if defined(_X11)
	return xlWidgetGetDiaph(wt);
#elif defined(_WAYLAND)
	return wlWidgetGetDiaph(wt);
#endif
}

int	_widget_do_main(widget_t wt)
{
#if defined(_X11)
	return xlWidgetDoMain(wt);
#elif defined(_WAYLAND)
	return wlWidgetDoMain(wt);
#endif
}

int	_widget_do_modal(widget_t wt)
{
#if defined(_X11)
	return xlWidgetDoModal(wt);
#elif defined(_WAYLAND)
	return wlWidgetDoModal(wt);
#endif
}

void _widget_do_track(widget_t wt)
{
#if defined(_X11)
	xlWidgetDoTrack(wt);
#elif defined(_WAYLAND)
	wlWidgetDoTrack(wt);
#endif
}

void _message_quit(int code)
{
#if defined(_X11)
	xlMessageQuit(code);
#elif defined(_WAYLAND)
	wlMessageQuit(code);
#endif
}

void _message_position(xpoint_t* pxp)
{
#if defined(_X11)
	xlMessagePosition(pxp);
#elif defined(_WAYLAND)
	wlMessagePosition(pxp);
#endif
}

/*********************************************************************************************************/
void _calc_widget_border(dword_t ws, border_t* pbd)
{
#if defined(_X11)
	xlCalcWidgetBorder(ws, pbd);
#elif defined(_WAYLAND)
	wlCalcWidgetBorder(ws, pbd);
#endif
}

void _adjust_widget_size(dword_t wstyle, xsize_t* pxs)
{
#if defined(_X11)
	xlAdjustWidgetSize(wstyle, pxs);
#elif defined(_WAYLAND)
	wlAdjustWidgetSize(wstyle, pxs);
#endif
}

void _get_screen_size(xsize_t* pxs)
{
#if defined(_X11)
	xlGetScreenSize(pxs);
#elif defined(_WAYLAND)
	wlGetScreenSize(pxs);
#endif
}

void _get_desktop_rect(xrect_t* pxr)
{
#if defined(_X11)
	xlGetDesktopRect(pxr);
#elif defined(_WAYLAND)
	wlGetDesktopRect(pxr);
#endif
}

void _screen_size_to_mm(xsize_t* pxs)
{
#if defined(_X11)
	xlScreenSizeToMm(pxs);
#elif defined(_WAYLAND)
	wlScreenSizeToMm(pxs);
#endif
}

void _screen_size_to_pt(xsize_t* pxs)
{
#if defined(_X11)
	xlScreenSizeToPt(pxs);
#elif defined(_WAYLAND)
	wlScreenSizeToPt(pxs);
#endif
}

#endif //XDU_SUPPORT_WIDGET
