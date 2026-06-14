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

#if defined(_COCOA)
#include "cocoa/_if_cocoa.h"
#elif defined(_XQUARTZ)
#include "xquartz/_if_xquartz.h"
#endif

#ifdef XDU_SUPPORT_WIDGET


void _widget_startup(int ver)
{
#if defined(_COCOA)
	coWidgetStartup(ver);
#elif defined(_XQUARTZ)
	xqWidgetStartup(ver);
#endif
}

void _widget_cleanup()
{
#if defined(_COCOA)
	coWidgetCleanup();
#elif defined(_XQUARTZ)
	xqWidgetCleanup();
#endif
}

widget_t _widget_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev)
{
#if defined(_COCOA)
	return coWidgetCreate(wname, wstyle, pxr, wparent, pev);
#elif defined(_XQUARTZ)
	return xqWidgetCreate(wname, wstyle, pxr, wparent, pev);
#endif
}

void _widget_destroy(widget_t wt)
{
#if defined(_COCOA)
	coWidgetDestroy(wt);
#elif defined(_XQUARTZ)
	xqWidgetDestroy(wt);
#endif
}

void _widget_close(widget_t wt, int ret)
{
#if defined(_COCOA)
	coWidgetClose(wt, ret);
#elif defined(_XQUARTZ)
	xqWidgetClose(wt, ret);
#endif
}

const if_subproc_t* _widget_get_subproc(widget_t wt, uid_t sid)
{
#if defined(_COCOA)
	return coWidgetGetSubproc(wt, sid);
#elif defined(_XQUARTZ)
	return xqWidgetGetSubproc(wt, sid);
#endif
}

bool_t _widget_set_subproc(widget_t wt, uid_t sid, if_subproc_t* sub)
{
#if defined(_COCOA)
	return coWidgetSetSubproc(wt, sid, sub);
#elif defined(_XQUARTZ)
	return xqWidgetSetSubproc(wt, sid, sub);
#endif
}

void _widget_del_subproc(widget_t wt, uid_t sid)
{
#if defined(_COCOA)
	coWidgetDelSubproc(wt, sid);
#elif defined(_XQUARTZ)
	xqWidgetDelSubproc(wt, sid);
#endif
}

bool_t _widget_set_subproc_delta(widget_t wt, uid_t sid, vword_t delta)
{
#if defined(_COCOA)
	return coWidgetSetSubprocDelta(wt, sid, delta);
#elif defined(_XQUARTZ)
	return xqWidgetSetSubprocDelta(wt, sid, delta);
#endif
}

vword_t _widget_get_subproc_delta(widget_t wt, uid_t sid)
{
#if defined(_COCOA)
	return coWidgetGetSubprocDelta(wt, sid);
#elif defined(_XQUARTZ)
	return xqWidgetGetSubprocDelta(wt, sid);
#endif
}

bool_t _widget_has_subproc(widget_t wt, uid_t sid)
{
#if defined(_COCOA)
	return coWidgetHasSubproc(wt, sid);
#elif defined(_XQUARTZ)
	return xqWidgetHasSubproc(wt, sid);
#endif
}

void _widget_set_core_delta(widget_t wt, vword_t pd)
{
#if defined(_COCOA)
	coWidgetSetCoreDelta(wt, pd);
#elif defined(_XQUARTZ)
	xqWidgetSetCoreDelta(wt, pd);
#endif
}

vword_t _widget_get_core_delta(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetGetCoreDelta(wt);
#elif defined(_XQUARTZ)
	return xqWidgetGetCoreDelta(wt);
#endif
}

void _widget_set_user_delta(widget_t wt, vword_t pd)
{
#if defined(_COCOA)
	coWidgetSetUserDelta(wt, pd);
#elif defined(_XQUARTZ)
	xqWidgetSetUserDelta(wt, pd);
#endif
}

vword_t _widget_get_user_delta(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetGetUserDelta(wt);
#elif defined(_XQUARTZ)
	return xqWidgetGetUserDelta(wt);
#endif
}

void _widget_set_style(widget_t wt, dword_t ws)
{
#if defined(_COCOA)
	coWidgetSetStyle(wt, ws);
#elif defined(_XQUARTZ)
	xqWidgetSetStyle(wt, ws);
#endif
}

dword_t _widget_get_style(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetGetStyle(wt);
#elif defined(_XQUARTZ)
	return xqWidgetGetStyle(wt);
#endif
}

void _widget_set_accel(widget_t wt, const accel_table_t* pacl, int n)
{
#if defined(_COCOA)
	coWidgetSetAccel(wt, pacl, n);
#elif defined(_XQUARTZ)
	xqWidgetSetAccel(wt, pacl, n);
#endif
}

void _widget_set_owner(widget_t wt, widget_t owner)
{
#if defined(_COCOA)
	coWidgetSetOwner(wt, owner);
#elif defined(_XQUARTZ)
	xqWidgetSetOwner(wt, owner);
#endif
}

widget_t _widget_get_owner(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetGetOwner(wt);
#elif defined(_XQUARTZ)
	return xqWidgetGetOwner(wt);
#endif
}

void _widget_set_user_id(widget_t wt, uid_t uid)
{
#if defined(_COCOA)
	coWidgetSetUserId(wt, uid);
#elif defined(_XQUARTZ)
	xqWidgetSetUserId(wt, uid);
#endif
}

uid_t _widget_get_user_id(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetGetUserId(wt);
#elif defined(_XQUARTZ)
	return xqWidgetGetUserId(wt);
#endif
}

void _widget_set_user_result(widget_t wt, int rt)
{
#if defined(_COCOA)
	coWidgetSetUserResult(wt, rt);
#elif defined(_XQUARTZ)
	xqWidgetSetUserResult(wt, rt);
#endif
}

int _widget_get_user_result(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetGetUserResult(wt);
#elif defined(_XQUARTZ)
	return xqWidgetGetUserResult(wt);
#endif
}

widget_t _widget_get_child(widget_t wt, uid_t uid)
{
#if defined(_COCOA)
	return coWidgetGetChild(wt, uid);
#elif defined(_XQUARTZ)
	return xqWidgetGetChild(wt, uid);
#endif
}

widget_t _widget_get_parent(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetGetParent(wt);
#elif defined(_XQUARTZ)
	return xqWidgetGetParent(wt);
#endif
}

void _widget_set_user_prop(widget_t wt, const tchar_t* pname,vword_t val)
{
#if defined(_COCOA)
	coWidgetSetUserProp(wt, pname, val);
#elif defined(_XQUARTZ)
	xqWidgetSetUserProp(wt, pname, val);
#endif
}

vword_t _widget_get_user_prop(widget_t wt, const tchar_t* pname)
{
#if defined(_COCOA)
	return coWidgetGetUserProp(wt, pname);
#elif defined(_XQUARTZ)
	return xqWidgetGetUserProp(wt, pname);
#endif
}

vword_t _widget_del_user_prop(widget_t wt, const tchar_t* pname)
{
#if defined(_COCOA)
	return coWidgetDelUserProp(wt, pname);
#elif defined(_XQUARTZ)
	return xqWidgetDelUserProp(wt, pname);
#endif
}

const if_dispatch_t* _widget_get_dispatch(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetGetDispatch(wt);
#elif defined(_XQUARTZ)
	return xqWidgetGetDispatch(wt);
#endif
}

bool_t _widget_is_maximized(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetIsMaximized(wt);
#elif defined(_XQUARTZ)
	return xqWidgetIsMaximized(wt);
#endif
}

bool_t _widget_is_minimized(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetIsMinimized(wt);
#elif defined(_XQUARTZ)
	return xqWidgetIsMinimized(wt);
#endif
}

bool_t _widget_enum_child(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv)
{
#if defined(_COCOA)
	return coWidgetEnumChild(wt, pf, pv);
#elif defined(_XQUARTZ)
	return xqWidgetEnumChild(wt, pf, pv);
#endif
}

visual_t _widget_client_context(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetClientContext(wt);
#elif defined(_XQUARTZ)
	return xqWidgetClientContext(wt);
#endif
}

visual_t _widget_window_context(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetWindowContext(wt);
#elif defined(_XQUARTZ)
	return xqWidgetWindowContext(wt);
#endif
}

void _widget_release_context(widget_t wt, visual_t dc)
{
#if defined(_COCOA)
	coWidgetReleaseContext(wt, dc);
#elif defined(_XQUARTZ)
	xqWidgetReleaseContext(wt, dc);
#endif
}

void _widget_get_client_rect(widget_t wt, xrect_t* prt)
{
#if defined(_COCOA)
	coWidgetGetClientRect(wt, prt);
#elif defined(_XQUARTZ)
	xqWidgetGetClientRect(wt, prt);
#endif
}

void _widget_get_window_rect(widget_t wt, xrect_t* prt)
{
#if defined(_COCOA)
	coWidgetGetWindowRect(wt, prt);
#elif defined(_XQUARTZ)
	xqWidgetGetWindowRect(wt, prt);
#endif
}

void _widget_client_to_screen(widget_t wt, xpoint_t* ppt)
{
#if defined(_COCOA)
	coWidgetClientToScreen(wt, ppt);
#elif defined(_XQUARTZ)
	xqWidgetClientToScreen(wt, ppt);
#endif
}

void _widget_screen_to_client(widget_t wt, xpoint_t* ppt)
{
#if defined(_COCOA)
	coWidgetScreenToClient(wt, ppt);
#elif defined(_XQUARTZ)
	xqWidgetScreenToClient(wt, ppt);
#endif
}

void _widget_client_to_window(widget_t wt, xpoint_t* ppt)
{
#if defined(_COCOA)
	coWidgetClientToWindow(wt, ppt);
#elif defined(_XQUARTZ)
	xqWidgetClientToWindow(wt, ppt);
#endif
}

void _widget_window_to_client(widget_t wt, xpoint_t* ppt)
{
#if defined(_COCOA)
	coWidgetWindowToClient(wt, ppt);
#elif defined(_XQUARTZ)
	xqWidgetWindowToClient(wt, ppt);
#endif
}

void _widget_center_window(widget_t wt, widget_t owner)
{
#if defined(_COCOA)
	coWidgetCenterWindow(wt, owner);
#elif defined(_XQUARTZ)
	xqWidgetCenterWindow(wt, owner);
#endif
}

void _widget_set_cursor(widget_t wt, int ci)
{
#if defined(_COCOA)
	coWidgetSetCursor(wt, ci);
#elif defined(_XQUARTZ)
	xqWidgetSetCursor(wt, ci);
#endif
}

void _widget_set_capture(widget_t wt, bool_t b)
{
#if defined(_COCOA)
	coWidgetSetCapture(wt, b);
#elif defined(_XQUARTZ)
	xqWidgetSetCapture(wt, b);
#endif
}

vword_t _widget_set_timer(widget_t wt, int ms)
{
#if defined(_COCOA)
	return coWidgetSetTimer(wt, ms);
#elif defined(_XQUARTZ)
	return xqWidgetSetTimer(wt, ms);
#endif
}

void _widget_kill_timer(widget_t wt, vword_t tid)
{
#if defined(_COCOA)
	coWidgetKillTimer(wt, tid);
#elif defined(_XQUARTZ)
	xqWidgetKillTimer(wt, tid);
#endif
}

void _widget_create_caret(widget_t wt, int w, int h)
{
#if defined(_COCOA)
	coWidgetCreateCaret(wt, w, h);
#elif defined(_XQUARTZ)
	xqWidgetCreateCaret(wt, w, h);
#endif
}

void _widget_destroy_caret(widget_t wt)
{
#if defined(_COCOA)
	coWidgetDestroyCaret(wt);
#elif defined(_XQUARTZ)
	xqWidgetDestroyCaret(wt);
#endif
}

void _widget_show_caret(widget_t wt, int x, int y)
{
#if defined(_COCOA)
	coWidgetShowCaret(wt, x, y);
#elif defined(_XQUARTZ)
	xqWidgetShowCaret(wt, x, y);
#endif
}

void _widget_set_focus(widget_t wt)
{
#if defined(_COCOA)
	coWidgetSetFocus(wt);
#elif defined(_XQUARTZ)
	xqWidgetSetFocus(wt);
#endif
}

bool_t _widget_key_state(widget_t wt, int ks)
{
#if defined(_COCOA)
	return coWidgetKeyState(wt, ks);
#elif defined(_XQUARTZ)
	return xqWidgetKeyState(wt, ks);
#endif
}

bool_t _widget_is_valid(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetIsValid(wt);
#elif defined(_XQUARTZ)
	return xqWidgetIsValid(wt);
#endif
}

bool_t _widget_is_focus(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetIsFocus(wt);
#elif defined(_XQUARTZ)
	return xqWidgetIsFocus(wt);
#endif
}

bool_t _widget_is_child(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetIsChild(wt);
#elif defined(_XQUARTZ)
	return xqWidgetIsChild(wt);
#endif
}

bool_t _widget_is_ownc(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetIsOwnerNc(wt);
#elif defined(_XQUARTZ)
	return xqWidgetIsOwnerNc(wt);
#endif
}

void _widget_move(widget_t wt, const xpoint_t* ppt)
{
#if defined(_COCOA)
	coWidgetMove(wt, ppt);
#elif defined(_XQUARTZ)
	xqWidgetMove(wt, ppt);
#endif
}

void _widget_size(widget_t wt, const xsize_t* pxs)
{
#if defined(_COCOA)
	coWidgetSize(wt, pxs);
#elif defined(_XQUARTZ)
	xqWidgetSize(wt, pxs);
#endif
}

void _widget_take(widget_t wt, int zor)
{
#if defined(_COCOA)
	coWidgetTake(wt, zor);
#elif defined(_XQUARTZ)
	xqWidgetTake(wt, zor);
#endif
}

void _widget_show(widget_t wt, dword_t sw)
{
#if defined(_COCOA)
	coWidgetShow(wt, sw);
#elif defined(_XQUARTZ)
	xqWidgetShow(wt, sw);
#endif
}

void _widget_layout(widget_t wt)
{
#if defined(_COCOA)
	coWidgetLayout(wt);
#elif defined(_XQUARTZ)
	xqWidgetLayout(wt);
#endif
}

void _widget_erase(widget_t wt, const xrect_t* prt)
{
#if defined(_COCOA)
	coWidgetErase(wt, prt);
#elif defined(_XQUARTZ)
	xqWidgetErase(wt, prt);
#endif
}

void _widget_enable(widget_t wt, bool_t b)
{
#if defined(_COCOA)
	coWidgetEnable(wt, b);
#elif defined(_XQUARTZ)
	xqWidgetEnable(wt, b);
#endif
}

void _widget_enable_hover(widget_t wt, bool_t b)
{
#if defined(_COCOA)
	coWidgetEnableHover(wt, b);
#elif defined(_XQUARTZ)
	xqWidgetEnableHover(wt, b);
#endif
}

void _widget_post_notice(widget_t wt, NOTICE* pnt)
{
#if defined(_COCOA)
	coWidgetPostNotice(wt, pnt);
#elif defined(_XQUARTZ)
	xqWidgetPostNotice(wt, pnt);
#endif
}

int _widget_send_notice(widget_t wt, NOTICE* pnt)
{
#if defined(_COCOA)
	return coWidgetSendNotice(wt, pnt);
#elif defined(_XQUARTZ)
	return xqWidgetSendNotice(wt, pnt);
#endif
}

void _widget_post_command(widget_t wt, int code, uid_t cid, vword_t data)
{
#if defined(_COCOA)
	coWidgetPostCommand(wt, code, cid, data);
#elif defined(_XQUARTZ)
	xqWidgetPostCommand(wt, code, cid, data);
#endif
}

int _widget_send_command(widget_t wt, int code, uid_t cid, vword_t data)
{
#if defined(_COCOA)
	return coWidgetSendCommand(wt, code, cid, data);
#elif defined(_XQUARTZ)
	return xqWidgetSendCommand(wt, code, cid, data);
#endif
}

void _widget_post_wchar(widget_t wt, wchar_t ch)
{
#if defined(_COCOA)
	coWidgetPostWChar(wt, ch);
#elif defined(_XQUARTZ)
	xqWidgetPostWChar(wt, ch);
#endif
}

void _widget_post_key(widget_t wt, int key)
{
#if defined(_COCOA)
	coWidgetPostKey(wt, key);
#elif defined(_XQUARTZ)
	xqWidgetPostKey(wt, key);
#endif
}

void _widget_set_title(widget_t wt, const tchar_t* token)
{
#if defined(_COCOA)
	coWidgetSetTitle(wt, token);
#elif defined(_XQUARTZ)
	xqWidgetSetTitle(wt, token);
#endif
}

int _widget_get_title(widget_t wt, tchar_t* buf, int max)
{
#if defined(_COCOA)
	return coWidgetGetTitle(wt, buf, max);
#elif defined(_XQUARTZ)
	return xqWidgetGetTitle(wt, buf, max);
#endif
}

void _widget_active(widget_t wt)
{
#if defined(_COCOA)
	coWidgetActive(wt);
#elif defined(_XQUARTZ)
	xqWidgetActive(wt);
#endif
}

void _widget_scroll(widget_t wt, bool_t horz, int line)
{
#if defined(_COCOA)
	coWidgetScroll(wt, horz, line);
#elif defined(_XQUARTZ)
	xqWidgetScroll(wt, horz, line);
#endif
}

void _widget_get_scroll_info(widget_t wt, bool_t horz, scroll_t* psl)
{
#if defined(_COCOA)
	coWidgetGetScrollInfo(wt, horz, psl);
#elif defined(_XQUARTZ)
	xqWidgetGetScrollInfo(wt, horz, psl);
#endif
}

void _widget_set_scroll_info(widget_t wt, bool_t horz, const scroll_t* psl)
{
#if defined(_COCOA)
	coWidgetSetScrollInfo(wt, horz, psl);
#elif defined(_XQUARTZ)
	xqWidgetSetScrollInfo(wt, horz, psl);
#endif
}

void _widget_set_color_mode(widget_t wt, const color_mod_t* pclr)
{
#if defined(_COCOA)
	coWidgetSetColorMode(wt, pclr);
#elif defined(_XQUARTZ)
	xqWidgetSetColorMode(wt, pclr);
#endif
}

void _widget_get_color_mode(widget_t wt, color_mod_t* pclr)
{
#if defined(_COCOA)
	coWidgetGetColorMode(wt, pclr);
#elif defined(_XQUARTZ)
	xqWidgetGetColorMode(wt, pclr);
#endif
}

const color_mod_t* _widget_get_color_mode_ptr(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetGetColorModePtr(wt);
#elif defined(_XQUARTZ)
	return xqWidgetGetColorModePtr(wt);
#endif
}

void _widget_set_diaph(widget_t wt, float f)
{
#if defined(_COCOA)
	coWidgetSetDiaph(wt, f);
#elif defined(_XQUARTZ)
	xqWidgetSetDiaph(wt, f);
#endif
}

float _widget_get_diaph(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetGetDiaph(wt);
#elif defined(_XQUARTZ)
	return xqWidgetGetDiaph(wt);
#endif
}

int	_widget_do_main(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetDoMain(wt);
#elif defined(_XQUARTZ)
	return xqWidgetDoMain(wt);
#endif
}

int	_widget_do_modal(widget_t wt)
{
#if defined(_COCOA)
	return coWidgetDoModal(wt);
#elif defined(_XQUARTZ)
	return xqWidgetDoModal(wt);
#endif
}

void _widget_do_track(widget_t wt)
{
#if defined(_COCOA)
	coWidgetDoTrack(wt);
#elif defined(_XQUARTZ)
	xqWidgetDoTrack(wt);
#endif
}

void _message_quit(int code)
{
#if defined(_COCOA)
	coMessageQuit(code);
#elif defined(_XQUARTZ)
	xqMessageQuit(code);
#endif
}

void _message_position(xpoint_t* pxp)
{
#if defined(_COCOA)
	coMessagePosition(pxp);
#elif defined(_XQUARTZ)
	xqMessagePosition(pxp);
#endif
}

/*********************************************************************************************************/
void _calc_widget_border(dword_t ws, border_t* pbd)
{
#if defined(_COCOA)
	coCalcWidgetBorder(ws, pbd);
#elif defined(_XQUARTZ)
	xqCalcWidgetBorder(ws, pbd);
#endif
}

void _adjust_widget_size(dword_t wstyle, xsize_t* pxs)
{
#if defined(_COCOA)
	coAdjustWidgetSize(wstyle, pxs);
#elif defined(_XQUARTZ)
	xqAdjustWidgetSize(wstyle, pxs);
#endif
}

void _get_screen_size(xsize_t* pxs)
{
#if defined(_COCOA)
	coGetScreenSize(pxs);
#elif defined(_XQUARTZ)
	xqGetScreenSize(pxs);
#endif
}

void _get_desktop_rect(xrect_t* pxr)
{
#if defined(_COCOA)
	coGetDesktopRect(pxr);
#elif defined(_XQUARTZ)
	xqGetDesktopRect(pxr);
#endif
}

void _screen_size_to_mm(xsize_t* pxs)
{
#if defined(_COCOA)
	coScreenSizeToMm(pxs);
#elif defined(_XQUARTZ)
	xqScreenSizeToMm(pxs);
#endif
}

void _screen_size_to_pt(xsize_t* pxs)
{
#if defined(_COCOA)
	coScreenSizeToPt(pxs);
#elif defined(_XQUARTZ)
	xqScreenSizeToPt(pxs);
#endif
}

#endif //XDU_SUPPORT_WIDGET
