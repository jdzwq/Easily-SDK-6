/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc widget document

	@module	_if_widget_win.c | widnows implement file

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

#if defined(_WCE)
#include "wince/_if_wince.h"
#elif defined(_W32)
#include "win32/_if_win32.h"
#endif

#ifdef XDU_SUPPORT_WIDGET


void _widget_startup(int ver)
{
#if defined(WINCE)
	wceWidgetStartup(ver);
#elif defined(WIN32)
	winWidgetStartup(ver);
#endif
}

void _widget_cleanup()
{
#if defined(WINCE)
	wceWidgetCleanup();
#elif defined(WIN32)
	winWidgetCleanup();
#endif
}

widget_t _widget_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev)
{
#if defined(WINCE)
	return wceWidgetCreate(wname, wstyle, pxr, wparent, pev);
#elif defined(WIN32)
	return winWidgetCreate(wname, wstyle, pxr, wparent, pev);
#endif
}

void _widget_destroy(widget_t wt)
{
#if defined(WINCE)
	wceWidgetDestroy(wt);
#elif defined(WIN32)
	winWidgetDestroy(wt);
#endif
}

void _widget_close(widget_t wt, int ret)
{
#if defined(WINCE)
	wceWidgetClose(wt, ret);
#elif defined(WIN32)
	winWidgetClose(wt, ret);
#endif
}

const if_subproc_t* _widget_get_subproc(widget_t wt, uid_t sid)
{
#if defined(WINCE)
	return wceWidgetGetSubproc(wt, sid);
#elif defined(WIN32)
	return winWidgetGetSubproc(wt, sid);
#endif
}

bool_t _widget_set_subproc(widget_t wt, uid_t sid, if_subproc_t* sub)
{
#if defined(WINCE)
	return wceWidgetSetSubproc(wt, sid, sub);
#elif defined(WIN32)
	return winWidgetSetSubproc(wt, sid, sub);
#endif
}

void _widget_del_subproc(widget_t wt, uid_t sid)
{
#if defined(WINCE)
	wceWidgetDelSubproc(wt, sid);
#elif defined(WIN32)
	winWidgetDelSubproc(wt, sid);
#endif
}

bool_t _widget_set_subproc_delta(widget_t wt, uid_t sid, vword_t delta)
{
#if defined(WINCE)
	return wceWidgetSetSubprocDelta(wt, sid, delta);
#elif defined(WIN32)
	return winWidgetSetSubprocDelta(wt, sid, delta);
#endif
}

vword_t _widget_get_subproc_delta(widget_t wt, uid_t sid)
{
#if defined(WINCE)
	return wceWidgetGetSubprocDelta(wt, sid);
#elif defined(WIN32)
	return winWidgetGetSubprocDelta(wt, sid);
#endif
}

bool_t _widget_has_subproc(widget_t wt, uid_t sid)
{
#if defined(WINCE)
	return wceWidgetHasSubproc(wt, sid);
#elif defined(WIN32)
	return winWidgetHasSubproc(wt, sid);
#endif
}

void _widget_set_core_delta(widget_t wt, vword_t pd)
{
#if defined(WINCE)
	wceWidgetSetCoreDelta(wt, pd);
#elif defined(WIN32)
	winWidgetSetCoreDelta(wt, pd);
#endif
}

vword_t _widget_get_core_delta(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetGetCoreDelta(wt);
#elif defined(WIN32)
	return winWidgetGetCoreDelta(wt);
#endif
}

void _widget_set_user_delta(widget_t wt, vword_t pd)
{
#if defined(WINCE)
	wceWidgetSetUserDelta(wt, pd);
#elif defined(WIN32)
	winWidgetSetUserDelta(wt, pd);
#endif
}

vword_t _widget_get_user_delta(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetGetUserDelta(wt);
#elif defined(WIN32)
	return winWidgetGetUserDelta(wt);
#endif
}

void _widget_set_style(widget_t wt, dword_t ws)
{
#if defined(WINCE)
	wceWidgetSetStyle(wt, ws);
#elif defined(WIN32)
	winWidgetSetStyle(wt, ws);
#endif
}

dword_t _widget_get_style(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetGetStyle(wt);
#elif defined(WIN32)
	return winWidgetGetStyle(wt);
#endif
}

void _widget_set_accel(widget_t wt, const accel_table_t* pacl, int n)
{
#if defined(WINCE)
	wceWidgetSetAccel(wt, pacl, n);
#elif defined(WIN32)
	winWidgetSetAccel(wt, pacl, n);
#endif
}

void _widget_set_owner(widget_t wt, widget_t owner)
{
#if defined(WINCE)
	wceWidgetSetOwner(wt, owner);
#elif defined(WIN32)
	winWidgetSetOwner(wt, owner);
#endif
}

widget_t _widget_get_owner(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetGetOwner(wt);
#elif defined(WIN32)
	return winWidgetGetOwner(wt);
#endif
}

void _widget_set_user_id(widget_t wt, uid_t uid)
{
#if defined(WINCE)
	wceWidgetSetUserId(wt, uid);
#elif defined(WIN32)
	winWidgetSetUserId(wt, uid);
#endif
}

uid_t _widget_get_user_id(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetGetUserId(wt);
#elif defined(WIN32)
	return winWidgetGetUserId(wt);
#endif
}

void _widget_set_user_result(widget_t wt, int rt)
{
#if defined(WINCE)
	wceWidgetSetUserResult(wt, rt);
#elif defined(WIN32)
	winWidgetSetUserResult(wt, rt);
#endif
}

int _widget_get_user_result(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetGetUserResult(wt);
#elif defined(WIN32)
	return winWidgetGetUserResult(wt);
#endif
}

widget_t _widget_get_child(widget_t wt, uid_t uid)
{
#if defined(WINCE)
	return wceWidgetGetChild(wt, uid);
#elif defined(WIN32)
	return winWidgetGetChild(wt, uid);
#endif
}

widget_t _widget_get_parent(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetGetParent(wt);
#elif defined(WIN32)
	return winWidgetGetParent(wt);
#endif
}

void _widget_set_user_prop(widget_t wt, const tchar_t* pname,vword_t val)
{
#if defined(WINCE)
	wceWidgetSetUserProp(wt, pname, val);
#elif defined(WIN32)
	winWidgetSetUserProp(wt, pname, val);
#endif
}

vword_t _widget_get_user_prop(widget_t wt, const tchar_t* pname)
{
#if defined(WINCE)
	return wceWidgetGetUserProp(wt, pname);
#elif defined(WIN32)
	return winWidgetGetUserProp(wt, pname);
#endif
}

vword_t _widget_del_user_prop(widget_t wt, const tchar_t* pname)
{
#if defined(WINCE)
	return wceWidgetDelUserProp(wt, pname);
#elif defined(WIN32)
	return winWidgetDelUserProp(wt, pname);
#endif
}

const if_dispatch_t* _widget_get_dispatch(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetGetDispatch(wt);
#elif defined(WIN32)
	return winWidgetGetDispatch(wt);
#endif
}

bool_t _widget_is_maximized(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetIsMaximized(wt);
#elif defined(WIN32)
	return winWidgetIsMaximized(wt);
#endif
}

bool_t _widget_is_minimized(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetIsMinimized(wt);
#elif defined(WIN32)
	return winWidgetIsMinimized(wt);
#endif
}

bool_t _widget_enum_child(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv)
{
#if defined(WINCE)
	return wceWidgetEnumChild(wt, pf, pv);
#elif defined(WIN32)
	return winWidgetEnumChild(wt, pf, pv);
#endif
}

visual_t _widget_client_context(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetClientContext(wt);
#elif defined(WIN32)
	return winWidgetClientContext(wt);
#endif
}

visual_t _widget_window_context(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetWindowContext(wt);
#elif defined(WIN32)
	return winWidgetWindowContext(wt);
#endif
}

void _widget_release_context(widget_t wt, visual_t dc)
{
#if defined(WINCE)
	wceWidgetReleaseContext(wt, dc);
#elif defined(WIN32)
	winWidgetReleaseContext(wt, dc);
#endif
}

void _widget_get_client_rect(widget_t wt, xrect_t* prt)
{
#if defined(WINCE)
	wceWidgetGetClientRect(wt, prt);
#elif defined(WIN32)
	winWidgetGetClientRect(wt, prt);
#endif
}

void _widget_get_window_rect(widget_t wt, xrect_t* prt)
{
#if defined(WINCE)
	wceWidgetGetWindowRect(wt, prt);
#elif defined(WIN32)
	winWidgetGetWindowRect(wt, prt);
#endif
}

void _widget_client_to_screen(widget_t wt, xpoint_t* ppt)
{
#if defined(WINCE)
	wceWidgetClientToScreen(wt, ppt);
#elif defined(WIN32)
	winWidgetClientToScreen(wt, ppt);
#endif
}

void _widget_screen_to_client(widget_t wt, xpoint_t* ppt)
{
#if defined(WINCE)
	wceWidgetScreenToClient(wt, ppt);
#elif defined(WIN32)
	winWidgetScreenToClient(wt, ppt);
#endif
}

void _widget_client_to_window(widget_t wt, xpoint_t* ppt)
{
#if defined(WINCE)
	wceWidgetClientToWindow(wt, ppt);
#elif defined(WIN32)
	winWidgetClientToWindow(wt, ppt);
#endif
}

void _widget_window_to_client(widget_t wt, xpoint_t* ppt)
{
#if defined(WINCE)
	wceWidgetWindowToClient(wt, ppt);
#elif defined(WIN32)
	winWidgetWindowToClient(wt, ppt);
#endif
}

void _widget_center_window(widget_t wt, widget_t owner)
{
#if defined(WINCE)
	wceWidgetCenterWindow(wt, owner);
#elif defined(WIN32)
	winWidgetCenterWindow(wt, owner);
#endif
}

void _widget_set_cursor(widget_t wt, int ci)
{
#if defined(WINCE)
	wceWidgetSetCursor(wt, ci);
#elif defined(WIN32)
	winWidgetSetCursor(wt, ci);
#endif
}

void _widget_set_capture(widget_t wt, bool_t b)
{
#if defined(WINCE)
	wceWidgetSetCapture(wt, b);
#elif defined(WIN32)
	winWidgetSetCapture(wt, b);
#endif
}

vword_t _widget_set_timer(widget_t wt, int ms)
{
#if defined(WINCE)
	return wceWidgetSetTimer(wt, ms);
#elif defined(WIN32)
	return winWidgetSetTimer(wt, ms);
#endif
}

void _widget_kill_timer(widget_t wt, vword_t tid)
{
#if defined(WINCE)
	wceWidgetKillTimer(wt, tid);
#elif defined(WIN32)
	winWidgetKillTimer(wt, tid);
#endif
}

void _widget_create_caret(widget_t wt, int w, int h)
{
#if defined(WINCE)
	wceWidgetCreateCaret(wt, w, h);
#elif defined(WIN32)
	winWidgetCreateCaret(wt, w, h);
#endif
}

void _widget_destroy_caret(widget_t wt)
{
#if defined(WINCE)
	wceWidgetDestroyCaret(wt);
#elif defined(WIN32)
	winWidgetDestroyCaret(wt);
#endif
}

void _widget_show_caret(widget_t wt, int x, int y)
{
#if defined(WINCE)
	wceWidgetShowCaret(wt, x, y);
#elif defined(WIN32)
	winWidgetShowCaret(wt, x, y);
#endif
}

void _widget_set_focus(widget_t wt)
{
#if defined(WINCE)
	wceWidgetSetFocus(wt);
#elif defined(WIN32)
	winWidgetSetFocus(wt);
#endif
}

bool_t _widget_key_state(widget_t wt, int ks)
{
#if defined(WINCE)
	return wceWidgetKeyState(wt, ks);
#elif defined(WIN32)
	return winWidgetKeyState(wt, ks);
#endif
}

bool_t _widget_is_valid(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetIsValid(wt);
#elif defined(WIN32)
	return winWidgetIsValid(wt);
#endif
}

bool_t _widget_is_focus(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetIsFocus(wt);
#elif defined(WIN32)
	return winWidgetIsFocus(wt);
#endif
}

bool_t _widget_is_child(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetIsChild(wt);
#elif defined(WIN32)
	return winWidgetIsChild(wt);
#endif
}

bool_t _widget_is_ownc(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetIsOwnerNc(wt);
#elif defined(WIN32)
	return winWidgetIsOwnerNc(wt);
#endif
}

void _widget_move(widget_t wt, const xpoint_t* ppt)
{
#if defined(WINCE)
	wceWidgetMove(wt, ppt);
#elif defined(WIN32)
	winWidgetMove(wt, ppt);
#endif
}

void _widget_size(widget_t wt, const xsize_t* pxs)
{
#if defined(WINCE)
	wceWidgetSize(wt, pxs);
#elif defined(WIN32)
	winWidgetSize(wt, pxs);
#endif
}

void _widget_take(widget_t wt, int zor)
{
#if defined(WINCE)
	wceWidgetTake(wt, zor);
#elif defined(WIN32)
	winWidgetTake(wt, zor);
#endif
}

void _widget_show(widget_t wt, dword_t sw)
{
#if defined(WINCE)
	wceWidgetShow(wt, sw);
#elif defined(WIN32)
	winWidgetShow(wt, sw);
#endif
}

void _widget_layout(widget_t wt)
{
#if defined(WINCE)
	wceWidgetLayout(wt);
#elif defined(WIN32)
	winWidgetLayout(wt);
#endif
}

void _widget_erase(widget_t wt, const xrect_t* prt)
{
#if defined(WINCE)
	wceWidgetErase(wt, prt);
#elif defined(WIN32)
	winWidgetErase(wt, prt);
#endif
}

void _widget_enable(widget_t wt, bool_t b)
{
#if defined(WINCE)
	wceWidgetEnable(wt, b);
#elif defined(WIN32)
	winWidgetEnable(wt, b);
#endif
}

void _widget_enable_hover(widget_t wt, bool_t b)
{
#if defined(WINCE)
	wceWidgetEnableHover(wt, b);
#elif defined(WIN32)
	winWidgetEnableHover(wt, b);
#endif
}

void _widget_post_notice(widget_t wt, NOTICE* pnt)
{
#if defined(WINCE)
	wceWidgetPostNotice(wt, pnt);
#elif defined(WIN32)
	winWidgetPostNotice(wt, pnt);
#endif
}

int _widget_send_notice(widget_t wt, NOTICE* pnt)
{
#if defined(WINCE)
	return wceWidgetSendNotice(wt, pnt);
#elif defined(WIN32)
	return winWidgetSendNotice(wt, pnt);
#endif
}

void _widget_post_command(widget_t wt, int code, uid_t cid, vword_t data)
{
#if defined(WINCE)
	wceWidgetPostCommand(wt, code, cid, data);
#elif defined(WIN32)
	winWidgetPostCommand(wt, code, cid, data);
#endif
}

int _widget_send_command(widget_t wt, int code, uid_t cid, vword_t data)
{
#if defined(WINCE)
	return wceWidgetSendCommand(wt, code, cid, data);
#elif defined(WIN32)
	return winWidgetSendCommand(wt, code, cid, data);
#endif
}

void _widget_post_wchar(widget_t wt, wchar_t ch)
{
#if defined(WINCE)
	wceWidgetPostWChar(wt, ch);
#elif defined(WIN32)
	winWidgetPostWChar(wt, ch);
#endif
}

void _widget_post_key(widget_t wt, int key)
{
#if defined(WINCE)
	wceWidgetPostKey(wt, key);
#elif defined(WIN32)
	winWidgetPostKey(wt, key);
#endif
}

void _widget_set_title(widget_t wt, const tchar_t* token)
{
#if defined(WINCE)
	wceWidgetSetTitle(wt, token);
#elif defined(WIN32)
	winWidgetSetTitle(wt, token);
#endif
}

int _widget_get_title(widget_t wt, tchar_t* buf, int max)
{
#if defined(WINCE)
	return wceWidgetGetTitle(wt, buf, max);
#elif defined(WIN32)
	return winWidgetGetTitle(wt, buf, max);
#endif
}

void _widget_active(widget_t wt)
{
#if defined(WINCE)
	wceWidgetActive(wt);
#elif defined(WIN32)
	winWidgetActive(wt);
#endif
}

void _widget_scroll(widget_t wt, bool_t horz, int line)
{
#if defined(WINCE)
	wceWidgetScroll(wt, horz, line);
#elif defined(WIN32)
	winWidgetScroll(wt, horz, line);
#endif
}

void _widget_get_scroll_info(widget_t wt, bool_t horz, scroll_t* psl)
{
#if defined(WINCE)
	wceWidgetGetScrollInfo(wt, horz, psl);
#elif defined(WIN32)
	winWidgetGetScrollInfo(wt, horz, psl);
#endif
}

void _widget_set_scroll_info(widget_t wt, bool_t horz, const scroll_t* psl)
{
#if defined(WINCE)
	wceWidgetSetScrollInfo(wt, horz, psl);
#elif defined(WIN32)
	winWidgetSetScrollInfo(wt, horz, psl);
#endif
}

void _widget_set_color_mode(widget_t wt, const color_mod_t* pclr)
{
#if defined(WINCE)
	wceWidgetSetColorMode(wt, pclr);
#elif defined(WIN32)
	winWidgetSetColorMode(wt, pclr);
#endif
}

void _widget_get_color_mode(widget_t wt, color_mod_t* pclr)
{
#if defined(WINCE)
	wceWidgetGetColorMode(wt, pclr);
#elif defined(WIN32)
	winWidgetGetColorMode(wt, pclr);
#endif
}

const color_mod_t* _widget_get_color_mode_ptr(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetGetColorModePtr(wt);
#elif defined(WIN32)
	return winWidgetGetColorModePtr(wt);
#endif
}

void _widget_set_diaph(widget_t wt, float f)
{
#if defined(WINCE)
	wceWidgetSetDiaph(wt, f);
#elif defined(WIN32)
	winWidgetSetDiaph(wt, f);
#endif
}

float _widget_get_diaph(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetGetDiaph(wt);
#elif defined(WIN32)
	return winWidgetGetDiaph(wt);
#endif
}

int	_widget_do_main(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetDoMain(wt);
#elif defined(WIN32)
	return winWidgetDoMain(wt);
#endif
}

int	_widget_do_modal(widget_t wt)
{
#if defined(WINCE)
	return wceWidgetDoModal(wt);
#elif defined(WIN32)
	return winWidgetDoModal(wt);
#endif
}

void _widget_do_track(widget_t wt)
{
#if defined(WINCE)
	wceWidgetDoTrack(wt);
#elif defined(WIN32)
	winWidgetDoTrack(wt);
#endif
}

void _message_quit(int code)
{
#if defined(WINCE)
	wceMessageQuit(code);
#elif defined(WIN32)
	winMessageQuit(code);
#endif
}

void _message_position(xpoint_t* pxp)
{
#if defined(WINCE)
	wceMessagePosition(pxp);
#elif defined(WIN32)
	winMessagePosition(pxp);
#endif
}

/*********************************************************************************************************/
void _calc_widget_border(dword_t ws, border_t* pbd)
{
#if defined(WINCE)
	wceCalcWidgetBorder(ws, pbd);
#elif defined(WIN32)
	winCalcWidgetBorder(ws, pbd);
#endif
}

void _adjust_widget_size(dword_t wstyle, xsize_t* pxs)
{
#if defined(WINCE)
	wceAdjustWidgetSize(wstyle, pxs);
#elif defined(WIN32)
	winAdjustWidgetSize(wstyle, pxs);
#endif
}

void _get_screen_size(xsize_t* pxs)
{
#if defined(WINCE)
	wceGetScreenSize(pxs);
#elif defined(WIN32)
	winGetScreenSize(pxs);
#endif
}

void _get_desktop_size(xsize_t* pxs)
{
#if defined(WINCE)
	wceGetDesktopSize(pxs);
#elif defined(WIN32)
	winGetDesktopSize(pxs);
#endif
}

void _screen_size_to_mm(xsize_t* pxs)
{
#if defined(WINCE)
	wceScreenSizeToMm(pxs);
#elif defined(WIN32)
	winScreenSizeToMm(pxs);
#endif
}

void _screen_size_to_pt(xsize_t* pxs)
{
#if defined(WINCE)
	wceScreenSizeToPt(pxs);
#elif defined(WIN32)
	winScreenSizeToPt(pxs);
#endif
}

#endif //XDU_SUPPORT_WIDGET
