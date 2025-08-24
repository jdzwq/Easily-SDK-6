/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc widget document

	@module	impwin.h | interface file

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

#ifndef _IMPWIDGET_H
#define _IMPWIDGET_H

#include "../xdudef.h"

#ifdef XDU_SUPPORT_WIDGET


#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION widget_create: create frame, popup, child widget or dialog window.
@INPUT const tchar_t* wname: widget name.
@INPUT dword_t wstyle: widget style, it can be WD_STYLE_CONTROL, WD_STYLE_POPUP, WD_STYLE_DIALOG, WD_STYLE_FRAME.
@INPUT const xrect_t* pxr: rect struct for widget initialize position and size.
if wstyle is WD_STYLE_CONTROL the rect beint to parent window client, otherwise the rect is screen coordinate based.
@INPUT widget_t wparent: the parent window resource handle, child widget must have a parent window.
@INPUT if_dispatch_t* pev: the window message dispatch struct.
@RETURN widget_t: if succeeds retur window resource handle, fails return NULL.
*/
EXP_API widget_t widget_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, if_dispatch_t* pev);

/*
@FUNCTION widget_destroy: destroy the widget.
@INPUT widget_t wt: widget resource handle.
@RETURN void: none.
*/
EXP_API	void	widget_destroy(widget_t wt);

/*
@FUNCTION widget_close: close the widget and return a state value.
@INPUT widget_t wt: widget resource handle.
@INPUT int ret: the return value.
@RETURN void: none.
*/
EXP_API	void	widget_close(widget_t wt, int ret);

/*
@FUNCTION widget_get_return: get widget returned state value at closing.
@INPUT widget_t wt: widget resource handle.
@RETURN int: the closed widget return value, default is zero.
*/
EXP_API int		widget_get_return(widget_t wt);

/*
@FUNCTION widget_get_dispatch: get the widget message dispatch struct.
@INPUT widget_t wt: widget resource handle.
@RETURN if_dispatch_t: return the dispatch struct if exists, else return NULL.
*/
EXP_API const if_dispatch_t* widget_get_dispatch(widget_t wt);

/*
@FUNCTION widget_set_style: reset the widget style.
@INPUT widget_t wt: widget resource handle.
@INPUT dword_t ws: widget style, it can be WD_STYLE_HSCROLL, WD_STYLE_VSCROLL, WD_STYLE_PAGING, or combined.
@RETURN void: none.
*/
EXP_API void	widget_set_style(widget_t wt, dword_t ws);

/*
@FUNCTION widget_get_style: get the widget style.
@INPUT widget_t wt: widget resource handle.
@RETURN dword_t: widget style, it can be WD_STYLE_HSCROLL, WD_STYLE_VSCROLL, WD_STYLE_PAGING, or combined.
*/
EXP_API dword_t widget_get_style(widget_t wt);

/*
@FUNCTION widget_set_core_delta: set the widget defined data.
@INPUT widget_t wt: widget resource handle.
@INPUT vword_t pd: the widget defined data.
@RETURN void: none.
*/
EXP_API void	widget_set_core_delta(widget_t wt, vword_t pd);

/*
@FUNCTION widget_get_core_delta: get the widget defined data.
@INPUT widget_t wt: widget resource handle.
@RETURN vword_t: widget defined data.
*/
EXP_API vword_t	widget_get_core_delta(widget_t wt);

/*
@FUNCTION widget_set_user_delta: set the user defined data.
@INPUT widget_t wt: widget resource handle.
@INPUT vword_t pd: the user defined data.
@RETURN void: none.
*/
EXP_API void	widget_set_user_delta(widget_t wt, vword_t pd);

/*
@FUNCTION widget_get_user_delta: get the user defined data.
@INPUT widget_t wt: widget resource handle.
@RETURN vword_t: user defined data.
*/
EXP_API vword_t	widget_get_user_delta(widget_t wt);

/*
@FUNCTION widget_set_user_id: set the user control id.
@INPUT widget_t wt: widget resource handle.
@INPUT dword_t uid: the user control id.
@RETURN void: none.
*/
EXP_API void	widget_set_user_id(widget_t wt, dword_t uid);

/*
@FUNCTION widget_get_user_id: get the user control id.
@INPUT widget_t wt: widget resource handle.
@RETURN dword_t: user control id.
*/
EXP_API dword_t widget_get_user_id(widget_t wt);

/*
@FUNCTION widget_set_owner: set widget owner window, widget will send command, notice message to owner window.
@INPUT widget_t wt: the widget resource handle.
@INPUT widget_t owner: the owner window resource handle.
@RETURN void: none.
*/
EXP_API void	widget_set_owner(widget_t wt, widget_t owner);

/*
@FUNCTION widget_get_owner: get widget owner window, widget will send command, notice message to owner window.
@INPUT widget_t wt: the widget resource handle.
@RETURN widget_t: if succeeds return  owner window resource handle, fails return NULL.
*/
EXP_API widget_t widget_get_owner(widget_t wt);

/*
@FUNCTION widget_get_child: get child widget by control id.
@INPUT widget_t wt: the widget resource handle.
@INPUT dword_t uid: the control id.
@RETURN widget_t: if succeeds return child window resource handle, fails return NULL.
*/
EXP_API widget_t widget_get_child(widget_t wt, dword_t uid);

/*
@FUNCTION widget_get_parent: get parent widget.
@INPUT widget_t wt: the widget resource handle.
@RETURN widget_t: if succeeds return parent window resource handle, fails return NULL.
*/
EXP_API widget_t widget_get_parent(widget_t wt);

/*
@FUNCTION widget_set_user_prop: set widget property.
@INPUT widget_t wt: the widget resource handle.
@INPUT const tchar_t* pkey: the property key token.
@INPUT vword_t pval: the property value.
@RETURN void: none.
*/
EXP_API void	widget_set_user_prop(widget_t wt, const tchar_t* pkey, vword_t pval);

/*
@FUNCTION widget_get_user_prop: get widget property value by key.
@INPUT widget_t wt: the widget resource handle.
@INPUT const tchar_t* pkey: the property key token.
@RETURN vword_t: return the property value if exists, otherwise return zero.
*/
EXP_API vword_t	widget_get_user_prop(widget_t wt, const tchar_t* pkey);

/*
@FUNCTION widget_get_user_prop: delete widget property by key and return the value stored.
@INPUT widget_t wt: the widget resource handle.
@INPUT const tchar_t* pkey: the property key token.
@RETURN vword_t: return the property value if exists, otherwise return zero.
*/
EXP_API vword_t	widget_del_user_prop(widget_t wt, const tchar_t* pkey);

/*
@FUNCTION widget_client_context: reference a widget client device context, it clipped by widget client rectangle.
client context used to draw user view.
@INPUT widget_t wt: the widget resource handle.
@RETURN visual_t: if succeeds return device context resource handle, fails return NULL.
*/
EXP_API visual_t widget_client_context(widget_t wt);

/*
@FUNCTION widget_window_context: reference a widget window device context, it clipped by widget window rectangle.
window context used to draw frame.
@INPUT widget_t wt: the widget resource handle.
@RETURN visual_t: if succeeds return device context resource handle, fails return NULL.
*/
EXP_API visual_t widget_window_context(widget_t wt);

/*
@FUNCTION widget_release_context: release client or window device context.
@INPUT widget_t wt: the widget resource handle.
@INPUT visual_t dc: the device context handle.
@RETURN void: none.
*/
EXP_API void	widget_release_context(widget_t wt, visual_t dc);

/*
@FUNCTION widget_get_client_rect: get client rectangle, the coordinate is window client based.
@INPUT widget_t wt: the widget resource handle.
@OUTPUT xrect_t* prt: the rect struct.
@RETURN void: none.
*/
EXP_API void	widget_get_client_rect(widget_t wt, xrect_t* prt);

/*
@FUNCTION widget_get_window_rect: get window rectangle, the coordinate is screen based.
@INPUT widget_t wt: the widget resource handle.
@OUTPUT xrect_t* prt: the rect struct.
@RETURN void: none.
*/
EXP_API void	widget_get_window_rect(widget_t wt, xrect_t* prt);

/*
@FUNCTION widget_get_window_edge: get window frame edge width and height in points.
@INPUT widget_t wt: the widget resource handle.
@OUTPUT xsize_t* pxs: the size struct.
@RETURN void: none.
*/
EXP_API void	widget_get_window_edge(widget_t wt, xsize_t* pxs);


/*
@FUNCTION widget_client_to_screen: mapping client points to screen coordinate.
@INPUT widget_t wt: the widget resource handle.
@INOUTPUT xpoint_t* pst: the point struct for inputing the client point and outputing the screen point.
@RETURN void: none.
*/
EXP_API void	widget_client_to_screen(widget_t wt, xpoint_t* pst);

/*
@FUNCTION widget_screen_to_client: mapping screen points to client coordinate.
@INPUT widget_t wt: the widget resource handle.
@INOUTPUT xpoint_t* pst: the point struct for inputing the screen point and outputing the client point.
@RETURN void: none.
*/
EXP_API void	widget_screen_to_client(widget_t wt, xpoint_t* pst);

/*
@FUNCTION widget_client_to_window: mapping client points to window coordinate.
@INPUT widget_t wt: the widget resource handle.
@INOUTPUT xpoint_t* pst: the point struct for inputing the client point and outputing the window point.
@RETURN void: none.
*/
EXP_API void	widget_client_to_window(widget_t wt, xpoint_t* pst);

/*
@FUNCTION widget_window_to_client: mapping window points to client coordinate.
@INPUT widget_t wt: the widget resource handle.
@INOUTPUT xpoint_t* pst: the point struct for inputing the window point and outputing the client point.
@RETURN void: none.
*/
EXP_API void	widget_window_to_client(widget_t wt, xpoint_t* pst);

/*
@FUNCTION widget_size: resize widget client.
@INPUT widget_t wt: the widget resource handle.
@INPUT const xsize_t* pxs: the new size.
@RETURN void: none.
*/
EXP_API void	widget_size(widget_t wt, const xsize_t* pxs);

/*
@FUNCTION widget_move: move widget to new position.
@INPUT widget_t wt: the widget resource handle.
@INPUT const xpoint_t* ppt: the new point.
@RETURN void: none.
*/
EXP_API void	widget_move(widget_t wt, const xpoint_t* ppt);

/*
@FUNCTION widget_move: change widget z-order.
@INPUT widget_t wt: the widget resource handle.
@INPUT int zor: the new z-order, it can be WS_TAKE_NOTOPMOST, WS_TAKE_BOTTOM, WS_TAKE_TOP, WS_TAKE_TOPMOST.
@RETURN void: none.
*/
EXP_API void	widget_take(widget_t wt, int zor);

/*
@FUNCTION widget_show: show or hide widget.
@INPUT widget_t wt: the widget resource handle.
@INPUT dword_t sw: the show mode, it can be WS_SHOW_NORMAL, WS_SHOW_HIDE, WS_SHOW_MAXIMIZE, WS_SHOW_MINIMIZE, WS_SHOW_FULLSCREEN, WS_SHOW_POPUPTOP.
@RETURN void: none.
*/
EXP_API void	widget_show(widget_t wt, dword_t sw);

/*
@FUNCTION widget_center_window: centre the child or popup widget posotion to parent or screen center.
@INPUT widget_t wt: the widget resource handle.
@INPUT widget_t owner: the owner widget, if NULL indicate screen, else indicate parent widget.
@RETURN void: none.
*/
EXP_API void	widget_center_window(widget_t wt, widget_t owner);

/*
@FUNCTION widget_layout: relayout whole widndow.
@INPUT widget_t wt: the widget resource handle.
@RETURN void: none.
*/
EXP_API void	widget_layout(widget_t wt);

/*
@FUNCTION widget_erase: redraw rect in widget client.
@INPUT widget_t wt: the widget resource handle.
@INPUT const xrect_t* prt: the rect need to redraw.
@RETURN void: none.
*/
EXP_API void	widget_erase(widget_t wt, const xrect_t* prt);

/*
@FUNCTION widget_enable: enable or disable window, the window disabled can not get focus for inputing.
@INPUT widget_t wt: the widget resource handle.
@INPUT bool_t b: nonezero for enable, zero for disable.
@RETURN void: none.
*/
EXP_API void	widget_enable(widget_t wt, bool_t b);

/*
@FUNCTION widget_active: activate the widndow.
@INPUT widget_t wt: the widget resource handle.
@RETURN void: none.
*/
EXP_API void	widget_active(widget_t wt);

/*
@FUNCTION widget_set_cursor: set widget cursor type.
@INPUT widget_t wt: the widget resource handle.
@INPUT int cur: cursor type, it can be CURSOR_SIZENS, CURSOR_SIZEWE, CURSOR_SIZEALL, CURSOR_HAND, CURSOR_HELP, CURSOR_DRAG, CURSOR_ARROW, CURSOR_IBEAM.
@RETURN void: none.
*/
EXP_API void	widget_set_cursor(widget_t wt,int curs);

/*
@FUNCTION widget_set_capture: let widget capture or discard mouse input.
@INPUT widget_t wt: the widget resource handle.
@INPUT bool_t b: nonezero for capturing, zero for discarding.
@RETURN void: none.
*/
EXP_API void	widget_set_capture(widget_t wt,bool_t b);

/*
@FUNCTION widget_create_caret: create a widget input caret.
@INPUT widget_t wt: the widget resource handle.
@INPUT int w: the caret width in points.
@INPUT int h: the caret height in points.
@RETURN void: none.
*/
EXP_API void	widget_create_caret(widget_t wt, int w, int h);

/*
@FUNCTION widget_destroy_caret: destroy widget input caret.
@INPUT widget_t wt: the widget resource handle.
@RETURN void: none.
*/
EXP_API void	widget_destroy_caret(widget_t wt);

/*
@FUNCTION widget_show_caret: show widget input caret.
@INPUT widget_t wt: the widget resource handle.
@INPUT int w: the caret width in points.
@INPUT int h: the caret height in points.
@INPUT bool_t b: nonzero for showing, zero for hiding.
@RETURN void: none.
*/
EXP_API void	widget_show_caret(widget_t wt, int x, int y);

/*
@FUNCTION widget_set_focus: let the widget get focus.
@INPUT widget_t wt: the widget resource handle.
@RETURN void: none.
*/
EXP_API void	widget_set_focus(widget_t wt);

/*
@FUNCTION widget_key_state: test the key is pressed.
@INPUT widget_t wt: the widget resource handle.
@INPUT byte_t key: the virtual key.
@RETURN bool_t: if return nonzero indicate is pressed, zero indicate released.
*/
EXP_API bool_t	widget_key_state(widget_t wt,byte_t key);

/*
@FUNCTION widget_is_hotvoer: test widget can track mouse hot.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if return nonzero indicate is tracked, zero indicate not.
*/
EXP_API bool_t	widget_is_hotvoer(widget_t wt);

/*
@FUNCTION widget_is_editor: test widget is editor control.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if return nonzero indicate is editor, zero indicate not.
*/
EXP_API bool_t	widget_is_editor(widget_t wt);

/*
@FUNCTION widget_is_valid: test widget is valid.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if return nonzero indicate is valid, zero indicate not.
*/
EXP_API bool_t	widget_is_valid(widget_t wt);

/*
@FUNCTION widget_is_child: test widget is child.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if return nonzero indicate is child, zero indicate not.
*/
EXP_API bool_t	widget_is_child(widget_t wt);

/*
@FUNCTION widget_is_focus: test widget is focused.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if return nonzero indicate is focused, zero indicate not.
*/
EXP_API bool_t	widget_is_focus(widget_t wt);

/*
@FUNCTION widget_can_focus: test widget can be focused.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if return nonzero indicate can be focused, zero indicate can not be.
*/
EXP_API bool_t	widget_can_focus(widget_t wt);

/*
@FUNCTION widget_can_paging: test widget can be paged.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if return nonzero indicate can be paged, zero indicate can not be.
*/
EXP_API bool_t	widget_can_paging(widget_t wt);

/*
@FUNCTION widget_has_close: test widget has close button.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if return nonzero indicate so, zero indicate not so.
*/
EXP_API bool_t	widget_has_close(widget_t wt);

/*
@FUNCTION widget_has_size: test widget has size button.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if return nonzero indicate so, zero indicate not so.
*/
EXP_API bool_t	widget_has_size(widget_t wt);

/*
@FUNCTION widget_has_border: test widget has border.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if return nonzero indicate so, zero indicate not so.
*/
EXP_API bool_t	widget_has_border(widget_t wt);

/*
@FUNCTION widget_scroll: scroll the widget.
@INPUT widget_t wt: the widget resource handle.
@INPUT bool_t horz: nonzero for horizon scroll, zero for vertical scroll.
@INPUT int line: line will be scrolled.
@RETURN void: none.
*/
EXP_API void	widget_scroll(widget_t wt, bool_t horz, int line);

/*
@FUNCTION widget_get_scroll: get widget scroll information.
@INPUT widget_t wt: the widget resource handle.
@INPUT bool_t horz: nonzero for horizon scroll, zero for vertical scroll.
@OUTPUT scroll_t* psl: scroll struct for returning information.
@RETURN void: none.
*/
EXP_API void	widget_get_scroll_info(widget_t wt, bool_t horz, scroll_t* psl);

/*
@FUNCTION widget_set_scroll: set widget scroll information.
@INPUT widget_t wt: the widget resource handle.
@INPUT bool_t horz: nonzero for horizon scroll, zero for vertical scroll.
@INPUT const scroll_t* psl: scroll struct for setting scroll information.
@RETURN void: none.
*/
EXP_API void	widget_set_scroll_info(widget_t wt, bool_t horz, const scroll_t* psc);

/*
@FUNCTION widget_post_char: post a char input message into windows message queue.
@INPUT widget_t wt: the widget resource handle.
@INPUT wchar_t ch: the wide character.
@RETURN void: none.
*/
EXP_API void	widget_post_wchar(widget_t wt, wchar_t ch);

/*
@FUNCTION widget_post_char: post a key press message into windows message queue, and not wait the message processed.
@INPUT widget_t wt: the widget resource handle.
@INPUT int key: the key code, eg: KEY_*.
@RETURN void: none.
*/
EXP_API void	widget_post_key(widget_t wt, int key);

/*
@FUNCTION widget_post_notice: post notice message to owner window, and not wait the message processed.
@INPUT widget_t wt: the widget resource handle.
@INPUT NOTICE* pnt: the notice message struct.
@RETURN none:
*/
EXP_API void	widget_post_notice(widget_t wt, NOTICE* pnt);

/*
@FUNCTION widget_send_notice: send notice message to owner window, and not wait the message processed.
@INPUT widget_t wt: the widget resource handle.
@INPUT NOTICE* pnt: the notice message struct.
@RETURN int: return nonzero if message precessed.
*/
EXP_API int		widget_send_notice(widget_t wt, NOTICE* pnt);

/*
@FUNCTION widget_post_command: post command message to owner window, and not wait the message processed.
@INPUT widget_t wt: the widget resource handle.
@INPUT int code: the command message code.
@INPUT int cid: the control id of the widget.
@INPUT vword_t data: the extract data posed with command message.
@RETURN void: none.
*/
EXP_API void	widget_post_command(widget_t wt, int code, int cid, vword_t data);

/*
@FUNCTION widget_send_command: send command message to owner window, and wait the message processed.
@INPUT widget_t wt: the widget resource handle.
@INPUT int code: the command message code.
@INPUT int cid: the control id of the widget.
@INPUT vword_t data: the extract data posed with command message.
@RETURN int: return nonzero if message precessed.
*/
EXP_API int		widget_send_command(widget_t wt, int code, int cid, vword_t data);

/*
@FUNCTION widget_set_title: set widget title.
@INPUT widget_t wt: the widget resource handle.
@INPUT const tchar_t* token: the title token.
@RETURN void: none.
*/
EXP_API void	widget_set_title(widget_t wt, const tchar_t* token);

/*
@FUNCTION widget_get_title: get widget title.
@INPUT widget_t wt: the widget resource handle.
@OUTPUT tchar_t* buf: string buffer for returning title.
@INPUT int max: string buffer maximize size, not include terminate character.
@RETURN int: the returned title length in characters.
*/
EXP_API int		widget_get_title(widget_t wt, tchar_t* buf, int max);

/*
@FUNCTION widget_is_maximized: test widget is maximized.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if nonzero indicate so, zero indicate not so.
*/
EXP_API bool_t	widget_is_maximized(widget_t wt);

/*
@FUNCTION widget_is_minimized: test widget is minimized.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: if nonzero indicate so, zero indicate not so.
*/
EXP_API bool_t	widget_is_minimized(widget_t wt);

/*
@FUNCTION widget_set_subproc: set widget subclass routing.
@INPUT widget_t wt: the widget resource handle.
@INPUT dword_t sid: the subclass id.
@INPUT if_subproc_t* sub: the subclass message dispatch struct.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t	widget_set_subproc(widget_t wt, dword_t sid, if_subproc_t* sub);

/*
@FUNCTION widget_del_subproc: delete widget subclass routing.
@INPUT widget_t wt: the widget resource handle.
@INPUT dword_t sid: the subclass id.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API void	widget_del_subproc(widget_t wt, dword_t sid);

/*
@FUNCTION widget_set_subproc_delta: set widget subclass routing extract data.
@INPUT widget_t wt: the widget resource handle.
@INPUT dword_t sid: the subclass id.
@INPUT vword_t delta: the subclass extract data.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t	widget_set_subproc_delta(widget_t wt, dword_t sid, vword_t delta);

/*
@FUNCTION widget_get_subproc_delta: get widget subclass routing extract data.
@INPUT widget_t wt: the widget resource handle.
@INPUT dword_t sid: the subclass id.
@RETURN vword_t: return the subclass extract data if exists, otherwise return zero.
*/
EXP_API vword_t widget_get_subproc_delta(widget_t wt, dword_t sid);

/*
@FUNCTION widget_has_subproc: test widget has subclass routing.
@INPUT widget_t wt: the widget resource handle.
@RETURN bool_t: return nonzero if exists, otherwise return zero.
*/
EXP_API bool_t	widget_has_subproc(widget_t wt);

/*
@FUNCTION widget_set_timer: set widget timer routing.
@INPUT widget_t wt: the widget resource handle.
@INPUT int ms: the time period in millisecond.
@RETURN vword_t: if succeeds return timer id, otherwise return zero.
*/
EXP_API vword_t widget_set_timer(widget_t wt, int ms);

/*
@FUNCTION widget_kill_timer: remove widget timer routing.
@INPUT widget_t wt: the widget resource handle.
@INPUT vword_t tid: the timer id.
@RETURN void: none.
*/
EXP_API void	widget_kill_timer(widget_t wt, vword_t tid);

/*
@FUNCTION widget_attach_accel: attach a accelerator to widget.
@INPUT widget_t wt: the widget resource handle.
@INPUT res_acl_t acl: the accelerator resource handle.
@RETURN void: none.
*/
EXP_API void	widget_set_accel(widget_t wt, const accel_table_t* pacl, int n);

/*
@FUNCTION widget_enum_child: enumerate child widgets.
@INPUT widget_t wt: the widget resource handle.
@INPUT PF_ENUM_WINDOW_PROC pf: the callback function for every child widget enumerated.
@INPUT vword_t pv: the parameter translated into PF_ENUM_WINDOW_PROC function.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t	widget_enum_child(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv);

/*
@FUNCTION widget_noti_xfont: notify the widget font changed.
@INPUT widget_t wt: windowd resource handle.
@INPUT const xfont_t* pxf: the font struct.
@RETURN void: none.
*/
EXP_API void	widget_noti_xfont(widget_t wt, const xfont_t* pxf);

/*
@FUNCTION widget_noti_xface: notify the widget face changed.
@INPUT widget_t wt: windowd resource handle.
@INPUT const xface_t* pxa: the face struct.
@RETURN void: none.
*/
EXP_API void	widget_noti_xface(widget_t wt, const xface_t* pxa);

/*
@FUNCTION widget_noti_xbrush: notify the widget brush changed.
@INPUT widget_t wt: windowd resource handle.
@INPUT const xbrush_t* pxb: the brush struct.
@RETURN void: none.
*/
EXP_API void	widget_noti_xbrush(widget_t wt, const xbrush_t* pxb);

/*
@FUNCTION widget_noti_xpen: notify the widget pen changed.
@INPUT widget_t wt: windowd resource handle.
@INPUT const xpen_t* pxp: the pen struct.
@RETURN void: none.
*/
EXP_API void	widget_noti_xpen(widget_t wt, const xpen_t* pxp);

/*
@FUNCTION widget_set_color_mode: set the widget color mode.
@INPUT widget_t wt: windowd resource handle.
@INPUT const color_mod_t* pclr: the color mode struct.
@RETURN void: none.
*/
EXP_API void	widget_set_color_mode(widget_t wt, const color_mod_t* pclr);

/*
@FUNCTION widget_get_color_mode: copy the widget color mode.
@INPUT widget_t wt: windowd resource handle.
@OUTPUT color_mod_t* pclr: the color mode struct.
@RETURN void: none.
*/
EXP_API void	widget_get_color_mode(widget_t wt, color_mod_t* pclr);

/*
@FUNCTION widget_set_diaph: set widget alphablend level.
@INPUT widget_t wt: the widget resource handle.
@INPUT byte_t b: the alphablend level: 0~255, or use predefined value: ALPHA_SOLID(250), ALPHA_SOFT(128), ALPHA_TRANS(64).
@RETURN void: none.
*/
EXP_API void	widget_set_diaph(widget_t wt, float b);

/*
@FUNCTION widget_get_alpha: get widget alphablend level.
@INPUT widget_t wt: the widget resource handle.
@RETURN byte_t: the alphablend level, 255 for not setting alphablend level.
*/
EXP_API float	widget_get_diaph(widget_t wt);

EXP_API void	calc_widget_border(dword_t wstyle, border_t* pbd);

EXP_API void	adjust_widget_size(dword_t wstyle, xsize_t* pxs);

/*
@FUNCTION get_screen_size: calc screen size in points.
@OUTPUT xsize_t* pxs: the size struct.
@RETURN void: none.
*/
EXP_API void	get_screen_size(xsize_t* pxs);

/*
@FUNCTION get_desktop_size: calc desktop size in points.
@OUTPUT xsize_t* pxs: the size struct.
@RETURN void: none.
*/
EXP_API void	get_desktop_size(xsize_t* pxs);

/*
@FUNCTION screen_size_to_pt: mapping points size to millimeter size.
@INOUTPUT xsize_t* pxs: the size struct for input points size and return millimeter size.
@RETURN void: none.
*/
EXP_API void	screen_size_to_pt(xsize_t* pxs);

/*
@FUNCTION screen_size_to_tm: mapping millimeter size to points size.
@INOUTPUT xsize_t* pxs: the size struct for input millimeter size and return points size.
@RETURN void: none.
*/
EXP_API void	screen_size_to_mm(xsize_t* pxs);

#ifdef XDU_SUPPORT_CONTEXT_OPENGL
EXP_API res_glc_t widget_get_glctx(widget_t wt);
#endif

/*
@FUNCTION widget_do_modal: run the widget in normal mode, usually used by overlapped window.
@INPUT widget_t wt: the widget resource handle.
@RETURN int: the widget exit code.
*/
EXP_API int		widget_do_main(widget_t wt);

/*
@FUNCTION widget_do_modal: run the widget in modal mode, usually used by dialog.
@INPUT widget_t wt: the widget resource handle.
@RETURN int: the widget modal ending code.
*/
EXP_API int		widget_do_modal(widget_t wt);

/*
@FUNCTION widget_do_modal: run the widget in trace mode, usually used by memu.
@INPUT widget_t wt: the widget resource handle.
@RETURN void: none.
*/
EXP_API void	widget_do_track(widget_t wt);

EXP_API void 	message_quit(int ret);

EXP_API void 	message_position(xpoint_t* pxp);


#ifdef	__cplusplus
}
#endif

#endif /*XDU_SUPPORT_WIDGET*/

#endif /*IMPWIN_H*/