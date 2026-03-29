/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc event defination document

	@module	msginf.h | interface file

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


#ifndef _EDIINF_H
#define	_EDIINF_H

#include "../xdudef.h"

#ifdef XDU_SUPPORT_WIDGET

/*define widget notify header*/
typedef struct _NOTICE{
	widget_t widget;
	unsigned int user;
	unsigned int code;
}NOTICE, *LPNOTICE;

/*subclass widget event*/
typedef int(*SUB_ON_LBUTTON_DOWN)(widget_t, const xpoint_t*, uid_t, vword_t);
typedef int(*SUB_ON_LBUTTON_UP)(widget_t, const xpoint_t*, uid_t, vword_t);
typedef int(*SUB_ON_LBUTTON_DBCLICK)(widget_t, const xpoint_t*, uid_t, vword_t);
typedef int(*SUB_ON_RBUTTON_DOWN)(widget_t, const xpoint_t*, uid_t, vword_t);
typedef int(*SUB_ON_RBUTTON_UP)(widget_t, const xpoint_t*, uid_t, vword_t);
typedef int(*SUB_ON_MOUSE_MOVE)(widget_t, unsigned int, const xpoint_t*, uid_t, vword_t);
typedef int(*SUB_ON_MOUSE_ENTER)(widget_t, unsigned int, const xpoint_t*, uid_t, vword_t);
typedef int(*SUB_ON_MOUSE_LEAVE)(widget_t, unsigned int, const xpoint_t*, uid_t, vword_t);
typedef int(*SUB_ON_MOUSE_HOVER)(widget_t, unsigned int, const xpoint_t*, uid_t, vword_t);
typedef int(*SUB_ON_WHEEL)(widget_t, bool_t, int, uid_t, vword_t);
typedef int(*SUB_ON_SCROLL)(widget_t, bool_t, int, uid_t, vword_t);
typedef int(*SUB_ON_KEYDOWN)(widget_t, dword_t, int, uid_t, vword_t);
typedef int(*SUB_ON_KEYUP)(widget_t, dword_t, int, uid_t, vword_t);
typedef int(*SUB_ON_WCHAR)(widget_t, wchar_t, uid_t, vword_t);
typedef int(*SUB_ON_SIZE)(widget_t, int, const xsize_t*, uid_t, vword_t);
typedef int(*SUB_ON_MOVE)(widget_t, const xpoint_t*, uid_t, vword_t);
typedef int(*SUB_ON_SHOW)(widget_t, bool_t, uid_t, vword_t);
typedef int(*SUB_ON_ACTIVATE)(widget_t, int, uid_t, vword_t);
typedef int(*SUB_ON_PAINT)(widget_t, visual_t, const xrect_t*, uid_t, vword_t);
typedef int(*SUB_ON_SET_FOCUS)(widget_t, widget_t, uid_t, vword_t);
typedef int(*SUB_ON_KILL_FOCUS)(widget_t, widget_t, uid_t, vword_t);
typedef int(*SUB_ON_NOTICE)(widget_t, NOTICE*, uid_t, vword_t);
typedef int(*SUB_ON_MENU_COMMAND)(widget_t, int, int, vword_t, uid_t, vword_t);
typedef int(*SUB_ON_PARENT_COMMAND)(widget_t, int, vword_t, uid_t, vword_t);
typedef int(*SUB_ON_CHILD_COMMAND)(widget_t, int, vword_t, uid_t, vword_t);
typedef int(*SUB_ON_SELF_COMMAND)(widget_t, int, vword_t, uid_t, vword_t);
typedef int(*SUB_ON_COMMAND_FIND)(widget_t, str_find_t*, uid_t, vword_t);
typedef int(*SUB_ON_COMMAND_REPLACE)(widget_t, str_replace_t*, uid_t, vword_t);
typedef int(*SUB_ON_TIMER)(widget_t, vword_t, uid_t, vword_t);
typedef int(*SUB_ON_CLOSE)(widget_t, uid_t, vword_t);

typedef int(*SUB_ON_SYSCLR_CLICK)(widget_t, const xpoint_t*, uid_t, vword_t);
typedef int(*SUB_ON_SYSLOG_CLICK)(widget_t, const xpoint_t*, uid_t, vword_t);

typedef void(*SUB_ON_SUBBING)(widget_t, uid_t, vword_t);
typedef void(*SUB_ON_UNSUBBED)(widget_t, uid_t, vword_t);

typedef struct _if_subproc_t{
	SUB_ON_SUBBING		sub_on_subbing;
	SUB_ON_UNSUBBED		sub_on_unsubbed;
	SUB_ON_CLOSE		sub_on_close;

	SUB_ON_LBUTTON_DOWN	sub_on_lbutton_down;
	SUB_ON_LBUTTON_UP	sub_on_lbutton_up;
	SUB_ON_LBUTTON_DBCLICK	sub_on_lbutton_dbclick;
	SUB_ON_RBUTTON_DOWN	sub_on_rbutton_down;
	SUB_ON_RBUTTON_UP	sub_on_rbutton_up;
	SUB_ON_MOUSE_MOVE	sub_on_mouse_move;
	SUB_ON_MOUSE_ENTER	sub_on_mouse_enter;
	SUB_ON_MOUSE_LEAVE	sub_on_mouse_leave;
	SUB_ON_MOUSE_HOVER	sub_on_mouse_hover;
	SUB_ON_WHEEL		sub_on_wheel;
	SUB_ON_SCROLL		sub_on_scroll;
	SUB_ON_KEYDOWN		sub_on_keydown;
	SUB_ON_KEYUP		sub_on_keyup;
	SUB_ON_WCHAR		sub_on_wchar;
	SUB_ON_SIZE			sub_on_size;
	SUB_ON_MOVE			sub_on_move;
	SUB_ON_SHOW			sub_on_show;
	SUB_ON_ACTIVATE		sub_on_activate;
	SUB_ON_SET_FOCUS	sub_on_set_focus;
	SUB_ON_KILL_FOCUS	sub_on_kill_focus;
	SUB_ON_PAINT		sub_on_paint;
	SUB_ON_NOTICE		sub_on_notice;
	SUB_ON_MENU_COMMAND		sub_on_menu_command;
	SUB_ON_PARENT_COMMAND	sub_on_parent_command;
	SUB_ON_CHILD_COMMAND	sub_on_child_command;
	SUB_ON_SELF_COMMAND		sub_on_self_command;
	SUB_ON_COMMAND_FIND		sub_on_command_find;
	SUB_ON_COMMAND_REPLACE	sub_on_command_replace;

	SUB_ON_SYSCLR_CLICK		sub_on_sysclr_click;
	SUB_ON_SYSLOG_CLICK		sub_on_syslog_click;

	SUB_ON_TIMER		sub_on_timer;

	void* proc;
	uid_t sid;
	vword_t delta;
}if_subproc_t;

typedef int(*PF_ON_CREATE)(widget_t, void*);
typedef int(*PF_ON_CLOSE)(widget_t);
typedef void(*PF_ON_DESTROY)(widget_t);
typedef void(*PF_ON_LBUTTON_DOWN)(widget_t, const xpoint_t*);
typedef void(*PF_ON_LBUTTON_UP)(widget_t, const xpoint_t*);
typedef void(*PF_ON_LBUTTON_DBCLICK)(widget_t, const xpoint_t*);
typedef void(*PF_ON_RBUTTON_DOWN)(widget_t, const xpoint_t*);
typedef void(*PF_ON_RBUTTON_UP)(widget_t, const xpoint_t*);
typedef void(*PF_ON_MOUSE_MOVE)(widget_t, dword_t, const xpoint_t*);
typedef void(*PF_ON_MOUSE_ENTER)(widget_t, dword_t, const xpoint_t*);
typedef void(*PF_ON_MOUSE_LEAVE)(widget_t, dword_t, const xpoint_t*);
typedef void(*PF_ON_MOUSE_HOVER)(widget_t, dword_t, const xpoint_t*);
typedef void(*PF_ON_WHEEL)(widget_t, bool_t, int);
typedef void(*PF_ON_SCROLL)(widget_t, bool_t, int);
typedef void(*PF_ON_KEYDOWN)(widget_t, dword_t, int);
typedef void(*PF_ON_KEYUP)(widget_t, dword_t, int);
typedef void(*PF_ON_WCHAR)(widget_t, wchar_t);
typedef void(*PF_ON_SIZE)(widget_t, int, const xsize_t*);
typedef void(*PF_ON_MOVE)(widget_t, const xpoint_t*);
typedef void(*PF_ON_SHOW)(widget_t, bool_t);
typedef void(*PF_ON_ACTIVATE)(widget_t, int);
typedef void(*PF_ON_PAINT)(widget_t, visual_t, const xrect_t*);
typedef void(*PF_ON_SET_FOCUS)(widget_t, widget_t);
typedef void(*PF_ON_KILL_FOCUS)(widget_t, widget_t);
typedef void(*PF_ON_NOTICE)(widget_t, NOTICE*);
typedef void(*PF_ON_MENU_COMMAND)(widget_t, int, int, vword_t);
typedef void(*PF_ON_PARENT_COMMAND)(widget_t, int, vword_t);
typedef void(*PF_ON_CHILD_COMMAND)(widget_t, int, vword_t);
typedef void(*PF_ON_SELF_COMMAND)(widget_t, int, vword_t);
typedef void(*PF_ON_COMMAND_FIND)(widget_t, str_find_t*);
typedef void(*PF_ON_COMMAND_REPLACE)(widget_t, str_replace_t*);
typedef void(*PF_ON_SYSCMD_CLICK)(widget_t, const xpoint_t*);
typedef void(*PF_ON_TIMER)(widget_t, vword_t);
typedef void(*PF_ON_IDLE)(widget_t);

/*widget event*/
typedef struct _if_dispatch_t{
	PF_ON_CREATE		pf_on_create;
	PF_ON_CLOSE			pf_on_close;
	PF_ON_DESTROY		pf_on_destroy;
	PF_ON_LBUTTON_DOWN	pf_on_lbutton_down;
	PF_ON_LBUTTON_UP	pf_on_lbutton_up;
	PF_ON_LBUTTON_DBCLICK	pf_on_lbutton_dbclick;
	PF_ON_RBUTTON_DOWN	pf_on_rbutton_down;
	PF_ON_RBUTTON_UP	pf_on_rbutton_up;
	PF_ON_MOUSE_MOVE	pf_on_mouse_move;
	PF_ON_MOUSE_ENTER	pf_on_mouse_enter;
	PF_ON_MOUSE_LEAVE	pf_on_mouse_leave;
	PF_ON_MOUSE_HOVER	pf_on_mouse_hover;
	PF_ON_WHEEL			pf_on_wheel;
	PF_ON_SCROLL		pf_on_scroll;
	PF_ON_KEYDOWN		pf_on_keydown;
	PF_ON_KEYUP			pf_on_keyup;
	PF_ON_WCHAR			pf_on_wchar;
	PF_ON_SIZE			pf_on_size;
	PF_ON_MOVE			pf_on_move;
	PF_ON_SHOW			pf_on_show;
	PF_ON_ACTIVATE		pf_on_activate;
	PF_ON_SET_FOCUS		pf_on_set_focus;
	PF_ON_KILL_FOCUS	pf_on_kill_focus;
	PF_ON_PAINT			pf_on_paint;
	PF_ON_NOTICE		pf_on_notice;
	PF_ON_MENU_COMMAND		pf_on_menu_command;
	PF_ON_PARENT_COMMAND	pf_on_parent_command;
	PF_ON_CHILD_COMMAND		pf_on_child_command;
	PF_ON_SELF_COMMAND		pf_on_self_command;
	PF_ON_COMMAND_FIND		pf_on_command_find;
	PF_ON_COMMAND_REPLACE	pf_on_command_replace;

	PF_ON_SYSCMD_CLICK		pf_on_syscmd_click;

	PF_ON_TIMER			pf_on_timer;
	PF_ON_IDLE			pf_on_idle;

	const void* param;
}if_dispatch_t;

#endif /*XDU_SUPPORT_WIDGET*/

#endif	/* _EDIINF_H */

