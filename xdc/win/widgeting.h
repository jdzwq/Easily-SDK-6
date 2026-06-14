/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc event document

	@module	widgeting.h | interface file

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

#ifndef _WIDGETING_H
#define _WIDGETING_H

#define EVENT_BEGIN_DISPATH(pv)			{if_dispatch_t* pev = pv;
#ifdef XDU_SUPPORT_WIDGET_NC
#define EVENT_ON_NCPAINT(proc)			pev->pf_on_nc_paint = proc;
#define EVENT_ON_NCCALCSIZE(proc)		pev->pf_on_nc_calcsize = proc;
#define EVENT_ON_NCHITTEST(proc)		pev->pf_on_nc_hittest = proc;
#endif
#define EVENT_ON_CREATE(proc)			pev->pf_on_create = proc;
#define EVENT_ON_DESTROY(proc)			pev->pf_on_destroy = proc;
#define EVENT_ON_CLOSE(proc)			pev->pf_on_close = proc;
#define EVENT_ON_LBUTTON_DOWN(proc)		pev->pf_on_lbutton_down = proc;
#define EVENT_ON_LBUTTON_UP(proc)		pev->pf_on_lbutton_up = proc;
#define EVENT_ON_LBUTTON_DBCLICK(proc)	pev->pf_on_lbutton_dbclick = proc;
#define EVENT_ON_RBUTTON_DOWN(proc)		pev->pf_on_rbutton_down = proc;
#define EVENT_ON_RBUTTON_UP(proc)		pev->pf_on_rbutton_up = proc;
#define EVENT_ON_MOUSE_MOVE(proc)		pev->pf_on_mouse_move = proc;
#define EVENT_ON_MOUSE_HOVER(proc)		pev->pf_on_mouse_hover = proc;
#define EVENT_ON_MOUSE_LEAVE(proc)		pev->pf_on_mouse_leave = proc;
#define EVENT_ON_WHEEL(proc)			pev->pf_on_wheel = proc;
#define EVENT_ON_SCROLL(proc)			pev->pf_on_scroll = proc;
#define EVENT_ON_KEYDOWN(proc)			pev->pf_on_keydown = proc;
#define EVENT_ON_WCHAR(proc)			pev->pf_on_wchar = proc;
#define EVENT_ON_SIZE(proc)				pev->pf_on_size = proc;
#define EVENT_ON_MOVE(proc)				pev->pf_on_move = proc;
#define EVENT_ON_SHOW(proc)				pev->pf_on_show = proc;
#define EVENT_ON_ENABLE(proc)			pev->pf_on_enable = proc;
#define EVENT_ON_SET_FOCUS(proc)		pev->pf_on_set_focus = proc;
#define EVENT_ON_KILL_FOCUS(proc)		pev->pf_on_kill_focus = proc;
#define EVENT_ON_PAINT(proc)			pev->pf_on_paint = proc;
#define EVENT_ON_NOTICE(proc)			pev->pf_on_notice = proc;
#define EVENT_ON_MENU_COMMAND(proc)		pev->pf_on_menu_command = proc;
#define EVENT_ON_PARENT_COMMAND(proc)	pev->pf_on_parent_command = proc;
#define EVENT_ON_CHILD_COMMAND(proc)	pev->pf_on_child_command = proc;
#define EVENT_ON_COMMAND_FIND(proc)		pev->pf_on_command_find = proc;
#define EVENT_ON_COMMAND_REPLACE(proc)	pev->pf_on_command_replace = proc;
#define EVENT_ON_SELF_COMMAND(proc)		pev->pf_on_self_command = proc;
#define EVENT_ON_SYSCMD_CLICK(proc)		pev->pf_on_syscmd_click = proc;
#define EVENT_ON_TIMER(proc)			pev->pf_on_timer = proc;
#define EVENT_ON_SPLITOR_IMPLEMENT		{pev->pf_on_mouse_move = widget_splitor_on_mousemove;pev->pf_on_lbutton_down=widget_splitor_on_lbuttondown;pev->pf_on_lbutton_up=widget_splitor_on_lbuttonup;pev->pf_on_size=widget_splitor_on_size;pev->pf_on_paint=widget_splitor_on_paint;}
#define EVENT_ON_DOCKER_IMPLEMENT		{pev->pf_on_mouse_move = widget_docker_on_mousemove;pev->pf_on_lbutton_down=widget_docker_on_lbuttondown;pev->pf_on_lbutton_up=widget_docker_on_lbuttonup;pev->pf_on_paint=widget_docker_on_paint;}
#define EVENT_END_DISPATH				}



#define SUBPROC_BEGIN_DISPATH(pv)			{if_subproc_t* pev = pv;
#define SUBPROC_ON_SUBBING(proc)			pev->sub_on_subbing = proc;
#define SUBPROC_ON_UNSUBBING(proc)			pev->sub_on_unsubbed = proc;
#define SUBPROC_ON_CLOSE(proc)				pev->sub_on_close = proc;
#define SUBPROC_ON_LBUTTON_DOWN(proc)		pev->sub_on_lbutton_down = proc;
#define SUBPROC_ON_LBUTTON_UP(proc)			pev->sub_on_lbutton_up = proc;
#define SUBPROC_ON_LBUTTON_DBCLICK(proc)	pev->sub_on_lbutton_dbclick = proc;
#define SUBPROC_ON_RBUTTON_DOWN(proc)		pev->sub_on_rbutton_down = proc;
#define SUBPROC_ON_RBUTTON_UP(proc)			pev->sub_on_rbutton_up = proc;
#define SUBPROC_ON_MOUSE_MOVE(proc)			pev->sub_on_mouse_move = proc;
#define SUBPROC_ON_MOUSE_HOVER(proc)		pev->sub_on_mouse_hover = proc;
#define SUBPROC_ON_MOUSE_LEAVE(proc)		pev->sub_on_mouse_leave = proc;
#define SUBPROC_ON_WHEEL(proc)				pev->sub_on_wheel = proc;
#define SUBPROC_ON_SCROLL(proc)				pev->sub_on_scroll = proc;
#define SUBPROC_ON_KEYDOWN(proc)			pev->sub_on_keydown = proc;
#define SUBPROC_ON_WCHAR(proc)				pev->sub_on_wchar = proc;
#define SUBPROC_ON_SIZE(proc)				pev->sub_on_size = proc;
#define SUBPROC_ON_MOVE(proc)				pev->sub_on_move = proc;
#define SUBPROC_ON_SHOW(proc)				pev->sub_on_show = proc;
#define SUBPROC_ON_ENABLE(proc)				pev->sub_on_enable = proc;
#define SUBPROC_ON_SET_FOCUS(proc)			pev->sub_on_set_focus = proc;
#define SUBPROC_ON_KILL_FOCUS(proc)			pev->sub_on_kill_focus = proc;
#define SUBPROC_ON_PAINT(proc)				pev->sub_on_paint = proc;
#define SUBPROC_ON_NOTICE(proc)				pev->sub_on_notice = proc;
#define SUBPROC_ON_MENU_COMMAND(proc)		pev->sub_on_menu_command = proc;
#define SUBPROC_ON_PARENT_COMMAND(proc)		pev->sub_on_parent_command = proc;
#define SUBPROC_ON_CHILD_COMMAND(proc)		pev->sub_on_child_command = proc;
#define SUBPROC_ON_SELF_COMMAND(proc)		pev->sub_on_self_command = proc;
#define SUBPROC_ON_COMMAND_FIND(proc)		pev->sub_on_command_find = proc;
#define SUBPROC_ON_COMMAND_REPLACE(proc)	pev->sub_on_command_replace = proc;
#define SUBPROC_ON_SELF_COMMAND(proc)		pev->sub_on_self_command = proc;
#define SUNPROC_ON_SYSCMD_CLICK(proc)		pev->sub_on_syscmd_click = proc;
#define SUBPROC_ON_TIMER(proc)				pev->sub_on_timer = proc;
#define SUBPROC_ON_SPLITOR_IMPLEMENT		{pev->sub_on_mouse_move = widget_splitor_sub_mousemove;pev->sub_on_lbutton_down=widget_splitor_sub_lbuttondown;pev->sub_on_lbutton_up=widget_splitor_sub_lbuttonup;pev->sub_on_size=widget_splitor_sub_size;pev->sub_on_paint=widget_splitor_sub_paint;}
#define SUBPROC_ON_DOCKER_IMPLEMENT			{pev->sub_on_mouse_move = widget_docker_sub_mousemove;pev->sub_on_lbutton_down=widget_docker_sub_lbuttondown;pev->sub_on_lbutton_up=widget_docker_sub_lbuttonup;pev->sub_on_paint=widget_docker_sub_paint;}
#define SUBPROC_ON_DESIGNER_IMPLEMENT		{pev->sub_on_mouse_move = designer_sub_mousemove;pev->sub_on_lbutton_down=designer_sub_lbutton_down;pev->sub_on_lbutton_up=designer_sub_lbutton_up;pev->sub_on_lbutton_dbclick=designer_sub_lbutton_dbclick;pev->sub_on_rbutton_down=designer_sub_rbutton_down;pev->sub_on_rbutton_up=designer_sub_rbutton_up;pev->sub_on_paint=designer_sub_paint;pev->sub_on_keydown=designer_sub_keydown;}
#define SUBPROC_ON_EDITOR_IMPLEMENT			{pev->sub_on_scroll = editor_sub_scroll;pev->sub_on_wheel = editor_sub_wheel;pev->sub_on_child_command=editor_sub_child_command;pev->sub_on_keydown=editor_sub_keydown;pev->sub_on_wchar=editor_sub_wchar;}
#define SUBPROC_ON_DIALOG_IMPLEMENT			{pev->sub_on_paint=dialog_sub_paint;pev->sub_on_size=dialog_sub_size;}
#define SUBPROC_END_DISPATH					}



#ifdef	__cplusplus
extern "C" {
#endif


#ifdef	__cplusplus
}
#endif


#endif /*_WIDGETING_H*/