/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu linux definition document

	@module	_xdu_linux.h | linux interface file

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

#ifndef _XDU_X11_H
#define _XDU_X11_H

#define XDU_SUPPORT_SHELL
#define XDU_SUPPORT_CONTEXT
#define XDU_SUPPORT_CONTEXT_BITMAP
#define XDU_SUPPORT_CONTEXT_GDI

#define XDU_SUPPORT_CLIPBOARD
#define XDU_SUPPORT_WIDGET


#ifdef XDU_SUPPORT_CONTEXT
#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xos.h>
#include <X11/keysym.h>
#include <X11/Xatom.h>
#include <X11/XKBlib.h>
#include <X11/cursorfont.h>
#include <X11/Xresource.h>
#include <X11/Xlocale.h>
#include <X11/extensions/Xrender.h>
#endif

#ifdef XDU_SUPPORT_CONTEXT_CAIRO
#include <cairo/cairo.h>
#include <cairo/cairo-xlib.h>
#endif

#ifdef XDU_SUPPORT_CONTEXT
typedef struct _X11_atoms_t{
    Atom net_active_window;
    Atom net_close_window;
    Atom net_wm_action_close;
    Atom net_wm_action_fullscreen;
    Atom net_wm_action_maximize_horz;
    Atom net_wm_action_maximize_vert;
    Atom net_wm_action_minimize;
    Atom net_wm_action_move;
    Atom net_wm_action_resize;
    Atom net_wm_action_shade;
    Atom net_wm_allowed_actions;
    Atom net_wm_name;
    Atom net_wm_state;
    Atom net_wm_state_fullscreen;
    Atom net_wm_state_hidden;
    Atom net_wm_state_maximized_horz;
    Atom net_wm_state_maximized_vert;
    Atom net_wm_state_modal;
    Atom net_wm_state_shaded;
    Atom net_wm_state_skip_pager;
    Atom net_wm_state_skip_taskbar;
    Atom net_wm_state_sticky;
    Atom net_wm_window_type;
    Atom net_wm_window_type_combo;
    Atom net_wm_window_type_desktop;
    Atom net_wm_window_type_dialog;
    Atom net_wm_window_type_dropdown_menu;
    Atom net_wm_window_type_dnd;
    Atom net_wm_window_type_dock;
    Atom net_wm_window_type_menu;
    Atom net_wm_window_type_normal;
    Atom net_wm_window_type_notification;
    Atom net_wm_window_type_popup_menu;
    Atom net_wm_window_type_splash;
    Atom net_wm_window_type_toolbar;
    Atom net_wm_window_type_tooltip;
    Atom net_wm_window_type_utility;
    Atom net_wm_ping;
    Atom wm_change_state;
    Atom wm_colormap_windows;
    Atom wm_delete_window;
    Atom wm_hints;
    Atom wm_name;
    Atom wm_normal_hints;
    Atom wm_protocols;
    Atom wm_state;
    Atom wm_take_focus;
    Atom wm_transient_for;

    Atom wm_wchar;
    Atom wm_quit;
    Atom wm_command;
    Atom wm_notice;
    Atom wm_input;
    Atom wm_scroll;
    
    Atom xdu_struct;
    Atom xdu_dispatch;
    Atom xdu_subproc;
    Atom xdu_user_delta;
    Atom xdu_core_delta;

}X11_atoms_t;

extern X11_atoms_t  g_atoms;

extern res_queue_t g_queue;

#define XRGB(ch) (unsigned short)((double)ch * 65535.0 / 256.0)

extern XIM          g_xim;
extern Display*     g_display;
//global fonstset cache
extern fontset_t    g_fontset;

typedef Colormap    res_clrmap_t;
#ifdef XDU_SUPPORT_CONTEXT_BITMAP
typedef struct _x11_bitmap_t{
	handle_head head;

    bool_t ref;
	XImage* image;
}X11_bitmap_t;
#endif

typedef struct _X11_context_t{
    handle_head head;

    int type;
    GC context;
    Drawable device;
    int width;
    int height;
    Visual* visual;
    Colormap color;
    unsigned int depth;

    fontset_t fontset;
}X11_context_t;

typedef struct _x11_fontset_t{
	handle_head head;

    void* font_object;
}X11_fontset_t;

#endif /*XDU_SUPPORT_CONTEXT*/

#ifdef XDU_SUPPORT_CLIPBOARD

/*clipboard format*/
#define CB_FORMAT_MBS		1
#define CB_FORMAT_UCS		13
#define CB_FORMAT_DIB		8

#ifdef _UNICODE
#define DEF_CB_FORMAT		CB_FORMAT_UCS
#else
#define DEF_CB_FORMAT		CB_FORMAT_MBS
#endif
#endif /*XDU_SUPPORT_CLIPBOARD*/

#ifdef XDU_SUPPORT_WIDGET
typedef struct _X11_widget_t{
    handle_head head;

    uid_t uid;
	Window self;
	Window parent;
	Window owner;
    void* accel;
	
    dword_t style;
	int mode;
	int result;
	int retcode;

	float diaph;
	dword_t mask;
	long evmsk;
    int state;
	bool_t disable;

    scroll_t hs;
	scroll_t vs;
    color_mod_t clrs;

    Cursor cur;
	XIC xic;
    res_timer_t ctt;

	bool_t tog;
	caret_t car;

    xpoint_t pt;
    xsize_t st;
}X11_widget_t;

#endif

#define SYSTEM_FONTNAME     _T("Simsun")

#endif //_XDU_X11_H