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

#ifdef XDU_SUPPORT_WIDGET

XIM     g_xim = (XIM)0;

#define WIDGET_EVENTS   (KeyPressMask | KeyReleaseMask \
                        | ButtonPressMask | ButtonReleaseMask | Button1MotionMask | Button2MotionMask | Button3MotionMask | Button4MotionMask | Button5MotionMask | ButtonMotionMask \
                        | EnterWindowMask |	LeaveWindowMask | PointerMotionMask| PointerMotionHintMask \
                        | KeymapStateMask \
						| ExposureMask \
						| VisibilityChangeMask \
						| StructureNotifyMask \
						| SubstructureNotifyMask \
						| FocusChangeMask \
						| PropertyChangeMask \
						| ColormapChangeMask \
						| OwnerGrabButtonMask)
#define WIDGET_CHILD_EVENTS (KeyPressMask | KeyReleaseMask \
						| ButtonPressMask | ButtonReleaseMask | ButtonMotionMask | Button1MotionMask | Button2MotionMask | Button3MotionMask | Button4MotionMask | Button5MotionMask \
						| EnterWindowMask |	LeaveWindowMask | PointerMotionMask| PointerMotionHintMask \
						| ExposureMask \
						| FocusChangeMask \
						| StructureNotifyMask | SubstructureNotifyMask \
						| KeymapStateMask)
#define WIDGET_POPUP_EVENTS (KeyPressMask | KeyReleaseMask \
						| ButtonPressMask | ButtonReleaseMask | ButtonMotionMask | Button1MotionMask | Button2MotionMask | Button3MotionMask | Button4MotionMask | Button5MotionMask \
						| EnterWindowMask |	LeaveWindowMask | PointerMotionMask | PointerMotionHintMask \
						| ExposureMask \
						| FocusChangeMask \
						| StructureNotifyMask | SubstructureNotifyMask)						
#define WIDGET_MAIN_EVENTS (KeyPressMask | KeyReleaseMask \
						| ButtonPressMask | ButtonReleaseMask | ButtonMotionMask | Button1MotionMask | Button2MotionMask | Button3MotionMask | Button4MotionMask | Button5MotionMask \
						| EnterWindowMask |	LeaveWindowMask | PointerMotionMask | PointerMotionHintMask \
						| ExposureMask \
						| FocusChangeMask \
						| StructureNotifyMask | SubstructureNotifyMask \
						| VisibilityChangeMask \
						| KeymapStateMask)



#define WIDGET_TITLE_SPAN		(float)10	//mm
#define WIDGET_MENU_SPAN		(float)7.5	//mm
#define WIDGET_SCROLL_SPAN		(float)5	//mm
#define WIDGET_ICON_SPAN		(float)3	//mm
#define WIDGET_FRAME_EDGE		(float)1.5	//mm
#define WIDGET_CHILD_EDGE		(float)0.5	//mm

#define WIDGET_BORDER_WIDTH		2 //pt

#define DEFAULT_SCROLL_DELTA	120
#define DEFAULT_CARET_BLINK		500

#define HIWORD(dw)		(unsigned short)(((unsigned int)(dw) >> 16) & 0x0000FFFF)
#define LOWORD(dw)		(unsigned short)((unsigned int)(dw) & 0x0000FFFF)

#define IS_META_KEY(key)	(key == XK_Shift_L || key == XK_Shift_R || key == XK_Control_L || key == XK_Control_R ||key == XK_Caps_Lock || key == XK_Shift_Lock || key == XK_Meta_L || key == XK_Meta_R || key == XK_Alt_L || key == XK_Alt_R || key == XK_Super_L || key == XK_Super_R ||key == XK_Hyper_L || key == XK_Hyper_R)

res_queue_t g_queue = 0;
X11_atoms_t  g_atoms = {0};

static int X11_to_keycode(int xk)
{
    switch (xk)
    {
        case XK_BackSpace: return KEY_BACK; 
        case XK_Tab: return KEY_TAB; 
        case XK_Return: return KEY_ENTER;
        case XK_Escape: return KEY_ESC;
        case 32: return KEY_SPACE;
        case XK_Page_Up: return KEY_PAGEUP; 
        case XK_Page_Down: return KEY_PAGEDOWN;
        case XK_End: return KEY_END;
        case XK_Home: return KEY_HOME;
        case XK_Left: return KEY_LEFT; 
        case XK_Up: return KEY_UP; 
        case XK_Right: return KEY_RIGHT; 
        case XK_Down: return KEY_DOWN;
        case XK_Insert: return KEY_INSERT; 
        case XK_Delete: return KEY_DELETE;
        case XK_F1: return KEY_F1;
        case XK_F2: return KEY_F2;
        case XK_F3: return KEY_F3;
        case XK_F4: return KEY_F4;
        case XK_F5: return KEY_F5;
        case XK_F6: return KEY_F6;
        case XK_F7: return KEY_F7;
        case XK_F8: return KEY_F8;
        case XK_F9: return KEY_F9;
        case XK_F10: return KEY_F10;
        case XK_F11: return KEY_F11;
        case XK_F12: return KEY_F12;
        default: return (int)0; 
    }
}

static int keycode_to_X11(int key)
{
    switch (key)
    {
        case KEY_BACK: return XK_BackSpace; 
        case KEY_TAB: return XK_Tab; 
        case KEY_ENTER: return XK_Return;
        case KEY_ESC: return XK_Escape;
        case KEY_SPACE: return 32;
        case KEY_PAGEUP: return XK_Page_Up; 
        case KEY_PAGEDOWN: return XK_Page_Down;
        case KEY_END: return XK_End;
        case KEY_HOME: return XK_Home;
        case KEY_LEFT: return XK_Left; 
        case KEY_UP: return XK_Up; 
        case KEY_RIGHT: return XK_Right; 
        case KEY_DOWN: return XK_Down;
        case KEY_INSERT: return XK_Insert; 
        case KEY_DELETE: return XK_Delete;
        case KEY_F1: return XK_F1;
        case KEY_F2: return XK_F2;
        case KEY_F3: return XK_F3;
        case KEY_F4: return XK_F4;
        case KEY_F5: return XK_F5;
        case KEY_F6: return XK_F6;
        case KEY_F7: return XK_F7;
        case KEY_F8: return XK_F8;
        case KEY_F9: return XK_F9;
        case KEY_F10: return XK_F10;
        case KEY_F11: return XK_F11;
        case KEY_F12: return XK_F12;
        default: return (int)0; 
    }
}

static dword_t _key_state(unsigned int unFlags)
{
    dword_t mask = 0;

    if (unFlags & ShiftMask)
        mask |= KS_WITH_SHIFT;
    if (unFlags & ControlMask)
        mask |= KS_WITH_CONTROL;
    if (unFlags & Mod1Mask)
        mask |= KS_WITH_ALT;

    return mask;
}

static dword_t _mouse_state(unsigned int nsState)
{
    dword_t mask = 0;

    if (nsState & Button1Mask)
        mask |= MS_WITH_LBUTTON;
    if (nsState & Button3Mask)
        mask |= MS_WITH_RBUTTON;
    
    return mask;
}

static int _tmp_error_handler(Display* dpy, XErrorEvent* pee)
{
	return 0;
}

static int _tmp_ioerr_handler(Display* dpy)
{
	return 0;
}

static int _tmp_ioexit_handler(Display* dpy, void* pd)
{
	return 0;
}

static bool_t _WindowSetProper(Window win, Atom atom, const unsigned char* data, dword_t len)
{
    return (Success == XChangeProperty(g_display, win, atom, XA_STRING, 8, PropModeReplace, data, len))? 1 : 0;
}

static bool_t _WindowGetProper(Window win, Atom atom, unsigned char* data, dword_t len)
{
    Atom type = 0;
    int format = 0;
    unsigned int nitems = 0, after = 0;
    unsigned char *prop = 0;
    
    if (Success != XGetWindowProperty(g_display, win, atom, 0, 1024, False, XA_STRING, &type, &format, &nitems, &after, &prop))
        return 0;
    
    if(prop)
    {
        xmem_copy((void*)data,(void*)prop, len);
    }
    
    XFree(prop);
    
    return 1;
}

static bool_t _WindowDelProper(Window win, Atom atom)
{    
    return (Success == XDeleteProperty(g_display, win, atom))? 1 : 0;
}

static X11_widget_t* GETXDUSTRUCT(Window win)
{
    byte_t bys[VOID_SIZE] = {0};

    XErrorHandler pf_org;
	XIOErrorHandler pf_io;

	pf_org = XSetErrorHandler(_tmp_error_handler);
	pf_io = XSetIOErrorHandler(_tmp_ioerr_handler);

    _WindowGetProper(win, g_atoms.xdu_struct, bys, VOID_SIZE);

	XSetErrorHandler(pf_org);
	XSetIOErrorHandler(pf_io);

    return (X11_widget_t*)GET_VOID_NET(bys, 0);
}

static void SETXDUSTRUCT(Window win, X11_widget_t* p)
{
    byte_t bys[VOID_SIZE] = {0};
	
    PUT_VOID_NET(bys, 0, p);
    
    _WindowSetProper(win, g_atoms.xdu_struct, bys, VOID_SIZE);
}

static if_dispatch_t* GETXDUDISPATCH(Window win)
{
    byte_t bys[VOID_SIZE] = {0};
	XErrorHandler pf_org;

	pf_org = XSetErrorHandler(_tmp_error_handler);
    _WindowGetProper(win, g_atoms.xdu_dispatch, bys, VOID_SIZE);
	XSetErrorHandler(pf_org);

    return (if_dispatch_t*)GET_VOID_NET(bys, 0);
}

static void SETXDUDISPATCH(Window win, if_dispatch_t* p)
{
    byte_t bys[VOID_SIZE] = {0};
    
    PUT_VOID_NET(bys, 0, p);
    
    _WindowSetProper(win, g_atoms.xdu_dispatch, bys, VOID_SIZE);
}

static if_subproc_t* GETXDUSUBPROC(Window win)
{
    byte_t bys[VOID_SIZE] = {0};
    XErrorHandler pf_org;

	pf_org = XSetErrorHandler(_tmp_error_handler);
    _WindowGetProper(win, g_atoms.xdu_subproc, bys, VOID_SIZE);
	XSetErrorHandler(pf_org);

    return (if_subproc_t*)GET_VOID_NET(bys, 0);
}

static void SETXDUSUBPROC(Window win, if_subproc_t* p)
{
    byte_t bys[VOID_SIZE] = {0};
    
    PUT_VOID_NET(bys, 0, p);
    
    _WindowSetProper(win, g_atoms.xdu_subproc, bys, VOID_SIZE);
}

static void* GETXDUCOREDELTA(Window win)
{
    byte_t bys[VOID_SIZE] = {0};
    XErrorHandler pf_org;

	pf_org = XSetErrorHandler(_tmp_error_handler);
    _WindowGetProper(win, g_atoms.xdu_core_delta, bys, VOID_SIZE);
	XSetErrorHandler(pf_org);
    
    return (void*)GET_VOID_NET(bys, 0);
}

static void SETXDUCOREDELTA(Window win, void* p)
{
    byte_t bys[VOID_SIZE] = {0};
    
    PUT_VOID_NET(bys, 0, p);
    
    _WindowSetProper(win, g_atoms.xdu_core_delta, bys, VOID_SIZE);
}

static void* GETXDUUSERDELTA(Window win)
{
    byte_t bys[VOID_SIZE] = {0};
	XErrorHandler pf_org;

	pf_org = XSetErrorHandler(_tmp_error_handler);
    _WindowGetProper(win, g_atoms.xdu_user_delta, bys, VOID_SIZE);
    XSetErrorHandler(pf_org);

    return (void*)GET_VOID_NET(bys, 0);
}

static void SETXDUUSERDELTA(Window win, void* p)
{
    byte_t bys[VOID_SIZE] = {0};
    
    PUT_VOID_NET(bys, 0, p);
    
    _WindowSetProper(win, g_atoms.xdu_user_delta, bys, VOID_SIZE);
}

/*******************************************************************************************/

void _widget_startup(int ver)
{
	g_atoms.net_active_window = XInternAtom (g_display, "_NET_ACTIVE_WINDOW", False);
    g_atoms.net_close_window = XInternAtom (g_display, "_NET_CLOSE_WINDOW", False);
    g_atoms.net_wm_action_close = XInternAtom (g_display, "_NET_WM_ACTION_CLOSE", False);
    g_atoms.net_wm_action_fullscreen = XInternAtom (g_display, "_NET_WM_ACTION_FULLSCREEN", False);
    g_atoms.net_wm_action_maximize_horz = XInternAtom (g_display, "_NET_WM_ACTION_MAXIMIZE_HORZ", False);
    g_atoms.net_wm_action_maximize_vert = XInternAtom (g_display, "_NET_WM_ACTION_MAXIMIZE_VERT", False);
    g_atoms.net_wm_action_minimize = XInternAtom (g_display, "_NET_WM_ACTION_MINIMIZE", False);
    g_atoms.net_wm_action_move = XInternAtom (g_display, "_NET_WM_ACTION_MOVE", False);
    g_atoms.net_wm_action_resize = XInternAtom (g_display, "_NET_WM_ACTION_RESIZE", False);
    g_atoms.net_wm_action_shade = XInternAtom (g_display, "_NET_WM_ACTION_SHADE", False);
    g_atoms.net_wm_allowed_actions = XInternAtom (g_display, "_NET_WM_ALLOWED_ACTIONS", False);
    g_atoms.net_wm_name = XInternAtom (g_display, "_NET_WM_NAME", False);
    g_atoms.net_wm_state = XInternAtom (g_display, "_NET_WM_STATE", False);
    g_atoms.net_wm_state_fullscreen = XInternAtom (g_display, "_NET_WM_STATE_FULLSCREEN", False);
    g_atoms.net_wm_state_hidden = XInternAtom (g_display, "_NET_WM_STATE_HIDDEN", False);
    g_atoms.net_wm_state_maximized_horz = XInternAtom (g_display, "_NET_WM_STATE_MAXIMIZED_HORZ", False);
    g_atoms.net_wm_state_maximized_vert = XInternAtom (g_display, "_NET_WM_STATE_MAXIMIZED_VERT", False);
    g_atoms.net_wm_state_modal = XInternAtom (g_display, "_NET_WM_STATE_MODAL", False);
    g_atoms.net_wm_state_shaded = XInternAtom (g_display, "_NET_WM_STATE_SHADED", False);
    g_atoms.net_wm_state_skip_pager = XInternAtom (g_display, "_NET_WM_STATE_SKIP_PAGER", False);
    g_atoms.net_wm_state_skip_taskbar = XInternAtom (g_display, "_NET_WM_STATE_SKIP_TASKBAR", False);
    g_atoms.net_wm_state_sticky = XInternAtom (g_display, "_NET_WM_STATE_STICKY", False);
    g_atoms.net_wm_window_type = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE", False);
    g_atoms.net_wm_window_type_combo = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_COMBO", False);
    g_atoms.net_wm_window_type_desktop = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_DESKTOP", False);
    g_atoms.net_wm_window_type_dialog = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_DIALOG", False);
    g_atoms.net_wm_window_type_dock = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_DOCK", False);
    g_atoms.net_wm_window_type_dnd = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_DND", False);
    g_atoms.net_wm_window_type_dropdown_menu = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_DROPDOWN_MENU", False);
    g_atoms.net_wm_window_type_menu = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_MENU", False);
    g_atoms.net_wm_window_type_normal = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_NORMAL", False);
    g_atoms.net_wm_window_type_notification = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_NOTIFICATION", False);
    g_atoms.net_wm_window_type_popup_menu = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_POPUP_MENU", False);
    g_atoms.net_wm_window_type_splash = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_SPLASH", False);
    g_atoms.net_wm_window_type_tooltip = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_TOOLTIP", False);
    g_atoms.net_wm_window_type_toolbar = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_TOOLBAR", False);
    g_atoms.net_wm_window_type_utility = XInternAtom (g_display, "_NET_WM_WINDOW_TYPE_UTILITY", False);
    g_atoms.net_wm_ping = XInternAtom (g_display, "_NET_WM_PING", False);
	g_atoms.wm_change_state = XInternAtom (g_display, "WM_CHANGE_STATE", False);
    g_atoms.wm_colormap_windows = XInternAtom (g_display, "WM_COLORMAP_WINDOWS", False);
    g_atoms.wm_delete_window = XInternAtom (g_display, "WM_DELETE_WINDOW", False);
    g_atoms.wm_hints = XInternAtom (g_display, "WM_HINTS", False);
    g_atoms.wm_name = XInternAtom (g_display, "WM_NAME", False);
    g_atoms.wm_normal_hints = XInternAtom (g_display, "WM_NORMAL_HINTS", False);
    g_atoms.wm_protocols = XInternAtom (g_display, "WM_PROTOCOLS", False);
    g_atoms.wm_state = XInternAtom (g_display, "WM_STATE", False);
    g_atoms.wm_take_focus = XInternAtom (g_display, "WM_TAKE_FOCUS", False);
    g_atoms.wm_transient_for = XInternAtom (g_display, "WM_TRANSIENT_FOR", False);

	g_atoms.wm_wchar = XInternAtom (g_display, "WM_WCHAR", False);
	g_atoms.wm_quit = XInternAtom (g_display, "WM_QUIT", False);
	g_atoms.wm_command = XInternAtom (g_display, "WM_COMMAND", False);
	g_atoms.wm_notice = XInternAtom (g_display, "WM_NOTICE", False);
	g_atoms.wm_input = XInternAtom (g_display, "WM_INPUT", False);
	g_atoms.wm_scroll = XInternAtom (g_display, "WM_SCROLL", False);

    g_atoms.xdu_struct = XInternAtom (g_display, "XDUSTRUCT", False);
    g_atoms.xdu_dispatch = XInternAtom (g_display, "XDUDISPATCH", False);
    g_atoms.xdu_subproc = XInternAtom (g_display, "XDUSUBPROC", False);
    g_atoms.xdu_user_delta = XInternAtom (g_display, "XDUUSERDELTA", False);
    g_atoms.xdu_core_delta = XInternAtom (g_display, "XDUCOREDELTA", False);

	g_queue = create_timer_queue();

	setlocale(LC_ALL, "");
    XSetLocaleModifiers("");

    g_xim = XOpenIM(g_display, NULL, NULL, NULL);
}

void _widget_cleanup()
{
	if(g_queue) destroy_timer_queue(g_queue);
	g_queue = 0;

	if(g_xim) XCloseIM(g_xim);
    g_xim = 0;
}

/*******************************************************************************************/

static bool_t _message_translate(XEvent* pmsg)
{
	X11_widget_t* pxw;
	accel_table_t* pac;
	char keystr[5] = {0};
	KeySym keysys = 0;
	Status status = 0;
	unsigned int state;
	int i, keys = 0;
	char ch = 0;
	char* pch = NULL;
	char kch = 0;
	wchar_t wc = 0;

	XClientMessageEvent ev = {0};

	if(pmsg->type == KeyPress)
	{
		if(XFilterEvent(pmsg, pmsg->xkey.window))
			return 1;

		pxw = GETXDUSTRUCT(pmsg->xkey.window);
		if(!pxw) return 0;

		if(pxw->xic)
			keys = XmbLookupString(pxw->xic, &(pmsg->xkey), keystr, 4, &keysys, &status);
		else
			keys = XLookupString(&(pmsg->xkey), keystr, 4, &keysys, &status);

		if(!keys)
		{
			return 0;
		}
		//if(!IsFunctionKey(keysys) && !IsMiscFunctionKey(keysys) && !IsCursorKey(keysys)
		
		//if(pmsg->xkey.state & ShiftMask) state |= KS_WITH_SHIFT;
		if(pmsg->xkey.state & ControlMask) state |= KS_WITH_CONTROL;
		if(pmsg->xkey.state & Mod1Mask) state |= KS_WITH_ALT;

		switch(keys)
		{
		case 1:
			ch = keystr[0];
			keysys = XLookupKeysym(&(pmsg->xkey), 0);
			break;
		case 2:
			ch = keystr[1];
			keysys = XLookupKeysym(&(pmsg->xkey), 1);
			break;
		case 3:
			ch = keystr[2];
			keysys = XLookupKeysym(&(pmsg->xkey), 2);
			break;
		default:
			ch = keystr[3];
			keysys = XLookupKeysym(&(pmsg->xkey), 3);
			break;
		}

		if(pxw->acl)
		{
			pch = XKeysymToString(keysys);
			kch = (pch) ? *pch : 0;

			pac = (accel_table_t*)pxw->acl;
			i = 0;
			while (pac[i].vir != 0 && pac[i].key != 0)
			{
				if (pac[i].vir == state && pac[i].key == kch)
				{
					ev.type = ClientMessage;
					ev.serial = 0;
					ev.send_event = 1;
					ev.display = g_display;
					ev.window = pmsg->xkey.window;
					ev.message_type = g_atoms.wm_command;
					ev.format = 32;
					ev.data.l[0] = pxw->uid;
					ev.data.l[1] = pac[i].cmd;
					ev.data.l[2] = 0;
					ev.data.l[3] = ev.data.l[4] = 0;

					XSendEvent(g_display, pmsg->xkey.window, False, SubstructureNotifyMask, (XEvent *)&ev);

					return 1;
				}

				i++;
			}
		}

		mbtowc(&wc, keystr, keys);

		ev.type = ClientMessage;
		ev.serial = 0;
		ev.send_event = 1;
		ev.display = g_display;
		ev.window = pmsg->xkey.window;
		ev.message_type = g_atoms.wm_wchar;
		ev.format = 32;
		ev.data.l[0] = (long)wc;

		XSendEvent(g_display, pmsg->xkey.window, False, SubstructureNotifyMask, (XEvent *)&ev);
	}else if(pmsg->type == KeyRelease)
	{
		if(XFilterEvent(pmsg, pmsg->xkey.window))
			return 1;
	}

    return 0;
}

static int _message_dispatch(XEvent* pmsg)
{
	X11_widget_t* pxw;
	widget_t wt;
	if_dispatch_t* pif;
	if_subproc_t* psub;

	KeySym key;
	xpoint_t xp;
	xsize_t xs;
	xrect_t xr;
	dword_t ms;
	
	switch(pmsg->type)
	{
		case KeymapNotify:
            XRefreshKeyboardMapping(&pmsg->xmapping);
            break;
		case KeyPress:
			pxw = GETXDUSTRUCT(pmsg->xkey.window);
			if(!pxw) break;
			if(pxw->disable) break;
			wt = &(pxw->head);

			pxw->mask = _key_state(pmsg->xkey.state);
			key = XLookupKeysym(&(pmsg->xkey), 0);

			if(pxw->xic && key == 0) break;

			psub = GETXDUSUBPROC(pmsg->xkey.window);
			if(psub && psub->sub_on_keydown)
			{
				pxw->result = (*psub->sub_on_keydown)(wt, pxw->mask, (int)(key), psub->sid, psub->delta);
				if(pxw->result) break;
			}

			pif = GETXDUDISPATCH(pmsg->xkey.window);
			if(pif && pif->pf_on_keydown)
			{
				(*pif->pf_on_keydown)(wt, pxw->mask, (int)(key));
			}
			break;
		case KeyRelease:
			pxw = GETXDUSTRUCT(pmsg->xkey.window);
			if(!pxw) break;
			if(pxw->disable) break;
			wt = &(pxw->head);

			pxw->mask = _key_state(pmsg->xkey.state);
			key = XLookupKeysym(&(pmsg->xkey), 0);

			psub = GETXDUSUBPROC(pmsg->xkey.window);
			if(psub && psub->sub_on_keyup)
			{
				pxw->result = (*psub->sub_on_keyup)(wt, pxw->mask, (int)(key), psub->sid, psub->delta);
				if(pxw->result) break;
			}

			pif = GETXDUDISPATCH(pmsg->xkey.window);
			if(pif && pif->pf_on_keyup)
			{
				(*pif->pf_on_keyup)(wt, pxw->mask, (int)(key));
			}
			break;
		case ButtonPress:
		pxw = GETXDUSTRUCT(pmsg->xbutton.window);
			if(!pxw) break;
			if(pxw->disable) break;
			wt = &(pxw->head);
		
			xp.x = pmsg->xbutton.x;
			xp.y = pmsg->xbutton.y;
			_widget_window_to_client(wt, &xp);

			psub = GETXDUSUBPROC(pmsg->xbutton.window);
			if(pmsg->xbutton.button == Button1)
			{
				if(psub && psub->sub_on_lbutton_down)
				{
					pxw->result = (*psub->sub_on_lbutton_down)(wt, &xp, psub->sid, psub->delta);
					if(pxw->result) break;
				}
			}else if(pmsg->xbutton.button == Button3)
			{
				if(psub && psub->sub_on_rbutton_down)
				{
					pxw->result = (*psub->sub_on_rbutton_down)(wt, &xp, psub->sid, psub->delta);
					if(pxw->result) break;
				}
			}

			pif = GETXDUDISPATCH(pmsg->xbutton.window);
			if(pmsg->xbutton.button == Button1)
			{
				if (pif && pif->pf_on_lbutton_down)
				{
					(*pif->pf_on_lbutton_down)(wt, &xp);
				}
			}else if(pmsg->xbutton.button == Button3)
			{
				if (pif && pif->pf_on_rbutton_down)
				{
					(*pif->pf_on_rbutton_down)(wt, &xp);
				}
			}
			break;
		case ButtonRelease:
			pxw = GETXDUSTRUCT(pmsg->xbutton.window);
			if(!pxw) break;
			if(pxw->disable) break;
			wt = &(pxw->head);
		
			xp.x = pmsg->xbutton.x;
			xp.y = pmsg->xbutton.y;
			_widget_window_to_client(wt, &xp);

			psub = GETXDUSUBPROC(pmsg->xbutton.window);
			if(pmsg->xbutton.button == Button1)
			{
				if(psub && psub->sub_on_lbutton_up)
				{
					pxw->result = (*psub->sub_on_lbutton_up)(wt, &xp, psub->sid, psub->delta);
					if(pxw->result) break;
				}
			}else if(pmsg->xbutton.button == Button3)
			{
				if(psub && psub->sub_on_rbutton_down)
				{
					pxw->result = (*psub->sub_on_rbutton_up)(wt, &xp, psub->sid, psub->delta);
					if(pxw->result) break;
				}
			}else if(pmsg->xbutton.button == Button4)
			{
				if(psub && psub->sub_on_scroll)
				{
					pxw->result = (*psub->sub_on_scroll)(wt, 0, DEFAULT_SCROLL_DELTA, psub->sid, psub->delta);
					if(pxw->result) break;
				}
			}else if(pmsg->xbutton.button == Button5)
			{
				if(psub && psub->sub_on_scroll)
				{
					pxw->result = (*psub->sub_on_scroll)(wt, 0, -DEFAULT_SCROLL_DELTA, psub->sid, psub->delta);
					if(pxw->result) break;
				}
			}

			pif = GETXDUDISPATCH(pmsg->xbutton.window);
			if(pmsg->xbutton.button == Button1)
			{
				if (pif && pif->pf_on_lbutton_up)
				{
					(*pif->pf_on_lbutton_up)(wt, &xp);
				}
			}else if(pmsg->xbutton.button == Button3)
			{
				if (pif && pif->pf_on_rbutton_up)
				{
					(*pif->pf_on_rbutton_up)(wt, &xp);
				}
			}else if(pmsg->xbutton.button == Button4)
			{
				if (pif && pif->pf_on_wheel)
				{
					wt = &(pxw->head);
					(*pif->pf_on_wheel)(wt, 0, DEFAULT_SCROLL_DELTA);
				}
			}else if(pmsg->xbutton.button == Button5)
			{
				if (pif && pif->pf_on_wheel)
				{
					wt = &(pxw->head);
					(*pif->pf_on_wheel)(wt, 0, -DEFAULT_SCROLL_DELTA);
				}
			}
			break;
		case MotionNotify:
			pxw = GETXDUSTRUCT(pmsg->xmotion.window);
			if(!pxw) break;
			if(pxw->disable) break;
			wt = &(pxw->head);

			xp.x = pmsg->xmotion.x;
			xp.y = pmsg->xmotion.y;
			_widget_window_to_client(wt, &xp);

			pxw->mask = _mouse_state(pmsg->xmotion.state) | _key_state(pmsg->xmotion.state);

			psub = GETXDUSUBPROC(pmsg->xmotion.window);
			if(psub && psub->sub_on_mouse_move)
			{
				pxw->result = (*psub->sub_on_mouse_move)(wt, pxw->mask, &xp, psub->sid, psub->delta);
				if(pxw->result) break;
			}

			pif = GETXDUDISPATCH(pmsg->xmotion.window);
			if (pif && pif->pf_on_mouse_move)
			{			
				(*pif->pf_on_mouse_move)(wt, pxw->mask, &xp);
			}
			break;
		case EnterNotify:
			pxw = GETXDUSTRUCT(pmsg->xcrossing.window);
			if(!pxw) break;
			if(pxw->disable) break;
			wt = &(pxw->head);

			xp.x = pmsg->xcrossing.x;
			xp.y = pmsg->xcrossing.y;
			_widget_window_to_client(wt, &xp);

			pxw->mask = _mouse_state(pmsg->xcrossing.state) | _key_state(pmsg->xcrossing.state);

			psub = GETXDUSUBPROC(pmsg->xcrossing.window);
			if(psub && psub->sub_on_mouse_enter)
			{
				pxw->result = (*psub->sub_on_mouse_enter)(wt, pxw->mask, &xp, psub->sid, psub->delta);
				if(pxw->result) break;
			}

			pif = GETXDUDISPATCH(pmsg->xcrossing.window);
			if (pif && pif->pf_on_mouse_enter)
			{
				(*pif->pf_on_mouse_enter)(wt, pxw->mask, &xp);
			}
			break;
		case LeaveNotify:
			pxw = GETXDUSTRUCT(pmsg->xcrossing.window);
			if(!pxw) break;
			if(pxw->disable) break;
			wt = &(pxw->head);

			xp.x = pmsg->xcrossing.x;
			xp.y = pmsg->xcrossing.y;
			_widget_window_to_client(wt, &xp);

			pxw->mask = _mouse_state(pmsg->xcrossing.state) | _key_state(pmsg->xcrossing.state);

			psub = GETXDUSUBPROC(pmsg->xcrossing.window);
			if(psub && psub->sub_on_mouse_leave)
			{
				pxw->result = (*psub->sub_on_mouse_leave)(wt, pxw->mask, &xp, psub->sid, psub->delta);
				if(pxw->result) break;
			}

			pif = GETXDUDISPATCH(pmsg->xcrossing.window);
			if (pif && pif->pf_on_mouse_leave)
			{
				(*pif->pf_on_mouse_leave)(wt, pxw->mask, &xp);
			}
			break;
		case Expose:
			pxw = GETXDUSTRUCT(pmsg->xexpose.window);
			if(!pxw) break;
			wt = &(pxw->head);

			xr.x = pmsg->xexpose.x;
			xr.y = pmsg->xexpose.y;
			xr.w = pmsg->xexpose.width;
			xr.h = pmsg->xexpose.height;

			psub = GETXDUSUBPROC(pmsg->xexpose.window);
			if(psub && psub->sub_on_paint)
			{
				visual_t rdc;
				rdc = _create_display_context(wt);
				pxw->result = (*psub->sub_on_paint)(wt, rdc, &xr, psub->sid, psub->delta);
				_destroy_context(rdc);
				if(pxw->result) break;
			}

			pif = GETXDUDISPATCH(pmsg->xexpose.window);
			if(pif && pif->pf_on_paint)
			{
				visual_t rdc;
				rdc = _create_display_context(wt);
				(*pif->pf_on_paint)(wt, rdc, &xr);
				_destroy_context(rdc);
			}
			break;
		case FocusIn:
			pxw = GETXDUSTRUCT(pmsg->xfocus.window);
			if(!pxw) break;
			if(pxw->disable) break;
			wt = &(pxw->head);

			if((pxw->style & WD_STYLE_EDITOR) && pxw->xic)
			{
				XSetICFocus(pxw->xic);
			}

			psub = GETXDUSUBPROC(pmsg->xfocus.window);
			if(psub && psub->sub_on_set_focus)
			{
				pxw->result = (*psub->sub_on_set_focus)(wt, pmsg->xfocus.window, psub->sid, psub->delta);
				if(pxw->result) break;
			}

			pif = GETXDUDISPATCH(pmsg->xfocus.window);
			if (pif && pif->pf_on_set_focus)
			{
				(*pif->pf_on_set_focus)(wt, pmsg->xfocus.window);
			}
			break;
		case FocusOut:
			pxw = GETXDUSTRUCT(pmsg->xfocus.window);
			if(!pxw) break;
			if(pxw->disable) break;
			wt = &(pxw->head);

			if(pxw->xic)
			{
				XUnsetICFocus(pxw->xic);
			}

			psub = GETXDUSUBPROC(pmsg->xfocus.window);
			if(psub && psub->sub_on_kill_focus)
			{
				pxw->result = (*psub->sub_on_kill_focus)(wt, pmsg->xfocus.window, psub->sid, psub->delta);
				if(pxw->result) break;
			}

			pif = GETXDUDISPATCH(pmsg->xfocus.window);
			if (pif && pif->pf_on_kill_focus)
			{
				(*pif->pf_on_kill_focus)(wt, pmsg->xfocus.window);
			}
			break;
		case ResizeRequest:
			pxw = GETXDUSTRUCT(pmsg->xresizerequest.window);
			if(!pxw) break;
			wt = &(pxw->head);

			xs.w = pmsg->xresizerequest.width;
			xs.h = pmsg->xresizerequest.height;

			psub = GETXDUSUBPROC(pmsg->xresizerequest.window);
			if(psub && psub->sub_on_size)
			{
				pxw->result = (*psub->sub_on_size)(wt, WS_SIZE_RESTORE, &xs, psub->sid, psub->delta);
				if(pxw->result) break;
			}

			pif = GETXDUDISPATCH(pmsg->xresizerequest.window);
			if(pif && pif->pf_on_size)
			{
				(*pif->pf_on_size)(wt, WS_SIZE_RESTORE, &xs);
			}
			break;
		case ConfigureNotify:
			pxw = GETXDUSTRUCT(pmsg->xconfigure.window);
			if(!pxw) break;
			wt = &(pxw->head);

			xp.x = pmsg->xconfigure.x;
			xp.y = pmsg->xconfigure.y;

			psub = GETXDUSUBPROC(pmsg->xconfigure.window);
			if(pxw->pt.x != pmsg->xconfigure.x || pxw->pt.y != pmsg->xconfigure.y)
			{
				if(psub && psub->sub_on_move)
				{
					pxw->result = (*psub->sub_on_move)(wt, &xp, psub->sid, psub->delta);
					pxw->pt.x = xp.x;
					pxw->pt.y = xp.y;
					if(pxw->result) break;
				}
			}

			pif = GETXDUDISPATCH(pmsg->xconfigure.window);
			if(pxw->pt.x != pmsg->xconfigure.x || pxw->pt.y != pmsg->xconfigure.y)
			{
				if(pif && pif->pf_on_move)
				{
					(*pif->pf_on_move)(wt, &xp);
				}
				pxw->pt.x = xp.x;
				pxw->pt.y = xp.y;
			}

			xs.w = pmsg->xconfigure.width;
			xs.h = pmsg->xconfigure.height;

			if(pxw->st.w != pmsg->xconfigure.width || pxw->st.h != pmsg->xconfigure.height)
			{
				if(psub && psub->sub_on_size)
				{
					pxw->result = (*psub->sub_on_size)(wt, WS_SIZE_LAYOUT, &xs, psub->sid, psub->delta);
					pxw->st.w = pmsg->xconfigure.width;
					pxw->st.h = pmsg->xconfigure.height;
					if(pxw->result) break;
				}
			}

			if(pxw->st.w != pmsg->xconfigure.width || pxw->st.h != pmsg->xconfigure.height)
			{
				if(pif && pif->pf_on_size)
				{
					(*pif->pf_on_size)(wt, WS_SIZE_LAYOUT, &xs);
				}
				pxw->st.w = pmsg->xconfigure.width;
				pxw->st.h = pmsg->xconfigure.height;
			}
			break;
		case MapNotify:
			pxw = GETXDUSTRUCT(pmsg->xmap.window);
			if(!pxw) break;
			wt = &(pxw->head);

			psub = GETXDUSUBPROC(pmsg->xmap.window);
			if(psub && psub->sub_on_show)
			{
				pxw->result = (*psub->sub_on_show)(wt, 1, psub->sid, psub->delta);
				if(pxw->result) break;
			}

			pif = GETXDUDISPATCH(pmsg->xmap.window);
			if(pif && pif->pf_on_show)
			{
				(*pif->pf_on_show)(wt, 1);
			}
			break;
		case UnmapNotify:
			pxw = GETXDUSTRUCT(pmsg->xunmap.window);
			if(!pxw) break;
			wt = &(pxw->head);

			psub = GETXDUSUBPROC(pmsg->xunmap.window);
			if(psub && psub->sub_on_show)
			{
				pxw->result = (*psub->sub_on_show)(wt, 0, psub->sid, psub->delta);
				if(pxw->result) break;
			}

			pif = GETXDUDISPATCH(pmsg->xunmap.window);
			if(pif && pif->pf_on_show)
			{
				(*pif->pf_on_show)(wt, 0);
			}
			break;
		case CreateNotify:
			break;
		case DestroyNotify:
			break;
		case ClientMessage:
			pxw = GETXDUSTRUCT(pmsg->xclient.window);
			if(!pxw) break;
			if(pxw->disable) break;
			wt = &(pxw->head);

			if(pmsg->xclient.message_type == g_atoms.wm_command)
			{
				psub = GETXDUSUBPROC(pmsg->xclient.window);
				pif = GETXDUDISPATCH(pmsg->xclient.window);

				if(pmsg->xclient.data.l[0] == IDC_PARENT)
				{
					if(psub && psub->sub_on_parent_command)
					{
						pxw->result = (*psub->sub_on_parent_command)(wt, (int)(pmsg->xclient.data.l[1]), (vword_t)(pmsg->xclient.data.l[2]), psub->sid, psub->delta);
						if(pxw->result) break;
					}

					if(pif && pif->pf_on_parent_command)
					{
						(*pif->pf_on_parent_command)(wt, (int)(pmsg->xclient.data.l[1]), (vword_t)(pmsg->xclient.data.l[2]));
					}
				}else if(pmsg->xclient.data.l[0] == IDC_CHILD)
				{
					if(psub && psub->sub_on_child_command)
					{
						pxw->result = (*psub->sub_on_child_command)(wt, (int)(pmsg->xclient.data.l[1]), (vword_t)(pmsg->xclient.data.l[2]), psub->sid, psub->delta);
						if(pxw->result) break;
					}

					if(pif && pif->pf_on_child_command)
					{
						(*pif->pf_on_child_command)(wt, (int)(pmsg->xclient.data.l[1]), (vword_t)(pmsg->xclient.data.l[2]));
					}
				}else if(pmsg->xclient.data.l[0] == IDC_SELF)
				{
					if(psub && psub->sub_on_self_command)
					{
						pxw->result = (*psub->sub_on_self_command)(wt, (int)(pmsg->xclient.data.l[1]), (vword_t)(pmsg->xclient.data.l[2]), psub->sid, psub->delta);
						if(pxw->result) break;
					}

					if(pif && pif->pf_on_self_command)
					{
						(*pif->pf_on_self_command)(wt, (int)(pmsg->xclient.data.l[1]), (vword_t)(pmsg->xclient.data.l[2]));
					}
				}else
				{
					if(psub && psub->sub_on_menu_command)
					{
						pxw->result = (*psub->sub_on_menu_command)(wt, (int)(pmsg->xclient.data.l[1]), (int)(pmsg->xclient.data.l[0]), (vword_t)(pmsg->xclient.data.l[2]), psub->sid, psub->delta);
						if(pxw->result) break;
					}

					if(pif && pif->pf_on_menu_command)
					{
						(*pif->pf_on_menu_command)(wt, (int)(pmsg->xclient.data.l[1]), (int)(pmsg->xclient.data.l[0]), (vword_t)(pmsg->xclient.data.l[2]));
					}
				}
				break;
			}

			if(pmsg->xclient.message_type == g_atoms.wm_notice)
			{
				psub = GETXDUSUBPROC(pmsg->xclient.window);
				if(psub && psub->sub_on_notice)
				{
					pxw->result = (*psub->sub_on_notice)(wt, (NOTICE *)(pmsg->xclient.data.l[2]), psub->sid, psub->delta);
					if(pxw->result) break;
				}

				pif = GETXDUDISPATCH(pmsg->xclient.window);
				if (pif && pif->pf_on_notice)
				{
					(*pif->pf_on_notice)(wt, (NOTICE *)(pmsg->xclient.data.l[2]));
				}
				break;
			}

			if(pmsg->xclient.message_type == g_atoms.wm_scroll)
			{
				psub = GETXDUSUBPROC(pmsg->xclient.window);
				pif = GETXDUDISPATCH(pmsg->xclient.window);

				if(pmsg->xclient.data.l[0] == 1)
				{
					if(psub && psub->sub_on_scroll)
					{
						pxw->result = (*psub->sub_on_scroll)(wt, (bool_t)1, (int)(pmsg->xclient.data.l[1]), psub->sid, psub->delta);
						if(pxw->result) break;
					}

					if(pif && pif->pf_on_scroll)
					{
						(*pif->pf_on_scroll)(wt, (bool_t)1, (int)(pmsg->xclient.data.l[1]));
					}
				}else
				{
					if(psub && psub->sub_on_scroll)
					{
						pxw->result = (*psub->sub_on_scroll)(wt, (bool_t)0, (int)(pmsg->xclient.data.l[1]), psub->sid, psub->delta);
						if(pxw->result) break;
					}

					if(pif && pif->pf_on_scroll)
					{
						(*pif->pf_on_scroll)(wt, (bool_t)0, (int)(pmsg->xclient.data.l[1]));
					}
				}
				break;
			}

			if(pmsg->xclient.message_type == g_atoms.net_active_window)
			{
				psub = GETXDUSUBPROC(pmsg->xclient.window);
				if(psub && psub->sub_on_activate)
				{
					pxw->result = (*psub->sub_on_activate)(wt, 1, psub->sid, psub->delta);
					if(pxw->result) break;
				}

				pif = GETXDUDISPATCH(pmsg->xclient.window);
				if(pif && pif->pf_on_activate)
				{
					(*pif->pf_on_activate)(wt, 1);
				}
				break;
			}

			if(pmsg->xclient.message_type == g_atoms.wm_protocols && pmsg->xclient.data.l[0] == g_atoms.wm_take_focus)
			{
				wt = &(pxw->head);
				_widget_set_focus(wt);
				break;
			}

			if(pmsg->xclient.message_type == g_atoms.wm_protocols && pmsg->xclient.data.l[0] == g_atoms.wm_delete_window)
			{
				wt = &(pxw->head);
				_widget_close(wt, 0);
				break;
			}

			if(pmsg->xclient.message_type == g_atoms.wm_wchar)
			{
				psub = GETXDUSUBPROC(pmsg->xclient.window);
				if(psub && psub->sub_on_wchar)
				{
					pxw->result = (*psub->sub_on_wchar)(wt, (wchar_t)(pmsg->xclient.data.l[0]), psub->sid, psub->delta);
					if(pxw->result) break;
				}

				pif = GETXDUDISPATCH(pmsg->xclient.window);
				if(pif && pif->pf_on_wchar)
				{
					wt = &(pxw->head);
					(*pif->pf_on_wchar)(wt, (wchar_t)(pmsg->xclient.data.l[0]));
				}
				break;
			}

			break;
	}

	return 0;
}

static void _message_fetch(XEvent* pmsg, Window win)
{
	XWindowAttributes attr = {0};
	Bool rt;
	int x, y;
	Window cld;

    if(win)
	{
		XGetWindowAttributes(g_display, win, &attr);
		XWindowEvent(g_display, win, attr.your_event_mask, pmsg);

		return;
	}

    XNextEvent(g_display, pmsg);
}

static bool_t _message_peek(XEvent* pmsg)
{
	if(!XPending(g_display))
		return 0;

    XPeekEvent(g_display, pmsg);
	
	return 1;
}

widget_t _widget_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev)
{
	X11_widget_t* pxw_par = (wparent)? TypePtrFromHead(X11_widget_t, wparent) : NULL;
	widget_t wt;
    Window win, rot, par;
    int screen_num, screen_dep;
	int window_width, window_height, border_width = 0;
    XSetWindowAttributes attr = {0};
	Atom atom, atoms[2] = {0};
	XWMHints *hints = NULL;
	XWindowAttributes wattr = {0};

	border_t bd = {0};
	X11_widget_t* pxw = NULL;
	if_dispatch_t* pv = NULL;
	
    screen_num = DefaultScreen(g_display);
	screen_dep = DefaultDepth(g_display, screen_num);
	rot = RootWindow(g_display, screen_num);

	attr.border_pixel = WhitePixel(g_display, screen_num);
	attr.background_pixel = BlackPixel(g_display, screen_num);

	par = (pxw_par)? pxw_par->self : rot;

	if(wstyle & WD_STYLE_TITLE)
	{
		attr.override_redirect = False;
		attr.event_mask = WIDGET_MAIN_EVENTS;
		border_width = WIDGET_BORDER_WIDTH;
	}else
	{
		attr.override_redirect = True;
		if(wstyle & WD_STYLE_CHILD)
		{
			border_width = 0;
			attr.event_mask = WIDGET_CHILD_EVENTS;
		}else
		{
			border_width = WIDGET_BORDER_WIDTH;
			attr.event_mask = WIDGET_POPUP_EVENTS;
		}
	}

	if(wstyle & WD_STYLE_NOACTIVE)
	{
		attr.event_mask &= ~(KeyPressMask | KeyReleaseMask | FocusChangeMask);
	}

	window_width = (pxr->w > border_width)? pxr->w : (WIDGET_BORDER_WIDTH + 1);
	window_height = (pxr->h > border_width)? pxr->h : (WIDGET_BORDER_WIDTH + 1);

	win = XCreateWindow(g_display,
			par,
			pxr->x, pxr->y, (window_width - border_width), (window_height - border_width),
			border_width,
			screen_dep,
			InputOutput,
            CopyFromParent,
            (CWOverrideRedirect | CWBorderPixel | CWBackPixel | CWEventMask),
            &attr);


	if(!win) return (widget_t)0;

	if(wname)
	{
		XStoreName(g_display, win, wname);
	}

	if(wstyle & WD_STYLE_TITLE)
	{
		atom = g_atoms.net_wm_window_type_normal;
	}else
	{
		if(wstyle & WD_STYLE_CHILD)
		{
			atom = g_atoms.net_wm_window_type_normal;
		}else
		{
			atom = g_atoms.net_wm_window_type_popup_menu;
		}
	}
    
    XChangeProperty(g_display, win, g_atoms.net_wm_window_type, XA_ATOM, 32, PropModeReplace, (unsigned char *) &atom, 1);

	if(wstyle & WD_STYLE_FRAME)
	{
		if(!(wstyle & WD_STYLE_NOACTIVE))
		{
			atoms[0] = g_atoms.wm_take_focus;
			atoms[1] = g_atoms.wm_delete_window;
			XSetWMProtocols (g_display, win, atoms, 2);
		}else 
		{
			atoms[0] = g_atoms.wm_delete_window;
			XSetWMProtocols (g_display, win, atoms, 1);
		}
	}else
	{
		if(!(wstyle & WD_STYLE_NOACTIVE))
		{
			atoms[0] = g_atoms.wm_take_focus;
			XSetWMProtocols (g_display, win, atoms, 1);
		}
	}

	if(wstyle & WD_STYLE_NOACTIVE)
	{
		hints = XAllocWMHints();
		hints->flags |= InputHint;
		hints->input = False;
		XSetWMHints(g_display, win, hints);
		XFree(hints);
	}

	pxw = (X11_widget_t*)xmem_alloc_handle(sizeof(X11_widget_t));

	pxw->parent = (par == rot)? NULL : par;
	pxw->self = win;
	pxw->style = wstyle;
	pxw->state = WS_SHOW_HIDE;
	pxw->evmsk = attr.event_mask;

	parse_xcolor(&pxw->bkg, GDI_ATTR_RGB_BLACK);
	parse_xcolor(&pxw->frg, GDI_ATTR_RGB_WHITE);
	parse_xcolor(&pxw->txt, GDI_ATTR_RGB_WHITE);
	parse_xcolor(&pxw->msk, GDI_ATTR_RGB_WHITE);
	parse_xcolor(&pxw->ico, GDI_ATTR_RGB_GRAY);

	if(wstyle & WD_STYLE_EDITOR)
	{
		pxw->xic = XCreateIC(g_xim, XNInputStyle, XIMPreeditNothing | XIMStatusNothing, XNClientWindow, win, NULL);
	}

	SETXDUSTRUCT(win, pxw);
	if(pev)
	{
		pv = (if_dispatch_t*)xmem_alloc(sizeof(if_dispatch_t));
		xmem_copy((void*)pv, (void*)pev, sizeof(if_dispatch_t));
		SETXDUDISPATCH(win, pv);
	}

	wt = &(pxw->head);

	if(pev && pev->pf_on_create)
	{
		(*pev->pf_on_create)(wt, pev->param);
	}

    return wt;
}

void _widget_destroy(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	if_dispatch_t* pv;
	Window win;

	pv = GETXDUDISPATCH(pxw->self);

	if(pv && pv->pf_on_destroy)
	{
		(*pv->pf_on_destroy)(wt);
	}

	if(pxw->acl)
	{
		xmem_free(pxw->acl);
	}

	if(pxw->xic)
	{
		XDestroyIC(pxw->xic);
	}

	if(pxw->cur)
	{
		XFreeCursor(g_display, pxw->cur);
	}

	if(pv) xmem_free(pv);
	SETXDUDISPATCH(pxw->self, NULL);
	
	SETXDUSTRUCT(pxw->self, NULL);
    XDestroyWindow(g_display, pxw->self);

	xmem_free_handle((xhand_t)pxw);
}

void _widget_close(widget_t wt, int ret)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
    if_dispatch_t* pv;

	pxw->result = ret;
	
	pv = GETXDUDISPATCH(pxw->self);
	if(pv && pv->pf_on_close)
	{
		if((*pv->pf_on_close)(wt))
			return;
	}

	_widget_destroy(wt);
}

if_subproc_t* _widget_get_subproc(widget_t wt, uid_t sid)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	return GETXDUSUBPROC(pxw->self);
}

bool_t _widget_set_subproc(widget_t wt, uid_t sid, if_subproc_t* sub)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	SETXDUSUBPROC(pxw->self, sub);
	pxw->sid = sid;

	return 1;
}

void _widget_del_subproc(widget_t wt, uid_t sid)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	if(pxw->sid != sid) return;

	SETXDUSUBPROC(pxw->self, NULL);
	pxw->sid = 0;
}

bool_t _widget_set_subproc_delta(widget_t wt, uid_t sid, vword_t delta)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	if_subproc_t* psub;

	if(pxw->sid != sid) return 0;

	psub = GETXDUSUBPROC(pxw->self);
	if(!psub) return 0;
	
	psub->delta = delta;

	return 1;
}

vword_t _widget_get_subproc_delta(widget_t wt, uid_t sid)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	if_subproc_t* psub;

	if(pxw->sid != sid) return 0;

	psub = GETXDUSUBPROC(pxw->self);

	return (psub)? psub->delta : 0;
}

bool_t _widget_has_subproc(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	return (GETXDUSUBPROC(pxw->self) == NULL) ? 0 : 1;
}

void _widget_set_core_delta(widget_t wt, vword_t pd)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	SETXDUCOREDELTA(pxw->self, (void*)pd);
}

vword_t _widget_get_core_delta(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	return (vword_t)GETXDUCOREDELTA(pxw->self);
}

void _widget_set_user_delta(widget_t wt, vword_t pd)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	SETXDUUSERDELTA(pxw->self, (void*)pd);
}

vword_t _widget_get_user_delta(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	return (vword_t)GETXDUUSERDELTA(pxw->self);
}

void _widget_set_style(widget_t wt, dword_t ws)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	pxw->style = ws;
}

dword_t _widget_get_style(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	return (pxw)? pxw->style : 0;
}

void _widget_set_accel(widget_t wt, const accel_table_t* pacl, int n)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	accel_table_t* pa;

	if(pxw->acl) xmem_free(pxw->acl);

	pa = (accel_table_t*)xmem_alloc((n + 1) * sizeof(accel_table_t));
	xmem_copy((void*)pa, (void*)pacl, n * sizeof(accel_table_t));

	pa[n].vir = 0, pa[n].key = 0, pa[n].cmd = 0;
	pxw->acl = pa;
}

void _widget_set_owner(widget_t wt, widget_t owner)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	X11_widget_t* pxw_owner = TypePtrFromHead(X11_widget_t, owner);

	pxw->owner = (owner)? pxw_owner->self : NULL;
}

widget_t _widget_get_owner(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	X11_widget_t* pxw_owner;

	if(!pxw->owner) return NULL;

	pxw_owner = GETXDUSTRUCT(pxw->owner);
	return (pxw_owner)? (widget_t)&(pxw_owner->head) : (widget_t)0;
}

void _widget_set_user_id(widget_t wt, uid_t uid)
{
    X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	pxw->uid = uid;
}

uid_t _widget_get_user_id(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

    return (pxw)? pxw->uid : 0;
}

void _widget_set_user_result(widget_t wt, int rt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	pxw->result = rt;
}

int _widget_get_user_result(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

    return (pxw)? pxw->result : 0;
}

widget_t _widget_get_child(widget_t wt, uid_t uid)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
    unsigned int i, n;
    Window Root, Parent, child;
    Window* Children = NULL;

    if(XQueryTree(g_display, pxw->self, &Root, &Parent, &Children, &n) != True)
        return NULL;

	pxw = NULL;
    for(i=0;i<n;i++)
    {
        child = Children[i];
        pxw = GETXDUSTRUCT(child);

        if(pxw && pxw->uid == uid)
            break;
    }

	if(Children) XFree(Children);
    
    return (pxw)? (widget_t)&(pxw->head) : NULL;
}

widget_t _widget_get_parent(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	X11_widget_t* pxw_parent;

	if(!pxw->parent) return NULL;

	pxw_parent = GETXDUSTRUCT(pxw->parent);
	return (pxw_parent)? (widget_t)&(pxw_parent->head) : (widget_t)0;
}

void _widget_set_user_prop(widget_t wt, const tchar_t* pname,vword_t val)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
    unsigned char bys[VOID_SIZE] = {0};
    Atom ua;

    PUT_VOID_NET(bys, 0, val);
    
	ua = XInternAtom (g_display, pname, False);

    _WindowSetProper(pxw->self, ua, bys, VOID_SIZE);
}

vword_t _widget_get_user_prop(widget_t wt, const tchar_t* pname)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
    unsigned char bys[VOID_SIZE] = {0};
    Atom ua;

	ua = XInternAtom (g_display, pname, False);
    _WindowGetProper(pxw->self, ua, bys, VOID_SIZE);
    
    return (vword_t)GET_VOID_NET(bys, 0);
}

vword_t _widget_del_user_prop(widget_t wt, const tchar_t* pname)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
    vword_t rt;
    Atom ua;

    rt = _widget_get_user_prop(pxw->self, pname);
	ua = XInternAtom (g_display, pname, False);
    _WindowDelProper(pxw->self, ua);
    
    return rt;
}

const if_dispatch_t* _widget_get_dispatch(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	return GETXDUDISPATCH(pxw->self);
}

void _widget_get_menu_rect(widget_t wt, xrect_t* pxr)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	dword_t ws;

	ws = _widget_get_style(wt);
	if (ws & WD_STYLE_OWNERNC)
	{
		_widget_get_window_rect(wt, pxr);

		pxr->x += pxw->bd.edge;
		pxr->w -= (2 * pxw->bd.edge);
		pxr->y += (pxw->bd.edge + pxw->bd.title);
		pxr->h = pxw->bd.menu;
	}
}

void _widget_get_border(widget_t wt, border_t* pbd)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	xmem_copy((void*)pbd, (void*)(&pxw->bd), sizeof(border_t));
}

bool_t _widget_is_maximized(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	return (pxw->state == WS_SHOW_MAXIMIZE)? 1 : 0;
}

bool_t _widget_is_minimized(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	return (pxw->state == WS_SHOW_MINIMIZE)? 1 : 0;
}

bool_t _widget_enum_child(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	widget_t widget;
	unsigned int i, n;
    Window Root, Parent, child;
    Window* Children = NULL;

    if(XQueryTree(g_display, pxw->self, &Root, &Parent, &Children, &n) != True)
        return 0;

    for(i=0;i<n;i++)
    {
        child = Children[i];
        pxw = GETXDUSTRUCT(child);
		widget = (pxw)? &(pxw->head) : NULL;

        if(widget && (*pf)(widget, pv))
            break;
    }

	if(Children) XFree(Children);
    
    return 1;
}

visual_t _widget_client_ctx(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	visual_t rdc;

	rdc = _create_display_context(wt);

	return rdc;
}

visual_t _widget_window_ctx(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	visual_t rdc;

	rdc = _create_display_context(wt);

	return rdc;
}

void _widget_release_ctx(widget_t wt, visual_t dc)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	_destroy_context(dc);
}

void _widget_get_client_rect(widget_t wt, xrect_t* prt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XWindowAttributes attr = {0};
	border_t bd = {0};

	XGetWindowAttributes(g_display, pxw->self, &attr);
	_widget_get_border(wt, &bd);

	prt->x = 0;
	prt->y = 0;
	prt->w = attr.width - 2 * bd.edge - bd.vscroll;
	prt->h = attr.height - 2 * bd.edge - bd.title - bd.menu - bd.hscroll;
}

void _widget_get_window_rect(widget_t wt, xrect_t* prt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XWindowAttributes attr = {0};
	int dst_x = 0, dst_y = 0;
	Window rot = 0, cld = 0;

	XGetWindowAttributes(g_display, pxw->self, &attr);

	rot = RootWindow(g_display, DefaultScreen(g_display));

	XTranslateCoordinates(g_display, pxw->self, rot, attr.x, attr.y, &dst_x, &dst_y, &cld);

	prt->x = dst_x - attr.border_width;
	prt->y = dst_y - attr.border_width;
	prt->w = attr.width + 2 * attr.border_width;
	prt->h = attr.height + 2 * attr.border_width;
}

void _widget_client_to_screen(widget_t wt, xpoint_t* ppt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	Window rot = 0, cld = 0;
	int dst_x = 0, dst_y = 0;

	rot = RootWindow(g_display, DefaultScreen(g_display));

	XTranslateCoordinates(g_display, pxw->self, rot, ppt->x, ppt->y, &dst_x, &dst_y, &cld);

	ppt->x = dst_x;
	ppt->y = dst_y;
}

void _widget_screen_to_client(widget_t wt, xpoint_t* ppt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	Window rot = 0, cld = 0;
	int dst_x = 0, dst_y = 0;

	rot = RootWindow(g_display, DefaultScreen(g_display));

	XTranslateCoordinates(g_display, rot, pxw->self, ppt->x, ppt->y, &dst_x, &dst_y, &cld);

	ppt->x = dst_x;
	ppt->y = dst_y;
}

void _widget_client_to_window(widget_t wt, xpoint_t* ppt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	border_t bd = {0};

	_widget_get_border(wt, &bd);

	ppt->x += bd.edge;
	ppt->y += (bd.edge + bd.title + bd.menu);
}

void _widget_window_to_client(widget_t wt, xpoint_t* ppt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	border_t bd = {0};

	_widget_get_border(wt, &bd);

	ppt->x -= bd.edge;
	ppt->y -= (bd.edge + bd.title + bd.menu);
}

void _widget_center_window(widget_t wt, widget_t owner)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
    
    XWindowAttributes attr = {0};
    xrect_t owner_rect = {0};
    xpoint_t center_pos = {0};
    
    XGetWindowAttributes(g_display, pxw->self, &attr);
    
    if (owner)
    {
        _widget_get_window_rect(owner, &owner_rect);
    }
    else
    {
		owner_rect.x = 0;
		owner_rect.y = 0;
        owner_rect.w = DisplayWidth(g_display, DefaultScreen(g_display));
        owner_rect.h = DisplayHeight(g_display, DefaultScreen(g_display));
    }
       
	center_pos.x = owner_rect.x + (owner_rect.w - attr.width) / 2;
	center_pos.y = owner_rect.y + (owner_rect.h - attr.height) / 2;

    if (center_pos.x < 0) center_pos.x = 0;
    if (center_pos.y < 0) center_pos.y = 0;
    
    XMoveWindow(g_display, pxw->self, center_pos.x, center_pos.y);
    XFlush(g_display);
}

void _widget_set_cursor(widget_t wt, int ci)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	XUndefineCursor(g_display, pxw->self);

	if(pxw->cur)
	{
		XFreeCursor(g_display, pxw->cur);
		pxw->cur = 0;
	}

	switch (ci)
	{
	case CURSOR_SIZENS:
		pxw->cur = XCreateFontCursor(g_display, XC_sb_v_double_arrow);
		break;
	case CURSOR_SIZEWE:
		pxw->cur = XCreateFontCursor(g_display, XC_sb_h_double_arrow);
		break;
	case CURSOR_SIZEALL:
		pxw->cur = XCreateFontCursor(g_display, XC_sizing);
		break;
	case CURSOR_HAND:
		pxw->cur = XCreateFontCursor(g_display, XC_hand1);
		break;
	case CURSOR_HELP:
		pxw->cur = XCreateFontCursor(g_display, XC_question_arrow);
		break;
	case CURSOR_DRAG:
		pxw->cur = XCreateFontCursor(g_display, XC_draped_box);
		break;
	case CURSOR_ARROW:
		pxw->cur = XCreateFontCursor(g_display, XC_arrow);
		break;
	case CURSOR_IBEAM:
		pxw->cur = XCreateFontCursor(g_display, XC_xterm);
		break;
	default:
		break;
	}

	if(pxw->cur)
	{
		XDefineCursor(g_display, pxw->self, pxw->cur);
	}
}

void _widget_set_capture(widget_t wt, bool_t b)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	if(b)
	{
		XGrabPointer(g_display, pxw->self, 0, 
			ButtonPressMask | ButtonReleaseMask | PointerMotionMask | FocusChangeMask | EnterWindowMask | LeaveWindowMask,
			GrabModeAsync,GrabModeAsync, None, None, CurrentTime);
	}else 
	{
		XUngrabPointer(g_display, CurrentTime);
	}
}

static void _widget_timer_proc(void* pa, res_timer_t rt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, (widget_t)pa);

	if_dispatch_t* pv = GETXDUDISPATCH(pxw->self);

	if(pv && pv->pf_on_timer)
	{
		(*pv->pf_on_timer)((widget_t)&(pxw->head), (vword_t)rt);
	}
}

vword_t _widget_set_timer(widget_t wt, int ms)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	res_timer_t rt;

	if(!g_queue) return (vword_t)0;

	rt = create_timer(g_queue, 500, ms, (PF_TIMERFUNC)_widget_timer_proc, (void*)wt);

    return (vword_t)rt;
}

void _widget_kill_timer(widget_t wt, vword_t tid)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	res_timer_t rt = (res_timer_t)tid;

	if(!g_queue) return;

	destroy_timer(g_queue, rt);
}

static void _widget_caret_proc(void* pa, res_timer_t rt)
{
	widget_t wt = (widget_t)(pa);

	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	if_dispatch_t* pv = GETXDUDISPATCH(pxw->self);

	int screen;
	GC gc;
	Colormap map;
	XColor clr;

	if(!pxw->car.blink) return;

	if(pxw->tog)
	{
		XClearArea(g_display, pxw->self, pxw->car.x, pxw->car.y, pxw->car.w, pxw->car.h, True);
	}
	else
	{
		screen = DefaultScreen(g_display);
		map = DefaultColormap(g_display, screen);
		gc = XCreateGC(g_display, pxw->self, 0, NULL);
	
		clr.red = XRGB(pxw->frg.r);
		clr.green = XRGB(pxw->frg.g);
		clr.blue = XRGB(pxw->frg.b);
		XAllocColor(g_display, map, &clr);
		XSetForeground(g_display, gc, clr.pixel);

		XFillRectangle(g_display, pxw->self, gc, pxw->car.x, pxw->car.y, pxw->car.w, pxw->car.h);

		XFreeColors(g_display, map, &(clr.pixel), 1, 0);

		XFreeGC(g_display, gc);
	}

	pxw->tog = (pxw->tog)? 0 : 1;
}

void _widget_create_caret(widget_t wt, int w, int h)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	if(pxw->ctt) return;

	pxw->car.x = 0;
	pxw->car.y = 0;
	pxw->car.w = w;
	pxw->car.h = h;
	pxw->car.blink = DEFAULT_CARET_BLINK;

	pxw->ctt = create_timer(g_queue, 500, pxw->car.blink, (PF_TIMERFUNC)_widget_caret_proc, (void*)wt);
}

void _widget_destroy_caret(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	pxw->car.blink = 0;

	if(pxw->ctt)
	{
		destroy_timer(g_queue, pxw->ctt);
		pxw->ctt = 0;
	}
}

void _widget_show_caret(widget_t wt, int x, int y)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	XClearArea(g_display, pxw->self, pxw->car.x, pxw->car.y, pxw->car.w, pxw->car.h, True);

	pxw->car.x = x;
	pxw->car.y = y;
	pxw->car.blink = DEFAULT_CARET_BLINK;
}

void _widget_set_focus(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	Window org = 0;
	int rev = 0;

	if(pxw->style & WD_STYLE_NOACTIVE) return;

	XGetInputFocus(g_display, &org, &rev);
	if(org == pxw->self) return;
	
	XSetInputFocus(g_display, pxw->self, RevertToParent, CurrentTime);
}

bool_t _widget_key_state(widget_t wt, int ks)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	switch (ks)
	{
	case KS_WITH_SHIFT:
		if(pxw->mask & ShiftMask) return 1;
		break;
	case KS_WITH_CONTROL:
		if(pxw->mask & ControlMask) return 1;
		break;
	case KS_WITH_ALT:
		if(pxw->mask & Mod1Mask) return 1;
		break;
	}

	return 0;
}

bool_t _widget_is_valid(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	if(!wt) return 0;
	if(!pxw->self) return 0;
	if(GETXDUSTRUCT(pxw->self) == NULL) return 0;

	return 1;
}

bool_t _widget_is_focus(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	Window fw = 0;
	int r = 0;

	XGetInputFocus(g_display, &fw, &r);

	return (pxw->self == fw)? 1 : 0;
}

bool_t _widget_is_child(widget_t wt)
{
    X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	return (pxw->style & WD_STYLE_CHILD)? 1 : 0;
}

bool_t _widget_is_ownc(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	return (pxw->style & WD_STYLE_OWNERNC) ? 1 : 0;
}

void _widget_move(widget_t wt, const xpoint_t* ppt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	XMoveWindow(g_display, pxw->self, ppt->x, ppt->y);

	XFlush(g_display);
}

void _widget_size(widget_t wt, const xsize_t* pxs)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	XResizeWindow(g_display, pxw->self, pxs->w, pxs->h);
}

void _widget_take(widget_t wt, int zor)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XWindowChanges wc = {0};

	switch(zor)
	{
	case WS_TAKE_TOP:
		wc.stack_mode = Above;
		break;
	case WS_TAKE_BOTTOM:
		wc.stack_mode = Below;
		break;
	case WS_TAKE_TOPMOST:
		wc.stack_mode = TopIf;
		break;
	case WS_TAKE_NOTOPMOST:
		wc.stack_mode = Opposite;
		break;
	}

	XConfigureWindow(g_display, pxw->self, CWStackMode, &wc);
}

void _widget_show(widget_t wt, dword_t sw)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XClientMessageEvent ev = {0};

	switch(sw)
	{
	case WS_SHOW_MINIMIZE:
		XMapWindow(g_display, pxw->self);
		XIconifyWindow(g_display, pxw->self, DefaultScreen(g_display));
		
		pxw->state = WS_SHOW_MINIMIZE;
		break;
	case WS_SHOW_MAXIMIZE:
		XMapWindow(g_display, pxw->self);

		ev.type = ClientMessage;
		ev.serial = 0;
		ev.send_event = 1;
		ev.display = g_display;
		ev.window = pxw->self;
		ev.message_type = g_atoms.net_wm_state;
		ev.format = 32;
		ev.data.l[0] = 1;
		ev.data.l[1] = g_atoms.net_wm_state_maximized_vert;
		ev.data.l[2] = g_atoms.net_wm_state_maximized_horz;
		ev.data.l[3] = 1;

		XSendEvent(g_display, RootWindow(g_display, DefaultScreen(g_display)), False, SubstructureRedirectMask | SubstructureNotifyMask, &ev);

		pxw->state = WS_SHOW_MAXIMIZE;
		break;
	case WS_SHOW_HIDE:
		XWithdrawWindow(g_display, pxw->self, DefaultScreen(g_display));

		pxw->state = WS_SHOW_HIDE;
		break;
	default:
		XMapWindow(g_display, pxw->self);

		pxw->state = WS_SHOW_NORMAL;
		break;
	}
}

void _widget_paint(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	XClearWindow(g_display, pxw->self);
    XFlush(g_display);
}

void _widget_layout(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	if_dispatch_t* pif;
	xsize_t st;

	pif = GETXDUDISPATCH(pxw->self);

	if(pif && pif->pf_on_size)
	{
		st.w = pxw->st.w;
		st.h = pxw->st.h;
		(*pif->pf_on_size)(wt, WS_SIZE_RESTORE, &st);
	}

	XClearWindow(g_display, pxw->self);
    XFlush(g_display);
}

void _widget_erase(widget_t wt, const xrect_t* prt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	if(!prt)
		XClearArea(g_display, pxw->self, 0, 0, 0, 0, True);
	else
		XClearArea(g_display, pxw->self, prt->x, prt->y, prt->w, prt->h, True);
}

void _widget_enable(widget_t wt, bool_t b)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	pxw->disable = (b)? 0 : 1;
}

void _widget_post_notice(widget_t wt, NOTICE* pnt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XClientMessageEvent ev = {0};

    ev.type = ClientMessage;
	ev.serial = 0;
	ev.send_event = 1;
	ev.display = g_display;
    ev.window = pxw->self;
    ev.message_type = g_atoms.wm_notice;
    ev.format = 32;
    ev.data.l[0] = pnt->user;
    ev.data.l[1] = pnt->code;
    ev.data.l[2] = (long)pnt;
	ev.data.l[3] = ev.data.l[4] = 0;
    
    XSendEvent (g_display, pxw->self, False, SubstructureNotifyMask, (XEvent*)&ev);
}

int _widget_send_notice(widget_t wt, NOTICE* pnt)
{
    X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	if_dispatch_t* pif;

	pif = GETXDUDISPATCH(pxw->self);

	if(pif && pif->pf_on_notice)
	{
		(*pif->pf_on_notice)(wt, pnt);

		return 1;
	}

	return 0;
}

void _widget_post_command(widget_t wt, int code, uid_t cid, vword_t data)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XClientMessageEvent ev = {0};

    ev.type = ClientMessage;
	ev.serial = 0;
	ev.send_event = 1;
	ev.display = g_display;
    ev.window = pxw->self;
    ev.message_type = g_atoms.wm_command;
    ev.format = 32;
    ev.data.l[0] = cid;
    ev.data.l[1] = code;
    ev.data.l[2] = data;
	ev.data.l[3] = ev.data.l[4] = 0;
    
    XSendEvent (g_display, pxw->self, False, SubstructureNotifyMask, (XEvent*)&ev);
}

int _widget_send_command(widget_t wt, int code, uid_t cid, vword_t data)
{
    X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	if_dispatch_t* pif;

	pif = GETXDUDISPATCH(pxw->self);

	switch(cid)
	{
	case IDC_PARENT:
		if(pif && pif->pf_on_parent_command)
		{
			(*pif->pf_on_parent_command)(wt, code, data);
			return 1;
		}
		break;
	case IDC_CHILD:
		if(pif && pif->pf_on_child_command)
		{
			(*pif->pf_on_child_command)(wt, code, data);
			return 1;
		}
		break;
	case IDC_SELF:
		if(pif && pif->pf_on_self_command)
		{
			(*pif->pf_on_self_command)(wt, code, data);
			return 1;
		}
		break;
	default:
		if(pif && pif->pf_on_menu_command)
		{
			(*pif->pf_on_menu_command)(wt, code, cid, data);
			return 1;
		}
		break;
	}

	return 0;
}

void _widget_post_wchar(widget_t wt, wchar_t ch)
{
	X11_widget_t* pxw = (wt)? TypePtrFromHead(X11_widget_t, wt) : NULL;

	XClientMessageEvent ev = {0};
	Window fw = 0;
	int fs = 0;
	
	if(!pxw)
	{
		XGetInputFocus(g_display, &fw, &fs);
		if(!fw) return;

		pxw = GETXDUSTRUCT(fw);
	}

	ev.type = ClientMessage;
	ev.serial = 0;
	ev.send_event = 1;
	ev.display = g_display;
	ev.window = pxw->self;
	ev.message_type = g_atoms.wm_wchar;
	ev.format = 32;
	ev.data.l[0] = (long)ch;

	XSendEvent(g_display, pxw->self, False, SubstructureNotifyMask, (XEvent *)&ev);
}

void _widget_post_key(widget_t wt, int key)
{
	X11_widget_t* pxw = (wt)? TypePtrFromHead(X11_widget_t, wt) : NULL;

	XKeyEvent ev = {0};
	Window fw = 0;
	int fs = 0;

	if(!pxw)
	{
		XGetInputFocus(g_display, &fw, &fs);
		if(!fw) return;

		pxw = GETXDUSTRUCT(fw);
	}

    ev.type = KeyPress;
	ev.serial = 0;
	ev.send_event = 1;
	ev.display = g_display;
    ev.window = pxw->self;
    ev.root = DefaultRootWindow(g_display);
	ev.subwindow = 0;
    ev.time = CurrentTime;
    ev.x = 0;
    ev.y = 0;
    ev.x_root = 0;
	ev.y_root = 0;
	ev.state = 0;
	ev.keycode = XKeysymToKeycode(g_display, key);
	ev.same_screen = 1;
    
    XSendEvent (g_display, pxw->self, False, NoEventMask, (XEvent*)&ev);

	ev.type = KeyRelease;
	ev.serial = 0;
	ev.send_event = 1;
	ev.display = g_display;
    ev.window = pxw->self;
    ev.root = DefaultRootWindow(g_display);
	ev.subwindow = 0;
    ev.time = CurrentTime;
    ev.x = 0;
    ev.y = 0;
    ev.x_root = 0;
	ev.y_root = 0;
	ev.state = 0;
	ev.keycode = XKeysymToKeycode(g_display, key);
	ev.same_screen = 1;

	XSendEvent (g_display, pxw->self, False, NoEventMask, (XEvent*)&ev);
}

void _widget_set_title(widget_t wt, const tchar_t* token)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	XWithdrawWindow(g_display, pxw->self, DefaultScreen(g_display));
	XStoreName(g_display, pxw->self, token);
	XMapWindow(g_display, pxw->self);
}

int _widget_get_title(widget_t wt, tchar_t* buf, int max)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XTextProperty tps = {0};
	int len;

	XGetWMName(g_display, pxw->self, &tps);
	len = strlen(tps.value);
	len = (len < max)? len : max;

	if(buf)
	{
		strncpy(buf, tps.value, len);
	}

	return len;
}

void _widget_active(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XClientMessageEvent ev = {0};

    ev.type = ClientMessage;
	ev.serial = 0;
	ev.send_event = 1;
	ev.display = g_display;
    ev.window = pxw->self;
    ev.message_type = g_atoms.net_active_window;
    ev.format = 32;
    ev.data.l[0] = 1;
    ev.data.l[1] = CurrentTime;
    ev.data.l[2] = 0;
	ev.data.l[3] = 0;
	ev.data.l[4] = 0;
    
    XSendEvent (g_display, pxw->self, False, SubstructureNotifyMask, (XEvent*)&ev);
}

void _widget_scroll(widget_t wt, bool_t horz, int line)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XClientMessageEvent ev = {0};

    ev.type = ClientMessage;
	ev.serial = 0;
	ev.send_event = 1;
	ev.display = g_display;
    ev.window = pxw->self;
    ev.message_type = g_atoms.wm_scroll;
    ev.format = 32;
    ev.data.l[0] = (horz)? 1 : 0;
    ev.data.l[1] = line;
    ev.data.l[2] = 0;
	ev.data.l[3] = 0;
	ev.data.l[4] = 0;
    
    XSendEvent (g_display, pxw->self, False, SubstructureNotifyMask, (XEvent*)&ev);
}

void _widget_get_scroll_info(widget_t wt, bool_t horz, scroll_t* psl)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	if(horz)
		xmem_copy((void*)psl, (void*)&(pxw->hs), sizeof(scroll_t));
	else
		xmem_copy((void*)psl, (void*)&(pxw->vs), sizeof(scroll_t));
}

static int CALLBACK _update_horz_position(widget_t wt, vword_t b)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XWindowAttributes attr = {0};
	int dst_x = 0, dst_y = 0;

	XGetWindowAttributes(g_display, pxw->self, &attr);

	dst_x = attr.x + *(int*)b;
	dst_y = attr.y;
	XMoveWindow(g_display, pxw->self, dst_x, dst_y);

	return (0);
}

static int CALLBACK _update_vert_position(widget_t wt, vword_t b)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XWindowAttributes attr = {0};
	int dst_x = 0, dst_y = 0;

	XGetWindowAttributes(g_display, pxw->self, &attr);

	dst_x = attr.x;
	dst_y = attr.y + *(int*)b;
	XMoveWindow(g_display, pxw->self, dst_x, dst_y);

	return (0);
}

void _widget_set_scroll_info(widget_t wt, bool_t horz, const scroll_t* psl)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	int b;

	if(horz)
	{
		b = (psl->pos - pxw->hs.pos);
		xmem_copy((void*)&(pxw->hs), (void*)psl, sizeof(scroll_t));

		if(!b) return;

		_widget_enum_child(wt, (PF_ENUM_WINDOW_PROC)_update_horz_position, (vword_t)&b);
	}
	else
	{
		b = (psl->pos - pxw->vs.pos);
		xmem_copy((void*)&(pxw->vs), (void*)psl, sizeof(scroll_t));

		if(!b) return;

		_widget_enum_child(wt, (PF_ENUM_WINDOW_PROC)_update_vert_position, (vword_t)&b);
	}

	XFlush(g_display);
}

void _widget_set_point(widget_t wt, const xpoint_t* ppt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	xmem_copy((void*)&pxw->pt, (void*)ppt, sizeof(xpoint_t));
}

void _widget_get_point(widget_t wt, xpoint_t* ppt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	xmem_copy((void*)ppt, (void*)&pxw->pt, sizeof(xpoint_t));
}

void _widget_set_size(widget_t wt, const xsize_t* pst)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	xmem_copy((void*)&pxw->st, (void*)pst, sizeof(xsize_t));
}

void _widget_get_size(widget_t wt, xsize_t* pst)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	xmem_copy((void*)pst, (void*)&pxw->st, sizeof(xsize_t));
}

static int CALLBACK _widget_set_child_color_mode(widget_t wt, vword_t pv)
{
	dword_t dw = _widget_get_style(wt);
	
	if (dw & WD_STYLE_NOCHANGE) return 1;

	_widget_set_color_mode(wt, (const color_mod_t*)pv);

	return 1;
}

void _widget_set_color_mode(widget_t wt, const color_mod_t* pclr)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	XSetWindowAttributes attr = {0};
	XColor frg = {0}, bkg = {0};
	Colormap map;

	if (!(pxw->style & WD_STYLE_NOCHANGE))
	{
		xmem_copy((void*)&pxw->bkg, (void*)&pclr->clr_bkg, sizeof(xcolor_t));
		xmem_copy((void*)&pxw->frg, (void*)&pclr->clr_frg, sizeof(xcolor_t));
		xmem_copy((void*)&pxw->txt, (void*)&pclr->clr_txt, sizeof(xcolor_t));
		xmem_copy((void*)&pxw->msk, (void*)&pclr->clr_msk, sizeof(xcolor_t));
		xmem_copy((void*)&pxw->ico, (void*)&pclr->clr_ico, sizeof(xcolor_t));

		map = DefaultColormap(g_display, DefaultScreen(g_display));
		frg.red = XRGB(pclr->clr_frg.r);
		frg.green = XRGB(pclr->clr_frg.g);
		frg.blue = XRGB(pclr->clr_frg.b);
		XAllocColor(g_display, map, &frg);

		bkg.red = XRGB(pclr->clr_bkg.r);
		bkg.green = XRGB(pclr->clr_bkg.g);
		bkg.blue = XRGB(pclr->clr_bkg.b);
		XAllocColor(g_display, map, &bkg);

		attr.border_pixel = frg.pixel;
		attr.background_pixel = bkg.pixel;

		XChangeWindowAttributes(g_display, pxw->self, CWBorderPixel | CWBackPixel, &attr);

		XFreeColors(g_display, map, &(frg.pixel), 1, 0);
		XFreeColors(g_display, map, &(bkg.pixel), 1, 0);

		_widget_send_command(wt, COMMAND_COLOR, IDC_SELF, (vword_t)pclr);
	}

	_widget_enum_child(wt, _widget_set_child_color_mode, (vword_t)pclr);
}

void _widget_get_color_mode(widget_t wt, color_mod_t* pclr)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	xmem_copy((void*)&pclr->clr_bkg, (void*)&pxw->bkg, sizeof(xcolor_t));
	xmem_copy((void*)&pclr->clr_frg, (void*)&pxw->frg, sizeof(xcolor_t));
	xmem_copy((void*)&pclr->clr_txt, (void*)&pxw->txt, sizeof(xcolor_t));
	xmem_copy((void*)&pclr->clr_msk, (void*)&pxw->msk, sizeof(xcolor_t));
	xmem_copy((void*)&pclr->clr_ico, (void*)&pxw->ico, sizeof(xcolor_t));
}

void _widget_set_diaph(widget_t wt, float f)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	Atom opacity_atom;
    unsigned long opacity;
    
	pxw->diaph = f;
	opacity = (unsigned long)(f * 255);

    opacity_atom = XInternAtom(g_display, "_NET_WM_WINDOW_OPACITY", False);
    
    if ((int)f == 1)
    {
        XDeleteProperty(g_display, pxw->self, opacity_atom);
    }
    else
    {
        opacity = ((unsigned long)opacity << 24) | 0x00FFFFFF;
        XChangeProperty(g_display, pxw->self, opacity_atom, XA_CARDINAL, 32,
                       PropModeReplace, (unsigned char*)&opacity, 1);
    }
    
    XFlush(g_display);
}

float _widget_get_diaph(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);

	return pxw->diaph;
}

void _widget_noti_xfont(widget_t wt, const xfont_t* pxf)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	if_dispatch_t* pif = GETXDUDISPATCH(pxw->self);

	if(pif && pif->pf_on_xfont)
	{
		(*pif->pf_on_xfont)(wt, pxf);
	}
}

void _widget_noti_xface(widget_t wt, const xface_t* pxa)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	if_dispatch_t* pif = GETXDUDISPATCH(pxw->self);

	if(pif && pif->pf_on_xface)
	{
		(*pif->pf_on_xface)(wt, pxa);
	}
}

void _widget_noti_xbrush(widget_t wt, const xbrush_t* pxb)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	if_dispatch_t* pif = GETXDUDISPATCH(pxw->self);

	if(pif && pif->pf_on_xbrush)
	{
		(*pif->pf_on_xbrush)(wt, pxb);
	}
}

void _widget_noti_xpen(widget_t wt, const xpen_t* pxp)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	if_dispatch_t* pif = GETXDUDISPATCH(pxw->self);

	if(pif && pif->pf_on_xpen)
	{
		(*pif->pf_on_xpen)(wt, pxp);
	}
}

int	_widget_do_main(widget_t wt)
{
	XEvent msg = {0};
    
	while(_widget_is_valid(wt))
    {
		while (XPending(g_display))
		{
			//_widget_idle(wt, bool_false);

			_message_fetch(&msg, (widget_t)0);

			if (XFilterEvent(&msg, None))
				continue;

			if (_message_translate(&msg))
				continue;

			_message_dispatch(&msg);
		}

		//_widget_idle(wt, bool_true);
		usleep(1000);
    }

	return 0;
}

int	_widget_do_modal(widget_t wt)
{
	X11_widget_t* pxw = TypePtrFromHead(X11_widget_t, wt);
	Window own;
	widget_t wp;
	XEvent msg = {0};
    
	wp = _widget_get_owner(wt);
	if(wp) 
	{
		own = ((X11_widget_t*)TypePtrFromHead(X11_widget_t, wp))->self;
		_widget_enable(wp, 0);
	}else{
		own = RootWindow(g_display, DefaultScreen(g_display));
	}

	XSetTransientForHint(g_display, pxw->self, own);

	_widget_set_focus(wt);

	while(_widget_is_valid(wt))
    {
		while (XPending(g_display))
		{
			//_widget_idle(wt, bool_false);

			_message_fetch(&msg, (widget_t)0);

			if (_message_translate(&msg))
				continue;

			_message_dispatch(&msg);
		}

		//_widget_idle(wt, bool_true);
		usleep(1000);
    }

	if(wp)
	{
		_widget_enable(wp, 1);
		_widget_set_focus(wp);
	}

	return 0;
}

void _widget_do_track(widget_t wt)
{
	XEvent msg = {0};
    
	XSync(g_display, True);

	_widget_set_capture(wt, 1);

	while(_widget_is_valid(wt))
    {
		_message_fetch(&msg, (widget_t)0);
		
		_message_dispatch(&msg);
    }

	_widget_set_capture(wt, 0);
}

void _message_quit(int code)
{
	XClientMessageEvent ev = {0};

    ev.type = ClientMessage;
	ev.serial = 0;
	ev.send_event = 1;
	ev.display = g_display;
    ev.window = DefaultRootWindow(g_display);
    ev.message_type = g_atoms.wm_quit;
    ev.format = 32;
    ev.data.l[0] = code;
    ev.data.l[1] = CurrentTime;
    ev.data.l[2] = 0;
	ev.data.l[3] = 0;
	ev.data.l[4] = 0;
    
    XSendEvent (g_display, DefaultRootWindow(g_display), False, SubstructureNotifyMask, (XEvent*)&ev);
}

void _message_position(xpoint_t* pxp)
{
    Window root, child;
    int root_x, root_y, win_x, win_y;
    unsigned int mask;
    
    if (XQueryPointer(g_display, DefaultRootWindow(g_display), 
                      &root, &child, &root_x, &root_y, 
                      &win_x, &win_y, &mask))
    {
        pxp->x = root_x;
        pxp->y = root_y;
    }
    else
    {
        pxp->x = 0;
        pxp->y = 0;
    }
}
/*********************************************************************************************************/
void _adjust_widget_size(dword_t ws, xsize_t* pxs)
{
	if(ws & WD_STYLE_CHILD) return;

	if(ws & WD_STYLE_TITLE)
	{
		pxs->h += (int)((WIDGET_TITLE_SPAN +  WIDGET_FRAME_EDGE) * PTPERMM);
		pxs->w += (int)(WIDGET_FRAME_EDGE * 2 * PTPERMM);
	}else
	{
		pxs->h += (int)(WIDGET_CHILD_EDGE * 2 * PTPERMM);
		pxs->w += (int)(WIDGET_CHILD_EDGE * 2 * PTPERMM);
	}
}

void _calc_widget_border(dword_t ws, border_t* pbd)
{
	NOP;
}

void _get_screen_size(xsize_t* pxs)
{
	pxs->w = DisplayWidth(g_display, DefaultScreen(g_display));
    pxs->h = DisplayHeight(g_display, DefaultScreen(g_display));
}

void _get_desktop_size(xsize_t* pxs)
{
	pxs->w = DisplayWidth(g_display, DefaultScreen(g_display));
    pxs->h = DisplayHeight(g_display, DefaultScreen(g_display));
}

void _screen_size_to_mm(xsize_t* pxs)
{
	double dx, dy;

	dx = (double)DisplayWidthMM(g_display, DefaultScreen(g_display)) / (double)DisplayWidth(g_display, DefaultScreen(g_display));
	dy = (double)DisplayHeightMM(g_display, DefaultScreen(g_display)) / (double)DisplayHeight(g_display, DefaultScreen(g_display));

	pxs->fw = (float)((double)pxs->w * dx);
	pxs->fh = (float)((double)pxs->h * dy);
}

void _screen_size_to_pt(xsize_t* pxs)
{
	double dx, dy;

	dx = (double)DisplayWidth(g_display, DefaultScreen(g_display)) / (double)DisplayWidthMM(g_display, DefaultScreen(g_display));
	dy = (double)DisplayHeight(g_display, DefaultScreen(g_display)) / (double)DisplayHeightMM(g_display, DefaultScreen(g_display));

	pxs->w = (int)((double)pxs->fw * dx);
	pxs->h = (int)((double)pxs->fh * dy);
}

#endif //XDU_SUPPORT_WIDGET
