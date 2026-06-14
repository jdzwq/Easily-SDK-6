/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc widget document

	@module	wl_widget.c | wayland implement file

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

#include "_if_wayland.h"
#include "_wayland.h"

#include <linux/input.h>


#define WIDGET_EVENTS   (WAYLAND_EVENT_KEY_DOWN | WAYLAND_EVENT_KEY_UP \
                        | WAYLAND_EVENT_LBUTTON_DOWN | WAYLAND_EVENT_LBUTTON_UP | WAYLAND_EVENT_RBUTTON_DOWN | WAYLAND_EVENT_RBUTTON_UP | WAYLAND_EVENT_MOUSE_WHEEL \
						| WAYLAND_EVENT_MOUSE_ENTER | WAYLAND_EVENT_MOUSE_LEAVE \
						| WAYLAND_EVENT_EXPOSE \
						| WAYLAND_EVENT_SET_FOCUS | WAYLAND_EVENT_KILL_FOCUS \
						| WAYLAND_EVENT_ACTIVATE | WAYLAND_EVENT_SHOW \
						| WAYLAND_EVENT_SIZE \
						| WAYLAND_EVENT_CREATE | WAYLAND_EVENT_DESTROY | WAYLAND_EVENT_CLOSE)
#define WIDGET_CHILD_EVENTS (WAYLAND_EVENT_KEY_DOWN | WAYLAND_EVENT_KEY_UP \
                        | WAYLAND_EVENT_LBUTTON_DOWN | WAYLAND_EVENT_LBUTTON_UP | WAYLAND_EVENT_RBUTTON_DOWN | WAYLAND_EVENT_RBUTTON_UP | WAYLAND_EVENT_MOUSE_WHEEL \
						| WAYLAND_EVENT_MOUSE_ENTER | WAYLAND_EVENT_MOUSE_LEAVE \
						| WAYLAND_EVENT_EXPOSE \
						| WAYLAND_EVENT_SET_FOCUS | WAYLAND_EVENT_KILL_FOCUS \
						| WAYLAND_EVENT_ACTIVATE \
						| WAYLAND_EVENT_SIZE \
						| WAYLAND_EVENT_CREATE | WAYLAND_EVENT_DESTROY)
#define WIDGET_POPUP_EVENTS (WAYLAND_EVENT_KEY_DOWN | WAYLAND_EVENT_KEY_UP \
                        | WAYLAND_EVENT_LBUTTON_DOWN | WAYLAND_EVENT_LBUTTON_UP | WAYLAND_EVENT_RBUTTON_DOWN | WAYLAND_EVENT_RBUTTON_UP | WAYLAND_EVENT_MOUSE_WHEEL \
						| WAYLAND_EVENT_MOUSE_ENTER | WAYLAND_EVENT_MOUSE_LEAVE \
						| WAYLAND_EVENT_EXPOSE \
						| WAYLAND_EVENT_SET_FOCUS | WAYLAND_EVENT_KILL_FOCUS \
						| WAYLAND_EVENT_ACTIVATE | WAYLAND_EVENT_SHOW \
						| WAYLAND_EVENT_SIZE \
						| WAYLAND_EVENT_CREATE | WAYLAND_EVENT_DESTROY | WAYLAND_EVENT_CLOSE)				
#define WIDGET_MAIN_EVENTS (WAYLAND_EVENT_KEY_DOWN | WAYLAND_EVENT_KEY_UP \
                        | WAYLAND_EVENT_LBUTTON_DOWN | WAYLAND_EVENT_LBUTTON_UP | WAYLAND_EVENT_RBUTTON_DOWN | WAYLAND_EVENT_RBUTTON_UP | WAYLAND_EVENT_MOUSE_WHEEL \
						| WAYLAND_EVENT_MOUSE_ENTER | WAYLAND_EVENT_MOUSE_LEAVE \
						| WAYLAND_EVENT_EXPOSE \
						| WAYLAND_EVENT_SET_FOCUS | WAYLAND_EVENT_KILL_FOCUS \
						| WAYLAND_EVENT_ACTIVATE | WAYLAND_EVENT_SHOW \
						| WAYLAND_EVENT_SIZE \
						| WAYLAND_EVENT_CREATE | WAYLAND_EVENT_DESTROY | WAYLAND_EVENT_CLOSE)
#define WIDGET_FOCUS_EVENTS (WAYLAND_EVENT_KEY_DOWN | WAYLAND_EVENT_KEY_UP \
						| WAYLAND_EVENT_SET_FOCUS | WAYLAND_EVENT_KILL_FOCUS)


#define WIDGET_BORDER_WIDTH		2 //pt

#define DEFAULT_SCROLL_DELTA	120
#define DEFAULT_CARET_BLINK		500

#define HIWORD(dw)		(unsigned short)(((unsigned int)(dw) >> 16) & 0x0000FFFF)
#define LOWORD(dw)		(unsigned short)((unsigned int)(dw) & 0x0000FFFF)

#define IS_META_KEY(key)	(key == XK_Shift_L || key == XK_Shift_R || key == XK_Control_L || key == XK_Control_R ||key == XK_Caps_Lock || key == XK_Shift_Lock || key == XK_Meta_L || key == XK_Meta_R || key == XK_Alt_L || key == XK_Alt_R || key == XK_Super_L || key == XK_Super_R ||key == XK_Hyper_L || key == XK_Hyper_R)

res_queue_t g_queue = 0;

static int wayland_to_keycode(int xk)
{
    /*switch (xk)
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
    }*/

	return (int)0; 
}

static int keycode_to_wayland(int key)
{
    /*switch (key)
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
    }*/

	return (int)0; 
}

static dword_t _key_state(unsigned int unFlags)
{
    dword_t mask = 0;

    if (unFlags & WAYLAND_STATE_SHIFT)
        mask |= KS_WITH_SHIFT;
    if (unFlags & WAYLAND_STATE_CONTROL)
        mask |= KS_WITH_CONTROL;
    if (unFlags & WAYLAND_STATE_ALT)
        mask |= KS_WITH_ALT;

    return mask;
}

static dword_t _mouse_state(unsigned int nsState)
{
    dword_t mask = 0;

    return mask;
}

static wayland_widget_t* GETXDUSTRUCT(wayland_window* win)
{
    return (wayland_widget_t*)WaylandGetWindowProper(win, WAYLAND_ATOM_STRUCT);
}

static void SETXDUSTRUCT(wayland_window* win, wayland_widget_t* p)
{
    WaylandSetWindowProper(win, WAYLAND_ATOM_STRUCT, (vword_t)p);
}

static if_dispatch_t* GETXDUDISPATCH(wayland_window* win)
{
    return (if_dispatch_t*)WaylandGetWindowProper(win, WAYLAND_ATOM_DISPATCH);
}

static void SETXDUDISPATCH(wayland_window* win, if_dispatch_t* p)
{
    WaylandSetWindowProper(win, WAYLAND_ATOM_DISPATCH, (vword_t)p);
}

static if_subproc_t* GETXDUSUBPROC(wayland_window* win)
{
    return (if_subproc_t*)WaylandGetWindowProper(win, WAYLAND_ATOM_SUBPROC);
}

static void SETXDUSUBPROC(wayland_window* win, if_subproc_t* p)
{
    WaylandSetWindowProper(win, WAYLAND_ATOM_SUBPROC, (vword_t)p);
}

static void* GETXDUCOREDELTA(wayland_window* win)
{
    return (void*)WaylandGetWindowProper(win, WAYLAND_ATOM_COREDELTA);
}

static void SETXDUCOREDELTA(wayland_window* win, void* p)
{
    WaylandSetWindowProper(win, WAYLAND_ATOM_COREDELTA, (vword_t)p);
}

static void* GETXDUUSERDELTA(wayland_window* win)
{
    return (void*)WaylandGetWindowProper(win, WAYLAND_ATOM_USERDELTA);
}

static void SETXDUUSERDELTA(wayland_window* win, void* p)
{
    WaylandSetWindowProper(win, WAYLAND_ATOM_USERDELTA, (vword_t)p);
}

/******************************************************************************************/

void wlWidgetStartup(int ver)
{
	g_queue = create_timer_queue();
}

void wlWidgetCleanup(void)
{
	if(g_queue) destroy_timer_queue(g_queue);
	g_queue = 0;
}

/*******************************************************************************************/

static bool_t _EventTranslate(wayland_window* window, dword_t event_id, dword_t event_code, vword_t event_data)
{
	accel_table_t* pac;
	char keystr[5] = {0};
	unsigned int state = 0;
	int i, keys = 0;
	char ch = 0;
	char* pch = NULL;
	char kch = 0;
	wchar_t wc = 0;

	if(WAYLAND_EVENTMAP(event_id) == WAYLAND_EVENT_KEY_DOWN)
	{
		if(WAYLAND_STATEMAP(event_id) == WAYLAND_STATE_SHIFT) state |= KS_WITH_SHIFT;
		if(WAYLAND_STATEMAP(event_id) == WAYLAND_STATE_CONTROL) state |= KS_WITH_CONTROL;
		if(WAYLAND_STATEMAP(event_id) == WAYLAND_STATE_ALT) state |= KS_WITH_ALT;

		switch(keys)
		{
		case 1:
			ch = keystr[0];
			break;
		case 2:
			ch = keystr[1];
			break;
		case 3:
			ch = keystr[2];
			break;
		default:
			ch = keystr[3];
			break;
		}

		return 1;
	}

    return 0;
}

static int _MessageDispatch(wayland_window* window, dword_t event_id, dword_t event_code, vword_t event_data)
{
	widget_t wt;
	wayland_widget_t* pxw;
	if_dispatch_t* pif;
	if_subproc_t* psub;

	xpoint_t xp;
	xrect_t xr;
	dword_t ks;
	int rev, key;

	switch (WAYLAND_EVENTMAP(event_id))
	{
	case WAYLAND_EVENT_KEY_DOWN:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		key = wayland_to_keycode((int)event_code);

		ks = _key_state(WAYLAND_EVENTMAP(event_id));
		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_keydown)
		{
			pxw->result = (*psub->sub_on_keydown)(wt, ks, (int)(key), psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_keydown)
		{
			(*pif->pf_on_keydown)(wt, ks, (int)(key));
		}
		break;
	case WAYLAND_EVENT_KEY_UP:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		ks = _key_state(WAYLAND_EVENTMAP(event_id));
		key = wayland_to_keycode((int)event_code);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_keyup)
		{
			pxw->result = (*psub->sub_on_keyup)(wt, ks, (int)(key), psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_keyup)
		{
			(*pif->pf_on_keyup)(wt, ks, (int)(key));
		}
		break;
	case WAYLAND_EVENT_LBUTTON_DOWN:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		xp.x = GETVWORDL(event_data);
		xp.y = GETVWORDH(event_data);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_lbutton_down)
		{
			pxw->result = (*psub->sub_on_lbutton_down)(wt, &xp, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_lbutton_down)
		{
			(*pif->pf_on_lbutton_down)(wt, &xp);
		}
		break;
	case WAYLAND_EVENT_LBUTTON_UP:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		xp.x = GETVWORDL(event_data);
		xp.y = GETVWORDH(event_data);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_lbutton_up)
		{
			pxw->result = (*psub->sub_on_lbutton_up)(wt, &xp, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_lbutton_up)
		{
			(*pif->pf_on_lbutton_up)(wt, &xp);
		}
		break;
	case WAYLAND_EVENT_RBUTTON_DOWN:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		xp.x = GETVWORDL(event_data);
		xp.y = GETVWORDH(event_data);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_rbutton_down)
		{
			pxw->result = (*psub->sub_on_rbutton_down)(wt, &xp, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_rbutton_down)
		{
			(*pif->pf_on_rbutton_down)(wt, &xp);
		}
		break;
	case WAYLAND_EVENT_RBUTTON_UP:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		xp.x = GETVWORDL(event_data);
		xp.y = GETVWORDH(event_data);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_rbutton_up)
		{
			pxw->result = (*psub->sub_on_rbutton_up)(wt, &xp, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_rbutton_up)
		{
			(*pif->pf_on_rbutton_up)(wt, &xp);
		}
		break;
	case WAYLAND_EVENT_MOUSE_MOVE:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		xp.x = GETVWORDL(event_data);
		xp.y = GETVWORDH(event_data);

		ks = _mouse_state(GETVWORDL(event_data)) | _key_state(GETVWORDH(event_data));

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_mouse_move)
		{
			pxw->result = (*psub->sub_on_mouse_move)(wt, ks, &xp, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_mouse_move)
		{
			(*pif->pf_on_mouse_move)(wt, ks, &xp);
		}
		break;
	case WAYLAND_EVENT_MOUSE_ENTER:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		xp.x = GETVWORDL(event_data);
		xp.y = GETVWORDH(event_data);

		ks = _mouse_state(GETVWORDL(event_data)) | _key_state(GETVWORDH(event_data));

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_mouse_enter)
		{
			pxw->result = (*psub->sub_on_mouse_enter)(wt, ks, &xp, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_mouse_enter)
		{
			(*pif->pf_on_mouse_enter)(wt, ks, &xp);
		}
		break;
	case WAYLAND_EVENT_MOUSE_LEAVE:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		xp.x = GETVWORDL(event_data);
		xp.y = GETVWORDH(event_data);

		ks = _mouse_state(GETVWORDL(event_data)) | _key_state(GETVWORDH(event_data));

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_mouse_leave)
		{
			pxw->result = (*psub->sub_on_mouse_leave)(wt, ks, &xp, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_mouse_leave)
		{
			(*pif->pf_on_mouse_leave)(wt, ks, &xp);
		}
		break;
	case WAYLAND_EVENT_EXPOSE:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		wt = &(pxw->head);

		xmem_copy((void *)&xr, (void *)event_data, sizeof(xrect_t));

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_paint)
		{
			visual_t rdc = NULL;
			pxw->result = (*psub->sub_on_paint)(wt, rdc, &xr, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_paint)
		{
			visual_t rdc = NULL;;
			(*pif->pf_on_paint)(wt, rdc, &xr);
		}
		break;
	case WAYLAND_EVENT_SET_FOCUS:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_set_focus)
		{
			pxw->result = (*psub->sub_on_set_focus)(wt, NULL, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_set_focus)
		{
			(*pif->pf_on_set_focus)(wt, NULL);
		}
		break;
	case WAYLAND_EVENT_KILL_FOCUS:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_kill_focus)
		{
			pxw->result = (*psub->sub_on_kill_focus)(wt, NULL, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_kill_focus)
		{
			(*pif->pf_on_kill_focus)(wt, NULL);
		}
		break;
	case WAYLAND_EVENT_SIZE:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		wt = &(pxw->head);

		xmem_copy((void *)&xr, (void *)event_data, sizeof(xrect_t));

		if (xr.x != pxw->pt.x || xr.y != pxw->pt.y)
		{
			pxw->pt.x = xr.x;
			pxw->pt.y = xr.y;

			psub = GETXDUSUBPROC(window);
			if (psub && psub->sub_on_move)
			{
				pxw->result = (*psub->sub_on_move)(wt, &(pxw->pt), psub->sid, psub->delta);
				if (pxw->result)
					break;
			}

			pif = GETXDUDISPATCH(window);
			if (pif && pif->pf_on_move)
			{
				(*pif->pf_on_move)(wt, &(pxw->pt));
			}
		}

		if (xr.w != pxw->st.w || xr.h != pxw->st.h)
		{
			pxw->st.w = xr.w;
			pxw->st.h = xr.h;

			psub = GETXDUSUBPROC(window);
			if (psub && psub->sub_on_size)
			{
				pxw->result = (*psub->sub_on_size)(wt, WS_SIZE_RESTORE, &(pxw->st), psub->sid, psub->delta);
				if (pxw->result)
					break;
			}

			pif = GETXDUDISPATCH(window);
			if (pif && pif->pf_on_size)
			{
				(*pif->pf_on_size)(wt, WS_SIZE_RESTORE, &(pxw->st));
			}
		}
		break;
	case WAYLAND_EVENT_SHOW:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		wt = &(pxw->head);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_show)
		{
			pxw->result = (*psub->sub_on_show)(wt, event_code, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_show)
		{
			(*pif->pf_on_show)(wt, event_code);
		}
		break;
	case WAYLAND_EVENT_CREATE:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		wt = &(pxw->head);

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_create)
		{
			(*pif->pf_on_create)(wt, (void*)event_data);
		}
		break;
	case WAYLAND_EVENT_DESTROY:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		wt = &(pxw->head);

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_destroy)
		{
			(*pif->pf_on_destroy)(wt);
		}
		break;
	case WAYLAND_EVENT_COMMAND:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		if (GETDWORDL(event_code) == IDC_PARENT)
		{
			psub = GETXDUSUBPROC(window);
			if (psub && psub->sub_on_parent_command)
			{
				pxw->result = (*psub->sub_on_parent_command)(wt, (int)GETDWORDH(event_code), event_data, psub->sid, psub->delta);
				if (pxw->result)
					break;
			}

			pif = GETXDUDISPATCH(window);
			if (pif && pif->pf_on_parent_command)
			{
				(*pif->pf_on_parent_command)(wt, (int)GETDWORDH(event_code), event_data);
			}
		}
		else if (GETDWORDL(event_code) == IDC_CHILD)
		{
			psub = GETXDUSUBPROC(window);
			if (psub && psub->sub_on_child_command)
			{
				pxw->result = (*psub->sub_on_child_command)(wt, (int)GETDWORDH(event_code), event_data, psub->sid, psub->delta);
				if (pxw->result)
					break;
			}

			pif = GETXDUDISPATCH(window);
			if (pif && pif->pf_on_child_command)
			{
				(*pif->pf_on_child_command)(wt, (int)GETDWORDH(event_code), event_data);
			}
		}
		else if (GETDWORDL(event_code) == IDC_SELF)
		{
			psub = GETXDUSUBPROC(window);
			if (psub && psub->sub_on_self_command)
			{
				pxw->result = (*psub->sub_on_self_command)(wt, (int)GETDWORDH(event_code), event_data, psub->sid, psub->delta);
				if (pxw->result)
					break;
			}

			pif = GETXDUDISPATCH(window);
			if (pif && pif->pf_on_self_command)
			{
				(*pif->pf_on_self_command)(wt, (int)GETDWORDH(event_code), event_data);
			}
		}
		else
		{
			psub = GETXDUSUBPROC(window);
			if (psub && psub->sub_on_menu_command)
			{
				pxw->result = (*psub->sub_on_menu_command)(wt, (int)GETDWORDH(event_code), (int)GETDWORDL(event_code), event_data, psub->sid, psub->delta);
				if (pxw->result)
					break;
			}

			pif = GETXDUDISPATCH(window);
			if (pif && pif->pf_on_menu_command)
			{
				(*pif->pf_on_menu_command)(wt, (int)GETDWORDH(event_code), (int)GETDWORDL(event_code), event_data);
			}
		}
		break;
	case WAYLAND_EVENT_NOTICE:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_notice)
		{
			pxw->result = (*psub->sub_on_notice)(wt, (NOTICE *)event_data, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_notice)
		{
			(*pif->pf_on_notice)(wt, (NOTICE *)event_data);
		}
		break;
	case WAYLAND_EVENT_SCROLL:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_scroll)
		{
			pxw->result = (*psub->sub_on_scroll)(wt, (bool_t)event_code, (int)event_data, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_scroll)
		{
			(*pif->pf_on_scroll)(wt, (bool_t)event_code, (int)event_data);
		}
		break;
	case WAYLAND_EVENT_ACTIVATE:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_activate)
		{
			pxw->result = (*psub->sub_on_activate)(wt, 1, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_activate)
		{
			(*pif->pf_on_activate)(wt, 1);
		}
		break;
	case WAYLAND_EVENT_WCHAR:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_wchar)
		{
			pxw->result = (*psub->sub_on_wchar)(wt, (wchar_t)event_code, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_wchar)
		{
			(*pif->pf_on_wchar)(wt, (wchar_t)event_code);
		}
		break;
	case WAYLAND_EVENT_CLOSE:
		pxw = GETXDUSTRUCT(window);
		if (!pxw)
			break;
		if (pxw->disable)
			break;
		wt = &(pxw->head);

		psub = GETXDUSUBPROC(window);
		if (psub && psub->sub_on_close)
		{
			pxw->result = (*psub->sub_on_close)(wt, psub->sid, psub->delta);
			if (pxw->result)
				break;
		}

		pif = GETXDUDISPATCH(window);
		if (pif && pif->pf_on_close)
		{
			pxw->result = (*pif->pf_on_close)(wt);
		}
		else
		{
			pxw->result = 0;
		}

		if (!pxw->result)
		{
			pxw->mode = WS_MODE_INVALID;
		}
		break;
	}

	return 0;
}

widget_t wlWidgetCreate(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev)
{
	wayland_widget_t* pxw_par = (wparent)? TypePtrFromHead(wayland_widget_t, wparent) : NULL;
    wayland_widget_t* pxw_new;

	wayland_window *par, *win;
	int window_x, window_y, window_width, window_height, border_width = 0;
	int window_type;
	dword_t event_mask = 0;

	wayland_widget_t* pxw = NULL;
	if_dispatch_t* pv = NULL;
	
	par = (pxw_par)? pxw_par->self : NULL;

	if(wstyle & WD_STYLE_TITLE)
	{
		window_type = (wstyle & WD_STYLE_SIZEBOX)? WAYLAND_WINDOW_TYPE_OVERLAP : WAYLAND_WINDOW_TYPE_DIALOG;
		event_mask = WIDGET_MAIN_EVENTS;
	}else
	{
		if(wstyle & WD_STYLE_CHILD)
		{
			window_type = WAYLAND_WINDOW_TYPE_CHILD;
			event_mask = WIDGET_CHILD_EVENTS;
		}else
		{
			window_type = WAYLAND_WINDOW_TYPE_POPUP;
			event_mask = WIDGET_POPUP_EVENTS;
		}
	}

	if(wstyle & WD_STYLE_NOACTIVE)
	{
		event_mask &= ~WIDGET_FOCUS_EVENTS;
	}

	window_x = pxr->x;
	window_y = pxr->y;
	window_width = (pxr->w > WIDGET_BORDER_WIDTH)? pxr->w : (WIDGET_BORDER_WIDTH + 1);
	window_height = (pxr->h > WIDGET_BORDER_WIDTH)? pxr->h : (WIDGET_BORDER_WIDTH + 1);

	win = WaylandCreateWindow(par, window_type, event_mask, wname, window_x, window_y, window_width, window_height);
	if(!win) return NULL;

	pxw_new = (wayland_widget_t*)xmem_alloc_handle(sizeof(wayland_widget_t));
	pxw_new->head.tag = _HANDLE_WIDGET;
	pxw_new->parent = par;
	pxw_new->self = win;
	pxw_new->style = wstyle;
	pxw_new->mode = WS_MODE_NORMAL;
	pxw_new->accel = NULL;
	pxw_new->result = 0;

	pxw_new->pt.x = window_x;
	pxw_new->pt.y = window_y;
	pxw_new->st.w = window_width;
	pxw_new->st.h = window_height;

	SETXDUSTRUCT(win, pxw_new);

	if(pev)
	{
		pv = (if_dispatch_t*)xmem_alloc(sizeof(if_dispatch_t));
		xmem_copy((void*)pv, (void*)pev, sizeof(if_dispatch_t));
		SETXDUDISPATCH(win, pv);
	}

    return &(pxw_new->head);
}

void wlWidgetDestroy(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	if_dispatch_t* pv;
	wayland_window* win;

	if(pxw->accel)
	{
		xmem_free(pxw->accel);
	}

	pv = GETXDUDISPATCH(pxw->self);
	if(pv) xmem_free(pv);

	SETXDUDISPATCH(pxw->self, NULL);

	WaylandDestroyWindow(pxw->self);

	xmem_free_handle((xhand_t)pxw);
}

void wlWidgetClose(widget_t wt, int ret)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
    if_dispatch_t* pv;

	if(pxw->style & WD_STYLE_CHILD)
	{
		wlWidgetDestroy(wt);
		return;
	}

	WaylandEventsAdd(pxw->self, WAYLAND_EVENT_CLOSE, 0, 0);
	WaylandEventsFlash();

	if(pxw->result) return;

	switch(pxw->mode)
	{
	case WS_MODE_MAIN:
		pxw->retcode = ret;
		break;
	case WS_MODE_MODAL:
		pxw->retcode = ret;
		break;
	case WS_MODE_TRACK:
		pxw->retcode = ret;
		break;
	}
}

const if_subproc_t* wlWidgetGetSubproc(widget_t wt, uid_t sid)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	if_subproc_t* psub = GETXDUSUBPROC(pxw->self);

	return (psub && psub->sid == sid)? psub : NULL;
}

bool_t wlWidgetSetSubproc(widget_t wt, uid_t sid, if_subproc_t* sub)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	if_subproc_t* psub;

	psub = (if_subproc_t*)xmem_alloc(sizeof(if_subproc_t));
	xmem_copy((void*)psub, (void*)sub, sizeof(if_subproc_t));
	psub->sid = sid;

	SETXDUSUBPROC(pxw->self, psub);

	return 1;
}

void wlWidgetDelSubproc(widget_t wt, uid_t sid)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	if_subproc_t* psub = GETXDUSUBPROC(pxw->self);

	if(psub && psub->sid == sid)
	{
		xmem_free(psub);
		SETXDUSUBPROC(pxw->self, NULL);
	}
}

bool_t wlWidgetSetSubprocDelta(widget_t wt, uid_t sid, vword_t delta)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	if_subproc_t* psub = GETXDUSUBPROC(pxw->self);

	if(psub && psub->sid == sid)
	{
		psub->delta = delta;
		return bool_true;
	}else
	{
		return bool_false;
	}
}

vword_t wlWidgetGetSubprocDelta(widget_t wt, uid_t sid)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	if_subproc_t* psub = GETXDUSUBPROC(pxw->self);

	return (psub && psub->sid == sid)? psub->delta : 0;
}

bool_t wlWidgetHasSubproc(widget_t wt, uid_t sid)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	if_subproc_t* psub = GETXDUSUBPROC(pxw->self);

	return (psub && psub->sid == sid) ? bool_true : bool_false;
}

void wlWidgetSetCoreDelta(widget_t wt, vword_t pd)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	SETXDUCOREDELTA(pxw->self, (void*)pd);
}

vword_t wlWidgetGetCoreDelta(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return (vword_t)GETXDUCOREDELTA(pxw->self);
}

void wlWidgetSetUserDelta(widget_t wt, vword_t pd)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	SETXDUUSERDELTA(pxw->self, (void*)pd);
}

vword_t wlWidgetGetUserDelta(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return (vword_t)GETXDUUSERDELTA(pxw->self);
}

void wlWidgetSetStyle(widget_t wt, dword_t ws)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	pxw->style = ws;
}

dword_t wlWidgetGetStyle(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return (pxw)? pxw->style : 0;
}

void wlWidgetSetAccel(widget_t wt, const accel_table_t* pacl, int n)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	accel_table_t* pa;

	if(pxw->accel) xmem_free(pxw->accel);

	pa = (accel_table_t*)xmem_alloc((n + 1) * sizeof(accel_table_t));
	xmem_copy((void*)pa, (void*)pacl, n * sizeof(accel_table_t));

	pa[n].vir = 0, pa[n].key = 0, pa[n].cmd = 0;
	pxw->accel = pa;
}

void wlWidgetSetOwner(widget_t wt, widget_t owner)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	wayland_widget_t* pxw_owner = TypePtrFromHead(wayland_widget_t, owner);

	pxw->owner = (owner)? pxw_owner->self : 0;
}

widget_t wlWidgetGetOwner(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	wayland_widget_t* pxw_owner;

	if(!pxw->owner) return NULL;

	pxw_owner = GETXDUSTRUCT(pxw->owner);
	return (pxw_owner)? (widget_t)&(pxw_owner->head) : (widget_t)0;
}

void wlWidgetSetUserId(widget_t wt, uid_t uid)
{
    wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	pxw->uid = uid;
}

uid_t wlWidgetGetUserId(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

    return (pxw)? pxw->uid : 0;
}

void wlWidgetSetUserResult(widget_t wt, int rt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	pxw->result = rt;
}

int wlWidgetGetUserResult(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

    return (pxw)? pxw->result : 0;
}

widget_t wlWidgetGetChild(widget_t wt, uid_t uid)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	wayland_widget_t* pxw_child;
	int i;

	for(i = 0; i < pxw->self->childs_count; i++)
	{
		pxw_child = GETXDUSTRUCT(pxw->self->childs[i]);
		if(pxw_child->uid == uid)
		{
			return &(pxw_child->head);
		}
	}

	return NULL;
}

widget_t wlWidgetGetParent(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	wayland_widget_t* pxw_parent;

	if(!pxw->parent) return NULL;

	pxw_parent = GETXDUSTRUCT(pxw->parent);
	
	return &(pxw_parent->head);
}

void wlWidgetSetUserProp(widget_t wt, const tchar_t* pname,vword_t val)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

vword_t wlWidgetGetUserProp(widget_t wt, const tchar_t* pname)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
    unsigned char bys[VOID_SIZE] = {0};

	return 0;
}

vword_t wlWidgetDelUserProp(widget_t wt, const tchar_t* pname)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
    vword_t rt = 0;
    
    return rt;
}

const if_dispatch_t* wlWidgetGetDispatch(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return GETXDUDISPATCH(pxw->self);
}

bool_t wlWidgetIsMaximized(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return (pxw->self->win_state == WAYLAND_WINDOW_STATE_MAXIMIZED)? 1 : 0;
}

bool_t wlWidgetIsMinimized(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return (pxw->self->win_state == WAYLAND_WINDOW_STATE_MINIMIZED)? 1 : 0;
}

bool_t wlWidgetEnumChild(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	unsigned int i;
	wayland_widget_t* pxw_child;

	for(i = 0;i < pxw->self->childs_count; i++)
	{
		pxw_child = GETXDUSTRUCT(pxw->self->childs[i]);
		
		if(pxw_child && !(*pf)(&(pxw_child->head), pv)) 
			return bool_false;;
	}

    return bool_true;
}

visual_t wlWidgetClientContext(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	visual_t rdc = NULL;

	return rdc;
}

visual_t wlWidgetWindowContext(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	visual_t rdc = NULL;

	return rdc;
}

void wlWidgetReleaseContext(widget_t wt, visual_t dc)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

void wlWidgetGetClientRect(widget_t wt, xrect_t* prt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	WaylandGetClientRect(pxw->self, prt);
}

void wlWidgetGetWindowRect(widget_t wt, xrect_t* prt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	WaylandGetWindowRect(pxw->self, prt);
}

void wlWidgetClientToScreen(widget_t wt, xpoint_t* ppt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	WaylandClientToScreen(pxw->self, ppt);
}

void wlWidgetScreenToClient(widget_t wt, xpoint_t* ppt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	WaylandScreenToClient(pxw->self, ppt);
}

void wlWidgetClientToWindow(widget_t wt, xpoint_t* ppt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	
	WaylandClientToWindow(pxw->self, ppt);
}

void wlWidgetWindowToClient(widget_t wt, xpoint_t* ppt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	
	WaylandWindowToClient(pxw->self, ppt);
}

void wlWidgetCenterWindow(widget_t wt, widget_t owner)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	xrect_t xr_self, xr_owner = {0};

	wlWidgetGetWindowRect(wt, &xr_self);

	if(owner)
		wlWidgetGetWindowRect(owner, &xr_owner);
	else
		wlGetDesktopRect(&xr_owner);

	pt_center_rect(&xr_self, xr_owner.w, xr_owner.h);

	wlWidgetMove(wt, RECTPOINT(&xr_self));
}

void wlWidgetSetCursor(widget_t wt, int ci)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

void wlWidgetSetCapture(widget_t wt, bool_t b)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

static void _widget_timer_proc(void* pa, res_timer_t rt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, (widget_t)pa);

	if_dispatch_t* pv = GETXDUDISPATCH(pxw->self);

	if(pv && pv->pf_on_timer)
	{
		(*pv->pf_on_timer)((widget_t)&(pxw->head), (vword_t)rt);
	}
}

vword_t wlWidgetSetTimer(widget_t wt, int ms)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	res_timer_t rt;

	if(!g_queue) return (vword_t)0;

	rt = create_timer(g_queue, 500, ms, (PF_TIMERFUNC)_widget_timer_proc, (void*)wt);

    return (vword_t)rt;
}

void wlWidgetKillTimer(widget_t wt, vword_t tid)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	res_timer_t rt = (res_timer_t)tid;

	if(!g_queue) return;

	destroy_timer(g_queue, rt);
}

static void _widget_caret_proc(void* pa, res_timer_t rt)
{
	widget_t wt = (widget_t)(pa);

	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	if_dispatch_t* pv = GETXDUDISPATCH(pxw->self);

}

void wlWidgetCreateCaret(widget_t wt, int w, int h)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	if(pxw->ctt) return;

	pxw->car.x = 0;
	pxw->car.y = 0;
	pxw->car.w = w;
	pxw->car.h = h;
	pxw->car.blink = DEFAULT_CARET_BLINK;

	pxw->ctt = create_timer(g_queue, 500, pxw->car.blink, (PF_TIMERFUNC)_widget_caret_proc, (void*)wt);
}

void wlWidgetDestroyCaret(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	pxw->car.blink = 0;

	if(pxw->ctt)
	{
		destroy_timer(g_queue, pxw->ctt);
		pxw->ctt = 0;
	}
}

void wlWidgetShowCaret(widget_t wt, int x, int y)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

void wlWidgetSetFocus(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	WaylandSetFocusWindow(pxw->self);
}

bool_t wlWidgetKeyState(widget_t wt, int ks)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	dword_t mask = 0;

	mask = WaylandKeyboardState();

	switch (ks)
	{
	case KS_WITH_SHIFT:
		if(mask & WAYLAND_STATE_SHIFT) return 1;
		break;
	case KS_WITH_CONTROL:
		if(mask & WAYLAND_STATE_CONTROL) return 1;
		break;
	case KS_WITH_ALT:
		if(mask & WAYLAND_STATE_ALT) return 1;
		break;
	}

	return 0;
}

bool_t wlWidgetIsValid(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	if(!wt) return 0;
	if(!pxw->self) return 0;
	if(GETXDUSTRUCT(pxw->self) == NULL) return 0;

	return 1;
}

bool_t wlWidgetIsFocus(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	wayland_window* fw = 0;
	int r = 0;

	return (pxw->self == fw)? 1 : 0;
}

bool_t wlWidgetIsChild(widget_t wt)
{
    wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return (pxw->style & WD_STYLE_CHILD)? 1 : 0;
}

bool_t wlWidgetIsOwnerNc(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return (pxw->style & WD_STYLE_OWNERNC) ? 1 : 0;
}

void wlWidgetMove(widget_t wt, const xpoint_t* ppt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

void wlWidgetSize(widget_t wt, const xsize_t* pxs)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
}

void wlWidgetTake(widget_t wt, int zor)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

void wlWidgetShow(widget_t wt, dword_t sw)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	switch(sw)
	{
	case WS_SHOW_MINIMIZE:
		break;
	case WS_SHOW_MAXIMIZE:
		break;
	case WS_SHOW_HIDE:
		break;
	default:
		break;
	}
}

void wlWidgetLayout(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	if_dispatch_t* pif;

	pif = GETXDUDISPATCH(pxw->self);
}

void wlWidgetErase(widget_t wt, const xrect_t* prt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
}

void wlWidgetEnable(widget_t wt, bool_t b)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	pxw->disable = (b)? 0 : 1;
}

void wlWidgetEnableHover(widget_t wt, bool_t b)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

void wlWidgetPostNotice(widget_t wt, NOTICE* pnt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
}

int wlWidgetSendNotice(widget_t wt, NOTICE* pnt)
{
    wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	if_dispatch_t* pif;

	pif = GETXDUDISPATCH(pxw->self);

	if(pif && pif->pf_on_notice)
	{
		(*pif->pf_on_notice)(wt, pnt);

		return 1;
	}

	return 0;
}

void wlWidgetPostCommand(widget_t wt, int code, uid_t cid, vword_t data)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

int wlWidgetSendCommand(widget_t wt, int code, uid_t cid, vword_t data)
{
    wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
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

void wlWidgetPostWChar(widget_t wt, wchar_t ch)
{
	wayland_widget_t* pxw = (wt)? TypePtrFromHead(wayland_widget_t, wt) : NULL;
}

void wlWidgetPostKey(widget_t wt, int key)
{
	wayland_widget_t* pxw = (wt)? TypePtrFromHead(wayland_widget_t, wt) : NULL;

}

void wlWidgetSetTitle(widget_t wt, const tchar_t* token)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

int wlWidgetGetTitle(widget_t wt, tchar_t* buf, int max)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return 0;
}

void wlWidgetActive(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

void wlWidgetScroll(widget_t wt, bool_t horz, int line)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

void wlWidgetGetScrollInfo(widget_t wt, bool_t horz, scroll_t* psl)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	if(horz)
		xmem_copy((void*)psl, (void*)&(pxw->hs), sizeof(scroll_t));
	else
		xmem_copy((void*)psl, (void*)&(pxw->vs), sizeof(scroll_t));
}

static int CALLBACK _update_horz_position(widget_t wt, vword_t b)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);


	return (0);
}

static int CALLBACK _update_vert_position(widget_t wt, vword_t b)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return (0);
}

void wlWidgetSetScrollInfo(widget_t wt, bool_t horz, const scroll_t* psl)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	int b;

	if(horz)
	{
		b = (psl->pos - pxw->hs.pos);
		xmem_copy((void*)&(pxw->hs), (void*)psl, sizeof(scroll_t));

		if(!b) return;

		wlWidgetEnumChild(wt, (PF_ENUM_WINDOW_PROC)_update_horz_position, (vword_t)&b);
	}
	else
	{
		b = (psl->pos - pxw->vs.pos);
		xmem_copy((void*)&(pxw->vs), (void*)psl, sizeof(scroll_t));

		if(!b) return;

		wlWidgetEnumChild(wt, (PF_ENUM_WINDOW_PROC)_update_vert_position, (vword_t)&b);
	}
}

static int CALLBACK _widget_set_child_color_mode(widget_t wt, vword_t pv)
{
	dword_t dw = wlWidgetGetStyle(wt);
	
	if (dw & WD_STYLE_NOCHANGE) return 1;

	return 1;
}

void wlWidgetSetColorMode(widget_t wt, const color_mod_t* pclr)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	wlWidgetEnumChild(wt, _widget_set_child_color_mode, (vword_t)pclr);
}

void wlWidgetGetColorMode(widget_t wt, color_mod_t* pclr)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	xmem_copy((void*)pclr, (void*)&(pxw->clrs), sizeof(color_mod_t));
}

const color_mod_t* wlWidgetGetColorModePtr(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return &(pxw->clrs);
}

void wlWidgetSetDiaph(widget_t wt, float f)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
}

float wlWidgetGetDiaph(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return pxw->diaph;
}

int	wlWidgetDoMain(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

	return (0);
}

int	wlWidgetDoModal(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
	wayland_widget_t* powner;

	return (0);
}

void wlWidgetDoTrack(widget_t wt)
{
	wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);

}

void wlMessageQuit(int code)
{

}

void wlMessagePosition(xpoint_t* pxp)
{
    wayland_window* root, child;

}
/*********************************************************************************************************/
void wlCalcWidgetBorder(dword_t ws, border_t* pbd)
{
    pbd->edge = pbd->title = pbd->scrh = pbd->scrw = 0;

	if (ws & WD_STYLE_TITLE)
	{
		pbd->title = FRAME_TITLE_DOTS;
	}

	if (ws & WD_STYLE_BORDER)
	{
		if (ws & WD_STYLE_CHILD)
			pbd->edge = CHILD_EDGE_DOTS;
		else
			pbd->edge = FRAME_EDGE_DOTS;
	}

	if (ws & WD_STYLE_HSCROLL)
	{
		pbd->scrh = FRAME_SCROLL_DOTS;
	}

	if (ws & WD_STYLE_VSCROLL)
	{
		pbd->scrw = FRAME_SCROLL_DOTS;
	}
}

void wlAdjustWidgetSize(dword_t wstyle, xsize_t* pxs)
{
	if(wstyle & WD_STYLE_CHILD)
		return;

	pxs->h += (FRAME_TITLE_DOTS + FRAME_EDGE_DOTS);
	pxs->w += (FRAME_EDGE_DOTS * 2);
}

void wlGetScreenSize(xsize_t* pxs)
{
	WaylandGetScreenSize(pxs);
}

void wlGetDesktopRect(xrect_t* pxr)
{
	WaylandGetDesktopRect(pxr);
}

void wlScreenSizeToMm(xsize_t* pxs)
{
	wayland_display* display = WaylandDefaultDisplay();
	dev_cap_t cap;

	WaylandGetDeviceCap(display, &cap);

	pxs->fw = (float)((float) pxs->w * ((float)cap.horz_size / (float)cap.horz_res));
	pxs->fh = (float)((float) pxs->h * ((float)cap.vert_size / (float)cap.vert_res));
}

void wlScreenSizeToPt(xsize_t* pxs)
{
	wayland_display* display = WaylandDefaultDisplay();
	dev_cap_t cap;

	WaylandGetDeviceCap(display, &cap);

	pxs->w = (int)((float) pxs->fw * ((float)cap.horz_res / (float)cap.horz_size));
	pxs->h = (int)((float) pxs->fh * ((float)cap.vert_res / (float)cap.vert_size));
}
