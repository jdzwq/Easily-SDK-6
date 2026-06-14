/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc widget document

	@module	if_window.c | linux implement file

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

#include "_wayland.h"

#include <linux/input.h>

void _window_paint(void *data, struct wl_callback *callback, uint32_t time);

static const struct wl_callback_listener paint_listener = {
    .done = _window_paint
};

void _window_paint(void *data, struct wl_callback *callback, uint32_t time) 
{
	wayland_window* pwin = (data)? (wayland_window*)data : NULL;

	struct wl_callback *frame_callback;
	wayland_surface* psur;
	xrect_t rt = {0};

	if (!pwin) return;

    if(pwin->evt_mask & WAYLAND_EVENT_EXPOSE & WAYLAND_EVENT_MASK)
    {
        WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_EXPOSE, 0, (vword_t)&rt);
    }
	
	psur = pwin->sur_client;

    frame_callback = wl_surface_frame(psur->raw_face);
    wl_callback_add_listener(frame_callback, &paint_listener, data);

    WaylandGetClientRect((wayland_window*)data, &rt);
	WaylandClientToScreen((wayland_window*)data, (xpoint_t*)&rt);
    wl_surface_damage(psur->raw_face, rt.x, rt.y, rt.w, rt.h);
    wl_surface_commit(psur->raw_face);
}

static void _window_configure(void *data, struct xdg_toplevel *top, int32_t w, int32_t h, struct wl_array *states)
{
   wayland_window* pwin = (data)? (wayland_window*)data : NULL;

    uint32_t *state;

    wl_array_for_each(state, states) 
    {
        switch (*state)
        {
        case XDG_TOPLEVEL_STATE_MAXIMIZED:
            if(pwin->evt_mask & WAYLAND_EVENT_SIZE & WAYLAND_EVENT_MASK)
            {
                WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_SIZE, WS_SHOW_MAXIMIZE, MAKEVWORD(w, h));
            }
            break;
        case XDG_TOPLEVEL_STATE_FULLSCREEN:
            if(pwin->evt_mask & WAYLAND_EVENT_SIZE & WAYLAND_EVENT_MASK)
            {
                WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_SIZE, WS_SHOW_FULLSCREEN, MAKEVWORD(w, h));
            }
            break;
        case XDG_TOPLEVEL_STATE_RESIZING:
            if(pwin->evt_mask & WAYLAND_EVENT_SIZE & WAYLAND_EVENT_MASK)
            {
                WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_SIZE, WS_SHOW_NORMAL, MAKEVWORD(w, h));
            }
            break;
        case XDG_TOPLEVEL_STATE_ACTIVATED:
            if(pwin->evt_mask & WAYLAND_EVENT_ACTIVATE & WAYLAND_EVENT_MASK)
            {
                WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_ACTIVATE, 0, (vword_t)NULL);
            }
            break;
        }
    }

    //xdg_toplevel_set_minimized(pwin->xdg_top);
}

static void _window_close(void *data, struct xdg_toplevel *top)
{
    wayland_window* pwin = (data)? (wayland_window*)data : NULL;

    if(pwin->evt_mask & WAYLAND_EVENT_DESTROY & WAYLAND_EVENT_MASK)
    {
        WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_DESTROY, 0, (vword_t)NULL);
    }
}

static const struct xdg_toplevel_listener xdg_toplevel_listener = {
    .configure = _window_configure,
    .close = _window_close,
};

static void _popup_configure(void *data, struct xdg_popup *popup, int32_t x, int32_t y, int32_t width, int32_t height)
{
    wayland_window* pwin = (data)? (wayland_window*)data : NULL;
    
    if(pwin->evt_mask & WAYLAND_EVENT_SIZE & WAYLAND_EVENT_MASK)
    {
        WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_SIZE, WS_SHOW_NORMAL, MAKEVWORD(width, height));
    }
}

static void _popup_done(void *data, struct xdg_popup *popup)
{
    wayland_window* pwin = (data)? (wayland_window*)data : NULL;
    
    if(pwin->evt_mask & WAYLAND_EVENT_CLOSE & WAYLAND_EVENT_MASK)
    {
        WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_CLOSE, 0, (vword_t)NULL);
    }
}

static const struct xdg_popup_listener xdg_popup_listener = {
    .configure = _popup_configure,
    .popup_done = _popup_done,
};

static void _mouse_enter(void *data, struct wl_pointer *pointer, uint32_t serial,
                          struct wl_surface *surface, wl_fixed_t sx, wl_fixed_t sy) 
{
    wayland_window* pwin = (data)? (wayland_window*)data : NULL;
    
    if(pwin->evt_mask & WAYLAND_EVENT_MOUSE_ENTER & WAYLAND_EVENT_MASK)
    {
        WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_MOUSE_ENTER, 0, MAKEVWORD(sx, sy));
    }
}

static void _mouse_leave(void *data, struct wl_pointer *pointer, uint32_t serial,
                          struct wl_surface *surface) 
{
    wayland_window* pwin = (data)? (wayland_window*)data : NULL;
    
    if(pwin->evt_mask & WAYLAND_EVENT_MOUSE_LEAVE & WAYLAND_EVENT_MASK)
    {
        WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_MOUSE_LEAVE, 0, (vword_t)NULL);
    }
}

static void _mouse_motion(void *data, struct wl_pointer *pointer, uint32_t time,
                           wl_fixed_t sx, wl_fixed_t sy) 
{
    wayland_display* pdisp = WaylandDefaultDisplay();
    wayland_window* pwin = (data)? (wayland_window*)data : NULL;
    
    pdisp->track_xpos = sx;
    pdisp->track_ypos = sy;

    if(pwin->evt_mask & WAYLAND_EVENT_MOUSE_MOVE & WAYLAND_EVENT_MASK)
    {
        WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_MOUSE_MOVE, 0, MAKEVWORD(sx, sy));
    }
}

static void _mouse_button(void *data, struct wl_pointer *pointer, uint32_t serial,
                            uint32_t time, uint32_t button, uint32_t state) 
{
    wayland_display* pdisp = WaylandDefaultDisplay();
    wayland_window* pwin = (data)? (wayland_window*)data : NULL;
    
    if(state == WL_POINTER_BUTTON_STATE_PRESSED)
    {
        if(pwin->evt_mask & WAYLAND_EVENT_LBUTTON_DOWN & WAYLAND_EVENT_MASK)
        {
            if(button == BTN_LEFT)
                WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_LBUTTON_DOWN, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
            else if(button == BTN_RIGHT)
                WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_RBUTTON_DOWN, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
        }
    }else
    {
        if(pwin->evt_mask & WAYLAND_EVENT_LBUTTON_UP & WAYLAND_EVENT_MASK)
        {
            if(button == BTN_LEFT)
                WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_LBUTTON_UP, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
            else if(button == BTN_RIGHT)
                WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_RBUTTON_UP, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
        }
    }
}

static void _mouse_axis(void *data, struct wl_pointer *pointer, uint32_t time,
                         uint32_t axis, wl_fixed_t value) 
{
    wayland_window* pwin = (data)? (wayland_window*)data : NULL;
    
    if(pwin->evt_mask & WAYLAND_EVENT_MOUSE_WHEEL & WAYLAND_EVENT_MASK)
    {
        if(axis == WL_POINTER_AXIS_VERTICAL_SCROLL)
            WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_MOUSE_WHEEL, 0, (vword_t)value);
        else if(axis == WL_POINTER_AXIS_HORIZONTAL_SCROLL)
            WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_MOUSE_WHEEL, 1, (vword_t)value);
    }
}

static const struct wl_pointer_listener mouse_listener = {
    .enter = _mouse_enter,
    .leave = _mouse_leave,
    .motion = _mouse_motion,
    .button = _mouse_button,
    .axis = _mouse_axis,
};

static void _key_keymap(void *data, struct wl_keyboard *keyboard, uint32_t format, int fd, uint32_t size) 
{
    // Handle keymap (for input method, usually just close fd if not used)
}

static void _set_focus(void *data, struct wl_keyboard *keyboard, uint32_t serial, struct wl_surface *surface, struct wl_array *keys) 
{
    wayland_window* pwin = (data)? (wayland_window*)data : NULL;
    
    if(pwin->evt_mask & WAYLAND_EVENT_SET_FOCUS & WAYLAND_EVENT_MASK)
    {
        WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_SET_FOCUS, 0, (vword_t)NULL);
    }
}

static void _kill_focus(void *data, struct wl_keyboard *keyboard, uint32_t serial, struct wl_surface *surface) 
{
    wayland_window* pwin = (data)? (wayland_window*)data : NULL;
    
    if(pwin->evt_mask & WAYLAND_EVENT_KILL_FOCUS & WAYLAND_EVENT_MASK)
    {
        WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_KILL_FOCUS, 0, (vword_t)NULL);
    }
}

static void _key_press(void *data, struct wl_keyboard *keyboard, uint32_t serial, uint32_t time, uint32_t key, uint32_t state) 
{
    wayland_window* pwin = (data)? (wayland_window*)data : NULL;
    
    if(state == WL_KEYBOARD_KEY_STATE_PRESSED)
    {
        if(pwin->evt_mask & WAYLAND_EVENT_KEY_DOWN & WAYLAND_EVENT_MASK)
        {
            WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_KEY_DOWN, key, (vword_t)time);
        }
    }else
    {
        if(pwin->evt_mask & WAYLAND_EVENT_KEY_UP & WAYLAND_EVENT_MASK)
        {
            WaylandEventsAdd((wayland_window*)data, WAYLAND_EVENT_KEY_UP, key, (vword_t)time);
        }
    }
}

static void _key_modify(void *data, struct wl_keyboard *keyboard, uint32_t serial, uint32_t mods_depressed, uint32_t mods_latched, uint32_t mods_locked, uint32_t group) 
{
    wayland_display* pdisp =  WaylandDefaultDisplay();

    pdisp->track_mkey = mods_depressed | mods_latched | mods_locked;
    // Modifier keys (shift, ctrl, etc.)
}

static const struct wl_keyboard_listener key_listener = {
    .keymap = _key_keymap,
    .enter = _set_focus,
    .leave = _kill_focus,
    .key = _key_press,
    .modifiers = _key_modify,
    .repeat_info = NULL // (optional, protocol version >= 4)
};

static void _WaylandAddChild(wayland_window* child)
{
    wayland_window* parent = child->parent;

    parent = child->parent;
    if (!parent) return;

    if (parent->childs_count >= WAYLAND_MAX_CHILDS) return;

    parent->childs[parent->childs_count] = child;
    parent->childs_count++;
}

static void _WaylandDelChild(wayland_window* child)
{
    wayland_window* parent = child->parent;
    int i;

    parent = child->parent;
    if (!parent) return;

    for(i=0;i<parent->childs_count;i++)
    {
        if(parent->childs[i] == child)
        {
            for(;i<parent->childs_count-1;i++)
            {
                parent->childs[i] = parent->childs[i+1];
            }
            parent->childs[parent->childs_count-1] = NULL;
            parent->childs_count--;
            break;
        }
    }
}

wayland_window* WaylandCreateWindow(wayland_window* parent, int type, dword_t mask, const tchar_t* title, int x, int y, int width, int height)
{
    wayland_window* par_win = (parent) ? (wayland_window*)parent : NULL;
    wayland_window* pwin;

    wayland_display* pdisp = NULL;
    wayland_surface* psur = NULL;
    struct xdg_positioner *xdg_pos = NULL;
    wayland_surface* par_sur = NULL;
    struct wl_callback *frame_callback = NULL;

    xrect_t xr;

    if (type == WAYLAND_WINDOW_TYPE_CHILD && !par_win) goto err_ret;

    pwin = (wayland_window*)xmem_alloc(sizeof(wayland_window));
    pwin->parent = parent;
    pwin->childs_count = 0;
    pwin->x = x;
    pwin->y = y;
    pwin->width = width;
    pwin->height = height;
    pwin->win_type = type;
    pwin->evt_mask = mask;

    pdisp = WaylandDefaultDisplay();

    if(type == WAYLAND_WINDOW_TYPE_CHILD)
    {
        pwin->edge_width = 0;
        pwin->title_height = 0;
    }
    else if(type == WAYLAND_WINDOW_TYPE_POPUP)
    {
        pwin->edge_width = WAYLAND_WINDOW_EDGE_WIDTH;
        pwin->title_height = WAYLAND_WINDOW_EDGE_WIDTH;
    }else
    {
        pwin->edge_width = WAYLAND_WINDOW_EDGE_WIDTH;
        pwin->title_height = WAYLAND_WINDOW_TITLE_HEIGHT;
    }

    if(type != WAYLAND_WINDOW_TYPE_CHILD)
    {
        xr.x = pwin->x;
        xr.y = pwin->y;
        xr.w = pwin->width;
        xr.h = pwin->height;

        pwin->sur_window = WaylandCreateSurface(WaylandDefaultDisplay(), &xr);
        if (!pwin->sur_window) goto err_ret;

        psur = pwin->sur_window;

        pwin->xdg_top = xdg_surface_get_toplevel(psur->xdg_face);
        if (!pwin->xdg_top) goto err_ret;

        //configure event
        xdg_toplevel_add_listener(pwin->xdg_top, &xdg_toplevel_listener, pwin);
        //xdg_toplevel_set_title(pwin->xdg_top, title ? title : "Easily");
        //xdg_toplevel_set_max_size(pwin->xdg_top, gw_scrcap.horz_res, gw_scrcap.vert_res);
        //xdg_toplevel_set_min_size(pwin->xdg_top, xr.w, xr.h);
        xdg_surface_set_window_geometry(psur->xdg_face, 0, 0, xr.w, xr.h);

        par_sur = pwin->sur_window;
    }else
    {
        par_sur = par_win->sur_client;
    }

    //client rect
    xr.x = pwin->x + pwin->edge_width;
    xr.y = pwin->y + pwin->title_height;
    xr.w = pwin->width - 2 * pwin->edge_width;
    xr.h = pwin->height - pwin->title_height - pwin->edge_width;

    pwin->sur_client = WaylandCreateSurface(par_sur->display, &xr);
    if (!pwin->sur_client) goto err_ret;

    psur = pwin->sur_client;

    xdg_pos = xdg_wm_base_create_positioner(pdisp->xdg_base);
    if (!xdg_pos) goto err_ret;

    xdg_positioner_set_offset(xdg_pos, 0, 0);
    xdg_positioner_set_size(xdg_pos, xr.w, xr.h);
    xdg_positioner_set_anchor_rect(xdg_pos, pwin->edge_width, pwin->title_height, xr.w, xr.h);
    xdg_positioner_set_anchor(xdg_pos, XDG_POSITIONER_ANCHOR_NONE);
    xdg_positioner_set_gravity(xdg_pos, XDG_POSITIONER_GRAVITY_NONE);
    xdg_positioner_set_constraint_adjustment(xdg_pos,
                                             XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_SLIDE_X |
                                                 XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_SLIDE_Y |
                                                 XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_FLIP_X |
                                                 XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_FLIP_Y);

    pwin->xdg_pop = xdg_surface_get_popup(psur->xdg_face, par_sur->xdg_face, xdg_pos);
    if (!pwin->xdg_pop) goto err_ret;

    //configure event
    xdg_popup_add_listener(pwin->xdg_pop, &xdg_popup_listener, pwin);
    xdg_positioner_destroy(xdg_pos);
    xdg_pos = NULL;

    if(pwin->sur_window)
    {
        WaylandFillSurface(pwin->sur_window, 0xFFFFFFFF, NULL);
    }

     if(pwin->sur_client)
    {
        WaylandFillSurface(pwin->sur_client, 0xFF000000, NULL);
    }

    //expose event
    frame_callback = wl_surface_frame(psur->raw_face);
    wl_callback_add_listener(frame_callback, &paint_listener, pwin);

    //mouse event
    wl_pointer_add_listener(pdisp->raw_mouse, &mouse_listener, pwin);

    //keyboard event
    wl_keyboard_add_listener(pdisp->raw_keybd, &key_listener, pwin);
    
    return pwin;
err_ret:

    if(xdg_pos) xdg_positioner_destroy(xdg_pos);

    if (pwin && pwin->xdg_pop) xdg_popup_destroy(pwin->xdg_pop);
    if (pwin && pwin->xdg_top) xdg_toplevel_destroy(pwin->xdg_top);

    if(pwin && pwin->sur_client) WaylandDestroySurface(pwin->sur_client);
    if(pwin && pwin->sur_window) WaylandDestroySurface(pwin->sur_window);

    xmem_free(pwin);

    return NULL;
}

void WaylandDestroyWindow(wayland_window* pwin)
{
    if (pwin->xdg_pop) xdg_popup_destroy(pwin->xdg_pop);
    if (pwin->xdg_top) xdg_toplevel_destroy(pwin->xdg_top);

    if(pwin->sur_client) WaylandDestroySurface(pwin->sur_client);
    if(pwin->sur_window) WaylandDestroySurface(pwin->sur_window);

	xmem_free(pwin);
}

void WaylandSetWindowProper(wayland_window* window, int atom, vword_t prop)
{
    if(atom < 0 || atom >= WAYLAND_MAX_ATOMS) return;

    window->atoms[atom] = prop;
}

vword_t WaylandGetWindowProper(wayland_window* window, int atom)
{
    if(atom < 0 || atom >= WAYLAND_MAX_ATOMS) return 0;

    return window->atoms[atom];
}

vword_t WaylandDelWindowProper(wayland_window* window, int atom)
{
    vword_t prop;

    if(atom < 0 || atom >= WAYLAND_MAX_ATOMS) return 0;

    prop = window->atoms[atom];
    window->atoms[atom] = 0;
    return prop;
}

bool_t WaylandIsWindow(wayland_window* pwin)
{
    return (pwin && pwin->sur_window) ? bool_true : bool_false;
}

bool_t WaylandShowWindow(wayland_window* window, bool_t bShow)
{
    (void)window;
    (void)bShow;

    return bool_true;
}

void WaylandUpdateWindow(wayland_window* pwin)
{
    xrect_t xr;

    if(pwin->sur_window) 
    {
        WaylandGetWindowRect(pwin, &xr);
        WaylandUpdateSurface(pwin->sur_window, &xr, bool_true);
    }

    if(pwin->sur_client)
    {
        WaylandGetClientRect(pwin, &xr);
        WaylandClientToScreen(pwin, (xpoint_t*)&xr);
        WaylandUpdateSurface(pwin->sur_client, &xr, bool_true);
    }
}

void WaylandInvalidRect(wayland_window* pwin, const xrect_t* pxr)
{
    xrect_t xr;

    xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));
    WaylandClientToScreen(pwin, (xpoint_t*)&xr);
    
    WaylandUpdateSurface(pwin->sur_client, &xr, bool_false);
}

void WaylandSetFocusWindow(wayland_window* pwin)
{
    wayland_display* pdisp = WaylandDefaultDisplay();

    if(pdisp->track_focus && pdisp->track_focus == pwin)
        return;

    if(pdisp->track_focus)
    {
        WaylandEventsAdd(pdisp->track_focus, WAYLAND_EVENT_KILL_FOCUS, 0, (vword_t)pdisp->track_focus);
    }

    pdisp->track_focus = pwin;
    WaylandEventsAdd(pwin, WAYLAND_EVENT_SET_FOCUS, 0, (vword_t)pwin);
}

wayland_window* WaylandGetFocusWindow(void)
{
    wayland_display* pdisp = WaylandDefaultDisplay();

    return pdisp->track_focus;
}

dword_t WaylandKeyboardState(void)
{
    wayland_display* pdisp = WaylandDefaultDisplay();

    return pdisp->track_mkey;
}

void WaylandMousePosition(xpoint_t* ppt)
{
    wayland_display* pdisp = WaylandDefaultDisplay();

    ppt->x = pdisp->track_xpos;
    ppt->y = pdisp->track_ypos;
}

wayland_surface* WaylandGetWindowSurface(wayland_window* pwin)
{
    return pwin->sur_window;
}

wayland_surface* WaylandGetClientSurface(wayland_window* pwin)
{
    return pwin->sur_client;
}

void WaylandGetScreenSize(xsize_t* pxs)
{
    wayland_display* pdisp = WaylandDefaultDisplay();
    dev_cap_t dev;

    WaylandGetDeviceCap(pdisp, &dev);

    pxs->w = dev.horz_res;
    pxs->h = dev.vert_res;
}

void WaylandGetDesktopRect(xrect_t* prt)
{
    wayland_display* pdisp = WaylandDefaultDisplay();
    dev_cap_t dev;

    WaylandGetDeviceCap(pdisp, &dev);

    prt->x = 0;
    prt->y = 0;
    prt->w = dev.horz_res;
    prt->h = dev.vert_res;
}

void WaylandGetWindowRect(wayland_window* pwin, xrect_t* prt)
{
    prt->x = pwin->x;
    prt->y = pwin->y;
    prt->w = pwin->width;
    prt->h = pwin->height;
}

void WaylandGetClientRect(wayland_window* pwin, xrect_t* prt)
{
    prt->x = 0;
    prt->y = 0;
    prt->w = pwin->width - 2 * pwin->edge_width;
    prt->h = pwin->height - pwin->title_height - pwin->edge_width;
}

void WaylandClientToScreen(wayland_window* pwin, xpoint_t* ppt)
{
    ppt->x += (pwin->x + pwin->edge_width);
    ppt->y += (pwin->y + pwin->title_height);
}

void WaylandScreenToClient(wayland_window* pwin, xpoint_t* ppt)
{
    ppt->x -= (pwin->x + pwin->edge_width);
    ppt->y -= (pwin->y + pwin->title_height);
}

void WaylandClientToWindow(wayland_window* pwin, xpoint_t* ppt)
{
    ppt->x += (pwin->x + pwin->edge_width);
    ppt->y += (pwin->y + pwin->title_height);
}

void WaylandWindowToClient(wayland_window* pwin, xpoint_t* ppt)
{
    ppt->x -= (pwin->x + pwin->edge_width);
    ppt->y -= (pwin->y + pwin->title_height);
}


