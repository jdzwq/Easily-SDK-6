/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc context document

	@module	if_display.c | linux implement file

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

#define WAYLAND_IS_MODIFIER_KEY(key) ((key) == XKB_KEY_Shift_L || \
                                    (key) == XKB_KEY_Shift_R || \
                                    (key) == XKB_KEY_Control_L || \
                                    (key) == XKB_KEY_Control_R || \
                                    (key) == XKB_KEY_Alt_L || \
                                    (key) == XKB_KEY_Alt_R || \
                                    (key) == XKB_KEY_Meta_L || \
                                    (key) == XKB_KEY_Meta_R || \
                                    (key) == XKB_KEY_Caps_Lock)

static wayland_display* gw_display = NULL;

static void _handle_geometry(void *data, struct wl_output *output,
                            int32_t x, int32_t y, 
                            int32_t physical_width, int32_t physical_height, 
                            int32_t subpixel,
                            const char *make, const char *model, int32_t transform) 
{
    wayland_display* pdisp = (wayland_display*)data;
    dev_cap_t *pcap = &(pdisp->dispcap);

    pcap->horz_size = physical_width; //mm
    pcap->vert_size = physical_height; //mm

    pcap->horz_res = physical_width * LOGPTPERMM;
    pcap->vert_res = physical_height * LOGPTPERMM;
    
	pcap->horz_pixels = (int)MMPERINCH;
	pcap->vert_pixels = (int)MMPERINCH;

    pcap->horz_feed = 0;
    pcap->vert_feed = 0;
}

static void _handle_mode(void *data, struct wl_output *output,
    uint32_t flags, int32_t width, int32_t height, int32_t refresh)
{

    wayland_display* pdisp = (wayland_display*)data;
    dev_cap_t *pcap = &(pdisp->dispcap);

    if (flags & WL_OUTPUT_MODE_CURRENT) 
    {
        pcap->horz_res = width; 
        pcap->vert_res = height;

        pcap->horz_pixels = (int)MMPERINCH;
        pcap->vert_pixels = (int)MMPERINCH;

        pcap->horz_feed = 0;
        pcap->vert_feed = 0;
    }
}

static void _handle_done(void *data, struct wl_output *output) 
{
    NOP;
}

static void _handle_scale(void *data, struct wl_output *output, int32_t factor) 
{
    NOP;
}

static const struct wl_output_listener output_listener = {
    .geometry = _handle_geometry,
    .mode = _handle_mode,
    .done = _handle_done,
    .scale = _handle_scale,
};


static void seat_handle_capabilities(void *data, struct wl_seat *seat, uint32_t capabilities) 
{
    wayland_display* pdisp = (wayland_display*)data;

    if (capabilities & WL_SEAT_CAPABILITY_POINTER) 
    {
        pdisp->raw_mouse = wl_seat_get_pointer(seat);
    }

    if (capabilities & WL_SEAT_CAPABILITY_KEYBOARD)
    {
        pdisp->raw_keybd = wl_seat_get_keyboard(seat);
    }
}

static const struct wl_seat_listener seat_listener = {
    .capabilities = seat_handle_capabilities,
};

static void registry_handler(void *data,struct wl_registry *registry, uint32_t id,
    const char *interface,uint32_t version)
{
     wayland_display* pdisp = (wayland_display*)data;

    if (strcmp(interface, "wl_output") == 0) 
    {
        pdisp->raw_dev = wl_registry_bind(registry, id, &wl_output_interface, 1);
        wl_output_add_listener(pdisp->raw_dev, &output_listener, data);    
        wl_display_roundtrip(pdisp->raw_disp);
    }else if (strcmp(interface, "wl_seat") == 0) 
    {
        pdisp->raw_seat = wl_registry_bind(registry, id, &wl_seat_interface, 1);
        wl_seat_add_listener(pdisp->raw_seat, &seat_listener, data);
        wl_display_roundtrip(pdisp->raw_disp);
    }else if (strcmp(interface, "wl_shm") == 0) 
    {
        pdisp->raw_shm = wl_registry_bind(registry, id, &wl_shm_interface, 1);
    }else if (strcmp(interface, "wl_compositor") == 0) 
    {
        pdisp->raw_comp = wl_registry_bind(registry, id, &wl_compositor_interface, 4);
    }else if (strcmp(interface, "wl_subcompositor") == 0) 
    {
        pdisp->sub_comp = wl_registry_bind(registry, id, &wl_subcompositor_interface, 1);
    }else if (strcmp(interface, "xdg_wm_base") == 0) 
    {
        pdisp->xdg_base = wl_registry_bind(registry, id, &xdg_wm_base_interface, 1);
    }
}

static void registry_remover(void *data, struct wl_registry *registry, uint32_t id)
{
    NOP;
}

static const struct wl_registry_listener registry_listener = {
    registry_handler,
    registry_remover
};

static void _wm_base_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial)
{
    xdg_wm_base_pong(wm_base, serial);
}

static const struct xdg_wm_base_listener wm_base_listener = {
    .ping = _wm_base_ping
};


static void _mouse_enter(void *data, struct wl_pointer *pointer, uint32_t serial,
                          struct wl_surface *surface, wl_fixed_t sx, wl_fixed_t sy) 
{
    wayland_display* pdisp = (wayland_display*)data;
    wayland_window* pwin = (wayland_window*)wl_surface_get_user_data(surface);
    if(!pwin) return;

    pdisp->track_xpos = WAYLAND_FIX_TO_INT(sx);
    pdisp->track_ypos = WAYLAND_FIX_TO_INT(sy);
    pdisp->track_mouse = surface;

    if(pwin->sur_window && pwin->sur_window->raw_face == surface)
    {
        if ((pwin->evt_mask & WAYLAND_EVENT_MASK_NOTCLI) && pwin->evt_proc)
        {
            (*pwin->evt_proc)(pwin, WAYLAND_EVENT_HITTEST, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
        }
    }else if(pwin->sur_client && pwin->sur_client->raw_face == surface)
    {
        if ((pwin->evt_mask & WAYLAND_EVENT_MASK_POINTER) && pwin->evt_proc)
        {
            (*pwin->evt_proc)(pwin, WAYLAND_EVENT_MOUSE_ENTER, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
        }
    }
}

static void _mouse_leave(void *data, struct wl_pointer *pointer, uint32_t serial,
                          struct wl_surface *surface) 
{
    wayland_display* pdisp = (wayland_display*)data;
    wayland_window* pwin = (wayland_window*)wl_surface_get_user_data(surface);
    if(!pwin) return;
    
    if(pwin->sur_window && pwin->sur_window->raw_face == surface)
    {
        if ((pwin->evt_mask & WAYLAND_EVENT_MASK_NOTCLI) && pwin->evt_proc)
        {
            (*pwin->evt_proc)(pwin, WAYLAND_EVENT_HITTEST, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
        }
    }else if(pwin->sur_client && pwin->sur_client->raw_face == surface)
    {
        if ((pwin->evt_mask & WAYLAND_EVENT_MASK_POINTER) && pwin->evt_proc)
        {
            (*pwin->evt_proc)(pwin, WAYLAND_EVENT_MOUSE_LEAVE, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
        }
    }

    pdisp->track_xpos = 0;
    pdisp->track_ypos = 0;
    pdisp->track_mouse = NULL;
}

static void _mouse_motion(void *data, struct wl_pointer *pointer, uint32_t time,
                           wl_fixed_t sx, wl_fixed_t sy) 
{
    wayland_display* pdisp = (wayland_display*)data;
    wayland_window* pwin = (pdisp->track_mouse) ? (wayland_window*)wl_surface_get_user_data(pdisp->track_mouse) : NULL;
    if(!pwin) return;
    
    pdisp->track_xpos = WAYLAND_FIX_TO_INT(sx);
    pdisp->track_ypos = WAYLAND_FIX_TO_INT(sy);

    if(pwin->sur_window && pwin->sur_window->raw_face == pdisp->track_mouse)
    {
        if ((pwin->evt_mask & WAYLAND_EVENT_MASK_NOTCLI) && pwin->evt_proc)
        {
           (*pwin->evt_proc)(pwin, WAYLAND_EVENT_NCMOUSE_MOVE, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
        }
    }else if(pwin->sur_client && pwin->sur_client->raw_face == pdisp->track_mouse)
    {
        if ((pwin->evt_mask & WAYLAND_EVENT_MASK_POINTER) && pwin->evt_proc)
        {
            (*pwin->evt_proc)(pwin, WAYLAND_EVENT_MOUSE_MOVE, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
        }
    }
}

static void _mouse_button(void *data, struct wl_pointer *pointer, uint32_t serial,
                            uint32_t time, uint32_t button, uint32_t state) 
{
    wayland_display* pdisp = (wayland_display*)data;
    wayland_window* pwin = (pdisp->track_mouse) ? (wayland_window*)wl_surface_get_user_data(pdisp->track_mouse) : NULL;
    if(!pwin) return;
    
    if(state == WL_POINTER_BUTTON_STATE_PRESSED)
    {
        if (pwin->sur_window && pwin->sur_window->raw_face == pdisp->track_mouse)
        {
            if ((pwin->evt_mask & WAYLAND_EVENT_MASK_NOTCLI) && pwin->evt_proc)
            {
                if (button == BTN_LEFT)
                    (*pwin->evt_proc)(pwin, WAYLAND_EVENT_NCLBUTTON_DOWN, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
                else if (button == BTN_RIGHT)
                    (*pwin->evt_proc)(pwin, WAYLAND_EVENT_NCRBUTTON_DOWN, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
            }
        }
        else if (pwin->sur_client && pwin->sur_client->raw_face == pdisp->track_mouse)
        {
            if ((pwin->evt_mask & WAYLAND_EVENT_MASK_POINTER) && pwin->evt_proc)
            {
                if (button == BTN_LEFT)
                    (*pwin->evt_proc)(pwin, WAYLAND_EVENT_LBUTTON_DOWN, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
                else if (button == BTN_RIGHT)
                    (*pwin->evt_proc)(pwin, WAYLAND_EVENT_RBUTTON_DOWN, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
            }
        }
    }else
    {
        if (pwin->sur_window && pwin->sur_window->raw_face == pdisp->track_mouse)
        {
            if ((pwin->evt_mask & WAYLAND_EVENT_MASK_NOTCLI) && pwin->evt_proc)
            {
                if (button == BTN_LEFT)
                    (*pwin->evt_proc)(pwin, WAYLAND_EVENT_NCLBUTTON_UP, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
                else if (button == BTN_RIGHT)
                    (*pwin->evt_proc)(pwin, WAYLAND_EVENT_NCRBUTTON_UP, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
            }
        }
        else if(pwin->sur_client && pwin->sur_client->raw_face == pdisp->track_mouse)
        {
            if ((pwin->evt_mask & WAYLAND_EVENT_MASK_POINTER) && pwin->evt_proc)
            {
                if (button == BTN_LEFT)
                    (*pwin->evt_proc)(pwin, WAYLAND_EVENT_LBUTTON_UP, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
                else if (button == BTN_RIGHT)
                    (*pwin->evt_proc)(pwin, WAYLAND_EVENT_RBUTTON_UP, 0, MAKEVWORD(pdisp->track_xpos, pdisp->track_ypos));
            }
        }
    }
}

static void _mouse_axis(void *data, struct wl_pointer *pointer, uint32_t time,
                         uint32_t axis, wl_fixed_t value) 
{
    wayland_display* pdisp = (wayland_display*)data;
    wayland_window* pwin = (pdisp->track_mouse) ? (wayland_window*)wl_surface_get_user_data(pdisp->track_mouse) : NULL;
    if(!pwin) return;

    if (pwin->sur_window && pwin->sur_window->raw_face == pdisp->track_mouse)
    {
        NOP;
    }
    else if (pwin->sur_client && pwin->sur_client->raw_face == pdisp->track_mouse)
    {
        if ((pwin->evt_mask & WAYLAND_EVENT_MASK_TOUCHPAD) && pwin->evt_proc)
        {
            if (axis == WL_POINTER_AXIS_VERTICAL_SCROLL)
                (*pwin->evt_proc)(pwin, WAYLAND_EVENT_MOUSE_WHEEL, 0, (vword_t)WAYLAND_FIX_TO_INT(value));
            else if (axis == WL_POINTER_AXIS_HORIZONTAL_SCROLL)
                (*pwin->evt_proc)(pwin, WAYLAND_EVENT_MOUSE_WHEEL, 1, (vword_t)WAYLAND_FIX_TO_INT(value));
        }
    }
}

static const struct wl_pointer_listener mouse_listener = {
    .enter = _mouse_enter,
    .leave = _mouse_leave,
    .motion = _mouse_motion,
    .button = _mouse_button,
    .axis = _mouse_axis,
};

static void _input_keymap(void *data, struct wl_keyboard *keyboard, uint32_t format, int fd, uint32_t size) 
{
    // Handle keymap (for input method, usually just close fd if not used)
    wayland_display* pdisp = (wayland_display*)data;

    void *map;

    if (format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1) 
    { 
        close(fd); 
        return; 
    }

    if (!pdisp->xkb_ctx) 
    {
        pdisp->xkb_ctx = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
    }

    map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) 
    {
         close(fd); 
         return; 
    }

    if (pdisp->xkb_map) 
    { 
        xkb_keymap_unref(pdisp->xkb_map); 
        pdisp->xkb_map = NULL; 
    }

    if (pdisp->xkb_state) 
    { 
        xkb_state_unref(pdisp->xkb_state); 
        pdisp->xkb_state = NULL; 
    }

    pdisp->xkb_map = xkb_keymap_new_from_string(pdisp->xkb_ctx, 
                                            (const char*)map,
                                            XKB_KEYMAP_FORMAT_TEXT_V1, 
                                            XKB_KEYMAP_COMPILE_NO_FLAGS);
    if (pdisp->xkb_map)
    {
        pdisp->xkb_state = xkb_state_new(pdisp->xkb_map);
    }

    munmap(map, size);
    close(fd);
}

static void _input_enter(void *data, struct wl_keyboard *keyboard, uint32_t serial, struct wl_surface *surface, struct wl_array *keys) 
{
    wayland_display* pdisp = (wayland_display*)data;
    wayland_window* pwin = (wayland_window*)wl_surface_get_user_data(surface);
    if(!pwin) return;

    pdisp->track_input = surface;

    if (pwin->sur_window && pwin->sur_window->raw_face == surface)
    {
        if ((pwin->evt_mask & WAYLAND_EVENT_MASK_KEYBOARD) && pwin->evt_proc)
        {
            (*pwin->evt_proc)(pwin, WAYLAND_EVENT_ACTIVATE, 1, (vword_t)NULL);
        }
    }
}

static void _input_leave(void *data, struct wl_keyboard *keyboard, uint32_t serial, struct wl_surface *surface) 
{
    wayland_display* pdisp = (wayland_display*)data;
    wayland_window* pwin = (wayland_window*)wl_surface_get_user_data(surface);
    if(!pwin) return;

    if (pwin->sur_window && pwin->sur_window->raw_face == surface)
    {
        if(pwin->track_focus)
        {
            if ((pwin->track_focus->evt_mask & WAYLAND_EVENT_MASK_KEYBOARD) && pwin->track_focus->evt_proc)
            {
                (*pwin->track_focus->evt_proc)(pwin->track_focus, WAYLAND_EVENT_KILL_FOCUS, 0, (vword_t)NULL);
            }
            pwin->track_focus = NULL;
        }

        if ((pwin->evt_mask & WAYLAND_EVENT_MASK_KEYBOARD) && pwin->evt_proc)
        {
            (*pwin->evt_proc)(pwin, WAYLAND_EVENT_ACTIVATE, 0, (vword_t)NULL);
        }
    }
  
    pdisp->track_input = NULL;
}

static void _input_modify(void *data, struct wl_keyboard *keyboard, uint32_t serial, uint32_t mods_depressed, uint32_t mods_latched, uint32_t mods_locked, uint32_t group) 
{
    // Modifier keys (shift, ctrl, etc.)
    wayland_display* pdisp = (wayland_display*)data;

    const char *meta_names[] = { "Mod4", "Super", "Meta", "Win", "Hyper", NULL };
    const char **nm;
    xkb_mod_index_t idx;

    if (pdisp->xkb_state) 
    {
        xkb_state_update_mask(pdisp->xkb_state, mods_depressed, mods_latched, mods_locked, 0, 0, group);
    }

    pdisp->track_mkey = 0;

    if (pdisp->xkb_map && pdisp->xkb_state) 
    {
        idx = xkb_keymap_mod_get_index(pdisp->xkb_map, "Shift");
        if (idx && xkb_state_mod_index_is_active(pdisp->xkb_state, idx, XKB_STATE_MODS_DEPRESSED | XKB_STATE_MODS_LATCHED))
        {
            pdisp->track_mkey |= WAYLAND_STATE_SHIFT;
        }

        idx = xkb_keymap_mod_get_index(pdisp->xkb_map, "Control");
        if (idx && xkb_state_mod_index_is_active(pdisp->xkb_state, idx, XKB_STATE_MODS_DEPRESSED | XKB_STATE_MODS_LATCHED))
        {
            pdisp->track_mkey |= WAYLAND_STATE_CONTROL;
        }

        idx = xkb_keymap_mod_get_index(pdisp->xkb_map, "Alt");
        if (!idx) idx = xkb_keymap_mod_get_index(pdisp->xkb_map, "Mod1");
        if (idx && xkb_state_mod_index_is_active(pdisp->xkb_state, idx, XKB_STATE_MODS_DEPRESSED | XKB_STATE_MODS_LATCHED))
        {
            pdisp->track_mkey |= WAYLAND_STATE_ALT;
        }

        for (nm = meta_names; *nm; ++nm) 
        {
            idx = xkb_keymap_mod_get_index(pdisp->xkb_map, *nm);
            if (idx && xkb_state_mod_index_is_active(pdisp->xkb_state, idx, XKB_STATE_MODS_DEPRESSED | XKB_STATE_MODS_LATCHED)) 
            {
                pdisp->track_mkey |= WAYLAND_STATE_META;
                break;
            }
        }
    }
}

static void _input_press(void *data, struct wl_keyboard *keyboard, uint32_t serial, uint32_t time, uint32_t key, uint32_t state) 
{
    wayland_display* pdisp = (wayland_display*)data;
    wayland_window* pwin = (pdisp->track_input)? (wayland_window*)wl_surface_get_user_data(pdisp->track_input) : NULL;

    xkb_keycode_t xkb_key;
    xkb_keysym_t sym;
    wchar_t wc = 0;

    if(!pwin) return;
    if(!pdisp->xkb_state) return;
    
    xkb_key = (xkb_keycode_t)(key + 8);
    sym = xkb_state_key_get_one_sym(pdisp->xkb_state, xkb_key);
    if (!sym || WAYLAND_IS_MODIFIER_KEY(sym)) return;

    if (pwin->sur_window && pwin->sur_window->raw_face == pdisp->track_input)
    {
        NOP;
    }
    else if (pwin->sur_client && pwin->sur_client->raw_face == pdisp->track_input)
    {
       if (state == WL_KEYBOARD_KEY_STATE_PRESSED)
        {
            if ((pwin->evt_mask & WAYLAND_EVENT_MASK_KEYBOARD) && pwin->evt_proc)
            {
                (*pwin->evt_proc)(pwin, WAYLAND_EVENT_KEY_DOWN, sym | pdisp->track_mkey, (vword_t)time);
            }
        }
        else
        {
            if ((pwin->evt_mask & WAYLAND_EVENT_MASK_KEYBOARD) && pwin->evt_proc)
            {
                (*pwin->evt_proc)(pwin, WAYLAND_EVENT_KEY_UP, sym | pdisp->track_mkey, (vword_t)time);
            }

            wc = xkb_state_key_get_utf32(pdisp->xkb_state, xkb_key);
            if (wc)
            {
                if ((pwin->evt_mask & WAYLAND_EVENT_MASK_KEYBOARD) && pwin->evt_proc)
                    (*pwin->evt_proc)(pwin, WAYLAND_EVENT_WCHAR, (dword_t)wc, 0);
            }
        }
    }
}

static const struct wl_keyboard_listener input_listener = {
    .keymap = _input_keymap,
    .enter = _input_enter,
    .leave = _input_leave,
    .key = _input_press,
    .modifiers = _input_modify,
    .repeat_info = NULL // (optional, protocol version >= 4)
};

//////////////////////////////////////////////////////////////////////////////////////

bool_t WaylandConnect(void)
{
    if(gw_display) return bool_true;

    gw_display = WaylandCreateDisplay();

    return (gw_display) ? bool_true : bool_false;
}

void WaylandDisconnect(void)
{
    if(gw_display) WaylandDestroyDisplay(gw_display);
    gw_display = NULL;
}

wayland_display* WaylandDefaultDisplay(void)
{
    return gw_display;
}

wayland_display* WaylandCreateDisplay(void)
{
    wayland_display* pdisp = NULL;

    struct wl_registry *registry = NULL;
    char template[] = "/tmp/wayland-shm-buffer-XXXXXX";
    int stride;

    pdisp = (wayland_display*)xmem_alloc(sizeof(wayland_display));
    pdisp->pixcap.pixel_depth = 32;
    pdisp->pixcap.pixel_mode = WAYLAND_COLOR_MODE_ARGB32;
    pdisp->pixcap.pixel_size = 4;
    pdisp->pixcap.pixel_base = 0xFF000000;

    pdisp->raw_disp = wl_display_connect(NULL);
    if(!pdisp->raw_disp) goto err_ret;

    registry = wl_display_get_registry(pdisp->raw_disp);
    wl_registry_add_listener(registry, &registry_listener, pdisp);
    wl_display_roundtrip(pdisp->raw_disp);
    wl_registry_destroy(registry);
    registry = NULL;

    pdisp->shm_fd = mkstemp(template);
    if (pdisp->shm_fd < 0) goto err_ret;
   
    unlink(template);

    stride = pdisp->dispcap.horz_res * 4;
    pdisp->shm_size = stride * pdisp->dispcap.vert_res;

    if (ftruncate(pdisp->shm_fd, pdisp->shm_size) < 0) goto err_ret;

    pdisp->raw_pool = wl_shm_create_pool(pdisp->raw_shm, pdisp->shm_fd, pdisp->shm_size);

    if(pdisp->xdg_base)
    {
        xdg_wm_base_add_listener(pdisp->xdg_base, &wm_base_listener, pdisp);
    }
    
    //mouse event
    if(pdisp->raw_mouse)
    {
        wl_pointer_add_listener(pdisp->raw_mouse, &mouse_listener, pdisp);
    }

    //keyboard event
    if(pdisp->raw_keybd)
    {
        wl_keyboard_add_listener(pdisp->raw_keybd, &input_listener, pdisp);
    }

    return pdisp;
err_ret:

    if(registry) wl_registry_destroy(registry);

    if(pdisp && pdisp->raw_mouse) wl_pointer_destroy(pdisp->raw_mouse);
    if(pdisp && pdisp->raw_keybd) wl_keyboard_destroy(pdisp->raw_keybd);
    if(pdisp && pdisp->raw_seat) wl_seat_destroy(pdisp->raw_seat);

    if(pdisp && pdisp->raw_dev) wl_output_destroy(pdisp->raw_dev);

    if(pdisp && pdisp->xdg_base) xdg_wm_base_destroy(pdisp->xdg_base);
    if(pdisp && pdisp->raw_comp) wl_compositor_destroy(pdisp->raw_comp);
    if(pdisp && pdisp->sub_comp) wl_subcompositor_destroy(pdisp->sub_comp);
    
    if(pdisp && pdisp->raw_pool) wl_shm_pool_destroy(pdisp->raw_pool);
    if(pdisp && pdisp->shm_fd >= 0) close(pdisp->shm_fd);
    if(pdisp && pdisp->raw_shm) wl_shm_destroy(pdisp->raw_shm);
    if(pdisp && pdisp->raw_disp) wl_display_disconnect(pdisp->raw_disp);

    if(pdisp) xmem_free(pdisp);

    return NULL;
}

void WaylandDestroyDisplay(wayland_display* pdisp)
{
    if(pdisp->raw_mouse) wl_pointer_destroy(pdisp->raw_mouse);
    if(pdisp->raw_keybd) wl_keyboard_destroy(pdisp->raw_keybd);
    if(pdisp->raw_seat) wl_seat_destroy(pdisp->raw_seat);

    if(pdisp->raw_dev) wl_output_destroy(pdisp->raw_dev);

    if(pdisp->xdg_base) xdg_wm_base_destroy(pdisp->xdg_base);
    if(pdisp->raw_comp) wl_compositor_destroy(pdisp->raw_comp);
    if(pdisp->sub_comp) wl_subcompositor_destroy(pdisp->sub_comp);

    if(pdisp->raw_pool) wl_shm_pool_destroy(pdisp->raw_pool);
    if(pdisp->raw_shm) wl_shm_destroy(pdisp->raw_shm);
    if(pdisp->shm_fd >= 0) close(pdisp->shm_fd);
    if(pdisp->raw_disp) wl_display_disconnect(pdisp->raw_disp);

    xmem_free(pdisp);
}

bool_t WaylandDispatchDisplay(wayland_display* pdisp)
{
    if(wl_display_dispatch_pending(pdisp->raw_disp) > 0)
        return bool_true;

    return (wl_display_dispatch(pdisp->raw_disp) < 0)? bool_false : bool_true;
}

void WaylandFlashDisplay(wayland_display* pdisp, bool_t bWait)
{
    if(bWait) 
        wl_display_roundtrip(pdisp->raw_disp);
    else
        wl_display_flush(pdisp->raw_disp);
}

void WaylandGetDeviceCap(wayland_display* pdisp, dev_cap_t* pcap)
{
    xmem_copy((void*)pcap, (void*)&pdisp->dispcap, sizeof(dev_cap_t));
}

void WaylandGetPixelCap(wayland_display* pdisp, pix_cap_t* pcap)
{
    xmem_copy((void*)pcap, (void*)&pdisp->pixcap, sizeof(pix_cap_t));
}
