/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc context document

	@module	if_context.c | linux implement file

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


#ifdef XDU_SUPPORT_CONTEXT

static void wm_base_ping(void* data, struct xdg_wm_base* base, uint32_t serial) {
    xdg_wm_base_pong(base, serial);
}
static const struct xdg_wm_base_listener wm_base_listener = {
    .ping = wm_base_ping,
};

static void toplevel_configure(void* data, struct xdg_toplevel* tl, int32_t w, int32_t h, struct wl_array* states) {
    if (w > 0) win_w = w;
    if (h > 0) win_h = h;
}
static void toplevel_close(void* data, struct xdg_toplevel* tl) {
    running = false;
}
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure = toplevel_configure,
    .close = toplevel_close,
};

static int create_shm_file(size_t size) {
    // simple POSIX shm file that is immediately unlinked
    char name[64];
    snprintf(name, sizeof(name), "/wayland-shm-%d-%ld", getpid(), time(NULL));
    int fd = shm_open(name, O_CREAT | O_RDWR, 0600);
    if (fd < 0) return -1;
    shm_unlink(name);
    if (ftruncate(fd, (off_t)size) < 0) { close(fd); return -1; }
    return fd;
}

static void registry_global(void* data, struct wl_registry* reg, uint32_t name, const char* interface, uint32_t version) {
    if (strcmp(interface, "wl_compositor") == 0) {
        g_comp = wl_registry_bind(reg, name, &wl_compositor_interface, version < 4 ? version : 4);
    } else if (strcmp(interface, "wl_shm") == 0) {
        g_shm = wl_registry_bind(reg, name, &wl_shm_interface, 1);
    } else if (strcmp(interface, "xdg_wm_base") == 0) {
        g__base = wl_registry_bind(reg, name, &xdg_wm_base_interface, 3);
        xdg_wm_base_add_listener(g_base, &wm_base_listener, NULL);
    }
}
static void registry_global_remove(void* data, struct wl_registry* reg, uint32_t name) { (void)data; (void)reg; (void)name; }
static const struct wl_registry_listener registry_listener = {
    .global = registry_global,
    .global_remove = registry_global_remove,
};

int _context_startup(void)
{
    g_disp = wl_display_connect(NULL);
    g_regs = w_display_get_registry(dispaly)
    wl_registry_add_listener(registry, &registry_listener, NULL);
    wl_display_roundtrip(display); 

    int nVer = 0;
    char* dname;

    XInitThreads();
    
    dname = getenv("DISPLAY");
    
    g_display = XOpenDisplay(dname);

    if(!g_display) return (-1);

	return nVer;
}

void _context_cleanup(void)
{
    if (g_base) xdg_wm_base_destroyg_base);
    if (g_shm) wl_shm_destroy(g_shm);
    if (g_comp) wl_compositor_destroy(g_comp);
    if (g_regs) wl_registry_destroy(g_regs);
    if (g_disp) wl_display_disconnect(g_gisp);
}

visual_t _create_display_context(widget_t wt)
{
    NOP;
    
    return (visual_t)0;
}

visual_t _create_compatible_context(visual_t rdc, int cx, int cy)
{
   NOP;

   return (visual_t)0;
}

void _destroy_context(visual_t rdc)
{
    NOP;
}

void _get_device_caps(visual_t rdc, dev_cap_t* pcap)
{
    NOP;
}

void _render_context(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth)
{
    NOP;
}


float _pixel_metric(visual_t rdc)
{
	return LOGMMPERPT;
}

float _font_metric(visual_t rdc, const xfont_t* pxf)
{
	float pt = xstof(pxf->size);
	float pm = 0.0f;

	font_metric_by_pt(pt, &pm, NULL);

	return pm;
}

#endif //XDU_SUPPORT_CONTEXT
