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
    }if (strcmp(interface, "wl_compositor") == 0) 
    {
        pdisp->raw_comp = wl_registry_bind(registry, id, &wl_compositor_interface, 4);
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

    return pdisp;
err_ret:

    if(registry) wl_registry_destroy(registry);

    if(pdisp && pdisp->xdg_base) xdg_wm_base_destroy(pdisp->xdg_base);
    if(pdisp && pdisp->raw_comp) wl_compositor_destroy(pdisp->raw_comp);
    
    if(pdisp && pdisp->raw_pool) wl_shm_pool_destroy(pdisp->raw_pool);
    if(pdisp && pdisp->shm_fd >= 0) close(pdisp->shm_fd);
    if(pdisp && pdisp->raw_shm) wl_shm_destroy(pdisp->raw_shm);
    if(pdisp && pdisp->raw_disp) wl_display_disconnect(pdisp->raw_disp);

    if(pdisp) xmem_free(pdisp);

    return NULL;
}

void WaylandDestroyDisplay(wayland_display* pdisp)
{
    if(pdisp->xdg_base) xdg_wm_base_destroy(pdisp->xdg_base);
    if(pdisp->raw_comp) wl_compositor_destroy(pdisp->raw_comp);

    if(pdisp->raw_pool) wl_shm_pool_destroy(pdisp->raw_pool);
    if(pdisp->raw_shm) wl_shm_destroy(pdisp->raw_shm);
    if(pdisp->shm_fd >= 0) close(pdisp->shm_fd);
    if(pdisp->raw_disp) wl_display_disconnect(pdisp->raw_disp);

    xmem_free(pdisp);
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
