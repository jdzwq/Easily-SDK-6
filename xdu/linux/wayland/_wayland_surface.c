/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc context document

	@module	wayland_surface.c | wayland implement file

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

#include <unistd.h>

static void _wm_base_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial)
{
    xdg_wm_base_pong(wm_base, serial);
}

static const struct xdg_wm_base_listener wm_base_listener = {
    .ping = _wm_base_ping
};

static void _xdg_surface_configure(void *data, struct xdg_surface *surface, uint32_t serial)
{
    (void)data;
    xdg_surface_ack_configure(surface, serial);
}

static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = _xdg_surface_configure
};

wayland_surface* WaylandCreateSurface(wayland_display* display, const xrect_t* pxr)
{
    wayland_display* pdisp = (wayland_display*)display;
    wayland_surface* psur;

    dev_cap_t devcap = {0};
    pix_cap_t pixcap = {0};
    int i, offset, stride;

    psur = (wayland_surface*)xmem_alloc(sizeof(wayland_surface));
    psur->display = display;
    psur->frame.x = pxr->x;
    psur->frame.y = pxr->y;
    psur->frame.w = pxr->w;
    psur->frame.h = pxr->h;
    
    WaylandGetDeviceCap(display, &devcap);
    WaylandGetPixelCap(display, &pixcap);
    stride = devcap.horz_res * pixcap.pixel_size;
    offset = (pxr->y * devcap.horz_res + pxr->x) * pixcap.pixel_size;

    psur->raw_buff = wl_shm_pool_create_buffer(pdisp->raw_pool, offset, pxr->w, pxr->h, stride, WL_SHM_FORMAT_ARGB8888);
    psur->raw_face = wl_compositor_create_surface(pdisp->raw_comp);
    wl_surface_attach(psur->raw_face, psur->raw_buff, 0, 0);
    
    psur->xdg_face = xdg_wm_base_get_xdg_surface(pdisp->xdg_base, psur->raw_face);
    xdg_surface_add_listener(psur->xdg_face, &xdg_surface_listener, psur);

    return psur;
err_ret:
 
    if(psur && psur->xdg_face) xdg_surface_destroy(psur->xdg_face);
    if(psur && psur->raw_face) wl_surface_destroy(psur->raw_face);
    if(psur && psur->raw_buff) wl_buffer_destroy(psur->raw_buff);
    
    xmem_free(psur);
    return NULL;
}

void WaylandDestroySurface(wayland_surface* surface)
{
    wayland_surface* psur = (wayland_surface*)surface;

    if(psur->xdg_face) xdg_surface_destroy(psur->xdg_face);
    if(psur->raw_face) wl_surface_destroy(psur->raw_face);
    if(psur->raw_buff) wl_buffer_destroy(psur->raw_buff);

    xmem_free(psur);
}

void WaylandUpdateSurface(wayland_surface* surface, const xrect_t* pxr, bool_t flash)
{
    wayland_surface* psur = (wayland_surface*)surface;

    if(!pxr) pxr = &psur->frame;

    wl_surface_damage_buffer(psur->raw_face, pxr->x, pxr->y, pxr->w, pxr->h);
    wl_surface_commit(psur->raw_face);

    WaylandFlashDisplay(psur->display, flash);
}

void WaylandFillSurface(wayland_surface* surface, int pixel, const xrect_t* pxr)
{
    wayland_surface* psur = (wayland_surface*)surface;
    wayland_display* pdisp = (wayland_display*)psur->display;
    
    dev_cap_t devcap = {0};
    pix_cap_t pixcap = {0};
    int i, offset, stride;

    void *map_ptr = NULL;
    int *shm_data = NULL;
    off_t map_offset;
    size_t map_len;
    long page_size;

    if(!pxr) pxr = &psur->frame;

    WaylandGetDeviceCap(psur->display, &devcap);
    WaylandGetPixelCap(psur->display, &pixcap);

    stride = devcap.horz_res * pixcap.pixel_size;
    offset = (pxr->y * devcap.horz_res + pxr->x) * pixcap.pixel_size;

    page_size = PAGE_SIZE;
    map_offset = (off_t)(offset / page_size) * page_size;
    map_len = (size_t)(offset - (int)map_offset) + (size_t)stride * (size_t)pxr->h;

    map_ptr = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED,
        pdisp->shm_fd, map_offset);
    if(map_ptr == MAP_FAILED) goto err_ret;
   
    shm_data = (int*)((unsigned char*)map_ptr + (offset - (int)map_offset));
    for(i=0;i<pxr->h;i++)
    {
        xmem_int((shm_data + i * stride / pixcap.pixel_size),  pixel, pxr->w);
    }
    munmap(map_ptr, map_len);

    return;
err_ret:

    if(map_ptr) munmap(map_ptr, map_len);

    return;
}

