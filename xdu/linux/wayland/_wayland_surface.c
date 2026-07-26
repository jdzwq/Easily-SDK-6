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

void _surface_paint(void *data, struct wl_callback *callback, uint32_t time);

static const struct wl_callback_listener paint_listener = {
    .done = _surface_paint
};

void _surface_paint(void *data, struct wl_callback *callback, uint32_t time) 
{
    wayland_surface* psur = (data)? (wayland_surface*)data : NULL;
	wayland_window* pwin = (psur)? (wayland_window*)wl_surface_get_user_data(psur->raw_face) : NULL;

	struct wl_callback *frame_callback;
	xrect_t rt = {0};

	if (!pwin) return;

    if((pwin->evt_mask & WAYLAND_EVENT_MASK_EXPOSE)  && pwin->evt_proc)
    {
        (*pwin->evt_proc)(pwin, WAYLAND_EVENT_EXPOSE, 0, (vword_t)&rt);
    }
	
	psur = pwin->sur_client;

    wl_callback_destroy(callback);
    frame_callback = wl_surface_frame(psur->raw_face);
    wl_callback_add_listener(frame_callback, &paint_listener, data);

    WaylandGetClientRect(pwin, &rt);
	WaylandClientToScreen(pwin, (xpoint_t*)&rt);
    wl_surface_damage(psur->raw_face, rt.x, rt.y, rt.w, rt.h);
    wl_surface_commit(psur->raw_face);
}

static void _toplevel_configure(void *data, struct xdg_toplevel *top, int32_t w, int32_t h, struct wl_array *states)
{
    wayland_surface* psur = (data)? (wayland_surface*)data : NULL;
	wayland_window* pwin = (psur)? (wayland_window*)wl_surface_get_user_data(psur->raw_face) : NULL;

    uint32_t *state;

    if (!pwin) return;

    wl_array_for_each(state, states) 
    {
        switch (*state)
        {
        case XDG_TOPLEVEL_STATE_MAXIMIZED:
            if((pwin->evt_mask & WAYLAND_EVENT_MASK_CONFIG) && pwin->evt_proc)
            {
                (*pwin->evt_proc)(pwin, WAYLAND_EVENT_SIZE, WS_SHOW_MAXIMIZE, MAKEVWORD(w, h));
            }
            break;
        case XDG_TOPLEVEL_STATE_FULLSCREEN:
            if((pwin->evt_mask & WAYLAND_EVENT_MASK_CONFIG) && pwin->evt_proc)
            {
                (*pwin->evt_proc)(pwin, WAYLAND_EVENT_SIZE, WS_SHOW_FULLSCREEN, MAKEVWORD(w, h));
            }
            break;
        case XDG_TOPLEVEL_STATE_RESIZING:
            if((pwin->evt_mask & WAYLAND_EVENT_MASK_CONFIG) && pwin->evt_proc)
            {
                (*pwin->evt_proc)(pwin, WAYLAND_EVENT_SIZE, WS_SHOW_NORMAL, MAKEVWORD(w, h));
            }
            break;
        //case XDG_TOPLEVEL_STATE_ACTIVATED:
            /*if((pwin->evt_mask & WAYLAND_EVENT_MASK_CONFIG) && pwin->evt_proc)
            {
                (*pwin->evt_proc)(pwin, WAYLAND_EVENT_ACTIVATE, 1, (vword_t)NULL);
            }
            break;*/
        }
    }
}

static void _toplevel_close(void *data, struct xdg_toplevel *top)
{
    wayland_surface* psur = (data)? (wayland_surface*)data : NULL;
	wayland_window* pwin = (psur)? (wayland_window*)wl_surface_get_user_data(psur->raw_face) : NULL;

    if (!pwin) return;

    if((pwin->evt_mask & WAYLAND_EVENT_MASK_MAPING) && pwin->evt_proc)
    {
        (*pwin->evt_proc)(pwin, WAYLAND_EVENT_DESTROY, 0, (vword_t)NULL);
    }
}

static const struct xdg_toplevel_listener xdg_toplevel_listener = {
    .configure = _toplevel_configure,
    .close = _toplevel_close,
};

static void _popup_configure(void *data, struct xdg_popup *popup, int32_t x, int32_t y, int32_t width, int32_t height)
{
    wayland_surface* psur = (data)? (wayland_surface*)data : NULL;
	wayland_window* pwin = (psur)? (wayland_window*)wl_surface_get_user_data(psur->raw_face) : NULL;

    if (!pwin) return;

    if((pwin->evt_mask & WAYLAND_EVENT_MASK_CONFIG) && pwin->evt_proc)
    {
        (*pwin->evt_proc)(pwin, WAYLAND_EVENT_SIZE, WS_SHOW_NORMAL, MAKEVWORD(width, height));
    }
}

static void _popup_done(void *data, struct xdg_popup *popup)
{
    wayland_surface* psur = (data)? (wayland_surface*)data : NULL;
	wayland_window* pwin = (psur)? (wayland_window*)wl_surface_get_user_data(psur->raw_face) : NULL;

    if (!pwin) return;

    if((pwin->evt_mask & WAYLAND_EVENT_MASK_MAPING) && pwin->evt_proc)
    {
        (*pwin->evt_proc)(pwin, WAYLAND_EVENT_CLOSE, 0, (vword_t)NULL);
    }
}

static const struct xdg_popup_listener xdg_popup_listener = {
    .configure = _popup_configure,
    .popup_done = _popup_done,
};

static void _xdg_surface_configure(void *data, struct xdg_surface *surface, uint32_t serial)
{
    (void)data;
    xdg_surface_ack_configure(surface, serial);
}

static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = _xdg_surface_configure
};

static struct wl_buffer* _WaylandCreateBuffer(wayland_display* display, const xrect_t* pxr)
{
    wayland_display* pdisp = (wayland_display*)display;

    dev_cap_t devcap = {0};
    pix_cap_t pixcap = {0};
    int i, offset, stride;

    WaylandGetDeviceCap(display, &devcap);
    WaylandGetPixelCap(display, &pixcap);
    stride = devcap.horz_res * pixcap.pixel_size;
    offset = (pxr->y * devcap.horz_res + pxr->x) * pixcap.pixel_size;

    return wl_shm_pool_create_buffer(pdisp->raw_pool, offset, pxr->w, pxr->h, stride, WL_SHM_FORMAT_ARGB8888);
}

wayland_surface* WaylandCreateTopSurface(wayland_display* display, const xrect_t* pxr)
{
    wayland_display* pdisp = (display) ? display : WaylandDefaultDisplay();
    wayland_surface* psur;

    psur = (wayland_surface*)xmem_alloc(sizeof(wayland_surface));
    psur->type = WAYLAND_WSURFACE_TYPE_TOP;
    psur->display = pdisp;
    psur->parent = NULL;
    psur->frame.x = pxr->x;
    psur->frame.y = pxr->y;
    psur->frame.w = pxr->w;
    psur->frame.h = pxr->h;

    psur->raw_face = wl_compositor_create_surface(pdisp->raw_comp);
    psur->xdg_face = xdg_wm_base_get_xdg_surface(pdisp->xdg_base, psur->raw_face);
    xdg_surface_add_listener(psur->xdg_face, &xdg_surface_listener, psur);

    psur->xdg_top = xdg_surface_get_toplevel(psur->xdg_face);
    if (!psur->xdg_top)
        goto err_ret;

    // configure event
    xdg_toplevel_add_listener(psur->xdg_top, &xdg_toplevel_listener, psur);
    // xdg_toplevel_set_title(psur->xdg_top, title ? title : "Easily");
    // xdg_toplevel_set_max_size(psur->xdg_top, gw_scrcap.horz_res, gw_scrcap.vert_res);
    // xdg_toplevel_set_min_size(psur->xdg_top, xr.w, xr.h);
    xdg_surface_set_window_geometry(psur->xdg_face, 0, 0, psur->frame.w, psur->frame.h);

    return psur;
err_ret:
 
    if(psur && psur->xdg_top) xdg_toplevel_destroy(psur->xdg_top);
    if(psur && psur->xdg_face) xdg_surface_destroy(psur->xdg_face);
    if(psur && psur->raw_face) wl_surface_destroy(psur->raw_face);
    if(psur && psur->raw_buff) wl_buffer_destroy(psur->raw_buff);
    
    xmem_free(psur);
    return NULL;
}

wayland_surface* WaylandCreatePopSurface(wayland_surface* parent, const xrect_t* pxr)
{
    wayland_display* pdisp = (parent) ? parent->display : WaylandDefaultDisplay();
    wayland_surface* psur;

    struct xdg_positioner *xdg_pos = NULL;

    if(!parent) return NULL;

    psur = (wayland_surface*)xmem_alloc(sizeof(wayland_surface));
    psur->type = WAYLAND_SURFACE_TYPE_POP;
    psur->display = pdisp;
    psur->parent = parent;
    psur->frame.x = pxr->x;
    psur->frame.y = pxr->y;
    psur->frame.w = pxr->w;
    psur->frame.h = pxr->h;

    psur->raw_face = wl_compositor_create_surface(pdisp->raw_comp);
    psur->xdg_face = xdg_wm_base_get_xdg_surface(pdisp->xdg_base, psur->raw_face);
    xdg_surface_add_listener(psur->xdg_face, &xdg_surface_listener, psur);

    xdg_pos = xdg_wm_base_create_positioner(pdisp->xdg_base);
    if (!xdg_pos) goto err_ret;

    xdg_positioner_set_anchor_rect(xdg_pos, pxr->x, pxr->y, psur->frame.w, psur->frame.h);
    xdg_positioner_set_offset(xdg_pos, 0, 0);
    xdg_positioner_set_size(xdg_pos, psur->frame.w, psur->frame.h);
    xdg_positioner_set_anchor(xdg_pos, XDG_POSITIONER_ANCHOR_NONE);
    xdg_positioner_set_gravity(xdg_pos, XDG_POSITIONER_GRAVITY_NONE);
    xdg_positioner_set_constraint_adjustment(xdg_pos,
                                             XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_SLIDE_X |
                                                 XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_SLIDE_Y |
                                                 XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_FLIP_X |
                                                 XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_FLIP_Y);

    psur->xdg_pop = xdg_surface_get_popup(psur->xdg_face, parent->xdg_face, xdg_pos);
    if (!psur->xdg_pop) goto err_ret;

    //configure event
    xdg_popup_add_listener(psur->xdg_pop, &xdg_popup_listener, psur);
    xdg_positioner_destroy(xdg_pos);
    xdg_pos = NULL;

    return psur;
err_ret:
 
    if(psur && psur->xdg_pop) xdg_popup_destroy(psur->xdg_pop);
    if(psur && psur->xdg_face) xdg_surface_destroy(psur->xdg_face);
    if(psur && psur->raw_face) wl_surface_destroy(psur->raw_face);
    if(psur && psur->raw_buff) wl_buffer_destroy(psur->raw_buff);
    
    xmem_free(psur);
    return NULL;
}

wayland_surface* WaylandCreateSubSurface(wayland_surface* parent, const xrect_t* pxr)
{
    wayland_display* pdisp = (parent) ? parent->display : WaylandDefaultDisplay();
    wayland_surface* psur;

    if(!parent) return NULL;

    psur = (wayland_surface*)xmem_alloc(sizeof(wayland_surface));
    psur->type = WAYLAND_SURFACE_TYPE_SUB;
    psur->display = pdisp;
    psur->parent = parent;
    psur->frame.x = parent->frame.x + pxr->x;
    psur->frame.y = parent->frame.y + pxr->y;
    psur->frame.w = pxr->w;
    psur->frame.h = pxr->h;

    psur->raw_face = wl_compositor_create_surface(pdisp->raw_comp);
    psur->sub_face = wl_subcompositor_get_subsurface(pdisp->sub_comp, psur->raw_face, parent->raw_face);
    wl_subsurface_set_position(psur->sub_face, pxr->x, pxr->y);
    wl_subsurface_place_above(psur->sub_face, parent->raw_face);
    wl_subsurface_set_desync(psur->sub_face);

    return psur;
err_ret:
 
    if(psur && psur->sub_face) wl_subsurface_destroy(psur->sub_face);
    if(psur && psur->raw_face) wl_surface_destroy(psur->raw_face);
    if(psur && psur->raw_buff) wl_buffer_destroy(psur->raw_buff);
    
    xmem_free(psur);
    return NULL;
}

void WaylandDestroySurface(wayland_surface* surface)
{
    wayland_surface* psur = (wayland_surface*)surface;

    if(psur->type == WAYLAND_WSURFACE_TYPE_TOP)
    {
        if(psur->xdg_top) xdg_toplevel_destroy(psur->xdg_top);
        if(psur->xdg_face) xdg_surface_destroy(psur->xdg_face);
    }
    else if(psur->type == WAYLAND_SURFACE_TYPE_POP)
    {
        if(psur->xdg_pop) xdg_popup_destroy(psur->xdg_pop);
        if(psur->xdg_face) xdg_surface_destroy(psur->xdg_face);
    }
    else if(psur->type == WAYLAND_SURFACE_TYPE_SUB)
    {
        if(psur->sub_face) wl_subsurface_destroy(psur->sub_face);
    }
    
    if(psur->raw_face) wl_surface_destroy(psur->raw_face);
    if(psur->raw_buff) wl_buffer_destroy(psur->raw_buff);

    xmem_free(psur);
}

void WaylandAttachSurface(wayland_surface* surface)
{
    wayland_surface* psur = (wayland_surface*)surface;
    wayland_display* pdisp = (wayland_display*)surface->display;

    if(!psur->raw_buff)
    {
        psur->raw_buff = _WaylandCreateBuffer(pdisp, &(psur->frame));
    }

    wl_surface_attach(psur->raw_face, psur->raw_buff, 0, 0);
    wl_surface_damage_buffer(psur->raw_face, psur->frame.x, psur->frame.y, psur->frame.w, psur->frame.h);
    wl_surface_commit(psur->raw_face);

    WaylandFlashDisplay(psur->display, bool_true);
}

void WaylandDetchSurface(wayland_surface* surface)
{
    wayland_surface* psur = (wayland_surface*)surface;

    wl_surface_attach(psur->raw_face, NULL, 0, 0);
    wl_surface_commit(psur->raw_face);
    WaylandFlashDisplay(psur->display, bool_true);

    if(psur->raw_buff)
    {
        wl_buffer_destroy(psur->raw_buff);
        psur->raw_buff = NULL;
    }
}

void WaylandSizeSurface(wayland_surface* surface, const xsize_t* pxs)
{
    wayland_display* pdisp = (wayland_display*)surface->display;
    wayland_surface* psur = surface;

    xrect_t xr = {0};

    wl_surface_attach(psur->raw_face, NULL, 0, 0);
    if(psur->raw_buff)
    {
        wl_buffer_destroy(psur->raw_buff);
        psur->raw_buff = NULL;
    }

    psur->frame.w = pxs->w;
    psur->frame.h = pxs->h;
    
    xr.x = psur->frame.x;
    xr.y = psur->frame.y;
    xr.w = psur->frame.w;
    xr.h = psur->frame.h;
    
    psur->raw_buff = _WaylandCreateBuffer(pdisp, &xr);
    wl_surface_attach(psur->raw_face, psur->raw_buff, 0, 0);
    
    wl_surface_damage_buffer(psur->raw_face, xr.x, xr.y, xr.w, xr.h);
    wl_surface_commit(psur->raw_face);

    xdg_surface_set_window_geometry(psur->xdg_face, xr.x, xr.y, xr.w, xr.h);
}

void WaylandMoveSurface(wayland_surface* surface, const offset_t* pof)
{
    wayland_display* pdisp = (wayland_display*)surface->display;
    wayland_surface* psur = (wayland_surface*)surface;

    xrect_t xr = {0};

    wl_surface_attach(psur->raw_face, NULL, 0, 0);
    if(psur->raw_buff)
    {
        wl_buffer_destroy(psur->raw_buff);
        psur->raw_buff = NULL;
    }

    psur->frame.x += pof->cx;
    psur->frame.y += pof->cy;

    xr.x = psur->frame.x;
    xr.y = psur->frame.y;
    xr.w = psur->frame.w;
    xr.h = psur->frame.h;

    psur->raw_buff = _WaylandCreateBuffer(pdisp, &xr);
    wl_surface_attach(psur->raw_face, psur->raw_buff, 0, 0);
    wl_surface_damage_buffer(psur->raw_face, xr.x, xr.y, xr.w, xr.h);

    //wl_subsurface_set_position(psur->raw_face, pxp->x, pxp->y);
    wl_surface_commit(psur->raw_face);
    xdg_surface_set_window_geometry(psur->xdg_face, xr.x, xr.y, xr.w, xr.h);
}

bool_t WaylandMinimizeSurface(wayland_surface* surface)
{
    if(surface->type == WAYLAND_WSURFACE_TYPE_TOP)
    {
        xdg_toplevel_set_minimized(surface->xdg_top);
        return bool_true;
    }

    return bool_false;
}

bool_t WaylandMaximizeSurface(wayland_surface* surface)
{
    if(surface->type == WAYLAND_WSURFACE_TYPE_TOP)
    {
        xdg_toplevel_set_maximized(surface->xdg_top);
        return bool_true;
    }

    return bool_false;
}

bool_t WaylandFullscreenSurface(wayland_surface* surface)
{
    if(surface->type == WAYLAND_WSURFACE_TYPE_TOP)
    {
        xdg_toplevel_set_fullscreen(surface->xdg_top, NULL);
        return bool_true;
    }

    return bool_false;
}

void WaylandUpdateSurface(wayland_surface* surface, const xrect_t* pxr, bool_t flash)
{
    wayland_surface* psur = (wayland_surface*)surface;

    struct wl_callback *frame_callback = NULL;

    if(!psur->raw_buff) return;

    if(!pxr) pxr = &psur->frame;

    //expose event
    frame_callback = wl_surface_frame(psur->raw_face);
    if(frame_callback)
    {
        wl_callback_add_listener(frame_callback, &paint_listener, psur);
    }

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

