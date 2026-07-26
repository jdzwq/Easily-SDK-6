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

////////////////////////////////////////////////////////////////////////////

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

wayland_window* WaylandCreateWindow(wayland_window* parent, int type, const tchar_t* title, int x, int y, int width, int height)
{
    wayland_window* par_win = (parent) ? (wayland_window*)parent : NULL;
    wayland_window* pwin;

    wayland_display* pdisp = NULL;
    xrect_t xr = {0};

    if ((type == WAYLAND_WINDOW_TYPE_CHILD || type == WAYLAND_WINDOW_TYPE_POPUP) && !par_win) 
        goto err_ret;

    pwin = (wayland_window*)xmem_alloc(sizeof(wayland_window));
    pwin->parent = parent;
    pwin->childs_count = 0;
    pwin->x = x;
    pwin->y = y;
    pwin->width = width;
    pwin->height = height;
    pwin->win_type = type;

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

    xr.x = pwin->x;
    xr.y = pwin->y;
    xr.w = pwin->width;
    xr.h = pwin->height;

    switch(type)
    {
    case WAYLAND_WINDOW_TYPE_OVERLAP:
    case WAYLAND_WINDOW_TYPE_DIALOG:
    case WAYLAND_WINDOW_TYPE_POPUP:
        pwin->sur_window = WaylandCreateTopSurface(pdisp, &xr);
        if (!pwin->sur_window) goto err_ret;

        xr.x = pwin->edge_width;
        xr.y = pwin->title_height;
        xr.w = pwin->width - pwin->edge_width * 2;
        xr.h = pwin->height - pwin->title_height - pwin->edge_width;
        pwin->sur_client = WaylandCreateSubSurface(pwin->sur_window, &xr);
        if (!pwin->sur_client) goto err_ret;
        break;
    case WAYLAND_WINDOW_TYPE_CHILD:
        pwin->sur_client = WaylandCreateSubSurface(par_win->sur_client, &xr);
        if (!pwin->sur_client) goto err_ret;

        _WaylandAddChild(pwin);
        break;
    default:
        goto err_ret;
    }

    if(pwin->sur_window)
    {
        WaylandFillSurface(pwin->sur_window, 0xFFFFFFFF, NULL);
    }

    if(pwin->sur_client)
    {
        if(type == WAYLAND_WINDOW_TYPE_CHILD)
            WaylandFillSurface(pwin->sur_client, 0xFF00FF00, NULL);
        else
            WaylandFillSurface(pwin->sur_client, 0xFF000000, NULL);
    }

    if(pwin->sur_window)
    {
        wl_surface_set_user_data(pwin->sur_window->raw_face, pwin);
    }

    if(pwin->sur_client)
    {
        wl_surface_set_user_data(pwin->sur_client->raw_face, pwin);
    }
    
    return pwin;
err_ret:

    if(pwin && pwin->sur_client) WaylandDestroySurface(pwin->sur_client);
    if(pwin && pwin->sur_window) WaylandDestroySurface(pwin->sur_window);

    xmem_free(pwin);

    return NULL;
}

void WaylandDestroyWindow(wayland_window* pwin)
{
    if(pwin->win_type == WAYLAND_WINDOW_TYPE_CHILD)
    {
        _WaylandDelChild(pwin);
    }

    if(pwin->sur_client) WaylandDestroySurface(pwin->sur_client);
    if(pwin->sur_window) WaylandDestroySurface(pwin->sur_window);
    
	xmem_free(pwin);
}

void WaylandSetWindowProc(wayland_window* window, dword_t events, WaylandEventProc proc)
{
   window->evt_mask = events;
   window->evt_proc = proc;
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
    return (pwin && pwin->evt_proc) ? bool_true : bool_false;
}

void WaylandShowWindow(wayland_window* window, int nState)
{
    if(nState == WAYLAND_WINDOW_STATE_HIDE && window->win_state != WAYLAND_WINDOW_STATE_HIDE)
    {
        if(window->sur_window) WaylandDetchSurface(window->sur_window);
        if(window->sur_client) WaylandDetchSurface(window->sur_client);
    }

    if(nState != WAYLAND_WINDOW_STATE_HIDE && window->win_state == WAYLAND_WINDOW_STATE_HIDE)
    {
        if(window->sur_window) WaylandAttachSurface(window->sur_window);
        if(window->sur_client) WaylandAttachSurface(window->sur_client);
    }

    switch(nState)
    {
    case WAYLAND_WINDOW_STATE_NORMAL:
        break;
    case WAYLAND_WINDOW_STATE_MINIMIZED:
        if(window->sur_client) WaylandMinimizeSurface(window->sur_client);
        if(window->sur_window) WaylandMinimizeSurface(window->sur_window);
        break;
    case WAYLAND_WINDOW_STATE_MAXIMIZED:
        if(window->sur_client) WaylandMaximizeSurface(window->sur_client);
        if(window->sur_window) WaylandMaximizeSurface(window->sur_window);
        break;
    case WAYLAND_WINDOW_STATE_FULLSCREEN:
        if(window->sur_client) WaylandFullscreenSurface(window->sur_client);
        if(window->sur_window) WaylandFullscreenSurface(window->sur_window);
        break;
    }

    window->win_state = nState;
}

int WaylandWindowState(wayland_window* pwin)
{
    return pwin->win_state;
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

void WaylandSizeWindow(wayland_window* pwin, const xsize_t* pxs)
{
     if(pwin->sur_window) 
     {
        WaylandSizeSurface(pwin->sur_window, pxs);
     }

    if(pwin->sur_client)
    {
        WaylandSizeSurface(pwin->sur_client, pxs);
    }
}

void WaylandMoveWindow(wayland_window* pwin, const xpoint_t* pxp)
{
    offset_t off;

    off.cx = pxp->x - pwin->x;
    off.cy = pxp->y - pwin->y;

     if(pwin->sur_window) 
     {
        WaylandMoveSurface(pwin->sur_window, &off);
     }

    if(pwin->sur_client)
    {
        WaylandMoveSurface(pwin->sur_client, &off);
    }
}

void WaylandSetFocusWindow(wayland_window* pwin)
{
    wayland_display* pdisp = WaylandDefaultDisplay();
    wayland_window* parent = pwin->parent;

    while(parent && parent->win_type == WAYLAND_WINDOW_TYPE_CHILD)
    {
        parent = parent->parent;
    }

    switch (pwin->win_type)
    {
    case WAYLAND_WINDOW_TYPE_OVERLAP:
    case WAYLAND_WINDOW_TYPE_DIALOG:
        if (pwin->track_focus)
        {
            if ((pwin->track_focus->evt_mask & WAYLAND_EVENT_MASK_KEYBOARD) && pwin->track_focus->evt_proc)
            {
                (*pwin->track_focus->evt_proc)(pwin->track_focus, WAYLAND_EVENT_KILL_FOCUS, 0, (vword_t)NULL);
            }
            pwin->track_focus = NULL;
        }
        break;
    case WAYLAND_WINDOW_TYPE_POPUP:
        break;
    case WAYLAND_WINDOW_TYPE_CHILD:
        if (!parent) break;
        if (parent->track_focus == pwin)
            break;

        if (parent->track_focus && (parent->track_focus->evt_mask & WAYLAND_EVENT_MASK_KEYBOARD) && parent->track_focus->evt_proc)
        {
            (*parent->track_focus->evt_proc)(parent->track_focus, WAYLAND_EVENT_KILL_FOCUS, 0, (vword_t)NULL);
        }
        parent->track_focus = NULL;

        if (pwin && (pwin->evt_mask & WAYLAND_EVENT_MASK_KEYBOARD) && pwin->evt_proc)
        {
            if ((*pwin->evt_proc)(pwin, WAYLAND_EVENT_SET_FOCUS, 0, (vword_t)NULL) != WAYLAND_RESULT_ACCEPT)
                break;
            parent->track_focus = pwin;
        }
        break;
    }
}

wayland_window* WaylandGetFocusWindow(void)
{
    wayland_display* pdisp = WaylandDefaultDisplay();

    return (pdisp->track_main) ? pdisp->track_main->track_focus : NULL;
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
