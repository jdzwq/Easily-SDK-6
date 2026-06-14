/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc context document

	@module	xquartz_context.c | xquartz implement file

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

#include "_if_xquartz.h"

Display*     g_display = NULL;

int xqContextStartup(void)
{
    int nVer = 0;
    char* dname;

    XInitThreads();
    
    dname = getenv("DISPLAY");
    
    g_display = XOpenDisplay(dname);

    if(!g_display) return (-1);

	xqGdiInit(0);

	return nVer;
}

void xqContextCleanup(void)
{
	xqGdiUnInit();

    if(g_display)
    {
        XCloseDisplay(g_display);
        g_display = 0;
    }
}

visual_t xqCreateDisplayContext(widget_t wt)
{
    xquartz_widget_t* pxw = TypePtrFromHead(xquartz_widget_t, wt);
    xquartz_context_t* ctx = NULL;
    XGCValues gv = {0};
    XWindowAttributes attr = {0};
    GC gc = NULL;

    gc = DefaultGC(g_display, DefaultScreen(g_display));
    if(!gc) return NULL;

    XGetGCValues(g_display, gc, GCFunction | GCForeground | GCBackground | GCPlaneMask, &gv);
    gv.subwindow_mode = ClipByChildren;

    ctx = (xquartz_context_t*)xmem_alloc_handle(sizeof(xquartz_context_t));
    
    ctx->type = CONTEXT_WIDGET;
    ctx->device = (wt)? pxw->self : DefaultRootWindow(g_display);
    ctx->context = XCreateGC(g_display, ctx->device, 0, &gv);
    ctx->fontset = g_fontset;
    ctx->color = DefaultColormap(g_display, DefaultScreen(g_display));

    XGetWindowAttributes(g_display, ctx->device, &attr);
    ctx->width = attr.width;
    ctx->height = attr.height;
    ctx->color = attr.colormap;
    ctx->visual = attr.visual;
    ctx->depth = attr.depth;

#ifdef XLIB_SUPPORT_CAIRO
    ctx->fac = cairo_xqib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
    ctx->cai = cairo_create(ctx->fac);
#endif

    return &(ctx->head);
}

visual_t xqCreateCompatibleContext(visual_t rdc, int cx, int cy)
{
    xquartz_context_t* org = TypePtrFromHead(xquartz_context_t, rdc);
    XGCValues gv = {0};
    Window r;
    int x,y;
    unsigned int w,h,b,d;
    xquartz_context_t* ctx = NULL;
    
    XGetGeometry(g_display, org->device, &r, &x, &y, &w, &h, &b, &d);
    
    ctx = (xquartz_context_t*)xmem_alloc_handle(sizeof(xquartz_context_t));

    ctx->type = CONTEXT_MEMORY;
    ctx->device = XCreatePixmap (g_display, r, cx, cy, org->depth);
    ctx->context = XCreateGC(g_display, org->device, 0, &gv);
    ctx->fontset = g_fontset;

    ctx->width = cx;
    ctx->height = cy;
    /*if(org->type == CONTEXT_MEMORY)
        ctx->color = XCreateColormap(g_display, DefaultRootWindow(g_display), org->visual, 0);
    else
        ctx->color = XCreateColormap(g_display, org->device, org->visual, 0);*/
    ctx->color = DefaultColormap(g_display, DefaultScreen(g_display));
    ctx->visual = org->visual;
    ctx->depth = org->depth;
    
#ifdef XLIB_SUPPORT_CAIRO
    ctx->fac = cairo_xqib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
    ctx->cai = cairo_create(ctx->fac);
#endif

    return &(ctx->head);
}

void xqDestroyContext(visual_t rdc)
{
    xquartz_context_t* ctx = TypePtrFromHead(xquartz_context_t, rdc);

#ifdef XLIB_SUPPORT_CAIRO
    if(ctx->cai) cairo_destroy(ctx->cai);
    if(ctx->fac) cairo_surface_destroy(ctx->fac);
#endif

    if(ctx->type == CONTEXT_MEMORY && ctx->device)
        XFreePixmap(g_display, ctx->device);
    
    //if(ctx->color)
     //   XFreeColormap(g_display, ctx->color);

    if(ctx->context)
	    XFreeGC(g_display, ctx->context);
    
    xmem_free_handle((xhand_t)ctx);
}

void xqGetDeviceCaps(visual_t rdc, dev_cap_t* pcap)
{
    int scrn;
    
    scrn = DefaultScreen(g_display);

    pcap->horz_res = DisplayWidth(g_display, scrn);
    pcap->vert_res = DisplayHeight(g_display, scrn);
    
	pcap->horz_size = DisplayWidthMM(g_display, scrn);
	pcap->vert_size = DisplayHeightMM(g_display, scrn);

	pcap->horz_pixels = (int)((float)pcap->horz_res / (float)pcap->horz_size * MMPERINCH);
	pcap->vert_pixels = (int)((float)pcap->vert_res / (float)pcap->vert_size * MMPERINCH);

    pcap->horz_feed = 0;
    pcap->vert_feed = 0;
}

void xqRenderContext(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth)
{
    xquartz_context_t* src_ctx = TypePtrFromHead(xquartz_context_t, src);
    xquartz_context_t* dst_ctx = TypePtrFromHead(xquartz_context_t, dst);

    XCopyArea(g_display, src_ctx->device, dst_ctx->device, src_ctx->context, srcx, srcy, dstw, dsth, dstx, dsty);
}
