/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc device context document

	@module	if_context_cocoa.m | macos implement file

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

int _context_version(void)
{
	return (0);
}

int _context_startup()
{
	return (0);
}

void _context_cleanup(void)
{
	NOP;
}

visual_t _create_display_context(res_win_t wt)
{
	cocoa_context_t* ctx = NULL;

	ctx = (cocoa_context_t*)calloc(1, sizeof(cocoa_context_t));
	ctx->head.tag = _VISUAL_DISPLAY;

	NSGraphicsContext *graphicsContext = [NSGraphicsContext currentContext];
    ctx->context = [graphicsContext CGContext];
	ctx->client = [(NSView*)wt frame];
	ctx->type = CONTEXT_SCREEN;
	
	return (visual_t)&(ctx->head);
}

visual_t _create_compatible_context(visual_t rdc, int cx, int cy)
{
	cocoa_context_t* org = (cocoa_context_t*)rdc;
	cocoa_context_t* ctx = NULL;

	ctx = (cocoa_context_t*)calloc(1, sizeof(cocoa_context_t));
	ctx->head.tag = _VISUAL_DISPLAY;

	ctx->type = CONTEXT_MEMORY;

	size_t bytesPerPixel = 4;
    size_t bytesPerRow = cx * bytesPerPixel;
    size_t bufferSize = cy * bytesPerRow;

	ctx->bitmap = calloc(1, bufferSize);
    ctx->colors = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    ctx->context = CGBitmapContextCreate(
        ctx->bitmap,
        cx,
        cy,
        8,
        bytesPerRow,
        ctx->colors,
        kCGImageAlphaPremultipliedLast
    );
	ctx->client = org->client;

	return (visual_t)&(ctx->head);
}

void _destroy_context(visual_t rdc)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;

	switch (ctx->type)
	{
	case CONTEXT_WIDGET:
		break;
	case CONTEXT_SCREEN:
		break;
	case CONTEXT_MEMORY:
		CGContextRelease(ctx->context);
    	CGColorSpaceRelease(ctx->colors);
    	free(ctx->bitmap);
		break;
	case CONTEXT_PRINTER:
		break;
	}

	free(ctx);
}

void _get_device_caps(visual_t rdc, dev_cap_t* pcap)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;

	NSScreen *mainScreen = [NSScreen mainScreen];
    NSRect screenFrame = [mainScreen frame];
    NSRect visibleFrame = [mainScreen visibleFrame];

    CGFloat scaleFactor = [mainScreen backingScaleFactor]; 
    CGFloat dpi = 72.0 * scaleFactor; 

    CGFloat screenWidthMM = screenFrame.size.width / dpi * 25.4; // Convert inches to mm
    CGFloat screenHeightMM = screenFrame.size.height / dpi * 25.4;

	pcap->horz_res = screenFrame.size.width;
	pcap->vert_res = screenFrame.size.height;

	pcap->horz_pixels = 72;
	pcap->vert_pixels = 72;

	pcap->horz_size = (float)((float)(screenFrame.size.width) / dpi * 25.4);
	pcap->vert_size = (float)((float)(screenFrame.size.height) / dpi * 25.4);

	pcap->horz_feed = 0;
	pcap->vert_feed = 0;
}

void _render_context(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth)
{
	cocoa_context_t* src_ctx = (cocoa_context_t*)src;
	cocoa_context_t* dst_ctx = (cocoa_context_t*)dst;

  	CGImageRef image = CGBitmapContextCreateImage(src_ctx->context);
 
 	CGContextDrawImage(dst_ctx->context, CGRectMake(dstx, dsty, dstw, dsth), image);

	CGImageRelease(image);
}

/*******************************************************************************************************************/

float _pt_per_mm(visual_t rdc, bool_t horz)
{
	return 0.0f;
}

static int _font_size(visual_t rdc, int height)
{
    return 0;
}

void _text_pt_size(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
    NOP;
}

void _text_mm_size(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
   NOP;
}

void _text_pt_metric(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
    NOP;
}

void _text_mm_metric(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
   NOP;
}

void _cast_pt_to_mm(visual_t rdc, bool_t horz, xspan_t* pan)
{
   NOP;
}

void _cast_mm_to_pt(visual_t rdc, bool_t horz, xspan_t* pan)
{
    NOP;
}


#endif //XDU_SUPPORT_CONTEXT
