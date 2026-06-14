/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdi document

	@module	if_gdi.c | linux implement file

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
#include "../xduutil.h"

#if defined(_COCOA)
#include "cocoa/_if_cocoa.h"
#elif defined(_XQUARTZ)
#include "xquartz/_if_xquartz.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT

void _gdi_init(int osv)
{
#if defined(_COCOA)
	coGdiInit(osv);
#elif defined(_XQUARTZ)
	xqGdiInit(osv);
#endif
}

void _gdi_uninit(void)
{
#if defined(_COCOA)
	coGdiUnInit();
#elif defined(_XQUARTZ)
	xqGdiUnInit();
#endif
}

void _gdi_set_xfont(visual_t rdc, const xfont_t* pxf)
{
#if defined(_COCOA)
	coGdiSetXFont(rdc, pxf);
#elif defined(_XQUARTZ)
	xqGdiSetXFont(rdc, pxf);
#endif
}

void _gdi_get_xfont(visual_t rdc, xfont_t* pxf)
{
#if defined(_COCOA)
	coGdiGetXFont(rdc, pxf);
#elif defined(_XQUARTZ)
	xqGdiGetXFont(rdc, pxf);
#endif
}

void _gdi_get_point(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt)
{
#if defined(_COCOA)
	coGdiGetPoint(rdc, pxc, ppt);
#elif defined(_XQUARTZ)
	xqGdiGetPoint(rdc, pxc, ppt);
#endif
}

void _gdi_set_point(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt)
{
#if defined(_COCOA)
	coGdiSetPoint(rdc, pxc, ppt);
#elif defined(_XQUARTZ)
	xqGdiSetPoint(rdc, pxc, ppt);
#endif
}

void _gdi_draw_points(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n)
{
#if defined(_COCOA)
	coGdiDrawPoints(rdc, pxc, ppt, n);
#elif defined(_XQUARTZ)
	xqGdiDrawPoints(rdc, pxc, ppt, n);
#endif
}

void _gdi_draw_line(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2)
{
#if defined(_COCOA)
	coGdiDrawLine(rdc, pxp, ppt1, ppt2);
#elif defined(_XQUARTZ)
	xqGdiDrawLine(rdc, pxp, ppt1, ppt2);
#endif
}

void _gdi_draw_polyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n)
{
#if defined(_COCOA)
	coGdiDrawPolyline(rdc, pxp, ppt, n);
#elif defined(_XQUARTZ)
	xqGdiDrawPolyline(rdc, pxp, ppt, n);
#endif
}

void _gdi_draw_arc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t closewise, bool_t largearc)
{
#if defined(_COCOA)
	coGdiDrawArc(rdc, pxp, ppt1, ppt2, pxs, closewise, largearc);
#elif defined(_XQUARTZ)
	xqGdiDrawArc(rdc, pxp, ppt1, ppt2, pxs, closewise, largearc);
#endif
}

void _gdi_draw_bezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
#if defined(_COCOA)
	coGdiDrawBezier(rdc, pxp, ppt1, ppt2, ppt3, ppt4);
#elif defined(_XQUARTZ)
	xqGdiDrawBezier(rdc, pxp, ppt1, ppt2, ppt3, ppt4);
#endif
}

void _gdi_draw_curve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn)
{
#if defined(_COCOA)
	coGdiDrawCurve(rdc, pxp, ppt, pn);
#elif defined(_XQUARTZ)
	xqGdiDrawCurve(rdc, pxp, ppt, pn);
#endif
}

void _gdi_draw_path(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn)
{
#if defined(_COCOA)
	coGdiDrawPath(rdc, pxp, pxb, aa, pa, pn);
#elif defined(_XQUARTZ)
	xqGdiDrawPath(rdc, pxp, pxb, aa, pa, pn);
#endif
}

void _gdi_draw_rect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
#if defined(_COCOA)
	coGdiDrawRect(rdc, pxp, pxb, prt);
#elif defined(_XQUARTZ)
	xqGdiDrawRect(rdc, pxp, pxb, prt);
#endif
}

void _gdi_draw_round(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs)
{
#if defined(_COCOA)
	coGdiDrawRound(rdc, pxp, pxb, prt, pxs);
#elif defined(_XQUARTZ)
	xqGdiDrawRound(rdc, pxp, pxb, prt, pxs);
#endif
}

void _gdi_draw_ellipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
#if defined(_COCOA)
	coGdiDrawEllipse(rdc, pxp, pxb, prt);
#elif defined(_XQUARTZ)
	xqGdiDrawEllipse(rdc, pxp, pxb, prt);
#endif
}

void _gdi_draw_pie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct)
{
#if defined(_COCOA)
	coGdiDrawPie(rdc, pxp, pxb, prt, arcf, arct);
#elif defined(_XQUARTZ)
	xqGdiDrawPie(rdc, pxp, pxb, prt, arcf, arct);
#endif
}

void _gdi_draw_polygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n)
{
#if defined(_COCOA)
	coGdiDrawPolygon(rdc, pxp, pxb, ppt, n);
#elif defined(_XQUARTZ)
	xqGdiDrawPolygon(rdc, pxp, pxb, ppt, n);
#endif
}

void _gdi_draw_text(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len)
{
#if defined(_COCOA)
	coGdiDrawText(rdc, pxa, prt, txt, len);
#elif defined(_XQUARTZ)
	xqGdiDrawText(rdc, pxa, prt, txt, len);
#endif
}

void _gdi_text_out(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len)
{
#if defined(_COCOA)
	coGdiTextOut(rdc, pxa, ppt, txt, len);
#elif defined(_XQUARTZ)
	xqGdiTextOut(rdc, pxa, ppt, txt, len);
#endif
}

void _gdi_text_rect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt)
{
#if defined(_COCOA)
	coGdiTextRect(rdc, pxf, pxa, txt, len, prt);
#elif defined(_XQUARTZ)
	xqGdiTextRect(rdc, pxf, pxa, txt, len, prt);
#endif
}

void _gdi_text_size(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
#if defined(_COCOA)
	coGdiTextSize(rdc, pxf, txt, len, pxs);
#elif defined(_XQUARTZ)
	xqGdiTextSize(rdc, pxf, txt, len, pxs);
#endif
}

void _gdi_gradient_rect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt)
{
#if defined(_COCOA)
	coGdiGradientRect(rdc, clr_brim, clr_core, gradient, prt);
#elif defined(_XQUARTZ)
	xqGdiGradientRect(rdc, clr_brim, clr_core, gradient, prt);
#endif
}

void _gdi_alphablend_rect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity)
{
#if defined(_COCOA)
	coGdiAlphablendRect(rdc, pxc, prt, opacity);
#elif defined(_XQUARTZ)
	xqGdiAlphablendRect(rdc, pxc, prt, opacity);
#endif
}

void _gdi_invert_rect(visual_t rdc, const xrect_t* prt)
{
#if defined(_COCOA)
	coGdiInvertRect(rdc, prt);
#elif defined(_XQUARTZ)
	xqGdiInvertRect(rdc, prt);
#endif
}

void _gdi_exclude_rect(visual_t rdc, const xrect_t* pxr)
{
#if defined(_COCOA)
	coGdiExcludeRect(rdc, pxr);
#elif defined(_XQUARTZ)
	xqGdiExcludeRect(rdc, pxr);
#endif
}

void _gdi_inclip_rect(visual_t rdc, const xrect_t* pxr)
{
#if defined(_COCOA)
	coGdiInclipRect(rdc, pxr);
#elif defined(_XQUARTZ)
	xqGdiInclipRect(rdc, pxr);
#endif
}

#ifdef XDU_SUPPORT_CONTEXT_BITMAP
void _gdi_draw_image(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt)
{
#if defined(_COCOA)
	coGdiDrawImage(rdc, rbm, clr, prt);
#elif defined(_XQUARTZ)
	xqGdiDrawImage(rdc, rbm, clr, prt);
#endif
}

void _gdi_draw_bitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt)
{
#if defined(_COCOA)
	coGdiDrawBitmap(rdc, rbm, ppt);
#elif defined(_XQUARTZ)
	xqGdiDrawBitmap(rdc, rbm, ppt);
#endif
}
#endif

#ifdef XDU_SUPPORT_CONTEXT_REGION
void _gdi_fill_region(visual_t rdc, const xbrush_t* pxb, res_rgn_t rgn)
{
#if defined(_COCOA)
	coGdiFillRegion(rdc, pxb, rgn);
#elif defined(_XQUARTZ)
	xqGdiFillRegion(rdc, pxb, rgn);
#endif
}
#endif

void _gdi_font_size(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
#if defined(_COCOA)
	coGdiFontSize(rdc, pxf, pxs);
#elif defined(_XQUARTZ)
	xqGdiFontSize(rdc, pxf, pxs);
#endif
}

fontset_t _gdi_get_fontset(visual_t rdc)
{
#if defined(_COCOA)
	return coGdiGetFontset(rdc);
#elif defined(_XQUARTZ)
	return xqGdiGetFontset(rdc);
#endif
}

fontset_t _gdi_create_fontset(const xfont_t* pxf)
{
#if defined(_COCOA)
	return coGdiCreateFontset(pxf);
#elif defined(_XQUARTZ)
	return xqGdiCreateFontset(pxf);
#endif
}

void _gdi_destroy_fontset(fontset_t ft)
{
#if defined(_COCOA)
	coGdiDestroyFontset(ft);
#elif defined(_XQUARTZ)
	xqGdiDestroyFontset(ft);
#endif
}

void _gdi_word_size(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs)
{
#if defined(_COCOA)
	coGdiWordSize(ft, pch, chs, pxs);
#elif defined(_XQUARTZ)
	xqGdiWordSize(ft, pch, chs, pxs);
#endif
}

#endif //XDU_SUPPORT_CONTEXT_GRAPHIC



