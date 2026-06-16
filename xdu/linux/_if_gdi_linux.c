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

#if defined(_X11)
#include "X11/_if_X11.h"
#elif defined(_WAYLAND)
#include "wayland/_if_wayland.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT

void _gdi_init(int osv)
{
#if defined(_X11)
	xlGdiInit(osv);
#elif defined(_WAYLAND)
	wlGdiInit(osv);
#endif
}

void _gdi_uninit(void)
{
#if defined(_X11)
	xlGdiUnInit();
#elif defined(_WAYLAND)
	wlGdiUnInit();
#endif
}

void _gdi_set_xfont(visual_t rdc, const xfont_t* pxf)
{
#if defined(_X11)
	xlGdiSetXFont(rdc, pxf);
#elif defined(_WAYLAND)
	wlGdiSetXFont(rdc, pxf);
#endif
}

void _gdi_get_xfont(visual_t rdc, xfont_t* pxf)
{
#if defined(_X11)
	xlGdiGetXFont(rdc, pxf);
#elif defined(_WAYLAND)
	wlGdiGetXFont(rdc, pxf);
#endif
}

void _gdi_get_point(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt)
{
#if defined(_X11)
	xlGdiGetPoint(rdc, pxc, ppt);
#elif defined(_WAYLAND)
	wlGdiGetPoint(rdc, pxc, ppt);
#endif
}

void _gdi_set_point(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt)
{
#if defined(_X11)
	xlGdiSetPoint(rdc, pxc, ppt);
#elif defined(_WAYLAND)
	wlGdiSetPoint(rdc, pxc, ppt);
#endif
}

void _gdi_draw_points(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n)
{
#if defined(_X11)
	xlGdiDrawPoints(rdc, pxc, ppt, n);
#elif defined(_WAYLAND)
	wlGdiDrawPoints(rdc, pxc, ppt, n);
#endif
}

void _gdi_draw_line(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2)
{
#if defined(_X11)
	xlGdiDrawLine(rdc, pxp, ppt1, ppt2);
#elif defined(_WAYLAND)
	wlGdiDrawLine(rdc, pxp, ppt1, ppt2);
#endif
}

void _gdi_draw_polyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n)
{
#if defined(_X11)
	xlGdiDrawPolyline(rdc, pxp, ppt, n);
#elif defined(_WAYLAND)
	wlGdiDrawPolyline(rdc, pxp, ppt, n);
#endif
}

void _gdi_draw_arc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t closewise, bool_t largearc)
{
#if defined(_X11)
	xlGdiDrawArc(rdc, pxp, ppt1, ppt2, pxs, closewise, largearc);
#elif defined(_WAYLAND)
	wlGdiDrawArc(rdc, pxp, ppt1, ppt2, pxs, closewise, largearc);
#endif
}

void _gdi_draw_bezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
#if defined(_X11)
	xlGdiDrawBezier(rdc, pxp, ppt1, ppt2, ppt3, ppt4);
#elif defined(_WAYLAND)
	wlGdiDrawBezier(rdc, pxp, ppt1, ppt2, ppt3, ppt4);
#endif
}

void _gdi_draw_curve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn)
{
#if defined(_X11)
	xlGdiDrawCurve(rdc, pxp, ppt, pn);
#elif defined(_WAYLAND)
	wlGdiDrawCurve(rdc, pxp, ppt, pn);
#endif
}

void _gdi_draw_path(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn)
{
#if defined(_X11)
	xlGdiDrawPath(rdc, pxp, pxb, aa, pa, pn);
#elif defined(_WAYLAND)
	wlGdiDrawPath(rdc, pxp, pxb, aa, pa, pn);
#endif
}

void _gdi_draw_rect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
#if defined(_X11)
	xlGdiDrawRect(rdc, pxp, pxb, prt);
#elif defined(_WAYLAND)
	wlGdiDrawRect(rdc, pxp, pxb, prt);
#endif
}

void _gdi_draw_round(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs)
{
#if defined(_X11)
	xlGdiDrawRound(rdc, pxp, pxb, prt, pxs);
#elif defined(_WAYLAND)
	wlGdiDrawRound(rdc, pxp, pxb, prt, pxs);
#endif
}

void _gdi_draw_ellipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
#if defined(_X11)
	xlGdiDrawEllipse(rdc, pxp, pxb, prt);
#elif defined(_WAYLAND)
	wlGdiDrawEllipse(rdc, pxp, pxb, prt);
#endif
}

void _gdi_draw_pie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct)
{
#if defined(_X11)
	xlGdiDrawPie(rdc, pxp, pxb, prt, arcf, arct);
#elif defined(_WAYLAND)
	wlGdiDrawPie(rdc, pxp, pxb, prt, arcf, arct);
#endif
}

void _gdi_draw_polygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n)
{
#if defined(_X11)
	xlGdiDrawPolygon(rdc, pxp, pxb, ppt, n);
#elif defined(_WAYLAND)
	wlGdiDrawPolygon(rdc, pxp, pxb, ppt, n);
#endif
}

void _gdi_draw_text(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len)
{
#if defined(_X11)
	xlGdiDrawText(rdc, pxa, prt, txt, len);
#elif defined(_WAYLAND)
	wlGdiDrawText(rdc, pxa, prt, txt, len);
#endif
}

void _gdi_text_out(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len)
{
#if defined(_X11)
	xlGdiTextOut(rdc, pxa, ppt, txt, len);
#elif defined(_WAYLAND)
	wlGdiTextOut(rdc, pxa, ppt, txt, len);
#endif
}

void _gdi_text_rect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt)
{
#if defined(_X11)
	xlGdiTextRect(rdc, pxf, pxa, txt, len, prt);
#elif defined(_WAYLAND)
	wlGdiTextRect(rdc, pxf, pxa, txt, len, prt);
#endif
}

void _gdi_text_size(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
#if defined(_X11)
	xlGdiTextSize(rdc, pxf, txt, len, pxs);
#elif defined(_WAYLAND)
	wlGdiTextSize(rdc, pxf, txt, len, pxs);
#endif
}

void _gdi_gradient_rect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt)
{
#if defined(_X11)
	xlGdiGradientRect(rdc, clr_brim, clr_core, gradient, prt);
#elif defined(_WAYLAND)
	wlGdiGradientRect(rdc, clr_brim, clr_core, gradient, prt);
#endif
}

void _gdi_alphablend_rect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity)
{
#if defined(_X11)
	xlGdiAlphablendRect(rdc, pxc, prt, opacity);
#elif defined(_WAYLAND)
	wlGdiAlphablendRect(rdc, pxc, prt, opacity);
#endif
}

void _gdi_invert_rect(visual_t rdc, const xrect_t* prt)
{
#if defined(_X11)
	xlGdiInvertRect(rdc, prt);
#elif defined(_WAYLAND)
	wlGdiInvertRect(rdc, prt);
#endif
}

void _gdi_exclude_rect(visual_t rdc, const xrect_t* pxr)
{
#if defined(_X11)
	xlGdiExcludeRect(rdc, pxr);
#elif defined(_WAYLAND)
	wlGdiExcludeRect(rdc, pxr);
#endif
}

void _gdi_inclip_rect(visual_t rdc, const xrect_t* pxr)
{
#if defined(_X11)
	xlGdiInclipRect(rdc, pxr);
#elif defined(_WAYLAND)
	wlGdiInclipRect(rdc, pxr);
#endif
}

#ifdef XDU_SUPPORT_CONTEXT_BITMAP
void _gdi_draw_image(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt)
{
#if defined(_X11)
	xlGdiDrawImage(rdc, rbm, clr, prt);
#elif defined(_WAYLAND)
	wlGdiDrawImage(rdc, rbm, clr, prt);
#endif
}

void _gdi_draw_bitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt)
{
#if defined(_X11)
	xlGdiDrawBitmap(rdc, rbm, ppt);
#elif defined(_WAYLAND)
	wlGdiDrawBitmap(rdc, rbm, ppt);
#endif
}
#endif

#ifdef XDU_SUPPORT_CONTEXT_REGION
void _gdi_fill_region(visual_t rdc, const xbrush_t* pxb, res_rgn_t rgn)
{
#if defined(_X11)
	xlGdiFillRegion(rdc, pxb, rgn);
#elif defined(_WAYLAND)
	wlGdiFillRegion(rdc, pxb, rgn);
#endif
}
#endif

void _gdi_font_size(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
#if defined(_X11)
	xlGdiFontSize(rdc, pxf, pxs);
#elif defined(_WAYLAND)
	wlGdiFontSize(rdc, pxf, pxs);
#endif
}

fontset_t _gdi_get_fontset(visual_t rdc)
{
#if defined(_X11)
	return xlGdiGetFontset(rdc);
#elif defined(_WAYLAND)
	return wlGdiGetFontset(rdc);
#endif
}

fontset_t _gdi_create_fontset(const xfont_t* pxf)
{
#if defined(_X11)
	return xlGdiCreateFontset(pxf);
#elif defined(_WAYLAND)
	return wlGdiCreateFontset(pxf);
#endif
}

void _gdi_destroy_fontset(fontset_t ft)
{
#if defined(_X11)
	xlGdiDestroyFontset(ft);
#elif defined(_WAYLAND)
	wlGdiDestroyFontset(ft);
#endif
}

void _gdi_word_size(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs)
{
#if defined(_X11)
	xlGdiWordSize(ft, pch, chs, pxs);
#elif defined(_WAYLAND)
	wlGdiWordSize(ft, pch, chs, pxs);
#endif
}

#endif //XDU_SUPPORT_CONTEXT_GRAPHIC



