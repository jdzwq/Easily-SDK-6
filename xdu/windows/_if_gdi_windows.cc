/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdiplus document

	@module	if_gdi_win.c | windows implement file

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

#if defined(_WCE)
#include "wince/_if_wince.h"
#elif defined(_W32)
#include "win32/_if_win32.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT

void _gdi_init(int osv)
{
#if defined(WINCE)
	wceGdiInit(osv);
#elif defined(WIN32)
	winGdiInit(osv);
#endif
}

void _gdi_uninit(void)
{
#if defined(WINCE)
	wceGdiUnInit();
#elif defined(WIN32)
	winGdiUnInit();
#endif
}

void _gdi_set_xfont(visual_t rdc, const xfont_t* pxf)
{
#if defined(WINCE)
	wceGdiSetXFont(rdc, pxf);
#elif defined(WIN32)
	winGdiSetXFont(rdc, pxf);
#endif
}

void _gdi_get_xfont(visual_t rdc, xfont_t* pxf)
{
#if defined(WINCE)
	wceGdiGetXFont(rdc, pxf);
#elif defined(WIN32)
	winGdiGetXFont(rdc, pxf);
#endif
}

void _gdi_get_point(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt)
{
#if defined(WINCE)
	wceGdiGetPoint(rdc, pxc, ppt);
#elif defined(WIN32)
	winGdiGetPoint(rdc, pxc, ppt);
#endif
}

void _gdi_set_point(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt)
{
#if defined(WINCE)
	wceGdiSetPoint(rdc, pxc, ppt);
#elif defined(WIN32)
	winGdiSetPoint(rdc, pxc, ppt);
#endif
}

void _gdi_draw_points(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n)
{
#if defined(WINCE)
	wceGdiDrawPoints(rdc, pxc, ppt, n);
#elif defined(WIN32)
	winGdiDrawPoints(rdc, pxc, ppt, n);
#endif
}

void _gdi_draw_line(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2)
{
#if defined(WINCE)
	wceGdiDrawLine(rdc, pxp, ppt1, ppt2);
#elif defined(WIN32)
	winGdiDrawLine(rdc, pxp, ppt1, ppt2);
#endif
}

void _gdi_draw_polyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n)
{
#if defined(WINCE)
	wceGdiDrawPolyline(rdc, pxp, ppt, n);
#elif defined(WIN32)
	winGdiDrawPolyline(rdc, pxp, ppt, n);
#endif
}

void _gdi_draw_arc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t closewise, bool_t largearc)
{
#if defined(WINCE)
	wceGdiDrawArc(rdc, pxp, ppt1, ppt2, pxs, closewise, largearc);
#elif defined(WIN32)
	winGdiDrawArc(rdc, pxp, ppt1, ppt2, pxs, closewise, largearc);
#endif
}

void _gdi_draw_bezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
#if defined(WINCE)
	wceGdiDrawBezier(rdc, pxp, ppt1, ppt2, ppt3, ppt4);
#elif defined(WIN32)
	winGdiDrawBezier(rdc, pxp, ppt1, ppt2, ppt3, ppt4);
#endif
}

void _gdi_draw_curve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn)
{
#if defined(WINCE)
	wceGdiDrawCurve(rdc, pxp, ppt, pn);
#elif defined(WIN32)
	winGdiDrawCurve(rdc, pxp, ppt, pn);
#endif
}

void _gdi_draw_path(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn)
{
#if defined(WINCE)
	wceGdiDrawPath(rdc, pxp, pxb, aa, pa, pn);
#elif defined(WIN32)
	winGdiDrawPath(rdc, pxp, pxb, aa, pa, pn);
#endif
}

void _gdi_draw_rect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
#if defined(WINCE)
	wceGdiDrawRect(rdc, pxp, pxb, prt);
#elif defined(WIN32)
	winGdiDrawRect(rdc, pxp, pxb, prt);
#endif
}

void _gdi_draw_round(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs)
{
#if defined(WINCE)
	wceGdiDrawRound(rdc, pxp, pxb, prt, pxs);
#elif defined(WIN32)
	winGdiDrawRound(rdc, pxp, pxb, prt, pxs);
#endif
}

void _gdi_draw_ellipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
#if defined(WINCE)
	wceGdiDrawEllipse(rdc, pxp, pxb, prt);
#elif defined(WIN32)
	winGdiDrawEllipse(rdc, pxp, pxb, prt);
#endif
}

void _gdi_draw_pie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct)
{
#if defined(WINCE)
	wceGdiDrawPie(rdc, pxp, pxb, prt, arcf, arct);
#elif defined(WIN32)
	winGdiDrawPie(rdc, pxp, pxb, prt, arcf, arct);
#endif
}

void _gdi_draw_polygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n)
{
#if defined(WINCE)
	wceGdiDrawPolygon(rdc, pxp, pxb, ppt, n);
#elif defined(WIN32)
	winGdiDrawPolygon(rdc, pxp, pxb, ppt, n);
#endif
}

void _gdi_draw_text(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len)
{
#if defined(WINCE)
	wceGdiDrawText(rdc, pxa, prt, txt, len);
#elif defined(WIN32)
	winGdiDrawText(rdc, pxa, prt, txt, len);
#endif
}

void _gdi_text_out(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len)
{
#if defined(WINCE)
	wceGdiTextOut(rdc, pxa, ppt, txt, len);
#elif defined(WIN32)
	winGdiTextOut(rdc, pxa, ppt, txt, len);
#endif
}

void _gdi_text_rect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt)
{
#if defined(WINCE)
	wceGdiTextRect(rdc, pxf, pxa, txt, len, prt);
#elif defined(WIN32)
	winGdiTextRect(rdc, pxf, pxa, txt, len, prt);
#endif
}

void _gdi_text_size(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
#if defined(WINCE)
	wceGdiTextSize(rdc, pxf, txt, len, pxs);
#elif defined(WIN32)
	winGdiTextSize(rdc, pxf, txt, len, pxs);
#endif
}

void _gdi_gradient_rect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt)
{
#if defined(WINCE)
	wceGdiGradientRect(rdc, clr_brim, clr_core, gradient, prt);
#elif defined(WIN32)
	winGdiGradientRect(rdc, clr_brim, clr_core, gradient, prt);
#endif
}

void _gdi_alphablend_rect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity)
{
#if defined(WINCE)
	wceGdiAlphablendRect(rdc, pxc, prt, opacity);
#elif defined(WIN32)
	winGdiAlphablendRect(rdc, pxc, prt, opacity);
#endif
}

void _gdi_invert_rect(visual_t rdc, const xrect_t* prt)
{
#if defined(WINCE)
	wceGdiInvertRect(rdc, prt);
#elif defined(WIN32)
	winGdiInvertRect(rdc, prt);
#endif
}

void _gdi_exclude_rect(visual_t rdc, const xrect_t* pxr)
{
#if defined(WINCE)
	wceGdiExcludeRect(rdc, pxr);
#elif defined(WIN32)
	winGdiExcludeRect(rdc, pxr);
#endif
}

void _gdi_inclip_rect(visual_t rdc, const xrect_t* pxr)
{
#if defined(WINCE)
	wceGdiInclipRect(rdc, pxr);
#elif defined(WIN32)
	winGdiInclipRect(rdc, pxr);
#endif
}

#ifdef XDU_SUPPORT_CONTEXT_BITMAP
void _gdi_draw_image(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt)
{
#if defined(WINCE)
	wceGdiDrawImage(rdc, rbm, clr, prt);
#elif defined(WIN32)
	winGdiDrawImage(rdc, rbm, clr, prt);
#endif
}

void _gdi_draw_bitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt)
{
#if defined(WINCE)
	wceGdiDrawBitmap(rdc, rbm, ppt);
#elif defined(WIN32)
	winGdiDrawBitmap(rdc, rbm, ppt);
#endif
}
#endif

#ifdef XDU_SUPPORT_CONTEXT_REGION
void _gdi_fill_region(visual_t rdc, const xbrush_t* pxb, res_rgn_t rgn)
{
#if defined(WINCE)
	wceGdiFillRegion(rdc, pxb, rgn);
#elif defined(WIN32)
	winGdiFillRegion(rdc, pxb, rgn);
#endif
}
#endif

void _gdi_font_size(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
#if defined(WINCE)
	wceGdiFontSize(rdc, pxf, pxs);
#elif defined(WIN32)
	winGdiFontSize(rdc, pxf, pxs);
#endif
}

fontset_t _gdi_get_fontset(visual_t rdc)
{
#if defined(WINCE)
	return wceGdiGetFontset(rdc);
#elif defined(WIN32)
	return winGdiGetFontset(rdc);
#endif
}

fontset_t _gdi_create_fontset(const xfont_t* pxf)
{
#if defined(WINCE)
	return wceGdiCreateFontset(pxf);
#elif defined(WIN32)
	return winGdiCreateFontset(pxf);
#endif
}

void _gdi_destroy_fontset(fontset_t ft)
{
#if defined(WINCE)
	wceGdiDestroyFontset(ft);
#elif defined(WIN32)
	winGdiDestroyFontset(ft);
#endif
}

void _gdi_word_size(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs)
{
#if defined(WINCE)
	wceGdiWordSize(ft, pch, chs, pxs);
#elif defined(WIN32)
	winGdiWordSize(ft, pch, chs, pxs);
#endif
}

#endif //XDU_SUPPORT_CONTEXT_GRAPHIC


