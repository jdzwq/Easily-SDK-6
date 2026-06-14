/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu macos definition document

	@module	_if_cocoa.h | macos interface file

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

#ifndef _IF_COCOA_H
#define _IF_COCOA_H

#include "../../xdudef.h"

#if defined(__OBJC__)
#import <Cocoa/Cocoa.h>
#else
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h> 
#include <CoreImage/CoreImage.h>
typedef void* id;
#endif

//global fonstset cache
extern fontset_t g_fontset;

typedef id  res_clrmap_t;

typedef struct _cocoa_bitmap_t{
	handle_head head;

	CGImageRef image;
}cocoa_bitmap_t;

typedef struct _cocoa_context_t{
    handle_head head;
	
	CGContextRef context;
	CGColorSpaceRef colors;
	CGRect client;
	void* bitmap;
	
	int type;

	fontset_t fontset;
}cocoa_context_t;

typedef struct _cocoa_fontset_t{
	handle_head head;

    id font_object;
	float font_height;
}cocoa_fontset_t;

typedef struct _cocoa_widget_t{
	handle_head head;

	uid_t uid;
	id self;
	id parent;
	id owner;
	void* accel;

	dword_t style;
	int mode;
	int result;
	int retcode;

	float diaph;
	dword_t mask;
	int state;
	bool_t disable;

	scroll_t hs;
	scroll_t vs;
	color_mod_t clrs;
}cocoa_widget_t;


int coContextStartup(void);
void coContextCleanup(void);
visual_t coCreateDisplayContext(widget_t wt);
visual_t coCreateCompatibleContext(visual_t rdc, int cx, int cy);
void coDestroyContext(visual_t rdc);
void coGetDeviceCaps(visual_t rdc, dev_cap_t* pcap);
void coRenderContext(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth);

bitmap_t coCreateContextBitmap(visual_t rdc);
bitmap_t coCreateColorBitmap(visual_t rdc, const xcolor_t* pxc, int w, int h);
bitmap_t coCreatePatternBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h);
bitmap_t coCreateGradientBitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type);
bitmap_t coCreateCode128Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols);
bitmap_t coCreatePDF417Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t coCreateQRCodeBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t coCreateStorageBitmap(visual_t rdc, const tchar_t* fname);
bitmap_t coLoadBitmapFromBytes(visual_t rdc, const unsigned char* pb, dword_t bytes);
dword_t coSaveBitmapToBytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max);
bitmap_t coLoadBitmapFromIcon(visual_t rdc, const tchar_t* iname);
bitmap_t coLoadBitmapFromThumb(visual_t rdc, const tchar_t* file);
void coDestroyBitmap(bitmap_t rbm);
dword_t coGetBitmapBytes(bitmap_t rb);
void coGetBitmapSize(bitmap_t rbm, int* pw, int* ph);

void coGdiInit(int osv);
void coGdiUnInit(void);
void coGdiSetXFont(visual_t rdc, const xfont_t* pxf);
void coGdiGetXFont(visual_t rdc, xfont_t* pxf);
void coGdiGetPoint(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt);
void coGdiSetPoint(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt);
void coGdiDrawPoints(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n);
void coGdiDrawLine(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2);
void coGdiDrawPolyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n);
void coGdiDrawArc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t closewise, bool_t largearc);
void coGdiDrawBezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4);
void coGdiDrawCurve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn);
void coGdiDrawPath(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn);
void coGdiDrawRect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void coGdiDrawRound(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs);
void coGdiDrawEllipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void coGdiDrawPie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct);
void coGdiDrawPolygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n);
void coGdiDrawText(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len);
void coGdiTextOut(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len);
void coGdiTextRect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt);
void coGdiTextSize(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs);
void coGdiGradientRect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt);
void coGdiAlphablendRect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity);
void coGdiInvertRect(visual_t rdc, const xrect_t* prt);
void coGdiExcludeRect(visual_t rdc, const xrect_t* pxr);
void coGdiInclipRect(visual_t rdc, const xrect_t* pxr);
void coGdiDrawImage(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt);
void coGdiDrawBitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt);
void coGdiFontSize(visual_t rdc, const xfont_t* pxf, xsize_t* pxs);
fontset_t coGdiGetFontset(visual_t rdc);
fontset_t coGdiCreateFontset(const xfont_t* pxf);
void coGdiDestroyFontset(fontset_t ft);
void coGdiWordSize(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs);

void coWidgetStartup(int ver);
void coWidgetCleanup(void);
widget_t coWidgetCreate(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev);
void coWidgetDestroy(widget_t wt);
void coWidgetClose(widget_t wt, int ret);
const if_subproc_t* coWidgetGetSubproc(widget_t wt, uid_t sid);
bool_t coWidgetSetSubproc(widget_t wt, uid_t sid, if_subproc_t* sub);
void coWidgetDelSubproc(widget_t wt, uid_t sid);
bool_t coWidgetSetSubprocDelta(widget_t wt, uid_t sid, vword_t delta);
vword_t coWidgetGetSubprocDelta(widget_t wt, uid_t sid);
bool_t coWidgetHasSubproc(widget_t wt, uid_t sid);
void coWidgetSetCoreDelta(widget_t wt, vword_t pd);
vword_t coWidgetGetCoreDelta(widget_t wt);
void coWidgetSetUserDelta(widget_t wt, vword_t pd);
vword_t coWidgetGetUserDelta(widget_t wt);
void coWidgetSetStyle(widget_t wt, dword_t ws);
dword_t coWidgetGetStyle(widget_t wt);
void coWidgetSetAccel(widget_t wt, const accel_table_t* pacl, int n);
void coWidgetSetOwner(widget_t wt, widget_t owner);
widget_t coWidgetGetOwner(widget_t wt);
void coWidgetSetUserId(widget_t wt, uid_t uid);
uid_t coWidgetGetUserId(widget_t wt);
void coWidgetSetUserResult(widget_t wt, int rt);
int coWidgetGetUserResult(widget_t wt);
widget_t coWidgetGetChild(widget_t wt, uid_t uid);
widget_t coWidgetGetParent(widget_t wt);
void coWidgetSetUserProp(widget_t wt, const tchar_t* pname,vword_t val);
vword_t coWidgetGetUserProp(widget_t wt, const tchar_t* pname);
vword_t coWidgetDelUserProp(widget_t wt, const tchar_t* pname);
const if_dispatch_t* coWidgetGetDispatch(widget_t wt);
bool_t coWidgetIsMaximized(widget_t wt);
bool_t coWidgetIsMinimized(widget_t wt);
bool_t coWidgetEnumChild(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv);
visual_t coWidgetClientContext(widget_t wt);
visual_t coWidgetWindowContext(widget_t wt);
void coWidgetReleaseContext(widget_t wt, visual_t dc);
void coWidgetGetClientRect(widget_t wt, xrect_t* prt);
void coWidgetGetWindowRect(widget_t wt, xrect_t* prt);
void coWidgetClientToScreen(widget_t wt, xpoint_t* ppt);
void coWidgetScreenToClient(widget_t wt, xpoint_t* ppt);
void coWidgetClientToWindow(widget_t wt, xpoint_t* ppt);
void coWidgetWindowToClient(widget_t wt, xpoint_t* ppt);
void coWidgetCenterWindow(widget_t wt, widget_t owner);
void coWidgetSetCursor(widget_t wt, int ci);
void coWidgetSetCapture(widget_t wt, bool_t b);
vword_t coWidgetSetTimer(widget_t wt, int ms);
void coWidgetKillTimer(widget_t wt, vword_t tid);
void coWidgetCreateCaret(widget_t wt, int w, int h);
void coWidgetDestroyCaret(widget_t wt);
void coWidgetShowCaret(widget_t wt, int x, int y);
void coWidgetSetFocus(widget_t wt);
bool_t coWidgetKeyState(widget_t wt, int ks);
bool_t coWidgetIsValid(widget_t wt);
bool_t coWidgetIsFocus(widget_t wt);
bool_t coWidgetIsChild(widget_t wt);
bool_t coWidgetIsOwnerNc(widget_t wt);
void coWidgetMove(widget_t wt, const xpoint_t* ppt);
void coWidgetSize(widget_t wt, const xsize_t* pxs);
void coWidgetTake(widget_t wt, int zor);
void coWidgetShow(widget_t wt, dword_t sw);
void coWidgetLayout(widget_t wt);
void coWidgetErase(widget_t wt, const xrect_t* prt);
void coWidgetEnable(widget_t wt, bool_t b);
void coWidgetEnableHover(widget_t wt, bool_t b);
void coWidgetPostNotice(widget_t wt, NOTICE* pnt);
int coWidgetSendNotice(widget_t wt, NOTICE* pnt);
void coWidgetPostCommand(widget_t wt, int code, uid_t cid, vword_t data);
int coWidgetSendCommand(widget_t wt, int code, uid_t cid, vword_t data);
void coWidgetPostWChar(widget_t wt, wchar_t ch);
void coWidgetPostKey(widget_t wt, int key);
void coWidgetSetTitle(widget_t wt, const tchar_t* token);
int coWidgetGetTitle(widget_t wt, tchar_t* buf, int max);
void coWidgetActive(widget_t wt);
void coWidgetScroll(widget_t wt, bool_t horz, int line);
void coWidgetGetScrollInfo(widget_t wt, bool_t horz, scroll_t* psl);
void coWidgetSetScrollInfo(widget_t wt, bool_t horz, const scroll_t* psl);
void coWidgetSetColorMode(widget_t wt, const color_mod_t* pclr);
void coWidgetGetColorMode(widget_t wt, color_mod_t* pclr);
const color_mod_t* coWidgetGetColorModePtr(widget_t wt);
void coWidgetSetDiaph(widget_t wt, float f);
float coWidgetGetDiaph(widget_t wt);
int	coWidgetDoMain(widget_t wt);
int	coWidgetDoModal(widget_t wt);
void coWidgetDoTrack(widget_t wt);

void coMessageQuit(int code);
void coMessagePosition(xpoint_t* pxp);

void coCalcWidgetBorder(dword_t ws, border_t* pbd);
void coAdjustWidgetSize(dword_t wstyle, xsize_t* pxs);
void coGetScreenSize(xsize_t* pxs);
void coGetDesktopRect(xrect_t* pxr);
void coScreenSizeToMm(xsize_t* pxs);
void coScreenSizeToPt(xsize_t* pxs);

bool_t coShellGetFileName(widget_t owner, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen);
bool_t coShellGetPathName(widget_t owner, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen);
bool_t coShellGetCurPath(tchar_t* pathbuf, int pathlen);
bool_t coShellGetRunPath(tchar_t* pathbuf, int pathlen);
bool_t coShellGetAppPath(tchar_t* pathbuf, int pathlen);
bool_t coShellGetDocPath(tchar_t* pathbuf, int pathlen);
bool_t coShellGetTmpPath(tchar_t* pathbuf, int pathlen);

bool_t coClipboardPut(widget_t wt, int fmt, const byte_t* data, dword_t size);
dword_t coClipboardGet(widget_t wt, int fmt, byte_t* buf, dword_t max);


#endif //_IF_COCOA_H