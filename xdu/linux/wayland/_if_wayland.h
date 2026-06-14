/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu linux definition document

	@module	_if_wayland.h | wayland interface file

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

#ifndef _IF_WAYLAND_H
#define _IF_WAYLAND_H

#include "../../xdudef.h"
#include "_wayland.h"

extern res_queue_t g_queue;

//global fonstset cache
extern fontset_t    g_fontset;

typedef struct _wayland_bitmap_t{
	handle_head head;

}wayland_bitmap_t;

typedef struct _wayland_context_t{
    handle_head head;
    int type;

    fontset_t fontset;
}wayland_context_t;

typedef struct _wayland_fontset_t{
	handle_head head;

    void* font_object;
    float font_height;
}wayland_fontset_t;

typedef struct _wayland_widget_t{
    handle_head head;

    uid_t uid;
	wayland_window* self;
	wayland_window* parent;
	wayland_window* owner;
    void* accel;
	
    dword_t style;
	int mode;
	int result;
	int retcode;

	float diaph;
	bool_t disable;

    scroll_t hs;
	scroll_t vs;
    color_mod_t clrs;

    res_timer_t ctt;

	bool_t tog;
	caret_t car;

    xpoint_t pt;
    xsize_t st;
}wayland_widget_t;


int wlContextStartup(void);
void wlContextCleanup(void);
visual_t wlCreateDisplayContext(widget_t wt);
visual_t wlCreateCompatibleContext(visual_t rdc, int cx, int cy);
void wlDestroyContext(visual_t rdc);
void wlGetDeviceCaps(visual_t rdc, dev_cap_t* pcap);
void wlRenderContext(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth);

bitmap_t wlCreateContextBitmap(visual_t rdc);
bitmap_t wlCreateColorBitmap(visual_t rdc, const xcolor_t* pxc, int w, int h);
bitmap_t wlCreatePatternBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h);
bitmap_t wlCreateGradientBitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type);
bitmap_t wlCreateCode128Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols);
bitmap_t wlCreatePDF417Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t wlCreateQRCodeBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t wlCreateStorageBitmap(visual_t rdc, const tchar_t* fname);
bitmap_t wlLoadBitmapFromBytes(visual_t rdc, const unsigned char* pb, dword_t bytes);
dword_t wlSaveBitmapToBytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max);
bitmap_t wlLoadBitmapFromIcon(visual_t rdc, const tchar_t* iname);
bitmap_t wlLoadBitmapFromThumb(visual_t rdc, const tchar_t* file);
void wlDestroyBitmap(bitmap_t rbm);
dword_t wlGetBitmapBytes(bitmap_t rb);
void wlGetBitmapSize(bitmap_t rbm, int* pw, int* ph);

void wlGdiInit(int osv);
void wlGdiUnInit(void);
void wlGdiSetXFont(visual_t rdc, const xfont_t* pxf);
void wlGdiGetXFont(visual_t rdc, xfont_t* pxf);
void wlGdiGetPoint(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt);
void wlGdiSetPoint(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt);
void wlGdiDrawPoints(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n);
void wlGdiDrawLine(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2);
void wlGdiDrawPolyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n);
void wlGdiDrawArc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t closewise, bool_t largearc);
void wlGdiDrawBezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4);
void wlGdiDrawCurve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn);
void wlGdiDrawPath(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn);
void wlGdiDrawRect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void wlGdiDrawRound(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs);
void wlGdiDrawEllipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void wlGdiDrawPie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct);
void wlGdiDrawPolygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n);
void wlGdiDrawText(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len);
void wlGdiTextOut(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len);
void wlGdiTextRect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt);
void wlGdiTextSize(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs);
void wlGdiGradientRect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt);
void wlGdiAlphablendRect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity);
void wlGdiInvertRect(visual_t rdc, const xrect_t* prt);
void wlGdiExcludeRect(visual_t rdc, const xrect_t* pxr);
void wlGdiInclipRect(visual_t rdc, const xrect_t* pxr);
void wlGdiDrawImage(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt);
void wlGdiDrawBitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt);
void wlGdiFontSize(visual_t rdc, const xfont_t* pxf, xsize_t* pxs);
fontset_t wlGdiGetFontset(visual_t rdc);
fontset_t wlGdiCreateFontset(const xfont_t* pxf);
void wlGdiDestroyFontset(fontset_t ft);
void wlGdiWordSize(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs);

void wlWidgetStartup(int ver);
void wlWidgetCleanup(void);
widget_t wlWidgetCreate(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev);
void wlWidgetDestroy(widget_t wt);
void wlWidgetClose(widget_t wt, int ret);
const if_subproc_t* wlWidgetGetSubproc(widget_t wt, uid_t sid);
bool_t wlWidgetSetSubproc(widget_t wt, uid_t sid, if_subproc_t* sub);
void wlWidgetDelSubproc(widget_t wt, uid_t sid);
bool_t wlWidgetSetSubprocDelta(widget_t wt, uid_t sid, vword_t delta);
vword_t wlWidgetGetSubprocDelta(widget_t wt, uid_t sid);
bool_t wlWidgetHasSubproc(widget_t wt, uid_t sid);
void wlWidgetSetCoreDelta(widget_t wt, vword_t pd);
vword_t wlWidgetGetCoreDelta(widget_t wt);
void wlWidgetSetUserDelta(widget_t wt, vword_t pd);
vword_t wlWidgetGetUserDelta(widget_t wt);
void wlWidgetSetStyle(widget_t wt, dword_t ws);
dword_t wlWidgetGetStyle(widget_t wt);
void wlWidgetSetAccel(widget_t wt, const accel_table_t* pacl, int n);
void wlWidgetSetOwner(widget_t wt, widget_t owner);
widget_t wlWidgetGetOwner(widget_t wt);
void wlWidgetSetUserId(widget_t wt, uid_t uid);
uid_t wlWidgetGetUserId(widget_t wt);
void wlWidgetSetUserResult(widget_t wt, int rt);
int wlWidgetGetUserResult(widget_t wt);
widget_t wlWidgetGetChild(widget_t wt, uid_t uid);
widget_t wlWidgetGetParent(widget_t wt);
void wlWidgetSetUserProp(widget_t wt, const tchar_t* pname,vword_t val);
vword_t wlWidgetGetUserProp(widget_t wt, const tchar_t* pname);
vword_t wlWidgetDelUserProp(widget_t wt, const tchar_t* pname);
const if_dispatch_t* wlWidgetGetDispatch(widget_t wt);
bool_t wlWidgetIsMaximized(widget_t wt);
bool_t wlWidgetIsMinimized(widget_t wt);
bool_t wlWidgetEnumChild(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv);
visual_t wlWidgetClientContext(widget_t wt);
visual_t wlWidgetWindowContext(widget_t wt);
void wlWidgetReleaseContext(widget_t wt, visual_t dc);
void wlWidgetGetClientRect(widget_t wt, xrect_t* prt);
void wlWidgetGetWindowRect(widget_t wt, xrect_t* prt);
void wlWidgetClientToScreen(widget_t wt, xpoint_t* ppt);
void wlWidgetScreenToClient(widget_t wt, xpoint_t* ppt);
void wlWidgetClientToWindow(widget_t wt, xpoint_t* ppt);
void wlWidgetWindowToClient(widget_t wt, xpoint_t* ppt);
void wlWidgetCenterWindow(widget_t wt, widget_t owner);
void wlWidgetSetCursor(widget_t wt, int ci);
void wlWidgetSetCapture(widget_t wt, bool_t b);
vword_t wlWidgetSetTimer(widget_t wt, int ms);
void wlWidgetKillTimer(widget_t wt, vword_t tid);
void wlWidgetCreateCaret(widget_t wt, int w, int h);
void wlWidgetDestroyCaret(widget_t wt);
void wlWidgetShowCaret(widget_t wt, int x, int y);
void wlWidgetSetFocus(widget_t wt);
bool_t wlWidgetKeyState(widget_t wt, int ks);
bool_t wlWidgetIsValid(widget_t wt);
bool_t wlWidgetIsFocus(widget_t wt);
bool_t wlWidgetIsChild(widget_t wt);
bool_t wlWidgetIsOwnerNc(widget_t wt);
void wlWidgetMove(widget_t wt, const xpoint_t* ppt);
void wlWidgetSize(widget_t wt, const xsize_t* pxs);
void wlWidgetTake(widget_t wt, int zor);
void wlWidgetShow(widget_t wt, dword_t sw);
void wlWidgetLayout(widget_t wt);
void wlWidgetErase(widget_t wt, const xrect_t* prt);
void wlWidgetEnable(widget_t wt, bool_t b);
void wlWidgetEnableHover(widget_t wt, bool_t b);
void wlWidgetPostNotice(widget_t wt, NOTICE* pnt);
int wlWidgetSendNotice(widget_t wt, NOTICE* pnt);
void wlWidgetPostCommand(widget_t wt, int code, uid_t cid, vword_t data);
int wlWidgetSendCommand(widget_t wt, int code, uid_t cid, vword_t data);
void wlWidgetPostWChar(widget_t wt, wchar_t ch);
void wlWidgetPostKey(widget_t wt, int key);
void wlWidgetSetTitle(widget_t wt, const tchar_t* token);
int wlWidgetGetTitle(widget_t wt, tchar_t* buf, int max);
void wlWidgetActive(widget_t wt);
void wlWidgetScroll(widget_t wt, bool_t horz, int line);
void wlWidgetGetScrollInfo(widget_t wt, bool_t horz, scroll_t* psl);
void wlWidgetSetScrollInfo(widget_t wt, bool_t horz, const scroll_t* psl);
void wlWidgetSetColorMode(widget_t wt, const color_mod_t* pclr);
void wlWidgetGetColorMode(widget_t wt, color_mod_t* pclr);
const color_mod_t* wlWidgetGetColorModePtr(widget_t wt);
void wlWidgetSetDiaph(widget_t wt, float f);
float wlWidgetGetDiaph(widget_t wt);
int	wlWidgetDoMain(widget_t wt);
int	wlWidgetDoModal(widget_t wt);
void wlWidgetDoTrack(widget_t wt);

void wlMessageQuit(int code);
void wlMessagePosition(xpoint_t* pxp);

void wlCalcWidgetBorder(dword_t ws, border_t* pbd);
void wlAdjustWidgetSize(dword_t wstyle, xsize_t* pxs);
void wlGetScreenSize(xsize_t* pxs);
void wlGetDesktopRect(xrect_t* pxr);
void wlScreenSizeToMm(xsize_t* pxs);
void wlScreenSizeToPt(xsize_t* pxs);

bool_t wlShellGetFileName(widget_t owner, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen);
bool_t wlShellGetPathName(widget_t owner, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen);
bool_t wlShellGetCurPath(tchar_t* pathbuf, int pathlen);
bool_t wlShellGetRunPath(tchar_t* pathbuf, int pathlen);
bool_t wlShellGetAppPath(tchar_t* pathbuf, int pathlen);
bool_t wlShellGetDocPath(tchar_t* pathbuf, int pathlen);
bool_t wlShellGetTmpPath(tchar_t* pathbuf, int pathlen);

bool_t wlClipboardPut(widget_t wt, int fmt, const byte_t* data, dword_t size);
dword_t wlClipboardGet(widget_t wt, int fmt, byte_t* buf, dword_t max);


#endif //_IF_WAYLAND_H