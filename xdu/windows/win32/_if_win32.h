/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu windows definition document

	@module	_if_win32.h | windows interface file

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

#ifndef _IF_WIN32_H
#define _IF_WIN32_H

#include "../../xdudef.h"

#include <stdio.h>
#include <tchar.h>
#include <math.h>
#include <time.h>

#include <ole2.h>
#include <olectl.h>
#include <commctrl.h>
#include <ShellAPI.h>
#include <ShlObj.h>

//global fonstset cache
extern fontset_t g_fontset;

typedef struct _win32_widget_t{
	handle_head head;

	uid_t uid;
	HWND self;
	HWND parent;
	HWND owner;
	HACCEL accel;
	
	dword_t style;
	int mode;
	int result;
	int retcode;

	scroll_t hs;
	scroll_t vs;
	color_mod_t clrs;
}win32_widget_t;

typedef struct _win32_context_t{
	handle_head head;

	HDC context;
	union
	{
		HBITMAP bitmap;
		HWND window;
	}device;
	int type;

	fontset_t fontset;
}win32_context_t;

typedef struct _win32_fontset_t{
	handle_head head;

    void* font_object;
}win32_fontset_t;

typedef struct _win32_bitmap_t{
	handle_head head;

	HBITMAP bitmap;
}win32_bitmap_t;



int winContextStartup(void);
void winContextCleanup(void);
visual_t winCreateDisplayContext(widget_t wt);
visual_t winCreateCompatibleContext(visual_t rdc, int cx, int cy);
void winDestroyContext(visual_t rdc);
void winGetDeviceCaps(visual_t rdc, dev_cap_t* pcap);
void winRenderContext(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth);

bool_t winDefaultPrinterMode(dev_prn_t* pmod);
bool_t winSetupPrinterMode(widget_t wt, dev_prn_t* pmod);
visual_t winCreatePrinterContext(const dev_prn_t* pmod);
void winDestroyPrinterContext(visual_t rdc);
void winBeginPage(visual_t rdc);
void winEndPage(visual_t rdc);
void winBeginDoc(visual_t rdc, const tchar_t* docname);
void winEndDoc(visual_t rdc);

bitmap_t winCreateContextBitmap(visual_t rdc);
bitmap_t winCreateColorBitmap(visual_t rdc, const xcolor_t* pxc, int w, int h);
bitmap_t winCreatePatternBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h);
bitmap_t winCreateGradientBitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type);
bitmap_t winCreateCode128Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols);
bitmap_t winCreatePDF417Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t winCreateQRCodeBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t winCreateStorageBitmap(visual_t rdc, const tchar_t* fname);
bitmap_t winLoadBitmapFromBytes(visual_t rdc, const unsigned char* pb, dword_t bytes);
dword_t winSaveBitmapToBytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max);
bitmap_t winLoadBitmapFromIcon(visual_t rdc, const tchar_t* iname);
bitmap_t winLoadBitmapFromThumb(visual_t rdc, const tchar_t* file);
void winDestroyBitmap(bitmap_t rbm);
dword_t winGetBitmapBytes(bitmap_t rb);
void winGetBitmapSize(bitmap_t rbm, int* pw, int* ph);

void winGdiInit(int osv);
void winGdiUnInit(void);
void winGdiSetXFont(visual_t rdc, const xfont_t* pxf);
void winGdiGetXFont(visual_t rdc, xfont_t* pxf);
void winGdiGetPoint(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt);
void winGdiSetPoint(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt);
void winGdiDrawPoints(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n);
void winGdiDrawLine(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2);
void winGdiDrawPolyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n);
void winGdiDrawArc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t closewise, bool_t largearc);
void winGdiDrawBezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4);
void winGdiDrawCurve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn);
void winGdiDrawPath(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn);
void winGdiDrawRect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void winGdiDrawRound(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs);
void winGdiDrawEllipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void winGdiDrawPie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct);
void winGdiDrawPolygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n);
void winGdiDrawText(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len);
void winGdiTextOut(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len);
void winGdiTextRect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt);
void winGdiTextSize(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs);
void winGdiGradientRect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt);
void winGdiAlphablendRect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity);
void winGdiInvertRect(visual_t rdc, const xrect_t* prt);
void winGdiExcludeRect(visual_t rdc, const xrect_t* pxr);
void winGdiInclipRect(visual_t rdc, const xrect_t* pxr);
void winGdiDrawImage(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt);
void winGdiDrawBitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt);
void winGdiFontSize(visual_t rdc, const xfont_t* pxf, xsize_t* pxs);
fontset_t winGdiGetFontset(visual_t rdc);
fontset_t winGdiCreateFontset(const xfont_t* pxf);
void winGdiDestroyFontset(fontset_t ft);
void winGdiWordSize(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs);

void winWidgetStartup(int ver);
void winWidgetCleanup(void);
widget_t winWidgetCreate(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev);
void winWidgetDestroy(widget_t wt);
void winWidgetClose(widget_t wt, int ret);
const if_subproc_t* winWidgetGetSubproc(widget_t wt, uid_t sid);
bool_t winWidgetSetSubproc(widget_t wt, uid_t sid, if_subproc_t* sub);
void winWidgetDelSubproc(widget_t wt, uid_t sid);
bool_t winWidgetSetSubprocDelta(widget_t wt, uid_t sid, vword_t delta);
vword_t winWidgetGetSubprocDelta(widget_t wt, uid_t sid);
bool_t winWidgetHasSubproc(widget_t wt, uid_t sid);
void winWidgetSetCoreDelta(widget_t wt, vword_t pd);
vword_t winWidgetGetCoreDelta(widget_t wt);
void winWidgetSetUserDelta(widget_t wt, vword_t pd);
vword_t winWidgetGetUserDelta(widget_t wt);
void winWidgetSetStyle(widget_t wt, dword_t ws);
dword_t winWidgetGetStyle(widget_t wt);
void winWidgetSetAccel(widget_t wt, const accel_table_t* pacl, int n);
void winWidgetSetOwner(widget_t wt, widget_t owner);
widget_t winWidgetGetOwner(widget_t wt);
void winWidgetSetUserId(widget_t wt, uid_t uid);
uid_t winWidgetGetUserId(widget_t wt);
void winWidgetSetUserResult(widget_t wt, int rt);
int winWidgetGetUserResult(widget_t wt);
widget_t winWidgetGetChild(widget_t wt, uid_t uid);
widget_t winWidgetGetParent(widget_t wt);
void winWidgetSetUserProp(widget_t wt, const tchar_t* pname,vword_t val);
vword_t winWidgetGetUserProp(widget_t wt, const tchar_t* pname);
vword_t winWidgetDelUserProp(widget_t wt, const tchar_t* pname);
const if_dispatch_t* winWidgetGetDispatch(widget_t wt);
bool_t winWidgetIsMaximized(widget_t wt);
bool_t winWidgetIsMinimized(widget_t wt);
bool_t winWidgetEnumChild(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv);
visual_t winWidgetClientContext(widget_t wt);
visual_t winWidgetWindowContext(widget_t wt);
void winWidgetReleaseContext(widget_t wt, visual_t dc);
void winWidgetGetClientRect(widget_t wt, xrect_t* prt);
void winWidgetGetWindowRect(widget_t wt, xrect_t* prt);
void winWidgetClientToScreen(widget_t wt, xpoint_t* ppt);
void winWidgetScreenToClient(widget_t wt, xpoint_t* ppt);
void winWidgetClientToWindow(widget_t wt, xpoint_t* ppt);
void winWidgetWindowToClient(widget_t wt, xpoint_t* ppt);
void winWidgetCenterWindow(widget_t wt, widget_t owner);
void winWidgetSetCursor(widget_t wt, int ci);
void winWidgetSetCapture(widget_t wt, bool_t b);
vword_t winWidgetSetTimer(widget_t wt, int ms);
void winWidgetKillTimer(widget_t wt, vword_t tid);
void winWidgetCreateCaret(widget_t wt, int w, int h);
void winWidgetDestroyCaret(widget_t wt);
void winWidgetShowCaret(widget_t wt, int x, int y);
void winWidgetSetFocus(widget_t wt);
bool_t winWidgetKeyState(widget_t wt, int ks);
bool_t winWidgetIsValid(widget_t wt);
bool_t winWidgetIsFocus(widget_t wt);
bool_t winWidgetIsChild(widget_t wt);
bool_t winWidgetIsOwnerNc(widget_t wt);
void winWidgetMove(widget_t wt, const xpoint_t* ppt);
void winWidgetSize(widget_t wt, const xsize_t* pxs);
void winWidgetTake(widget_t wt, int zor);
void winWidgetShow(widget_t wt, dword_t sw);
void winWidgetLayout(widget_t wt);
void winWidgetErase(widget_t wt, const xrect_t* prt);
void winWidgetEnable(widget_t wt, bool_t b);
void winWidgetEnableHover(widget_t wt, bool_t b);
void winWidgetPostNotice(widget_t wt, NOTICE* pnt);
int winWidgetSendNotice(widget_t wt, NOTICE* pnt);
void winWidgetPostCommand(widget_t wt, int code, uid_t cid, vword_t data);
int winWidgetSendCommand(widget_t wt, int code, uid_t cid, vword_t data);
void winWidgetPostWChar(widget_t wt, wchar_t ch);
void winWidgetPostKey(widget_t wt, int key);
void winWidgetSetTitle(widget_t wt, const tchar_t* token);
int winWidgetGetTitle(widget_t wt, tchar_t* buf, int max);
void winWidgetActive(widget_t wt);
void winWidgetScroll(widget_t wt, bool_t horz, int line);
void winWidgetGetScrollInfo(widget_t wt, bool_t horz, scroll_t* psl);
void winWidgetSetScrollInfo(widget_t wt, bool_t horz, const scroll_t* psl);
void winWidgetSetColorMode(widget_t wt, const color_mod_t* pclr);
void winWidgetGetColorMode(widget_t wt, color_mod_t* pclr);
const color_mod_t* winWidgetGetColorModePtr(widget_t wt);
void winWidgetSetDiaph(widget_t wt, float f);
float winWidgetGetDiaph(widget_t wt);
int	winWidgetDoMain(widget_t wt);
int	winWidgetDoModal(widget_t wt);
void winWidgetDoTrack(widget_t wt);

void winMessageQuit(int code);
void winMessagePosition(xpoint_t* pxp);

void winCalcWidgetBorder(dword_t ws, border_t* pbd);
void winAdjustWidgetSize(dword_t wstyle, xsize_t* pxs);
void winGetScreenSize(xsize_t* pxs);
void winGetDesktopRect(xrect_t* pxr);
void winScreenSizeToMm(xsize_t* pxs);
void winScreenSizeToPt(xsize_t* pxs);

int winWidgetNcHintTest(widget_t wt, const xpoint_t* pxp);
int winWidgetNcCalcScroll(widget_t wt, bool_t horz, const xpoint_t* pxp);
void winWidgetNcDrawFrame(widget_t wt, visual_t dc, const xrect_t* prt);
void winWidgetNcDrawScroll(widget_t wt, visual_t dc, bool_t horz, const xrect_t* prt);


bool_t winShellGetFileName(widget_t owner, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen);
bool_t winShellGetPathName(widget_t owner, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen);
bool_t winShellGetCurPath(tchar_t* pathbuf, int pathlen);
bool_t winShellGetRunPath(tchar_t* pathbuf, int pathlen);
bool_t winShellGetAppPath(tchar_t* pathbuf, int pathlen);
bool_t winShellGetDocPath(tchar_t* pathbuf, int pathlen);
bool_t winShellGetTmpPath(tchar_t* pathbuf, int pathlen);

bool_t winClipboardPut(widget_t wt, int fmt, const byte_t* data, dword_t size);
dword_t winClipboardGet(widget_t wt, int fmt, byte_t* buf, dword_t max);


#endif //_IF_WIN32_H