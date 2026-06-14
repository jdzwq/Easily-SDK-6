/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu windows definition document

	@module	_xdu_wce.h | windows ce interface file

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

#ifndef _IF_WINCE_H
#define _IF_WINCE_H

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


typedef struct _wince_widget_t{
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
}wince_widget_t;

typedef COLORREF	pixel_t;


//global fonstset cache
extern fontset_t g_fontset;

typedef struct _wince_context_t{
	handle_head head;

	HDC context;
	union
	{
		HBITMAP bitmap;
		HWND window;
	}device;
	int type;

	fontset_t fontset;
}wince_context_t;

typedef struct _wince_fontset_t{
	handle_head head;

    void* font_object;
}wince_fontset_t;

typedef struct _wince_bitmap_t{
	handle_head head;

	HBITMAP bitmap;
}wince_bitmap_t;



int wceContextStartup(void);
void wceContextCleanup(void);
visual_t wceCreateDisplayContext(widget_t wt);
visual_t wceCreateCompatibleContext(visual_t rdc, int cx, int cy);
void wceDestroyContext(visual_t rdc);
void wceGetDeviceCaps(visual_t rdc, dev_cap_t* pcap);
void wceRenderContext(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth);

bool_t wceDefaultPrinterMode(dev_prn_t* pmod);
bool_t wceSetupPrinterMode(widget_t wt, dev_prn_t* pmod);
visual_t wceCreatePrinterContext(const dev_prn_t* pmod);
void wceDestroyPrinterContext(visual_t rdc);
void wceBeginPage(visual_t rdc);
void wceEndPage(visual_t rdc);
void wceBeginDoc(visual_t rdc, const tchar_t* docname);
void wceEndDoc(visual_t rdc);

bitmap_t wceCreateContextBitmap(visual_t rdc);
bitmap_t wceCreateColorBitmap(visual_t rdc, const xcolor_t* pxc, int w, int h);
bitmap_t wceCreatePatternBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h);
bitmap_t wceCreateGradientBitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type);
bitmap_t wceCreateCode128Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols);
bitmap_t wceCreatePDF417Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t wceCreateQRCodeBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t wceCreateStorageBitmap(visual_t rdc, const tchar_t* fname);
bitmap_t wceLoadBitmapFromBytes(visual_t rdc, const unsigned char* pb, dword_t bytes);
dword_t wceSaveBitmapToBytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max);
bitmap_t wceLoadBitmapFromIcon(visual_t rdc, const tchar_t* iname);
bitmap_t wceLoadBitmapFromThumb(visual_t rdc, const tchar_t* file);
void wceDestroyBitmap(bitmap_t rbm);
dword_t wceGetBitmapBytes(bitmap_t rb);
void wceGetBitmapSize(bitmap_t rbm, int* pw, int* ph);

void wceGdiInit(int osv);
void wceGdiUnInit(void);
void wceGdiSetXFont(visual_t rdc, const xfont_t* pxf);
void wceGdiGetXFont(visual_t rdc, xfont_t* pxf);
void wceGdiGetPoint(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt);
void wceGdiSetPoint(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt);
void wceGdiDrawPoints(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n);
void wceGdiDrawLine(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2);
void wceGdiDrawPolyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n);
void wceGdiDrawArc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t closewise, bool_t largearc);
void wceGdiDrawBezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4);
void wceGdiDrawCurve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn);
void wceGdiDrawPath(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn);
void wceGdiDrawRect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void wceGdiDrawRound(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs);
void wceGdiDrawEllipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void wceGdiDrawPie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct);
void wceGdiDrawPolygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n);
void wceGdiDrawText(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len);
void wceGdiTextOut(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len);
void wceGdiTextRect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt);
void wceGdiTextSize(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs);
void wceGdiGradientRect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt);
void wceGdiAlphaBlendRect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity);
void wceGdiInvertRect(visual_t rdc, const xrect_t* prt);
void wceGdiExcludeRect(visual_t rdc, const xrect_t* pxr);
void wceGdiInClipRect(visual_t rdc, const xrect_t* pxr);
void wceGdiDrawImage(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt);
void wceGdiDrawBitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt);
void wceGdiFontSize(visual_t rdc, const xfont_t* pxf, xsize_t* pxs);
fontset_t wceGdiGetFontset(visual_t rdc);
fontset_t wceGdiCreateFontset(const xfont_t* pxf);
void wceGdiDestroyFontset(fontset_t ft);
void wceGdiWordSize(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs);

void wceWidgetStartup(int ver);
void wceWidgetCleanup(void);
widget_t wceWidgetCreate(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev);
void wceWidgetDestroy(widget_t wt);
void wceWidgetClose(widget_t wt, int ret);
const if_subproc_t* wceWidgetGetSubproc(widget_t wt, uid_t sid);
bool_t wceWidgetSetSubproc(widget_t wt, uid_t sid, if_subproc_t* sub);
void wceWidgetDelSubproc(widget_t wt, uid_t sid);
bool_t wceWidgetSetSubprocDelta(widget_t wt, uid_t sid, vword_t delta);
vword_t wceWidgetGetSubprocDelta(widget_t wt, uid_t sid);
bool_t wceWidgetHasSubproc(widget_t wt, uid_t sid);
void wceWidgetSetCoreDelta(widget_t wt, vword_t pd);
vword_t wceWidgetGetCoreDelta(widget_t wt);
void wceWidgetSetUserDelta(widget_t wt, vword_t pd);
vword_t wceWidgetGetUserDelta(widget_t wt);
void wceWidgetSetStyle(widget_t wt, dword_t ws);
dword_t wceWidgetGetStyle(widget_t wt);
void wceWidgetSetAccel(widget_t wt, const accel_table_t* pacl, int n);
void wceWidgetSetOwner(widget_t wt, widget_t owner);
widget_t wceWidgetGetOwner(widget_t wt);
void wceWidgetSetUserId(widget_t wt, uid_t uid);
uid_t wceWidgetGetUserId(widget_t wt);
void wceWidgetSetUserResult(widget_t wt, int rt);
int wceWidgetGetUserResult(widget_t wt);
widget_t wceWidgetGetChild(widget_t wt, uid_t uid);
widget_t wceWidgetGetParent(widget_t wt);
void wceWidgetSetUserProp(widget_t wt, const tchar_t* pname,vword_t val);
vword_t wceWidgetGetUserProp(widget_t wt, const tchar_t* pname);
vword_t wceWidgetDelUserProp(widget_t wt, const tchar_t* pname);
const if_dispatch_t* wceWidgetGetDispatch(widget_t wt);
bool_t wceWidgetIsMaximized(widget_t wt);
bool_t wceWidgetIsMinimized(widget_t wt);
bool_t wceWidgetEnumChild(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv);
visual_t wceWidgetClientContext(widget_t wt);
visual_t wceWidgetWindowContext(widget_t wt);
void wceWidgetReleaseContext(widget_t wt, visual_t dc);
void wceWidgetGetClientRect(widget_t wt, xrect_t* prt);
void wceWidgetGetWindowRect(widget_t wt, xrect_t* prt);
void wceWidgetClientToScreen(widget_t wt, xpoint_t* ppt);
void wceWidgetScreenToClient(widget_t wt, xpoint_t* ppt);
void wceWidgetClientToWindow(widget_t wt, xpoint_t* ppt);
void wceWidgetWindowToClient(widget_t wt, xpoint_t* ppt);
void wceWidgetCenterWindow(widget_t wt, widget_t owner);
void wceWidgetSetCursor(widget_t wt, int ci);
void wceWidgetSetCapture(widget_t wt, bool_t b);
vword_t wceWidgetSetTimer(widget_t wt, int ms);
void wceWidgetKillTimer(widget_t wt, vword_t tid);
void wceWidgetCreateCaret(widget_t wt, int w, int h);
void wceWidgetDestroyCaret(widget_t wt);
void wceWidgetShowCaret(widget_t wt, int x, int y);
void wceWidgetSetFocus(widget_t wt);
bool_t wceWidgetKeyState(widget_t wt, int ks);
bool_t wceWidgetIsValid(widget_t wt);
bool_t wceWidgetIsFocus(widget_t wt);
bool_t wceWidgetIsChild(widget_t wt);
bool_t wceWidgetIsOwnerNc(widget_t wt);
void wceWidgetMove(widget_t wt, const xpoint_t* ppt);
void wceWidgetSize(widget_t wt, const xsize_t* pxs);
void wceWidgetTake(widget_t wt, int zor);
void wceWidgetShow(widget_t wt, dword_t sw);
void wceWidgetLayout(widget_t wt);
void wceWidgetErase(widget_t wt, const xrect_t* prt);
void wceWidgetEnable(widget_t wt, bool_t b);
void wceWidgetEnableHover(widget_t wt, bool_t b);
void wceWidgetPostNotice(widget_t wt, NOTICE* pnt);
int wceWidgetSendNotice(widget_t wt, NOTICE* pnt);
void wceWidgetPostCommand(widget_t wt, int code, uid_t cid, vword_t data);
int wceWidgetSendCommand(widget_t wt, int code, uid_t cid, vword_t data);
void wceWidgetPostWChar(widget_t wt, wchar_t ch);
void wceWidgetPostKey(widget_t wt, int key);
void wceWidgetSetTitle(widget_t wt, const tchar_t* token);
int wceWidgetGetTitle(widget_t wt, tchar_t* buf, int max);
void wceWidgetActive(widget_t wt);
void wceWidgetScroll(widget_t wt, bool_t horz, int line);
void wceWidgetGetScrollInfo(widget_t wt, bool_t horz, scroll_t* psl);
void wceWidgetSetScrollInfo(widget_t wt, bool_t horz, const scroll_t* psl);
void wceWidgetSetColorMode(widget_t wt, const color_mod_t* pclr);
void wceWidgetGetColorMode(widget_t wt, color_mod_t* pclr);
const color_mod_t* wceWidgetGetColorModePtr(widget_t wt);
void wceWidgetSetDiaph(widget_t wt, float f);
float wceWidgetGetDiaph(widget_t wt);
int	wceWidgetDoMain(widget_t wt);
int	wceWidgetDoModal(widget_t wt);
void wceWidgetDoTrack(widget_t wt);

void wceMessageQuit(int code);
void wceMessagePosition(xpoint_t* pxp);

void wceCalcWidgetBorder(dword_t ws, border_t* pbd);
void wceAdjustWidgetSize(dword_t wstyle, xsize_t* pxs);
void wceGetScreenSize(xsize_t* pxs);
void wceGetDesktopSize(xsize_t* pxs);
void wceScreenSizeToMm(xsize_t* pxs);
void wceScreenSizeToPt(xsize_t* pxs);

int wceWidgetNcHintTest(widget_t wt, const xpoint_t* pxp);
int wceWidgetNcCalcScroll(widget_t wt, bool_t horz, const xpoint_t* pxp);
void wceWidgetNcDrawFrame(widget_t wt, visual_t dc, const xrect_t* prt);
void wceWidgetNcDrawScroll(widget_t wt, visual_t dc, bool_t horz, const xrect_t* prt);


bool_t wceShellGetFileName(widget_t owner, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen);
bool_t wceShellGetPathName(widget_t owner, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen);
bool_t wceShellGetCurPath(tchar_t* pathbuf, int pathlen);
bool_t wceShellGetRunPath(tchar_t* pathbuf, int pathlen);
bool_t wceShellGetAppPath(tchar_t* pathbuf, int pathlen);
bool_t wceShellGetDocPath(tchar_t* pathbuf, int pathlen);
bool_t wceShellGetTmpPath(tchar_t* pathbuf, int pathlen);

bool_t wceClipboardPut(widget_t wt, int fmt, const byte_t* data, dword_t size);
dword_t wceClipboardGet(widget_t wt, int fmt, byte_t* buf, dword_t max);


#endif //_XDU_WINDOWS_H