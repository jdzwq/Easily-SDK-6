/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu macos definition document

	@module	_if_xquartz.h | macos xquartz interface file

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

#ifndef _IF_XQUARTZ_H
#define _IF_XQUARTZ_H

#include "../../xdudef.h"

#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xos.h>
#include <X11/keysym.h>
#include <X11/Xatom.h>
#include <X11/XKBlib.h>
#include <X11/cursorfont.h>
#include <X11/Xresource.h>
#include <X11/Xlocale.h>
#include <X11/extensions/Xrender.h>
#include <X11/Xft/Xft.h>


typedef struct _xquartz_atoms_t{
    Atom net_active_window;
    Atom net_close_window;
    Atom net_wm_action_close;
    Atom net_wm_action_fullscreen;
    Atom net_wm_action_maximize_horz;
    Atom net_wm_action_maximize_vert;
    Atom net_wm_action_minimize;
    Atom net_wm_action_move;
    Atom net_wm_action_resize;
    Atom net_wm_action_shade;
    Atom net_wm_allowed_actions;
    Atom net_wm_name;
    Atom net_wm_state;
    Atom net_wm_state_fullscreen;
    Atom net_wm_state_hidden;
    Atom net_wm_state_maximized_horz;
    Atom net_wm_state_maximized_vert;
    Atom net_wm_state_modal;
    Atom net_wm_state_shaded;
    Atom net_wm_state_skip_pager;
    Atom net_wm_state_skip_taskbar;
    Atom net_wm_state_sticky;
    Atom net_wm_window_type;
    Atom net_wm_window_type_combo;
    Atom net_wm_window_type_desktop;
    Atom net_wm_window_type_dialog;
    Atom net_wm_window_type_dropdown_menu;
    Atom net_wm_window_type_dnd;
    Atom net_wm_window_type_dock;
    Atom net_wm_window_type_menu;
    Atom net_wm_window_type_normal;
    Atom net_wm_window_type_notification;
    Atom net_wm_window_type_popup_menu;
    Atom net_wm_window_type_splash;
    Atom net_wm_window_type_toolbar;
    Atom net_wm_window_type_tooltip;
    Atom net_wm_window_type_utility;
    Atom net_wm_ping;
    Atom wm_change_state;
    Atom wm_colormap_windows;
    Atom wm_delete_window;
    Atom wm_hints;
    Atom wm_name;
    Atom wm_normal_hints;
    Atom wm_protocols;
    Atom wm_state;
    Atom wm_take_focus;
    Atom wm_transient_for;

    Atom wm_wchar;
    Atom wm_quit;
    Atom wm_command;
    Atom wm_notice;
    Atom wm_input;
    Atom wm_scroll;
    
    Atom xdu_struct;
    Atom xdu_dispatch;
    Atom xdu_subproc;
    Atom xdu_user_delta;
    Atom xdu_core_delta;

}xquartz_atoms_t;

extern xquartz_atoms_t  g_atoms;

extern res_queue_t g_queue;

#define XRGB(ch) (unsigned short)((double)ch * 65535.0 / 256.0)

extern XIM          g_xim;
extern Display*     g_display;
//global fonstset cache
extern fontset_t    g_fontset;

typedef Colormap    res_clrmap_t;

typedef struct _xquartz_bitmap_t{
	handle_head head;

    bool_t ref;
	XImage* image;
}xquartz_bitmap_t;

typedef struct _xquartz_context_t{
    handle_head head;
    int type;

    GC context;
    Drawable device;
    int width;
    int height;
    Visual* visual;
    Colormap color;
    unsigned int depth;

    fontset_t fontset;
}xquartz_context_t;

typedef struct _xquartz_fontset_t{
	handle_head head;

    void* font_object;
    float font_height;
}xquartz_fontset_t;

typedef struct _xquartz_widget_t{
    handle_head head;

    uid_t uid;
	Window self;
	Window parent;
	Window owner;
    void* accel;
	
    dword_t style;
	int mode;
	int result;
	int retcode;

	float diaph;
	dword_t mask;
	long evmsk;
    int state;
	bool_t disable;

    scroll_t hs;
	scroll_t vs;
    color_mod_t clrs;

    Cursor cur;
	XIC xic;
    res_timer_t ctt;

	bool_t tog;
	caret_t car;

    xpoint_t pt;
    xsize_t st;
}xquartz_widget_t;


int xqContextStartup(void);
void xqContextCleanup(void);
visual_t xqCreateDisplayContext(widget_t wt);
visual_t xqCreateCompatibleContext(visual_t rdc, int cx, int cy);
void xqDestroyContext(visual_t rdc);
void xqGetDeviceCaps(visual_t rdc, dev_cap_t* pcap);
void xqRenderContext(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth);

bitmap_t xqCreateContextBitmap(visual_t rdc);
bitmap_t xqCreateColorBitmap(visual_t rdc, const xcolor_t* pxc, int w, int h);
bitmap_t xqCreatePatternBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h);
bitmap_t xqCreateGradientBitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type);
bitmap_t xqCreateCode128Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols);
bitmap_t xqCreatePDF417Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t xqCreateQRCodeBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t xqCreateStorageBitmap(visual_t rdc, const tchar_t* fname);
bitmap_t xqLoadBitmapFromBytes(visual_t rdc, const unsigned char* pb, dword_t bytes);
dword_t xqSaveBitmapToBytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max);
bitmap_t xqLoadBitmapFromIcon(visual_t rdc, const tchar_t* iname);
bitmap_t xqLoadBitmapFromThumb(visual_t rdc, const tchar_t* file);
void xqDestroyBitmap(bitmap_t rbm);
dword_t xqGetBitmapBytes(bitmap_t rb);
void xqGetBitmapSize(bitmap_t rbm, int* pw, int* ph);

void xqGdiInit(int osv);
void xqGdiUnInit(void);
void xqGdiSetXFont(visual_t rdc, const xfont_t* pxf);
void xqGdiGetXFont(visual_t rdc, xfont_t* pxf);
void xqGdiGetPoint(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt);
void xqGdiSetPoint(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt);
void xqGdiDrawPoints(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n);
void xqGdiDrawLine(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2);
void xqGdiDrawPolyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n);
void xqGdiDrawArc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t closewise, bool_t largearc);
void xqGdiDrawBezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4);
void xqGdiDrawCurve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn);
void xqGdiDrawPath(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn);
void xqGdiDrawRect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void xqGdiDrawRound(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs);
void xqGdiDrawEllipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void xqGdiDrawPie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct);
void xqGdiDrawPolygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n);
void xqGdiDrawText(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len);
void xqGdiTextOut(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len);
void xqGdiTextRect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt);
void xqGdiTextSize(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs);
void xqGdiGradientRect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt);
void xqGdiAlphablendRect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity);
void xqGdiInvertRect(visual_t rdc, const xrect_t* prt);
void xqGdiExcludeRect(visual_t rdc, const xrect_t* pxr);
void xqGdiInclipRect(visual_t rdc, const xrect_t* pxr);
void xqGdiDrawImage(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt);
void xqGdiDrawBitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt);
void xqGdiFontSize(visual_t rdc, const xfont_t* pxf, xsize_t* pxs);
fontset_t xqGdiGetFontset(visual_t rdc);
fontset_t xqGdiCreateFontset(const xfont_t* pxf);
void xqGdiDestroyFontset(fontset_t ft);
void xqGdiWordSize(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs);

void xqWidgetStartup(int ver);
void xqWidgetCleanup(void);
widget_t xqWidgetCreate(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev);
void xqWidgetDestroy(widget_t wt);
void xqWidgetClose(widget_t wt, int ret);
const if_subproc_t* xqWidgetGetSubproc(widget_t wt, uid_t sid);
bool_t xqWidgetSetSubproc(widget_t wt, uid_t sid, if_subproc_t* sub);
void xqWidgetDelSubproc(widget_t wt, uid_t sid);
bool_t xqWidgetSetSubprocDelta(widget_t wt, uid_t sid, vword_t delta);
vword_t xqWidgetGetSubprocDelta(widget_t wt, uid_t sid);
bool_t xqWidgetHasSubproc(widget_t wt, uid_t sid);
void xqWidgetSetCoreDelta(widget_t wt, vword_t pd);
vword_t xqWidgetGetCoreDelta(widget_t wt);
void xqWidgetSetUserDelta(widget_t wt, vword_t pd);
vword_t xqWidgetGetUserDelta(widget_t wt);
void xqWidgetSetStyle(widget_t wt, dword_t ws);
dword_t xqWidgetGetStyle(widget_t wt);
void xqWidgetSetAccel(widget_t wt, const accel_table_t* pacl, int n);
void xqWidgetSetOwner(widget_t wt, widget_t owner);
widget_t xqWidgetGetOwner(widget_t wt);
void xqWidgetSetUserId(widget_t wt, uid_t uid);
uid_t xqWidgetGetUserId(widget_t wt);
void xqWidgetSetUserResult(widget_t wt, int rt);
int xqWidgetGetUserResult(widget_t wt);
widget_t xqWidgetGetChild(widget_t wt, uid_t uid);
widget_t xqWidgetGetParent(widget_t wt);
void xqWidgetSetUserProp(widget_t wt, const tchar_t* pname,vword_t val);
vword_t xqWidgetGetUserProp(widget_t wt, const tchar_t* pname);
vword_t xqWidgetDelUserProp(widget_t wt, const tchar_t* pname);
const if_dispatch_t* xqWidgetGetDispatch(widget_t wt);
bool_t xqWidgetIsMaximized(widget_t wt);
bool_t xqWidgetIsMinimized(widget_t wt);
bool_t xqWidgetEnumChild(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv);
visual_t xqWidgetClientContext(widget_t wt);
visual_t xqWidgetWindowContext(widget_t wt);
void xqWidgetReleaseContext(widget_t wt, visual_t dc);
void xqWidgetGetClientRect(widget_t wt, xrect_t* prt);
void xqWidgetGetWindowRect(widget_t wt, xrect_t* prt);
void xqWidgetClientToScreen(widget_t wt, xpoint_t* ppt);
void xqWidgetScreenToClient(widget_t wt, xpoint_t* ppt);
void xqWidgetClientToWindow(widget_t wt, xpoint_t* ppt);
void xqWidgetWindowToClient(widget_t wt, xpoint_t* ppt);
void xqWidgetCenterWindow(widget_t wt, widget_t owner);
void xqWidgetSetCursor(widget_t wt, int ci);
void xqWidgetSetCapture(widget_t wt, bool_t b);
vword_t xqWidgetSetTimer(widget_t wt, int ms);
void xqWidgetKillTimer(widget_t wt, vword_t tid);
void xqWidgetCreateCaret(widget_t wt, int w, int h);
void xqWidgetDestroyCaret(widget_t wt);
void xqWidgetShowCaret(widget_t wt, int x, int y);
void xqWidgetSetFocus(widget_t wt);
bool_t xqWidgetKeyState(widget_t wt, int ks);
bool_t xqWidgetIsValid(widget_t wt);
bool_t xqWidgetIsFocus(widget_t wt);
bool_t xqWidgetIsChild(widget_t wt);
bool_t xqWidgetIsOwnerNc(widget_t wt);
void xqWidgetMove(widget_t wt, const xpoint_t* ppt);
void xqWidgetSize(widget_t wt, const xsize_t* pxs);
void xqWidgetTake(widget_t wt, int zor);
void xqWidgetShow(widget_t wt, dword_t sw);
void xqWidgetLayout(widget_t wt);
void xqWidgetErase(widget_t wt, const xrect_t* prt);
void xqWidgetEnable(widget_t wt, bool_t b);
void xqWidgetEnableHover(widget_t wt, bool_t b);
void xqWidgetPostNotice(widget_t wt, NOTICE* pnt);
int xqWidgetSendNotice(widget_t wt, NOTICE* pnt);
void xqWidgetPostCommand(widget_t wt, int code, uid_t cid, vword_t data);
int xqWidgetSendCommand(widget_t wt, int code, uid_t cid, vword_t data);
void xqWidgetPostWChar(widget_t wt, wchar_t ch);
void xqWidgetPostKey(widget_t wt, int key);
void xqWidgetSetTitle(widget_t wt, const tchar_t* token);
int xqWidgetGetTitle(widget_t wt, tchar_t* buf, int max);
void xqWidgetActive(widget_t wt);
void xqWidgetScroll(widget_t wt, bool_t horz, int line);
void xqWidgetGetScrollInfo(widget_t wt, bool_t horz, scroll_t* psl);
void xqWidgetSetScrollInfo(widget_t wt, bool_t horz, const scroll_t* psl);
void xqWidgetSetColorMode(widget_t wt, const color_mod_t* pclr);
void xqWidgetGetColorMode(widget_t wt, color_mod_t* pclr);
const color_mod_t* xqWidgetGetColorModePtr(widget_t wt);
void xqWidgetSetDiaph(widget_t wt, float f);
float xqWidgetGetDiaph(widget_t wt);
int	xqWidgetDoMain(widget_t wt);
int	xqWidgetDoModal(widget_t wt);
void xqWidgetDoTrack(widget_t wt);

void xqMessageQuit(int code);
void xqMessagePosition(xpoint_t* pxp);

void xqCalcWidgetBorder(dword_t ws, border_t* pbd);
void xqAdjustWidgetSize(dword_t wstyle, xsize_t* pxs);
void xqGetScreenSize(xsize_t* pxs);
void xqGetDesktopRect(xrect_t* pxr);
void xqScreenSizeToMm(xsize_t* pxs);
void xqScreenSizeToPt(xsize_t* pxs);

bool_t xqShellGetFileName(widget_t owner, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen);
bool_t xqShellGetPathName(widget_t owner, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen);
bool_t xqShellGetCurPath(tchar_t* pathbuf, int pathlen);
bool_t xqShellGetRunPath(tchar_t* pathbuf, int pathlen);
bool_t xqShellGetAppPath(tchar_t* pathbuf, int pathlen);
bool_t xqShellGetDocPath(tchar_t* pathbuf, int pathlen);
bool_t xqShellGetTmpPath(tchar_t* pathbuf, int pathlen);

bool_t xqClipboardPut(widget_t wt, int fmt, const byte_t* data, dword_t size);
dword_t xqClipboardGet(widget_t wt, int fmt, byte_t* buf, dword_t max);


#endif //_IF_XQUARTZ_H