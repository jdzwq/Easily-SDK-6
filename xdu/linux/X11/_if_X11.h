/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu linux definition document

	@module	_if_X11.h | linux interface file

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

#ifndef _IF_X11_H
#define _IF_X11_H

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

#include <gtk/gtk.h>

typedef struct _X11_atoms_t{
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

}X11_atoms_t;

extern X11_atoms_t  g_atoms;

extern res_queue_t g_queue;

#define XRGB(ch) (unsigned short)((double)ch * 65535.0 / 256.0)

extern XIM          g_xim;
extern Display*     g_display;
//global fonstset cache
extern fontset_t    g_fontset;

typedef Colormap    res_clrmap_t;

typedef struct _X11_bitmap_t{
	handle_head head;

    bool_t ref;
	XImage* image;
}X11_bitmap_t;

typedef struct _X11_context_t{
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
}X11_context_t;

typedef struct _X11_fontset_t{
	handle_head head;

    void* font_object;
    float font_height;
}X11_fontset_t;

typedef struct _X11_widget_t{
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
}X11_widget_t;


int xlContextStartup(void);
void xlContextCleanup(void);
visual_t xlCreateDisplayContext(widget_t wt);
visual_t xlCreateCompatibleContext(visual_t rdc, int cx, int cy);
void xlDestroyContext(visual_t rdc);
void xlGetDeviceCaps(visual_t rdc, dev_cap_t* pcap);
void xlRenderContext(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth);

bitmap_t xlCreateContextBitmap(visual_t rdc);
bitmap_t xlCreateColorBitmap(visual_t rdc, const xcolor_t* pxc, int w, int h);
bitmap_t xlCreatePatternBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h);
bitmap_t xlCreateGradientBitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type);
bitmap_t xlCreateCode128Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols);
bitmap_t xlCreatePDF417Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t xlCreateQRCodeBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
bitmap_t xlCreateStorageBitmap(visual_t rdc, const tchar_t* fname);
bitmap_t xlLoadBitmapFromBytes(visual_t rdc, const unsigned char* pb, dword_t bytes);
dword_t xlSaveBitmapToBytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max);
bitmap_t xlLoadBitmapFromIcon(visual_t rdc, const tchar_t* iname);
bitmap_t xlLoadBitmapFromThumb(visual_t rdc, const tchar_t* file);
void xlDestroyBitmap(bitmap_t rbm);
dword_t xlGetBitmapBytes(bitmap_t rb);
void xlGetBitmapSize(bitmap_t rbm, int* pw, int* ph);

void xlGdiInit(int osv);
void xlGdiUnInit(void);
void xlGdiSetXFont(visual_t rdc, const xfont_t* pxf);
void xlGdiGetXFont(visual_t rdc, xfont_t* pxf);
void xlGdiGetPoint(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt);
void xlGdiSetPoint(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt);
void xlGdiDrawPoints(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n);
void xlGdiDrawLine(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2);
void xlGdiDrawPolyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n);
void xlGdiDrawArc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t closewise, bool_t largearc);
void xlGdiDrawBezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4);
void xlGdiDrawCurve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn);
void xlGdiDrawPath(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn);
void xlGdiDrawRect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void xlGdiDrawRound(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs);
void xlGdiDrawEllipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt);
void xlGdiDrawPie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct);
void xlGdiDrawPolygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n);
void xlGdiDrawText(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len);
void xlGdiTextOut(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len);
void xlGdiTextRect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt);
void xlGdiTextSize(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs);
void xlGdiGradientRect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt);
void xlGdiAlphablendRect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity);
void xlGdiInvertRect(visual_t rdc, const xrect_t* prt);
void xlGdiExcludeRect(visual_t rdc, const xrect_t* pxr);
void xlGdiInclipRect(visual_t rdc, const xrect_t* pxr);
void xlGdiDrawImage(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt);
void xlGdiDrawBitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt);
void xlGdiFontSize(visual_t rdc, const xfont_t* pxf, xsize_t* pxs);
fontset_t xlGdiGetFontset(visual_t rdc);
fontset_t xlGdiCreateFontset(const xfont_t* pxf);
void xlGdiDestroyFontset(fontset_t ft);
void xlGdiWordSize(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs);

void xlWidgetStartup(int ver);
void xlWidgetCleanup(void);
widget_t xlWidgetCreate(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev);
void xlWidgetDestroy(widget_t wt);
void xlWidgetClose(widget_t wt, int ret);
const if_subproc_t* xlWidgetGetSubproc(widget_t wt, uid_t sid);
bool_t xlWidgetSetSubproc(widget_t wt, uid_t sid, if_subproc_t* sub);
void xlWidgetDelSubproc(widget_t wt, uid_t sid);
bool_t xlWidgetSetSubprocDelta(widget_t wt, uid_t sid, vword_t delta);
vword_t xlWidgetGetSubprocDelta(widget_t wt, uid_t sid);
bool_t xlWidgetHasSubproc(widget_t wt, uid_t sid);
void xlWidgetSetCoreDelta(widget_t wt, vword_t pd);
vword_t xlWidgetGetCoreDelta(widget_t wt);
void xlWidgetSetUserDelta(widget_t wt, vword_t pd);
vword_t xlWidgetGetUserDelta(widget_t wt);
void xlWidgetSetStyle(widget_t wt, dword_t ws);
dword_t xlWidgetGetStyle(widget_t wt);
void xlWidgetSetAccel(widget_t wt, const accel_table_t* pacl, int n);
void xlWidgetSetOwner(widget_t wt, widget_t owner);
widget_t xlWidgetGetOwner(widget_t wt);
void xlWidgetSetUserId(widget_t wt, uid_t uid);
uid_t xlWidgetGetUserId(widget_t wt);
void xlWidgetSetUserResult(widget_t wt, int rt);
int xlWidgetGetUserResult(widget_t wt);
widget_t xlWidgetGetChild(widget_t wt, uid_t uid);
widget_t xlWidgetGetParent(widget_t wt);
void xlWidgetSetUserProp(widget_t wt, const tchar_t* pname,vword_t val);
vword_t xlWidgetGetUserProp(widget_t wt, const tchar_t* pname);
vword_t xlWidgetDelUserProp(widget_t wt, const tchar_t* pname);
const if_dispatch_t* xlWidgetGetDispatch(widget_t wt);
bool_t xlWidgetIsMaximized(widget_t wt);
bool_t xlWidgetIsMinimized(widget_t wt);
bool_t xlWidgetEnumChild(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv);
visual_t xlWidgetClientContext(widget_t wt);
visual_t xlWidgetWindowContext(widget_t wt);
void xlWidgetReleaseContext(widget_t wt, visual_t dc);
void xlWidgetGetClientRect(widget_t wt, xrect_t* prt);
void xlWidgetGetWindowRect(widget_t wt, xrect_t* prt);
void xlWidgetClientToScreen(widget_t wt, xpoint_t* ppt);
void xlWidgetScreenToClient(widget_t wt, xpoint_t* ppt);
void xlWidgetClientToWindow(widget_t wt, xpoint_t* ppt);
void xlWidgetWindowToClient(widget_t wt, xpoint_t* ppt);
void xlWidgetCenterWindow(widget_t wt, widget_t owner);
void xlWidgetSetCursor(widget_t wt, int ci);
void xlWidgetSetCapture(widget_t wt, bool_t b);
vword_t xlWidgetSetTimer(widget_t wt, int ms);
void xlWidgetKillTimer(widget_t wt, vword_t tid);
void xlWidgetCreateCaret(widget_t wt, int w, int h);
void xlWidgetDestroyCaret(widget_t wt);
void xlWidgetShowCaret(widget_t wt, int x, int y);
void xlWidgetSetFocus(widget_t wt);
bool_t xlWidgetKeyState(widget_t wt, int ks);
bool_t xlWidgetIsValid(widget_t wt);
bool_t xlWidgetIsFocus(widget_t wt);
bool_t xlWidgetIsChild(widget_t wt);
bool_t xlWidgetIsOwnerNc(widget_t wt);
void xlWidgetMove(widget_t wt, const xpoint_t* ppt);
void xlWidgetSize(widget_t wt, const xsize_t* pxs);
void xlWidgetTake(widget_t wt, int zor);
void xlWidgetShow(widget_t wt, dword_t sw);
void xlWidgetLayout(widget_t wt);
void xlWidgetErase(widget_t wt, const xrect_t* prt);
void xlWidgetEnable(widget_t wt, bool_t b);
void xlWidgetEnableHover(widget_t wt, bool_t b);
void xlWidgetPostNotice(widget_t wt, NOTICE* pnt);
int xlWidgetSendNotice(widget_t wt, NOTICE* pnt);
void xlWidgetPostCommand(widget_t wt, int code, uid_t cid, vword_t data);
int xlWidgetSendCommand(widget_t wt, int code, uid_t cid, vword_t data);
void xlWidgetPostWChar(widget_t wt, wchar_t ch);
void xlWidgetPostKey(widget_t wt, int key);
void xlWidgetSetTitle(widget_t wt, const tchar_t* token);
int xlWidgetGetTitle(widget_t wt, tchar_t* buf, int max);
void xlWidgetActive(widget_t wt);
void xlWidgetScroll(widget_t wt, bool_t horz, int line);
void xlWidgetGetScrollInfo(widget_t wt, bool_t horz, scroll_t* psl);
void xlWidgetSetScrollInfo(widget_t wt, bool_t horz, const scroll_t* psl);
void xlWidgetSetColorMode(widget_t wt, const color_mod_t* pclr);
void xlWidgetGetColorMode(widget_t wt, color_mod_t* pclr);
const color_mod_t* xlWidgetGetColorModePtr(widget_t wt);
void xlWidgetSetDiaph(widget_t wt, float f);
float xlWidgetGetDiaph(widget_t wt);
int	xlWidgetDoMain(widget_t wt);
int	xlWidgetDoModal(widget_t wt);
void xlWidgetDoTrack(widget_t wt);

void xlMessageQuit(int code);
void xlMessagePosition(xpoint_t* pxp);

void xlCalcWidgetBorder(dword_t ws, border_t* pbd);
void xlAdjustWidgetSize(dword_t wstyle, xsize_t* pxs);
void xlGetScreenSize(xsize_t* pxs);
void xlGetDesktopSize(xsize_t* pxs);
void xlScreenSizeToMm(xsize_t* pxs);
void xlScreenSizeToPt(xsize_t* pxs);

bool_t xlShellGetFileName(widget_t owner, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen);
bool_t xlShellGetPathName(widget_t owner, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen);
bool_t xlShellGetCurPath(tchar_t* pathbuf, int pathlen);
bool_t xlShellGetRunPath(tchar_t* pathbuf, int pathlen);
bool_t xlShellGetAppPath(tchar_t* pathbuf, int pathlen);
bool_t xlShellGetDocPath(tchar_t* pathbuf, int pathlen);
bool_t xlShellGetTmpPath(tchar_t* pathbuf, int pathlen);

bool_t xlClipboardPut(widget_t wt, int fmt, const byte_t* data, dword_t size);
dword_t xlClipboardGet(widget_t wt, int fmt, byte_t* buf, dword_t max);


#endif //_IF_X11_H