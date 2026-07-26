/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu linux definition document

	@module	_xdu_linux.h | linux interface file

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

#ifndef _WAYLAND_H
#define _WAYLAND_H

#include <wayland-client.h>
#include <wayland-cursor.h>

#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-keysyms.h>

#include "../../xdudef.h"
#include "xdg-shell-client-protocol.h"

#define LINK_TAG_EVENT 0xEE

#define WAYLAND_COLOR_MODE_ARGB32 0

#define WAYLAND_WINDOW_TITLE_HEIGHT 26
#define WAYLAND_WINDOW_EDGE_WIDTH   1

#define WAYLAND_WITH_LBUTTON	0x00010000
#define WAYLAND_WITH_RBUTTON	0x00020000
#define WAYLAND_WITH_MBUTTON	0x00040000

#define WAYLAND_STATE_SHIFT     0x10000000
#define WAYLAND_STATE_CONTROL   0x20000000
#define WAYLAND_STATE_ALT       0x40000000
#define WAYLAND_STATE_META      0x80000000

#define WAYLAND_EVENT_MASK_CONFIG   0x00010000
#define WAYLAND_EVENT_MASK_ACTIVE   0x00020000
#define WAYLAND_EVENT_MASK_MAPING   0x00040000
#define WAYLAND_EVENT_MASK_EXPOSE   0x00080000
#define WAYLAND_EVENT_MASK_POINTER  0x00100000
#define WAYLAND_EVENT_MASK_KEYBOARD 0x00200000
#define WAYLAND_EVENT_MASK_TOUCHPAD 0x00400000
#define WAYLAND_EVENT_MASK_NOTIFY   0x00800000
#define WAYLAND_EVENT_MASK_NOTCLI   0x10000000

#define WAYLAND_EVENT_CREATE    0x00010001
#define WAYLAND_EVENT_DESTROY   0x00010002
#define WAYLAND_EVENT_SIZE      0x00010004

#define WAYLAND_EVENT_SHOW      0x00020001
#define WAYLAND_EVENT_CLOSE     0x00020002

#define WAYLAND_EVENT_ACTIVATE  0x00040001

#define WAYLAND_EVENT_EXPOSE    0x00080001

#define WAYLAND_EVENT_MOUSE_ENTER     0x00100001
#define WAYLAND_EVENT_MOUSE_LEAVE     0x00100002
#define WAYLAND_EVENT_MOUSE_MOVE      0x00100004
#define WAYLAND_EVENT_MOUSE_WHEEL     0x00100008
#define WAYLAND_EVENT_LBUTTON_DOWN    0x00100010
#define WAYLAND_EVENT_LBUTTON_UP      0x00100020
#define WAYLAND_EVENT_RBUTTON_DOWN    0x00100040
#define WAYLAND_EVENT_RBUTTON_UP      0x00100080

#define WAYLAND_EVENT_SET_FOCUS       0x00200001
#define WAYLAND_EVENT_KILL_FOCUS      0x00200002
#define WAYLAND_EVENT_KEY_DOWN        0x00200004
#define WAYLAND_EVENT_KEY_UP          0x00200008
#define WAYLAND_EVENT_WCHAR           0x00200010

#define WAYLAND_EVENT_SCROLL          0x00400001

#define WAYLAND_EVENT_NOTICE          0x00800001
#define WAYLAND_EVENT_COMMAND         0x00800002

#define WAYLAND_EVENT_NCPAINT         0x10000001
#define WAYLAND_EVENT_HITTEST         0x10000002
#define WAYLAND_EVENT_NCMOUSE_MOVE      0x10000004
#define WAYLAND_EVENT_NCLBUTTON_DOWN    0x10000010
#define WAYLAND_EVENT_NCLBUTTON_UP      0x10000020
#define WAYLAND_EVENT_NCRBUTTON_DOWN    0x10000040
#define WAYLAND_EVENT_NCRBUTTON_UP      0x10000080

#define WAYLAND_FIX_TO_INT(f) (int)((float)(f) / 256.0f)

typedef struct _wayland_display* wayland_display_ptr;
typedef struct _wayland_surface* wayland_surface_ptr;
typedef struct _wayland_window* wayland_window_ptr;

typedef struct _wayland_display{
    struct wl_display *raw_disp;
    struct wl_output *raw_dev;
    struct wl_shm *raw_shm;
    struct wl_shm_pool *raw_pool;
    int shm_fd;
    int shm_size;

    struct wl_compositor *raw_comp;
    struct xdg_wm_base *xdg_base;
    struct wl_subcompositor *sub_comp;

    struct wl_seat *raw_seat;
    struct wl_pointer *raw_mouse;
    struct wl_keyboard *raw_keybd;

    struct wl_surface *track_mouse;
    struct wl_surface *track_input;

    int track_mkey;
    int track_xpos;
    int track_ypos;

    struct xkb_context *xkb_ctx;
    struct xkb_keymap  *xkb_map;
    struct xkb_state  *xkb_state;

    wayland_window_ptr track_main;
    
    dev_cap_t dispcap;
    pix_cap_t pixcap;
} wayland_display;

typedef enum _WAYLAND_SURFACE_TYPE{
    WAYLAND_WSURFACE_TYPE_TOP = 1,
    WAYLAND_SURFACE_TYPE_POP = 2,
    WAYLAND_SURFACE_TYPE_SUB = 3
} WAYLAND_SURFACE_TYPE;

typedef struct _wayland_surface{
    wayland_surface_ptr parent;
    wayland_display* display;
    xrect_t frame;

    int type;
    struct wl_buffer *raw_buff;
    struct wl_surface *raw_face;
    union{
        struct xdg_surface *xdg_face;
        struct wl_subsurface *sub_face;
    };
    union{
        struct xdg_toplevel *xdg_top;
        struct xdg_popup *xdg_pop;
    };
} wayland_surface;

typedef struct _wayland_window*    wayland_window_ptr;
typedef int (CALLBACK *wayland_win_proc)(wayland_window_ptr window, dword_t msg, dword_t code, vword_t data);

#define WAYLAND_MAX_ATOMS   16
#define WAYLAND_MAX_CHILDS  64

#define WAYLAND_ATOM_WINPROC	0
#define WAYLAND_ATOM_SUBPROC	1
#define WAYLAND_ATOM_STRUCT	    2
#define WAYLAND_ATOM_DISPATCH	3
#define WAYLAND_ATOM_COREDELTA	4
#define WAYLAND_ATOM_USERDELTA	5

typedef enum _WAYLAND_WINDOW_TYPE{
    WAYLAND_WINDOW_TYPE_OVERLAP = 0,
    WAYLAND_WINDOW_TYPE_DIALOG = 1,
    WAYLAND_WINDOW_TYPE_POPUP = 2,
    WAYLAND_WINDOW_TYPE_CHILD = 3
} WAYLAND_WINDOW_TYPE;

typedef enum _WAYLAND_WINDOW_STATE{
    WAYLAND_WINDOW_STATE_HIDE = 0,
    WAYLAND_WINDOW_STATE_NORMAL = 1,
    WAYLAND_WINDOW_STATE_MINIMIZED = 2,
    WAYLAND_WINDOW_STATE_MAXIMIZED = 3,
    WAYLAND_WINDOW_STATE_FULLSCREEN = 4
} WAYLAND_WINDOW_STATE;

typedef enum _WAYLAND_RESULT{
    WAYLAND_RESULT_ACCEPT = 0,
    WAYLAND_RESULT_REJECT = 1,
    WAYLAND_RESULT_IGNORE = 2
} WAYLAND_RESULT;

typedef int (CALLBACK *WaylandEventProc)(wayland_window_ptr window, dword_t event_id, dword_t event_code, vword_t event_data);

typedef struct _wayland_window{
    wayland_window_ptr parent;

    wayland_surface* sur_client;
    wayland_surface* sur_window;

	int x,y,width,height;
    int edge_width;
    int title_height;

    int win_type;
    int win_state;
    
    dword_t evt_mask;
    WaylandEventProc evt_proc;

    wayland_window_ptr track_focus;
    
    int childs_count;
    wayland_window_ptr childs[WAYLAND_MAX_CHILDS];
    vword_t atoms[WAYLAND_MAX_ATOMS];
} wayland_window;

bool_t WaylandConnect(void);
void WaylandDisconnect(void);
wayland_display* WaylandCreateDisplay(void);
void WaylandDestroyDisplay(wayland_display* disp);
wayland_display* WaylandDefaultDisplay(void);
bool_t WaylandDispatchDisplay(wayland_display* pdisp);
void WaylandFlashDisplay(wayland_display* disp, bool_t bWait);
void WaylandGetDeviceCap(wayland_display* disp, dev_cap_t* pcap);
void WaylandGetPixelCap(wayland_display* disp, pix_cap_t* pcap);

wayland_surface* WaylandCreateTopSurface(wayland_display* display, const xrect_t* pxr);
wayland_surface* WaylandCreatePopSurface(wayland_surface* parent, const xrect_t* pxr);
wayland_surface* WaylandCreateSubSurface(wayland_surface* parent, const xrect_t* pxr);
void WaylandDestroySurface(wayland_surface* surface);
void WaylandAttachSurface(wayland_surface* surface);
void WaylandDetchSurface(wayland_surface* surface);
bool_t WaylandMinimizeSurface(wayland_surface* surface);
bool_t WaylandMaximizeSurface(wayland_surface* surface);
bool_t WaylandFullscreenSurface(wayland_surface* surface);
void WaylandSizeSurface(wayland_surface* surface, const xsize_t* pxs);
void WaylandMoveSurface(wayland_surface* surface, const offset_t* pof);
void WaylandUpdateSurface(wayland_surface* surface, const xrect_t* pxr, bool_t flash);
void WaylandFillSurface(wayland_surface* surface, int pixel, const xrect_t* pxr);

void WaylandSetWindowProc(wayland_window* window, dword_t events, WaylandEventProc proc);
void WaylandSetWindowProper(wayland_window* window, int atom, vword_t prop);
vword_t WaylandGetWindowProper(wayland_window* window, int atom);
vword_t WaylandDelWindowProper(wayland_window* window, int atom);

wayland_window* WaylandCreateWindow(wayland_window* parent, int type, const tchar_t* title, int x, int y, int width, int height);
void WaylandDestroyWindow(wayland_window* window);
bool_t WaylandIsWindow(wayland_window* window);
void WaylandUpdateWindow(wayland_window* window);
void WaylandInvalidRect(wayland_window* window, const xrect_t* pxr);
wayland_surface* WaylandGetWindowSurface(wayland_window* window);
wayland_surface* WaylandGetClientSurface(wayland_window* window);
void WaylandGetWindowRect(wayland_window* window, xrect_t* pxr);
void WaylandGetClientRect(wayland_window* window, xrect_t* pxr);
void WaylandClientToScreen(wayland_window* window, xpoint_t* ppt);
void WaylandScreenToClient(wayland_window* window, xpoint_t* ppt);
void WaylandClientToWindow(wayland_window* window, xpoint_t* ppt);
void WaylandWindowToClient(wayland_window* window, xpoint_t* ppt);

void WaylandSizeWindow(wayland_window* pwin, const xsize_t* pxs);
void WaylandMoveWindow(wayland_window* pwin, const xpoint_t* pxp);
void WaylandShowWindow(wayland_window* pwin, int nState);
int WaylandWindowState(wayland_window* pwin);

void WaylandGetScreenSize(xsize_t* pxs);
void WaylandGetDesktopRect(xrect_t* prt);

void WaylandSetFocusWindow(wayland_window* pwin);
wayland_window* WaylandGetFocusWindow(void);
dword_t WaylandKeyboardState(void);
void WaylandMousePosition(xpoint_t* ppt);


#endif //_WAYLAND_H