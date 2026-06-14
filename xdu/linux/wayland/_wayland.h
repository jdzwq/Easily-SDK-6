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

#include "../../xdudef.h"
#include "xdg-shell-client-protocol.h"

#define LINK_TAG_EVENT 0xEE

#define WAYLAND_COLOR_MODE_ARGB32 0

#define WAYLAND_WINDOW_TITLE_HEIGHT 26
#define WAYLAND_WINDOW_EDGE_WIDTH   1

#define WAYLAND_STATE_SHIFT     0x20000000
#define WAYLAND_STATE_CONTROL   0x40000000
#define WAYLAND_STATE_ALT       0x80000000

#define WAYLAND_EVENT_MASK      0xEFFFFFFF

#define WAYLAND_EVENTMAP(eid)     ((eid) & WAYLAND_EVENT_MASK)
#define WAYLAND_STATEMAP(eid)     ((eid) & (~WAYLAND_EVENT_MASK))

#define WAYLAND_EVENT_EXPOSE    0x10000000
#define WAYLAND_EVENT_CREATE    0x10000001
#define WAYLAND_EVENT_DESTROY   0x10000002
#define WAYLAND_EVENT_CLOSE     0x10000004
#define WAYLAND_EVENT_SHOW      0x10000008
#define WAYLAND_EVENT_SIZE      0x10000010
#define WAYLAND_EVENT_ACTIVATE  0x10000020

#define WAYLAND_EVENT_MOUSE_ENTER     0x10000100
#define WAYLAND_EVENT_MOUSE_LEAVE     0x10000200
#define WAYLAND_EVENT_MOUSE_MOVE      0x10000400
#define WAYLAND_EVENT_MOUSE_WHEEL     0x10000800
#define WAYLAND_EVENT_LBUTTON_DOWN    0x10001000
#define WAYLAND_EVENT_LBUTTON_UP      0x10002000
#define WAYLAND_EVENT_RBUTTON_DOWN    0x10004000
#define WAYLAND_EVENT_RBUTTON_UP      0x10008000

#define WAYLAND_EVENT_SET_FOCUS       0x10010000
#define WAYLAND_EVENT_KILL_FOCUS      0x10020000
#define WAYLAND_EVENT_KEY_DOWN        0x10040000
#define WAYLAND_EVENT_KEY_UP          0x10080000

#define WAYLAND_EVENT_WCHAR           0x10100000
#define WAYLAND_EVENT_COMMAND         0x10200000
#define WAYLAND_EVENT_NOTICE          0x10400000
#define WAYLAND_EVENT_SCROLL          0x10800000

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

    struct wl_seat *raw_seat;
    struct wl_pointer *raw_mouse;
    struct wl_keyboard *raw_keybd;

    uint32_t track_serial;
    wayland_window_ptr track_focus;

    int track_mkey;
    int track_xpos;
    int track_ypos;
    
    dev_cap_t dispcap;
    pix_cap_t pixcap;

} wayland_display;

typedef struct _wayland_surface{
    wayland_display* display;
    xrect_t frame;

    struct wl_buffer *raw_buff;
    struct wl_surface *raw_face;
    struct xdg_surface *xdg_face;
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

typedef struct _wayland_window{
    wayland_window_ptr parent;

    wayland_surface* sur_client;
    struct xdg_popup *xdg_pop;

    wayland_surface* sur_window;
    struct xdg_toplevel *xdg_top;

	int x,y,width,height;
    int edge_width;
    int title_height;

    int win_type;
    dword_t evt_mask;
    int win_state;

    int childs_count;
    wayland_window_ptr childs[WAYLAND_MAX_CHILDS];
    vword_t atoms[WAYLAND_MAX_ATOMS];
} wayland_window;

bool_t WaylandConnect(void);
void WaylandDisconnect(void);
wayland_display* WaylandCreateDisplay(void);
void WaylandDestroyDisplay(wayland_display* disp);
wayland_display* WaylandDefaultDisplay(void);
void WaylandFlashDisplay(wayland_display* disp, bool_t bWait);
void WaylandGetDeviceCap(wayland_display* disp, dev_cap_t* pcap);
void WaylandGetPixelCap(wayland_display* disp, pix_cap_t* pcap);

void WaylandEventsInit(void);
void WaylandEventsUninit(void);
int WaylandEventsPending(void);
void WaylandEventsFlash(void);
void WaylandEventsAdd(wayland_window* window, dword_t event_id, dword_t event_code, vword_t event_data);
bool_t WaylandEventsFetch(wayland_window** pwindow, dword_t* pevent_id, dword_t* pevent_code, vword_t* pevent_data);
bool_t WaylandEventsPeek(wayland_window** pwindow, dword_t* pevent_id, dword_t* pevent_code, vword_t* pevent_data);

wayland_surface* WaylandCreateSurface(wayland_display* display, const xrect_t* pxr);
void WaylandDestroySurface(wayland_surface* surface);
void WaylandUpdateSurface(wayland_surface* surface, const xrect_t* pxr, bool_t flash);
void WaylandFillSurface(wayland_surface* surface, int pixel, const xrect_t* pxr);

void WaylandSetWindowProper(wayland_window* window, int atom, vword_t prop);
vword_t WaylandGetWindowProper(wayland_window* window, int atom);
vword_t WaylandDelWindowProper(wayland_window* window, int atom);

wayland_window* WaylandCreateWindow(wayland_window* parent, int type, dword_t mask, const tchar_t* title, int x, int y, int width, int height);
void WaylandDestroyWindow(wayland_window* window);
bool_t WaylandIsWindow(wayland_window* window);
void WaylandSetWindowProc(wayland_window* window, wayland_win_proc win_proc);
wayland_win_proc WaylandGetWindowProc(wayland_window* window);
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

void WaylandGetScreenSize(xsize_t* pxs);
void WaylandGetDesktopRect(xrect_t* prt);

void WaylandSetFocusWindow(wayland_window* pwin);
wayland_window* WaylandGetFocusWindow(void);
dword_t WaylandKeyboardState(void);
void WaylandMousePosition(xpoint_t* ppt);


#endif //_WAYLAND_H