/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc context document

	@module	if_wayland.c | linux implement file

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

#include "_if_wayland.h"

void WaylandDoNormal(wayland_window* window)
{
    wayland_display* pdisp = WaylandDefaultDisplay();

	pdisp->track_main = window;
    while (WaylandDispatchDisplay(pdisp));
}

#if defined (DEBUG) || defined (_DEBUG)
#define WIDGET_EVENTS   (WAYLAND_EVENT_MASK_CONFIG | WAYLAND_EVENT_MASK_MAPING | WAYLAND_EVENT_MASK_EXPOSE |  WAYLAND_EVENT_MASK_POINTER | WAYLAND_EVENT_MASK_KEYBOARD | WAYLAND_EVENT_MASK_TOUCHPAD | WAYLAND_EVENT_MASK_NOTIFY | WAYLAND_EVENT_MASK_NOTCLI)

static int CALLBACK _EventDispatch(wayland_window* window, dword_t event_id, dword_t event_code, vword_t event_data)
{
	xpoint_t xp;
	xrect_t xr;
	dword_t ks;
	int rev, key;

	switch (event_id)
	{
	case WAYLAND_EVENT_NCPAINT:
        printf("nc paint\n");
		break;
	case WAYLAND_EVENT_HITTEST:
        printf("mouse hit test: %d, %d\n", GETVWORDL(event_data), GETVWORDH(event_data));
		break;
	case WAYLAND_EVENT_NCLBUTTON_DOWN:
        printf("nc left button down: %d, %d\n", (int)GETVWORDL(event_data), (int)GETVWORDH(event_data));
		break;
	case WAYLAND_EVENT_NCLBUTTON_UP:
        printf("nc left button up: %d, %d\n", (int)GETVWORDL(event_data), (int)GETVWORDH(event_data));
		break;
	case WAYLAND_EVENT_NCRBUTTON_DOWN:
        printf("nc right button down: %d, %d\n", (int)GETVWORDL(event_data), (int)GETVWORDH(event_data));
		break;
	case WAYLAND_EVENT_NCRBUTTON_UP:
        printf("nc right button up: %d, %d\n", (int)GETVWORDL(event_data), (int)GETVWORDH(event_data));
		break;
	//case WAYLAND_EVENT_NCMOUSE_MOVE:
    //    printf("nc mouse move: %d, %d\n", GETVWORDL(event_data), GETVWORDH(event_data));
	//	break;
	case WAYLAND_EVENT_KEY_DOWN:
		printf("key down: %d\n", (int)event_code);
		break;
	case WAYLAND_EVENT_KEY_UP:
		printf("key up: %d\n", (int)event_code);
		break;
	case WAYLAND_EVENT_LBUTTON_DOWN:
        printf("left button down: %d, %d\n", (int)GETVWORDL(event_data), (int)GETVWORDH(event_data));
		WaylandSetFocusWindow(window);
		break;
	case WAYLAND_EVENT_LBUTTON_UP:
        printf("left button up: %d, %d\n", (int)GETVWORDL(event_data), (int)GETVWORDH(event_data));
		break;
	case WAYLAND_EVENT_RBUTTON_DOWN:
        printf("right button down: %d, %d\n", (int)GETVWORDL(event_data), (int)GETVWORDH(event_data));
		break;
	case WAYLAND_EVENT_RBUTTON_UP:
        printf("right button up: %d, %d\n", (int)GETVWORDL(event_data), (int)GETVWORDH(event_data));
		break;
	//case WAYLAND_EVENT_MOUSE_MOVE:
    //    printf("mouse move: %d, %d\n", GETVWORDL(event_data), GETVWORDH(event_data));
	//	break;
	case WAYLAND_EVENT_MOUSE_ENTER:
        printf("mouse enter: %d, %d\n", GETVWORDL(event_data), GETVWORDH(event_data));
		break;
	case WAYLAND_EVENT_MOUSE_LEAVE:
        printf("mouse leave: %d, %d\n", GETVWORDL(event_data), GETVWORDH(event_data));
		break;
	//case WAYLAND_EVENT_EXPOSE:
    //    printf("expose: %d, %d\n", GETVWORDL(event_code), GETVWORDH(event_code));
	//	break;
	case WAYLAND_EVENT_SET_FOCUS:
        printf("set focus: %p\n", (void*)event_data);
		break;
	case WAYLAND_EVENT_KILL_FOCUS:
        printf("kill focus: %p\n", (void*)event_data);
		break;
	case WAYLAND_EVENT_SIZE:
        printf("size: %d, %d\n", GETVWORDL(event_code), GETVWORDH(event_code));
		break;
	case WAYLAND_EVENT_SHOW:
        printf("show\n");
		break;
	case WAYLAND_EVENT_CREATE:
        printf("create\n");
		break;
	case WAYLAND_EVENT_DESTROY:
        printf("destroy\n");
		break;
	case WAYLAND_EVENT_COMMAND:
        printf("command: %d\n", (int)event_code);
		break;
	case WAYLAND_EVENT_NOTICE:
        printf("notice: %d\n", (int)event_code);
		break;
	case WAYLAND_EVENT_SCROLL:
        printf("scroll: %d, %d\n", (int)event_code, (int)event_data);
		break;
	case WAYLAND_EVENT_ACTIVATE:
        printf("activate: %d\n", (int)event_code);
		break;
	case WAYLAND_EVENT_WCHAR:
        printf("wchar: %d\n", (int)event_code);
		break;
	case WAYLAND_EVENT_CLOSE:
        printf("close\n");
		break;
	}

	return 0;
}

void test_wayland(void)
{
	xrect_t xr = {100, 100, 600, 600};
    if (WaylandConnect() < 0) return;

    wayland_window* wt = WaylandCreateWindow(NULL, WAYLAND_WINDOW_TYPE_OVERLAP, "Easily", 10, 10, 600, 600);
    WaylandSetWindowProc(wt,  WIDGET_EVENTS, _EventDispatch);
	WaylandShowWindow(wt, WAYLAND_WINDOW_STATE_NORMAL);

	wayland_window* cld = WaylandCreateWindow(wt, WAYLAND_WINDOW_TYPE_CHILD, "Child", 100, 100, 300, 300);
    WaylandSetWindowProc(cld,  WIDGET_EVENTS, _EventDispatch);
	WaylandShowWindow(cld, WAYLAND_WINDOW_STATE_NORMAL);

	WaylandSetFocusWindow(wt);
    WaylandUpdateWindow(wt);

    WaylandDoNormal(wt);

    WaylandDisconnect();
}
#endif //DEBUG

