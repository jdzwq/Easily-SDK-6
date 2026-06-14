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

    int rt = 0;
    wayland_window* win = NULL;
    dword_t event_id = 0;
    dword_t event_code = 0;
    vword_t event_data = 0;
    wayland_win_proc winproc = NULL;

    while (rt >= 0)
    {
        rt = WaylandEventsPending();
        if(rt < 0) break;

        if(rt > 0)
        {
            win = NULL;
            event_id = 0;
            event_code = 0;
            event_data = 0;
            //if(WaylandEventsFetch(&win, &event_id, &event_code, &event_data))
            {
                NOP;
            }
        }
        else
        {
            sleep(10);
        }
    }
}

#if defined (DEBUG) || defined (_DEBUG)
void test_wayland(void)
{
	xrect_t xr = {100, 100, 600, 600};
    if (WaylandConnect() < 0) return;

    wayland_window* wt = WaylandCreateWindow(NULL, WAYLAND_WINDOW_TYPE_OVERLAP, 0, "Easily", 100, 100, 600, 600);
    WaylandUpdateWindow(wt);

    WaylandDoNormal(wt);

    WaylandDisconnect();
}
#endif //DEBUG

