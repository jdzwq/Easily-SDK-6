/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc context document

	@module	wayland_events.c | wayland implement file

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

#include "_wayland.h"

typedef struct _wayland_event{
    link_t lk;

    wayland_window* window;
    dword_t event_id;
    dword_t event_code;
    vword_t event_data;
} wayland_event;

res_crit_t gw_wayland_critical	= NULL;
static link_t gw_wayland_events = {0};


void WaylandEventsInit(void)
{
	if(gw_wayland_critical) return;

	gw_wayland_critical = criti_create();

	init_root_link(&gw_wayland_events);
}

void WaylandEventsUninit(void)
{
	link_t_ptr plk, nlk;
	wayland_event* pev;

	if(!gw_wayland_critical) return;
	
	criti_enter(gw_wayland_critical);

	while (plk = delete_link(&gw_wayland_events, LINK_FIRST))
	{
		pev = TypePtrFromLink(wayland_event, plk);
		xmem_free(pev);
	}

	criti_leave(gw_wayland_critical);
	criti_destroy(gw_wayland_critical);
	gw_wayland_critical = NULL;
}

int WaylandEventsPending(void)
{
	wayland_display* pdisp = WaylandDefaultDisplay();
	int rt;

	rt = wl_display_dispatch_pending(pdisp->raw_disp);
	if(rt < 0) return (-1);

	if(rt == 0) 
	{
		rt = wl_display_dispatch(pdisp->raw_disp);
		if(rt < 0) return (-1);

		if(get_first_link(&gw_wayland_events))
			rt = 1;
		else
			rt = 0;
	}

	return rt;
}

void WaylandEventsAdd(wayland_window* window, dword_t event_id, dword_t event_code, vword_t event_data)
{
	wayland_event* pevt;

	pevt = (wayland_event*)xmem_alloc_handle(sizeof(wayland_event));
	pevt->lk.tag = LINK_TAG_EVENT;
	pevt->window = window;
	pevt->event_id = event_id;
	pevt->event_code = event_code;
	pevt->event_data = event_data;

	criti_enter(gw_wayland_critical);
	insert_link_after(&gw_wayland_events, LINK_LAST, &pevt->lk);
	criti_leave(gw_wayland_critical);
}

bool_t wEventsFetch(wayland_window** pwindow, dword_t* pevent_id, dword_t* pevent_code, vword_t* pevent_data)
{
	link_t_ptr plk;
	wayland_event* pev;
	bool_t rt = bool_false;

	criti_enter(gw_wayland_critical);

	plk = delete_link(&gw_wayland_events, LINK_FIRST);
	if(!plk)
	{
		pev = TypePtrFromLink(wayland_event, plk);

		if (pwindow) *pwindow = pev->window;
		if (pevent_id) *pevent_id = pev->event_id;
		if (pevent_code) *pevent_code = pev->event_code;
		if (pevent_data) *pevent_data = pev->event_data;

		xmem_free(pev);
		rt = bool_true;
	}

	criti_leave(gw_wayland_critical);

	return rt;
}

bool_t WaylandEventsPeek(wayland_window** pwindow, dword_t* pevent_id, dword_t* pevent_code, vword_t* pevent_data)
{
	link_t_ptr plk;
	wayland_event* pev;

	plk = get_first_link(&gw_wayland_events);
	if(!plk) return bool_false;

	pev = TypePtrFromLink(wayland_event, plk);

	if (pwindow) *pwindow = pev->window;
	if (pevent_id) *pevent_id = pev->event_id;
	if (pevent_code) *pevent_code = pev->event_code;
	if (pevent_data) *pevent_data = pev->event_data;
	
	return bool_true;
}

void WaylandEventsFlash(void)
{
	wayland_display* pdisp = WaylandDefaultDisplay();
}
