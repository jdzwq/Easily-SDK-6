/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc editor document

	@module	properedit.c | implement file

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

#include "../inf/editinf.h"

#include "../xdcobj.h"

/***********************************************************************/

static bool_t _properctrl_get_focus_info(widget_t wt, tchar_t* edtior, tchar_t* styles)
{
	link_t_ptr proper = properctrl_fetch(wt);
	link_t_ptr elk = properctrl_get_focus_entity(wt);

	if(!elk) return bool_false;

	xscpy(edtior, get_entity_editor_ptr(elk));
	xscpy(styles, get_proper_style_ptr(elk));

	return bool_true;
}

static void _properctrl_get_focus_rect(widget_t wt, xrect_t* pxr)
{
	link_t_ptr proper = properctrl_fetch(wt);
	link_t_ptr elk = properctrl_get_focus_entity(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_proper_entity(proper, elk));
#endif

	properctrl_get_entity_rect(wt, elk, bool_true, pxr);
}

static void* _properctrl_get_focus_data(widget_t wt)
{
	link_t_ptr proper = properctrl_fetch(wt);
	link_t_ptr elk = properctrl_get_focus_entity(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_proper_entity(proper, elk));
#endif
	
	return get_entity_value_ptr(elk);
}

static bool_t _properctrl_set_focus_data(widget_t wt, void* data)
{
	link_t_ptr proper = properctrl_fetch(wt);
	link_t_ptr elk = properctrl_get_focus_entity(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_proper_entity(proper, elk));
#endif
	
	return properctrl_set_entity_value(wt, elk, (const tchar_t*)data);
}

static bool_t _properctrl_get_focus_auto(widget_t wt)
{
	link_t_ptr proper = properctrl_fetch(wt);
	link_t_ptr elk = properctrl_get_focus_entity(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_proper_entity(proper, elk));
#endif
	
	return bool_false;
}

static bool_t _properctrl_get_focus_canbe(widget_t wt)
{
	link_t_ptr proper = properctrl_fetch(wt);
	link_t_ptr elk = properctrl_get_focus_entity(wt);

	if(properctrl_get_lock(wt)) return bool_false;
	
	return (elk && get_entity_editable(elk))? bool_true : bool_false;
}

static void _properctrl_set_focus_dirty(widget_t wt)
{
	link_t_ptr proper = properctrl_fetch(wt);
	link_t_ptr elk = properctrl_get_focus_entity(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_proper_entity(proper, elk));
#endif
}

static int _properctrl_set_focus_noti(widget_t wt, int cmd, void* data)
{
	link_t_ptr proper = properctrl_fetch(wt);
	link_t_ptr elk = properctrl_get_focus_entity(wt);
	link_t_ptr slk = (elk)? section_from_entity(elk) : NULL;

#ifdef _DEBUG
	XDK_ASSERT(is_proper_entity(proper, elk));
#endif
	
	switch(cmd)
	{
	case COMMAND_EDITING:
		return noti_proper_owner(wt, NC_ENTITYEDITING, proper, slk, elk, data);
	case COMMAND_COMMIT:
		return noti_proper_owner(wt, NC_ENTITYCOMMIT, proper, slk, elk, data);
	case COMMAND_ROLLBACK:
		return noti_proper_owner(wt, NC_ENTITYROLLBACK, proper, slk, elk, data);
	case COMMAND_UPDATE:
		return noti_proper_owner(wt, NC_ENTITYUPDATE, proper, slk, elk, data);
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////

editor_interface edit_properctrl = {
	.with_char = bool_true,
	
	.pf_get_obj_info = _properctrl_get_focus_info,
	.pf_get_obj_rect = _properctrl_get_focus_rect,
	.pf_get_obj_data = _properctrl_get_focus_data,
	.pf_set_obj_data = _properctrl_set_focus_data,
	.pf_get_obj_auto = _properctrl_get_focus_auto,
	.pf_get_obj_canbe = _properctrl_get_focus_canbe,
	.pf_set_obj_dirty = _properctrl_set_focus_dirty,
	.pf_set_obj_noti = _properctrl_set_focus_noti,
};

