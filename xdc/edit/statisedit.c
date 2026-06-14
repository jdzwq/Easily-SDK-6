/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc editor document

	@module	statisedit.c | implement file

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

static bool_t _statisctrl_get_focus_info(widget_t wt, tchar_t* edtior, tchar_t* styles)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr xlk = statisctrl_get_focus_xax(wt);
	link_t_ptr ylk = statisctrl_get_focus_yax(wt);

	if(!xlk) return bool_false;

	if(ylk)
		xscpy(edtior, ATTR_EDITOR_FIRENUM);
	else
		xscpy(edtior, ATTR_EDITOR_FIREEDIT);

	xscpy(styles, get_statis_style_ptr(statis));

	return bool_true;
}

static void _statisctrl_get_focus_rect(widget_t wt, xrect_t* pxr)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr xlk = statisctrl_get_focus_xax(wt);
	link_t_ptr ylk = statisctrl_get_focus_yax(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_statis_xax(statis, xlk));
#endif

	statisctrl_get_coor_rect(wt, xlk, ylk, pxr);
}

static void* _statisctrl_get_focus_data(widget_t wt)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr xlk = statisctrl_get_focus_xax(wt);
	link_t_ptr ylk = statisctrl_get_focus_yax(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_statis_xax(statis, xlk));
#endif
	
	if (ylk)
		return get_coor_text_ptr(xlk, ylk);
	else
		return get_xax_text_ptr(xlk);
}

static bool_t _statisctrl_set_focus_data(widget_t wt, void* data)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr xlk = statisctrl_get_focus_xax(wt);
	link_t_ptr ylk = statisctrl_get_focus_yax(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_statis_xax(statis, xlk));
#endif
	
	return statisctrl_set_coor_text(wt, xlk, ylk, (const tchar_t*)data);
}

static bool_t _statisctrl_get_focus_auto(widget_t wt)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr xlk = statisctrl_get_focus_xax(wt);
	link_t_ptr ylk = statisctrl_get_focus_yax(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_statis_xax(statis, xlk));
#endif
	
	return bool_false;
}

static bool_t _statisctrl_get_focus_canbe(widget_t wt)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr xlk = statisctrl_get_focus_xax(wt);

	if(statisctrl_get_lock(wt)) return bool_false;
	
	return (xlk && !get_xax_locked(xlk))? bool_true : bool_false;
}

static void _statisctrl_set_focus_dirty(widget_t wt)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr xlk = statisctrl_get_focus_xax(wt);
	link_t_ptr ylk = statisctrl_get_focus_yax(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_statis_xax(statis, xlk));
#endif

	set_coor_dirty(xlk, ylk, bool_true);
}

static int _statisctrl_set_focus_noti(widget_t wt, int cmd, void* data)
{
	link_t_ptr statis = statisctrl_fetch(wt);
	link_t_ptr xlk = statisctrl_get_focus_xax(wt);
	link_t_ptr ylk = statisctrl_get_focus_yax(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_statis_xax(statis, xlk));
#endif
	
	switch(cmd)
	{
	case COMMAND_EDITING:
		return noti_statis_owner(wt, NC_COOREDITING, statis, xlk, ylk, NULL, data);
	case COMMAND_COMMIT:
		return noti_statis_owner(wt, NC_COORCOMMIT, statis, xlk, ylk, NULL, data);
	case COMMAND_ROLLBACK:
		return noti_statis_owner(wt, NC_COORROLLBACK, statis, xlk, ylk, NULL, data);
	case COMMAND_UPDATE:
		return noti_statis_owner(wt, NC_COORUPDATE, statis, xlk, ylk, NULL, data);
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////

editor_interface edit_statisctrl = {
	.with_char = bool_false,

	.pf_get_obj_info = _statisctrl_get_focus_info,
	.pf_get_obj_rect = _statisctrl_get_focus_rect,
	.pf_get_obj_data = _statisctrl_get_focus_data,
	.pf_set_obj_data = _statisctrl_set_focus_data,
	.pf_get_obj_auto = _statisctrl_get_focus_auto,
	.pf_get_obj_canbe = _statisctrl_get_focus_canbe,
	.pf_set_obj_dirty = _statisctrl_set_focus_dirty,
	.pf_set_obj_noti = _statisctrl_set_focus_noti,
};

