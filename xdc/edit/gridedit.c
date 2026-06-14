/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc editor document

	@module	gridedit.c | implement file

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

static bool_t _gridctrl_get_focus_info(widget_t wt, tchar_t* edtior, tchar_t* styles)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr clk = gridctrl_get_focus_col(wt);

	if(!clk) return bool_false;

	xscpy(edtior, get_col_editor_ptr(clk));
	xscpy(styles, get_col_style_ptr(clk));

	return bool_true;
}

static void _gridctrl_get_focus_rect(widget_t wt, xrect_t* pxr)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr rlk = gridctrl_get_focus_row(wt);
	link_t_ptr clk = gridctrl_get_focus_col(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_grid_row(grid, rlk));
	XDK_ASSERT(is_grid_col(grid, clk));
#endif

	gridctrl_get_cell_rect(wt, rlk, clk, pxr);
}

static void* _gridctrl_get_focus_data(widget_t wt)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr rlk = gridctrl_get_focus_row(wt);
	link_t_ptr clk = gridctrl_get_focus_col(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_grid_row(grid, rlk));
	XDK_ASSERT(is_grid_col(grid, clk));
#endif
	
	return get_cell_text_ptr(rlk, clk);
}

static bool_t _gridctrl_set_focus_data(widget_t wt, void* data)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr rlk = gridctrl_get_focus_row(wt);
	link_t_ptr clk = gridctrl_get_focus_col(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_grid_row(grid, rlk));
	XDK_ASSERT(is_grid_col(grid, clk));
#endif
	
	return gridctrl_set_cell_text(wt, rlk, clk, (const tchar_t*)data);
}

static bool_t _gridctrl_get_focus_auto(widget_t wt)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	
	return bool_false;
}

static bool_t _gridctrl_get_focus_canbe(widget_t wt)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr rlk = gridctrl_get_focus_row(wt);
	link_t_ptr clk = gridctrl_get_focus_col(wt);
	
	if(gridctrl_get_lock(wt)) return bool_false;

	return (rlk && !get_row_locked(rlk) && clk && get_col_focusable(clk))? bool_true : bool_false;
}

static void _gridctrl_set_focus_dirty(widget_t wt)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr rlk = gridctrl_get_focus_row(wt);
	link_t_ptr clk = gridctrl_get_focus_col(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_grid_row(grid, rlk));
	XDK_ASSERT(is_grid_col(grid, clk));
#endif

	set_cell_dirty(rlk, clk, bool_true);
	set_row_dirty(rlk);
}

static int _gridctrl_set_focus_noti(widget_t wt, int cmd, void* data)
{
	link_t_ptr grid = gridctrl_fetch(wt);
	link_t_ptr rlk = gridctrl_get_focus_row(wt);
	link_t_ptr clk = gridctrl_get_focus_col(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_grid_row(grid, rlk));
	XDK_ASSERT(is_grid_col(grid, clk));
#endif
	
	switch(cmd)
	{
	case COMMAND_EDITING:
		return noti_grid_owner(wt, NC_CELLEDITING, grid, rlk, clk, data);
	case COMMAND_COMMIT:
		return noti_grid_owner(wt, NC_CELLCOMMIT, grid, rlk, clk, data);
	case COMMAND_ROLLBACK:
		return noti_grid_owner(wt, NC_CELLROLLBACK, grid, rlk, clk, data);
	case COMMAND_UPDATE:
		return noti_grid_owner(wt, NC_CELLUPDATE, grid, rlk, clk, data);
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////

editor_interface edit_gridctrl = {
	.with_char = bool_true,

	.pf_get_obj_info = _gridctrl_get_focus_info,
	.pf_get_obj_rect = _gridctrl_get_focus_rect,
	.pf_get_obj_data = _gridctrl_get_focus_data,
	.pf_set_obj_data = _gridctrl_set_focus_data,
	.pf_get_obj_auto = _gridctrl_get_focus_auto,
	.pf_get_obj_canbe = _gridctrl_get_focus_canbe,
	.pf_set_obj_dirty = _gridctrl_set_focus_dirty,
	.pf_set_obj_noti = _gridctrl_set_focus_noti,
};

