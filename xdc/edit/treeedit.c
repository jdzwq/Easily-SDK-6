/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc editor document

	@module	treeedit.c | implement file

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

static bool_t _treectrl_get_focus_info(widget_t wt, tchar_t* edtior, tchar_t* styles)
{
	link_t_ptr tree = treectrl_fetch(wt);
	link_t_ptr ilk = treectrl_get_focus_item(wt);

	if(!ilk) return bool_false;

	xscpy(edtior, ATTR_EDITOR_FIREEDIT);
	xscpy(styles, get_tree_style_ptr(tree));

	return bool_true;
}

static void _treectrl_get_focus_rect(widget_t wt, xrect_t* pxr)
{
	link_t_ptr tree = treectrl_fetch(wt);
	link_t_ptr ilk = treectrl_get_focus_item(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_tree_item(tree, ilk));
#endif

	treectrl_get_item_rect(wt, ilk, bool_true, pxr);
}

static void* _treectrl_get_focus_data(widget_t wt)
{
	link_t_ptr tree = treectrl_fetch(wt);
	link_t_ptr ilk = treectrl_get_focus_item(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_tree_item(tree, ilk));
#endif
	
	return get_tree_item_title_ptr(ilk);
}

static bool_t _treectrl_set_focus_data(widget_t wt, void* data)
{
	link_t_ptr tree = treectrl_fetch(wt);
	link_t_ptr ilk = treectrl_get_focus_item(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_tree_item(tree, ilk));
#endif
	
	return treectrl_set_item_title(wt, ilk, (const tchar_t*)data);
}

static bool_t _treectrl_get_focus_auto(widget_t wt)
{
	link_t_ptr tree = treectrl_fetch(wt);
	link_t_ptr ilk = treectrl_get_focus_item(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_tree_item(tree, ilk));
#endif
	
	return bool_false;
}

static bool_t _treectrl_get_focus_canbe(widget_t wt)
{
	link_t_ptr tree = treectrl_fetch(wt);
	link_t_ptr ilk = treectrl_get_focus_item(wt);

	if(treectrl_get_lock(wt)) return bool_false;
	
	return (ilk)? bool_true : bool_false;
}

static void _treectrl_set_focus_dirty(widget_t wt)
{
	link_t_ptr tree = treectrl_fetch(wt);
	link_t_ptr ilk = treectrl_get_focus_item(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_tree_item(tree, ilk));
#endif
}

static int _treectrl_set_focus_noti(widget_t wt, int cmd, void* data)
{
	link_t_ptr tree = treectrl_fetch(wt);
	link_t_ptr ilk = treectrl_get_focus_item(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_tree_item(tree, ilk));
#endif
	
	switch(cmd)
	{
	case COMMAND_EDITING:
		return noti_tree_owner(wt, NC_TREEITEMEDITING, tree, ilk, data);
	case COMMAND_COMMIT:
		return noti_tree_owner(wt, NC_TREEITEMCOMMIT, tree, ilk, data);
	case COMMAND_ROLLBACK:
		return noti_tree_owner(wt, NC_TREEITEMROLLBACK, tree, ilk, data);
	case COMMAND_UPDATE:
		return noti_tree_owner(wt, NC_TREEITEMUPDATE, tree, ilk, data);
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////

editor_interface edit_treectrl = {
	.with_char = bool_false,

	.pf_get_obj_info = _treectrl_get_focus_info,
	.pf_get_obj_rect = _treectrl_get_focus_rect,
	.pf_get_obj_data = _treectrl_get_focus_data,
	.pf_set_obj_data = _treectrl_set_focus_data,
	.pf_get_obj_auto = _treectrl_get_focus_auto,
	.pf_get_obj_canbe = _treectrl_get_focus_canbe,
	.pf_set_obj_dirty = _treectrl_set_focus_dirty,
	.pf_set_obj_noti = _treectrl_set_focus_noti,
};

