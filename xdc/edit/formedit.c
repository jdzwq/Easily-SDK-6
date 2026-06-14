/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc editor document

	@module	formedit.c | implement file

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

static bool_t _formctrl_get_focus_info(widget_t wt, tchar_t* edtior, tchar_t* styles)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = formctrl_get_focus_field(wt);

	if(!flk) return bool_false;

	xscpy(edtior, get_field_editor_ptr(flk));
	xscpy(styles, get_field_style_ptr(flk));

	return bool_true;
}

static void _formctrl_get_focus_rect(widget_t wt, xrect_t* pxr)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = formctrl_get_focus_field(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_form_field(form, flk));
#endif

	formctrl_get_field_rect(wt, flk, pxr);
}

static void* _formctrl_get_focus_data(widget_t wt)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = formctrl_get_focus_field(wt);
	const tchar_t* sz_class;

#ifdef _DEBUG
	XDK_ASSERT(is_form_field(form, flk));
#endif
	
	sz_class = get_field_class_ptr(flk);

	if(IS_DATA_FIELD(sz_class))
		return (void*)get_field_text_ptr(flk);
	else if(IS_EMBED_FIELD(sz_class))
		return (void*)get_field_embed_data(flk);
	else
		return NULL;
}

static bool_t _formctrl_set_focus_data(widget_t wt, void* data)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = formctrl_get_focus_field(wt);
	const tchar_t* sz_class;

#ifdef _DEBUG
	XDK_ASSERT(is_form_field(form, flk));
#endif
	
	sz_class = get_field_class_ptr(flk);

	if(IS_DATA_FIELD(sz_class))
	{
		return formctrl_set_field_text(wt, flk, (const tchar_t*)data);
	}else
	{
		return bool_false;
	}
}

static bool_t _formctrl_get_focus_auto(widget_t wt)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = formctrl_get_focus_field(wt);
	const tchar_t* sz_class;

#ifdef _DEBUG
	XDK_ASSERT(is_form_field(form, flk));
#endif
	
	sz_class = get_field_class_ptr(flk);

	return (IS_AUTO_FIELD(sz_class))? bool_true : bool_false;
}

static bool_t _formctrl_get_focus_canbe(widget_t wt)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = formctrl_get_focus_field(wt);

	if(formctrl_get_lock(wt)) return bool_false;
	
	return (flk && get_field_editable(flk))? bool_true : bool_false;
}

static void _formctrl_set_focus_dirty(widget_t wt)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = formctrl_get_focus_field(wt);
	const tchar_t* sz_class;

#ifdef _DEBUG
	XDK_ASSERT(is_form_field(form, flk));
#endif
	
	sz_class = get_field_class_ptr(flk);

	if(IS_EDITOR_FIELD(sz_class))
	{
		set_field_dirty(flk, bool_true);
	}
}

static int _formctrl_set_focus_noti(widget_t wt, int cmd, void* data)
{
	link_t_ptr form = formctrl_fetch(wt);
	link_t_ptr flk = formctrl_get_focus_field(wt);

#ifdef _DEBUG
	XDK_ASSERT(is_form_field(form, flk));
#endif
	
	switch(cmd)
	{
	case COMMAND_EDITING:
		return noti_form_owner(wt, NC_FIELDEDITING, form, flk, data);
	case COMMAND_COMMIT:
		return noti_form_owner(wt, NC_FIELDCOMMIT, form, flk, data);
	case COMMAND_ROLLBACK:
		return noti_form_owner(wt, NC_FIELDROLLBACK, form, flk, data);
	case COMMAND_UPDATE:
		return noti_form_owner(wt, NC_FIELDUPDATE, form, flk, data);
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////

editor_interface edit_formctrl = {
	.with_char = bool_true,

	.pf_get_obj_info = _formctrl_get_focus_info,
	.pf_get_obj_rect = _formctrl_get_focus_rect,
	.pf_get_obj_data = _formctrl_get_focus_data,
	.pf_set_obj_data = _formctrl_set_focus_data,
	.pf_get_obj_auto = _formctrl_get_focus_auto,
	.pf_get_obj_canbe = _formctrl_get_focus_canbe,
	.pf_set_obj_dirty = _formctrl_set_focus_dirty,
	.pf_set_obj_noti = _formctrl_set_focus_noti,
};

