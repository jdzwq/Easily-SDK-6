/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc designer document

	@module	designer.c | implement file

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

#include "designer.h"

#include "../xdcobj.h"


#define MAX_UNDO		7
#define MAX_FEED		10
#define MIN_WIDTH		40
#define MIN_HEIGHT		30

typedef struct _DESIGNERUNDO*	DESIGNERUNDO_PTR;
typedef struct _DESIGNERUNDO{
	byte_t* buff;
	dword_t size;

	DESIGNERUNDO_PTR next;
}DESIGNERUNDO;

typedef struct _designer_context{
	widget_t widget;

	void* cur_obj;

	bool_t b_drag;
	bool_t b_size;
	bool_t b_group;

	int org_hint;
	int org_x, cur_x;
	int org_y, cur_y;

	designer_interface desg;

	int max_undo;
	DESIGNERUNDO* ptu;
}designer_context;

//////////////////////////////////////////////////////////////////////////////////////////////////
static void _designer_done(designer_context* ptd)
{
	designer_interface* pdi = &(ptd->desg);
	DESIGNERUNDO *pnew,*pnxt;
	int count = 0;

	if (!ptd->max_undo)
		return;

	pnew = (DESIGNERUNDO*)xmem_alloc(sizeof(DESIGNERUNDO));

	pnew->size = (*pdi->pf_retrive_doc)(ptd->widget, NULL, MAX_LONG);
	pnew->buff = xmem_alloc(pnew->size);
	(*pdi->pf_retrive_doc)(ptd->widget, pnew->buff, pnew->size);

	pnew->next = ptd->ptu;
	ptd->ptu = pnew;

	while (count ++ < ptd->max_undo && pnew)
	{
		pnxt = pnew;
		pnew = pnew->next;
	}

	if (pnew)
	{
		pnxt->next = NULL;
	}

	while (pnew)
	{
		pnxt = pnew->next;

		xmem_free(pnew->buff);
		xmem_free(pnew);

		pnew = pnxt;
	}
}

static void _designer_discard(designer_context* ptd)
{
	designer_interface* pdi = &(ptd->desg);
	DESIGNERUNDO *prev;

	if (ptd->ptu)
	{
		prev = ptd->ptu;
		ptd->ptu = prev->next;
		
		xmem_free(prev->buff);
		xmem_free(prev);
	}
}

static void _designer_clean(designer_context* ptd)
{
	designer_interface* pdi = &(ptd->desg);
	DESIGNERUNDO *next;

	while (ptd->ptu)
	{
		next = ptd->ptu->next;

		xsfree(ptd->ptu->buff);
		xmem_free(ptd->ptu);

		ptd->ptu = next;
	}
}
/********************************************************************************************/

static int _designer_calc_hint(designer_context* ptd, const xpoint_t* pxp, void** pobj)
{
	designer_interface* pdi = &(ptd->desg);
	xrect_t xr;
	void* obj;

	obj = (*pdi->pf_get_next_obj)(ptd->widget, LINK_FIRST);
	while (obj)
	{
		(*pdi->pf_get_obj_rect)(ptd->widget, obj, &xr);

		if (pt_inside(pxp->x, pxp->y, xr.x + xr.w - MAX_FEED / 2, xr.y + xr.h / 2 - MAX_FEED / 2, xr.x + xr.w + MAX_FEED / 2, xr.y + xr.h / 2 + MAX_FEED / 2))
		{
			*pobj = obj;
			return HINT_VERT_SPLIT;
		}
		else if (pt_inside(pxp->x, pxp->y, xr.x + xr.w / 2 - MAX_FEED, xr.y + xr.h - MAX_FEED / 2, xr.x + xr.w / 2 + MAX_FEED, xr.y + xr.h + MAX_FEED / 2))
		{
			*pobj = obj;
			return HINT_HORZ_SPLIT;
		}
		else if (pt_inside(pxp->x, pxp->y, xr.x + xr.w - MAX_FEED / 2, xr.y + xr.h - MAX_FEED / 2, xr.x + xr.w + MAX_FEED / 2, xr.y + xr.h + MAX_FEED / 2))
		{
			*pobj = obj;
			return HINT_CROSS_SPLIT;
		}
		else if(pt_inside(pxp->x, pxp->y, xr.x, xr.y, xr.x + xr.w, xr.y + xr.h))
		{
			*pobj = obj;
			return HINT_OBJECT;
		}

		obj = (*pdi->pf_get_next_obj)(ptd->widget, obj);
	}

	*pobj = NULL;
	return HINT_NONE;
}

static void _designer_ensure_visible(designer_context* ptd, void* obj)
{
	designer_interface* pdi = &(ptd->desg);
	xrect_t xr;

	(*pdi->pf_get_obj_rect)(ptd->widget, obj, &xr);

	pt_expand_rect(&xr, MAX_FEED, MAX_FEED);

	widget_ensure_visible(ptd->widget, &xr, 1);
}

static int _designer_noti_owner(designer_context* ptd, unsigned int code, void* obj, vword_t data)
{
	designer_interface* pdi = &(ptd->desg);
	NOTICE_DESIGN nf = { 0 };
	widget_t owner;

	nf.widget = ptd->widget;
	nf.id = widget_get_user_id(ptd->widget);
	nf.code = code;

	nf.data = data;	
	nf.ret = 0;
	nf.object = obj;

	owner = widget_get_owner(ptd->widget);
	if(owner) 
		widget_send_notice(owner, (LPNOTICE)&nf);
	else
		nf.ret = 0;

	return nf.ret;
}

static void _designer_noti_reset_select(designer_context* ptd, bool_t b_sel)
{
	designer_interface* pdi = &(ptd->desg);
	link_t_ptr obj;
	int count = 0;

	obj = (*pdi->pf_get_next_obj)(ptd->widget, LINK_FIRST);
	while (obj)
	{
		if (!b_sel && (*pdi->pf_get_obj_selected)(ptd->widget, obj))
		{
			_designer_noti_owner(ptd, NC_OBJECT_UNSELECT, obj, 0);
			(*pdi->pf_set_obj_selected)(ptd->widget, obj, 0);

			count++;
		}

		if (b_sel && !(*pdi->pf_get_obj_selected)(ptd->widget, obj))
		{
			(*pdi->pf_set_obj_selected)(ptd->widget, obj, 1);
			_designer_noti_owner(ptd, NC_OBJECT_SELECTED, obj, 0);

			count++;
		}

		obj = (*pdi->pf_get_next_obj)(ptd->widget, obj);
	}

	if (count)
	{
		widget_erase(ptd->widget, NULL);
	}
}

static void _designer_noti_object_unselect(designer_context* ptd, void* obj)
{
	designer_interface* pdi = &(ptd->desg);
	xrect_t xr;

	XDK_ASSERT(obj != NULL);

	_designer_noti_owner(ptd, NC_OBJECT_UNSELECT, obj, 0);

	(*pdi->pf_set_obj_selected)(ptd->widget, obj, 0);

	(*pdi->pf_get_obj_rect)(ptd->widget, obj, &xr);

	pt_expand_rect(&xr, MAX_FEED, MAX_FEED);

	widget_erase(ptd->widget, &xr);
}

static void _designer_noti_object_selected(designer_context* ptd, void* obj)
{
	designer_interface* pdi = &(ptd->desg);
	xrect_t xr;

	XDK_ASSERT(obj != NULL);

	(*pdi->pf_set_obj_selected)(ptd->widget, obj, 1);

	_designer_noti_owner(ptd, NC_OBJECT_SELECTED, obj, 0);

	(*pdi->pf_get_obj_rect)(ptd->widget, obj, &xr);

	pt_expand_rect(&xr, MAX_FEED, MAX_FEED);

	widget_erase(ptd->widget, &xr);
}

static bool_t _designer_noti_object_changing(designer_context* ptd)
{
	designer_interface* pdi = &(ptd->desg);
	xrect_t xr;
	void *obf = ptd->cur_obj;

	XDK_ASSERT(obf != NULL);

	if(_designer_noti_owner(ptd, NC_OBJECT_CHANGING, obf, 0))
		return bool_false;

	ptd->cur_obj = NULL;

	(*pdi->pf_get_obj_rect)(ptd->widget, obf, &xr);

	pt_expand_rect(&xr, MAX_FEED, MAX_FEED);

	widget_erase(ptd->widget, &xr);

	return bool_true;
}

static void _designer_noti_object_changed(designer_context* ptd, void* obj)
{
	designer_interface* pdi = &(ptd->desg);
	xrect_t xr;

	XDK_ASSERT(obj != NULL);

	ptd->cur_obj = obj;

	_designer_noti_owner(ptd, NC_OBJECT_CHANGED, obj, 0);

	(*pdi->pf_get_obj_rect)(ptd->widget, obj, &xr);

	pt_expand_rect(&xr, MAX_FEED, MAX_FEED);

	widget_erase(ptd->widget, &xr);
}

static void _designer_noti_object_drag(designer_context* ptd, int x, int y)
{
	designer_interface* pdi = &(ptd->desg);
	xpoint_t pt;
	void *obf = ptd->cur_obj;

	XDK_ASSERT(obf != NULL);

	ptd->b_drag = (bool_t)1;
	ptd->org_x = x;
	ptd->org_y = y;

	if (widget_can_focus(ptd->widget))
	{
		widget_set_capture(ptd->widget, 1);
	}

	pt.x = x;
	pt.y = y;

	if(obf)
	{
		_designer_noti_owner(ptd, NC_OBJECT_DRAG, obf, (vword_t)&pt);
	}
}

static void _designer_noti_object_drop(designer_context* ptd, int x, int y)
{
	designer_interface* pdi = &(ptd->desg);
	xpoint_t pt;
	xrect_t xr;
	void *obj, *obf = ptd->cur_obj;
	int cx, cy;
	int cn = 0;

	XDK_ASSERT(obf != NULL);

	ptd->cur_x = x;
	ptd->cur_y = y;

	ptd->b_drag = (bool_t)0;

	if (widget_can_focus(ptd->widget))
	{
		widget_set_capture(ptd->widget, 0);
	}

	cx = x - ptd->org_x;
	cy = y - ptd->org_y;

	if (!cx && !cy)
		return;

	_designer_done(ptd);

	pt.x = x;
	pt.y = y;

	obj = (*pdi->pf_get_next_obj)(ptd->widget, LINK_FIRST);
	while (obj)
	{
		if (obj == obf || (*pdi->pf_get_obj_selected)(ptd->widget, obj))
		{
			(*pdi->pf_get_obj_rect)(ptd->widget, obj, &xr);

			pt.x = xr.x + cx;
			pt.y = xr.y + cy;

			(*pdi->pf_set_obj_point)(ptd->widget, obj, &pt);

			if (obj == obf)
			{
				_designer_noti_owner(ptd, NC_OBJECT_DROP, obf, (vword_t)&pt);
			}

			cn++;
		}

		obj = (*pdi->pf_get_next_obj)(ptd->widget, obj);
	}

	if(cn)
	{
		widget_erase(ptd->widget, NULL);
	}
}

static void _designer_noti_object_sizing(designer_context* ptd, int hint, int x, int y)
{
	designer_interface* pdi = &(ptd->desg);
	void *obf = ptd->cur_obj;

	XDK_ASSERT(obf != NULL);

	if (widget_can_focus(ptd->widget))
	{
		widget_set_capture(ptd->widget, 1);
	}

	ptd->org_hint = hint;
	ptd->org_x = x;
	ptd->org_y = y;

	ptd->b_size = (bool_t)1;

	_designer_noti_owner(ptd, NC_OBJECT_SIZING, obf, 0);
}

static void _designer_noti_object_sized(designer_context* ptd, int x, int y)
{
	designer_interface* pdi = &(ptd->desg);
	int hint;
	xrect_t xr;
	xsize_t xs;
	void *obf = ptd->cur_obj;

	XDK_ASSERT(obf != NULL);

	ptd->cur_x = x;
	ptd->cur_y = y;

	ptd->b_size = (bool_t)0;

	if (widget_can_focus(ptd->widget))
	{
		widget_set_capture(ptd->widget, 0);
	}
	widget_set_cursor(ptd->widget, CURSOR_ARROW);

	hint = ptd->org_hint;

	xs.w = ptd->cur_x - ptd->org_x;
	xs.h = ptd->cur_y - ptd->org_y;

	if (!xs.w && !xs.h)
		return;

	_designer_done(ptd);

	(*pdi->pf_get_obj_rect)(ptd->widget, obf, &xr);

	xs.w += xr.w;
	xs.h += xr.h;

	if (xs.w < MIN_WIDTH)
		xs.w = MIN_WIDTH;

	if (xs.h < MIN_HEIGHT)
		xs.h = MIN_HEIGHT;

	if (hint == HINT_HORZ_SPLIT)
	{
		xs.w = xr.w;
	}
	else if (hint == HINT_VERT_SPLIT)
	{
		xs.h = xr.h;
	}

	(*pdi->pf_set_obj_size)(ptd->widget, obf, &xs);

	xr.w = xs.w;
	xr.h = xs.h;
	pt_expand_rect(&xr, MAX_FEED, MAX_FEED);

	widget_erase(ptd->widget, NULL);

	_designer_noti_owner(ptd, NC_OBJECT_SIZED, obf, 0);
}

static void _designer_noti_object_grouping(designer_context* ptd, int x, int y)
{
	designer_interface* pdi = &(ptd->desg);

	if (widget_can_focus(ptd->widget))
	{
		widget_set_capture(ptd->widget, 1);
	}
	widget_set_cursor(ptd->widget,CURSOR_HAND);

	ptd->b_group = (bool_t)1;
	ptd->org_x = x;
	ptd->org_y = y;
}

static void _designer_noti_object_grouped(designer_context* ptd, int x, int y)
{
	designer_interface* pdi = &(ptd->desg);
	void* obj;
	xrect_t xr_group, xr;
	int n = 0;

	ptd->b_group = (bool_t)0;

	if (widget_can_focus(ptd->widget))
	{
		widget_set_capture(ptd->widget, 0);
	}
	widget_set_cursor(ptd->widget, CURSOR_ARROW);

	ptd->cur_x = x;
	ptd->cur_y = y;

	xr_group.x = (ptd->org_x < ptd->cur_x) ? ptd->org_x : ptd->cur_x;
	xr_group.y = (ptd->org_y < ptd->cur_y) ? ptd->org_y : ptd->cur_y;
	xr_group.w = (ptd->org_x > ptd->cur_x) ? ptd->org_x : ptd->cur_x - xr_group.x;
	xr_group.h = (ptd->org_y > ptd->cur_y) ? ptd->org_y : ptd->cur_y - xr_group.y;

	obj = (*pdi->pf_get_next_obj)(ptd->widget, LINK_FIRST);
	while (obj)
	{
		(*pdi->pf_get_obj_rect)(ptd->widget, obj, &xr);

		if (pt_inside(xr.x, xr.y, xr_group.x, xr_group.y, xr_group.x + xr_group.w, xr_group.y + xr_group.h))
		{
			(*pdi->pf_set_obj_selected)(ptd->widget, obj, 1);
			n++;
		}

		obj = (*pdi->pf_get_next_obj)(ptd->widget, obj);
	}

	pt_expand_rect(&xr_group, MAX_FEED, MAX_FEED);
	widget_erase(ptd->widget, &xr_group);
}

/********************************************************************************************/

static bool_t _designer_undo(designer_context* ptd)
{
	designer_interface* pdi = &(ptd->desg);
	DESIGNERUNDO *next;

	if(!ptd->ptu) return bool_false;

	if(ptd->cur_obj && !_designer_noti_object_changing(ptd))
		return bool_false;

	(*pdi->pf_restore_doc)(ptd->widget, ptd->ptu->buff, ptd->ptu->size);

	next = ptd->ptu->next;
	xmem_free(ptd->ptu->buff);
	xmem_free(ptd->ptu);
	ptd->ptu = next;

	return bool_true;
}

static bool_t _designer_copy(designer_context* ptd)
{
	designer_interface* pdi = &(ptd->desg);
	int len = 0;
	tchar_t* buf;
	void *obf = ptd->cur_obj;

	if (!obf) return bool_false;

	len = (*pdi->pf_get_obj_attrs)(ptd->widget, obf, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	len = (*pdi->pf_get_obj_attrs)(ptd->widget, obf, buf, len);

	if (!clipboard_put(ptd->widget, DEF_CB_FORMAT, (byte_t*)buf, (dword_t)((len+1) * sizeof(tchar_t))))
	{
		xsfree(buf);
		return bool_false;
	}

	xsfree(buf);
	return bool_true;
}

static bool_t _designer_cut(designer_context* ptd)
{
	designer_interface* pdi = &(ptd->desg);
	bool_t atom = 0;
	void* obf = ptd->cur_obj;

	if (!_designer_copy(ptd))
		return bool_false;

	if(!_designer_noti_object_changing(ptd))
		return bool_false;

	_designer_done(ptd);

	if (!((*pdi->pf_del_obj)(ptd->widget, obf)))
	{
		_designer_discard(ptd);
		return bool_false;
	}

	return bool_true;
}

static bool_t _designer_paste(designer_context* ptd)
{
	designer_interface* pdi = &(ptd->desg);
	tchar_t* buf;
	int len;
	int row, col, page;
	void* obj = NULL;
	bool_t atom = 0;

	len = clipboard_get(ptd->widget, DEF_CB_FORMAT, NULL, MAX_LONG);
	if (!len)
	{
		return bool_false;
	}

	_designer_done(ptd);

	buf = (tchar_t*)xmem_alloc(len);
	clipboard_get(ptd->widget, DEF_CB_FORMAT, (byte_t*)buf, len);
	len = xslen(buf);
	
	obj = (*pdi->pf_ins_obj)(ptd->widget, buf, len);
	if (!obj)
	{
		_designer_discard(ptd);

		xsfree(buf);
		return bool_false;
	}

	xsfree(buf);

	return bool_true;
}
/********************************************************************************************/

int designer_sub_lbutton_down(widget_t widget, const xpoint_t* pxp, uid_t sid, vword_t delta)
{
	designer_context* ptd = (designer_context*)delta;
	designer_interface* pdi = &(ptd->desg);
	int hint;
	void *obj, *obf = ptd->cur_obj;
	bool_t bSel, bCtl;

	XDK_ASSERT(sid == IDS_DESIGNER && ptd);

	bCtl = widget_key_state(ptd->widget, KS_WITH_CONTROL);

	obj = NULL;
	hint = _designer_calc_hint(ptd, pxp, &obj);

	switch (hint)
	{
	case HINT_HORZ_SPLIT:
		widget_set_cursor(widget, CURSOR_SIZENS);
		break;
	case HINT_VERT_SPLIT:
		widget_set_cursor(widget, CURSOR_SIZEWE);
		break;
	case HINT_CROSS_SPLIT:
		widget_set_cursor(widget, CURSOR_SIZEALL);
		break;
	case HINT_OBJECT:
		if(!bCtl)
			break;
		
		bSel = (*pdi->pf_get_obj_selected)(ptd->widget, obj);
		if(bSel)
			_designer_noti_object_unselect(ptd, obj);
		else
			_designer_noti_object_selected(ptd, obj);
		break;
	case HINT_NONE:	
		if(!bCtl)
		{
			_designer_noti_reset_select(ptd, 0);
		}
		break;
	}

	return 1;
}

int designer_sub_lbutton_up(widget_t widget, const xpoint_t* pxp, uid_t sid, vword_t delta)
{
	designer_context* ptd = (designer_context*)delta;
	designer_interface* pdi = &(ptd->desg);
	bool_t bRe, bCtl;
	int hint;
	void *obj, *obf = ptd->cur_obj;

	XDK_ASSERT(sid == IDS_DESIGNER && ptd);

	if (ptd->b_size)
	{
		_designer_noti_object_sized(ptd, pxp->x, pxp->y);
		return 1;
	}

	if (ptd->b_drag)
	{
		widget_set_cursor(widget, CURSOR_ARROW);

		_designer_noti_object_drop(ptd, pxp->x, pxp->y);
		return 1;
	}

	if (ptd->b_group)
	{
		_designer_noti_object_grouped(ptd, pxp->x, pxp->y);
		return 1;
	}

	bCtl = widget_key_state(ptd->widget, KS_WITH_CONTROL);
	if(bCtl) return 1;

	obj = NULL;
	hint = _designer_calc_hint(ptd, pxp, &obj);
	bRe = (obj == obf)? 1 : 0;

	if(obf && !bRe)
	{
		if(!_designer_noti_object_changing(ptd))
			bRe = 1;
	}

	if (obj && !bRe)
	{
		_designer_noti_object_changed(ptd, obj);
	}

	return 1;
}

int designer_sub_mousemove(widget_t widget, dword_t mk, const xpoint_t* pxp, uid_t sid, vword_t delta)
{
	designer_context* ptd = (designer_context*)delta;
	designer_interface* pdi = &(ptd->desg);
	int hint;
	xrect_t xr;
	void *obj, *obf = ptd->cur_obj;

	XDK_ASSERT(sid == IDS_DESIGNER && ptd);

	if (ptd->b_size || ptd->b_drag || ptd->b_group)
	{
		ptd->cur_x = pxp->x;
		ptd->cur_y = pxp->y;

		widget_erase(widget, NULL);
		return 1;
	}

	obj = NULL;
	hint = _designer_calc_hint(ptd, pxp, &obj);

	if (hint == HINT_HORZ_SPLIT && obj == obf && !(mk & KS_WITH_CONTROL))
	{
		widget_set_cursor(widget, CURSOR_SIZENS);

		if (mk & MS_WITH_LBUTTON)
		{
			_designer_noti_object_sizing(ptd, hint, pxp->x, pxp->y);
			return 1;
		}
	}
	else if (hint == HINT_VERT_SPLIT && obj == obf && !(mk & KS_WITH_CONTROL))
	{
		widget_set_cursor(widget, CURSOR_SIZEWE);

		if (mk & MS_WITH_LBUTTON)
		{
			_designer_noti_object_sizing(ptd, hint, pxp->x, pxp->y);
			return 1;
		}
	}
	else if (hint == HINT_CROSS_SPLIT && obj == obf && !(mk & KS_WITH_CONTROL))
	{
		widget_set_cursor(widget, CURSOR_SIZEALL);

		if (mk & MS_WITH_LBUTTON)
		{
			_designer_noti_object_sizing(ptd, hint, pxp->x, pxp->y);
			return 1;
		}
	}
	else if (hint == HINT_OBJECT && obj == obf && !(mk & KS_WITH_CONTROL))
	{
		if (mk & MS_WITH_LBUTTON)
		{
			widget_set_cursor(widget, CURSOR_HAND);

			_designer_noti_object_drag(ptd, pxp->x, pxp->y);
			return 1;
		}
	}
	else if (hint == HINT_NONE)
	{
		if (mk & MS_WITH_LBUTTON)
		{
			_designer_noti_object_grouping(ptd, pxp->x, pxp->y);
			return 1;
		}
	}

	return 1;
}

int designer_sub_lbutton_dbclick(widget_t widget, const xpoint_t* pxp, uid_t sid, vword_t delta)
{
	designer_context* ptd = (designer_context*)delta;
	designer_interface* pdi = &(ptd->desg);
	int hint;
	void *obj;

	XDK_ASSERT(sid == IDS_DESIGNER && ptd);

	obj = NULL;
	hint = _designer_calc_hint(ptd, pxp, &obj);

	if(hint == HINT_NONE)
	{	
		(*pdi->pf_all_obj_selected)(widget, bool_true);
		widget_erase(widget, NULL);

		return 1;
	}

	return 1;
}

int designer_sub_keydown(widget_t widget, dword_t ks, int nKey, uid_t sid, vword_t delta)
{
	designer_context* ptd = (designer_context*)delta;
	designer_interface* pdi = &(ptd->desg);
	void *obj, *org, *obf = ptd->cur_obj;
	xrect_t xr;
	int n = 0, m = 1;
	bool_t b_ctl, b_sft;

	XDK_ASSERT(sid == IDS_DESIGNER && ptd);

	b_ctl = ((ks & KS_WITH_CONTROL) || (ks & KS_WITH_CMD))? 1 : 0;
	b_sft = (ks & KS_WITH_SHIFT)? 1 : 0;

	if (nKey == KEY_UP || nKey == KEY_DOWN || nKey == KEY_LEFT || nKey == KEY_RIGHT)
	{
		_designer_done(ptd);

		obj = (*pdi->pf_get_next_obj)(widget, LINK_FIRST);
		while (obj)
		{
			if(obj != obf && !(*pdi->pf_get_obj_selected)(ptd->widget, obj))
			{
				obj = (*pdi->pf_get_next_obj)(widget, obj);
				continue;
			}

			if(obj == obf)
			{
				if (b_sft)
					_designer_noti_owner(ptd, NC_OBJECT_SIZING, obj, 0);
				else
					_designer_noti_owner(ptd, NC_OBJECT_DRAG, obj, 0);
			}

			(*pdi->pf_get_obj_rect)(widget, obj, &xr);

			switch (nKey)
			{
			case KEY_DOWN:
				if (b_sft)
					xr.h += m;
				else
					xr.y += m;
				break;
			case KEY_UP:
				if (b_sft)
					xr.h = (xr.h - m < 0) ? xr.h : xr.h - m;
				else
					xr.y = (xr.y - m < 0) ? xr.y : xr.y - m;
				break;
			case KEY_LEFT:
				if (b_sft)
					xr.w = (xr.w - m < 0) ? xr.w : xr.w - m;
				else
					xr.x = (xr.x - m < 0) ? xr.x : xr.x - m;
				break;
			case KEY_RIGHT:
				if (b_sft)
					xr.w += m;
				else
					xr.x += m;
				break;
			}

			(*pdi->pf_set_obj_rect)(widget, obj, &xr);

			if(obj == obf)
			{
				if (b_sft)
					_designer_noti_owner(ptd, NC_OBJECT_SIZED, obj, 0);
				else
					_designer_noti_owner(ptd, NC_OBJECT_DROP, obj, 0);
			}

			n++;
			obj = (*pdi->pf_get_next_obj)(widget, obj);
		}

		if(n) widget_erase(widget, NULL);

		return 1;
	}else if(nKey == KEY_BACK || nKey == KEY_DELETE)
	{
		_designer_done(ptd);

		obj = (*pdi->pf_get_next_obj)(widget, LINK_FIRST);
		while (obj)
		{
			if(obj != obf && !(*pdi->pf_get_obj_selected)(ptd->widget, obj))
			{
				obj = (*pdi->pf_get_next_obj)(widget, obj);
				continue;
			}

			if(obj == obf)
			{
				_designer_noti_object_unselect(ptd, obj);
			}

			org = (*pdi->pf_get_next_obj)(widget, obj);

			if (!(*pdi->pf_del_obj)(widget, obj))
			{
				_designer_discard(ptd);
				return 1;
			}

			n++;
			obj = org;
		}

		if(n) widget_erase(widget, NULL);

		return 1;
	}else if(b_ctl && nKey == KEY_COPY)
	{
		_designer_copy(ptd);
	}else if(b_ctl && nKey == KEY_CUT)
	{
		_designer_cut(ptd);
	}else if(b_ctl && nKey == KEY_PASTE)
	{
		_designer_paste(ptd);
	}else if(b_ctl && nKey == KEY_UNDO)
	{
		_designer_undo(ptd);
	}

	return 1;
}

int designer_sub_paint(widget_t widget, visual_t dc, const xrect_t* pxr, uid_t sid, vword_t delta)
{
	designer_context* ptd = (designer_context*)delta;
	designer_interface* pdi = &(ptd->desg);
	xrect_t xr;
	visual_t rdc;
	canvas_t canv;
	
	drawing_interface ifc = { 0 };
	drawing_interface ifv = { 0 };

	const color_mod_t* pclrs;
	xcolor_t xc = { 0 };
	xpen_t xp = {0};

	void *obj, *obf = ptd->cur_obj;

	XDK_ASSERT(sid == IDS_DESIGNER && ptd);

	pclrs = widget_get_color_mode_ptr(widget);

	default_xpen(&xp);
	format_xcolor(&(pclrs->clr_frg), xp.color);

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);
	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	widget_hand_paint(widget, rdc, NULL);

	get_canvas_interface(canv, &ifc);
	widget_get_canv_rect(widget, (canvbox_t*)&(ifc.rect));
	ifc.pclrs = pclrs;

	(*pdi->pf_render_doc)(widget, &ifc);

	get_visual_interface(rdc, &ifv);

	if (widget_can_paging(widget))
	{
		xmem_copy((void*)&xc, (void*)&(pclrs->clr_frg), sizeof(xcolor_t));
		lighten_xcolor(&xc, DEF_SOFT_DARKEN);

		draw_ruler(&ifc, &xc, (const xrect_t*)&(ifc.rect));
	}

	//draw focus
	if (ptd->b_drag)
	{
		xscpy(xp.style, GDI_ATTR_STROKE_STYLE_DASH);

		(*pdi->pf_get_obj_rect)(widget, obf, &xr);

		xr.x += (ptd->cur_x - ptd->org_x);
		xr.y += (ptd->cur_y - ptd->org_y);

		(*ifv.pf_draw_rect)(ifv.ctx, &xp, NULL, &xr);
	}
	else if (ptd->b_size)
	{
		xscpy(xp.style, GDI_ATTR_STROKE_STYLE_DASH);

		(*pdi->pf_get_obj_rect)(widget, obf, &xr);

		if (ptd->org_hint == HINT_VERT_SPLIT)
		{
			xr.w = (ptd->cur_x - xr.x);
		}
		else if (ptd->org_hint == HINT_HORZ_SPLIT)
		{
			xr.h = (ptd->cur_y - xr.y);
		}
		else
		{
			xr.w = (ptd->cur_x - xr.x);
			xr.h = (ptd->cur_y - xr.y);
		}

		(*ifv.pf_draw_rect)(ifv.ctx, &xp, NULL, &xr);
	}
	else if (ptd->b_group)
	{
		xscpy(xp.style, GDI_ATTR_STROKE_STYLE_DASH);

		xr.x = ptd->org_x;
		xr.w = ptd->cur_x - ptd->org_x;
		xr.y = ptd->org_y;
		xr.h = ptd->cur_y - ptd->org_y;

		(*ifv.pf_draw_rect)(ifv.ctx, &xp, NULL, &xr);
	}
	else if (obf)
	{
		(*pdi->pf_get_obj_rect)(widget, obf, &xr);

		xmem_copy((void *)&xc, (void *)&(pclrs->clr_frg), sizeof(xcolor_t));

		draw_sizing_raw(&ifv, &xc, &xr, ALPHA_SOLID, SIZING_BOTTOMCENTER | SIZING_RIGHTCENTER | SIZING_BOTTOMRIGHT);
	}

	// draw selected
	parse_xcolor(&xc, DEF_ALPHA_COLOR);

	obj = (*pdi->pf_get_next_obj)(widget, LINK_FIRST);
	while (obj)
	{
		if ((*pdi->pf_get_obj_selected)(widget, obj))
		{
			(*pdi->pf_get_obj_rect)(widget, obj, &xr);
			pt_expand_rect(&xr, DEF_INNER_FEED, DEF_INNER_FEED);

			(*ifv.pf_alphablend_rect)(ifv.ctx, &xc, &xr, ALPHA_TRANS);
		}
		obj = (*pdi->pf_get_next_obj)(widget, obj);
	}

	end_canvas_paint(canv, dc, pxr);

	return 1;
}

/*******************************************************************************/

void hand_designer_create(widget_t widget, const designer_interface* pdi)
{
	if_subproc_t sub = {0};
	designer_context* ptd;

	SUBPROC_BEGIN_DISPATH(&sub)

	SUBPROC_ON_DESIGNER_IMPLEMENT

	SUBPROC_END_DISPATH

	if(widget_set_subproc(widget, IDS_DESIGNER, &sub))
	{
		ptd = (designer_context*)xmem_alloc(sizeof(designer_context));
		ptd->widget = widget;
		ptd->max_undo = MAX_UNDO;
		xmem_copy((void*)&(ptd->desg), (void*)pdi, sizeof(designer_interface));
		widget_set_subproc_delta(widget, IDS_DESIGNER, (vword_t)ptd);
	}
}

void hand_designer_destroy(widget_t widget)
{
	designer_context* ptd;

	ptd = (designer_context*)widget_get_subproc_delta(widget, IDS_DESIGNER);
	if(ptd)
	{
		xmem_free(ptd);
	}
}

bool_t designer_get_dirty(widget_t widget)
{
	designer_context* ptd;

	ptd = (designer_context*)widget_get_subproc_delta(widget, IDS_DESIGNER);

	XDK_ASSERT(ptd != NULL);

	return (ptd->ptu) ? bool_true : bool_false;
}

void designer_set_dirty(widget_t widget, bool_t bDirty)
{
	designer_context* ptd;

	ptd = (designer_context*)widget_get_subproc_delta(widget, IDS_DESIGNER);

	XDK_ASSERT(ptd != NULL);

	if (bDirty)
		_designer_done(ptd);
	else
		_designer_clean(ptd);
}

void* designer_get_focused(widget_t widget)
{
	designer_context* ptd;

	ptd = (designer_context*)widget_get_subproc_delta(widget, IDS_DESIGNER);

	XDK_ASSERT(ptd != NULL);

	return ptd->cur_obj;
}