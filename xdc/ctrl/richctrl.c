/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc rich control document

	@module	richctrl.c | implement file

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

#include "ctrl.h"

#include "../xdcobj.h"


typedef struct _richctrl_delta_t{
	textor_context textor;
	link_t_ptr anch;

	widget_t hsc;
	widget_t vsc;

	bool_t b_lock;

	int chs;
	tchar_t pch[CHS_LEN + 1];

	xfont_t xf;
	xface_t xa;
}richctrl_delta_t;

#define GETRICHCTRLDELTA(ph) 	(richctrl_delta_t*)widget_get_user_delta(ph)
#define SETRICHCTRLDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

static int _richctrl_get_text(void* data, tchar_t* buf, int max)
{
	link_t_ptr text = (link_t_ptr)data;

	return format_rich_doc(text, buf, max);
}

static void _richctrl_set_text(void* data, const tchar_t* buf, int len)
{
	link_t_ptr text = (link_t_ptr)data;

	parse_rich_doc(text, buf, len);
}

static bool_t _richctrl_get_paging(widget_t widget, xsize_t* pse)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd && ptd->textor.data);

	if (widget_get_style(widget) & WD_STYLE_PAGING)
	{
		pse->fw = get_rich_width((link_t_ptr)(ptd->textor.data));
		pse->fh = get_rich_height((link_t_ptr)(ptd->textor.data));

		widget_size_to_pt(widget, pse);

		return 1;
	}
	else
	{
		widget_get_client_rect(widget, &xr);

		pse->w = xr.w;
		pse->h = xr.h;

		return 0;
	}
}
/********************************************************************************************/
int noti_richctrl_owner(widget_t widget, unsigned int code, link_t_ptr ptr, link_t_ptr nlk, void* data)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);
	NOTICE_RICH nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;
	nf.data = data;
	nf.ret = 0;

	nf.rich = ptr;
	nf.anch = nlk;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);

	return nf.ret;
}

void noti_richctrl_reset_scroll(widget_t widget, bool_t bUpdate)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (widget_is_valid(ptd->vsc))
	{
		if (bUpdate)
			widget_erase(ptd->vsc, NULL);
		else
			widget_close(ptd->vsc, 0);
	}

	if (widget_is_valid(ptd->hsc))
	{
		if (bUpdate)
			widget_erase(ptd->hsc, NULL);
		else
			widget_close(ptd->hsc, 0);
	}
}
/********************************************************************************************/
int hand_richctrl_create(widget_t widget, void* data)
{
	richctrl_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (richctrl_delta_t*)xmem_alloc(sizeof(richctrl_delta_t));
	xmem_zero((void*)ptd, sizeof(richctrl_delta_t));

	SETRICHCTRLDELTA(widget, ptd);

	ptd->textor.widget = widget;
	ptd->textor.cdc = widget_client_context(widget);
	ptd->textor.data = NULL;
	ptd->textor.pf_scan_text = (PF_SCAN_TEXT)scan_rich_text;
	ptd->textor.pf_get_text = _richctrl_get_text;
	ptd->textor.pf_set_text = _richctrl_set_text;
	ptd->textor.pf_get_paging = _richctrl_get_paging;
	ptd->textor.max_undo = 1024;

	ptd->textor.pxf = &ptd->xf;
	ptd->textor.pxa = &ptd->xa;

	ptd->b_lock = 1;

	return 0;
}

void hand_richctrl_destroy(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (widget_is_valid(ptd->hsc))
		widget_destroy(ptd->hsc);

	if (widget_is_valid(ptd->vsc))
		widget_destroy(ptd->vsc);

	hand_textor_clean(&ptd->textor);

	widget_release_context(widget, ptd->textor.cdc);

	xmem_free(ptd);

	SETRICHCTRLDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_richctrl_copy(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_copy(&ptd->textor);
}

void hand_richctrl_cut(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (ptd->b_lock)
		return;

	if (!ptd->textor.data)
		return;

	if (hand_textor_cut(&ptd->textor) != _TEXTOR_PRESS_ACCEPT)
		return;

	widget_post_command(widget, COMMAND_UPDATE, IDC_SELF, (vword_t)NULL);

	if (ptd->anch != (link_t_ptr)ptd->textor.object)
	{
		ptd->anch = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
	}
}

void hand_richctrl_paste(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (ptd->b_lock)
		return;

	if (!ptd->textor.data)
		return;

	if (hand_textor_paste(&ptd->textor) != _TEXTOR_PRESS_ACCEPT)
		return;

	widget_post_command(widget, COMMAND_UPDATE, IDC_SELF, (vword_t)NULL);

	if (ptd->anch != (link_t_ptr)ptd->textor.object)
	{
		ptd->anch = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
	}
}

void hand_richctrl_undo(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (ptd->b_lock)
		return;

	if (!ptd->textor.data)
		return;

	if (hand_textor_undo(&ptd->textor) != _TEXTOR_PRESS_ACCEPT)
		return;

	widget_post_command(widget, COMMAND_UPDATE, IDC_SELF, (vword_t)NULL);

	if (ptd->anch != (link_t_ptr)ptd->textor.object)
	{
		ptd->anch = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
	}
}

void hand_richctrl_set_focus(widget_t widget, widget_t wt)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_set_focus(&ptd->textor, wt);
}

void hand_richctrl_kill_focus(widget_t widget, widget_t wt)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_kill_focus(&ptd->textor, wt);

	if (widget_is_editor(widget))
	{
		if (richctrl_get_dirty(widget))
			widget_send_command(widget_get_owner(widget), COMMAND_COMMIT, IDC_CHILD, (vword_t)NULL);
		else
			widget_send_command(widget_get_owner(widget), COMMAND_ROLLBACK, IDC_CHILD, (vword_t)NULL);
	}
}

void hand_richctrl_keydown(widget_t widget, dword_t ks, int key)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	switch (key)
	{
	case KEY_BACK:
		if (ptd->b_lock)
			break;

		if (_TEXTOR_PRESS_ACCEPT == hand_textor_back(&ptd->textor))
		{
			widget_post_command(widget, COMMAND_UPDATE, IDC_SELF, (vword_t)NULL);

			if (ptd->anch != (link_t_ptr)ptd->textor.object)
			{
				ptd->anch = (link_t_ptr)ptd->textor.object;
				widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
			}
		}
		break;
	case KEY_DELETE:
		if (ptd->b_lock)
			break;

		if (_TEXTOR_PRESS_ACCEPT == hand_textor_delete(&ptd->textor))
		{
			widget_post_command(widget, COMMAND_UPDATE, IDC_SELF, (vword_t)NULL);

			if (ptd->anch != (link_t_ptr)ptd->textor.object)
			{
				ptd->anch = (link_t_ptr)ptd->textor.object;
				widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
			}
		}
		break;
	case KEY_TAB:
		break;
	case KEY_ENTER:
		break;
	case KEY_ESC:
		if (ptd->b_lock)
			break;

		hand_textor_escape(&ptd->textor);
		break;
	case KEY_LEFT:
		hand_textor_left(&ptd->textor);

		if (ptd->anch != (link_t_ptr)ptd->textor.object)
		{
			ptd->anch = (link_t_ptr)ptd->textor.object;
			widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)ptd->anch);
		}
		break;
	case KEY_RIGHT:
		hand_textor_right(&ptd->textor);

		if (ptd->anch != (link_t_ptr)ptd->textor.object)
		{
			ptd->anch = (link_t_ptr)ptd->textor.object;
			widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)ptd->anch);
		}
		break;
	case KEY_UP:
		hand_textor_up(&ptd->textor);

		if (ptd->anch != (link_t_ptr)ptd->textor.object)
		{
			ptd->anch = (link_t_ptr)ptd->textor.object;
			widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)ptd->anch);
		}
		break;
	case KEY_DOWN:
		hand_textor_down(&ptd->textor);

		if (ptd->anch != (link_t_ptr)ptd->textor.object)
		{
			ptd->anch = (link_t_ptr)ptd->textor.object;
			widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)ptd->anch);
		}
		break;
	case KEY_PAGEDOWN:
		hand_textor_move_next_page(&ptd->textor);
		break;
	case KEY_PAGEUP:
		hand_textor_move_prev_page(&ptd->textor);
		break;
	case KEY_HOME:
		hand_textor_move_first_page(&ptd->textor);
		break;
	case KEY_END:
		hand_textor_move_last_page(&ptd->textor);
		break;
	case _T('c'):
	case _T('C'):
		if (widget_key_state(widget, KS_WITH_CONTROL))
		{
			hand_richctrl_copy(widget);
		}
		break;
	case _T('x'):
	case _T('X'):
		if (widget_key_state(widget, KS_WITH_CONTROL))
		{
			hand_richctrl_cut(widget);
		}
		break;
	case _T('v'):
	case _T('V'):
		if (widget_key_state(widget, KS_WITH_CONTROL))
		{
			hand_richctrl_paste(widget);
		}
		break;
	case _T('z'):
	case _T('Z'):
		if (widget_key_state(widget, KS_WITH_CONTROL))
		{
			hand_richctrl_undo(widget);
		}
		break;
	}
}

void hand_richctrl_wchar(widget_t widget, wchar_t ch)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (ptd->b_lock)
		return;

	if (!ptd->textor.data)
		return;

	if (ch == KEY_BACK)
		return;

	if (ch != KEY_ENTER && ch != KEY_TAB && ch > 0 && ch < 32)
		return;

	if (is_rich_text_reserve(ch))
		return;

#if defined(_UNICODE) || defined(UNICODE)
	ptd->pch[0] = ch;
	ptd->chs = 1;
	ptd->pch[ptd->chs] = L'\0';
#else
	ucs_byte_to_mbs(ch, ptd->pch);
	ptd->chs = xschs(ptd->pch);
	ptd->pch[ptd->chs] = '\0';
#endif

	if (_TEXTOR_PRESS_ACCEPT == hand_textor_word(&ptd->textor, ptd->pch))
	{
		widget_post_command(widget, COMMAND_UPDATE, IDC_SELF, (vword_t)NULL);
	}
}

void hand_richctrl_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);
	
	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_lbutton_down(&ptd->textor, pxp);
}

void hand_richctrl_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_lbutton_up(&ptd->textor, pxp);

	if (ptd->anch != (link_t_ptr)ptd->textor.object)
	{
		ptd->anch = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)ptd->anch);
	}
}

void hand_richctrl_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	if (ptd->textor.object)
	{
		hand_textor_selectobj(&ptd->textor);
	}
}


void hand_richctrl_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;
}

void hand_richctrl_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);
	xpoint_t xp;

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	xp.x = pxp->x;
	xp.y = pxp->y;
	widget_client_to_screen(widget, &xp);

	textor_menu(widget, &xp, WS_LAYOUT_LEFTBOTTOM);
}

void hand_richctrl_mousemove(widget_t widget, dword_t mk, const xpoint_t* ppt)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_mousemove(&ptd->textor, mk, ppt);
}

void hand_richctrl_size(widget_t widget, int code, const xsize_t* prs)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	switch(code)
	{
	case WS_SIZE_FULLSCREEN:
		break;
	case WS_SIZE_MAXIMIZED:
		break;
	case WS_SIZE_MINIMIZED:
		break;
	case WS_SIZE_LAYOUT:
		break;
	}

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_size(&ptd->textor, code, prs);
}

void hand_richctrl_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_scroll(&ptd->textor, bHorz, nLine);
}

void hand_richctrl_wheel(widget_t widget, bool_t bHorz, int nDelta)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);
	scroll_t scr = { 0 };
	int nLine;
	widget_t win;

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	widget_get_scroll_info(widget, bHorz, &scr);

	if (bHorz)
		nLine = (nDelta > 0) ? scr.min : -scr.min;
	else
		nLine = (nDelta < 0) ? scr.min : -scr.min;

	if (hand_textor_scroll(&ptd->textor, bHorz, nLine))
	{
		if (!bHorz && !(widget_get_style(widget) & WD_STYLE_VSCROLL))
		{
			if (!widget_is_valid(ptd->vsc))
			{
				ptd->vsc = show_vertbox(widget);
			}
			else
			{
				widget_erase(ptd->vsc, NULL);
			}
		}

		if (bHorz && !(widget_get_style(widget) & WD_STYLE_HSCROLL))
		{
			if (!widget_is_valid(ptd->hsc))
			{
				ptd->hsc = show_horzbox(widget);
			}
			else
			{
				widget_erase(ptd->hsc, NULL);
			}
		}

		return;
	}

	win = widget_get_parent(widget);

	if (widget_is_valid(win))
	{
		widget_scroll(win, bHorz, nLine);
	}
}

void hand_richctrl_self_command(widget_t widget, int code, vword_t data)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	if (code == COMMAND_UPDATE)
	{
		noti_richctrl_owner(widget, NC_RICHANCHUPDATE, (link_t_ptr)ptd->textor.data, (link_t_ptr)ptd->anch, NULL);
	}
	else if (code == COMMAND_CHANGE)
	{
		noti_richctrl_owner(widget, NC_RICHANCHCHANGED, (link_t_ptr)ptd->textor.data, (link_t_ptr)ptd->anch, NULL);
	}
}

void hand_richctrl_menu_command(widget_t widget, int code, int cid, vword_t data)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (cid == IDC_EDITMENU)
	{
		switch (code)
		{
		case COMMAND_COPY:
			hand_richctrl_copy(widget);
			break;
		case COMMAND_CUT:
			hand_richctrl_cut(widget);
			break;
		case COMMAND_PASTE:
			hand_richctrl_paste(widget);
			break;
		case COMMAND_UNDO:
			hand_richctrl_undo(widget);
			break;
		}

		widget_close((widget_t)data, 1);
	}
}

void hand_richctrl_xfont(widget_t widget, const xfont_t* pxf)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	xmem_copy((void*)&ptd->xf, (void*)pxf, sizeof(xfont_t));
}

void hand_richctrl_xface(widget_t widget, const xface_t* pxa)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	xmem_copy((void*)&ptd->xa, (void*)pxa, sizeof(xface_t));
}

void hand_richctrl_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_paint(&ptd->textor, dc, pxr);
}

/************************************************************************************************/
widget_t richctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent)
{
	if_dispatch_t ev = { 0 };
	widget_t wt;
	xface_t xa;

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_richctrl_create)
		EVENT_ON_DESTROY(hand_richctrl_destroy)

		EVENT_ON_PAINT(hand_richctrl_paint)

		EVENT_ON_SIZE(hand_richctrl_size)
		EVENT_ON_SCROLL(hand_richctrl_scroll)
		EVENT_ON_WHEEL(hand_richctrl_wheel)

		EVENT_ON_KEYDOWN(hand_richctrl_keydown)
		EVENT_ON_WCHAR(hand_richctrl_wchar)

		EVENT_ON_MOUSE_MOVE(hand_richctrl_mousemove)
		EVENT_ON_LBUTTON_DBCLICK(hand_richctrl_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_richctrl_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_richctrl_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_richctrl_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_richctrl_rbutton_up)

		EVENT_ON_SELF_COMMAND(hand_richctrl_self_command)
		EVENT_ON_MENU_COMMAND(hand_richctrl_menu_command)

		EVENT_ON_SET_FOCUS(hand_richctrl_set_focus)
		EVENT_ON_KILL_FOCUS(hand_richctrl_kill_focus)

		EVENT_ON_XFONT(hand_richctrl_xfont)
		EVENT_ON_XFACE(hand_richctrl_xface)

		

	EVENT_END_DISPATH

	wt = widget_create(wname, wstyle, pxr, wparent, &ev);
	if (!wt) return (widget_t)0;

	default_xface(&xa);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);
	widget_noti_xface(wt, &xa);

	return wt;
}

void richctrl_attach(widget_t widget, link_t_ptr data)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(data && is_rich_doc(data));

	ptd->textor.data = (void*)data;
	ptd->textor.object = NULL;
	ptd->textor.page = 1;

	ptd->anch = NULL;
	richctrl_redraw(widget);

	widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
}

link_t_ptr richctrl_fetch(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return (link_t_ptr)ptd->textor.data;
}

link_t_ptr richctrl_detach(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);
	link_t_ptr ptr;

	XDK_ASSERT(ptd != NULL);

	ptr = (link_t_ptr)ptd->textor.data;
	ptd->textor.data = NULL;
	ptd->textor.object = NULL;
	ptd->textor.page = 0;

	ptd->anch = NULL;

	return ptr;
}

link_t_ptr richctrl_get_focus_anch(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);
	link_t_ptr nlk = NULL;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return NULL;

	return ptd->anch;
}

void richctrl_set_focus_anch(widget_t widget, link_t_ptr nlk)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_findobj(&ptd->textor, nlk);

	if (ptd->anch != (link_t_ptr)ptd->textor.object)
	{
		ptd->anch = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)ptd->anch);
	}
}

void richctrl_delete_anch(widget_t widget, link_t_ptr nlk)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	if (ptd->b_lock)
		return;

	hand_textor_done(&ptd->textor);

	delete_rich_anch(nlk);
	
	richctrl_redraw(widget);
}

link_t_ptr richctrl_insert_anch(widget_t widget, link_t_ptr pos)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);
	link_t_ptr nlk;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return NULL;

	if (ptd->b_lock)
		return NULL;

	hand_textor_done(&ptd->textor);

	if (pos == LINK_FIRST)
		pos = get_rich_next_anch((link_t_ptr)ptd->textor.data, LINK_FIRST);
	else if (pos == LINK_LAST)
		pos = get_rich_prev_anch((link_t_ptr)ptd->textor.data, LINK_LAST);
	else
	{
#ifdef _DEBUG
		XDK_ASSERT(is_rich_anch((link_t_ptr)ptd->textor.data, pos));
#endif
	}

	if (!pos) pos = LINK_FIRST;

	nlk = insert_rich_anch((link_t_ptr)ptd->textor.data, pos);

	richctrl_redraw(widget);

	return nlk;
}

void richctrl_set_anch_text(widget_t widget, link_t_ptr nlk, const tchar_t* token)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	if (ptd->b_lock)
		return;

	hand_textor_done(&ptd->textor);

	set_rich_anch_text(nlk, token, -1);

	richctrl_redraw(widget);
}

void richctrl_get_anch_rect(widget_t widget, link_t_ptr nlk, xrect_t* pxr)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	textor_object_rect(&ptd->textor, nlk, pxr);
}

void richctrl_redraw(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_redraw(&ptd->textor);

	if (ptd->anch != (link_t_ptr)ptd->textor.object)
	{
		ptd->anch = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)ptd->anch);
	}
}

void richctrl_select_cur(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_selectobj(&ptd->textor);

	if (ptd->anch != (link_t_ptr)ptd->textor.object)
	{
		ptd->anch = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)ptd->anch);
	}
}

void richctrl_select_all(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_selectall(&ptd->textor);

	if (ptd->anch != (link_t_ptr)ptd->textor.object)
	{
		ptd->anch = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)ptd->anch);
	}
}

int richctrl_get_selected_text(widget_t widget, tchar_t* buf, int max)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return 0;

	return hand_textor_selected_text(&ptd->textor, buf, max);
}

void richctrl_set_dirty(widget_t widget, bool_t bDirty)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	if (bDirty)
		hand_textor_done(&ptd->textor);
	else
		hand_textor_clean(&ptd->textor);
}

bool_t richctrl_get_dirty(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return 0;

	return (ptd->textor.ptu != NULL) ? 1 : 0;
}

void richctrl_move_to_page(widget_t widget, int page)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_move_to_page(&ptd->textor, page);
}

void richctrl_move_first_page(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_move_first_page(&ptd->textor);
}

void richctrl_move_last_page(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_move_last_page(&ptd->textor);
}

void richctrl_move_next_page(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_move_next_page(&ptd->textor);
}

void richctrl_move_prev_page(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_move_prev_page(&ptd->textor);
}

int richctrl_get_cur_page(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return 0;

	return textor_cur_page(&ptd->textor);
}

int richctrl_get_max_page(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return 0;

	return textor_max_page(&ptd->textor);
}

bool_t richctrl_get_lock(widget_t widget)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->b_lock;
}

void richctrl_set_lock(widget_t widget, bool_t bLock)
{
	richctrl_delta_t* ptd = GETRICHCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_lock = bLock;
}
