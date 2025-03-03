﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc tag text control document

	@module	tagctrl.c | implement file

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

#include "../xdcimp.h"
#include "../xdcinit.h"

typedef struct _tagctrl_delta_t{
	textor_context textor;
	link_t_ptr phrase;
	
	res_win_t hsc;
	res_win_t vsc;

	bool_t b_lock;

	int chs;
	tchar_t pch[CHS_LEN + 1];
}tagctrl_delta_t;

#define GETTAGCTRLDELTA(ph) 	(tagctrl_delta_t*)widget_get_user_delta(ph)
#define SETTAGCTRLDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/********************************************************************************************/
static int _tagctrl_get_text(void* data, tchar_t* buf, int max)
{
	link_t_ptr tag = (link_t_ptr)data;

	return format_tag_doc(tag, buf, max);
}

static void _tagctrl_set_text(void* data, const tchar_t* buf, int len)
{
	link_t_ptr tag = (link_t_ptr)data;

	parse_tag_doc(tag, buf, len);
}

static bool_t _tagctrl_get_paging(res_win_t widget, xsize_t* pse)
{
	xrect_t xr;

	widget_get_client_rect(widget, &xr);

	pse->w = xr.w;
	pse->h = xr.h;

	return 0;
}
/********************************************************************************************/
int noti_tagctrl_owner(res_win_t widget, unsigned int code, link_t_ptr tag, link_t_ptr nlk, void* data)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);
	NOTICE_TAG nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;
	nf.data = data;
	nf.ret = 0;

	nf.tag = tag;
	nf.words = nlk;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);

	return nf.ret;
}

void noti_tagctrl_reset_scroll(res_win_t widget, bool_t bUpdate)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (widget_is_valid(ptd->vsc))
	{
		if (bUpdate)
			widget_update(ptd->vsc);
		else
			widget_close(ptd->vsc, 0);
	}

	if (widget_is_valid(ptd->hsc))
	{
		if (bUpdate)
			widget_update(ptd->hsc);
		else
			widget_close(ptd->hsc, 0);
	}
}
/********************************************************************************************/
int hand_tagctrl_create(res_win_t widget, void* data)
{
	tagctrl_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (tagctrl_delta_t*)xmem_alloc(sizeof(tagctrl_delta_t));
	xmem_zero((void*)ptd, sizeof(tagctrl_delta_t));

	SETTAGCTRLDELTA(widget, ptd);

	ptd->textor.widget = widget;
	ptd->textor.cdc = widget_client_ctx(widget);
	ptd->textor.data = NULL;
	ptd->textor.pf_scan_text = (PF_SCAN_TEXT)scan_tag_text;
	ptd->textor.pf_get_text = _tagctrl_get_text;
	ptd->textor.pf_set_text = _tagctrl_set_text;
	ptd->textor.pf_get_paging = _tagctrl_get_paging;
	ptd->textor.max_undo = 1024;

	ptd->b_lock = 1;

	return 0;
}

void hand_tagctrl_destroy(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (widget_is_valid(ptd->hsc))
		widget_destroy(ptd->hsc);

	if (widget_is_valid(ptd->vsc))
		widget_destroy(ptd->vsc);

	hand_textor_clean(&ptd->textor);

	widget_release_ctx(widget, ptd->textor.cdc);

	xmem_free(ptd);

	SETTAGCTRLDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_tagctrl_copy(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_copy(&ptd->textor);
}

void hand_tagctrl_cut(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (ptd->b_lock)
		return;

	if (!ptd->textor.data)
		return;

	if (_TEXTOR_PRESS_ACCEPT != hand_textor_cut(&ptd->textor))
		return;

	widget_post_command(widget, COMMAND_UPDATE, IDC_SELF, (vword_t)NULL);

	if (ptd->phrase != (link_t_ptr)ptd->textor.object)
	{
		ptd->phrase = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
	}
}

void hand_tagctrl_paste(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (ptd->b_lock)
		return;

	if (!ptd->textor.data)
		return;

	if (_TEXTOR_PRESS_ACCEPT != hand_textor_paste(&ptd->textor))
		return;

	widget_post_command(widget, COMMAND_UPDATE, IDC_SELF, (vword_t)NULL);

	if (ptd->phrase != (link_t_ptr)ptd->textor.object)
	{
		ptd->phrase = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
	}
}

void hand_tagctrl_undo(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (ptd->b_lock)
		return;

	if (!ptd->textor.data)
		return;

	if (_TEXTOR_PRESS_ACCEPT != hand_textor_undo(&ptd->textor))
		return;

	widget_post_command(widget, COMMAND_UPDATE, IDC_SELF, (vword_t)NULL);

	if (ptd->phrase != (link_t_ptr)ptd->textor.object)
	{
		ptd->phrase = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
	}
}

void hand_tagctrl_set_focus(res_win_t widget, res_win_t wt)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_set_focus(&ptd->textor, wt);
}

void hand_tagctrl_kill_focus(res_win_t widget, res_win_t wt)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_kill_focus(&ptd->textor, wt);

	if (widget_is_editor(widget))
	{
		if (tagctrl_get_dirty(widget))
			widget_send_command(widget_get_owner(widget), COMMAND_COMMIT, IDC_CHILD, (vword_t)NULL);
		else
			widget_send_command(widget_get_owner(widget), COMMAND_ROLLBACK, IDC_CHILD, (vword_t)NULL);
	}
}

void hand_tagctrl_keydown(res_win_t widget, dword_t ks, int key)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

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

			if (ptd->phrase != (link_t_ptr)ptd->textor.object)
			{
				ptd->phrase = (link_t_ptr)ptd->textor.object;
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

			if (ptd->phrase != (link_t_ptr)ptd->textor.object)
			{
				ptd->phrase = (link_t_ptr)ptd->textor.object;
				widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
			}
		}
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

		if (ptd->phrase != (link_t_ptr)ptd->textor.object)
		{
			ptd->phrase = (link_t_ptr)ptd->textor.object;
			widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
		}
		break;
	case KEY_RIGHT:
		hand_textor_right(&ptd->textor);

		if (ptd->phrase != (link_t_ptr)ptd->textor.object)
		{
			ptd->phrase = (link_t_ptr)ptd->textor.object;
			widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
		}
		break;
	case KEY_UP:
		hand_textor_up(&ptd->textor);

		if (ptd->phrase != (link_t_ptr)ptd->textor.object)
		{
			ptd->phrase = (link_t_ptr)ptd->textor.object;
			widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
		}
		break;
	case KEY_DOWN:
		hand_textor_down(&ptd->textor);

		if (ptd->phrase != (link_t_ptr)ptd->textor.object)
		{
			ptd->phrase = (link_t_ptr)ptd->textor.object;
			widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
		}
		break;
	case _T('c'):
	case _T('C'):
		if (widget_key_state(widget, KEY_CONTROL))
		{
			hand_tagctrl_copy(widget);
		}
		break;
	case _T('x'):
	case _T('X'):
		if (widget_key_state(widget, KEY_CONTROL))
		{
			hand_tagctrl_cut(widget);
		}
		break;
	case _T('v'):
	case _T('V'):
		if (widget_key_state(widget, KEY_CONTROL))
		{
			hand_tagctrl_paste(widget);
		}
		break;
	case _T('z'):
	case _T('Z'):
		if (widget_key_state(widget, KEY_CONTROL))
		{
			hand_tagctrl_undo(widget);
		}
		break;
	}
}

void hand_tagctrl_char(res_win_t widget, tchar_t ch)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

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

	if (is_tag_text_reserve(ch))
		return;
	
	if (!ptd->chs)
	{
		ptd->chs = xschs(&ch);

		xsncpy(ptd->pch, &ch, 1);
		ptd->chs--;

		if (ptd->chs)
			return;
	}
	else
	{
		xsncat(ptd->pch, &ch, 1);
		ptd->chs--;

		if (ptd->chs)
			return;
	}

	if (_TEXTOR_PRESS_ACCEPT == hand_textor_word(&ptd->textor, ptd->pch))
	{
		widget_post_command(widget, COMMAND_UPDATE, IDC_SELF, (vword_t)NULL);
	}
}

void hand_tagctrl_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);
	
	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_lbutton_down(&ptd->textor, pxp);
}

void hand_tagctrl_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_lbutton_up(&ptd->textor, pxp);

	if (ptd->phrase != (link_t_ptr)ptd->textor.object)
	{
		ptd->phrase = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
	}
}

void hand_tagctrl_lbutton_dbclick(res_win_t widget, const xpoint_t* pxp)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_selectobj(&ptd->textor);
}

void hand_tagctrl_rbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

}

void hand_tagctrl_rbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);
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

void hand_tagctrl_mousemove(res_win_t widget, dword_t mk, const xpoint_t* ppt)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);
	
	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_mousemove(&ptd->textor, mk, ppt);
}

void hand_tagctrl_size(res_win_t widget, int code, const xsize_t* prs)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	noti_tagctrl_reset_scroll(widget, 0);

	hand_textor_size(&ptd->textor, code, prs);
}

void hand_tagctrl_scroll(res_win_t widget, bool_t bHorz, int nLine)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_scroll(&ptd->textor, bHorz, nLine);
}

void hand_tagctrl_wheel(res_win_t widget, bool_t bHorz, int nDelta)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);
	scroll_t scr = { 0 };
	int nLine;
	res_win_t win;

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
				widget_update(ptd->vsc);
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
				widget_update(ptd->hsc);
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

void hand_tagctrl_self_command(res_win_t widget, int code, vword_t data)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	if (code == COMMAND_UPDATE)
	{
		noti_tagctrl_owner(widget, NC_TAGJOINTUPDATE, (link_t_ptr)ptd->textor.data, ptd->phrase, NULL);
	}
	else if (code == COMMAND_CHANGE)
	{
		noti_tagctrl_owner(widget, NC_TAGJOINTCHANGED, (link_t_ptr)ptd->textor.data, ptd->phrase, NULL);
	}
}

void hand_tagctrl_menu_command(res_win_t widget, int code, int cid, vword_t data)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);
	
	if (cid == IDC_EDITMENU)
	{
		switch (code)
		{
		case COMMAND_COPY:
			hand_tagctrl_copy(widget);
			break;
		case COMMAND_CUT:
			hand_tagctrl_cut(widget);
			break;
		case COMMAND_PASTE:
			hand_tagctrl_paste(widget);
			break;
		case COMMAND_UNDO:
			hand_tagctrl_undo(widget);
			break;
		}
		
		widget_close((res_win_t)data, 1);
	}
}


void hand_tagctrl_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	if (!ptd)
		return;

	if (!ptd->textor.data)
		return;

	hand_textor_paint(&ptd->textor, dc, pxr);
}

/************************************************************************************************/
res_win_t tagctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, res_win_t wparent)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_tagctrl_create)
		EVENT_ON_DESTROY(hand_tagctrl_destroy)

		EVENT_ON_PAINT(hand_tagctrl_paint)

		EVENT_ON_SIZE(hand_tagctrl_size)

		EVENT_ON_SCROLL(hand_tagctrl_scroll)
		EVENT_ON_WHEEL(hand_tagctrl_wheel)

		EVENT_ON_KEYDOWN(hand_tagctrl_keydown)
		EVENT_ON_CHAR(hand_tagctrl_char)

		EVENT_ON_MOUSE_MOVE(hand_tagctrl_mousemove)
		EVENT_ON_LBUTTON_DBCLICK(hand_tagctrl_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_tagctrl_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_tagctrl_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_tagctrl_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_tagctrl_rbutton_up)

		EVENT_ON_SET_FOCUS(hand_tagctrl_set_focus)
		EVENT_ON_KILL_FOCUS(hand_tagctrl_kill_focus)
		EVENT_ON_SELF_COMMAND(hand_tagctrl_self_command)
		EVENT_ON_MENU_COMMAND(hand_tagctrl_menu_command)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void tagctrl_redraw(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_redraw(&ptd->textor);

	if (ptd->phrase != (link_t_ptr)ptd->textor.object)
	{
		ptd->phrase = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
	}
}

void tagctrl_select_all(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_selectall(&ptd->textor);

	if (ptd->phrase != (link_t_ptr)ptd->textor.object)
	{
		ptd->phrase = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
	}
}

void tagctrl_select_cur(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_selectcur(&ptd->textor);

	if (ptd->phrase != (link_t_ptr)ptd->textor.object)
	{
		ptd->phrase = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
	}
}

int tagctrl_get_selected_text(res_win_t widget, tchar_t* buf, int max)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return 0;

	return hand_textor_selected_text(&ptd->textor, buf, max);
}

void tagctrl_attach(res_win_t widget, link_t_ptr data)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(data && is_tag_doc(data));

	ptd->textor.data = (void*)data;
	ptd->textor.object = NULL;
	ptd->textor.page = 1;
	
	ptd->phrase = NULL;

	tagctrl_redraw(widget);

	widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
}

link_t_ptr tagctrl_fetch(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return (link_t_ptr)ptd->textor.data;
}

link_t_ptr tagctrl_detach(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);
	link_t_ptr ptr;

	XDK_ASSERT(ptd != NULL);

	ptr = (link_t_ptr)ptd->textor.data;
	ptd->textor.data = NULL;
	ptd->textor.object = NULL;
	ptd->textor.page = 0;

	ptd->phrase = NULL;

	return ptr;
}

link_t_ptr tagctrl_get_focus_phrase(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);
	link_t_ptr nlk = NULL;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return NULL;

	return ptd->phrase;
}

void tagctrl_set_focus_phrase(res_win_t widget, link_t_ptr nlk)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_findobj(&ptd->textor, nlk);

	if (ptd->phrase != (link_t_ptr)ptd->textor.object)
	{
		ptd->phrase = (link_t_ptr)ptd->textor.object;
		widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
	}
}

void tagctrl_delete_phrase(res_win_t widget, link_t_ptr nlk)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_done(&ptd->textor);

	delete_tag_node(nlk);

	tagctrl_redraw(widget);
}

void tagctrl_set_phrase_text(res_win_t widget, link_t_ptr nlk, const tchar_t* token, int len)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	if (ptd->b_lock)
		return;

	hand_textor_done(&ptd->textor);

	set_tag_phrase_text(nlk, token, len);

	tagctrl_redraw(widget);
}

void tagctrl_get_phrase_rect(res_win_t widget, link_t_ptr nlk, xrect_t* pxr)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	textor_object_rect(&ptd->textor, nlk, pxr);
}

bool_t tagctrl_get_dirty(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return 0;

	return (ptd->textor.ptu != NULL) ? 1 : 0;
}

void tagctrl_set_dirty(res_win_t widget, bool_t bDirty)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	if (bDirty)
		hand_textor_done(&ptd->textor);
	else
		hand_textor_clean(&ptd->textor);
}

void tagctrl_move_to_page(res_win_t widget, int page)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_move_to_page(&ptd->textor, page);
}

void tagctrl_move_first_page(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_move_first_page(&ptd->textor);
}

void tagctrl_move_last_page(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_move_last_page(&ptd->textor);
}

void tagctrl_move_next_page(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_move_next_page(&ptd->textor);
}

void tagctrl_move_prev_page(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return;

	hand_textor_move_prev_page(&ptd->textor);
}

int tagctrl_get_cur_page(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return 0;

	return textor_cur_page(&ptd->textor);
}

int tagctrl_get_max_page(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->textor.data)
		return 0;

	return textor_max_page(&ptd->textor);
}

bool_t tagctrl_get_lock(res_win_t widget)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->b_lock;
}

void tagctrl_set_lock(res_win_t widget, bool_t bLock)
{
	tagctrl_delta_t* ptd = GETTAGCTRLDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->b_lock = bLock;
}
