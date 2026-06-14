/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc widget document

	@module	_if_widget_win.c | widnows implement file

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

#include "_if_wince.h"

#pragma comment(lib,"comctl32.lib")
#pragma comment(lib, "Imm32.lib")
#pragma comment(lib, "Msimg32.lib")


#define GETXDUSTRUCT(hWnd)			(wince_widget_t*)GetProp(hWnd, XDUSTRUCT)
#define SETXDUSTRUCT(hWnd, ev)		SetProp(hWnd, XDUSTRUCT, (HANDLE)ev)

#define GETXDUDISPATCH(hWnd)		(if_dispatch_t*)GetProp(hWnd, XDUDISPATCH)
#define SETXDUDISPATCH(hWnd, ev)	SetProp(hWnd, XDUDISPATCH, (HANDLE)ev)

#define GETXDUSUBPROC(hWnd)			(if_subproc_t*)GetProp(hWnd, XDUSUBPROC)
#define SETXDUSUBPROC(hWnd, lp)		SetProp(hWnd, XDUSUBPROC, (HANDLE)lp)

#define GETXDUCOREDELTA(hWnd)		(vword_t)GetProp(hWnd, XDUCOREDELTA)
#define SETXDUCOREDELTA(hWnd, lp)	SetProp(hWnd, XDUCOREDELTA, (HANDLE)lp)

#define GETXDUUSERDELTA(hWnd)		(vword_t)GetProp(hWnd, XDUUSERDELTA)
#define SETXDUUSERDELTA(hWnd, lp)	SetProp(hWnd, XDUUSERDELTA, (HANDLE)lp)

LRESULT CALLBACK XdcWidgetProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

static DWORD _WindowStyle(dword_t wstyle)
{
	DWORD dw = 0;

	if (wstyle & WD_STYLE_OWNERNC)
	{
		if (wstyle & WD_STYLE_CHILD)
			dw |= (WS_CHILD | WS_CLIPSIBLINGS);
		else
			dw |= (WS_POPUP | WS_CLIPSIBLINGS | WS_CLIPCHILDREN);

		if (wstyle & WD_STYLE_TITLE)
			dw |= WS_CAPTION;
	}
	else
	{
		if (wstyle & WD_STYLE_CHILD)
			dw |= WS_CHILD;
		else
			dw |= WS_POPUP;

		if (wstyle & WD_STYLE_BORDER)
			dw |= WS_BORDER;

		//if(~(wstyle & WD_STYLE_OWNERSC) && (wstyle & WD_STYLE_HSCROLL))
		//	dw |= WS_HSCROLL;

		//if (~(wstyle & WD_STYLE_OWNERSC) && (wstyle & WD_STYLE_VSCROLL))
		//	dw |= WS_VSCROLL;

		if (wstyle & WD_STYLE_TITLE)
		{
			if (wstyle & WD_STYLE_SIZEBOX)
			{
				dw |= (WS_POPUP | WS_CAPTION);
			}
			else
			{
				dw |= (WS_POPUP | WS_CAPTION);
			}
		}
	}

	return dw;
}

static int _SizeCode(int sc)
{
	switch(sc)
	{
	case SIZE_MAXIMIZED:
		return WS_SIZE_MAXIMIZED;
	case SIZE_MINIMIZED:
		return WS_SIZE_MINIMIZED;
	case SIZE_MAXHIDE:
		return -1;
	case SIZE_MAXSHOW:
		return WS_SIZE_MAXSHOW;
	case SIZE_RESTORED:
		return WS_SIZE_RESTORE;
	default:
		return WS_SIZE_RESTORE;
	}
}

/*******************************************************************************************/

ATOM RegisterXdcWidgetClass(HINSTANCE hInstance)
{
	WNDCLASS wcex = { 0 };

	wcex.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
	wcex.lpfnWndProc = (WNDPROC)XdcWidgetProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = NULL;
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = NULL;
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = XDUWIDGET;

	return RegisterClass(&wcex);
}


LRESULT CALLBACK XdcWidgetProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	wince_widget_t* pws = GETXDUSTRUCT(hWnd);
	widget_t widget = (pws)? &(pws->head) : NULL;
	DWORD ds = (pws) ? pws->style : 0;

	LPCREATESTRUCT lpcs;
	if_dispatch_t* pev;
	wince_context_t wct = { 0 };
	TRACKMOUSEEVENT te = { 0 };
	COLORREF clrref;


	switch (message)
	{
	case WM_CREATE:
		lpcs = (LPCREATESTRUCT)lParam;
		if (lpcs->lpCreateParams)
		{
			if_dispatch_t* pv = (if_dispatch_t*)lpcs->lpCreateParams;
			if (pv)
			{
				pev = (if_dispatch_t*)xmem_alloc(sizeof(if_dispatch_t));
				CopyMemory((void*)pev, (void*)pv, sizeof(if_dispatch_t));
				SETXDUDISPATCH(hWnd, pev);
			}
		}

		pws = (wince_widget_t*)xmem_alloc_handle(sizeof(wince_widget_t));
		pws->head.tag = _HANDLE_WIDGET;
		pws->self = hWnd;
		pws->parent = lpcs->hwndParent;
		pws->accel = NULL;

		clrref = GetSysColor(COLOR_WINDOW);
		pws->clrs.clr_bkg.r = GetRValue(clrref);
		pws->clrs.clr_bkg.g = GetGValue(clrref);
		pws->clrs.clr_bkg.b = GetBValue(clrref);

		clrref = GetSysColor(COLOR_WINDOWFRAME);
		pws->clrs.clr_frg.r = GetRValue(clrref);
		pws->clrs.clr_frg.g = GetGValue(clrref);
		pws->clrs.clr_frg.b = GetBValue(clrref);

		clrref = GetSysColor(COLOR_WINDOWTEXT);
		pws->clrs.clr_txt.r = GetRValue(clrref);
		pws->clrs.clr_txt.g = GetGValue(clrref);
		pws->clrs.clr_txt.b = GetBValue(clrref);

		SETXDUSTRUCT(hWnd, pws);
		widget = &(pws->head);
		pev = GETXDUDISPATCH(hWnd);

		if (pev && pev->pf_on_create)
		{
			if ((*pev->pf_on_create)(widget, (void*)(pev->param)))
				return -1;
		}
		break;
	case WM_DESTROY:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_destroy)
		{
			(*pev->pf_on_destroy)(widget);
		}

		if (pev)
		{
			RemoveProp(hWnd, XDUDISPATCH);
			xmem_free(pev);
		}

		if (pws)
		{
			if(pws->accel) DestroyAcceleratorTable(pws->accel);

			RemoveProp(hWnd, XDUSTRUCT);
			xmem_free_handle(&(pws->head));
		}
		break;
	case WM_CLOSE:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_close)
		{
			if (pws->result = (*pev->pf_on_close)(widget))
				return 0;
		}else
		{
			pws->result = 0;
		}

		if(!pws->result)
		{
			pws->mode = WS_MODE_INVALID;
		}
		break;
	case WM_LBUTTONDBLCLK:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_lbutton_dbclick)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			(*pev->pf_on_lbutton_dbclick)(widget, &xp);
		}
		break;
	case WM_LBUTTONDOWN:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_lbutton_down)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			(*pev->pf_on_lbutton_down)(widget, &xp);
		}
		break;
	case WM_LBUTTONUP:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_lbutton_up)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			(*pev->pf_on_lbutton_up)(widget, &xp);
		}
		break;
	case WM_RBUTTONDOWN:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_rbutton_down)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			(*pev->pf_on_rbutton_down)(widget, &xp);
		}
		break;
	case WM_RBUTTONUP:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_rbutton_up)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			(*pev->pf_on_rbutton_up)(widget, &xp);
		}
		break;
	case WM_MOUSEMOVE:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_mouse_move)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			(*pev->pf_on_mouse_move)(widget, (dword_t)wParam, &xp);
		}
		break;
	case WM_MOUSEHOVER:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_mouse_hover)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			(*pev->pf_on_mouse_hover)(widget, (dword_t)wParam, &xp);
		}
		break;
	case WM_MOUSELEAVE:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_mouse_leave)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			(*pev->pf_on_mouse_leave)(widget, (dword_t)wParam, &xp);
		}
		break;
	case WM_MOVE:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_move)
		{
			xpoint_t xp;

			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			(*pev->pf_on_move)(widget, &xp);
			return 0;
		}
		break;
	case WM_SIZE:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_size)
		{
			xsize_t xs;
			
			xs.w = (int)(short)LOWORD(lParam);
			xs.h = (int)(short)HIWORD(lParam);

			int sc = _SizeCode((int)wParam);

			(*pev->pf_on_size)(widget, sc, &xs);

			return 0;
		}
		break;
	case WM_SHOWWINDOW:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_show && !lParam)
		{
			(*pev->pf_on_show)(widget, (bool_t)wParam);
			return 0;
		}
		break;
	case WM_HSCROLL:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_scroll)
		{
			scroll_t scr = { 0 };
			wceWidgetGetScrollInfo(widget, 1, &scr);
			
			switch (LOWORD(wParam))
			{
			case SB_LEFT:
				(*pev->pf_on_scroll)(widget, (bool_t)1, -scr.pos);
				break;
			case SB_RIGHT:
				(*pev->pf_on_scroll)(widget, (bool_t)1, scr.max - scr.pos);
				break;
			case SB_LINELEFT:
				(*pev->pf_on_scroll)(widget, (bool_t)1, -scr.min);
				break;
			case SB_LINERIGHT:
				(*pev->pf_on_scroll)(widget, (bool_t)1, scr.min);
				break;
			case SB_PAGELEFT:
				(*pev->pf_on_scroll)(widget, (bool_t)1, -scr.page);
				break;
			case SB_PAGERIGHT:
				(*pev->pf_on_scroll)(widget, (bool_t)1, scr.page);
				break;
			case SB_THUMBPOSITION:
				(*pev->pf_on_scroll)(widget, (bool_t)1, scr.track - scr.pos);
				break;
			case SB_ENDSCROLL:
				break;
			}
			return 0;
		}
		break;
	case WM_VSCROLL:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_scroll)
		{
			scroll_t scr = { 0 };
			wceWidgetGetScrollInfo(widget, 0, &scr);

			switch (LOWORD(wParam))
			{
			case SB_TOP:
				(*pev->pf_on_scroll)(widget, (bool_t)0, -scr.pos);
				break;
			case SB_BOTTOM:
				(*pev->pf_on_scroll)(widget, (bool_t)0, scr.max - scr.pos);
				break;
			case SB_LINEUP:
				(*pev->pf_on_scroll)(widget, (bool_t)0, -scr.min);
				break;
			case SB_LINEDOWN:
				(*pev->pf_on_scroll)(widget, (bool_t)0, scr.min);
				break;
			case SB_PAGEUP:
				(*pev->pf_on_scroll)(widget, (bool_t)0, -scr.page);
				break;
			case SB_PAGEDOWN:
				(*pev->pf_on_scroll)(widget, (bool_t)0, scr.page);
				break;
			case SB_THUMBPOSITION:
				(*pev->pf_on_scroll)(widget, (bool_t)0, scr.track - scr.pos);
				break;
			case SB_ENDSCROLL:
				break;
			}
			return 0;
		}
		break;
	case WM_SCROLL:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_scroll)
		{
			(*pev->pf_on_scroll)(widget, (bool_t)wParam, (int)lParam);
		}
		return 0;
	case WM_ACTIVATE:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_activate)
		{
			int ac = 0;
			switch (LOWORD(wParam))
			{
			case WA_CLICKACTIVE:
				ac = WS_ACTIVE_CLICK;
				break;
			case WS_ACTIVE_OTHER:
				ac = WS_ACTIVE_OTHER;
				break;
			case WS_ACTIVE_NONE:
				ac = WS_ACTIVE_NONE;
				break;
			}

			(*pev->pf_on_activate)(widget, ac);
		}
		break;
	case WM_MOUSEACTIVATE:
		if (ds & WD_STYLE_NOACTIVE)
			return MA_NOACTIVATE;

		te.cbSize = sizeof(TRACKMOUSEEVENT);
		te.dwFlags |= (TME_HOVER | TME_LEAVE);
		te.dwHoverTime = HOVER_DEFAULT;
		te.hwndTrack = hWnd;
		TrackMouseEvent(&te);
		break;
	case WM_ERASEBKGND:
		if ((ds & WD_STYLE_OWNERNC))
		{
			return 0;
		}
		break;
	case WM_PAINT:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_paint)
		{
			PAINTSTRUCT ps;
			RECT rtFront;

			if (GetUpdateRect(hWnd, &rtFront, FALSE))
			{
				xrect_t xrFront;
				xrFront.x = rtFront.left;
				xrFront.y = rtFront.top;
				xrFront.w = rtFront.right - rtFront.left;
				xrFront.h = rtFront.bottom - rtFront.top;

				BeginPaint(hWnd, &ps);

				wct.context = ps.hdc;
				wct.device.window = hWnd;
				wct.type = CONTEXT_WIDGET;

				(*pev->pf_on_paint)(widget, (visual_t)&(wct.head), &xrFront);

				ZeroMemory((void*)&wct, sizeof(wince_context_t));

				EndPaint(hWnd, &ps);
			}
		}
		break;
	case WM_KEYDOWN:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_keydown)
		{
			dword_t ks = 0;

			if (GetKeyState(VK_SHIFT)) ks |= KS_WITH_SHIFT;
			if (GetKeyState(VK_CONTROL)) ks |= KS_WITH_CONTROL;
			if (GetKeyState(VK_MENU)) ks |= KS_WITH_ALT;

			(*pev->pf_on_keydown)(widget, ks, (int)wParam);
			return 0;
		}
		break;
	case WM_CHAR:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_wchar)
		{
			(*pev->pf_on_wchar)(widget, (wchar_t)wParam);
			return 0;
		}
		break;
	case WM_SETFOCUS:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_set_focus)
		{
			(*pev->pf_on_set_focus)(widget, (widget_t)NULL);
			return 0;
		}
		break;
	case WM_KILLFOCUS:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_kill_focus)
		{
			(*pev->pf_on_kill_focus)(widget, (widget_t)NULL);
			return 0;
		}
		break;
	case WM_COMMAND:
		pev = GETXDUDISPATCH(hWnd);
		if (pev)
		{
			if (LOWORD(wParam) == IDC_PARENT)
			{
				if (HIWORD(wParam) == COMMAND_FIND)
				{
					if (pev->pf_on_command_find)
					{
						(*pev->pf_on_command_find)(widget, (str_find_t*)lParam);
						return 0;
					}
				}
				else if (HIWORD(wParam) == COMMAND_REPLACE)
				{
					if (pev->pf_on_command_replace)
					{
						(*pev->pf_on_command_replace)(widget, (str_replace_t*)lParam);
						return 0;
					}
				}
				else if (pev->pf_on_parent_command)
				{
					(*pev->pf_on_parent_command)(widget, (int)(short)HIWORD(wParam), (vword_t)lParam);
					return 0;
				}
			}
			else if (LOWORD(wParam) == IDC_CHILD)
			{
				if (pev->pf_on_child_command)
				{
					(*pev->pf_on_child_command)(widget, (int)(short)HIWORD(wParam), (vword_t)lParam);
					return 0;
				}
			}
			else if (LOWORD(wParam) == IDC_SELF)
			{
				if (pev->pf_on_self_command)
				{
					(*pev->pf_on_self_command)(widget, (int)(short)HIWORD(wParam), (vword_t)lParam);
					return 0;
				}
			}
			else
			{
				if (pev->pf_on_menu_command)
				{
					(*pev->pf_on_menu_command)(widget, (int)(short)HIWORD(wParam), (uid_t)(short)LOWORD(wParam), (vword_t)lParam);
					return 0;
				}
			}
		}
		break;
	case WM_TIMER:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_timer)
		{
			(*pev->pf_on_timer)(widget, (vword_t)(wParam));
			return 0;
		}
		break;
	case WM_NOTICE:
		pev = GETXDUDISPATCH(hWnd);
		if (pev && pev->pf_on_notice)
		{
			(*pev->pf_on_notice)(widget, (NOTICE*)lParam);
		}
		return 0;
	}

	return DefWindowProc(hWnd, message, wParam, lParam);
}

LRESULT CALLBACK XdcSubclassProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	wince_widget_t* pws = GETXDUSTRUCT(hWnd);
	widget_t widget = (pws)? (&pws->head) : NULL;
	DWORD ds = (pws) ? pws->style : 0;

	if_subproc_t* pev = GETXDUSUBPROC(hWnd);

	DWORD uIdSubclass;
	uIdSubclass = (pev)? pev->sid : 0;

	wince_context_t wct = { 0 };

	switch (message)
	{
	case WM_LBUTTONDBLCLK:
		if (pev && pev->sub_on_lbutton_dbclick)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			if ((*pev->sub_on_lbutton_dbclick)(widget, &xp, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_LBUTTONDOWN:
		if (pev && pev->sub_on_lbutton_down)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			if ((*pev->sub_on_lbutton_down)(widget, &xp, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_LBUTTONUP:
		if (pev && pev->sub_on_lbutton_up)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			if ((*pev->sub_on_lbutton_up)(widget, &xp, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_RBUTTONDOWN:
		if (pev && pev->sub_on_rbutton_down)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			if ((*pev->sub_on_rbutton_down)(widget, &xp, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_RBUTTONUP:
		if (pev && pev->sub_on_rbutton_up)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			if ((*pev->sub_on_rbutton_up)(widget, &xp, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_MOUSEMOVE:
		if (pev && pev->sub_on_mouse_move)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			if ((*pev->sub_on_mouse_move)(widget, (dword_t)wParam, &xp, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_MOUSEHOVER:
		if (pev && pev->sub_on_mouse_hover)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			if ((*pev->sub_on_mouse_hover)(widget, (dword_t)wParam, &xp, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_MOUSELEAVE:
		if (pev && pev->sub_on_mouse_leave)
		{
			xpoint_t xp;
			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			if ((*pev->sub_on_mouse_leave)(widget, (dword_t)wParam, &xp, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_SIZE:
		if (pev && pev->sub_on_size)
		{
			xsize_t xs = { 0 };
			xs.w = (int)(short)LOWORD(lParam);
			xs.h = (int)(short)HIWORD(lParam);

			int sc = _SizeCode((int)wParam);

			if ((*pev->sub_on_size)(widget, sc, &xs, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_MOVE:
		if (pev && pev->sub_on_move)
		{
			xpoint_t xp = { 0 };

			xp.x = (int)(short)LOWORD(lParam);
			xp.y = (int)(short)HIWORD(lParam);

			if ((*pev->sub_on_move)(widget, &xp, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_SHOWWINDOW:
		if (pev && pev->sub_on_show)
		{
			if ((*pev->sub_on_show)(widget, (bool_t)wParam, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_SCROLL:
		if (pev && pev->sub_on_scroll)
		{
			if ((*pev->sub_on_scroll)(widget, (bool_t)wParam, (int)lParam, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_ERASEBKGND:
		if ((ds & WD_STYLE_OWNERNC))
		{
			return 0;
		}
		break;
	case WM_PAINT:
		if (pev && pev->sub_on_paint)
		{
			PAINTSTRUCT ps;
			RECT rtFront;
			bool_t rt;

			if (GetUpdateRect(hWnd, &rtFront, FALSE))
			{
				xrect_t xrFront;
				xrFront.x = rtFront.left;
				xrFront.y = rtFront.top;
				xrFront.w = rtFront.right - rtFront.left;
				xrFront.h = rtFront.bottom - rtFront.top;

				BeginPaint(hWnd, &ps);

				wct.context = ps.hdc;
				wct.device.window = hWnd;
				wct.type = CONTEXT_WIDGET;

				rt = (*pev->sub_on_paint)(widget, (visual_t)&(wct.head), &xrFront, (uid_t)uIdSubclass, pev->delta);

				ZeroMemory((void*)&wct, sizeof(wince_context_t));

				EndPaint(hWnd, &ps);

				if (rt)
					return 0;
			}
		}
		break;
	case WM_KEYDOWN:
		if (pev && pev->sub_on_keydown)
		{
			dword_t ks = 0;

			if (GetKeyState(VK_SHIFT)) ks |= KS_WITH_SHIFT;
			if (GetKeyState(VK_CONTROL)) ks |= KS_WITH_CONTROL;
			if (GetKeyState(VK_MENU)) ks |= KS_WITH_ALT;

			if ((*pev->sub_on_keydown)(widget, ks, (int)wParam, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_CHAR:
		if (pev && pev->sub_on_wchar)
		{
			if ((*pev->sub_on_wchar)(widget, (wchar_t)wParam, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_SETFOCUS:
		if (pev && pev->sub_on_set_focus)
		{
			if ((*pev->sub_on_set_focus)(widget, (widget_t)wParam, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_KILLFOCUS:
		if (pev && pev->sub_on_kill_focus)
		{
			if ((*pev->sub_on_kill_focus)(widget, (widget_t)wParam, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_NOTICE:
		if (pev && pev->sub_on_notice)
		{
			if ((*pev->sub_on_notice)(widget, (NOTICE*)lParam, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_COMMAND:
		if (pev)
		{
			if (LOWORD(wParam) == IDC_PARENT)
			{
				if (HIWORD(wParam) == COMMAND_FIND)
				{
					if (pev->sub_on_command_find)
					{
						if ((*pev->sub_on_command_find)(widget, (str_find_t*)lParam, (uid_t)uIdSubclass, pev->delta))
							return 0;
					}
				}
				else if (HIWORD(wParam) == COMMAND_REPLACE)
				{
					if (pev->sub_on_command_replace)
					{
						if ((*pev->sub_on_command_replace)(widget, (str_replace_t*)lParam, (uid_t)uIdSubclass, pev->delta))
							return 0;
					}
				}
				else if (pev->sub_on_parent_command)
				{
					if ((*pev->sub_on_parent_command)(widget, (int)HIWORD(wParam), (vword_t)lParam, (uid_t)uIdSubclass, pev->delta))
						return 0;
				}
			}
			else if (LOWORD(wParam) == IDC_CHILD)
			{
				if (pev->sub_on_child_command)
				{
					if ((*pev->sub_on_child_command)(widget, (int)HIWORD(wParam), (vword_t)lParam, (uid_t)uIdSubclass, pev->delta))
						return 0;
				}
			}
			else if (LOWORD(wParam) == IDC_SELF)
			{
				if (pev->sub_on_self_command)
				{
					if ((*pev->sub_on_self_command)(widget, (int)HIWORD(wParam), (vword_t)lParam, (uid_t)uIdSubclass, pev->delta))
						return 0;
				}
			}
			else 
			{
				if (pev->sub_on_menu_command)
				{
					if ((*pev->sub_on_menu_command)(widget, (int)HIWORD(wParam), (int)LOWORD(wParam), (vword_t)lParam, (uid_t)uIdSubclass, pev->delta))
						return 0;
				}
			}
		}
		break;
	case WM_TIMER:
		if (pev && pev->sub_on_timer)
		{
			if ((*pev->sub_on_timer)(widget, (vword_t)wParam, (uid_t)uIdSubclass, pev->delta))
				return 0;
		}
		break;
	case WM_CLOSE:
		if (pev && pev->sub_on_close)
		{
			if ((*pev->sub_on_close)(widget, (uid_t)uIdSubclass, pev->delta))
				return 1;
		}
		break;
	case WM_DESTROY:
		if (pev && pev->sub_on_unsubbed)
		{
			(*pev->sub_on_unsubbed)(widget, (uid_t)uIdSubclass, pev->delta);
		}
		break;
	}

	if(pev && pev->proc)
		return CallWindowProc((WNDPROC)pev->proc,hWnd,message,wParam,lParam);
	else
		return DefWindowProc(hWnd,message,wParam,lParam);		
}

void wceWidgetStartup(int ver)
{
	HINSTANCE hInst = GetModuleHandle(NULL);

	RegisterXdcWidgetClass(hInst);
}

void wceWidgetCleanup()
{
	HINSTANCE hInst = GetModuleHandle(NULL);

	UnregisterClass(XDUWIDGET, hInst);
}

widget_t wceWidgetCreate(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent, const if_dispatch_t* pev)
{
	wince_widget_t* pws;
	DWORD winStyle = _WindowStyle(wstyle);
	HWND hParent = (wparent)? ((wince_widget_t*)wparent)->self : NULL;

	HWND hWnd = CreateWindow(XDUWIDGET, wname, winStyle, pxr->x, pxr->y, pxr->w, pxr->h, hParent, NULL, NULL, (void*)pev);

	if (!IsWindow(hWnd)) return NULL;

	pws = GETXDUSTRUCT(hWnd);
	if(!pws)
	{
		DestroyWindow(hWnd);
		return NULL;
	}

	pws->style = wstyle;
	pws->mode = WS_MODE_NORMAL;

	if (wstyle & WD_STYLE_OWNERNC)
	{
		SetWindowPos(hWnd, NULL, 0, 0, 0, 0, SWP_FRAMECHANGED | SWP_NOCOPYBITS | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER);
	}

	return (widget_t)pws;
}

void wceWidgetDestroy(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;

	DestroyWindow(pws->self);
}

void wceWidgetClose(widget_t wt, int ret)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	int mode;
	if_subproc_t* psub;
	if_dispatch_t* pdisp;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	psub = GETXDUSUBPROC(pws->self);
	if (psub && psub->sub_on_close)
	{
		if ((*psub->sub_on_close)(wt, psub->sid, psub->delta))
			return;
	}

	pdisp = GETXDUDISPATCH(pws->self);
	if (pdisp && pdisp->pf_on_close)
	{
		if (pws->result = (*pdisp->pf_on_close)(wt))
			return;
	}

	if(pws->style & WD_STYLE_CHILD)
	{
		wceWidgetDestroy(wt);
		return;
	}

	mode = pws->mode;
	pws->mode = WS_MODE_INVALID;

	CloseWindow(pws->self);

	switch(mode)
	{
	case WS_MODE_MAIN:
		pws->retcode = ret;
		PostQuitMessage(ret);
		break;
	case WS_MODE_MODAL:
		pws->retcode = ret;
		break;
	case WS_MODE_TRACK:
		break;
	}
}

const if_subproc_t* wceWidgetGetSubProc(widget_t wt, uid_t sid)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return NULL;
	if (!IsWindow(pws->self)) return NULL;

	return GETXDUSUBPROC(pws->self);
}

bool_t wceWidgetSetSubProc(widget_t wt, uid_t sid, if_subproc_t* sub)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	BOOL b;
	DWORD_PTR p = 0;
	if_subproc_t* psub;
	xrect_t xr = { 0 };

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	if (!sub) return 0;

	psub = GETXDUSUBPROC(pws->self);
	if (psub) return 0;

	psub->sid = sid;
	psub->proc = (void*)GetWindowLongPtr(wt, GWL_WNDPROC);
	SetWindowLongPtr(wt, GWL_WNDPROC, (LONG)XdcSubclassProc);

	psub = (if_subproc_t*)xmem_alloc(sizeof(if_subproc_t));
	CopyMemory((void*)psub, (void*)sub, sizeof(if_subproc_t));

	SETXDUSUBPROC(pws->self, psub);

	if (psub->sub_on_subbing)
	{
		(*psub->sub_on_subbing)(wt, sid, psub->delta);
	}

	return 1;
}

void wceWidgetDelSubProc(widget_t wt, uid_t sid)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	if_subproc_t* psub;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	psub = GETXDUSUBPROC(pws->self);
	if (!psub) return;

	SetWindowLongPtr(wt, GWL_WNDPROC, (LONG)psub->proc);

	xmem_free(psub);

	SETXDUSUBPROC(pws->self, NULL);
}

bool_t wceWidgetSetSubProcDelta(widget_t wt, uid_t sid, vword_t delta)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	if_subproc_t* psub;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	psub = GETXDUSUBPROC(pws->self);
	psub->delta = delta;

	return 1;
}

vword_t wceWidgetGetSubProcDelta(widget_t wt, uid_t sid)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	if_subproc_t* psub;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	psub = GETXDUSUBPROC(pws->self);

	return psub->delta;
}

bool_t wceWidgetHasSubProc(widget_t wt, uid_t sid)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	if_subproc_t* psub;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	psub = GETXDUSUBPROC(pws->self);

	return (psub)? 1 : 0;
}

void wceWidgetSetStyle(widget_t wt, dword_t ws)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if (pws) pws->style = ws;
}

dword_t wceWidgetGetStyle(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	return (pws) ? pws->style : 0;
}

void wceWidgetSetAccel(widget_t wt, const accel_table_t* pact, int n)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	HACCEL hac;
	ACCEL* pa;
	int i;

	pa = (ACCEL*)xmem_alloc(sizeof(ACCEL) * n);
	for (i = 0; i < n; i++)
	{
		pa[i].fVirt = (BYTE)pact[i].vir;
		pa[i].key = (WORD)pact[i].key;
		pa[i].cmd = (WORD)pact[i].cmd;
	}

	hac = CreateAcceleratorTable(pa, n);
	xmem_free(pa);

	pws->accel = hac;
}

void wceWidgetSetOwner(widget_t wt, widget_t owner)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	wince_widget_t* pws_owner = (wince_widget_t*)owner;

	if (pws) pws->owner = ((owner)? pws_owner->self : NULL);
}

widget_t wceWidgetGetOwner(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	wince_widget_t* pws_owner;

	if (!IsWindow(pws->owner)) return NULL;
	pws_owner = GETXDUSTRUCT(pws->owner);

	return (pws_owner) ? (widget_t)&(pws_owner->head) : NULL;
}

void wceWidgetSetCoreDelta(widget_t wt, vword_t pd)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	SETXDUCOREDELTA(pws->self, pd);
}

vword_t wceWidgetGetCoreDelta(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	return GETXDUCOREDELTA(pws->self);
}

void wceWidgetSetUserDelta(widget_t wt, vword_t pd)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	SETXDUUSERDELTA(pws->self, pd);
}

vword_t wceWidgetGetUserDelta(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	return GETXDUUSERDELTA(pws->self);
}

void wceWidgetSetUserId(widget_t wt, uid_t uid)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	if (GetWindowLongPtr(pws->self, GWL_STYLE) & WS_CHILD)
		SetWindowLongPtr(pws->self, GWL_ID, (LONG)uid);

	pws->uid = uid;
}

uid_t wceWidgetGetUserId(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	if (GetWindowLongPtr(pws->self, GWL_STYLE) & WS_CHILD)
		return (dword_t)GetWindowLongPtr(pws->self, GWL_ID);
	else
		return pws->uid;
}

void wceWidgetSetUserResult(widget_t wt, int rt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	pws->result = rt;
}

int wceWidgetGetUserResult(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	return (pws)? pws->result : 0;
}

widget_t wceWidgetGetChild(widget_t wt, uid_t uid)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	wince_widget_t* pws_child;
	HWND hChild;

	if(!pws) return NULL;
	if (!IsWindow(pws->self)) return NULL;

	hChild = GetDlgItem(pws->self, uid);
	if (!IsWindow(hChild)) return NULL;

	pws_child = GETXDUSTRUCT(hChild);
	return (pws_child)? (widget_t)&(pws_child->head) : NULL;
}

widget_t wceWidgetGetParent(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	wince_widget_t* pws_parent;
	HWND hParent;

	if(!pws) return NULL;
	if (!IsWindow(pws->self)) return NULL;

	hParent = GetParent(pws->self);
	if (!IsWindow(hParent)) return NULL;

	pws_parent = GETXDUSTRUCT(hParent);
	return (pws_parent)? (widget_t)&(pws_parent->head) : NULL;
}

void wceWidgetSetUserProp(widget_t wt, const tchar_t* pname, vword_t pval)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	SetProp(pws->self, pname, (HANDLE)pval);
}

vword_t wceWidgetGetUserProp(widget_t wt, const tchar_t* pname)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	return (vword_t)GetProp(pws->self, pname);
}

vword_t wceWidgetDelUserProp(widget_t wt, const tchar_t* pname)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	return (vword_t)RemoveProp(pws->self, pname);
}

const if_dispatch_t* wceWidgetGetDispatch(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return NULL;
	if (!IsWindow(pws->self)) return NULL;

	return GETXDUDISPATCH(pws->self);
}

bool_t wceWidgetIsMaximized(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	return (IsZoomed(pws->self)) ? 1 : 0;
}

bool_t wceWidgetIsMinimized(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	return (IsIconic((HWND)wt)) ? 1 : 0;
}

typedef struct _enum_child_window_param{
	PF_ENUM_WINDOW_PROC pf;
	vword_t pv;
}enum_child_window_param;

static int STDCALL _enum_child_window(HWND hWnd, LPARAM lp)
{
	enum_child_window_param* pp = (enum_child_window_param*)lp;
	widget_t wt;

	wt = (widget_t)GETXDUSTRUCT(hWnd);
	return (*(pp->pf))(wt, pp->pv);
}

bool_t wceWidgetEnumChild(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	enum_child_window_param ep;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	HWND hWnd;

	hWnd = GetWindow(pws->self, GW_CHILD);
	while(hWnd)
	{
		(*pf)(hWnd,pv);

		hWnd = GetWindow(hWnd, GW_HWNDNEXT);
	}
	return 1;
}

visual_t wceWidgetClientContext(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	wince_context_t* pct;

	if(!pws) return NULL;
	if (!IsWindow(pws->self)) return NULL;

	pct = (wince_context_t*)xmem_alloc_handle(sizeof(wince_context_t));
	pct->context = GetDC(pws->self);
	pct->device.window = pws->self;
	pct->type = CONTEXT_WIDGET;
	pct->fontset = g_fontset;
	
	return (visual_t)pct;
}

visual_t wceWidgetWindowContext(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	wince_context_t* pct;

	if(!pws) return NULL;
	if (!IsWindow(pws->self)) return NULL;

	pct = (wince_context_t*)xmem_alloc_handle(sizeof(wince_context_t));
	pct->context = GetWindowDC(pws->self);
	pct->device.window = pws->self;
	pct->type = CONTEXT_WIDGET;
	pct->fontset = g_fontset;

	return (visual_t)pct;
}

void wceWidgetReleaseContext(widget_t wt, visual_t dc)
{
	wince_context_t* pct = (wince_context_t*)dc;

	if(!pct) return;

	ReleaseDC(pct->device.window, pct->context);

	xmem_free_handle((xhand_t)pct);
}

void wceWidgetGetClientRect(widget_t wt, xrect_t* prt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	RECT rt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	GetClientRect(pws->self, &rt);

	prt->x = rt.left;
	prt->y = rt.top;
	prt->w = rt.right - rt.left;
	prt->h = rt.bottom - rt.top;
}

void wceWidgetGetWindowRect(widget_t wt, xrect_t* prt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	RECT rt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	GetWindowRect(pws->self, &rt);

	prt->x = rt.left;
	prt->y = rt.top;
	prt->w = rt.right - rt.left;
	prt->h = rt.bottom - rt.top;
}

void wceWidgetClientToScreen(widget_t wt, xpoint_t* ppt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	POINT pt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	pt.x = ppt->x;
	pt.y = ppt->y;

	ClientToScreen(pws->self, &pt);

	ppt->x = pt.x;
	ppt->y = pt.y;
}

void wceWidgetScreenToClient(widget_t wt, xpoint_t* ppt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	POINT pt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	pt.x = ppt->x;
	pt.y = ppt->y;

	ScreenToClient(pws->self, &pt);

	ppt->x = pt.x;
	ppt->y = pt.y;
}

void wceWidgetClientToWindow(widget_t wt, xpoint_t* ppt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	POINT pt = { 0 };
	RECT rt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	ClientToScreen(pws->self, &pt);
	GetWindowRect(pws->self, &rt);

	pt.x -= rt.left;
	pt.y -= rt.top;

	ppt->x += pt.x;
	ppt->y += pt.y;
}

void wceWidgetWindowToClient(widget_t wt, xpoint_t* ppt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	POINT pt = { 0 };
	RECT rt;
	
	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	GetWindowRect(pws->self, &rt);
	pt.x = rt.left;
	pt.y = rt.top;
	ScreenToClient(pws->self, &pt);

	ppt->x += pt.x;
	ppt->y += pt.y;
}

void wceWidgetCenterWindow(widget_t wt, widget_t owner)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	wince_widget_t* pws_owner = (wince_widget_t*)owner;
	HWND hOwner;
	RECT rtChild, rtOwner;
	int cx, cy;
	BOOL bChild;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	hOwner = (pws_owner) ? pws_owner->self : GetDesktopWindow();

	bChild = GetWindowLongPtr(pws->self, GWL_STYLE) & WS_CHILD;
	if (bChild)
	{
		GetClientRect(hOwner, &rtOwner);
	}
	else
	{
		GetWindowRect(hOwner, &rtOwner);
	}

	GetWindowRect(pws->self, &rtChild);
	cx = rtChild.right - rtChild.left;
	cy = rtChild.bottom - rtChild.top;

	rtChild.left = rtOwner.left + (rtOwner.right - rtOwner.left - cx) / 2;
	rtChild.right = rtOwner.right - (rtOwner.right - rtOwner.left - cx) / 2;
	rtChild.top = rtOwner.top + (rtOwner.bottom - rtOwner.top - cy) / 2;
	rtChild.bottom = rtOwner.bottom - (rtOwner.bottom - rtOwner.top - cy) / 2;

	SetWindowPos(pws->self, NULL, rtChild.left, rtChild.top, rtChild.right - rtChild.left, rtChild.bottom - rtChild.top, SWP_NOACTIVATE | SWP_NOSIZE | SWP_NOZORDER);
}

void wceWidgetSetCursor(widget_t wt, int curs)
{
	switch (curs)
	{
	case CURSOR_SIZENS:
		SetCursor(LoadCursor(NULL, MAKEINTRESOURCE(IDC_SIZENS)));
		break;
	case CURSOR_SIZEWE:
		SetCursor(LoadCursor(NULL, MAKEINTRESOURCE(IDC_SIZEWE)));
		break;
	case CURSOR_SIZEALL:
		SetCursor(LoadCursor(NULL, MAKEINTRESOURCE(IDC_SIZEALL)));
		break;
	case CURSOR_HAND:
		SetCursor(LoadCursor(NULL, MAKEINTRESOURCE(IDC_HAND)));
		break;
	case CURSOR_HELP:
		SetCursor(LoadCursor(NULL, MAKEINTRESOURCE(IDC_HELP)));
		break;
	case CURSOR_DRAG:
		SetCursor(LoadCursor(NULL, MAKEINTRESOURCE(IDC_APPSTARTING)));
		break;
	case CURSOR_ARROW:
		SetCursor(LoadCursor(NULL, MAKEINTRESOURCE(IDC_ARROW)));
		break;
	case CURSOR_IBEAM:
		SetCursor(LoadCursor(NULL, MAKEINTRESOURCE(IDC_IBEAM)));
		break;
	case CURSOR_WAIT:
		SetCursor(LoadCursor(NULL, MAKEINTRESOURCE(IDC_WAIT)));
		break;
	default:
		SetCursor(LoadCursor(NULL, MAKEINTRESOURCE(IDC_ARROW)));
		break;
	}
}

void wceWidgetSetCapture(widget_t wt, bool_t b)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	if (b)
		SetCapture(pws->self);
	else
		ReleaseCapture();
}

vword_t wceWidgetSetTimer(widget_t wt, int ms)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	return (vword_t)SetTimer(pws->self, IDC_TIMER, ms, NULL);
}

void wceWidgetKillTimer(widget_t wt, vword_t tid)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	if (tid)
		KillTimer(pws->self, (UINT_PTR)tid);
	else
		KillTimer(pws->self, (UINT_PTR)IDC_TIMER);
}

void wceWidgetCreateCaret(widget_t wt, int w, int h)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	CreateCaret(pws->self, NULL, w, h);
	HideCaret(pws->self);
}

void wceWidgetDestroyCaret(widget_t wt)
{
	DestroyCaret();
}

void wceWidgetShowCaret(widget_t wt, int x, int y)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	SetCaretPos(x, y);

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	ShowCaret(pws->self);
}

void wceWidgetEnableHover(widget_t wt, bool_t b)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	TRACKMOUSEEVENT te = { 0 };

	te.cbSize = sizeof(TRACKMOUSEEVENT);
	if(b)
	{
		te.dwFlags = (TME_HOVER | TME_LEAVE);
		te.dwHoverTime = HOVER_DEFAULT;
	}else
	{
		te.dwFlags = (TME_CANCEL | TME_HOVER | TME_LEAVE);
	}
	te.hwndTrack = pws->self;

	TrackMouseEvent(&te);
}

void wceWidgetSetFocus(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	SetFocus(pws->self);
}

bool_t wceWidgetKeyState(widget_t wt, int key)
{
	int ks;

	switch (key)
	{
	case KEY_SHIFT:
		ks = GetKeyState(VK_SHIFT);
		break;
	case KEY_CONTROL:
		ks = GetKeyState(VK_CONTROL);
		break;
	default:
		ks = 0;
	}

	return (ks & 0x8000) ? 1 : 0;
}

bool_t wceWidgetIsValid(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!wt) return 0;
	
	return (IsWindow(pws->self)) ? 1 : 0;
}

bool_t wceWidgetIsFocus(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	return (GetFocus() == pws->self) ? 1 : 0;
}

bool_t wceWidgetIsChild(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	return (GetWindowLongPtr(pws->self, GWL_STYLE) & WS_CHILD) ? 1 : 0;
}

void wceWidgetPostWChar(widget_t wt, wchar_t ch)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	INPUT input[2] = { 0 };

	if (IsWindow(pws->self))
	{
		PostMessage(pws->self, WM_CHAR, (WPARAM)ch, (LPARAM)1);
	}
	else
	{
		input[0].type = INPUT_KEYBOARD;
		input[0].ki.wVk = 0;
		input[0].ki.wScan = ch;
		input[0].ki.dwFlags = 0;
		SendInput(1, input, sizeof(INPUT));

		input[1].type = INPUT_KEYBOARD;
		input[1].ki.wVk = 0;
		input[1].ki.wScan = ch;
		input[1].ki.dwFlags = KEYEVENTF_KEYUP;
		SendInput(1, input + 1, sizeof(INPUT));
	}
}

void wceWidgetPostKey(widget_t wt, int key)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	INPUT input[2] = { 0 };

	if (IsWindow(pws->self))
	{
		PostMessage((HWND)pws->self, WM_KEYDOWN, (WPARAM)key, (LPARAM)1);
		PostMessage((HWND)pws->self, WM_KEYUP, (WPARAM)key, (LPARAM)1);
	}
	else
	{
		input[0].type = INPUT_KEYBOARD;
		input[0].ki.wVk = key;
		input[0].ki.wScan = 1;
		input[0].ki.dwFlags = 0;
		SendInput(1, input, sizeof(INPUT));

		input[1].type = INPUT_KEYBOARD;
		input[1].ki.wVk = key;
		input[1].ki.wScan = 1;
		input[1].ki.dwFlags = KEYEVENTF_KEYUP;
		SendInput(1, input + 1, sizeof(INPUT));
	}
}

void wceWidgetMove(widget_t wt, const xpoint_t* ppt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	RECT rt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	GetWindowRect(pws->self, &rt);
	rt.left = ppt->x;
	rt.top = ppt->y;

	SetWindowPos(pws->self, NULL, rt.left, rt.top, rt.right - rt.left, rt.bottom - rt.top, SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOZORDER);
}

void wceWidgetSize(widget_t wt, const xsize_t* pxs)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	RECT rt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	GetWindowRect(pws->self, &rt);
	rt.right = rt.left + pxs->w;
	rt.bottom = rt.top + pxs->h;

	SetWindowPos(pws->self, NULL, rt.left, rt.top, rt.right - rt.left, rt.bottom - rt.top, SWP_NOMOVE | SWP_NOACTIVATE | SWP_NOZORDER);
}

void wceWidgetTake(widget_t wt, int zor)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	HWND wnd;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	switch (zor)
	{
	case WS_TAKE_BOTTOM:
		wnd = HWND_BOTTOM;
		break;
	case WS_TAKE_TOP:
		wnd = HWND_TOP;
		break;
	case WS_TAKE_TOPMOST:
		wnd = HWND_TOPMOST;
		break;
	default:
		wnd = HWND_NOTOPMOST;
		break;
	}

	SetWindowPos(pws->self, wnd, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE);
}

void wceWidgetShow(widget_t wt, dword_t sw)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	DWORD dw = (pws) ? pws->style : 0;
	RECT rt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	if (sw == WS_SHOW_HIDE)
	{
		ShowWindow(pws->self, SW_HIDE);
	}
	else if (sw == WS_SHOW_NORMAL)
	{
		if (dw & WD_STYLE_NOACTIVE)
		{
			ShowWindow(pws->self, SW_SHOWNA);
		}
		else
		{
			ShowWindow(pws->self, SW_SHOW);
		}
	}
	else if (sw == WS_SHOW_MAXIMIZE)
	{
		ShowWindow(pws->self, SW_MAXIMIZE);
	}
	else if (sw == WS_SHOW_MINIMIZE)
	{
		ShowWindow(pws->self, SW_MINIMIZE);
	}
	else if (sw == WS_SHOW_FULLSCREEN)
	{
		rt.left = rt.top = 0;
		rt.right = GetSystemMetrics(SM_CXFULLSCREEN);
		rt.bottom = GetSystemMetrics(SM_CYFULLSCREEN);

		AdjustWindowRectEx(&rt, (DWORD)GetWindowLongPtr(pws->self, GWL_STYLE), 0, 0);

		if (dw & WD_STYLE_NOACTIVE)
			SetWindowPos(pws->self, HWND_TOP, 0, 0, rt.right - rt.left, rt.bottom - rt.top, SWP_SHOWWINDOW | SWP_NOACTIVATE);
		else
			SetWindowPos(pws->self, HWND_TOP, 0, 0, rt.right - rt.left, rt.bottom - rt.top, SWP_SHOWWINDOW);
	}
	else if (sw == WS_SHOW_POPUPTOP)
	{
		if (dw & WD_STYLE_NOACTIVE)
			SetWindowPos(pws->self, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW | SWP_NOACTIVATE);
		else
			SetWindowPos(pws->self, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
	}
}

void wceWidgetErase(widget_t wt, const xrect_t* prt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	RECT rt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	if (prt)
	{
		rt.left = prt->x;
		rt.top = prt->y;
		rt.right = prt->x + prt->w;
		rt.bottom = prt->y + prt->h;
		InvalidateRect(pws->self, &rt, 0);
	}
	else
	{
		InvalidateRect(pws->self, NULL, 0);
	}
}

void wceWidgetLayout(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	if(pws->style & WD_STYLE_OWNERNC)
	{
		SetWindowPos(pws->self, NULL, 0, 0, 0, 0, SWP_FRAMECHANGED | SWP_NOCOPYBITS | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOREDRAW);
	}

	PostMessage(pws->self, WM_SIZE, WS_SIZE_LAYOUT, 0);
}

void wceWidgetEnable(widget_t wt, bool_t b)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	if (b)
		EnableWindow(pws->self, 1);
	else
		EnableWindow(pws->self, 0);
}

void wceWidgetActive(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	SetActiveWindow(pws->self);
}

void wceWidgetPostNotice(widget_t wt, NOTICE* pnt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	PostMessage(pws->self, WM_NOTICE, (WPARAM)pnt->user, (LPARAM)pnt);
}

int wceWidgetSendNotice(widget_t wt, NOTICE* pnt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	return (int)SendMessage(pws->self, WM_NOTICE, (WPARAM)pnt->user, (LPARAM)pnt);
}

void wceWidgetPostCommand(widget_t wt, int code, uid_t cid, vword_t data)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	PostMessage(pws->self, WM_COMMAND, MAKEWPARAM(cid,code), (LPARAM)data);
}

int wceWidgetSendCommand(widget_t wt, int code, uid_t cid, vword_t data)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	return (int)SendMessage(pws->self, WM_COMMAND, MAKEWPARAM(cid, code), (LPARAM)data);
}

void wceWidgetSetTitle(widget_t wt, const tchar_t* token)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	DWORD dw;
	dw = GetWindowLongPtr(pws->self, GWL_STYLE);

	if (dw & WS_CAPTION)
	{
		SetWindowText(pws->self, token);
	}
}

int wceWidgetGetTitle(widget_t wt, tchar_t* buf, int max)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	DWORD dw;
	int len;

	if(!pws) return 0;
	if (!IsWindow(pws->self)) return 0;

	dw = GetWindowLongPtr(pws->self, GWL_STYLE);

	if (dw & WS_CAPTION)
	{
		len = GetWindowTextLength(pws->self);
		if (buf)
		{
			len = (len < max) ? len : max;
			GetWindowText(pws->self, buf, len + 1);
		}
		return len;
	}

	return 0;
}

void wceWidgetScroll(widget_t wt, bool_t horz, int line)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	PostMessage(pws->self, WM_SCROLL, (vword_t)horz, (vword_t)line);
}

void wceWidgetGetScrollInfo(widget_t wt, bool_t horz, scroll_t* psl)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	
	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	if(horz)
		xmem_copy((void*)psl, (void*)&(pws->hs), sizeof(scroll_t));
	else
		xmem_copy((void*)psl, (void*)&(pws->vs), sizeof(scroll_t));
}

static int CALLBACK _update_horz_position(widget_t wt, vword_t b)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	RECT rt;
	int dst_x = 0, dst_y = 0;

	GetWindowRect(pws->self, &rt);

	if(pws->style & WD_STYLE_CHILD)
	{
		ScreenToClient(pws->parent, (LPPOINT)(&rt));
	}

	rt.left += *(int*)b;
	SetWindowPos(pws->self, NULL, rt.left, rt.top, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOREDRAW | SWP_NOSENDCHANGING | SWP_DEFERERASE);

	return (0);
}

static int CALLBACK _update_vert_position(widget_t wt, vword_t b)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	RECT rt;

	GetWindowRect(pws->self, &rt);

	if(pws->style & WD_STYLE_CHILD)
	{
		ScreenToClient(pws->parent, (LPPOINT)(&rt));
	}

	rt.top += *(int*)b;
	SetWindowPos(pws->self, NULL, rt.left, rt.top, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOREDRAW | SWP_NOSENDCHANGING | SWP_DEFERERASE);

	return (0);
}

void wceWidgetSetScrollInfo(widget_t wt, bool_t horz, const scroll_t* psl)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	dword_t ds = (pws) ? pws->style : 0;

	SCROLLINFO si = { 0 };

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	int b;

	if(horz)
	{
		b = (psl->pos - pws->hs.pos);
		xmem_copy((void*)&(pws->hs), (void*)psl, sizeof(scroll_t));

		if(!b) return;

		wceWidgetEnumChild(wt, (PF_ENUM_WINDOW_PROC)_update_horz_position, (vword_t)&b);
	}
	else
	{
		b = (psl->pos - pws->vs.pos);
		xmem_copy((void*)&(pws->vs), (void*)psl, sizeof(scroll_t));

		if(!b) return;

		wceWidgetEnumChild(wt, (PF_ENUM_WINDOW_PROC)_update_vert_position, (vword_t)&b);
	}
}

void wceWidgetSetDiaph(widget_t wt, float b)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	DWORD dw;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	dw = GetWindowLongPtr(pws->self, GWL_EXSTYLE);
	SetWindowLongPtr(pws->self, GWL_EXSTYLE, dw | WS_EX_LAYERED);
	SetLayeredWindowAttributes(pws->self, 0, (BYTE)((1.0 - b) * 255), LWA_ALPHA);
}

float wceWidgetGetDiaph(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	BYTE b = 0;

	if(!pws) return 1.0f;
	if (!IsWindow(pws->self)) return 1.0f;

	GetLayeredWindowAttributes(pws->self, NULL, &b, NULL);

	return (float)(1.0f - (float)b / 255.0);
}

static int CALLBACK _widget_set_child_color_mode(widget_t wt, vword_t pv)
{
	dword_t dw = wceWidgetGetStyle(wt);
		
	if (dw & WD_STYLE_NOCHANGE)
		return 1;

	wceWidgetSetColorMode(wt, (const color_mod_t*)pv);

	return 1;
}

void wceWidgetSetColorMode(widget_t wt, const color_mod_t* pclr)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	dword_t dw = (pws)? pws->style : 0;

	if (!pws) return;
	if (dw & WD_STYLE_NOCHANGE) return;

	CopyMemory((void*)&(pws->clrs), (void*)pclr, sizeof(color_mod_t));

	wceWidgetSendCommand(wt, COMMAND_COLOR, IDC_SELF, (vword_t)pclr);

	wceWidgetEnumChild(wt, (PF_ENUM_WINDOW_PROC)_widget_set_child_color_mode, (vword_t)pclr);
}

void wceWidgetGetColorMode(widget_t wt, color_mod_t* pclr)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	if (!pws) return;

	CopyMemory((void*)pclr, (void*)&(pws->clrs), sizeof(color_mod_t));
}

const color_mod_t* wceWidgetGetColorModePtr(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;

	return (pws)? &(pws->clrs) : NULL;
}

/*********************************************************************************************************/

int wceWidgetDoMain(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	HWND hMain;
	MSG msg = { 0 };
	BOOL bShow = FALSE;
	BOOL bModal = TRUE;
	int ret = 0;

	if(!pws) return -1;
	if (!IsWindow(pws->self)) return -1;

	hMain = pws->self;
	pws->mode = WS_MODE_MAIN;

	bShow = GetWindowLongPtr(hMain, GWL_STYLE) & WS_VISIBLE;

	if (!bShow)
	{
		ShowWindow(hMain, SW_SHOWNORMAL);
		UpdateWindow(hMain);
	}

	do{
		while (PeekMessage(&msg, NULL, NULL, NULL, PM_NOREMOVE))
		{
			if (!GetMessage(&msg, NULL, NULL, NULL))
			{
				PostQuitMessage(-1);
				bModal = FALSE;
				break;
			}

			if(msg.message == WM_QUIT)
			{
				bModal = FALSE;
				break;
			}

			if (msg.hwnd == hMain && msg.message == WM_KEYDOWN)
			{
				if (pws->accel && TranslateAccelerator(hMain, pws->accel, &msg))
					continue;
			}

			TranslateMessage(&msg);
			DispatchMessage(&msg);

			if (!IsWindow(hMain))
			{
				bModal = FALSE;
				break;
			}

			if(pws->mode != WS_MODE_MAIN)
			{
				bModal = FALSE;
				break;
			}
		}
	} while (bModal);

	if(IsWindow(hMain))
	{
		ret = pws->retcode;
		wceWidgetDestroy(wt);
	}

	return ret;
}

int wceWidgetDoModal(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	HWND hDiag, hOwner;
	MSG msg = { 0 };
	BOOL bShow = FALSE;
	BOOL bModal = TRUE;
	int ret = 0;

	if(!pws) return -1;
	if (!IsWindow(pws->self)) return -1;

	hDiag = pws->self;
	pws->mode = WS_MODE_MODAL;
	
	hOwner = (pws->owner)? pws->owner : pws->parent;
	if (hOwner)
	{
		EnableWindow(hOwner, FALSE);
	}

	bShow = GetWindowLongPtr(hDiag, GWL_STYLE) & WS_VISIBLE;

	if (!bShow)
	{
		ShowWindow(hDiag, SW_SHOWNORMAL);
		UpdateWindow(hDiag);
	}

	do{
		while (PeekMessage(&msg, NULL, NULL, NULL, PM_NOREMOVE))
		{
			if (!GetMessage(&msg, NULL, NULL, NULL))
			{
				PostQuitMessage(-1);
				bModal = FALSE;
				break;
			}

			if (msg.hwnd == hDiag && msg.message == WM_KEYDOWN)
			{
				if (pws->accel && TranslateAccelerator(hDiag, pws->accel, &msg))
					continue;
			}

			TranslateMessage(&msg);
			DispatchMessage(&msg);

			if (!IsWindow(hDiag))
			{
				bModal = FALSE;
				break;
			}

			if(pws->mode != WS_MODE_MODAL)
			{
				bModal = FALSE;
				break;
			}
		}
	} while (bModal);

	ret = pws->retcode;
	wceWidgetDestroy(wt);

	if (hOwner)
	{
		EnableWindow(hOwner, TRUE);
		SetForegroundWindow(hOwner);
		SetWindowPos(hOwner, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOREDRAW | SWP_NOSENDCHANGING | SWP_DEFERERASE);
	}

	return ret;
}

void wceWidgetDoTrack(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	HWND hMenu;
	MSG msg = { 0 };
	BOOL bShow = FALSE;
	BOOL bTrack = TRUE;

	if(!pws) return;
	if (!IsWindow(pws->self)) return;

	hMenu = pws->self;
	pws->mode = WS_MODE_TRACK;

	bShow = GetWindowLongPtr(hMenu, GWL_STYLE) & WS_VISIBLE;

	if (!bShow)
	{
		ShowWindow(hMenu, SW_SHOWNORMAL);
		UpdateWindow(hMenu);
	}

	SetCapture(hMenu);

	do{
		while (PeekMessage(&msg, NULL, NULL, NULL, PM_NOREMOVE))
		{
			if (msg.hwnd == hMenu && msg.message == WM_KEYDOWN && msg.wParam == KEY_ESC)
			{
				GetMessage(&msg, NULL, NULL, NULL);//remove esc
				bTrack = FALSE;
				break;
			}

			if (!GetMessage(&msg, NULL, NULL, NULL))
			{
				PostQuitMessage(-1);
				bTrack = FALSE;
				break;
			}

			TranslateMessage(&msg);
			DispatchMessage(&msg);

			if (!IsWindow(hMenu))
			{
				bTrack = FALSE;
				break;
			}

			if(pws->mode != WS_MODE_TRACK)
			{
				bTrack = FALSE;
				break;
			}
		}
	} while (bTrack);

	ReleaseCapture();

	wceWidgetDestroy(wt);
}

void wceMessageQuit(int code)
{
	PostQuitMessage(code);
}

void wceMessagePosition(xpoint_t* ppt)
{
	DWORD dw = GetMessagePos();

	ppt->x = LOWORD(dw);
	ppt->y = HIWORD(dw);
}

/*********************************************************************************************************/

void wceAdjustWidgetSize(dword_t ws, xsize_t* pxs)
{
	RECT rt = { 0 };

	AdjustWindowRectEx(&rt, _WindowStyle(ws), 0, 0);

	pxs->w = rt.right - rt.left;
	pxs->h = rt.bottom - rt.top;

	pxs->w += 2;
	pxs->h += 2;
}

void wceCalcWidgetBorder(dword_t ws, border_t* pbd)
{
	pbd->edge = pbd->title = pbd->scrh = pbd->scrw = 0;

	if (ws & WD_STYLE_TITLE)
	{
		pbd->title = FRAME_TITLE_DOTS;
	}

	if (ws & WD_STYLE_BORDER)
	{
		if (ws & WD_STYLE_CHILD)
			pbd->edge = CHILD_EDGE_DOTS;
		else
			pbd->edge = FRAME_EDGE_DOTS;
	}

	if (ws & WD_STYLE_HSCROLL)
	{
		pbd->scrh = FRAME_SCROLL_DOTS;
	}

	if (ws & WD_STYLE_VSCROLL)
	{
		pbd->scrw = FRAME_SCROLL_DOTS;
	}
}

void wceGetScreenSize(xsize_t* pxs)
{
	pxs->w = GetSystemMetrics(SM_CXFULLSCREEN);
	pxs->h = GetSystemMetrics(SM_CYFULLSCREEN);
}

void wceGetDesktopSize(xsize_t* pxs)
{
	RECT rt;

	SystemParametersInfo(SPI_GETWORKAREA, 0, &rt, 0);
	pxs->w = rt.right - rt.left;
	pxs->h = rt.bottom - rt.top;
}

void wceScreenSizeToMm(xsize_t* pxs)
{
	HDC hDC;
	float htpermm, vtpermm;
	float cx, cy;

	hDC = GetDC(NULL);

	htpermm = (float)((float)GetDeviceCaps(hDC, LOGPIXELSX) * INCHPERMM);
	vtpermm = (float)((float)GetDeviceCaps(hDC, LOGPIXELSY) * INCHPERMM);

	cx = (float)((float)pxs->w / htpermm);
	cy = (float)((float)pxs->h / vtpermm);

	pxs->fw = cx;
	pxs->fh = cy;

	ReleaseDC(NULL, hDC);
}

void wceScreenSizeToPt(xsize_t* pxs)
{
	HDC hDC;
	float htpermm, vtpermm;
	int cx, cy;

	hDC = GetDC(NULL);

	htpermm = (float)((float)GetDeviceCaps(hDC, LOGPIXELSX) * INCHPERMM);
	vtpermm = (float)((float)GetDeviceCaps(hDC, LOGPIXELSY) * INCHPERMM);

	cx = (int)((float)pxs->fw * htpermm);
	cy = (int)((float)pxs->fh * vtpermm);

	pxs->w = cx;
	pxs->h = cy;

	ReleaseDC(NULL, hDC);
}

