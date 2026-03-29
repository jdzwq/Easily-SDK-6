/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc defination document

	@module	xdudef.h | interface file

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


#ifndef _XDUDEF_H
#define	_XDUDEF_H

#include <xdk.h>
#include <xdg.h>

#if defined(_OS_WINDOWS)
#include "win32/_xdu_win32.h"
#elif defined(_OS_MACOS)
#include "cocoa/_xdu_cocoa.h"
#elif defined(_OS_LINUX)
#include "X11/_xdu_X11.h"
#endif

#define _HANDLE_WIDGET		0x60
typedef struct _handle_head	 *widget_t;

/*widget class*/
#define XDUWIDGET		_T("XDUWIDGET")
/*widget store property*/
#define XDUSTRUCT		_T("XDUSTRUCT")
#define XDUDISPATCH		_T("XDUDISPATCH")
#define XDUSUBPROC		_T("XDUSUBPROC")
#define XDUUSERDELTA	_T("XDUUSERDELTA")
#define XDUCOREDELTA	_T("XDUCOREDELTA")

/*widget alphablend level*/
#define ALPHA_SOLID			250
#define ALPHA_SOFT			128
#define ALPHA_TRANS			64

#define WM_NOTICE			(WM_EASYMSG_MIN + 1)
#define WM_SCROLL			(WM_EASYMSG_MIN + 2)

#define IDS_SUBCLASS_MIN		10
#define IDS_SUBCLASS_MAX		20

#define IDC_USERCTRL_MIN		100
#define IDC_USERCTRL_MAX		200

/*widget control identify*/
#define IDC_SELF			(IDC_USERCTRL_MIN - 1)
#define IDC_CHILD			(IDC_USERCTRL_MIN - 2)
#define IDC_PARENT			(IDC_USERCTRL_MIN - 3)
#define IDC_TIMER			(IDC_USERCTRL_MIN - 4)


/*widget style*/
#define WD_STYLE_CHILD		0x00000001
#define WD_STYLE_EDITOR		0x00000002
#define WD_STYLE_DOCKER		0x00000004
#define WD_STYLE_HOTOVER	0x00000008

#define WD_STYLE_SIZEBOX	0x00000010
#define WD_STYLE_CLOSEBOX	0x00000020
#define WD_STYLE_HSCROLL	0x00000040
#define WD_STYLE_VSCROLL	0x00000080

#define WD_STYLE_TITLE		0x00000100
#define WD_STYLE_BORDER		0x00000200
#define WD_STYLE_MENUBAR	0x00000400
#define WD_STYLE_OWNERSC	0x00000800

#define WD_STYLE_PAGING		0x00001000
#define WD_STYLE_NOACTIVE	0x00002000
#define WD_STYLE_NOCHANGE	0x00004000
#ifdef XDU_SUPPORT_WIDGET_NC
#define WD_STYLE_OWNERNC	0x00008000
#else
#define WD_STYLE_OWNERNC	0x00000000
#endif

#define WD_STYLE_CONTROL	(WD_STYLE_CHILD | WD_STYLE_OWNERSC | WD_STYLE_OWNERNC)
#define WD_STYLE_POPUP		(WD_STYLE_OWNERSC | WD_STYLE_OWNERNC)
#define WD_STYLE_MENU		(WD_STYLE_NOACTIVE | WD_STYLE_OWNERSC | WD_STYLE_OWNERNC)
#define WD_STYLE_DIALOG		(WD_STYLE_TITLE | WD_STYLE_CLOSEBOX | WD_STYLE_BORDER | WD_STYLE_OWNERSC | WD_STYLE_OWNERNC)
#define WD_STYLE_FRAME		(WD_STYLE_TITLE | WD_STYLE_CLOSEBOX | WD_STYLE_SIZEBOX | WD_STYLE_BORDER | WD_STYLE_OWNERSC | WD_STYLE_OWNERNC)

/*pushbox style*/
#define WD_PUSHBOX_TEXT		0x00010000
#define WD_PUSHBOX_CHECK	0x00020000
#define	WD_PUSHBOX_ICON		0x00040000
#define WD_PUSHBOX_IMAGE	0x00080000

/*mouse button state*/
#define MS_WITH_LBUTTON		0x0001
#define MS_WITH_RBUTTON		0x0002
#define MS_WITH_MBUTTON		0x0010
/*key button state*/
#define KS_WITH_CONTROL		0x0008
#define KS_WITH_SHIFT		0x0004
#define KS_WITH_ALT			0x0020
#define KS_WITH_CAPS		0x0040
#define KS_WITH_CMD			0x0080

/*mouse track mode*/
#define MS_TRACK_HOVER		0x00000001
#define	MS_TRACK_LEAVE		0x00000002

/*widget size mode*/
#define WS_SIZE_RESTORE		0
#define WS_SIZE_MINIMIZED	1
#define WS_SIZE_MAXIMIZED	2
#define WS_SIZE_FULLSCREEN	3
#define WS_SIZE_MAXSHOW		4
#define WS_SIZE_LAYOUT		5

/*widget position mode*/
#define WS_TAKE_TOP			0
#define WS_TAKE_BOTTOM		1
#define WS_TAKE_TOPMOST		(-1)
#define WS_TAKE_NOTOPMOST	(-2)

/*widget show type*/
#define WS_SHOW_NORMAL		0
#define WS_SHOW_HIDE		1
#define WS_SHOW_MAXIMIZE	2
#define WS_SHOW_MINIMIZE	3
#define WS_SHOW_FULLSCREEN	4
#define WS_SHOW_POPUPTOP	5

/*widget running mode*/
#define WS_MODE_INVALID		(-1)
#define WS_MODE_NORMAL		0
#define WS_MODE_MAIN		1
#define WS_MODE_MODAL		2
#define WS_MODE_TRACK		3

/*widget docking position*/
#define WS_DOCK_TOP			0x00000001
#define WS_DOCK_BOTTOM		0x00000002
#define WS_DOCK_LEFT		0x00000004
#define WS_DOCK_RIGHT		0x00000008
#define WS_DOCK_DYNA		0x00010000

/*widget activate mode*/
#define WS_ACTIVE_NONE		0
#define WS_ACTIVE_OTHER		1
#define WS_ACTIVE_CLICK		2

/*widget layout position*/
#define WS_LAYOUT_LEFTTOP		1
#define WS_LAYOUT_RIGHTTOP		2
#define WS_LAYOUT_LEFTBOTTOM	3
#define WS_LAYOUT_RIGHTBOTTOM	4

#ifdef XDU_SUPPORT_WIDGET
typedef int(CALLBACK *PF_ENUM_WINDOW_PROC)(widget_t widget, vword_t pv);

#endif

#ifdef XDU_SUPPORT_WIDGET_NC
/*widget nc hit test*/
#define HINT_NOWHERE	0
#define HINT_TITLE		2
#define HINT_CLIENT		1
#define HINT_RESTORE	4
#define HINT_MINIMIZE	8
#define HINT_MAXIMIZE	9
#define HINT_LEFT		10
#define HINT_RIGHT		11
#define HINT_TOP		12
#define HINT_TOPLEFT	13
#define HINT_TOPRIGHT	14
#define HINT_BOTTOM		15
#define HINT_LEFTBOTTOM	16
#define HINT_RIGHTBOTTOM	17
#define HINT_BORDER		18
#define HINT_CLOSE		20
#define HINT_ICON		21
#define HINT_MENUBAR	22
#define HINT_HSCROLL	23
#define HINT_VSCROLL	24
#define HINT_PAGEUP		25
#define HINT_PAGEDOWN	26
#define HINT_LINEUP		27
#define HINT_LINEDOWN	28
#define HINT_LINELEFT	29
#define HINT_LINERIGHT	30

#endif

/*widget frame*/
#define FRAME_TITLE_DOTS	32
#define FRAME_SCROLL_DOTS	10
#define FRAME_ICON_DOTS		10
#define FRAME_EDGE_DOTS		4
#define CHILD_EDGE_DOTS		2

/*widget scroll code*/
#define SCROLL_LINEUP           0
#define SCROLL_LINELEFT         0
#define SCROLL_LINEDOWN         1
#define SCROLL_LINERIGHT        1
#define SCROLL_PAGEUP           2
#define SCROLL_PAGELEFT         2
#define SCROLL_PAGEDOWN         3
#define SCROLL_PAGERIGHT        3
#define SCROLL_THUMBPOSITION    4
#define SCROLL_THUMBTRACK       5
#define SCROLL_TOP              6
#define SCROLL_LEFT             6
#define SCROLL_BOTTOM           7
#define SCROLL_RIGHT            7
#define SCROLL_ENDSCROLL        8

/*widget command code*/
#define COMMAND_COLOR		1
#define COMMAND_TABSKIP		9
#define COMMAND_UPDATE		11
#define COMMAND_CHANGE		12
#define COMMAND_COMMIT		13
#define COMMAND_COPY		20
#define COMMAND_CUT			21
#define COMMAND_PASTE		22
#define COMMAND_UNDO		23
#define	COMMAND_ROLLBACK	27
#define COMMAND_TABORDER	30
#define COMMAND_QURYDRAG	40
#define COMMAND_QUERYDROP	41
#define COMMAND_QUERYINFO	42
#define COMMAND_FIND		43
#define COMMAND_REPLACE		44
#define COMMAND_RENAME		45
#define COMMAND_REMOVE		46

/*tab opera*/
#define TABORDER_LEFT		0
#define TABORDER_UP			1
#define TABORDER_RIGHT		2
#define TABORDER_DOWN		3
#define TABORDER_END		4
#define	TABORDER_HOME		5
#define TABORDER_PAGEUP		6
#define TABORDER_PAGEDOWN	7

//widget message button
#define MSGBTN_OK		0x00000001
#define MSGBTN_CANCEL	0x00000002
#define MSGBTN_YES		0x00000004
#define MSGBTN_NO		0x00000008
#define MSGBTN_KNOWN	0x00000010

//widget message icon
#define MSGICO_TIP		0x00010000
#define MSGICO_WRN		0x00020000
#define MSGICO_ERR		0x00040000

/*widget cursor identify*/
#define CURSOR_ARROW		1
#define CURSOR_WAIT			2
#define CURSOR_SIZENS		3
#define CURSOR_SIZEWE		4
#define CURSOR_SIZEALL		5
#define CURSOR_HAND			6
#define CURSOR_HELP			7
#define CURSOR_DRAG			8
#define CURSOR_IBEAM		9

/*widget icon identify*/
#define ICON_APPLICATION	_T("application")
#define ICON_QUESTION		_T("question")
#define ICON_EXCLAMATION	_T("exclamation")
#define ICON_INFORMATION	_T("information")
#define ICON_WARING			_T("waring")
#define ICON_ERROR			_T("error")
#define ICON_HAND			_T("hand")
#define ICON_ASTERISK		_T("asterisk")

/*define context type*/
#define CONTEXT_WIDGET		0
#define CONTEXT_MEMORY		1
#define CONTEXT_SCREEN		2
#define CONTEXT_PRINTER		3

/*keycode*/
#define KEY_SHIFT		0x10
#define KEY_CONTROL		0x11
#define KEY_ALT			0x12

#define KEY_BACK		0x08
#define KEY_TAB			0x09
#define KEY_ENTER		0x0D
#define KEY_ESC			0x1B
#define KEY_SPACE		0x20
#define KEY_PAGEUP		0x21
#define KEY_PAGEDOWN	0x22
#define KEY_END			0x23
#define KEY_HOME		0x24
#define KEY_LEFT		0x25
#define KEY_UP			0x26
#define KEY_RIGHT		0x27
#define KEY_DOWN		0x28
#define KEY_INSERT		0x2D
#define KEY_DELETE		0x2E
#define KEY_F1			0x70
#define KEY_F2			0x71
#define KEY_F3			0x72
#define KEY_F4			0x73
#define KEY_F5			0x74
#define KEY_F6			0x75
#define KEY_F7			0x76
#define KEY_F8			0x77
#define KEY_F9			0x78
#define KEY_F10			0x79
#define KEY_F11			0x7A
#define KEY_F12			0x7B

#define KEY_COPY		0x1163
#define KEY_PASTE		0x1176
#define KEY_CUT			0x1178
#define KEY_UNDO		0x117A

typedef struct _accel_table_t{
	unsigned char vir;
	unsigned short key;
	unsigned short cmd;
}accel_table_t;

typedef struct _str_find_t{
	bool_t b_case;
	bool_t b_back;
	const tchar_t* sub_str;
	bool_t b_none;
}str_find_t;

typedef struct _str_replace_t
{
	bool_t b_case;
	bool_t b_back;
	const tchar_t* org_str;
	const tchar_t* new_str;
	bool_t b_none;
}str_replace_t;

#include "inf/ediinf.h"
#include "inf/xduinf.h"

#endif	/* _XDUDEF_H */

