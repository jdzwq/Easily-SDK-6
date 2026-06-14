/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc defination document

	@module	xdcdef.h | interface file

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


#ifndef _XDCDEF_H
#define	_XDCDEF_H

#include <xdl.h>
#include <xdg.h>
#include <xdu.h>

#define XDCKEYBOX			_T("XDCKEYBOX")

/*reserved subproc id*/
#define IDS_DIALOG			(IDS_SUBCLASS_MIN + 1)
#define IDS_DATEBOX			(IDS_SUBCLASS_MIN + 2)
#define IDS_TIMEBOX			(IDS_SUBCLASS_MIN + 3)
#define IDS_KEYBOX			(IDS_SUBCLASS_MIN + 4)
#define IDS_NUMBOX			(IDS_SUBCLASS_MIN + 5)
#define IDS_EDITBOX			(IDS_SUBCLASS_MIN + 6)
#define IDS_DROPBOX			(IDS_SUBCLASS_MIN + 7)
#define IDS_WORDSBOX		(IDS_SUBCLASS_MIN + 8)
#define IDS_CHECKBOX		(IDS_SUBCLASS_MIN + 9)
#define IDS_ICONBOX			(IDS_SUBCLASS_MIN + 10)
#define IDS_LISTBOX			(IDS_SUBCLASS_MIN + 11)
#define IDS_RADIOBOX		(IDS_SUBCLASS_MIN + 12)
#define IDS_SLIDEBOX		(IDS_SUBCLASS_MIN + 13)
#define IDS_SPINBOX			(IDS_SUBCLASS_MIN + 14)

#define IDS_SPLITOR			(IDS_SUBCLASS_MIN + 17)
#define IDS_DESIGNER		(IDS_SUBCLASS_MIN + 18)
#define IDS_EDITOR			(IDS_SUBCLASS_MIN + 19)

/*reserved control id*/
#define IDC_FIREEDIT		(IDC_USERCTRL_MIN + 1)
#define IDC_FIRELIST		(IDC_USERCTRL_MIN + 2)
#define IDC_FIREDATE		(IDC_USERCTRL_MIN + 3)
#define IDC_FIRETIME		(IDC_USERCTRL_MIN + 4)
#define IDC_FIRENUM			(IDC_USERCTRL_MIN + 5)
#define IDC_FIREWORDS		(IDC_USERCTRL_MIN + 6)
#define IDC_FIRECHECK		(IDC_USERCTRL_MIN + 7)
#define IDC_FIREGRID		(IDC_USERCTRL_MIN + 8)

#define IDC_EDITBOX			(IDC_USERCTRL_MIN + 11)
#define IDC_DATEBOX			(IDC_USERCTRL_MIN + 12)
#define IDC_TIMEBOX			(IDC_USERCTRL_MIN + 13)
#define IDC_DROPBOX			(IDC_USERCTRL_MIN + 14)
#define IDC_KEYBOX			(IDC_USERCTRL_MIN + 15)
#define IDC_NUMBOX			(IDC_USERCTRL_MIN + 16)
#define IDC_WORDSBOX		(IDC_USERCTRL_MIN + 17)
#define IDC_CHECKBOX		(IDC_USERCTRL_MIN + 18)
#define IDC_RICHBOX			(IDC_USERCTRL_MIN + 19)
#define IDC_MEMOBOX			(IDC_USERCTRL_MIN + 20)
#define IDC_TAGBOX			(IDC_USERCTRL_MIN + 21)
#define IDC_PHOTOBOX		(IDC_USERCTRL_MIN + 22)
#define IDC_IMAGESBOX		(IDC_USERCTRL_MIN + 23)
#define IDC_GRIDBOX			(IDC_USERCTRL_MIN + 24)
#define IDC_STATISBOX		(IDC_USERCTRL_MIN + 25)
#define IDC_TABLEBOX		(IDC_USERCTRL_MIN + 26)
#define IDC_FORMBOX			(IDC_USERCTRL_MIN + 27)
#define IDC_MENUBOX			(IDC_USERCTRL_MIN + 28)

#define IDC_EDITMENU		(IDC_USERCTRL_MIN + 29)
#define IDC_TOOLTIP			(IDC_USERCTRL_MIN + 30)
#define IDC_VERTBOX			(IDC_USERCTRL_MIN + 31)
#define IDC_HORZBOX			(IDC_USERCTRL_MIN + 32)

#define IDC_MSGDLG			(IDC_USERCTRL_MIN + 40)
#define IDC_PROEPRDLG		(IDC_USERCTRL_MIN + 41)
#define IDC_TABLEDLG		(IDC_USERCTRL_MIN + 42)
#define IDC_PROPERDLG		(IDC_USERCTRL_MIN + 43)
#define IDC_LISTDLG			(IDC_USERCTRL_MIN + 44)
#define IDC_ANNODLG			(IDC_USERCTRL_MIN + 45)
#define IDC_INPUTDLG		(IDC_USERCTRL_MIN + 46)
#define IDC_TEXTDLG			(IDC_USERCTRL_MIN + 47)
#define IDC_PREVIEWDLG		(IDC_USERCTRL_MIN + 48)
#define IDC_GRIDDLG			(IDC_USERCTRL_MIN + 49)

/*notice return code*/
#define RET_NOTICE_ACCEPT		0
#define RET_NOTICE_REJECT		1
#define RET_NOTICE_DELETE		2

#define IS_VISIBLE_CHAR(ch) (((nChar >= _T('0') && nChar <= _T('9')) || (nChar >= _T('A') && nChar <= _T('Z')) || (nChar >= _T('a') && nChar <= _T('z')) || (nChar == _T('-')) || (nChar == _T('.')))? 1 : 0)
#define IS_ASCII_CHAR(ch) ((ch >= 32 && ch < 127)? 1 : 0)

#define DEF_TIPTIME		3000

typedef struct _PAGEINFO{
	int total_width;
	int total_height;
	int page_width;
	int page_height;
	int line_width;
	int line_height;
}PAGEINFO;

typedef struct _DOCKINFO{
	dword_t style;
	int cx, cy;
}DOCKINFO;

typedef struct _docker_t{
	widget_t widget;
	DOCKINFO dock[4];
	int x, y;
	int ind;
	bool_t drag;
}docker_t;

typedef struct _splitor_t{
	widget_t widget;
	link_t_ptr split;
	link_t_ptr item;
	int x, y;
}splitor_t;


#define DEF_CTRL_BRUSH		_T("fill-style:solid;fill-color:RGB(250,250,250);fill-opacity:250;")
#define DEF_CTRL_PEN		_T("stroke-style:solid;stroke-color:RGB(168,168,168);stroke-width:1;stroke-opacity:250;")
#define DEF_CTRL_FONT		_T("font-style:normal;font-size:10.5;font-family:Arial;font-weight:400;")
#define DEF_CTRL_FACE		_T("text-color:RGB(10,10,10);text-align:near;line-align:center;text-wrap:line-barek;")

#define DEF_ALARM_COLOR		_T("RGB(178,34,34)")
#define DEF_ENABLE_COLOR	_T("RGB(36,36,36)")
#define DEF_DISABLE_COLOR	_T("RGB(198,198,198)")
#define DEF_ALPHA_COLOR		_T("RGB(152,185,158)")

#define TEXT_STYLE_YELLOW	_T("text-color:RGB(160,82,45)")
#define TEXT_STYLE_PURPLE	_T("text-color:RGB(139,0,139);")
#define TEXT_STYLE_BLUE		_T("text-color:RGB(0,0,139);")
#define TEXT_STYLE_GREEN	_T("text-color:RGB(0,158,0);")
#define TEXT_STYLE_CYAN		_T("text-color:RGB(47,79,79);")
#define TEXT_STYLE_RED		_T("text-color:RGB(198,0,0);")
#define TEXT_STYLE_ORANGE	_T("text-color:RGB(250,127,0);")
#define TEXT_STYLE_SLATE	_T("text-color:RGB(108,123,139);")
#define TEXT_STYLE_GRAY		_T("text-color:RGB(168,168,168);")

#define TEXTOR_MENU_UNDO			_T("Cancel")
#define TEXTOR_MENU_CUT				_T("Cut")
#define TEXTOR_MENU_PASTE			_T("Paste")
#define TEXTOR_MENU_COPY			_T("Copy")

#define MSGDLG_PUSHBOX_CLOSE		_T("Close")
#define MSGDLG_PUSHBOX_OK			_T("OK")
#define MSGDLG_PUSHBOX_CANCEL		_T("Cancel")
#define MSGDLG_PUSHBOX_YES			_T("Yes")
#define MSGDLG_PUSHBOX_NO			_T("No")
#define MSGDLG_PUSHBOX_KNOWN		_T("No Tip Next")

#define MSGDLG_TITLE_TIP			_T("Tip")
#define MSGDLG_TITLE_WRN			_T("Warning")
#define MSGDLG_TITLE_ERR			_T("Error")

#define LISTDLG_PUSHBOX_OK			_T("OK")

#define ANNODLG_PUSHBOX_OK			_T("OK")
#define ANNODLG_PUSHBOX_COMMIT		_T("Commit")
#define ANNODLG_PUSHBOX_FONTSIZE	_T("FontSize")
#define ANNODLG_PUSHBOX_FONTCOLOR	_T("FontColor")

#define PREVIEWDLG_TREE_TITLE		_T("Title")
#define PREVIEWDLG_TREE_DEFITEM		_T("SVG Item")
#define PREVIEWDLG_STATUS_PAGEGUID	_T("Page%d %dPages")
#define PREVIEWDLG_PUSHBOX_CLOSE	_T("Close")
#define PREVIEWDLG_PUSHBOX_PRINTCUR	_T("Print Current")
#define PREVIEWDLG_PUSHBOX_PRINTSEL	_T("Print Selected")
#define PREVIEWDLG_PUSHBOX_PRINTALL	_T("Print All")
#define PREVIEWDLG_PUSHBOX_SETUP	_T("Printer Setup")
#define PREVIEWDLG_PUSHBOX_SAVEAS	_T("Save As")
#define PREVIEWDLG_PUSHBOX_SAVE		_T("Save")
#define PREVIEWDLG_PUSHBOX_OPEN		_T("Open")

#define PROPERDLG_PUSHBOX_OK		_T("OK")
#define GRIDDLG_PUSHBOX_OK			_T("OK")
#define TABLEDLG_PUSHBOX_OK			_T("OK")
#define TEXTDLG_PUSHBOX_OK			_T("OK")

#ifndef LAN_CN
#define LAN_CN
#endif


#ifdef _OS_WINDOWS
#include "lang/_xdc_ansi.h"
#endif

#include "inf/desginf.h"
#include "inf/editinf.h"

#endif	/* _XDCDEF_H */

