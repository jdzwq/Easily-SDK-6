/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu macos definition document

	@module	_xdu_macos.h | macos interface file

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

#ifndef _XDU_MACOS_H
#define _XDU_MACOS_H

//#define XDU_SUPPORT_BLUT
#define XDU_SUPPORT_SHELL
#define XDU_SUPPORT_CONTEXT
#define XDU_SUPPORT_CONTEXT_BITMAP
#define XDU_SUPPORT_CONTEXT_GDI

#define XDU_SUPPORT_CLIPBOARD
#define XDU_SUPPORT_WIDGET
//#define XDU_SUPPORT_WIDGET_NC

#ifdef XDU_SUPPORT_BLUT
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#endif

#if defined(__OBJC__)
#import <Cocoa/Cocoa.h>
#else
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h> 
#include <CoreImage/CoreImage.h>
typedef void* id;
#endif

#ifdef XDU_SUPPORT_WIDGET

#endif


#ifdef XDU_SUPPORT_CONTEXT


#define XRGB(ch) (unsigned short)((double)ch * 65535.0 / 256.0)

typedef id  res_clrmap_t;
typedef id	res_font_t;

#ifdef XDU_SUPPORT_CONTEXT_BITMAP
typedef struct _cocoa_bitmap_t{
	handle_head head;

	CGImageRef image;
}cocoa_bitmap_t;

typedef struct _cocoa_context_t{
    handle_head head;
	
	CGContextRef context;
	CGColorSpaceRef colors;
	CGRect client;
	void* bitmap;
	
	int type;
}cocoa_context_t;

#endif

#endif /*XDU_SUPPORT_CONTEXT*/

#ifdef XDU_SUPPORT_CLIPBOARD

/*clipboard format*/
#define CB_FORMAT_MBS		1
#define CB_FORMAT_UCS		13
#define CB_FORMAT_DIB		8

#ifdef _UNICODE
#define DEF_CB_FORMAT		CB_FORMAT_UCS
#else
#define DEF_CB_FORMAT		CB_FORMAT_MBS
#endif
#endif /*XDU_SUPPORT_CLIPBOARD*/


#ifdef XDU_SUPPORT_WIDGET
typedef struct _cocoa_widget_t{
	handle_head head;

	id self;
	id parent;
	id owner;

	uid_t uid;
	dword_t style;
	dword_t mask;
	int state;
	bool_t disable;
	bool_t idling;

	void* acl;

	int result;

	border_t bd;
	xpoint_t pt;
	xsize_t st;

	scroll_t hs;
	scroll_t vs;

	float diaph;
	clr_mod_t clrs;
}cocoa_widget_t;

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
#define HINT_MENUBAR	100
#define HINT_HSCROLL	101
#define HINT_VSCROLL	102
#define HINT_PAGEUP		103
#define HINT_PAGEDOWN	104
#define HINT_MENUBAR	110
#define HINT_HSCROLL	111
#define HINT_VSCROLL	112
#define HINT_PAGEUP		113
#define HINT_PAGEDOWN	114
#define HINT_LINEUP		115
#define HINT_LINEDOWN	116
#define HINT_LINELEFT	117
#define HINT_LINERIGHT	118
#endif
#endif /*XDU_SUPPORT_WIDGET*/

#define SYSTEM_FONTNAME     _T("Helvetica")

#endif //_XDU_MACOS_H