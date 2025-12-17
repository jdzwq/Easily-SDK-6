/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc text scanner interface document

	@module	scaninf.h | interface file

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

#ifndef _SCANINF_H
#define _SCANINF_H

typedef enum{
	_SCANNER_OPERA_STOP = 0,
	_SCANNER_OPERA_NEXT = 1,
	_SCANNER_OPERA_DEL = 2,
	_SCANNER_OPERA_INS = 3,
	_SCANNER_OPERA_PAGED = 4,
}SCANNER_OPERA;

typedef enum{
	_SCANNER_STATE_BEGIN = 0,
	_SCANNER_STATE_CATOR = 1,
	_SCANNER_STATE_WORDS = 2,
	_SCANNER_STATE_LINEBREAK = 3,
	_SCANNER_STATE_PAGEBREAK = 4,
	_SCANNER_STATE_NEWLINE = 5,
	_SCANNER_STATE_NEWPAGE = 6,
	_SCANNER_STATE_END = -1,
}SCANNER_STATE;

typedef struct _word_place_t
{
	int char_w, char_h, line_h;
	int cur_x, cur_y, cur_w, cur_h;
	int min_x, min_y, max_x, max_y;
}word_place_t;

#define OBJECT_ATTR_XFONT	0x00000001
#define OBJECT_ATTR_XFACE	0x00000002
#define OBJECT_ATTR_XBRUSH	0x00000004
#define OBJECT_ATTR_XPEN	0x00000008

typedef struct _object_attr_t
{
	dword_t ret;

	xfont_t** ppxf;
	xface_t** ppxa;
	xbrush_t** ppxb;
	xpen_t** ppxp;
}object_attr_t;

typedef int(CALLBACK *PF_SCAN_TEXTOR_CALLBACK)(int scan, void* object, object_attr_t* attr, bool_t b_atom, bool_t b_ins, bool_t b_del, bool_t b_sel, const tchar_t* cur_word, int cur_count, tchar_t* ret_word, int page, int cur_row, int cur_col, const word_place_t* ptm, void* pp);

typedef bool_t(INFCALL *PF_SCAN_IS_PAGING)(void* ctx);
typedef bool_t(INFCALL *PF_SCAN_BREAK_PAGE)(void* ctx);
typedef int(INFCALL *PF_SCAN_NEXT_PAGE)(void* ctx);
typedef int(INFCALL *PF_SCAN_NEXT_WORD)(void* ctx, tchar_t** ppch, xsize_t* pse, bool_t* pins, bool_t* pdel, bool_t* psel, bool_t* patom);
typedef int(INFCALL *PF_SCAN_INSERT_WORD)(void* ctx, tchar_t* pch, xsize_t* pse);
typedef int(INFCALL *PF_SCAN_DELETE_WORD)(void* ctx);
typedef void(INFCALL *PF_SCAN_CUR_OBJECT)(void* ctx, void** pobj);
typedef void(INFCALL *PF_SCAN_OBJECT_ATTR)(void* ctx, void* pobj, object_attr_t* pret);

typedef struct _words_scan_interface{
	void* ctx;

	PF_SCAN_IS_PAGING	pf_is_paging;
	PF_SCAN_BREAK_PAGE	pf_break_page;
	PF_SCAN_NEXT_PAGE	pf_next_page;
	PF_SCAN_NEXT_WORD	pf_next_word;
	PF_SCAN_INSERT_WORD	pf_insert_word;
	PF_SCAN_DELETE_WORD	pf_delete_word;
	PF_SCAN_CUR_OBJECT	pf_cur_object;
	PF_SCAN_OBJECT_ATTR	pf_object_attr;
}words_scan_interface;



#endif /*SCANINF_H*/