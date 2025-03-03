﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc text view

	@module	textview.c | implement file

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
#include "textscan.h"

#include "../xdldoc.h"


typedef struct _text_scan_context{
	string_t vs;
	int pos;
	tchar_t pch[ESC_LEN + 1];

	PF_TEXT_SIZE pf_text_size;
	void* ctx;
	const xfont_t* pxf;
}text_scan_context;

bool_t call_string_is_paging(void* ctx)
{
	return 0;
}

bool_t call_string_break_page(void* ctx)
{
	return 0;
}

int call_string_next_page(void* ctx)
{
	return 1;
}

int call_string_next_words(void* ctx, tchar_t** ppch, xsize_t* pse, bool_t* pins, bool_t* pdel, bool_t* psel, bool_t* patom)
{
	text_scan_context* pscan = (text_scan_context*)ctx;
	int n;
	xsize_t xs;

	n = xschs(pscan->pch);
	pscan->pos += n;

	string_get_chars(pscan->vs, pscan->pos, pscan->pch, 1);
	
	n = xschs(pscan->pch);
	if (n > 1)
	{
		string_get_chars(pscan->vs, pscan->pos + 1, pscan->pch + 1, n - 1);
	}

	if (n == 1 && IS_CONTROL_CHAR(pscan->pch[0]))
	{
		pse->w *= 1;
		pse->h *= 1;
	}
	else
	{
		(*pscan->pf_text_size)(pscan->ctx, pscan->pxf, pscan->pch, n, &xs);

		if (xs.w)
			pse->w = xs.w;
		if (xs.h)
			pse->h = xs.h;
	}

	*ppch = pscan->pch;

	*pins = 1;
	*pdel = 1;
	*psel = 1;
	*patom = 0;

	return n;
}

int call_string_insert_words(void* ctx, tchar_t* pch, xsize_t* pse)
{
	text_scan_context* pscan = (text_scan_context*)ctx;
	int n;

	xszero(pscan->pch, CHS_LEN + 1);

	n = xschs(pch);
	string_ins_chars(pscan->vs, pscan->pos, pch, n);

	return n;
}

int call_string_delete_words(void* ctx)
{
	text_scan_context* pscan = (text_scan_context*)ctx;
	int n;

	pscan->pch[0] = string_get_char(pscan->vs, pscan->pos);
	n = xschs(pscan->pch);
	string_del_chars(pscan->vs, pscan->pos, n);

	xszero(pscan->pch, CHS_LEN + 1);

	return n;
}

void call_string_cur_object(void* ctx, void** pobj)
{
	text_scan_context* pscan = (text_scan_context*)ctx;

	*pobj = (void*)pscan->vs;
}

void scan_var_text(string_t vs, const measure_interface* pif, const xfont_t* pxf, const xface_t* pxa, int bx, int by, int bw, int bh, bool_t paged, PF_SCAN_TEXTOR_CALLBACK pf, void* pp)
{
	text_scan_context ro = { 0 };
	wordscan_interface it = { 0 };

	ro.vs = vs;
	ro.pf_text_size = pif->pf_measure_size;
	ro.ctx = pif->ctx;
	ro.pxf = pxf;

	it.ctx = (void*)&ro;
	it.pf_is_paging = call_string_is_paging;
	it.pf_cur_object = call_string_cur_object;
	it.pf_delete_word = call_string_delete_words;
	it.pf_insert_word = call_string_insert_words;
	it.pf_next_word = call_string_next_words;

	if (paged)
	{
		it.pf_next_page = call_string_next_page;
		it.pf_break_page = call_string_break_page;
	}

	scan_object_text(pif, pxf, pxa, bx, by, bw, bh, &it, pf, pp);
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct _FIXSTRWORDOPERATOR{
	tchar_t* buf;
	int size;
	int len,pos;
	tchar_t pch[ESC_LEN + 1];

	PF_TEXT_SIZE pf_text_size;
	void* ctx;
	const xfont_t* pxf;
}FIXSTRWORDOPERATOR;

bool_t call_fixstr_is_paging(void* ctx)
{
	return 0;
}

bool_t call_fixstr_break_page(void* ctx)
{
	return 0;
}

int call_fixstr_next_page(void* ctx)
{
	return 1;
}

int call_fixstr_next_words(void* ctx, tchar_t** ppch, xsize_t* pse, bool_t* pins, bool_t* pdel, bool_t* psel, bool_t* patom)
{
	FIXSTRWORDOPERATOR* pscan = (FIXSTRWORDOPERATOR*)ctx;
	int n;
	xsize_t xs;

	n = xschs(pscan->pch);
	pscan->pos += n;

	if (pscan->pos == pscan->len)
	{
		*pins = 1;
		*pdel = 0;
		*psel = 0;
		*patom = 0;

		pse->w = 0;

		return 0;
	}

	n = xschs(pscan->buf + pscan->pos);
	xsncpy(pscan->pch, pscan->buf + pscan->pos, n);

	if (n == 1 && IS_CONTROL_CHAR(pscan->pch[0]))
	{
		pse->w *= 1;
		pse->h *= 1;
	}
	else
	{
		(*pscan->pf_text_size)(pscan->ctx, pscan->pxf, pscan->pch, n, &xs);

		if (xs.w)
			pse->w = xs.w;
		if (xs.h)
			pse->h = xs.h;
	}

	*ppch = pscan->pch;

	*pins = 1;
	*pdel = 1;
	*psel = 1;
	*patom = 0;

	return n;
}

int call_fixstr_insert_words(void* ctx, tchar_t* pch, xsize_t* pse)
{
	FIXSTRWORDOPERATOR* pscan = (FIXSTRWORDOPERATOR*)ctx;
	int n;

	n = xschs(pch);

	if (pscan->len + n >= pscan->size)
		return 0;

	xsnins(pscan->buf, pscan->pos, pch, n);
	pscan->len += n;

	xszero(pscan->pch, CHS_LEN + 1);

	return n;
}

int call_fixstr_delete_words(void* ctx)
{
	FIXSTRWORDOPERATOR* pscan = (FIXSTRWORDOPERATOR*)ctx;
	int n;

	if (pscan->pos < 0)
		return 0;

	n = xschs(pscan->buf + pscan->pos);
	xsndel(pscan->buf, pscan->pos, n);
	pscan->len -= n;

	xszero(pscan->pch, CHS_LEN + 1);

	return n;
}

void call_fixstr_cur_object(void* ctx, void** pobj)
{
	FIXSTRWORDOPERATOR* pscan = (FIXSTRWORDOPERATOR*)ctx;

	*pobj = (void*)pscan->buf;
}

void scan_fix_text(tchar_t* buf, int size, const measure_interface* pif, const xfont_t* pxf, const xface_t* pxa, int bx, int by, int bw, int bh, bool_t paged, PF_SCAN_TEXTOR_CALLBACK pf, void* pp)
{
	FIXSTRWORDOPERATOR ro = { 0 };
	wordscan_interface it = { 0 };

	ro.buf = buf;
	ro.size = size;
	ro.len = xslen(buf);
	ro.pf_text_size = pif->pf_measure_size;
	ro.ctx = pif->ctx;
	ro.pxf = pxf;

	it.ctx = (void*)&ro;
	it.pf_is_paging = call_fixstr_is_paging;
	it.pf_cur_object = call_fixstr_cur_object;
	it.pf_delete_word = call_fixstr_delete_words;
	it.pf_insert_word = call_fixstr_insert_words;
	it.pf_next_word = call_fixstr_next_words;

	if (paged)
	{
		it.pf_next_page = call_fixstr_next_page;
		it.pf_break_page = call_fixstr_break_page;
	}

	scan_object_text(pif, pxf, pxa, bx, by, bw, bh, &it, pf, pp);
}
