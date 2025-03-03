﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc rich view document

	@module	richview.c | implement file

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

#include "richscan.h"

#include "../xdlgdi.h"
#include "../xdldoc.h"


typedef struct _rich_scan_context{
	bool_t paged;
	int page;

	link_t_ptr rich;
	link_t_ptr nlk;

	const tchar_t* text;
	int len, pos;
	int ind;
	tchar_t pch[CHS_LEN + 1];
	int point;

	float permm;
	float indent;
	int place;

	PF_TEXT_SIZE pf_text_size;
	void* ctx;
	const xfont_t* pxf;
}rich_scan_context;

#define RICHWORD_INDICATOR_NEXT_NODE	-4
#define RICHWORD_INDICATOR_NEXT_INDENT	-3
#define RICHWORD_INDICATOR_NEXT_ATOM	-2
#define RICHWORD_INDICATOR_NEXT_BREAK	-1
#define RICHWORD_INDICATOR_NEXT_WORD	0

bool_t call_rich_is_paging(void* ctx)
{
	rich_scan_context* pscan = (rich_scan_context*)ctx;

	return pscan->paged;
}

bool_t call_rich_break_page(void* ctx)
{
	rich_scan_context* pscan = (rich_scan_context*)ctx;
	page_cator_t cat = { 0 };
	int i, pages = 0;
	link_t_ptr nlk;
	bool_t done = 0;

	if (is_last_link(pscan->nlk) && pscan->ind == RICHWORD_INDICATOR_NEXT_NODE)
	{
		return 0;
	}

	done = 0;
	nlk = pscan->nlk;
	while (nlk)
	{
		pages = get_dom_node_page_cator_count(nlk);
		for (i = pages; i >=1; i--)
		{
			get_dom_node_page_cator(nlk, i, &cat);
			if (cat.page >= pscan->page)
			{
				del_dom_node_page_cator(nlk, i);
			}
			if (cat.page == pscan->page)
			{
				done = 1;
				break;
			}
		}
		if (done)
			break;

		nlk = get_rich_prev_anch(pscan->rich, nlk);
	}

	nlk = get_rich_next_anch(pscan->rich, pscan->nlk);
	while (nlk)
	{
		del_dom_node_page_cator(nlk, 0);

		nlk = get_rich_next_anch(pscan->rich, nlk);
	}

	cat.page = pscan->page;
	cat.indi = pscan->ind;
	cat.pos = pscan->pos;
	xscpy(cat.pch, pscan->pch);
	cat.point = pscan->point;

	pages = get_dom_node_page_cator_count(pscan->nlk) + 1;

	set_dom_node_page_cator(pscan->nlk, pages, &cat);

	return 1;
}

int call_rich_next_page(void* ctx)
{
	rich_scan_context* pscan = (rich_scan_context*)ctx;

	page_cator_t cat = { 0 };
	int pages;

	if (!pscan->page)
	{
		pscan->nlk = get_rich_next_anch(pscan->rich, LINK_FIRST);

		if (pscan->nlk)
		{
			pscan->indent = get_rich_anch_text_indent(pscan->nlk);
			pscan->text = NULL;
			pscan->len = (pscan->indent > 0) ? 1 : 0;
			pscan->pos = -1;
			xscpy(pscan->pch, _T("\t"));

			pscan->point = -1;

			pscan->ind = RICHWORD_INDICATOR_NEXT_INDENT;
		}
		else
		{
			pscan->text = NULL;
			pscan->len = 0;
			pscan->pos = 0;
			xszero(pscan->pch, CHS_LEN + 1);

			pscan->point = 0;

			pscan->ind = RICHWORD_INDICATOR_NEXT_NODE;
		}
	}
	else
	{
		while (pscan->nlk)
		{
			pages = 1;
			while(get_dom_node_page_cator(pscan->nlk, pages, &cat))
			{
				if (cat.page == pscan->page)
					break;

				pages++;
			}
			
			if (cat.page == pscan->page)
				break;

			pscan->nlk = get_rich_next_anch(pscan->rich, pscan->nlk);
		}

		if (!pscan->nlk)
			return 0;

		pscan->pos = cat.pos;
		pscan->ind = cat.indi;
		xscpy(pscan->pch, cat.pch);
		pscan->point = cat.point;

		if (pscan->ind == RICHWORD_INDICATOR_NEXT_INDENT)
		{
			pscan->indent = get_rich_anch_text_indent(pscan->nlk);
			pscan->text = NULL;
			pscan->len = (pscan->indent > 0) ? 1 : 0;
		}
		else if (pscan->ind == RICHWORD_INDICATOR_NEXT_ATOM || pscan->ind == RICHWORD_INDICATOR_NEXT_BREAK)
		{
			pscan->text = get_rich_anch_title_ptr(pscan->nlk);
			pscan->len = xslen(pscan->text);
		}
		else
		{
			pscan->text = get_rich_anch_text_ptr(pscan->nlk);
			pscan->len = xslen(pscan->text);
		}
	}
	
	pscan->page++;

	return pscan->page;
}

int call_rich_next_words(void* ctx, tchar_t** ppch, xsize_t* pse, bool_t* pins, bool_t* pdel, bool_t* psel, bool_t* patom)
{
	rich_scan_context* pscan = (rich_scan_context*)ctx;
	int n;
	xsize_t xs = { 0 };

	if (pscan->ind == RICHWORD_INDICATOR_NEXT_NODE)
	{
		pscan->nlk = (pscan->nlk) ? get_rich_next_anch(pscan->rich, pscan->nlk) : NULL;
		if (!pscan->nlk)
		{
			*pins = 0;
			*pdel = 0;
			*psel = 0;
			*patom = 0;

			pse->w = 0;

			return 0;
		}

		pscan->indent = get_rich_anch_text_indent(pscan->nlk);
		pscan->text = NULL;
		pscan->len = (pscan->indent > 0) ? 1 : 0;
		pscan->pos = -1;
		xscpy(pscan->pch, _T("\t"));

		pscan->point = -1;

		pscan->ind = RICHWORD_INDICATOR_NEXT_INDENT;
	}

	if (pscan->ind == RICHWORD_INDICATOR_NEXT_INDENT)
	{
		if (pscan->pos < 0)
		{
			pscan->place = (int)(get_rich_anch_text_place(pscan->nlk) * pscan->permm);
		}

		n = xslen(pscan->pch);
		pscan->pos += n;

		if (pscan->pos == pscan->len)
		{
			xszero(pscan->pch, CHS_LEN + 1);

			pscan->text = get_rich_anch_title_ptr(pscan->nlk);
			pscan->len = xslen(pscan->text);
			pscan->pos = 0;
			pscan->point = -1;

			pscan->ind = RICHWORD_INDICATOR_NEXT_ATOM;
		}
		else
		{
			xscpy(pscan->pch, _T("\t"));
			*ppch = pscan->pch;
			n = 1;

			pse->w = (int)(pscan->indent * pscan->permm);
		}
	}

	if (pscan->ind == RICHWORD_INDICATOR_NEXT_ATOM)
	{
		n = xschs(pscan->pch);
		pscan->pos += n;

		if (pscan->pos == pscan->len)
		{
			pscan->len++;
			pscan->ind = RICHWORD_INDICATOR_NEXT_BREAK;
		}
		else
		{
			n = xschs(pscan->text + pscan->pos);
			xsncpy(pscan->pch, pscan->text + pscan->pos, n);

			*ppch = pscan->pch;

			if (n == 1 && pscan->pch[0] == _T('\t'))
			{
				pse->w *= 4;
			}
			else if (n == 1 && IS_CONTROL_CHAR(pscan->pch[0]))
			{
				pse->w *= 1;
			}
			else
			{
				(*pscan->pf_text_size)(pscan->ctx, pscan->pxf, pscan->pch, n, &xs);

				if (xs.w)
					pse->w = xs.w;
				if (xs.h)
					pse->h = xs.h;
			}

			if (pscan->place)
			{
				pscan->place -= pse->w;
			}
		}
	}

	if (pscan->ind == RICHWORD_INDICATOR_NEXT_BREAK)
	{
		if (pscan->pos == pscan->len)
		{
			pscan->text = get_rich_anch_text_ptr(pscan->nlk);
			pscan->len = xslen(pscan->text);
			pscan->pos = 0;
			pscan->point = 0;

			xszero(pscan->pch, CHS_LEN + 1);
			pscan->ind = RICHWORD_INDICATOR_NEXT_WORD;
		}
		else
		{
			pscan->len--;
			pscan->pos = pscan->len;

			xscpy(pscan->pch, _T("\0"));
			n = 1;

			*ppch = pscan->pch;

			if (pscan->place)
			{
				pscan->place -= pse->w;
			}
		}
	}

	if (pscan->ind == RICHWORD_INDICATOR_NEXT_WORD)
	{
		n = xschs(pscan->pch);
		pscan->pos += n;

		if (n) pscan->point++;

		if (pscan->pos == pscan->len)
		{
			if (get_rich_anch_lined(pscan->nlk))
				xscpy(pscan->pch, _T("\n"));
			else
				xscpy(pscan->pch, _T("\t"));

			n = 1;
			*ppch = pscan->pch;

			if (pscan->place > 0)
			{
				pse->w = pscan->place;
			}

			pscan->place = 0;

			pscan->ind = RICHWORD_INDICATOR_NEXT_NODE;
		}
		else
		{
			n = xschs(pscan->text + pscan->pos);
			xsncpy(pscan->pch, pscan->text + pscan->pos, n);
			*ppch = pscan->pch;

			if (!get_dom_node_line_cator(pscan->nlk, pscan->point, &pse->w, &pse->h))
			{
				if (n == 1 && pscan->pch[0] == _T('\t'))
				{
					pse->w *= 4;
				}
				else if (n == 1 && IS_CONTROL_CHAR(pscan->pch[0]))
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

				ins_dom_node_line_cator(pscan->nlk, pscan->point, pse->w, pse->h);
			}

			if (pscan->place)
			{
				pscan->place -= pse->w;
			}
		}
	}

	switch (pscan->ind)
	{
	case RICHWORD_INDICATOR_NEXT_NODE:
		*pins = 1;
		*pdel = 0;
		*psel = 0;
		*patom = 0;
		break;
	case RICHWORD_INDICATOR_NEXT_INDENT:
		*pins = 0;
		*pdel = 0;
		*psel = 0;
		*patom = 0;
		break;
	case RICHWORD_INDICATOR_NEXT_ATOM:
		*pins = (get_rich_anch_fixed(pscan->nlk))? 0 : 1;
		*pdel = *pins;
		*psel = 0;
		*patom = 1;
		break;
	case RICHWORD_INDICATOR_NEXT_BREAK:
		*pins = (get_rich_anch_fixed(pscan->nlk)) ? 0 : 1;
		*pdel = 0;
		*psel = 0;
		*patom = 1;
		break;
	case RICHWORD_INDICATOR_NEXT_WORD:
		*pins = 1;
		*pdel = 1;
		*psel = 1;
		*patom = 0;
		break;
	default:
		*pins = 0;
		*pdel = 0;
		*psel = 0;
		*patom = 0;
		break;
	}

	return n;
}

int call_rich_insert_words(void* ctx, tchar_t* pch, xsize_t* pse)
{
	rich_scan_context* pscan = (rich_scan_context*)ctx;
	int n = 0;
	xsize_t xs = { 0 };

	if (!pscan->nlk)
		return 0;

	switch (pscan->ind)
	{
	case RICHWORD_INDICATOR_NEXT_INDENT:
		break;
	case RICHWORD_INDICATOR_NEXT_ATOM:
	case RICHWORD_INDICATOR_NEXT_BREAK:
		n = xschs(pch);
		pscan->text = rich_anch_title_ins_chars(pscan->nlk, pscan->pos, pch, n);
		pscan->len += n;

		xszero(pscan->pch, CHS_LEN + 1);
		break;
	case RICHWORD_INDICATOR_NEXT_NODE:
	case RICHWORD_INDICATOR_NEXT_WORD:
		n = xschs(pch);
		pscan->text = rich_anch_text_ins_chars(pscan->nlk, pscan->pos, pch, n);
		pscan->len += n;

		if (n == 1 && pch[0] == _T('\t'))
		{
			xs.w = pse->w * 4;
			xs.h = pse->h;
		}
		else if (n == 1 && IS_CONTROL_CHAR(pch[0]))
		{
			xs.w = pse->w;
			xs.h = pse->h;
		}
		else
		{
			(*pscan->pf_text_size)(pscan->ctx, pscan->pxf, pch, n, &xs);

			if (!xs.w)
				xs.w = pse->w;
			if (!xs.h)
				xs.h = pse->h;
		}

		ins_dom_node_line_cator(pscan->nlk, pscan->point, xs.w, xs.h);

		xszero(pscan->pch, CHS_LEN + 1);
		pscan->ind = RICHWORD_INDICATOR_NEXT_WORD;
		break;
	}

	return n;
}

int call_rich_delete_words(void* ctx)
{
	rich_scan_context* pscan = (rich_scan_context*)ctx;
	int n = 0;

	if (!pscan->nlk)
		return 0;

	switch (pscan->ind)
	{
	case RICHWORD_INDICATOR_NEXT_NODE:
		break;
	case RICHWORD_INDICATOR_NEXT_INDENT:
		break;
	case RICHWORD_INDICATOR_NEXT_ATOM:
	case RICHWORD_INDICATOR_NEXT_BREAK:
		n = xschs(pscan->text + pscan->pos);
		pscan->text = rich_anch_title_del_chars(pscan->nlk, pscan->pos, n);
		pscan->len -= n;

		xszero(pscan->pch, CHS_LEN + 1);
		break;
	case RICHWORD_INDICATOR_NEXT_WORD:
		n = xschs(pscan->text + pscan->pos);
		pscan->text = rich_anch_text_del_chars(pscan->nlk, pscan->pos, n);
		pscan->len -= n;

		del_dom_node_line_cator(pscan->nlk, pscan->point);

		xszero(pscan->pch, CHS_LEN + 1);
		break;
	}

	return n;
}

void call_rich_cur_object(void* ctx, void** pobj)
{
	rich_scan_context* pscan = (rich_scan_context*)ctx;

	*pobj = (void*)pscan->nlk;
}

void scan_rich_text(link_t_ptr ptr, const measure_interface* pif, const xfont_t* pxf, const xface_t* pxa, int bx, int by, int bw, int bh, bool_t paged, PF_SCAN_TEXTOR_CALLBACK pf, void* pp)
{
	rich_scan_context ro = { 0 };
	wordscan_interface it = { 0 };

	ro.rich = ptr;
	ro.pf_text_size = pif->pf_measure_size;
	ro.ctx = pif->ctx;
	ro.pxf = pxf;
	ro.permm = (*pif->pf_measure_pixel)(pif->ctx, 1);

	it.ctx = (void*)&ro;
	it.pf_is_paging = call_rich_is_paging;
	it.pf_cur_object = call_rich_cur_object;
	it.pf_delete_word = call_rich_delete_words;
	it.pf_insert_word = call_rich_insert_words;
	it.pf_next_word = call_rich_next_words;

	if (paged)
	{
		ro.paged = paged;
		it.pf_next_page = call_rich_next_page;
		it.pf_break_page = call_rich_break_page;
	}
	else
	{
		call_rich_next_page((void*)&ro);
	}
	
	scan_object_text(pif, pxf, pxa, bx, by, bw, bh, &it, pf, pp);
}
