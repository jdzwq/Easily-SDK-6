/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc tag view document

	@module	tagview.c | implement file

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

#include "tagscan.h"

#include "../xdldoc.h"


typedef struct _tag_scan_contet{
	bool_t paged;
	int page;

	link_t_ptr tag;
	link_t_ptr nlk;
	const tchar_t* text;
	int len, pos;
	int ind;
	tchar_t pch[CHS_LEN + 1];

	int point;

	PF_TEXT_SIZE pf_text_size;
	void* ctx;
	const xfont_t* pxf;
}tag_scan_contet;

#define TAGWORD_INDICATOR_NEXT_NODE		0
#define TAGWORD_INDICATOR_NEXT_WORD		1

#if defined(_UNICODE) || defined(UNICODE)
#define TAGWORD_IS_PHRASE_SPLIT(pch)	(pch[0] == L',' || pch[0] == L':' || pch[0] == L'，' || pch[0] == L'：')
#else
#define TAGWORD_IS_PHRASE_SPLIT(pch)	(pch[0] == ',' || pch[0] == ',' || xsncmp(pch,"，",CHS_LEN) == 0 ||  xsncmp(pch,"：",CHS_LEN) == 0)
#endif

#if defined(_UNICODE) || defined(UNICODE)
#define TAGWORD_IS_SENTENCE_SPLIT(pch)	(pch[0] == L'.' || pch[0] == L'!' || pch[0] == L'?' || pch[0] == L';' || pch[0] == L'。' || pch[0] == L'！' || pch[0] == L'？'|| pch[0] == L'；')
#else
#define TAGWORD_IS_SENTENCE_SPLIT(pch)	(pch[0] == '.' || pch[0] == '!' || pch[0] == '?' || pch[0] == ';' || xsncmp(pch,"。",CHS_LEN) == 0 || xsncmp(pch,"！",CHS_LEN) == 0 || xsncmp(pch,"？",CHS_LEN) == 0|| xsncmp(pch,"；",CHS_LEN) == 0)
#endif

#if defined(_UNICODE) || defined(UNICODE)
#define TAGWORD_IS_PARAGRAPH_SPLIT(pch)	(pch[0] == L'\n')
#else
#define TAGWORD_IS_PARAGRAPH_SPLIT(pch)	(pch[0] == '\n')
#endif

bool_t call_tag_is_paging(void* ctx)
{
	return 0;
}

bool_t call_tag_break_page(void* ctx)
{
	return 0;
}

int call_tag_next_page(void* ctx)
{
	tag_scan_contet* pscan = (tag_scan_contet*)ctx;

	if (!pscan->page)
	{
		pscan->page = 1;
	}

	return pscan->page;
}


int call_tag_next_words(void* ctx, tchar_t** ppch, xsize_t* pse, bool_t* pins, bool_t* pdel, bool_t* psel, bool_t* patom)
{
	tag_scan_contet* pscan = (tag_scan_contet*)ctx;
	int n;
	xsize_t xs;

	if (pscan->ind == TAGWORD_INDICATOR_NEXT_NODE)
	{
		pscan->nlk = (pscan->nlk) ? get_tag_next_leaf_node(pscan->tag, pscan->nlk, 0) : get_tag_next_leaf_node(pscan->tag, LINK_FIRST, 0);
		
		if (!pscan->nlk)
		{
			*pins = 1;
			*pdel = 0;
			*psel = 0;
			*patom = 0;

			pse->w = 0;

			return 0;
		}

		pscan->text = get_tag_phrase_text_ptr(pscan->nlk);
		pscan->len = xslen(pscan->text);
		pscan->pos = 0;
		pscan->point = 0;
		pscan->ind = TAGWORD_INDICATOR_NEXT_WORD;

		xszero(pscan->pch, CHS_LEN + 1);
	}

	if (pscan->ind == TAGWORD_INDICATOR_NEXT_WORD)
	{
		n = xschs(pscan->pch);
		pscan->pos += n;

		if (n) pscan->point++;

		n = xschs(pscan->text + pscan->pos);
		xsncpy(pscan->pch, pscan->text + pscan->pos, n);

		if (!get_dom_node_line_cator(pscan->nlk, pscan->point, &pse->w, &pse->h))
		{
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

			ins_dom_node_line_cator(pscan->nlk, pscan->point, pse->w, pse->h);
		}
	}

	*ppch = pscan->pch;

	if (pscan->pos + n == pscan->len)
	{
		pscan->ind = TAGWORD_INDICATOR_NEXT_NODE;
	}

	*pins = 1;
	*pdel = 1;
	*psel = 1;
	*patom = (is_tag_phrase(pscan->nlk))? 0 : 2;

	return n;
}

int call_tag_insert_words(void* ctx, tchar_t* pch, xsize_t* pse)
{
	tag_scan_contet* pscan = (tag_scan_contet*)ctx;
	int n = 0;
	xsize_t xs = { 0 };
	link_t_ptr dlk;

	if (!pscan->nlk)
	{
		pscan->nlk = get_tag_prev_leaf_node(pscan->tag, LINK_LAST, 0);
		if (!(pscan->nlk))
		{
			pscan->nlk = get_tag_prev_leaf_node(pscan->tag, LINK_LAST, 1);
			pscan->text = NULL;
			pscan->len = 0;
			pscan->pos = 0;

			pscan->point = 0;
		}
		else
		{
			pscan->text = get_tag_phrase_text_ptr(pscan->nlk);
			pscan->len = xslen(pscan->text);
			pscan->pos = pscan->len;

			pscan->point = get_dom_node_line_cator_count(pscan->nlk);
		}
		pscan->ind = TAGWORD_INDICATOR_NEXT_WORD;
	}

	switch (pscan->ind)
	{
	case TAGWORD_INDICATOR_NEXT_NODE:
	case TAGWORD_INDICATOR_NEXT_WORD:
		n = xschs(pch);
		pscan->text = tag_phrase_text_ins_chars(pscan->nlk, pscan->pos, pch, n);
		pscan->len += n;

		if (n == 1 && pscan->pch[0] == _T('\t'))
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
		pscan->ind = TAGWORD_INDICATOR_NEXT_WORD;

		if (TAGWORD_IS_PHRASE_SPLIT(pch))
		{
			split_tag_phrase(pscan->nlk, pscan->pos + 1);
			pscan->ind = TAGWORD_INDICATOR_NEXT_NODE;
		}
		else if (TAGWORD_IS_SENTENCE_SPLIT(pch))
		{
			dlk = split_tag_phrase(pscan->nlk, pscan->pos + 1);
			split_tag_sentence(get_dom_parent_node(dlk), dlk);
			pscan->ind = TAGWORD_INDICATOR_NEXT_NODE;
		}
		else if (TAGWORD_IS_PARAGRAPH_SPLIT(pch))
		{
			dlk = split_tag_phrase(pscan->nlk, pscan->pos + 1);
			dlk = split_tag_sentence(get_dom_parent_node(dlk), dlk);
			split_tag_paragraph(get_dom_parent_node(dlk), dlk);
			pscan->ind = TAGWORD_INDICATOR_NEXT_NODE;
		}
		break;
	}

	return n;
}

int call_tag_delete_words(void* ctx)
{
	tag_scan_contet* pscan = (tag_scan_contet*)ctx;
	int n = 0;
	link_t_ptr plk, nlk;

	if (!pscan->nlk)
		return 0;

	switch (pscan->ind)
	{
	case TAGWORD_INDICATOR_NEXT_NODE:
	case TAGWORD_INDICATOR_NEXT_WORD:
		if (TAGWORD_IS_PARAGRAPH_SPLIT((pscan->text + pscan->pos)))
		{
			plk = get_dom_parent_node(pscan->nlk);
			plk = get_dom_parent_node(plk);
			merge_tag_paragraph(plk);
		}
		else if (TAGWORD_IS_SENTENCE_SPLIT((pscan->text + pscan->pos)))
		{
			plk = get_dom_parent_node(pscan->nlk);
			merge_tag_sentence(plk);
		}
		else if (TAGWORD_IS_PHRASE_SPLIT((pscan->text + pscan->pos)))
		{
			merge_tag_phrase(pscan->nlk);
		}

		n = xschs(pscan->text + pscan->pos);
		pscan->text = tag_phrase_text_del_chars(pscan->nlk, pscan->pos, n);
		pscan->len = xslen(pscan->text);

		xszero(pscan->pch, CHS_LEN + 1);

		del_dom_node_line_cator(pscan->nlk, pscan->point);

		if (!pscan->len)
		{
			plk = get_dom_parent_node(pscan->nlk);

			nlk = pscan->nlk;
			pscan->nlk = get_tag_prev_leaf_node(pscan->tag, nlk, 0);
			delete_tag_node(nlk);

			if (pscan->nlk)
			{
				pscan->text = get_tag_phrase_text_ptr(pscan->nlk);
				pscan->len = xslen(pscan->text);
				pscan->pos = pscan->len;
				pscan->point = get_dom_node_line_cator_count(pscan->nlk);

				pscan->ind = TAGWORD_INDICATOR_NEXT_WORD;
			}
			else
			{
				while (plk != pscan->tag)
				{
					nlk = plk;
					plk = get_dom_parent_node(nlk);
					if (get_dom_first_child_node(nlk))
						break;

					delete_tag_node(nlk);
				}
				
				pscan->text = NULL;
				pscan->len = 0;
				pscan->pos = 0;
				pscan->point = 0;

				pscan->ind = TAGWORD_INDICATOR_NEXT_NODE;
			}
		}
		break;
	}

	return n;
}

void call_tag_cur_object(void* ctx, void** pobj)
{
	tag_scan_contet* pscan = (tag_scan_contet*)ctx;

	*pobj = (void*)pscan->nlk;
}

void scan_tag_text(link_t_ptr ptr, const measure_interface* pif, const xfont_t* pxf, const xface_t* pxa, int bx, int by, int bw, int bh, bool_t paged, PF_SCAN_TEXTOR_CALLBACK pf, void* pp)
{
	tag_scan_contet ro = { 0 };
	wordscan_interface it = { 0 };

	ro.tag = ptr;
	ro.nlk = NULL;
	ro.pf_text_size = pif->pf_measure_size;
	ro.ctx = pif->ctx;
	ro.pxf = pxf;

	it.ctx = (void*)&ro;
	it.pf_is_paging = call_tag_is_paging;
	it.pf_cur_object = call_tag_cur_object;
	it.pf_delete_word = call_tag_delete_words;
	it.pf_insert_word = call_tag_insert_words;
	it.pf_next_word = call_tag_next_words;

	if (paged)
	{
		ro.paged = paged;
		it.pf_next_page = call_tag_next_page;
		it.pf_break_page = call_tag_break_page;
	}
	else
	{
		call_tag_next_page((void*)&ro);
	}
	
	scan_object_text(pif, pxf, pxa, bx, by, bw, bh, &it, pf, pp);
}
