/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc text scanner document

	@module	scanner.c | implement file

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

#include "scanner.h"


void scan_object_text(const measure_interface* pmv, const viewbox_t* pvb, words_scan_interface* pit, PF_SCAN_TEXTOR_CALLBACK pf, void* pp)
{
	float line_rati = 1.0f;
	int break_mode = 0;

	object_attr_t attr = {0};

	tchar_t sch[4] = { 0 };
	tchar_t* pch = NULL;
	int chs;

	int ts, to;
	bool_t b_newline = 0;
	bool_t b_newpage = 0;
	bool_t b_cancel = 0;
	bool_t b_paging = 0;

	bool_t b_atom = 0;
	bool_t b_ins = 0;
	bool_t b_del = 0;
	bool_t b_sel = 0;

	void *org_obj, *cur_obj = NULL;
	int row_at = 0;
	int col_at = 0;
	int page = 0;

	word_place_t tm = { 0 };
	xsize_t xs, se = {0};

	(*pit->pf_cur_object)(pit->ctx, &cur_obj);

	attr.ret = 0;
	(*pit->pf_object_attr)(pit->ctx, cur_obj, &attr);

	if((attr.ret & OBJECT_ATTR_XFACE) && attr.pxa)
	{
		break_mode = parse_wrap(attr.pxa);

		if (is_null(attr.pxa->line_height))
			line_rati = xstof(DEF_GDI_TEXT_LINE_HEIGHT);
		else
			line_rati = xstof(attr.pxa->line_height);

		if (line_rati < 1)
			line_rati = 1.0;
	}

	if((attr.ret & OBJECT_ATTR_XFONT) && attr.pxf)
	{
		(*pmv->mea->pf_measure_font)(pmv->ctx, attr.pxf, &se);
	}

	tm.char_w = se.w;
	tm.char_h = se.h;
	tm.line_h = (int)((float)se.h * (line_rati - 1.0));
	tm.min_x = pvb->px;
	tm.min_y = pvb->py;
	tm.max_x = pvb->px + pvb->pw;
	tm.max_y = pvb->py + pvb->ph;
	tm.cur_x = tm.min_x + tm.char_w;
	tm.cur_y = tm.min_y + tm.line_h;

	b_paging = (*pit->pf_is_paging)(pit->ctx);

	to = (*pf)(_SCANNER_STATE_BEGIN, NULL, &attr, 0, 0, 0, 0, NULL, 0, NULL, 0, -1, 0, &tm, pp);

	if (to != _SCANNER_OPERA_STOP)
	{
		if (b_paging)
			to = _SCANNER_OPERA_PAGED;
		else
			to = _SCANNER_OPERA_NEXT;
	}

	while (to != _SCANNER_OPERA_STOP)
	{
		switch (to)
		{
		case _SCANNER_OPERA_PAGED:
			while (to == _SCANNER_OPERA_PAGED)
			{
				page = (*pit->pf_next_page)(pit->ctx);
				if (!page)
				{
					to = _SCANNER_OPERA_STOP;
					break;
				}

				to = (*pf)(_SCANNER_STATE_CATOR, NULL, &attr, 0, 0, 0, 0, NULL, 0, NULL, page, 0, 0, &tm, pp);
			}	
			continue;

			break;
		case _SCANNER_OPERA_NEXT:
			if (b_newline)
			{
				b_newline = 0;
				break;
			}
			if (b_newpage)
			{
				b_newpage = 0;
				break;
			}

			pch = NULL;
			xs.w = tm.char_w;
			xs.h = tm.char_h;
			chs = (*pit->pf_next_word)(pit->ctx, &pch, &xs, &b_ins, &b_del, &b_sel, &b_atom);
			if (!chs)
			{
				b_cancel = 1;
				break;
			}
			
			if (b_atom)
			{
				chs = xslen(pch);
			}

			org_obj = cur_obj;
			cur_obj = NULL;
			(*pit->pf_cur_object)(pit->ctx, &cur_obj);

			if (org_obj != cur_obj)
			{
				attr.ret = 0;
				(*pit->pf_object_attr)(pit->ctx, cur_obj, &attr);

				if ((attr.ret & OBJECT_ATTR_XFACE) && attr.pxa)
				{
					break_mode = parse_wrap(attr.pxa);

					if (is_null(attr.pxa->line_height))
						line_rati = xstof(DEF_GDI_TEXT_LINE_HEIGHT);
					else
						line_rati = xstof(attr.pxa->line_height);

					if (line_rati < 1)
						line_rati = 1.0;
				}

				if ((attr.ret & OBJECT_ATTR_XFONT) && attr.pxf)
				{
					(*pmv->mea->pf_measure_font)(pmv->ctx, attr.pxf, &se);
					tm.char_w = se.w;
					tm.char_h = se.h;
					tm.line_h = (int)((float)se.h * (line_rati - 1.0));
				}
			}

			break;
		case _SCANNER_OPERA_INS:
			xs.w = tm.char_w;
			xs.h = tm.char_h;
			if ((*pit->pf_insert_word)(pit->ctx, sch, &xs))
			{
				to = _SCANNER_OPERA_NEXT;
			}
			else
			{
				to = _SCANNER_OPERA_STOP;
			}
			continue;
		case _SCANNER_OPERA_DEL:
			if((*pit->pf_delete_word)(pit->ctx))
			{
				to = _SCANNER_OPERA_NEXT;
			}
			else
			{
				to = _SCANNER_OPERA_STOP;
			}
			continue;
		}

		if (b_cancel)
		{
			b_cancel = 0;

			chs = 0;
			sch[0] = 0;
			ts = _SCANNER_STATE_END;
		}
		else if (pch && *pch == _T('\r'))
		{
			chs = 0;
			xsncpy(sch, _T("\r"), 1);

			ts = _SCANNER_STATE_NEWLINE;
		}
		else if (pch && *pch == _T('\v'))
		{
			chs = 0;
			xsncpy(sch, _T("\v"), 1);

			ts = _SCANNER_STATE_NEWPAGE;
		}
		else if (pch && *pch == _T('\n'))
		{
			tm.cur_w = xs.w; //tm.char_w * 2;
			tm.cur_h = xs.h; // tm.char_h;

			chs = 1;
			xsncpy(sch, _T("\n"), chs);

			ts = _SCANNER_STATE_LINEBREAK;
		}
		else if (pch && *pch == _T('\f'))
		{
			tm.cur_w = xs.w; // tm.char_w * 2;
			tm.cur_h = xs.h; // tm.char_h;

			if (b_paging)
			{
				chs = 1;
				xsncpy(sch, _T("\f"), chs);

				ts = _SCANNER_STATE_PAGEBREAK;
			}
			else
			{
				chs = 1;
				xsncpy(sch, _T("\f"), chs);

				ts = _SCANNER_STATE_LINEBREAK;
			}
		}
		else
		{
			tm.cur_w = xs.w; // tm.char_w;
			tm.cur_h = xs.h; // tm.char_h;

			ts = _SCANNER_STATE_WORDS;
		}

		sch[0] = 0;

		switch (ts)
		{
		case _SCANNER_STATE_WORDS:
		case _SCANNER_STATE_LINEBREAK:
		case _SCANNER_STATE_PAGEBREAK:
			if (b_atom == 1)
				to = (*pf)(ts, cur_obj, &attr, b_atom, b_ins, b_del, b_sel, pch, chs, sch, page, row_at, col_at, &tm, pp);
			else if (b_atom == 2)
				to = (*pf)(ts, cur_obj, &attr, b_atom, b_ins, b_del, b_sel, pch, chs, sch, page, row_at, col_at, &tm, pp);
			else
				to = (*pf)(ts, cur_obj, &attr, b_atom, b_ins, b_del, b_sel, pch, chs, sch, page, row_at, col_at, &tm, pp);
			break;
		case _SCANNER_STATE_NEWLINE:
			to = (*pf)(ts, cur_obj, &attr, 0, 0, 0, 0, NULL, chs, NULL, page, row_at, col_at, &tm, pp);
			break;
		case _SCANNER_STATE_NEWPAGE:
			to = (*pf)(ts, cur_obj, &attr, 0, 0, 0, 0, NULL, chs, NULL, page, row_at, col_at, &tm, pp);
			break;
		case _SCANNER_STATE_END:
			to = (*pf)(ts, cur_obj, &attr, b_atom, b_ins, b_del, b_sel, NULL, chs, sch, page, row_at, col_at, &tm, pp);
			if (to != _SCANNER_OPERA_INS)
				to = _SCANNER_OPERA_STOP;
			break;
		}

		if (to != _SCANNER_OPERA_NEXT)
			continue;

		switch (ts)
		{
		case _SCANNER_STATE_WORDS:
			tm.cur_x += tm.cur_w;
			tm.cur_w = 0;

			col_at++;

			if (b_paging && (tm.cur_x - tm.char_w > tm.min_x) && (tm.cur_x + tm.char_w > tm.max_x) && (tm.cur_y + 2 * (tm.cur_h + tm.line_h) > tm.max_y))
			{
				ts = _SCANNER_STATE_NEWPAGE;
				b_newpage = 1;
				xsncpy(sch, _T("\v"), 1);
				pch = sch;
			}
			else if ((break_mode == WORD_BREAK) && (tm.cur_x - tm.char_w > tm.min_x) && (tm.cur_x + tm.char_w > tm.max_x))
			{
				ts = _SCANNER_STATE_NEWLINE;
				b_newline = 1;
				xsncpy(sch, _T("\r"), 1);
				pch = sch;
			}
			break;
		case _SCANNER_STATE_LINEBREAK:
			tm.cur_x += tm.cur_w;
			tm.cur_w = 0;

			col_at++;

			if (b_paging && (tm.cur_y + 2 * (tm.cur_h + tm.line_h) > tm.max_y))
			{
				ts = _SCANNER_STATE_NEWPAGE;
				b_newpage = 1;
				xsncpy(sch, _T("\v"), 1);
				pch = sch;
			}
			else if (break_mode == LINE_BREAK)
			{
				ts = _SCANNER_STATE_NEWLINE;
				b_newline = 1;
				xsncpy(sch, _T("\r"), 1);
				pch = sch;
			}
			break;
		case _SCANNER_STATE_PAGEBREAK:
			tm.cur_x += tm.cur_w;
			tm.cur_w = 0;

			col_at++;

			b_newpage = 1;
			xsncpy(sch, _T("\v"), 1);
			pch = sch;

			break;
		case _SCANNER_STATE_NEWLINE:
			tm.cur_y += (tm.cur_h + tm.line_h);
			tm.cur_x = tm.min_x + tm.char_w;
			tm.cur_h = 0;

			row_at++;
			col_at = 0;

			break;
		case _SCANNER_STATE_NEWPAGE:
			if ((*pit->pf_break_page)(pit->ctx))
			{
				page = (*pit->pf_next_page)(pit->ctx);
				
				tm.cur_x = tm.min_x + tm.char_w;
				tm.cur_y = tm.min_y + tm.line_h;

				row_at = 0;
				col_at = 0;

				to = (*pf)(_SCANNER_STATE_CATOR, NULL, &attr, 0, 0, 0, 0, NULL, 0, NULL, page, row_at, col_at, &tm, pp);
			}
			break;
		}
	}
}
