/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc tag text doc document

	@module	tagdoc.c | implement file

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

#include "tagdoc.h"

#include "../xdldoc.h"


link_t_ptr create_tag_doc()
{
	link_t_ptr ptr;

	ptr = create_dom_doc();
	set_dom_node_name(ptr, DOC_TAG, -1);

	return ptr;
}

void destroy_tag_doc(link_t_ptr ptr)
{
	destroy_dom_doc(ptr);
}

bool_t is_tag_doc(link_t_ptr ptr)
{
	return (compare_text(get_dom_node_name_ptr(ptr), -1, DOC_TAG, -1, 0) == 0) ? 1 : 0;
}

void clear_tag_doc(link_t_ptr ptr)
{
	delete_dom_child_nodes(ptr);
}

link_t_ptr tag_doc_from_node(link_t_ptr nlk)
{
	while (nlk && compare_text(get_dom_node_name_ptr(nlk), -1, DOC_TAG, -1, 0) != 0)
	{
		nlk = get_dom_parent_node(nlk);
	}

	return nlk;
}

bool_t is_tag_chapter(link_t_ptr plk)
{
	return (compare_text(get_dom_node_name_ptr(plk), -1, DOC_TAG_CHAPTER, -1, 0) == 0) ? 1 : 0;
}

int get_tag_chapter_count(link_t_ptr ptr)
{
	XDK_ASSERT(ptr && is_tag_doc(ptr));

	return get_dom_child_node_count(ptr);
}

link_t_ptr insert_tag_chapter(link_t_ptr ptr, link_t_ptr pos)
{
	link_t_ptr nlk;

	XDK_ASSERT(ptr && is_tag_doc(ptr));

	nlk = insert_dom_node(ptr, pos);

	set_dom_node_name(nlk, DOC_TAG_CHAPTER, -1);

	return nlk;
}

link_t_ptr get_tag_next_chapter(link_t_ptr ptr, link_t_ptr pos)
{
	XDK_ASSERT(ptr && is_tag_doc(ptr));

	if (pos == LINK_FIRST)
		return get_dom_first_child_node(ptr);
	else if (pos == LINK_LAST)
		return get_dom_last_child_node(ptr);
	else
		return get_dom_next_sibling_node(pos);
}

link_t_ptr get_tag_prev_chapter(link_t_ptr ptr, link_t_ptr pos)
{
	XDK_ASSERT(ptr && is_tag_doc(ptr));

	if (pos == LINK_FIRST)
		return get_dom_first_child_node(ptr);
	else if (pos == LINK_LAST)
		return get_dom_last_child_node(ptr);
	else
		return get_dom_prev_sibling_node(pos);
}

bool_t is_tag_paragraph(link_t_ptr plk)
{
	return (compare_text(get_dom_node_name_ptr(plk), -1, DOC_TAG_PARAGRAPH, -1, 0) == 0) ? 1 : 0;
}

int get_tag_paragraph_count(link_t_ptr plk)
{
	XDK_ASSERT(plk && is_tag_chapter(plk));

	return get_dom_child_node_count(plk);
}

link_t_ptr insert_tag_paragraph(link_t_ptr plk, link_t_ptr pos)
{
	link_t_ptr nlk;

	XDK_ASSERT(plk && is_tag_chapter(plk));

	nlk = insert_dom_node(plk, pos);

	set_dom_node_name(nlk, DOC_TAG_PARAGRAPH, -1);

	return nlk;
}

link_t_ptr get_tag_next_paragraph(link_t_ptr plk, link_t_ptr pos)
{
	XDK_ASSERT(plk && is_tag_chapter(plk));

	if (pos == LINK_FIRST)
		return get_dom_first_child_node(plk);
	else if (pos == LINK_LAST)
		return get_dom_last_child_node(plk);
	else
		return get_dom_next_sibling_node(pos);
}

link_t_ptr get_tag_prev_paragraph(link_t_ptr plk, link_t_ptr pos)
{
	XDK_ASSERT(plk && is_tag_chapter(plk));

	if (pos == LINK_FIRST)
		return get_dom_first_child_node(plk);
	else if (pos == LINK_LAST)
		return get_dom_last_child_node(plk);
	else
		return get_dom_prev_sibling_node(pos);
}

bool_t is_tag_sentence(link_t_ptr plk)
{
	return (compare_text(get_dom_node_name_ptr(plk), -1, DOC_TAG_SENTENCE, -1, 0) == 0) ? 1 : 0;
}

int get_tag_setence_count(link_t_ptr plk)
{
	XDK_ASSERT(plk && is_tag_paragraph(plk));

	return get_dom_child_node_count(plk);
}

link_t_ptr insert_tag_sentence(link_t_ptr plk, link_t_ptr pos)
{
	link_t_ptr nlk;

	XDK_ASSERT(plk && is_tag_paragraph(plk));

	nlk = insert_dom_node(plk, pos);

	set_dom_node_name(nlk, DOC_TAG_SENTENCE, -1);

	return nlk;
}

link_t_ptr get_tag_next_sentence(link_t_ptr plk, link_t_ptr pos)
{
	XDK_ASSERT(plk && is_tag_paragraph(plk));

	if (pos == LINK_FIRST)
		return get_dom_first_child_node(plk);
	else if (pos == LINK_LAST)
		return get_dom_last_child_node(plk);
	else
		return get_dom_next_sibling_node(pos);
}

link_t_ptr get_tag_prev_sentence(link_t_ptr plk, link_t_ptr pos)
{
	XDK_ASSERT(plk && is_tag_paragraph(plk));

	if (pos == LINK_FIRST)
		return get_dom_first_child_node(plk);
	else if (pos == LINK_LAST)
		return get_dom_last_child_node(plk);
	else
		return get_dom_prev_sibling_node(pos);
}

bool_t is_tag_phrase(link_t_ptr plk)
{
	return (compare_text(get_dom_node_name_ptr(plk), -1, DOC_TAG_PHRASE, -1, 0) == 0) ? 1 : 0;
}

int get_tag_phrase_count(link_t_ptr plk)
{
	XDK_ASSERT(plk && is_tag_sentence(plk));

	return get_dom_child_node_count(plk);
}

link_t_ptr insert_tag_phrase(link_t_ptr plk, link_t_ptr pos)
{
	link_t_ptr nlk;

	XDK_ASSERT(plk && is_tag_sentence(plk));

	nlk = insert_dom_node(plk, pos);

	set_dom_node_name(nlk, DOC_TAG_PHRASE, -1);

	return nlk;
}

link_t_ptr get_tag_next_phrase(link_t_ptr plk, link_t_ptr pos)
{
	XDK_ASSERT(plk && is_tag_sentence(plk));

	if (pos == LINK_FIRST)
		return get_dom_first_child_node(plk);
	else if (pos == LINK_LAST)
		return get_dom_last_child_node(plk);
	else
		return get_dom_next_sibling_node(pos);
}

link_t_ptr get_tag_prev_phrase(link_t_ptr plk, link_t_ptr pos)
{
	XDK_ASSERT(plk && is_tag_sentence(plk));

	if (pos == LINK_FIRST)
		return get_dom_first_child_node(plk);
	else if (pos == LINK_LAST)
		return get_dom_last_child_node(plk);
	else
		return get_dom_prev_sibling_node(pos);
}

void delete_tag_node(link_t_ptr nlk)
{
	delete_dom_node(nlk);
}

link_t_ptr get_tag_next_leaf_node(link_t_ptr ptr, link_t_ptr pos, bool_t add)
{
	link_t_ptr plk, nlk = NULL;

	if (pos == LINK_FIRST)
	{
		plk = get_tag_next_chapter(ptr, LINK_FIRST);
		if (plk)
		{
			plk = get_tag_next_paragraph(plk, LINK_FIRST);
			if (plk)
			{
				plk = get_tag_next_sentence(plk, LINK_FIRST);
				if (plk)
				{
					nlk = get_tag_next_phrase(plk, LINK_FIRST);
				}
			}
		}
	}
	else if (pos == LINK_LAST)
	{
		plk = get_tag_next_chapter(ptr, LINK_LAST);
		if (plk)
		{
			plk = get_tag_next_paragraph(plk, LINK_LAST);
			if (plk)
			{
				plk = get_tag_next_sentence(plk, LINK_LAST);
				if (plk)
				{
					nlk = get_tag_next_phrase(plk, LINK_LAST);
				}
			}
		}
	}
	else
	{
		plk = get_dom_parent_node(pos); //sentence
		nlk = get_tag_next_phrase(plk, pos);
		if (!nlk)
		{
			pos = plk;
			plk = get_dom_parent_node(plk); // paragraph
			plk = get_tag_next_sentence(plk, pos);

		}
	}

	if (!add)
		return NULL;

	if (nlk && is_tag_chapter(nlk))
	{
		plk = nlk;
		plk = insert_tag_paragraph(plk, LINK_LAST);
		plk = insert_tag_sentence(plk, LINK_LAST);
		nlk = insert_tag_phrase(plk, LINK_LAST);

		return nlk;
	}
	
	if (nlk && is_tag_paragraph(nlk))
	{
		plk = nlk;
		plk = insert_tag_sentence(plk, LINK_LAST);
		nlk = insert_tag_phrase(plk, LINK_LAST);

		return nlk;
	}

	if (nlk && is_tag_sentence(nlk))
	{
		plk = nlk;
		nlk = insert_tag_phrase(plk, LINK_LAST);

		return nlk;
	}

	plk = insert_tag_chapter(ptr, LINK_LAST);
	plk = insert_tag_paragraph(plk, LINK_LAST);
	plk = insert_tag_sentence(plk, LINK_LAST);
	nlk = insert_tag_phrase(plk, LINK_LAST);

	return nlk;
}

link_t_ptr get_tag_prev_leaf_node(link_t_ptr ptr, link_t_ptr pos, bool_t add)
{
	link_t_ptr plk, nlk;

	nlk = get_dom_next_leaf_node(ptr, pos);
	if (nlk && is_tag_phrase(nlk))
		return nlk;

	if (!add)
		return NULL;

	if (nlk && is_tag_chapter(nlk))
	{
		plk = nlk;
		plk = insert_tag_paragraph(plk, LINK_FIRST);
		plk = insert_tag_sentence(plk, LINK_FIRST);
		nlk = insert_tag_phrase(plk, LINK_FIRST);

		return nlk;
	}

	if (nlk && is_tag_paragraph(nlk))
	{
		plk = nlk;
		plk = insert_tag_sentence(plk, LINK_FIRST);
		nlk = insert_tag_phrase(plk, LINK_FIRST);

		return nlk;
	}

	if (nlk && is_tag_sentence(nlk))
	{
		plk = nlk;
		nlk = insert_tag_phrase(plk, LINK_FIRST);

		return nlk;
	}

	plk = insert_tag_chapter(ptr, LINK_FIRST);
	plk = insert_tag_paragraph(plk, LINK_FIRST);
	plk = insert_tag_sentence(plk, LINK_FIRST);
	nlk = insert_tag_phrase(plk, LINK_FIRST);

	return nlk;
}

link_t_ptr merge_tag_chapter(link_t_ptr plk)
{
	link_t_ptr nxt, nlk;

	XDK_ASSERT(plk && is_tag_chapter(plk));

	nxt = get_next_link(plk);
	if (!nxt)
		return NULL;

	while (nlk = detach_dom_node(nxt, LINK_FIRST))
	{
		attach_dom_node(plk, LINK_LAST, nlk);
	}

	delete_tag_node(nxt);

	return plk;
}

link_t_ptr split_tag_chapter(link_t_ptr plk, link_t_ptr nlk)
{
	link_t_ptr dtr, ptr, ppk;

	XDK_ASSERT(plk && is_tag_chapter(plk));
	XDK_ASSERT(nlk && is_tag_paragraph(nlk));

	ptr = get_dom_parent_node(plk);
	dtr = insert_tag_chapter(ptr, plk);

	while (nlk)
	{
		ppk = get_dom_next_sibling_node(nlk);

		nlk = detach_dom_node(plk, nlk);
		attach_dom_node(dtr, LINK_LAST, nlk);

		nlk = ppk;
	}

	return dtr;
}

link_t_ptr merge_tag_paragraph(link_t_ptr plk)
{
	link_t_ptr nxt, nlk;

	XDK_ASSERT(plk && is_tag_paragraph(plk));

	nxt = get_next_link(plk);
	if (!nxt)
		return NULL;

	while (nlk = detach_dom_node(nxt, LINK_FIRST))
	{
		attach_dom_node(plk, LINK_LAST, nlk);
	}

	delete_tag_node(nxt);

	return plk;
}

link_t_ptr split_tag_paragraph(link_t_ptr plk, link_t_ptr nlk)
{
	link_t_ptr dtr, ptr, ppk;

	XDK_ASSERT(plk && is_tag_paragraph(plk));
	XDK_ASSERT(nlk && is_tag_sentence(nlk));

	ptr = get_dom_parent_node(plk);
	dtr = insert_tag_paragraph(ptr, plk);

	while (nlk)
	{
		ppk = get_dom_next_sibling_node(nlk);

		nlk = detach_dom_node(plk, nlk);
		attach_dom_node(dtr, LINK_LAST, nlk);

		nlk = ppk;
	}

	return dtr;
}

link_t_ptr merge_tag_sentence(link_t_ptr plk)
{
	link_t_ptr nxt, nlk;

	XDK_ASSERT(plk && is_tag_sentence(plk));

	nxt = get_next_link(plk);
	if (!nxt)
		return NULL;

	while (nlk = detach_dom_node(nxt, LINK_FIRST))
	{
		attach_dom_node(plk, LINK_LAST, nlk);
	}

	delete_tag_node(nxt);

	return plk;
}

link_t_ptr split_tag_sentence(link_t_ptr plk, link_t_ptr nlk)
{
	link_t_ptr dtr, ptr, ppk;

	XDK_ASSERT(plk && is_tag_sentence(plk));
	XDK_ASSERT(nlk && is_tag_phrase(nlk));

	ptr = get_dom_parent_node(plk);
	dtr = insert_tag_sentence(ptr, plk);

	while (nlk)
	{
		ppk = get_dom_next_sibling_node(nlk);

		nlk = detach_dom_node(plk, nlk);
		attach_dom_node(dtr, LINK_LAST, nlk);

		nlk = ppk;
	}

	return dtr;
}

link_t_ptr merge_tag_phrase(link_t_ptr nlk)
{
	link_t_ptr nxt;
	int n;
	tchar_t* buf;

	XDK_ASSERT(nlk && is_tag_phrase(nlk));

	nxt = get_next_link(nlk);
	if (!nxt)
		return NULL;

	n = xslen(get_tag_phrase_text_ptr(nlk)) + xslen(get_tag_phrase_text_ptr(nxt));

	if (n)
	{
		buf = detach_dom_node_text(nlk);
		buf = xsrealloc(buf, n + 1);
		xscat(buf, get_tag_phrase_text_ptr(nxt));

		attach_dom_node_text(nlk, buf);
	}

	delete_tag_node(nxt);

	return nlk;
}

link_t_ptr split_tag_phrase(link_t_ptr nlk, int pos)
{
	link_t_ptr dlk, plk;
	tchar_t *buf, *str;
	int len;

	XDK_ASSERT(nlk && is_tag_phrase(nlk));

	plk = get_dom_parent_node(nlk);
	dlk = insert_tag_phrase(plk, nlk);

	buf = detach_dom_node_text(nlk);
	len = xslen(buf);
	if (pos < 0)
		pos = len;
	else
		pos = (pos < len) ? pos : len;

	if (len - pos)
	{
		str = xsalloc(len - pos + 1);
		xsncpy(str, (buf + pos), len - pos);
		attach_dom_node_text(dlk, str);
	}

	buf[pos] = _T('\0');
	attach_dom_node_text(nlk, buf);

	return dlk;
}

int format_tag_doc(link_t_ptr ptr, tchar_t* buf, int max)
{
	link_t_ptr clk, plk, slk, rlk;
	int len, total = 0;
	const tchar_t *sz_text;

	clk = get_tag_next_chapter(ptr, LINK_FIRST);
	while (clk)
	{
		if (total + 2 > max)
			return total;

		if (buf)
		{
			buf[total] = _T('\\');
			buf[total + 1] = _T('#');
		}
		total += 2;

		sz_text = get_tag_chapter_title_ptr(clk);
		len = xslen(sz_text);

		if (total + len > max)
			return total;

		if (buf)
		{
			xsncpy((buf + total), sz_text, len);
		}
		total += len;

		plk = get_tag_next_paragraph(clk, LINK_FIRST);
		while (plk)
		{
			if (total + 2 > max)
				return total;

			if (buf)
			{
				buf[total] = _T('\\');
				buf[total + 1] = _T('$');
			}
			total += 2;

			slk = get_tag_next_sentence(plk, LINK_FIRST);
			while (slk)
			{
				if (total + 2 > max)
					return total;

				if (buf)
				{
					buf[total] = _T('\\');
					buf[total + 1] = _T('&');
				}
				total += 2;

				rlk = get_tag_next_phrase(slk, LINK_FIRST);
				while (rlk)
				{
					if (total + 2 > max)
						return total;

					if (buf)
					{
						buf[total] = _T('\\');
						buf[total + 1] = _T('~');
					}
					total += 2;

					sz_text = get_tag_phrase_text_ptr(rlk);
					len = xslen(sz_text);

					if (total + len > max)
						return total;

					if (buf)
					{
						xsncpy((buf + total), sz_text, len);
					}
					total += len;

					rlk = get_tag_next_phrase(slk, rlk);
				}

				slk = get_tag_next_sentence(plk, slk);
			}

			plk = get_tag_next_paragraph(clk, plk);
		}

		clk = get_tag_next_chapter(ptr, clk);
	}

	return total;
}

bool_t parse_tag_doc(link_t_ptr ptr, const tchar_t* buf, int len)
{
	link_t_ptr clk, plk, slk, rlk;
	const tchar_t *tk_text;
	int len_text, total = 0;

	if (len < 0)
		len = xslen(buf);

	clear_tag_doc(ptr);

	while (total < len)
	{
		if (*(buf + total) == _T('\\') && *(buf + total + 1) == _T('#'))
		{
			clk = insert_tag_chapter(ptr, LINK_LAST);
			total += 2;

			plk = slk = rlk= NULL;

			tk_text = buf + total;
			len_text = 0;
			while (*(buf + total) != _T('\\') && *(buf + total) != _T('\0'))
			{
				len_text++;
			}
			set_tag_chapter_title(clk, tk_text, len_text);

			total += len_text;
		}

		if (*(buf + total) == _T('\\') && *(buf + total + 1) == _T('$'))
		{
			if (!clk)
				clk = insert_tag_chapter(ptr, LINK_LAST);

			plk = insert_tag_paragraph(clk, LINK_LAST);
			total += 2;

			slk = rlk = NULL;
		}

		if (*(buf + total) == _T('\\') && *(buf + total + 1) == _T('&'))
		{
			if (!clk)
				clk = insert_tag_chapter(ptr, LINK_LAST);

			if (!plk)
				plk = insert_tag_paragraph(clk, LINK_LAST);

			slk = insert_tag_sentence(plk, LINK_LAST);
			total += 2;

			rlk = NULL;
		}

		if (*(buf + total) == _T('\\') && *(buf + total + 1) == _T('~'))
		{
			if (!clk)
				clk = insert_tag_chapter(ptr, LINK_LAST);

			if (!plk)
				plk = insert_tag_paragraph(clk, LINK_LAST);

			if (!slk)
				slk = insert_tag_sentence(plk, LINK_LAST);

			rlk = insert_tag_phrase(slk, LINK_LAST);
			total += 2;

			tk_text = buf + total;
			len_text = 0;
			while (*(buf + total) != _T('\\') && *(buf + total) != _T('\0'))
			{
				len_text++;
			}
			set_tag_phrase_text(clk, tk_text, len_text);

			total += len_text;
		}
	}

	return 1;
}

bool_t is_tag_text_reserve(tchar_t ch)
{
	return (ch == _T('\\')) ? 1 : 0;
}
