﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xml operator document

	@module	xmlopera.c | implement file

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

#include "xmltio.h"

#include "../xdldoc.h"


void call_write_xml_begin(void* pv)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	pop->stack = create_stack_table();
}

bool_t call_write_xml_head_attr(void* pv, const tchar_t* key, int klen, const tchar_t* val, int vlen)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	if (!pop->doc)
		return 0;

	if (!IS_XML_DOC(pop->doc))
		return 0;

	if (xsnicmp(XML_ATTR_ENCODING, key, klen) == 0)
		set_xml_encoding(pop->doc, val, vlen);
	else if (xsnicmp(XML_ATTR_VERSION, key, klen) == 0)
		set_xml_version(pop->doc, val, vlen);

	return 1;
}

bool_t call_write_xml_node_begin(void* pv)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	push_stack_node(pop->stack, (void*)pop->nlk);

	if (!pop->nlk)
		pop->nlk = IS_XML_DOC(pop->doc) ? get_xml_dom_node(pop->doc) : pop->doc;
	else
		pop->nlk = insert_dom_node(pop->nlk, LINK_LAST);

	return 1;
}

bool_t call_write_xml_node_retain(void* pv)
{
	xml_opera_context* pop = (xml_opera_context*)pv;
	link_t_ptr plk;

	plk = (link_t_ptr)peek_stack_node(pop->stack, -1);
	if (!plk)
		plk = IS_XML_DOC(pop->doc) ? get_xml_dom_node(pop->doc) : pop->doc;

	pop->nlk = insert_dom_node(plk, LINK_LAST);

	return 1;
}

bool_t call_write_xml_node_end(void* pv)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	pop->nlk = (pop->stack) ? (link_t_ptr)pop_stack_node(pop->stack) : NULL;

	if (!pop->nlk)
		return 0;

	return 1;
}

link_t_ptr call_peek_xml_node(void* pv)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	if (!pop->stack)
		return NULL;

	return peek_stack_node(pop->stack, -1);
}

bool_t call_write_xml_node_name(void* pv, const tchar_t* ns, int nslen, const tchar_t* na, int nalen)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	if (!pop->nlk)
		return 0;

	if (is_null(ns) || !nslen)
	{
		set_dom_node_name(pop->nlk, na, nalen);
	}
	else
	{
		set_dom_node_ns(pop->nlk, ns, nslen);
		set_dom_node_name(pop->nlk, na, nalen);
	}

	return 1;
}

bool_t call_write_xml_node_attr(void* pv, const tchar_t* key, int klen, const tchar_t* val, int vlen)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	if (!pop->nlk)
		return 0;

	set_dom_node_attr(pop->nlk, key, klen, val, vlen);

	return 1;
}

bool_t call_write_xml_node_xmlns(void* pv, const tchar_t* key, int klen, const tchar_t* val, int vlen)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	if (!pop->nlk)
		return 0;

	set_dom_node_xmlns(pop->nlk, key, klen, val, vlen);

	return 1;
}

bool_t call_write_xml_node_text(void* pv, bool_t b_cdata, const tchar_t* text, int len)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	if (!pop->nlk)
		return 0;

	set_dom_node_text(pop->nlk, text, len);

	if (b_cdata)
	{
		set_dom_node_cdata(pop->nlk, 1);
	}

	return 1;
}

bool_t call_write_xml_node_mask(void* pv, dword_t mask, bool_t b_check)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	if (!pop->nlk)
		return 0;

	set_dom_node_mask_check(pop->nlk, mask, b_check);

	return 1;
}

bool_t call_peek_xml_node_mask(void* pv, dword_t mask)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	if (!pop->nlk)
		return 0;

	return get_dom_node_mask_check(pop->nlk, mask);
}

const tchar_t* call_peek_xml_node_name(void* pv)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	if (!pop->nlk)
		return NULL;

	return get_dom_node_name_ptr(pop->nlk);
}

void call_write_xml_end(void* pv, int code)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	if (pop->stack)
	{
		destroy_stack_table(pop->stack);
		pop->stack = NULL;
	}
}

bool_t call_write_xml_has_node(void* pv)
{
	xml_opera_context* pop = (xml_opera_context*)pv;

	return (pop->nlk) ? 1 : 0;
}

/************************************************************************************************************/

bool_t call_read_xml_head_begin(void* pv)
{
	opera_interface* pb = (opera_interface*)pv;
	int pos = 0;
	bool_t b_ns = 0;

	pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, _T("<?xml "), -1);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	return 1;
}

bool_t call_read_xml_head_attr(void* pv, const tchar_t* key, const tchar_t* val)
{
	opera_interface* pb = (opera_interface*)pv;
	tchar_t pch[2] = { 0 };
	int pos = 0;

	pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, key, -1);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	pch[0] = _T('=');
	pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	pch[0] = _T('\"');
	pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	while (val && *val)
	{
		pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, val);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;
		val++;
	}

	pch[0] = _T('\"');
	pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	pch[0] = _T(' ');
	pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	return 1;
}

bool_t call_read_xml_head_end(void* pv)
{
	opera_interface* pb = (opera_interface*)pv;
	int pos = 0;

	pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, _T("?>"), -1);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	return 1;
}

bool_t call_read_xml_node_attr(void* pv, const tchar_t* key, const tchar_t* val)
{
	opera_interface* pb = (opera_interface*)pv;
	bool_t b_esc;
	tchar_t pch[2] = { 0 };
	int pos = 0;

	b_esc = (*pb->pf_can_escape)(pb->ctx);

	pch[0] = _T(' ');
	pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, key, -1);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	pch[0] = _T('=');
	pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	pch[0] = _T('\"');
	pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	while (val && *val)
	{
		if (b_esc && _IsEscapeChar(*val))
		{
			pch[0] = _T('&');
			pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
			if (pos == C_ERR)
			{
				pb->pos = C_ERR;
				return 0;
			}
			pb->pos += pos;

			pos = (*pb->pf_write_escape)(pb->ctx, pb->max, pb->pos, pb->encode, *val);
			if (pos == C_ERR)
			{
				pb->pos = C_ERR;
				return 0;
			}
			pb->pos += pos;

			val++;
		}
		else
		{
			pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, val);
			if (pos == C_ERR)
			{
				pb->pos = C_ERR;
				return 0;
			}
			pb->pos += pos;
#ifdef _UNICODE
			val += ucs_sequence(*(val));
#else
			val += mbs_sequence(*(val));
#endif
		}
	}

	pch[0] = _T('\"');
	pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	return 1;
}

bool_t call_read_xml_node_begin(void* pv, int indent, bool_t b_parent, const tchar_t* ns, const tchar_t* nn)
{
	opera_interface* pb = (opera_interface*)pv;
	tchar_t pch[2] = { 0 };
	int pos = 0;
	bool_t b_ns = 0;

	if (pb->pf_write_carriage)
	{
		pos = (*pb->pf_write_carriage)(pb->ctx, pb->max, pb->pos, pb->encode);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;
	}

	while (indent && pb->pf_write_indent)
	{
		pos = (*pb->pf_write_indent)(pb->ctx, pb->max, pb->pos, pb->encode);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;

		indent--;
	}

	pch[0] = _T('<');
	pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	if (!is_null(ns))
		b_ns = 1;

	if (b_ns)
	{
		pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, ns, -1);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;

		pch[0] = _T(':');
		pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;
	}

	pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, nn, -1);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	return 1;
}

bool_t call_read_xml_node_close(void* pv, int indent, bool_t b_parent)
{
	opera_interface* pb = (opera_interface*)pv;
	tchar_t pch[2] = { 0 };
	int pos = 0;

	pch[0] = _T('>');
	pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
	if (pos == C_ERR)
	{
		pb->pos = C_ERR;
		return 0;
	}
	pb->pos += pos;

	return 1;
}

bool_t call_read_xml_node_text(void* pv, bool_t b_cdata, const tchar_t* text, int len)
{
	opera_interface* pb = (opera_interface*)pv;
	tchar_t pch[2] = { 0 };
	bool_t b_esc;
	int i, pos = 0;

	if (len < 0)
		len = xslen(text);

	if (!len)
		return 1;

	if (b_cdata)
	{
		pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, _T("<!"), -1);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;

		pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, CDATA_HEAD, -1);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;
	}

	if (b_cdata)
	{
		pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, text, len);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;

		pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, CDATA_TAIL, -1);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;

		pch[0] = _T('>');
		pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;
	}
	else
	{
		b_esc = (*pb->pf_can_escape)(pb->ctx);

		for (i = 0; i < len;)
		{
			if (b_esc && _IsEscapeChar(text[i]))
			{
				pch[0] = _T('&');
				pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
				if (pos == C_ERR)
				{
					pb->pos = C_ERR;
					return 0;
				}
				pb->pos += pos;

				pos = (*pb->pf_write_escape)(pb->ctx, pb->max, pb->pos, pb->encode, text[i]);
				if (pos == C_ERR)
				{
					pb->pos = C_ERR;
					return 0;
				}
				i++;
				pb->pos += pos;
			}
			else
			{
				pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, text + i);
				if (pos == C_ERR)
				{
					pb->pos = C_ERR;
					return 0;
				}
#ifdef _UNICODE
				i += ucs_sequence(*(text + i));
#else
				i += mbs_sequence(*(text + i));
#endif
				pb->pos += pos;
			}
		}
	}

	return 1;
}

bool_t call_read_xml_node_end(void* pv, int indent, bool_t b_parent, bool_t b_close, const tchar_t* ns, const tchar_t* nn)
{
	opera_interface* pb = (opera_interface*)pv;
	tchar_t pch[2] = { 0 };
	int pos = 0;
	bool_t b_ns = 0;

	if (b_close)
	{
		if (b_parent && pb->pf_write_carriage)
		{
			pos = (*pb->pf_write_carriage)(pb->ctx, pb->max, pb->pos, pb->encode);
			if (pos == C_ERR)
			{
				pb->pos = C_ERR;
				return 0;
			}
			pb->pos += pos;
		}

		while (b_parent && indent && pb->pf_write_indent)
		{
			pos = (*pb->pf_write_indent)(pb->ctx, pb->max, pb->pos, pb->encode);
			if (pos == C_ERR)
			{
				pb->pos = C_ERR;
				return 0;
			}
			pb->pos += pos;

			indent--;
		}

		pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, _T("</"), -1);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;

		if (!is_null(ns))
			b_ns = 1;

		if (b_ns)
		{
			pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, ns, -1);
			if (pos == C_ERR)
			{
				pb->pos = C_ERR;
				return 0;
			}
			pb->pos += pos;

			pch[0] = _T(':');
			pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
			if (pos == C_ERR)
			{
				pb->pos = C_ERR;
				return 0;
			}
			pb->pos += pos;
		}

		pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, nn, -1);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;

		pch[0] = _T('>');
		pos = (*pb->pf_write_char)(pb->ctx, pb->max, pb->pos, pb->encode, pch);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;
	}
	else
	{
		pos = (*pb->pf_write_token)(pb->ctx, pb->max, pb->pos, pb->encode, _T("/>"), -1);
		if (pos == C_ERR)
		{
			pb->pos = C_ERR;
			return 0;
		}
		pb->pos += pos;
	}

	return 1;
}
