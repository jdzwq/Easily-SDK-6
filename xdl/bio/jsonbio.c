﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc json bio document

	@module	jsonbio.c | implement file

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

#include "jsonbio.h"

#include "../xdloop.h"
#include "../xdldoc.h"

bool_t parse_json_doc_from_memo(link_t_ptr json, link_t_ptr txt)
{
	opera_interface bo = { 0 };
	memo_opera_context to = { 0 };

	to.txt = txt;
	to.nlk = NULL;
	to.len = to.pos = 0;

	bo.ctx = (void*)&to;
	bo.max = 0;
	bo.encode = DEF_UCS;
	bo.pf_read_char = call_memo_read_char;
	bo.pf_can_escape = call_memo_can_escape;
	bo.pf_with_eof = call_memo_with_eof;

	return parse_json_doc_from_object(json, &bo);
}

bool_t format_json_doc_to_memo(link_t_ptr json, link_t_ptr txt)
{
	opera_interface bo = { 0 };
	memo_opera_context to = { 0 };

	to.txt = txt;
	to.nlk = NULL;
	to.len = to.pos = 0;

	bo.ctx = (void*)&to;
	bo.max = 0;
	bo.pos = 0;
	bo.encode = DEF_UCS;
	bo.pf_write_char = call_memo_write_char;
	bo.pf_write_token = call_memo_write_token;
	bo.pf_can_escape = call_memo_can_escape;
	bo.pf_write_carriage = call_memo_write_carriage;
	bo.pf_write_indent = call_memo_write_indent;

	return format_json_doc_to_object(json, &bo);
}

bool_t parse_json_doc_from_string(link_t_ptr json, string_t vs)
{
	opera_interface bo = { 0 };
	STRINGOBJECT to = { 0 };

	to.var = vs;
	to.pos = 0;

	bo.ctx = (void*)&to;
	bo.max = 0;
	bo.encode = DEF_UCS;
	bo.pf_read_char = call_string_read_char;
	bo.pf_can_escape = call_string_can_escape;
	bo.pf_with_eof = call_string_with_eof;

	return parse_json_doc_from_object(json, &bo);
}

bool_t format_json_doc_to_string(link_t_ptr json, string_t vs)
{
	opera_interface bo = { 0 };
	STRINGOBJECT to = { 0 };

	to.var = vs;
	to.pos = 0;

	bo.ctx = (void*)&to;
	bo.max = 0;
	bo.pos = 0;
	bo.encode = DEF_UCS;
	bo.pf_write_char = call_string_write_char;
	bo.pf_write_token = call_string_write_token;
	bo.pf_can_escape = call_string_can_escape;

	return format_json_doc_to_object(json, &bo);
}

bool_t parse_json_doc_from_stream(link_t_ptr json, stream_t xs)
{
	opera_interface bo = { 0 };
	int encode;

	encode = stream_get_encode(xs);

	if (encode == _UNKNOWN)
	{
		encode = _UTF8;
		stream_set_encode(xs, encode);
	}

	if (encode == _UTF16_LIT || encode == _UTF16_BIG)
	{
		stream_read_utfbom(xs, NULL);
	}

	bo.ctx = (void*)xs;
	bo.max = 0;
	bo.encode = encode;
	bo.pf_read_char = call_stream_read_char;
	bo.pf_read_escape = call_stream_read_escape;
	bo.pf_can_escape = call_stream_can_escape;
	bo.pf_set_encode = call_stream_set_encode;
	bo.pf_with_eof = call_stream_with_eof;

	return parse_json_doc_from_object(json, &bo);
}

bool_t format_json_doc_to_stream(link_t_ptr json, stream_t xs)
{
	opera_interface bo = { 0 };
	int encode;

	encode = stream_get_encode(xs);

	if (encode == _UTF16_LIT || encode == _UTF16_BIG)
	{
		stream_write_utfbom(xs, NULL);
	}

	bo.ctx = (void*)xs;
	bo.max = 0;
	bo.pos = 0;
	bo.encode = stream_get_encode(xs);
	bo.pf_write_char = call_stream_write_char;
	bo.pf_write_escape = call_stream_write_escape;
	bo.pf_write_token = call_stream_write_token;
	bo.pf_can_escape = call_stream_can_escape;

	return format_json_doc_to_object(json, &bo);
}

bool_t parse_json_doc_from_bytes(link_t_ptr json, const byte_t* str, dword_t len, int encode)
{
	opera_interface bo = { 0 };

	int bytes = 0;

	if (!str || !len)
		return 0;

	bytes = skip_utfbom(str);
	str += bytes;
	len -= bytes;

	bo.ctx = (void*)str;
	bo.max = len;
	bo.encode = encode;
	bo.isdom = 1;
	bo.pf_read_char = call_buffer_read_char;
	bo.pf_read_escape = call_buffer_read_escape;
	bo.pf_can_escape = call_buffer_can_escape;
	bo.pf_with_eof = call_buffer_with_eof;

	return parse_json_doc_from_object(json, &bo);
}

dword_t format_json_doc_to_bytes(link_t_ptr json, byte_t* buf, dword_t max, int encode)
{
	opera_interface bo = { 0 };

	dword_t total = 0;

	if (encode == _UTF16_LIT || encode == _UTF16_BIG)
	{
		total += format_utfbom(encode, ((buf) ? (buf + total) : NULL));
		if (total >= max)
			return total;

		max -= total;
		if (buf)
		{
			buf += total;
		}
	}

	bo.ctx = (void*)buf;
	bo.max = max;
	bo.pos = 0;
	bo.encode = encode;
	bo.pf_write_char = call_buffer_write_char;
	bo.pf_write_escape = call_buffer_write_escape;
	bo.pf_write_token = call_buffer_write_token;
	bo.pf_can_escape = call_buffer_can_escape;

	if (format_json_doc_to_object(json, &bo))
		return (bo.pos + total);
	else
		return 0;
}

