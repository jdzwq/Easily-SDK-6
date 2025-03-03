﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc buffer operator document

	@module	bufferopera.c | implement file

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

#include "buffertio.h"


bool_t call_buffer_can_escape(void* p_obj)
{
	return 1;
}

bool_t call_buffer_with_eof(void* p_obj)
{
	return 1;
}

int call_buffer_read_escape(void* p_obj, int max, int pos, int encode, tchar_t* pch)
{
	byte_t* buf = (byte_t*)p_obj + pos;

	if (pos >= max)
	{
		*pch = _T('\0');
		return 0;
	}

	switch (encode)
	{
	case _UTF16_LIT:
		return (int)xml_utf16lit_decode(buf, pch);
	case _UTF16_BIG:
		return (int)xml_utf16big_decode(buf, pch);
	case _GB2312:
		return (int)xml_gb2312_decode(buf, pch);
	case _UTF8:
		return (int)xml_utf8_decode(buf, pch);
	default:
		return (int)xml_unn_decode(buf, pch);
	}

	return 0;
}

int call_buffer_write_escape(void* p_obj, int max, int pos, int encode, tchar_t ch)
{
	byte_t* buf = (p_obj) ? ((byte_t*)p_obj + pos) : NULL;

	switch (encode)
	{
	case _UTF16_LIT:
		return (int)xml_utf16lit_encode(ch, buf, max - pos);
	case _UTF16_BIG:
		return (int)xml_utf16big_encode(ch, buf, max - pos);
	case _GB2312:
		return (int)xml_gb2312_encode(ch, buf, max - pos);
	case _UTF8:
		return (int)xml_utf8_encode(ch, buf, max - pos);
	default:
		return (int)xml_unn_encode(ch, buf, max - pos);
	}

	return 0;
}

int call_buffer_read_char(void* p_obj, int max, int pos, int encode, tchar_t* pch)
{
	byte_t* buf = (byte_t*)p_obj + pos;

	if (pos >= max)
	{
		*pch = _T('\0');
		return 0;
	}

	switch (encode)
	{
	case _UTF16_LIT:
		pos = utf16_sequence(*(buf));
#ifdef _UNICODE
		utf16lit_byte_to_ucs(buf, pch);
#else
		utf16lit_byte_to_mbs(buf, pch);
#endif
		break;
	case _UTF16_BIG:
		pos = utf16_sequence(*(buf));
#ifdef _UNICODE
		utf16big_byte_to_ucs(buf, pch);
#else
		utf16big_byte_to_mbs(buf, pch);
#endif
		break;
	case _GB2312:
		pos = gb2312_sequence(*(buf));
#ifdef _UNICODE
		gb2312_byte_to_ucs(buf, pch);
#else
		gb2312_byte_to_mbs(buf, pch);
#endif 
		break;
	case _UTF8:
		pos = utf8_sequence(*(buf));
#ifdef _UNICODE
		utf8_byte_to_ucs(buf, pch);
#else
		utf8_byte_to_mbs(buf, pch);
#endif
		break;
	default:
		pos = unn_sequence(*(buf));
#ifdef _UNICODE
		unn_byte_to_ucs(buf, pch);
#else
		unn_byte_to_mbs(buf, pch);
#endif
		break;
	}

	return pos;
}

int call_buffer_read_token(void* p_obj, int max, int pos, int encode, tchar_t* pch, int len)
{
	byte_t* buf = (byte_t*)p_obj + pos;
	int ret;

	max -= pos;
	pos = 0;

	while (len > 0)
	{
		if (pos >= max)
		{
			*pch = _T('\0');
			return 0;
		}

		switch (encode)
		{
		case _UTF16_LIT:
			pos += utf16_sequence(*(buf));
#ifdef _UNICODE
			ret = utf16lit_byte_to_ucs(buf, pch);
#else
			ret = utf16lit_byte_to_mbs(buf, pch);
#endif
			break;
		case _UTF16_BIG:
			pos += utf16_sequence(*(buf));
#ifdef _UNICODE
			ret = utf16big_byte_to_ucs(buf, pch);
#else
			ret = utf16big_byte_to_mbs(buf, pch);
#endif
			break;
		case _GB2312:
			pos += gb2312_sequence(*(buf));
#ifdef _UNICODE
			ret = gb2312_byte_to_ucs(buf, pch);
#else
			ret = gb2312_byte_to_mbs(buf, pch);
#endif
			break;
		case _UTF8:
			pos += utf8_sequence(*(buf));
#ifdef _UNICODE
			ret = utf8_byte_to_ucs(buf, pch);
#else
			ret = utf8_byte_to_mbs(buf, pch);
#endif
			break;
		default:
#ifdef _UNICODE
			ret = unn_byte_to_ucs(buf, pch);
#else
			ret = unn_byte_to_mbs(buf, pch);
#endif
			break;
		}

		buf += pos;
		pch += ret;
		len -= ret;
	}

	return pos;
}

int call_buffer_write_char(void* p_obj, int max, int pos, int encode, const tchar_t* pch)
{
	byte_t* buf = (p_obj) ? ((byte_t*)p_obj + pos) : NULL;

	switch (encode)
	{
	case _UTF16_LIT:
#ifdef _UNICODE
		pos = ucs_byte_to_utf16lit(*pch, buf);
#else
		pos = mbs_byte_to_utf16lit(pch, buf);
#endif
		break;
	case _UTF16_BIG:
#ifdef _UNICODE
		pos = ucs_byte_to_utf16big(*pch, buf);
#else
		pos = mbs_byte_to_utf16big(pch, buf);
#endif
		break;
	case _GB2312:
#ifdef _UNICODE
		pos = ucs_byte_to_gb2312(*pch, buf);
#else
		pos = mbs_byte_to_gb2312(pch, buf);
#endif
		break;
	case _UTF8:
#ifdef _UNICODE
		pos = ucs_byte_to_utf8(*pch, buf);
#else
		pos = mbs_byte_to_utf8(pch, buf);
#endif
		break;
	default:
#ifdef _UNICODE
		pos = ucs_byte_to_unn(*pch, buf);
#else
		pos = mbs_byte_to_unn(pch, buf);
#endif
		break;
	}

	return pos;
}

int call_buffer_write_token(void* p_obj, int max, int pos, int encode, const tchar_t* pch, int len)
{
	byte_t* buf = (p_obj) ? ((byte_t*)p_obj + pos) : NULL;

	if (len < 0)
		len = xslen(pch);

	if (!len)
		return 0;

	switch (encode)
	{
	case _UTF16_LIT:
#ifdef _UNICODE
		pos = ucs_to_utf16lit(pch, len, buf, max - pos);
#else
		pos = mbs_to_utf16lit(pch, len, buf, max - pos);
#endif
		break;
	case _UTF16_BIG:
#ifdef _UNICODE
		pos = ucs_to_utf16big(pch, len, buf, max - pos);
#else
		pos = mbs_to_utf16big(pch, len, buf, max - pos);
#endif
		break;
	case _GB2312:
#ifdef _UNICODE
		pos = ucs_to_gb2312(pch, len, buf, max - pos);
#else
		pos = mbs_to_gb2312(pch, len, buf, max - pos);
#endif
		break;
	case _UTF8:
#ifdef _UNICODE
		pos = ucs_to_utf8(pch, len, buf, max - pos);
#else
		pos = mbs_to_utf8(pch, len, buf, max - pos);
#endif
		break;
	default:
#ifdef _UNICODE
		pos = ucs_to_unn(pch, len, buf, max - pos);
#else
		pos = mbs_to_unn(pch, len, buf, max - pos);
#endif
		break;
	}

	return pos;
}
