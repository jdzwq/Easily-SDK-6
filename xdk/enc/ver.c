/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc ver document

	@module	ver.c | implement file

	@devnote 张文权 2021.01 - 2021.12	v6.0
***********************************************************************/

/**********************************************************************
This program is free software : you can redistribute it and/or modify
it unver the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
LICENSE.GPL3 for more details.
***********************************************************************/

#include "ver.h"

#include "../xdkimp.h"
#include "../xdkstd.h"
#include "../xdkobj.h"

/**********************************************************************
Application VER Special rulers in BER TLV encoding:
	1. the Length field can be zero, and EndofContent will be used, none-zero Length use 4-fixed bytes
	2. the Tag Class must be 0x01 (Application defined), all tag in ver use 3-fixed bytes
	3. the Tag P/C must be 0 for single VV type encoding, and 1 for Array VV type.
***********************************************************************/

static dword_t _ver_write_tag(byte_t *buf, byte_t cls, byte_t* ptag)
{
	dword_t n, total = 0;
	byte_t b;

	//Identifier class
	b = cls & (BER_TAG_CLASS_MASK | BER_TAG_PC_MASK);

	if (buf)
	{
		b |= 0x1F;
		PUT_BYTE(buf, total, b);

		b = ptag[0] | 0x80;
		PUT_BYTE(buf, (total + 1), b);

		b = ptag[1] & 0x7F;
		PUT_BYTE(buf, (total + 2), b);
	}
	total += 3;

	return total;
}

static dword_t _ver_read_tag(const byte_t *buf, byte_t* pcls, byte_t* ptag)
{
	dword_t total = 0;

	XDK_ASSERT(buf != NULL);

	if(buf[total] & BER_TAG_VALUE_MASK != BER_TAG_VALUE_MASK)
	{
		set_last_error(_T("ver_read_tag"), _T("ERR_VER_BAD_TAG"), -1);
		return 0;
	}

	//Identifier class
	if(pcls) *pcls = (buf[total] & (BER_TAG_CLASS_MASK | BER_TAG_PC_MASK));
	total ++;

	if(!(buf[total] & 0x80))
	{
		set_last_error(_T("ver_read_tag"), _T("ERR_VER_BAD_TAG"), -1);
		return 0;
	}
	if(ptag) ptag[0] = (buf[total] & 0x7F);
	total ++;

	if((buf[total] & 0x80))
	{
		set_last_error(_T("ver_read_tag"), _T("ERR_VER_BAD_TAG"), -1);
		return 0;
	}
	if(ptag) ptag[1] = (buf[total] & 0x7F);
	total ++;

	return total;
}

static dword_t _ver_write_length(byte_t *buf, dword_t len)
{
	dword_t total = 0;

	// LongLength: four byte
	if (buf)
	{
		PUT_BYTE(buf, total, 0x84);
		PUT_DWORD_NET(buf, (total + 1), len);
	}
	total += 5;

	return total;
}

static dword_t _ver_read_length(const byte_t *buf, dword_t* plen)
{
	dword_t len, total = 0;

	XDK_ASSERT(buf != NULL);

	//Length
	if (buf[total] != 0x84)
	{
		set_last_error(_T("ver_read_length"), _T("ERR_VER_BAD_LENGTH"), -1);
		return 0;
	}

	if (plen) *plen = (int)GET_DWORD_NET(buf, (total + 1));
	total += 5;

	return total;
}

dword_t ver_write_sequence(byte_t *buf, byte_t** ppos)
{
	byte_t cls, tag[2];
	dword_t n, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = BER_SEQUENCE;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_sequence"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	n = _ver_write_length(((buf)? (buf + total) : NULL), 0);
	if (!n)
	{
		set_last_error(_T("ver_write_sequence"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if(ppos) *ppos = (buf)? VER_LENGTH_BUFF(buf) : NULL;

	return total;
}

void ver_write_sequence_length(byte_t *pos, dword_t len)
{
	XDK_ASSERT(pos != NULL);

	PUT_DWORD_NET(pos, 0, len);
}

dword_t ver_read_sequence(const byte_t *buf, dword_t* plen)
{
	byte_t cls, tag[2];
	dword_t len, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_sequence"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != BER_SEQUENCE)
	{
		set_last_error(_T("ver_read_sequence"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("ver_read_sequence"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if(plen) *plen = len;

	return total;
}

dword_t ver_write_set(byte_t *buf, byte_t** ppos)
{
	byte_t cls, tag[2];
	dword_t n, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = BER_SET;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_set"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	n = _ver_write_length(((buf)? (buf + total) : NULL), 0);
	if (!n)
	{
		set_last_error(_T("ver_write_set"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if(ppos) *ppos = (buf)? VER_LENGTH_BUFF(buf) : NULL;

	return total;
}

void ver_write_set_length(byte_t *pos, dword_t len)
{
	XDK_ASSERT(pos != NULL);

	PUT_DWORD_NET(pos, 0, (len - 4));
}

dword_t ver_read_set(const byte_t *buf, dword_t* plen)
{
	byte_t cls, tag[2];
	dword_t len, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_set"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != BER_SET)
	{
		set_last_error(_T("ver_read_set"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("ver_read_set"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if(plen) *plen = len;

	return total;
}

dword_t ver_read_tag(const byte_t *buf, byte_t* pcls, byte_t* ptag, dword_t* pcnt)
{
	byte_t cls, tag[2];
	dword_t cnt, len, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_tag"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("ver_read_null"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	switch(tag[1])
	{
	case VV_NULL:
		cnt = 0;
		break;
	case VV_BOOL:
		cnt = 1;
		break;
	case VV_BOOL_ARRAY:
		cnt = len;
		break;
	case VV_BYTE:
		cnt = 1;
		break;
	case VV_BYTE_ARRAY:
		cnt = len;
		break;
	case VV_SHORT:
		cnt = 1;
		break;
	case VV_SHORT_ARRAY:
		cnt = len / 2;
		break;
	case VV_INT:
		cnt = 1;
		break;
	case VV_INT_ARRAY:
		cnt = len / 4;
		break;
	case VV_LONG:
		cnt = 1;
		break;
	case VV_LONG_ARRAY:
		cnt = len / 8;
		break;
	case VV_FLOAT:
		cnt = 1;
		break;
	case VV_FLOAT_ARRAY:
		cnt = 0;
		n = 0;
		while(*(buf + total + n) || *(buf + total + n + 1))
		{
			if(*(buf + total + n) == 0)
				cnt++;
			
			n++;
		}
		break;
	case VV_DOUBLE:
		cnt = 1;
		break;
	case VV_DOUBLE_ARRAY:
		cnt = 0;
		n = 0;
		while(*(buf + total + n) || *(buf + total + n + 1))
		{
			if(*(buf + total + n) == 0)
				cnt++;
			
			n++;
		}
		break;
	case VV_DATETIME:
		cnt = 1;
		break;
	case VV_DATETIME_ARRAY:
		cnt = 0;
		n = 0;
		while(*(buf + total + n) || *(buf + total + n + 1))
		{
			if(*(buf + total + n) == 0)
				cnt++;
			
			n++;
		}
		break;
	case VV_STRING_GB2312:
		cnt = utf8_to_gb2312((buf + total), len, NULL, MAX_LONG);
		break;
	case VV_STRING_UTF8:
		cnt = len;
		break;
	case VV_STRING_UTF16LIT:
		cnt = utf8_to_utf16lit((buf + total), len, NULL, MAX_LONG);
		break;
	case VV_STRING_UTF16BIG:
		cnt = utf8_to_utf16big((buf + total), len, NULL, MAX_LONG);
		break;
	default:
		break;
	}

	if(pcls) *pcls = cls;
	if(ptag) *ptag = tag[1];
	if(pcnt) *pcnt = cnt;

	return total;
}

dword_t ver_write_null(byte_t *buf)
{
	byte_t cls, tag[2];
	dword_t n, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_NULL;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_null"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	n = _ver_write_length(((buf)? (buf + total) : NULL), 0);
	if (!n)
	{
		set_last_error(_T("ver_write_null"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	return total;
}

dword_t ver_read_null(const byte_t *buf)
{
	byte_t cls, tag[2];
	dword_t len, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_null"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_NULL)
	{
		set_last_error(_T("ver_read_null"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("ver_read_null"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	return total;
}

dword_t ver_write_bool(byte_t *buf, bool_t b)
{
	byte_t cls, tag[2];
	dword_t n, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_BOOL;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_bool"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	n = _ver_write_length(((buf)? (buf + total) : NULL), 1);
	if (!n)
	{
		set_last_error(_T("ver_write_bool"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf) PUT_BYTE(buf, total, (byte_t)b);
	total++;

	return total;
}

dword_t ver_write_bool_array(byte_t *buf, const bool_t* ba, dword_t an)
{
	byte_t cls, tag[2];
	dword_t i, n, total = 0;

	cls = BER_APPLICATION | BER_CONSTRUCTED;
	tag[0] = VV_ARRAY, tag[1] = VV_BOOL;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_bool"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	n = _ver_write_length(((buf)? (buf + total) : NULL), an);
	if (!n)
	{
		set_last_error(_T("ver_write_bool"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf && ba) 
	{
		for(i = 0;i < an; i++)
		{
			PUT_BYTE(buf, (total + i), (byte_t)ba[i]);
		}
	}
	total += an;

	return total;
}

dword_t ver_read_bool(const byte_t *buf, bool_t *pval)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_bool"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_BOOL)
	{
		set_last_error(_T("ver_read_bool"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_bool"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	if (pval) *pval = (buf[total]) ? bool_true : bool_false;
	total += len;

	return total;
}

dword_t ver_read_bool_array(const byte_t *buf, bool_t *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_bool"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != (BER_APPLICATION | BER_CONSTRUCTED) || tag[0] != VV_ARRAY || tag[1] != VV_BOOL)
	{
		set_last_error(_T("ver_read_bool"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_bool"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	if (pval)
	{
		an = (an < len)? an : len;
		for(i=0; i<an; i++)
		{
			*pval = (buf[total+i]) ? bool_true : bool_false;
		}
	}
	total += len;

	return total;
}

dword_t ver_write_byte(byte_t *buf, byte_t b)
{
	byte_t cls, tag[2];
	dword_t n, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_BYTE;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_byte"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	n = _ver_write_length(((buf)? (buf + total) : NULL), 1);
	if (!n)
	{
		set_last_error(_T("ver_write_byte"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf) PUT_BYTE(buf, total, b);
	total++;

	return total;
}

dword_t ver_write_byte_array(byte_t *buf, const byte_t* ba, dword_t an)
{
	byte_t cls, tag[2];
	dword_t i, n, total = 0;

	cls = BER_APPLICATION | BER_CONSTRUCTED;
	tag[0] = VV_ARRAY, tag[1] = VV_BYTE;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_bool"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	n = _ver_write_length(((buf)? (buf + total) : NULL), an);
	if (!n)
	{
		set_last_error(_T("ver_write_bool"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf && ba) 
	{
		xmem_copy((void*)(buf + total), (void*)ba, an);
	}
	total += an;

	return total;
}

dword_t ver_read_byte(const byte_t *buf, byte_t *pval)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_byte"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_BYTE)
	{
		set_last_error(_T("ver_read_byte"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_byte"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	if (pval) *pval = buf[total];
	total += len;

	return total;
}

dword_t ver_read_byte_array(const byte_t *buf, byte_t *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_byte_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != (BER_APPLICATION | BER_CONSTRUCTED) || tag[0] != VV_ARRAY || tag[1] != VV_BYTE)
	{
		set_last_error(_T("ver_read_byte_array"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_byte_array"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	if (pval)
	{
		an = (an < len)? an : len;
		xmem_copy((void*)pval, (void*)(buf + total), an);
	}
	total += len;

	return total;
}

dword_t ver_write_short(byte_t *buf, short val)
{
	byte_t cls, tag[2];
	sword_t n, len, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_SHORT;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_short"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = 2;
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_short"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf)
	{
		PUT_SWORD_NET(buf, total, (sword_t)val);
	}
	total += len;

	return total;
}

dword_t ver_write_short_array(byte_t *buf, const short* pval, dword_t an)
{
	byte_t cls, tag[2];
	sword_t i, n, len, total = 0;

	cls = BER_APPLICATION;
	tag[0] = VV_ARRAY, tag[1] = VV_SHORT;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_short_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = an * 2;
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_short_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf && pval)
	{
		for(i=0; i<an; i++)
		{
			PUT_SWORD_NET(buf, (total + i * 2), (sword_t)pval[i]);
		}
	}
	total += len;

	return total;
}

dword_t ver_read_short(const byte_t *buf, short *pval)
{
	byte_t cls, tag[2];
	dword_t len;
	int n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_short"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_SHORT)
	{
		set_last_error(_T("ver_read_short"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("ver_read_short"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if(pval) *pval = (short)GET_SWORD_NET(buf, total);
	total += len;

	return total;
}

dword_t ver_read_short_array(const byte_t *buf, short *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_short_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != (BER_APPLICATION | BER_CONSTRUCTED) || tag[0] != VV_ARRAY || tag[1] != VV_SHORT)
	{
		set_last_error(_T("ver_read_short_array"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_short_array"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	if (pval)
	{
		an = (an < len/2)? an : len/2;
		for(i=0; i<an; i++)
		{
			pval[i] = (short)GET_SWORD_NET(buf, (total + i * 2));
		}
	}
	total += len;

	return total;
}

dword_t ver_write_int(byte_t *buf, int val)
{
	byte_t cls, tag[2];
	sword_t n, len, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_INT;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_int"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = 4;
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_int"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf)
	{
		PUT_DWORD_NET(buf, total, (dword_t)val);
	}
	total += len;

	return total;
}

dword_t ver_write_int_array(byte_t *buf, const int* pval, dword_t an)
{
	byte_t cls, tag[2];
	sword_t i, n, len, total = 0;

	cls = BER_APPLICATION;
	tag[0] = VV_ARRAY, tag[1] = VV_INT;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_int_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = an * 4;
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_int_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf && pval)
	{
		for(i=0; i<an; i++)
		{
			PUT_DWORD_NET(buf, (total + i * 4), (dword_t)pval[i]);
		}
	}
	total += len;

	return total;
}

dword_t ver_read_int(const byte_t *buf, int *pval)
{
	byte_t cls, tag[2];
	dword_t len, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_int"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_INT)
	{
		set_last_error(_T("ver_read_int"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("ver_read_int"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if(pval) *pval = (int)GET_DWORD_NET(buf, total);
	total += len;

	return total;
}

dword_t ver_read_int_array(const byte_t *buf, int *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_int_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != (BER_APPLICATION | BER_CONSTRUCTED) || tag[0] != VV_ARRAY || tag[1] != VV_INT)
	{
		set_last_error(_T("ver_read_int_array"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_int_array"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	if (pval)
	{
		an = (an < len/4)? an : len/4;
		for(i=0; i<an; i++)
		{
			pval[i] = (int)GET_DWORD_NET(buf, (total + i * 4));
		}
	}
	total += len;

	return total;
}

dword_t ver_write_long(byte_t *buf, long long val)
{
	byte_t cls, tag[2];
	sword_t n, len, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_LONG;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_long"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = 8;
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_long"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf)
	{
		PUT_LWORD_NET(buf, total, (lword_t)val);
	}
	total += len;

	return total;
}

dword_t ver_write_long_array(byte_t *buf, const long long* pval, dword_t an)
{
	byte_t cls, tag[2];
	sword_t i, n, len, total = 0;

	cls = BER_APPLICATION;
	tag[0] = VV_ARRAY, tag[1] = VV_LONG;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_long_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = an * 8;
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_long_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf && pval)
	{
		for(i=0; i<an; i++)
		{
			PUT_LWORD_NET(buf, (total + i * 8), (lword_t)pval[i]);
		}
	}
	total += len;

	return total;
}

dword_t ver_read_long(const byte_t *buf, long long *pval)
{
	byte_t cls, tag[2];
	dword_t len, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_long"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_LONG)
	{
		set_last_error(_T("ver_read_long"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("ver_read_long"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if(pval) *pval = (long long)GET_LWORD_NET(buf, total);
	total += len;

	return total;
}

dword_t ver_read_long_array(const byte_t *buf, long long *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_long_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != (BER_APPLICATION | BER_CONSTRUCTED) || tag[0] != VV_ARRAY || tag[1] != VV_LONG)
	{
		set_last_error(_T("ver_read_long_array"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_long_array"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	if (pval)
	{
		an = (an < len/8)? an : len/8;
		for(i=0; i<an; i++)
		{
			pval[i] = (long long)GET_LWORD_NET(buf, (total + i * 8));
		}
	}
	total += len;

	return total;
}

dword_t ver_write_float(byte_t *buf, float val)
{
	byte_t cls, tag[2];
	sword_t n, len, total = 0;
	schar_t nums[NUM_LEN] = {0};

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_FLOAT;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_float"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = a_ftoxs(val, nums, NUM_LEN);
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_float"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf)
	{
		xmem_copy((void*)(buf + total), (void*)nums, len);
	}
	total += len;

	return total;
}

dword_t ver_write_float_array(byte_t *buf, const float* pval, dword_t an)
{
	byte_t cls, tag[2];
	sword_t i, n, len, total = 0;
	schar_t nums[NUM_LEN] = {0};

	cls = BER_APPLICATION;
	tag[0] = VV_ARRAY, tag[1] = VV_FLOAT;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_float_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = 0;
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_float_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	for (i = 0; i < an; i++)
	{
		n = a_ftoxs(pval[i], nums, NUM_LEN);
		if(buf) xmem_copy((void*)(buf + total + len), (void*)nums, (n + 1));
		len += (n + 1); // include one zero terminated-character
	}
	if(buf) buf[total + len] = 0x00; // addtional zero terminated-character
	len++;

	total += len;

	return total;
}

dword_t ver_read_float(const byte_t *buf, float *pval)
{
	byte_t cls, tag[2];
	dword_t len, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_float"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_FLOAT)
	{
		set_last_error(_T("ver_read_float"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("ver_read_float"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if(pval) *pval = a_xsntof((schar_t*)(buf + total), len);
	total += len;

	return total;
}

dword_t ver_read_float_array(const byte_t *buf, float *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_float_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != (BER_APPLICATION | BER_CONSTRUCTED) || tag[0] != VV_ARRAY || tag[1] != VV_FLOAT)
	{
		set_last_error(_T("ver_read_float_array"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_float_array"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	len = 0;
	i = 0;
	while(1)
	{
		n = 0;
		while(*(buf + total + len + n))
		{
			n++;
		}

		if(pval && i < an) pval[i++] = a_xsntof((schar_t*)(buf + total + len), n);

		len += (n + 1);
		if(!(*(buf + total + len))) 
		{
			len ++;
			break;
		}
	}
	total += len;

	return total;
}

dword_t ver_write_double(byte_t *buf, double val)
{
	byte_t cls, tag[2];
	sword_t n, len, total = 0;
	schar_t nums[NUM_LEN] = {0};

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_DOUBLE;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_double"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = a_numtoxs(val, nums, NUM_LEN);
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_double"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf)
	{
		xmem_copy((void*)(buf + total), (void*)nums, len);
	}
	total += len;

	return total;
}

dword_t ver_write_double_array(byte_t *buf, const double* pval, dword_t an)
{
	byte_t cls, tag[2];
	sword_t i, n, len, total = 0;
	schar_t nums[NUM_LEN] = {0};

	cls = BER_APPLICATION;
	tag[0] = VV_ARRAY, tag[1] = VV_DOUBLE;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_double_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = 0;
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_double_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	for (i = 0; i < an; i++)
	{
		n = a_numtoxs(pval[i], nums, NUM_LEN);
		if(buf) xmem_copy((void*)(buf + total + len), (void*)nums, (n + 1));
		len += (n + 1); // include one zero terminated-character
	}
	if(buf) buf[total + len] = 0x00; // addtional zero terminated-character
	len++;

	total += len;

	return total;
}

dword_t ver_read_double(const byte_t *buf, double *pval)
{
	byte_t cls, tag[2];
	dword_t len, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_double"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_DOUBLE)
	{
		set_last_error(_T("ver_read_double"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("ver_read_double"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if(pval) *pval = a_xsntonum((schar_t*)(buf + total), len);
	total += len;

	return total;
}

dword_t ver_read_double_array(const byte_t *buf, double *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_double_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != (BER_APPLICATION | BER_CONSTRUCTED) || tag[0] != VV_ARRAY || tag[1] != VV_DOUBLE)
	{
		set_last_error(_T("ver_read_double_array"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_double_array"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	len = 0;
	i = 0;
	while(1)
	{
		n = 0;
		while(*(buf + total + len + n))
		{
			n++;
		}

		if(pval && i < an) pval[i++] = a_xsntonum((schar_t*)(buf + total + len), n);

		len += (n + 1);
		if(!(*(buf + total + len))) 
		{
			len ++;
			break;
		}
	}
	total += len;

	return total;
}

dword_t ver_write_datetime(byte_t *buf, const xdate_t* val)
{
	byte_t cls, tag[2];
	sword_t n, len, total = 0;
	schar_t nums[NUM_LEN] = {0};
	tchar_t dts[DATE_LEN] = {0};

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_DATETIME;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_datetime"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	n = format_utctime(val, dts);
#if defined(_UNICODE) || defined(UNICODE)
	len = ucs_to_utf8(dts, n, nums, NUM_LEN);
#else
	len = mbs_to_utf8(dts, n, nums, NUM_LEN);
#endif

	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_datetime"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf)
	{
		xmem_copy((void*)(buf + total), (void*)nums, len);
	}
	total += len;

	return total;
}

dword_t ver_write_datetime_array(byte_t *buf, const xdate_t* pval, dword_t an)
{
	byte_t cls, tag[2];
	sword_t i, n, len, total = 0;
	schar_t nums[NUM_LEN] = {0};
	tchar_t dts[DATE_LEN] = {0};

	cls = BER_APPLICATION;
	tag[0] = VV_ARRAY, tag[1] = VV_DATETIME;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_datetime_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = 0;
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_datetime_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	for (i = 0; i < an; i++)
	{
		n = format_utctime((pval + i), dts);
#if defined(_UNICODE) || defined(UNICODE)
		n = ucs_to_utf8(dts, n, nums, NUM_LEN);
#else
		n = mbs_to_utf8(dts, n, nums, NUM_LEN);
#endif

		if(buf) xmem_copy((void*)(buf + total + len), (void*)nums, (n + 1));
		len += (n + 1); // include one zero terminated-character
	}
	if(buf) buf[total + len] = 0x00; // addtional zero terminated-character
	len++;

	total += len;

	return total;
}

dword_t ver_read_datetime(const byte_t *buf, xdate_t *pval)
{
	byte_t cls, tag[2];
	dword_t len, n, total = 0;
	tchar_t dts[DATE_LEN] = {0};

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_datetime"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_DATETIME)
	{
		set_last_error(_T("ver_read_datetime"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("ver_read_datetime"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

#if defined(_UNICODE) || defined(UNICODE)
	utf8_to_ucs((buf + total), len, dts, DATE_LEN);
#else
	utf8_to_mbs((buf + total), len, dts, DATE_LEN);
#endif

	if(pval) parse_datetime(pval, dts);
	total += len;

	return total;
}

dword_t ver_read_datetime_array(const byte_t *buf, xdate_t *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;
	tchar_t dts[DATE_LEN] = {0};

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_datetime_array"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != (BER_APPLICATION | BER_CONSTRUCTED) || tag[0] != VV_ARRAY || tag[1] != VV_DATETIME)
	{
		set_last_error(_T("ver_read_datetime_array"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_datetime_array"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	len = 0;
	i = 0;
	while(1)
	{
		n = 0;
		while(*(buf + total + len + n))
		{
			n++;
		}

#if defined(_UNICODE) || defined(UNICODE)
		utf8_to_ucs((buf + total + len), n, dts, DATE_LEN);
#else
		utf8_to_mbs((buf + total + len), n, dts, DATE_LEN);
#endif

		if(pval && i < an) 
		{
			parse_datetime((pval + i), dts);
			i++;
		}

		len += (n + 1);
		if(!(*(buf + total + len))) 
		{
			len ++;
			break;
		}
	}
	total += len;

	return total;
}

dword_t ver_write_gb2312_string(byte_t *buf, const byte_t* ba, dword_t an)
{
	byte_t cls, tag[2];
	dword_t i, len, n, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_STRING_GB2312;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_gb2312_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = gb2312_to_utf8(ba, an, NULL, MAX_LONG);

	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_gb2312_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf && ba) 
	{
		gb2312_to_utf8(ba, an, (buf + total), len);
	}
	total += len;

	return total;
}

dword_t ver_read_gb2312_string(const byte_t *buf, byte_t *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_gb2312_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_STRING_GB2312)
	{
		set_last_error(_T("ver_read_gb2312_string"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_gb2312_string"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	if (pval)
	{
		utf8_to_gb2312((buf + total), len, pval, an);
	}
	total += len;

	return total;
}

dword_t ver_write_utf8_string(byte_t *buf, const byte_t* ba, dword_t an)
{
	byte_t cls, tag[2];
	dword_t i, len, n, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_STRING_UTF8;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_utf8_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = an;
	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_utf8_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf && ba) 
	{
		xmem_copy((void*)(buf + total), (void*)ba, an);
	}
	total += len;

	return total;
}

dword_t ver_read_utf8_string(const byte_t *buf, byte_t *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_utf8_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_STRING_UTF8)
	{
		set_last_error(_T("ver_read_utf8_string"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_utf8_string"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	if (pval)
	{
		an = (an < len)? an : len;
		xmem_copy((void*)pval, (void*)(buf + total), an);
	}
	total += len;

	return total;
}

dword_t ver_write_utf16lit_string(byte_t *buf, const byte_t* ba, dword_t an)
{
	byte_t cls, tag[2];
	dword_t i, len, n, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_STRING_UTF16LIT;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_utf16lit_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = utf16lit_to_utf8(ba, an, NULL, MAX_LONG);

	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_utf16lit_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf && ba) 
	{
		utf16lit_to_utf8(ba, an, (buf + total), len);
	}
	total += len;

	return total;
}

dword_t ver_read_utf16lit_string(const byte_t *buf, byte_t *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_utf16lit_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_STRING_UTF16LIT)
	{
		set_last_error(_T("ver_read_utf16lit_string"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_utf16lit_string"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	if (pval)
	{
		utf8_to_utf16lit((buf + total), len, pval, an);
	}
	total += len;

	return total;
}

dword_t ver_write_utf16big_string(byte_t *buf, const byte_t* ba, dword_t an)
{
	byte_t cls, tag[2];
	dword_t i, len, n, total = 0;

	cls = BER_APPLICATION;
	tag[0] = 0x00, tag[1] = VV_STRING_UTF16BIG;
	n = _ver_write_tag(((buf)? (buf + total) : NULL), cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_write_utf16big_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	len = utf16big_to_utf8(ba, an, NULL, MAX_LONG);

	n = _ver_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("ver_write_utf16big_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	total += n;

	if (buf && ba) 
	{
		utf16big_to_utf8(ba, an, (buf + total), len);
	}
	total += len;

	return total;
}

dword_t ver_read_utf16big_string(const byte_t *buf, byte_t *pval, dword_t an)
{
	byte_t cls, tag[2];
	dword_t len;
	dword_t i, n, total = 0;

	n = _ver_read_tag((buf + total), &cls, tag);
	if (!n)
	{
		set_last_error(_T("ver_read_utf16big_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return 0;
	}
	if (cls != BER_APPLICATION || tag[1] != VV_STRING_UTF16BIG)
	{
		set_last_error(_T("ver_read_utf16big_string"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return 0;
	}
	total += n;

	n = _ver_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("ver_read_utf16big_string"), _T("ERR_BER_LEN_INVALID"), -1);
		return 0;
	}
	total += n;

	if (pval)
	{
		utf8_to_utf16big((buf + total), len, pval, an);
	}
	total += len;

	return total;
}