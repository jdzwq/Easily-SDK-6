/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc der document

	@module	der.c | implement file

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

#include "der.h"

#include "../xdkimp.h"
#include "../xdkstd.h"

/**********************************************************************
ASN.1 DER Special rulers in BER TLV encoding:
	1. the Length field must indicate, and EndofContent not used
	2. the Tag P/C must be primitive in base type encoding.
	3. the unused bit in bitstring must set to 0
***********************************************************************/


dword_t der_write_sequence(byte_t *buf, dword_t len)
{
	byte_t cls, tag;
	dword_t n, total = 0;

	cls = BER_CONSTRUCTED;
	tag = BER_SEQUENCE;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_sequence"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	n = ber_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("der_write_sequence"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	return total;
}

dword_t der_read_sequence(const byte_t *buf, dword_t* plen)
{
	byte_t cls, tag;
	dword_t n, total = 0;

	n = ber_read_tag((buf + total), &cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_sequence_of"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	if (cls != BER_CONSTRUCTED && tag != BER_SEQUENCE)
	{
		set_last_error(_T("der_read_sequence_of"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	n = ber_read_length((buf + total), plen);
	if(!n)
	{
		set_last_error(_T("der_read_sequence_of"), _T("ERR_BER_LEN_INVALID"), -1);
		return total;
	}
	total += n;

	return total;
}

dword_t der_write_set(byte_t *buf, dword_t len)
{
	byte_t cls, tag;
	dword_t n, total = 0;

	cls = BER_CONSTRUCTED;
	tag = BER_SET;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_set"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	n = ber_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("der_write_set"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	return total;
}

dword_t der_read_set(const byte_t *buf, dword_t* plen)
{
	byte_t cls, tag;
	dword_t n, total = 0;

	n = ber_read_tag((buf + total), &cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_set"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	if (cls != BER_CONSTRUCTED && tag != BER_SET)
	{
		set_last_error(_T("der_read_set"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	n = ber_read_length((buf + total), plen);
	if(!n)
	{
		set_last_error(_T("der_read_set"), _T("ERR_BER_LEN_INVALID"), -1);
		return total;
	}
	total += n;

	return total;
}

dword_t der_write_bool(byte_t *buf, bool_t b)
{
	byte_t cls, tag;
	dword_t n, total = 0;

	cls = 0;
	tag = BER_BOOLEAN;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_bool"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	n = ber_write_length(((buf)? (buf + total) : NULL), 1);
	if (!n)
	{
		set_last_error(_T("der_write_bool"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if (buf) PUT_BYTE(buf, total, ((b)? 0xFF : 0x00));
	total++;

	return total;
}

dword_t der_read_bool(const byte_t *buf, bool_t *pval)
{
	byte_t clr, tag;
	dword_t len;
	dword_t n, total = 0;

	n = ber_read_tag((buf + total), &clr, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_bool"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	if (tag != BER_BOOLEAN)
	{
		set_last_error(_T("der_read_bool"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	n = ber_read_length((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("der_read_bool"), _T("ERR_BER_LEN_INVALID"), -1);
		return total;
	}
	total += n;

	if (pval) *pval = (buf[total]) ? bool_true : bool_false;
	total += len;

	return total;
}

dword_t der_write_integer(byte_t *buf, int val)
{
	byte_t cls, tag;
	dword_t len, n, total = 0;
	byte_t c[4] = { 0 };

	PUT_DWORD_NET(c, 0, (dword_t)val);

	if (val < 0)
	{
		len = 4;
	}
	else
	{
		len = 0;
		while (!c[len] && len < 4)
			len++;

		if ((c[len] & 0x80) && len > 0)
			len--;

		len = (4 == len)? 1 : (4 - len);
	}

	cls = 0;
	tag = BER_INTEGER;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_integer"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	n = ber_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("der_write_integer"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if (buf)
	{
		xmem_copy((void*)(buf + total), (void*)(c + 4 - len), len);
	}
	total += len;

	return total;
}

dword_t der_read_integer(const byte_t *buf, int *pval)
{
	byte_t cls, tag;
	dword_t len;
	int n, total = 0;

	n = ber_read_tag((buf + total), &cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_integer"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	if (tag != BER_INTEGER)
	{
		set_last_error(_T("der_read_integer"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	n = ber_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("der_read_integer"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	switch (len)
	{
	case 1:
		if (pval)
		{
			*pval = (int)GET_BYTE(buf, total);
		}
		break;
	case 2:
		if (pval)
		{
			*pval = (int)GET_SWORD_NET(buf, total);
		}
		break;
	case 3:
		if (pval)
		{
			*pval = (int)GET_THREEBYTE_NET(buf, total);
		}
		break;
	case 4:
		if (pval)
		{
			*pval = (int)GET_DWORD_NET(buf, total);
		}
		break;
	default:
		if (pval)
		{
			*pval = 0;
		}
		break;
	}
	
	total += len;

	return total;
}

dword_t der_write_bit_string(byte_t *buf, const byte_t* str, dword_t bits)
{
	byte_t cls, tag;
	dword_t len, n, total = 0;
	byte_t pad, c;

	cls = 0;
	tag = BER_BIT_STRING;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_bit_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	//the bit token need bytes
	len = (bits + 7) / 8;
	n = ber_write_length(((buf)? (buf + total) : NULL), (len + 1));
	if (!n)
	{
		set_last_error(_T("der_write_bit_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	//the padding bits
	if (buf)
	{
		pad = (byte_t)(len * 8 - bits);
		PUT_BYTE(buf, total, pad);
		//the tail bits in last byte
		c = ~((0x01 << pad) - 1);
	}
	total++;

	if (buf && str)
	{
		xmem_copy((void*)(buf + total), (void*)str, len);
		buf[total - 1] &= c;
	}
	total += len;

	return total;
}

dword_t der_read_bit_string(const byte_t *buf, byte_t** pstr, dword_t* pbits)
{
	byte_t cls, tag;
	dword_t len, n, total = 0;

	n = ber_read_tag((buf + total), &cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_bit_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	if (tag != BER_BIT_STRING)
	{
		set_last_error(_T("der_read_bit_string"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	n = ber_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("der_read_bit_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if (pbits) *pbits = (len - 1) * 8 + buf[total];
	if (pstr) *pstr = buf + total + 1;

	total += len;

	return total;
}

dword_t der_write_octet_string(byte_t *buf, const byte_t* oct, dword_t len)
{
	byte_t cls, tag;
	dword_t n, total = 0;

	cls = 0;
	tag = BER_OCTET_STRING;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_octet_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	n = ber_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("der_write_octet_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if (buf && oct)
	{
		xmem_copy((void*)(buf + total), (void*)oct, len);
	}
	total += len;

	return total;
}

dword_t der_read_octet_string(const byte_t *buf, byte_t **poct, dword_t* plen)
{
	byte_t cls, tag;
	dword_t len, n, total = 0;

	n = ber_read_tag((buf + total), &cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_octet_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	if (tag != BER_OCTET_STRING)
	{
		set_last_error(_T("der_read_octet_string"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	n = ber_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("der_read_octet_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if(poct) *poct = buf + total;
	if(plen) *plen = len;
	
	total += len;

	return total;
}

dword_t der_write_null(byte_t *buf)
{
	byte_t cls, tag;
	dword_t n, total = 0;

	cls = 0;
	tag = BER_NULL;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_null"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	n = ber_write_length(((buf)? (buf + total) : NULL), 0);
	if (!n)
	{
		set_last_error(_T("der_write_null"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	return total;
}

dword_t der_read_null(const byte_t *buf)
{
	byte_t cls, tag;
	dword_t len, n, total = 0;

	n = ber_read_tag((buf + total), &cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_null"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	if (tag != BER_NULL)
	{
		set_last_error(_T("der_read_null"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	n = ber_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("der_read_null"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	return total;
}

dword_t der_write_oid(byte_t *buf, const byte_t* oid, dword_t len)
{
	byte_t cls, tag;
	dword_t n, total = 0;

	cls = 0;
	tag = BER_OID;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_oid"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	n = ber_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("der_write_oid"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if (buf && oid)
	{
		xmem_copy((void*)(buf + total), (void*)oid, len);
	}
	total += len;

	return total;
}

dword_t der_read_oid(const byte_t *buf, byte_t **poid, dword_t* plen)
{
	byte_t cls, tag;
	dword_t len, n, total = 0;

	n = ber_read_tag((buf + total), &cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_oid"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	if (tag != BER_OID)
	{
		set_last_error(_T("der_read_oid"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	n = ber_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("der_read_oid"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if (plen) *plen = len;
	if (poid) *poid = buf + total;
	
	total += len;

	return total;
}

dword_t der_write_utf8_string(byte_t *buf, const byte_t* utf, dword_t len)
{
	byte_t cls, tag;
	dword_t n, total = 0;

	cls = 0;
	tag = BER_UTF8_STRING;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_utf8_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	n = ber_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("der_write_utf8_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if (buf && utf)
	{
		xmem_copy((void*)(buf + total), (void*)utf, len);
	}
	total += len;

	return total;
}

dword_t der_read_utf8_string(const byte_t *buf, byte_t **putf, dword_t* plen)
{
	byte_t cls, tag;
	dword_t len, n, total = 0;

	n = ber_read_tag((buf + total), &cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_utf8_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	if (tag != BER_UTF8_STRING)
	{
		set_last_error(_T("der_read_utf8_string"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	n = ber_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("der_read_utf8_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if (plen) *plen = len;
	if (putf) *putf = buf + total;

	total += len;

	return total;
}

dword_t der_write_printable_string(byte_t *buf, const char* str, dword_t len)
{
	byte_t cls, tag;
	dword_t n, total = 0;

	cls = 0;
	tag = BER_PRINTABLE_STRING;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_printable_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	n = ber_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("der_write_printable_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if (buf && str)
	{
		xmem_copy((void*)(buf + total), (void*)str, len);
	}
	total += len;

	return total;
}

dword_t der_read_printable_string(const byte_t *buf, char **pstr, dword_t* plen)
{
	byte_t cls, tag;
	dword_t len, n, total = 0;

	n = ber_read_tag((buf + total), &cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_printable_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return C_ERR;
	}
	if (tag != BER_PRINTABLE_STRING)
	{
		set_last_error(_T("der_read_printable_string"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	n = ber_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("der_read_printable_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return C_ERR;
	}
	total += n;

	if (plen) *plen = len;
	if (pstr) *pstr = buf + total;
	
	total += len;

	return total;
}

dword_t der_write_ia5_string(byte_t *buf, const char* str, dword_t len)
{
	byte_t cls, tag;
	dword_t n, total = 0;

	cls = 0;
	tag = BER_IA5_STRING;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_ia5_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	n = ber_write_length(((buf)? (buf + total) : NULL), len);
	if (!n)
	{
		set_last_error(_T("der_write_ia5_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if (buf && str)
	{
		xmem_copy((void*)(buf + total), (void*)str, len);
	}
	total += len;

	return total;
}

dword_t der_read_ia5_string(const byte_t *buf, char **pstr, dword_t* plen)
{
	byte_t cls, tag;
	dword_t len, n, total = 0;

	n = ber_read_tag((buf + total), &cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_ia5_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	if (tag != BER_IA5_STRING)
	{
		set_last_error(_T("der_read_ia5_string"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	n = ber_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("der_read_ia5_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	if (plen) *plen = len;
	if (pstr) *pstr = buf + total;
	
	total += len;

	return total;
}

dword_t der_write_time(byte_t *buf, const xdate_t *pdt)
{
	byte_t cls, tag;
	dword_t n, total = 0;
	int year,mon,day,hour,minu,sec;

	cls = 0;
	tag = BER_UTC_TIME;
	n = ber_write_tag(((buf)? (buf + total) : NULL), cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_write_ia5_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	n = ber_write_length(((buf)? (buf + total) : NULL), 12);
	if (!n)
	{
		set_last_error(_T("der_write_ia5_string"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}
	total += n;

	year = pdt->year;
	if(year > 2050) year -= 2000;
	else year -= 1900;
	if(buf) buf[total +1] = year % 10 + '0';
	year /= 10;
	if(buf) buf[total] = year % 10 + '0';
	total += 2;

	mon = pdt->mon;
	if(buf) buf[total +1] = mon % 10 + '0';
	mon /= 10;
	if(buf) buf[total] = mon % 10 + '0';
	total += 2;

	day = pdt->day;
	if(buf) buf[total +1] = day % 10 + '0';
	day /= 10;
	if(buf) buf[total] = day % 10 + '0';
	total += 2;

	hour = pdt->hour;
	if(buf) buf[total +1] = hour % 10 + '0';
	hour /= 10;
	if(buf) buf[total] = hour % 10 + '0';
	total += 2;

	minu = pdt->min;
	if(buf) buf[total +1] = minu % 10 + '0';
	minu /= 10;
	if(buf) buf[total] = minu % 10 + '0';
	total += 2;

	sec = pdt->sec;
	if(buf) buf[total +1] = sec % 10 + '0';
	sec /= 10;
	if(buf) buf[total] = sec % 10 + '0';
	total += 2;

	return total;
}

dword_t der_read_time(const byte_t *buf, xdate_t *pdt)
{
	byte_t cls, tag;
	dword_t len, n, total = 0;
	int year_len, mon_len, day_len, hour_len, min_len, sec_len;

	if (pdt)
	{
		xmem_zero((void*)pdt, sizeof(xdate_t));
	}

	n = ber_read_tag((buf + total), &cls, &tag, 1);
	if (!n)
	{
		set_last_error(_T("der_read_time"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}

	n = ber_read_length((buf + total), &len);
	if (!n)
	{
		set_last_error(_T("der_read_time"), _T("ERR_BER_OUT_OF_DATA"), -1);
		return total;
	}

	if (tag == BER_UTC_TIME)
	{
		year_len = 2;
		mon_len = 2;
		day_len = 2;
		hour_len = 2;
		min_len = 2;
		sec_len = 2;
	}
	else if (tag == BER_GENERALIZED_TIME)
	{
		year_len = 4;
		mon_len = 2;
		day_len = 2;
		hour_len = 2;
		min_len = 2;
		sec_len = 2;
	}
	else
	{
		set_last_error(_T("der_read_time"), _T("ERR_BER_TAG_MISMATCH"), -1);
		return total;
	}
	total += n;

	while (len && year_len)
	{
		if (pdt)
		{
			pdt->year *= 10;
			pdt->year += (*(buf + total) - '0');
		}
		total++;
		year_len--;
		len--;
	}

	if (pdt->year < 50)
		pdt->year += 2000;
	else
		pdt->year += 1900;

	while (len && mon_len)
	{
		if (pdt)
		{
			pdt->mon *= 10;
			pdt->mon += (*(buf + total) - '0');
		}
		total++;
		mon_len--;
		len--;
	}

	while (len && day_len)
	{
		if (pdt)
		{
			pdt->day *= 10;
			pdt->day += (*(buf + total) - '0');
		}
		total++;
		day_len--;
		len--;
	}

	while (len && hour_len)
	{
		if (pdt)
		{
			pdt->hour *= 10;
			pdt->hour += (*(buf + total) - '0');
		}
		total++;
		hour_len--;
		len--;
	}

	while (len && min_len)
	{
		if (pdt)
		{
			pdt->min *= 10;
			pdt->min += (*(buf + total) - '0');
		}
		total++;
		min_len--;
		len--;
	}

	while (len && sec_len)
	{
		if (pdt)
		{
			pdt->sec *= 10;
			pdt->sec += (*(buf + total) - '0');
		}
		total++;
		sec_len--;
		len--;
	}

	while (len)
	{
		total++;
		len--;
	}

	return total;
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void der_self_test()
{
	printf("test ASN.1 DER encoding...\n");

	int n;
	int total = 0;
	byte_t tmp[1024];

	n = MAX_BYTE - 1;
	total += der_write_integer(tmp + total, n);
	printf("write: %d\n", n);

	n = MAX_SHORT - 1;
	total += der_write_integer(tmp + total, n);
	printf("write: %d\n", n);

	n = MAX_LONG - 1;
	total += der_write_integer(tmp + total, n);
	printf("write: %d\n", n);

	total = 0;

	total += der_read_integer(tmp + total, &n);
	if (n == MAX_BYTE - 1)
		printf("read: %d\n", n);
	else
		printf("read error: %d\n", n);

	total += der_read_integer(tmp + total, &n);
	if (n == MAX_SHORT - 1)
		printf("read: %d\n", n);
	else
		printf("read error: %d\n", n);

	total += der_read_integer(tmp + total, &n);
	if (n == MAX_LONG - 1)
		printf("read: %d\n", n);
	else
		printf("read error: %d\n", n);

	total = 0;

	total += der_write_null(tmp);
	printf("write: NULL\n", n);

	const char str[] = "OCTET TOKEN";
	total += der_write_octet_string((tmp + total), (byte_t*)str, a_xslen(str));
	printf("write: %s\n", str);

	total = 0;

	total += der_read_null((tmp + total));
	if (total)
		printf("rad: NULL\n", n);
	else
		printf("read error: NULL\n", n);

	byte_t* buf = { 0 };
	total += der_read_octet_string((tmp + total), &buf, (dword_t*)&n);
	printf("read: %s\n", buf);
}
#endif