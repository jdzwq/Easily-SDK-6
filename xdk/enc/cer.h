/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc ASN.1 CER document

	@module	cer.h | interface file

	@devnote 张文权 2021.01 - 2021.12	v6.0
***********************************************************************/

/**********************************************************************
This program is free software : you can redistribute it and/or modify
it uncer the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
LICENSE.GPL3 for more details.
***********************************************************************/

#ifndef _CER_H
#define _CER_H

#include "../xdkdef.h"


#ifdef	__cplusplus
extern "C" {
#endif

EXP_API dword_t cer_read_sequence(const byte_t *buf, dword_t* plen);

EXP_API dword_t cer_read_sequence_end(const byte_t *buf);

EXP_API dword_t cer_write_sequence(byte_t *buf, dword_t len);

EXP_API dword_t cer_write_sequence_end(byte_t *buf);

EXP_API dword_t cer_read_set(const byte_t *buf, dword_t* plen);

EXP_API dword_t cer_read_set_end(const byte_t *buf);

EXP_API dword_t cer_write_set(byte_t *buf, dword_t len);

EXP_API dword_t cer_write_set_end(byte_t *buf);

EXP_API dword_t cer_read_bool(const byte_t *buf, bool_t *pval);

EXP_API dword_t cer_write_bool(byte_t *buf, bool_t b);

EXP_API dword_t cer_read_integer(const byte_t *buf, int *pval);

EXP_API dword_t cer_write_integer(byte_t *buf, int val);

EXP_API dword_t cer_read_bit_string(const byte_t *buf, byte_t** pstr, dword_t* pbits);

EXP_API dword_t cer_write_bit_string(byte_t *buf, const byte_t* bstr, dword_t bits);

EXP_API dword_t cer_read_octet_string(const byte_t *buf, byte_t** poct, dword_t* plen);

EXP_API dword_t cer_write_octet_string(byte_t *buf, const byte_t* oct, dword_t len);

EXP_API dword_t cer_read_null(const byte_t *buf);

EXP_API dword_t cer_write_null(byte_t *buf);

EXP_API dword_t cer_read_time(const byte_t *buf, xdate_t* pdt);

EXP_API dword_t cer_write_time(byte_t *buf, const xdate_t* pdt);

EXP_API dword_t cer_read_oid(const byte_t *buf, byte_t** poid, dword_t* plen);

EXP_API dword_t cer_write_oid_string(byte_t *buf, const byte_t* oid, dword_t len);

EXP_API dword_t cer_read_utf8_string(const byte_t *buf, byte_t** putf, dword_t* plen);

EXP_API dword_t cer_write_utf8_string(byte_t *buf, const byte_t* utf, dword_t len);

EXP_API dword_t cer_read_printable_string(const byte_t *buf, char** pstr, dword_t* plen);

EXP_API dword_t cer_write_printable_string(byte_t *buf, const char* str, dword_t len);

EXP_API dword_t cer_read_ia5_string(const byte_t *buf, char** pstr, dword_t* plen);

EXP_API dword_t cer_write_ia5_string(byte_t *buf, const char* str, dword_t len);

#ifdef	__cplusplus
}
#endif

#endif /*_DER_H*/
