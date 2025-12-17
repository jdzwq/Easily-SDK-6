/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc application VER document

	@module	ver.h | interface file

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

#ifndef _VER_H
#define _VER_H

#include "../xdkdef.h"

#define VER_LENGTH_BUFF(buf)	((byte_t*)buf + 4)

#ifdef	__cplusplus
extern "C" {
#endif

EXP_API dword_t ver_write_sequence(byte_t *buf, byte_t** ppos);

EXP_API void ver_write_sequence_length(byte_t *pos, dword_t len);

EXP_API dword_t ver_read_sequence(const byte_t *buf, dword_t* plen);

EXP_API dword_t ver_write_set(byte_t *buf, byte_t** ppos);

EXP_API void ver_write_set_length(byte_t *pos, dword_t len);

EXP_API dword_t ver_read_set(const byte_t *buf, dword_t* plen);

EXP_API dword_t ver_read_tag(const byte_t *buf, byte_t* pcls, byte_t* ptag, dword_t* pcnt);

EXP_API dword_t ver_write_null(byte_t *buf);

EXP_API dword_t ver_read_null(const byte_t *buf);

EXP_API dword_t ver_write_bool(byte_t *buf, bool_t b);

EXP_API dword_t ver_write_bool_array(byte_t *buf, const bool_t* ba, dword_t an);

EXP_API dword_t ver_read_bool(const byte_t *buf, bool_t *pval);

EXP_API dword_t ver_read_bool_array(const byte_t *buf, bool_t *pval, dword_t an);

EXP_API dword_t ver_write_byte(byte_t *buf, byte_t b);

EXP_API dword_t ver_write_byte_array(byte_t *buf, const byte_t* ba, dword_t an);

EXP_API dword_t ver_read_byte(const byte_t *buf, byte_t *pval);

EXP_API dword_t ver_read_byte_array(const byte_t *buf, byte_t *pval, dword_t an);

EXP_API dword_t ver_write_short(byte_t *buf, short val);

EXP_API dword_t ver_write_short_array(byte_t *buf, const short* pval, dword_t an);

EXP_API dword_t ver_read_short(const byte_t *buf, short *pval);

EXP_API dword_t ver_read_short_array(const byte_t *buf, short *pval, dword_t an);

EXP_API dword_t ver_write_int(byte_t *buf, int val);

EXP_API dword_t ver_write_int_array(byte_t *buf, const int* pval, dword_t an);

EXP_API dword_t ver_read_int(const byte_t *buf, int *pval);

EXP_API dword_t ver_read_int_array(const byte_t *buf, int *pval, dword_t an);

EXP_API dword_t ver_write_long(byte_t *buf, long long val);

EXP_API dword_t ver_write_long_array(byte_t *buf, const long long* pval, dword_t an);

EXP_API dword_t ver_read_long(const byte_t *buf, long long *pval);

EXP_API dword_t ver_read_long_array(const byte_t *buf, long long *pval, dword_t an);

EXP_API dword_t ver_write_float(byte_t *buf, float val);

EXP_API dword_t ver_write_float_array(byte_t *buf, const float* pval, dword_t an);

EXP_API dword_t ver_read_float(const byte_t *buf, float *pval);

EXP_API dword_t ver_read_float_array(const byte_t *buf, float *pval, dword_t an);

EXP_API dword_t ver_write_double(byte_t *buf, double val);

EXP_API dword_t ver_write_double_array(byte_t *buf, const double* pval, dword_t an);

EXP_API dword_t ver_read_double(const byte_t *buf, double *pval);

EXP_API dword_t ver_read_double_array(const byte_t *buf, double *pval, dword_t an);

EXP_API dword_t ver_write_datetime(byte_t *buf, const xdate_t* val);

EXP_API dword_t ver_write_datetime_array(byte_t *buf, const xdate_t* pval, dword_t an);

EXP_API dword_t ver_read_datetime(const byte_t *buf, xdate_t *pval);

EXP_API dword_t ver_read_datetime_array(const byte_t *buf, xdate_t *pval, dword_t an);

EXP_API dword_t ver_write_gb2312_string(byte_t *buf, const byte_t* ba, dword_t an);

EXP_API dword_t ver_read_gb2312_string(const byte_t *buf, byte_t *pval, dword_t an);

EXP_API dword_t ver_write_utf8_string(byte_t *buf, const byte_t* ba, dword_t an);

EXP_API dword_t ver_read_utf8_string(const byte_t *buf, byte_t *pval, dword_t an);

EXP_API dword_t ver_write_utf16lit_string(byte_t *buf, const byte_t* ba, dword_t an);

EXP_API dword_t ver_read_utf16lit_string(const byte_t *buf, byte_t *pval, dword_t an);

EXP_API dword_t ver_write_utf16big_string(byte_t *buf, const byte_t* ba, dword_t an);

EXP_API dword_t ver_read_utf16big_string(const byte_t *buf, byte_t *pval, dword_t an);

#ifdef	__cplusplus
}
#endif

#endif /*_VER_H*/
