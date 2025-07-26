/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdsstr document

	@module	strext.h | interface file

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

#ifndef _XSTREXT_H
#define _XSTREXT_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************
xprintf usage:
pattern: %[flag][width][.][prec][size][type]
flag: [+|#]
width: [0-9]
prec: [0-9]
size: [h|l]
type: [c|d|u|x|X|f|s|S]
**********************************************/

/**********************************************
xscanf usage:
pattern: %[size][type]
size: [h|l]
type: [c|d|u|x|X|f|s|S]
**********************************************/

EXP_API int a_xsprintf_arg(schar_t* buf,const schar_t* fmt,va_list* parg);
EXP_API int w_xsprintf_arg(wchar_t* buf,const wchar_t* fmt,va_list* parg);

EXP_API int a_xsprintf(schar_t* buf,const schar_t* fmt,...);
EXP_API int w_xsprintf(wchar_t* buf,const wchar_t* fmt,...);

EXP_API int a_xsappend(schar_t* buf, const schar_t* fmt, ...);
EXP_API int w_xsappend(wchar_t* buf, const wchar_t* fmt, ...);

EXP_API const schar_t* a_xsscanf(const schar_t* str, const schar_t* fmt, ...);
EXP_API const wchar_t* w_xsscanf(const wchar_t* str, const wchar_t* fmt, ...);

EXP_API const schar_t* a_xsscanf_arg(const schar_t* str, const schar_t* fmt, va_list* parg);
EXP_API const wchar_t* w_xsscanf_arg(const wchar_t* str, const wchar_t* fmt, va_list* parg);

#ifdef	__cplusplus
}
#endif

#if defined(_UNICODE) || defined(UNICODE)
#define xsprintf			w_xsprintf
#define xsprintf_arg		w_xsprintf_arg
#define xsappend			w_xsappend
#define xsscanf				w_xsscanf
#define xsscanf_arg			w_xsscanf_arg

#define xschs(pch)			(((pch) && *(pch))? ucs_sequence(*(pch)) : 0)
#else
#define xsprintf			a_xsprintf
#define xsprintf_arg		a_xsprintf_arg
#define xsappend			a_xsappend
#define xsscanf				a_xsscanf
#define xsscanf_arg			a_xsscanf_arg

#define xschs(pch)			(((pch) && *(pch))? mbs_sequence(*(pch)) : 0)

#endif //UNICODE


#endif /*_STREXT_H*/