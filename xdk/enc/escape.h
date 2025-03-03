﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdl escape document

	@module	escape.h | interface file

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

#ifndef _ESCAPE_H
#define _ESCAPE_H

#include "../xdkdef.h"

//定义转义符
#define CH_ESC		_T('&')

#define CH_LT		_T('<')
#define A_LT		"lt;"	// < 
#define W_LT		L"lt;"	// < 
#ifdef _UNICODE
#define LT			W_LT
#else
#define LT			A_LT
#endif
#define LT_LEN		3

#define CH_GT		_T('>')
#define A_GT		"gt;"	// > 
#define W_GT		L"gt;"	// > 
#ifdef _UNICODE
#define GT			W_GT
#else
#define GT			A_GT
#endif
#define GT_LEN		3

#define CH_AMP		_T('&')
#define A_AMP		"amp;"	// & 
#define W_AMP		L"amp;"	// & 
#ifdef _UNICODE
#define AMP			W_AMP
#else
#define AMP			A_AMP
#endif
#define AMP_LEN		4

#define CH_APOS		_T('\'')
#define A_APOS		"apos;"	// ' 
#define W_APOS		L"apos;"	// ' 
#ifdef _UNICODE
#define APOS		W_APOS
#else
#define APOS		A_APOS
#endif
#define APOS_LEN	5

#define CH_QUOT		_T('\"')
#define A_QUOT		"quot;"	// " 
#define W_QUOT		L"quot;"	// " 
#ifdef _UNICODE
#define QUOT		W_QUOT
#else
#define QUOT		A_QUOT
#endif
#define QUOT_LEN	5

/****************************
#define CH_SPAC		_T(' ')
#define A_SPAC		"nbsp;" //  
#define W_SPAC		L"nbsp;" //  
#define SPAC_LEN	5		

#define CH_QDIV		_T('/')
#define A_QDIV		"div;" // / 
#define W_QDIV		L"div;" // / 
#define QDIV_LEN	4		

#define CH_PAGE		_T('\f')
#define A_PAGE		"page;"	// 
#define W_PAGE		L"page;"	// 
#ifdef _UNICODE
#define PAGE		W_PAGE
#else
#define PAGE		A_PAGE
#endif
#define PAGE_LEN	5

#define CH_CARR		_T('\r')
#define A_CARR		"carr;"	// 
#define W_CARR		L"carr;"	// 
#ifdef _UNICODE
#define CARR		W_CARR
#else
#define CARR		A_CARR
#endif
#define CARR_LEN	5
*********************************/

#define ESC_LEN		6

#ifdef	__cplusplus
extern "C" {
#endif

EXP_API void csv_token_encode(const tchar_t* val, int len, tchar_t* buf, int* pdw);

EXP_API int csv_token_decode(const tchar_t* val, tchar_t* buf, int* pdw);

EXP_API dword_t url_byte_encode(const byte_t* val, dword_t len, byte_t* buf, dword_t max);

EXP_API dword_t url_byte_decode(const byte_t* val, dword_t len, byte_t* buf, dword_t max);

#if defined(XDK_SUPPORT_ACP) || defined(XDK_SUPPORT_MBCS)
EXP_API dword_t xml_gb2312_decode(const byte_t* src, tchar_t* dest);

EXP_API dword_t xml_gb2312_encode(tchar_t ch, byte_t* dest, dword_t max);
#endif

EXP_API dword_t xml_utf8_decode(const byte_t* src, tchar_t* dest);

EXP_API dword_t xml_utf8_encode(tchar_t ch, byte_t* dest, dword_t max);

EXP_API dword_t xml_utf16lit_decode(const byte_t* src, tchar_t* dest);

EXP_API dword_t xml_utf16lit_encode(tchar_t ch, byte_t* dest, dword_t max);

EXP_API dword_t xml_utf16big_decode(const byte_t* src, tchar_t* dest);

EXP_API dword_t xml_utf16big_encode(tchar_t ch, byte_t* dest, dword_t max);

EXP_API dword_t xml_unn_decode(const byte_t* src, tchar_t* dest);

EXP_API dword_t xml_unn_encode(tchar_t ch, byte_t* dest, dword_t max);

EXP_API int xml_ucs_decode(const wchar_t* src, tchar_t* dest);

EXP_API int xml_ucs_encode(tchar_t ch, wchar_t* dest, int max);

EXP_API int xml_mbs_decode(const schar_t* src, tchar_t* dest);

EXP_API int xml_mbs_encode(tchar_t ch, schar_t* dest, int max);

#ifdef	__cplusplus
}
#endif

#endif /*ESCAPE_H*/
