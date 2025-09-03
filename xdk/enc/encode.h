/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc encode defination document

	@module	encode.h | interface file

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


#ifndef _ENCODE_H
#define	_ENCODE_H


/*define unicode prefix*/
#ifndef GBKBOM
#define GBKBOM		0xFF
#endif

#if ACP_BYTE_ORDER == BIG_ENDIAN
#ifndef BIGBOM
#define BIGBOM		0xFEFF
#endif
#ifndef LITBOM
#define LITBOM		0xFFFE
#endif
#ifndef UTFBOM
#define UTFBOM		0xEFBBBF
#endif
#ifndef DEFBOM
#define DEFBOM		BIGBOM
#endif
#else
#ifndef BIGBOM
#define BIGBOM		0xFFFE
#endif
#ifndef LITBOM
#define LITBOM		0xFEFF
#endif
#ifndef UTFBOM
#define UTFBOM		0xBFBBEF
#endif
#ifndef DEFBOM
#define DEFBOM		LITBOM
#endif
#endif

#define PUT_ENCODE(buf, off, enc)	(buf[off] = (unsigned char)(enc >> 16), buf[off + 1] = (unsigned char)(enc >> 8), buf[off + 2] = (unsigned char)(enc))
#define GET_ENCODE(buf, off)		(int)((unsigned int)buf[off] << 16 | (unsigned int)buf[off + 1] << 8 | (unsigned int)buf[off + 2])

#define _UNKNOWN        0x0000
#define _GB2312         GBKBOM
#define _UTF8_BOM       UTFBOM
#define _UTF16_LIT      LITBOM
#define _UTF16_BIG      BIGBOM
#if ACP_BYTE_ORDER == BIG_ENDIAN
#define _UCS2           _UTF16_BIG
#else
#define _UCS2           _UTF16_LIT
#endif


#ifdef _OS_WINDOWS
#define DEF_MBS			_GB2312
#else
#define DEF_MBS			_UTF8_BOM
#endif

#if ACP_BYTE_ORDER == BIG_ENDIAN
#define DEF_UCS			_UTF16_BIG
#else
#define DEF_UCS			_UTF16_LIT
#endif

#define CHARSET_ASCII		_T("ascii")
#define CHARSET_GB2312		_T("gb2312")
#define CHARSET_UTF8		_T("utf-8")
#define CHARSET_UTF16		_T("utf-16")

/*define max encode bytes*/
#ifdef _UNICODE
#define CHS_LEN		1
#else
#if DEF_MBS == _GB2312
#define CHS_LEN		2
#else
#define CHS_LEN		3
#endif
#endif

#define UTF_LEN		3

#endif	/* _ENCODE_H */

