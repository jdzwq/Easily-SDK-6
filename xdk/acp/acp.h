/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc codepage document

	@module	acp.h | interface file

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

#ifndef _ACP_H
#define _ACP_H

#include "../xdkdef.h"

#define LIT_MAKESHORT(lc,hc)	((((unsigned short)(hc) << 8) & 0xFF00) | ((unsigned short)(lc) & 0x00FF))
#define LIT_GETHCHAR(sw)		(unsigned char)(((unsigned short)(sw) >> 8) & 0x00FF)
#define LIT_GETLCHAR(sw)		(unsigned char)((unsigned short)(sw) & 0x00FF)

#define BIG_MAKESHORT(lc,hc)	((((unsigned short)(lc) << 8) & 0xFF00) | ((unsigned short)(hc) & 0x00FF))
#define BIG_GETHCHAR(sw)		(unsigned char)((unsigned short)(sw) & 0x00FF)
#define BIG_GETLCHAR(sw)		(unsigned char)(((unsigned short)(sw) >> 8) & 0x00FF) 

#if ACP_BYTE_ORDER == BIG_ENDIAN
#define MAKESHORT			BIG_MAKESHORT
#define GETLCHAR			BIG_GETLCHAR
#define GETHCHAR			BIG_GETHCHAR
#else
#define MAKESHORT			LIT_MAKESHORT
#define GETLCHAR			LIT_GETLCHAR
#define GETHCHAR			LIT_GETHCHAR
#endif

#define ALT_CHAR	0x20

#if ACP_BYTE_ORDER == 4321
#define BIGBOM		0xFEFF
#define LITBOM		0xFFFE
#define DEFBOM		BIGBOM
#else
#define BIGBOM		0xFFFE
#define LITBOM		0xFEFF
#define DEFBOM		LITBOM
#endif

/*define gb2312 range*/
#define MIN_CHS_GB2312		0xA1A1
#define MAX_CHS_GB2312		0xFEFF
#define CHS_GB2312_COUNT	8836
#define GB2312_CODE_INDEX(sw)		 ((GETHBYTE(sw) - 161) * 94 + GETLBYTE(sw) - 161)

/*define unicode range*/
#define MIN_CHS_UNICODE		0x4E00
#define MAX_CHS_UNICODE		0x9FA5
#define CHS_UNICODE_COUNT	20902
#define UNICODE_CODE_INDEX(sw)		 (sw - MIN_CHS_UNICODE)

/*code range*/
#define _ACP_GBKMIN			0xa1a0
#define _ACP_GBKMAX			0xfeff
#define _ACP_UCSMIN			0x00a0
#define _ACP_UCSMAX			0xffef

typedef struct _acp_index_t{
	dword_t code;
	dword_t offset;
}acp_index_t;

typedef struct _acp_table_t{
	sword_t code;
	sword_t help;
	vword_t addr;
}acp_table_t;

#define SHARE_GB2312_CODEPAGE		_T("share_gb2312_codepage")
#define SHARE_UNICODE_CODEPAGE		_T("share_unicode_codepage")

extern xhand_t acp_gb2312;
extern xhand_t acp_unicode;

#ifdef XDK_SUPPORT_ACP_TABLE
LOC_API int table_unicode_seek_help(unsigned short ucs, unsigned short* hlp);
LOC_API int table_gb2312_seek_help(const unsigned char* mbs, unsigned char* hlp);
LOC_API int table_unicode_seek_gb2312(unsigned short ucs, unsigned char* mbs);
LOC_API int table_gb2312_seek_unicode(unsigned char* mbs, unsigned short* ucs);

EXP_API void unicode_gb2312_code(int index, unsigned short* code, unsigned short* val, unsigned short* key);
EXP_API void gb2312_unicode_code(int index, unsigned short* code, unsigned short* val, unsigned short* key);
EXP_API bool_t save_gb2312_table(const tchar_t* fname);
EXP_API bool_t save_unicode_table(const tchar_t* fname);
#else
LOC_API int share_unicode_seek_help(unsigned short ucs, unsigned short* hlp);
LOC_API int share_gb2312_seek_help(const unsigned char* mbs, unsigned char* hlp);
LOC_API int share_unicode_seek_gb2312(unsigned short ucs, unsigned char* mbs);
LOC_API int share_gb2312_seek_unicode(unsigned char* mbs, unsigned short* ucs);

LOC_API vword_t share_get_gb2312_code_addr(const byte_t* pch);
LOC_API bool_t share_set_gb2312_code_addr(const byte_t* pch, vword_t addr);
LOC_API vword_t share_get_unicode_code_addr(unsigned short ucs);
LOC_API bool_t share_set_unicode_code_addr(unsigned short ucs, vword_t addr);
LOC_API bool_t share_acp_init(void);
LOC_API void share_acp_uninit(void);
#endif

LOC_API int acp_gb2312_code_sequence(byte_t b);

LOC_API int acp_gb2312_byte_to_unicode(const byte_t* src, wchar_t* dest);

LOC_API int acp_gb2312_to_unicode(const byte_t* src, dword_t slen, wchar_t* dest, int dlen);

LOC_API int acp_unicode_byte_to_gb2312(wchar_t ch, byte_t* dest);

LOC_API int acp_unicode_to_gb2312(const wchar_t* src, int slen, byte_t* dest, dword_t dlen);

LOC_API int acp_utf8_code_sequence(unsigned char b);

LOC_API int acp_utf8_byte_to_unicode(const byte_t* src, wchar_t* dest);

LOC_API int acp_utf8_to_unicode(const byte_t* src, dword_t slen, wchar_t* dest, int dlen);

LOC_API int acp_unicode_byte_to_utf8(wchar_t ch, byte_t* dest);

LOC_API int acp_unicode_to_utf8(const wchar_t* src, int slen, byte_t* dest, dword_t dlen);

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
@FUNCTION: get ascii characters count in code page.
@RETURN int: character count.
***********************************************************************/
EXP_API int acp_ascii_code_count(void);

/***********************************************************************
@FUNCTION: get next ascii character in code page.
@INOUTPUT pch: current character input and for next character outputing,
	the pch byte buffer size need 1 byte.
@RETURN bool_t: if next character exist return bool_true, 
	otherwise return bool_false.
***********************************************************************/
EXP_API bool_t acp_next_ascii_char(byte_t *pch);

/***********************************************************************
@FUNCTION: get gb2312 characters count in code page.
@RETURN int: character count.
***********************************************************************/
EXP_API int acp_gb2312_code_count(void);

/***********************************************************************
@FUNCTION: get next gb2312 character in code page.
@INOUTPUT pch: current character input and for next character outputing.
	the pch byte buffer size need 2 bytes.
@RETURN bool_t: if next character exist return bool_true, 
	otherwise return bool_false.
***********************************************************************/
EXP_API bool_t acp_next_gb2312_char(byte_t *pch);

/***********************************************************************
@FUNCTION: get unicode characters count in code page.
@RETURN int: character count.
***********************************************************************/
EXP_API int acp_unicode_code_count(void);

/***********************************************************************
@FUNCTION: get next unicode character in code page.
@INOUTPUT pch: current character input and for next character outputing.
	the pch byte buffer size need 2 bytes.
@RETURN bool_t: if next character exist return bool_true, 
	otherwise return bool_false.
***********************************************************************/
EXP_API bool_t acp_next_unicode_char(byte_t *pch);

/***********************************************************************
@FUNCTION: get help ascii character.
@INPUT src: the string token.
@INPUT len: the string character length.
@OUTPUT buf: for help string returning buffer.
@INPUT max: the buffer size, not include the zero-terminated character.
@RETURN int: the length of actual help characters returned.
@NOTE: the parameter buf set to NULL and max set to MAX_LONG, 
	can be used to test the length of help characters may be returned.
	w_ prefix is the UCS-VERSION and a_ prefix is the MBS_VERSION function.
***********************************************************************/
EXP_API int w_acp_help_code(const wchar_t* src, int len, wchar_t* buf, int max);
EXP_API int a_acp_help_code(const schar_t* src, int len, schar_t* buf, int max);

#if defined (DEBUG) || defined (_DEBUG)
	EXP_API void share_acp_dump(void);
#endif

#ifdef __cplusplus
}
#endif

#if defined(_UNICODE) || defined(UNICODE)
#define acp_help_code	w_acp_help_code
#else
#define acp_help_code	a_acp_help_code
#endif


#endif /*_ACP_H*/
