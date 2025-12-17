/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc test case document

	@module	acp_test.c | implement file

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

#include "acp.h"

#include "../xdkstd.h"
#include "../xdkimp.h"


#if defined (DEBUG) || defined (_DEBUG)

static void test_acp()
{
	printf("test acp converting...\n");

	char chs[4];
	wchar_t wc = L'中';
	int s;

#if DEF_MBS == _GB2312
	s = acp_unicode_byte_to_gb2312(wc, (byte_t*)chs);
	printf("gb2312 characterset: %s, %dbytes\n", chs, s);
#else
	s = acp_unicode_byte_to_utf8(wc, (byte_t*)chs);
	printf("utf8 characterset: %s, %dbytes\n", chs, s);
#endif

	schar_t* mbs_token = "A多BC字节中文";
	wchar_t* ucs_token = L"A宽字B节C中文";

	byte_t utf_buf[100] = {0};
	schar_t mbs_buf[100] = {0};
	wchar_t ucs_buf[100] = {0};

#if DEF_MBS == _GB2312
	s = acp_unicode_to_gb2312(ucs_token, -1, utf_buf, 100);
	printf("unicode to utf8: %s, %dbytes\n", utf_buf, s);
#else
	s = acp_unicode_to_utf8(ucs_token, -1, utf_buf, 100);
	printf("unicode to utf8: %s, %dbytes\n", utf_buf, s);
#endif

#if DEF_MBS == _GB2312
	s = a_xslen(mbs_token);
	s = acp_gb2312_to_unicode(mbs_token, s, ucs_buf, 100);
	wprintf(L"gb2312 to unicode: %s, %dbytes\n", ucs_buf, s);
#else
	s = a_xslen(mbs_token);
	s = acp_utf8_to_unicode(mbs_token, s, ucs_buf, 100);
	wprintf(L"utf8 to unicode: %S, %dbytes\n", ucs_buf, s);
#endif
}

void test_hlp()
{
	printf("test acp help...\n");

	const schar_t* a_str = "T汉字 拼F音a";
	const wchar_t* w_str = L"T汉字 拼F音a";

	schar_t a_hlp[10] = { 0 };
	int n = a_acp_help_code(a_str, -1, NULL, 10);
	a_acp_help_code(a_str, -1, a_hlp, 10);
	printf("mbs help: %s, %s\n", a_str, a_hlp);

	wchar_t w_hlp[10];
	n = w_acp_help_code(w_str, -1, NULL, 10);
	w_acp_help_code(w_str, -1, w_hlp, 10);
	wprintf(L"mbs help: %S, %S\n", w_str, w_hlp);
}

void test_seek()
{
	printf("test spec characters...\n");

	wchar_t wstr[2] = { L'，', L'。' };
	schar_t sstr[10] = { 0 };
	int n;

	n = ucs_to_mbs(wstr, 2, sstr, 10);
	printf("seek char: %s, %dbytes\n", sstr, n);
}

void test_words()
{
	printf("test words fetching...\n");
	
	const tchar_t* str = _T("abcd,中文汉字，$￥");
	int n = 0, words = 0, total = 0;
	tchar_t pch[CHS_LEN + 1] = { 0 };

	int len = xslen(str);

	while (n = peek_word((str + total), pch))
	{
		words++;
		_tprintf(_T("word: %s, %dbytes\n"), pch, n);
		total += n;
	}

	_tprintf(_T("total words:%d, %dbytes\n"), words, total);
}

void acp_self_test(void)
{

	test_acp();

	test_hlp();

	test_seek();

	test_words();
}

#endif
