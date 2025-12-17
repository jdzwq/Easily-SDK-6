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

#include "bar.h"

#include "../xdkstd.h"
#include "../xdkimp.h"
#include "../xdkoem.h"


#if defined (DEBUG) || defined (_DEBUG)
static void test_code128()
{
	printf("test code128 encoding...\n");

	schar_t* mbs_token = "hello world!";
	int n;
	schar_t bar_buf[1024] = {0};
	dword_t bar_len;
	int bar_units;

	n = a_xslen(mbs_token);
	bar_len = code128_encode((byte_t*)mbs_token, n, bar_buf, 1024);
	bar_units = code128_units(bar_buf, bar_len);
	printf("code128 text: %s, %d units\n", mbs_token, bar_units);
	printf("code128 sequence: %s\n", bar_buf);
}

static void test_pdf417()
{
	printf("test pdf417 encoding...\n");

	schar_t* mbs_token = "hello world!";
	int n;
	schar_t bar_buf[1024] = {0};
	dword_t bar_len;
	int bar_row, bar_col, bar_units;

	n = a_xslen(mbs_token);
	bar_len = pdf417_encode((byte_t*)mbs_token, n, bar_buf, 1024, &bar_row, &bar_col);
	bar_units = pdf417_units(bar_buf, bar_row, bar_col);
	printf("pdf417 text: %s, %d rows, %d cols, %d units\n", mbs_token, bar_row, bar_col, bar_units);
	printf("pdf417 sequence: %s\n", bar_buf);
}

static void test_qr()
{
	printf("test QR encoding...\n");
	
	schar_t* mbs_token = "hello world!";
	int n;
	schar_t bar_buf[1024] = {0};
	dword_t bar_len;
	int bar_row, bar_col, bar_units;

	n = a_xslen(mbs_token);
	bar_len = qr_encode((byte_t*)mbs_token, n, bar_buf, 1024, &bar_row, &bar_col);
	bar_units = qr_units(bar_buf, bar_row, bar_col);
	printf("QR text: %s, %d rows, %d cols, %d units\n", mbs_token, bar_row, bar_col, bar_units);
	printf("QR sequence: %s\n", bar_buf);
}

void bar_self_test(void)
{
	test_code128();

	test_pdf417();

	test_qr();
}

#endif
