
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif

void _error_level2()
{
	TRY_CATCH;

	raise_user_error(_T("_error_level2"), _T("level 2 error"));

	END_CATCH;
ONERROR:

	return;
}

void _error_level1()
{
	TRY_CATCH;

	_error_level2();

	raise_user_error(_T("_error_level1"), _T("level 1 error"));

	END_CATCH;
ONERROR:

	return;
}

void test_error()
{
	TRY_CATCH;

	_error_level1();

	raise_user_error(_T("_error_level0"), _T("level 0 error"));

	END_CATCH;
ONERROR:
	XDK_TRACE_LAST;
}

void test_mem()
{
	byte_t b[20] = { 0 };

	for (int i = 0; i< 10; i++)
	{
		b[i] = '0' + i;
	}

	xmem_move(b, 10, 10);
	xmem_zero(b, 10);

	xmem_move(b + 10, 10, -10);
	xmem_zero(b + 10, 10);
}

void test_conv()
{
	schar_t* mbs_token = "A多BC字节中文";
	wchar_t* ucs_token = L"A宽节BC中文";

	byte_t utf_buf[100] = {0};
	schar_t mbs_buf[100] = {0};
	wchar_t ucs_buf[100] = {0};
	int n, len;
	dword_t k;
	
	//setlocale(P_ALL, "zh_CN.UTF-8");
	n = wctomb(mbs_buf, *ucs_token);
	n = wctomb(mbs_buf, L'A');
	n = (int)mbstowcs(NULL, mbs_token, 0);
	n = strlen(mbs_token);
	len = mblen(mbs_token, n);
	n = (int)mbstowcs(ucs_buf, mbs_token, len);
	//setlocale(P_ALL, "");

	n = mbs_to_ucs(mbs_token, -1, NULL, 100);
	n = mbs_to_ucs(mbs_token, -1, ucs_buf, n);

	n = ucs_to_utf8(ucs_token, -1, NULL, 100);
	n = ucs_to_utf8(ucs_token, -1, utf_buf, n);

	k = a_xslen(mbs_token);
	n = utf8_to_mbs((byte_t*)mbs_token, k, NULL, 100);
	n = utf8_to_mbs((byte_t*)mbs_token, k, mbs_buf, n);
}

void test_utc()
{
	xdate_t dt;
	tchar_t sz_date[UTC_LEN + 1] = { 0 };

	get_utc_date(&dt);
	format_utctime(&dt, sz_date);

	xdate_t dt2;
	parse_datetime(&dt2, sz_date);

	int rt = compare_datetime(&dt, &dt2);
}

void test_times()
{
	xdate_t dt;
	tchar_t sz_date[UTC_LEN + 1] = { 0 };
	dword_t ms;

	ms = get_times();

	ms += 24 * 60 * 60;

	utc_date_from_times(&dt, ms);
	format_utctime(&dt, sz_date);
}

void test_stamp()
{
	xdate_t dt;
	tchar_t sz_date[UTC_LEN + 1] = { 0 };
	lword_t ms;
	dword_t m, s, k;

	ms = get_timestamp();
	m = ms / (1000 * 100);
	s = ms % (1000 * 100);
	k = m & 0x0FFFFFFF;

	utc_date_from_timestamp(&dt, ms);

	format_utctime(&dt, sz_date);

	_tprintf(_T("%s\n"), sz_date);

	ms = (lword_t)m * 100000 + (lword_t)s;

	utc_date_from_timestamp(&dt, ms);

	format_utctime(&dt, sz_date);

	_tprintf(_T("%s\n"), sz_date);
}

void test_func(int a, ...)
{
	va_list args;

	va_start(args, a);

	char c = (char)va_arg(args, int);

	int b = va_arg(args, int);

	va_end(args);
}

void test_printf()
{
	char tmp[100] = { 0 };
	int len = a_xsprintf(tmp, "%d '%Y-%m-%d %H:%i') as DT", -1);

	tchar_t buf[20] = { 0 };

	//sprintf(buf,  "%c",  'W');

	//test_func(10, _T('0'), 10);

	xsprintf(buf, _T("%s%"), _T("hello"));

	//printf(buf);
}

void test_money()
{
	tchar_t token[NUM_LEN] = { 0 };

	format_money_chs(10.01, 0, token, NUM_LEN);
}

void test_words()
{
	//const tchar_t* str = _T("这是ABC一段字体测试 文字");
	const tchar_t* str = _T("abcd,中文汉字，$￥");
	int n, total = 0;
	tchar_t pch[CHS_LEN + 1] = { 0 };

	int len = xslen(str);

	while (n = peek_word((str + total), pch))
	{
		_tprintf(_T("%s %d\n"), pch, n);
		total += n;
	}

	_tprintf(_T("len:%d total:%d\n"), len, total);
}

void test_intset()
{
	const tchar_t* str = _T("[1,2-5,7, 9-10, 12-20]");

	int n = parse_intset(str, -1, NULL, MAX_LONG);

	int* sa = (int*)xmem_alloc(n * sizeof(int));
	parse_intset(str, -1, sa, n);

	for (int i = 0; i < n; i++)
	{
		_tprintf(_T("%d\n"), sa[i]);
	}

	xmem_free(sa);
}

void test_nums()
{
	dword_t dl = 0xFFFFFFFF;
	dword_t dh = 0;
	lword_t ll = MAKELWORD(dl, dh) + 4096;

	dword_t h = GETLWORDH(ll);
	dword_t l = GETLWORDL(ll);

	XDK_ASSERT(dl == l && dh == h);
}



void test_hash32()
{
	int i, j, k = 0, n = 100000;
	tchar_t kid[NUM_LEN + 1] = { 0 };

	variant_t key = variant_alloc(VV_STRING_UTF8);

	key32_t* pka = (key32_t*)xmem_alloc(sizeof(key32_t) * n);

	_tprintf(_T("hash32 test case:%d\n"), n);

	for (i = 0; i < n; i++)
	{
		xsprintf(kid, _T("key%d"), i);
		variant_from_string(key, kid, -1);

		variant_hash32(key, pka + i);

		for (j = i - 1; j >= 0; j--)
		{
			if (pka[j] == pka[i])
			{
				k++;
				_tprintf(_T("key%d collide with key%d\n"), i, j);
			}
		}
	}

	variant_free(key);
	//xmem_free(pka);

	_tprintf(_T("hash32 collide:%f percent\n"), (double)k / (double)n * 100.0);
}

void test_hash64()
{
	int i, j, k = 0, n = 1000000;
	tchar_t kid[NUM_LEN + 1] = { 0 };

	variant_t key = variant_alloc(VV_STRING_UTF8);

	key64_t* pka = (key64_t*)xmem_alloc(sizeof(key64_t) * n);

	_tprintf(_T("hash64 test case:%d\n"), n);

	for (i = 0; i < n; i++)
	{
		xsprintf(kid, _T("key%d"), i);
		variant_from_string(key, kid, -1);

		variant_hash64(key, pka + i);

		for (j = i - 1; j >= 0; j--)
		{
			if (pka[j] == pka[i])
			{
				k++;
				_tprintf(_T("key%d collide with key%d\n"), i, j);
			}
		}
	}

	variant_free(key);
	xmem_free(pka);

	_tprintf(_T("hash64 collide:%f percent\n"), (double)k / (double)n * 100.0);
}


void test_printf_big5()
{
	FILE* fp = fopen("BG2UBG.KU", "rb");
	unsigned short c, u;

	FILE* fd = fopen("big.c", "w+");
	tchar_t hex[5];
	char cc[8], uc[8];
	wchar_t wc;

	while (!feof(fp))
	{
		fread(&c, sizeof(unsigned short), 1, fp);
		fread(&u, sizeof(unsigned short), 1, fp);

		gb2312_byte_to_ucs((byte_t*)&c, &wc);

		memset(hex, 0, 5);
		cc[0] = '0'; cc[1] = 'x';
		format_hexnum(c, hex, 4);
		cc[2] = (char)hex[0];
		cc[3] = (char)hex[1];
		cc[4] = (char)hex[2];
		cc[5] = (char)hex[3];
		cc[6] = ',';
		cc[7] = '\0';

		memset(hex, 0, 5);
		uc[0] = '0'; uc[1] = 'x';
		format_hexnum(wc, hex, 4);
		uc[2] = (char)hex[0];
		uc[3] = (char)hex[1];
		uc[4] = (char)hex[2];
		uc[5] = (char)hex[3];
		uc[6] = '\n';
		uc[7] = '\0';

		fwrite(cc, 1, 7, fd);
		fwrite(uc, 1, 7, fd);
	}

	fclose(fp);
	fclose(fd);
}
/*
void test_rtf()
{
	FILE *fp;
	int ec;

	fp = fopen("test.rtf", "r");
	if (!fp)
	{
		printf("Can't open test file!\n");
		return;
	}
	if ((ec = ecRtfParse(fp)) != ecOK)
		printf("error %d parsing rtf\n", ec);
	else
		printf("Parsed RTF file OK\n");
	fclose(fp);

}*/


int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_THREAD | XDK_INITIALIZE_CONSOLE);

	test_printf_big5();
	
	xdk_process_uninit();

#ifdef _OS_WINDOWS
	getch();
#endif

	return 0;
}

