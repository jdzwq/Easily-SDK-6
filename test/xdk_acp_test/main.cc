
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif

#ifdef XDK_SUPPORT_ACP_TABLE
void test_acp_table()
{
	save_gb2312_table(_T("gb2312.acp"));
	save_unicode_table(_T("unicode.acp"));
}
#endif

void test_acp_dump()
{
	tchar_t fpath[PATH_LEN + 1] = { 0 };

	get_runpath(NULL, fpath, PATH_LEN);

	_tprintf(_T("gb2312.acp path: %s\n"), fpath);
	
	share_acp_dump();
}

void test_hlp()
{
	const schar_t* a_str = "T汉字 拼F音a";
	const wchar_t* w_str = L"T汉字 拼F音a";

	schar_t a_hlp[10] = { 0 };
	int n = a_acp_help_code(a_str, -1, NULL, 10);
	a_acp_help_code(a_str, -1, a_hlp, 10);
	_tprintf(_T("a_hlp: %s\n"), a_hlp);

	wchar_t w_hlp[10];
	n = w_acp_help_code(w_str, -1, NULL, 10);
	w_acp_help_code(w_str, -1, w_hlp, 10);
	_tprintf(_T("w_hlp: %s\n"), w_hlp);
}

void test_conv()
{
	char chs[4];
	wchar_t wc = L'中';
	int s;

	setlocale(P_ALL, "zh_CN.GBK");
	s = wcstombs(chs, &wc, 4);
	_tprintf(_T("sys mbs_buf: %s, %dbytes\n"), chs, s);

	wc = 0;
	s = mbstowcs(&wc, chs, 1);
	_tprintf(_T("sys mbs_buf: %S, %dbytes\n"), &wc, s);

	setlocale(P_ALL, "");

	schar_t* mbs_token = "A多BC字节中文";
	wchar_t* ucs_token = L"A宽节BC中文";

	byte_t utf_buf[100] = {0};
	schar_t mbs_buf[100] = {0};
	wchar_t ucs_buf[100] = {0};
	int n, len;
	dword_t k;

	setlocale(P_ALL, "zh_CN.GBK");
	n = wcslen(ucs_token);
	n = sizeof(ucs_token);
	n = wcstombs(mbs_buf, ucs_token, 100);
	_tprintf(_T("sys mbs_buf: %s, %dbytes\n"), mbs_buf, n);

	len = strlen(mbs_token);
	n = mblen(mbs_token, len);
	n = (int)mbstowcs(ucs_buf, mbs_token, 100);
	_tprintf(_T("sys ucs_buf: %S, %dbytes\n"), ucs_buf, n);

	setlocale(P_ALL, "");
	
	setlocale(P_ALL, "zh_CN.UTF-8");
	n = wcslen(ucs_token);
	n = sizeof(ucs_token);
	n = wcstombs(mbs_buf, ucs_token, 100);
	_tprintf(_T("sys mbs_buf: %s, %dbytes\n"), mbs_buf, n);

	len = strlen(mbs_token);
	n = mblen(mbs_token, len);
	n = (int)mbstowcs(ucs_buf, mbs_token, 100);
	_tprintf(_T("sys ucs_buf: %S, %dbytes\n"), ucs_buf, n);

	setlocale(P_ALL, "");

	n = mbs_to_ucs(mbs_token, -1, NULL, 100);
	n = mbs_to_ucs(mbs_token, -1, ucs_buf, n);
	_tprintf(_T("acp ucs_buf: %S, %dbytes\n"), ucs_buf, n);

	n = ucs_to_utf8(ucs_token, -1, NULL, 100);
	n = ucs_to_utf8(ucs_token, -1, utf_buf, n);
	_tprintf(_T("acp utf_buf: %s, %dbytes\n"), (schar_t*)utf_buf, n);

	k = a_xslen(mbs_token);
	n = utf8_to_mbs((byte_t*)mbs_token, k, NULL, 100);
	n = utf8_to_mbs((byte_t*)mbs_token, k, (schar_t*)mbs_buf, n);
	_tprintf(_T("acp mbs_buf: %s, %dbytes\n"), mbs_buf, n);
}

void test_seek()
{
	wchar_t wstr[2] = { L'，', L'。' };
	schar_t sstr[10] = { 0 };
	int n;

	n = ucs_to_mbs(wstr, 2, sstr, 10);

	_tprintf(_T("seek char: %s, %dbytes\n"), sstr, n);
}

void test_words()
{
	//const tchar_t* str = _T("这是ABC一段字体测试 文字");
	const tchar_t* str = _T("abcd,中文汉字，$￥");
	int n = 0, words = 0, total = 0;
	tchar_t pch[CHS_LEN + 1] = { 0 };

	int len = xslen(str);

	while (n = peek_word((str + total), pch))
	{
		words++;
		_tprintf(_T("word: %s bytes: %d\n"), pch, n);
		total += n;
	}

	_tprintf(_T("total words:%d bytes:%d\n"), words, total);
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

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//test_acp_dump();

	//test_hlp();

	test_conv();

	//test_seek();

	//test_words();

	xdk_process_uninit();

#ifdef _OS_WINDOWS
	getch();
#endif

	return 0;
}

