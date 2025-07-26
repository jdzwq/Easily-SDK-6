
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif

void test_printf()
{
	int n;
	tchar_t sz[256];
	
	char sc = MIN_CHAR + 1;
	short ss = MIN_SHORT + 1;
	int si = MIN_LONG + 1;
	long long sl = MIN_LONG - 1;

	n = xsprintf(sz, _T("sc =%c ss=%hd si=%d sl=%ld"), sc, ss, si, sl);
	_tprintf(_T("%s\n"),sz);

	unsigned char uc = MAX_CHAR;
	unsigned short us = MAX_SHORT;
	unsigned int ui = MAX_LONG;
	unsigned long long ul = (long long)MAX_LONG + 1;

	n = xsprintf(sz, _T("ss=%hu si=%u sl=%lu"), us, ui, ul);
	_tprintf(_T("%s\n"),sz);

	xsprintf(sz, _T("max short=%#hX max int=%X max long=%#lx"), MAX_SHORT, MAX_LONG, MAX_LONGLONG);
	_tprintf(_T("%s\n"),sz);

	schar_t ssz[50];
	wchar_t wsz[50];
	const schar_t* sstr = "multibyte string";
	const wchar_t* wstr = L"wide string";
	a_xsprintf(ssz, "multibyte string test: %s, %S", sstr, wstr);
	printf("%s\n",ssz);
	w_xsprintf(wsz, L"wide string test: %S, %s", sstr, wstr);
	ucs_to_mbs(wsz, -1, ssz, 50);
	printf("%s\n",ssz);
}

void test_scanf()
{
	tchar_t c = 0;
	short s = 0;
	int i = 0;
	long long l = 0;
	double f = 0.0;

	xsscanf(_T("test: c=t s=1 i=2 l=3 f=4.0"),_T("test: c=%c s=%hd i=%d l=%ld f=%f"), &c, &s, &i, &l, &f);
	_tprintf(_T("test: c=%c s=%hd i=%d l=%lld f=%f\n"), c, s, i, l, f);
}

void test_hexnum()
{
	const tchar_t* TK_GBKBOM = _T("0xFF");
	const tchar_t* TK_BIGBOM = _T("0xFFFE");
	const tchar_t* TK_LITBOM = _T("0xFEFF");
	const tchar_t* TK_UTFBOM = _T("0xBFBBEF");	

	sword_t sw_gbkbom;
	dword_t dw_bigbom,dw_litbom;
	lword_t lw_utfbom;

	sw_gbkbom = hextol(TK_GBKBOM);
	XDK_ASSERT(sw_gbkbom == GBKBOM);
	_tprintf(_T("gbkbom: %s %X\n"), TK_GBKBOM, sw_gbkbom);

	dw_bigbom = hextol(TK_BIGBOM);
	XDK_ASSERT(dw_bigbom == BIGBOM);
	_tprintf(_T("bigbom: %s %X\n"), TK_BIGBOM, dw_bigbom);

	dw_bigbom = hextol(TK_BIGBOM);
	XDK_ASSERT(dw_bigbom == BIGBOM);
	_tprintf(_T("bigbom: %s %X\n"), TK_BIGBOM, dw_bigbom);

	dw_litbom = hextol(TK_LITBOM);
	XDK_ASSERT(dw_litbom == LITBOM);
	_tprintf(_T("litbom: %s %X\n"), TK_LITBOM, dw_litbom);

	lw_utfbom = hextoll(TK_UTFBOM);
	XDK_ASSERT(lw_utfbom == UTFBOM);
	_tprintf(_T("utfbom: %s %llX\n"), TK_UTFBOM, lw_utfbom);
}

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//test_hexnum();

	test_printf();

	//test_scanf();

	xdk_process_uninit();

#ifdef _OS_WINDOWS
	getch();
#endif

	return 0;
}

