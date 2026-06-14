
#include "_defi.h"


/********************************************************************************
//3000-303F��CJK ���źͱ�� (CJK Symbols and Punctuation)
//FF00-FFEF�����ͼ�ȫ����ʽ (Halfwidth and Fullwidth Form)
//4E00-9FFF��CJK ͳһ������� (CJK Unified Ideographs)
********************************************************************************/
/*
void cjk_ucs_3000()
{
	xhand_t fh;
	sword_t u;
	byte_t m[3] = { 0 };
	dword_t dw;

	byte_t pch[3] = { 0 };
	tchar_t str[NUM_LEN] = { 0 };
	byte_t utf_buf[1024] = { 0 };

	fh = xuncf_open_file(NULL, _T("UCS3300.TXT"), FILE_OPEN_CREATE);
	if (!fh)
		return;

	for (u = 0x3000; u <= 0x303f; u++)
	{
		sys_ucs_byte_to_gbk((wchar_t)u, m);

		pch[0] = GETSWORDH(u);
		pch[1] = GETSWORDL(u);

		xsprintf(str, _T("0x%02X%02X,0x%02X%02X,%S\n"), pch[0], pch[1], m[0], m[1], m);

#if defined(_UNICODE) || defined(UNICODE)
		dw = ucs_to_utf8(str, -1, utf_buf, 1024);
#else
		dw = mbs_to_utf8(str, -1, utf_buf, 1024);
#endif

		xuncf_write_file(fh, utf_buf, &dw);

	}

	xuncf_close_file(fh);
}

void cjk_ucs_ff00()
{
	xhand_t fh;
	sword_t u;
	byte_t m[3] = { 0 };
	dword_t dw;

	byte_t pch[3] = { 0 };
	tchar_t str[NUM_LEN] = { 0 };
	byte_t utf_buf[1024] = { 0 };

	fh = xuncf_open_file(NULL, _T("UCSFF00.TXT"), FILE_OPEN_CREATE);
	if (!fh)
		return;

	for (u = 0xFF00; u <= 0xFFEF; u++)
	{
		sys_ucs_byte_to_gbk((wchar_t)u, m);

		pch[0] = GETSWORDH(u);
		pch[1] = GETSWORDL(u);

		xsprintf(str, _T("0x%02X%02X,0x%02X%02X,%S\n"), pch[0], pch[1], m[0], m[1], m);

#if defined(_UNICODE) || defined(UNICODE)
		dw = ucs_to_utf8(str, -1, utf_buf, 1024);
#else
		dw = mbs_to_utf8(str, -1, utf_buf, 1024);
#endif

		xuncf_write_file(fh, utf_buf, &dw);

	}

	xuncf_close_file(fh);
}
*/

