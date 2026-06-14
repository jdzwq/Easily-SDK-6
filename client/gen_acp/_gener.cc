
#include "_defi.h"

void acp_gb2312_unicode()
{
	xhand_t fh;
	tchar_t fname[PATH_LEN];

	int i;
	sword_t fw, tw;
	tchar_t ch;

	dword_t dw;
	tchar_t str[512] = { 0 };
	byte_t utf_buf[1024] = { 0 };

	get_curpath(fname, PATH_LEN);
	xscat(fname, _T("/gb2312.acp"));

	fh = xuncf_open_file(NULL, fname, FILE_OPEN_CREATE);
	if (!fh) return;

	for (i = 0; i < CODE_SIZE; i++)
	{
		fw = code_gb2312_unicode[i][0];
		tw = code_gb2312_unicode[i][1];
		ch = (tchar_t)code_gb2312_unicode[i][2];
		if(!ch) ch = _T(' ');

		xsprintf(str, _T("0x%02X%02X,0x%02X%02X,%c\n"),
			GETSWORDH(fw), GETSWORDL(fw), 
			GETSWORDH(tw), GETSWORDL(tw), 
			ch);

#if defined(_UNICODE) || defined(UNICODE)
		dw = ucs_to_utf8(str, -1, utf_buf, 1024);
#else
		dw = mbs_to_utf8(str, -1, utf_buf, 1024);
#endif

		xuncf_write_file(fh, utf_buf, &dw);

	}

	xuncf_close_file(fh);
}

void acp_unicode_gb2312()
{
	xhand_t fh;
	tchar_t fname[PATH_LEN];

	int i;
	sword_t fw, tw;
	tchar_t ch;

	dword_t dw;
	tchar_t str[512] = { 0 };
	byte_t utf_buf[1024] = { 0 };

	get_curpath(fname, PATH_LEN);
	xscat(fname, _T("/unicode.acp"));

	fh = xuncf_open_file(NULL, fname, FILE_OPEN_CREATE);
	if (!fh) return;

	for (i = 0; i < CODE_SIZE; i++)
	{
		fw = code_unicode_gb2312[i][0];
		tw = code_unicode_gb2312[i][1];
		ch = (tchar_t)code_unicode_gb2312[i][2];
		if(!ch) ch = _T(' ');

		xsprintf(str, _T("0x%02X%02X,0x%02X%02X,%c\n"),
			GETSWORDH(fw), GETSWORDL(fw), 
			GETSWORDH(tw), GETSWORDL(tw), 
			ch);

#if defined(_UNICODE) || defined(UNICODE)
		dw = ucs_to_utf8(str, -1, utf_buf, 1024);
#else
		dw = mbs_to_utf8(str, -1, utf_buf, 1024);
#endif

		xuncf_write_file(fh, utf_buf, &dw);

	}

	xuncf_close_file(fh);
}
