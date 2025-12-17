
#include "_defi.h"

void dump_acp_gb2312()
{
	xhand_t fh;
	tchar_t fname[PATH_LEN];
	dword_t dw;
	tchar_t str[512] = { 0 };
	byte_t utf_buf[1024] = { 0 };

	byte_t* pb;
	dword_t n;
	int i;
	acp_table_t* pt;
	wchar_t wc[4] = {0};
	schar_t sc[4] = {0};
	schar_t py[2] = {0};

	if (!acp_gb2312) 
	{
		_tprintf(_T("unload acp_gb2312_table\n"));
	}

	get_curpath(fname, PATH_LEN);
	xscat(fname, _T("/unicode.txt"));

	fh = xuncf_open_file(NULL, fname, FILE_OPEN_CREATE);
	if (!fh) return;

	n = CHS_GB2312_COUNT * sizeof(acp_table_t);
	pb = (byte_t *)xshare_lock(acp_gb2312, 0, n);
	if (pb)
	{
		for (i = 0; i < CHS_GB2312_COUNT; i++)
		{
			pt = (acp_table_t *)(pb + i * sizeof(acp_table_t));
			wc[0] = GET_SWORD_LOC((byte_t *)pt, 0);
			py[0] = (unsigned char)GET_SWORD_LOC((byte_t *)pt, 2);
			if (!wc[0]) continue;

			ucs_to_utf8(wc, 1, (byte_t *)sc, 4);
			xsprintf(str, _T("unicode: %s, py: %s\n"), sc, py);

#if defined(_UNICODE) || defined(UNICODE)
			dw = ucs_to_utf8(str, -1, utf_buf, 1024);
#else
			dw = mbs_to_utf8(str, -1, utf_buf, 1024);
#endif

			xuncf_write_file(fh, utf_buf, &dw);
		}

		xshare_unlock(acp_gb2312, 0, n, pb);
	}

	xuncf_close_file(fh);
}

void dump_acp_unicode()
{
	xhand_t fh;
	tchar_t fname[PATH_LEN];
	dword_t dw;
	tchar_t str[512] = { 0 };
	byte_t utf_buf[1024] = { 0 };

	byte_t* pb;
	dword_t n;
	int i;
	acp_table_t* pt;
	schar_t bc[4] = {0};
	schar_t sc[4] = {0};
	schar_t py[2] = {0};

	if (!acp_unicode)
	{
		_tprintf(_T("unload acp_unicode_table\n"));
	}

	get_curpath(fname, PATH_LEN);
	xscat(fname, _T("/gb2312.txt"));

	fh = xuncf_open_file(NULL, fname, FILE_OPEN_CREATE);
	if (!fh) return;

	n = CHS_UNICODE_COUNT * sizeof(acp_table_t);
	pb = (byte_t *)xshare_lock(acp_unicode, 0, n);
	if (pb)
	{
		for (i = 0; i < CHS_UNICODE_COUNT; i++)
		{
			pt = (acp_table_t *)(pb + i * sizeof(acp_table_t));
			bc[0] = GETLBYTE(GET_SWORD_LOC((byte_t *)pt, 0));
			bc[1] = GETHBYTE(GET_SWORD_LOC((byte_t *)pt, 0));
			py[0] = (unsigned char)GET_SWORD_LOC((byte_t *)pt, 2);
			if (!bc[0] || !bc[1]) continue;

			gb2312_to_utf8((byte_t *)bc, 2, (byte_t *)sc, 4);
			xsprintf(str, _T("gb2312: %s, py: %s\n"), (char *)sc, py);

#if defined(_UNICODE) || defined(UNICODE)
			dw = ucs_to_utf8(str, -1, utf_buf, 1024);
#else
			dw = mbs_to_utf8(str, -1, utf_buf, 1024);
#endif

			xuncf_write_file(fh, utf_buf, &dw);
		}

		xshare_unlock(acp_unicode, 0, n, pb);
	}

	xuncf_close_file(fh);
}
