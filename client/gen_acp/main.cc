
#include <xdk.h>

//3000-303F：CJK 符号和标点 (CJK Symbols and Punctuation)
//FF00-FFEF：半型及全型形式 (Halfwidth and Fullwidth Form)
//4E00-9FFF：CJK 统一表意符号 (CJK Unified Ideographs)

/********************************************************************************/

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
		ucs_byte_to_gbk((wchar_t)u, m);

		pch[0] = GETHBYTE(u);
		pch[1] = GETLBYTE(u);

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
		ucs_byte_to_gbk((wchar_t)u, m);

		pch[0] = GETHBYTE(u);
		pch[1] = GETLBYTE(u);

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

int main(int argc, const char * argv[]) {

    xdk_process_init(XDK_APARTMENT_PROCESS);

	//cjk_ucs_3000();

	cjk_ucs_ff00();

    xdk_process_uninit();

    return 0;
}
