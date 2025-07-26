
#include <xdk.h>

void test_csv_encode()
{
	xhand_t xh = NULL;
	tchar_t buf[1024] = { 0 };
	tchar_t token[1024] = { 0 };
	dword_t dw = 0;
	int len = 0;

	TRY_CATCH;

	xh = xuncf_open_file(NULL, _T("test.csv"), FILE_OPEN_CREATE);
	if(xh == NULL)
	{
		raise_user_error(_T("test_csv_encode"), _T("xuncf_open_file failed"));
	}

	dw = a_xsprintf((schar_t*)buf, "代码,名称\n");
	xuncf_write_file(xh, (byte_t*)buf, &dw);

	csv_token_encode(_T("名称\"别名,其%他"),-1, token, &len);
	csv_token_decode(token, -1, buf, &len);
	_tprintf(_T("csv_token_decode: %s\n"), buf);

	dw = a_xsprintf((schar_t*)buf, "0001,%s\n", token);
	xuncf_write_file(xh, (byte_t*)buf, &dw);

	xuncf_close_file(xh);
	xh = NULL;

	END_CATCH;

	return;

ONERROR:
	if(xh) xuncf_close_file(xh);
	XDK_TRACE_LAST;
}

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	test_csv_encode();

	xdk_process_uninit();

	return 0;
}

