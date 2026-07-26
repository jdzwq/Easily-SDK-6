
#include "_appdef.h"


void _show_version()
{
	_tprintf(_T("xConvert 1.0 "));

#ifdef _OS_WINDOWS
	_tprintf(_T("Window "));
#endif

#ifdef _OS_MACOS
	_tprintf(_T("Macos "));
#endif

#ifdef _OS_LINUX
	_tprintf(_T("Linux "));
#endif

#ifdef _OS_64
	_tprintf(_T("64 "));
#endif

#ifdef _OS_32
	_tprintf(_T("32 "));
#endif

	_tprintf(_T("\n"));
}

void _show_help()
{
	_tprintf(_T("\
******************************************************************\n\
 * gen_sql usage:\n\
 * -v :show gen_sql version\n\
 * -h :show gen_sql usages\n\
 * -i path/to/file :show file coding information\n\
 * -l path/to/file lines encode :show file some head lines.\n\
 *    :lines [1-100].\n\
 *    :encode [gb2312|utf-8|utf-16-lit|utf-16-big].\n\
 * -c path/to/file src-encode dst-encode :convert file encoding.\n\
 *    :src-encode [gb2312|utf-8|utf-16-lit|utf-16-big].\n\
 *    :dst-encode [gb2312|utf-8|utf-16-lit|utf-16-big].\n\
 * -g path/to/file encode target :generate sql operating file.\n\
 *    :encode [gb2312|utf-8|utf-16-lit|utf-16-big].\n\
 *    :target [ddl|ctl|sql].\n\
******************************************************************\n"));
}

#if defined(WINDOWS)
#pragma comment( linker, "/subsystem:windows /entry:mainCRTStartup" )
int _tmain(int argc, _TCHAR* argv[]){
#else
int main(int argc, const char * argv[]) {
#endif

	tchar_t param[10] = {0};
	tchar_t pname[PATH_LEN] = { 0 };
	tchar_t pv3[RES_LEN] = { 0 };
	tchar_t pv4[RES_LEN] = { 0 };

    xdk_process_init(XDK_APARTMENT_PROCESS);

	if (argc > 1)
	{
		xscpy(param, argv[1]);
	}

	if (argc > 2)
	{
		xscpy(pname, argv[2]);
	}

	if (argc > 3)
	{
		xscpy(pv3, argv[3]);
	}

	if (argc > 4)
	{
		xscpy(pv4, argv[4]);
	}

	switch(param[1])
	{
	case _T('v'):
	case _T('V'):
		_show_version();
		break;
	case _T('h'):
	case _T('H'):
		_show_help();
		break;
	case _T('i'):
	case _T('I'):
		_show_info(pname);
		break;
	case _T('l'):
	case _T('L'):
		_show_lines(pname, xstol(pv3), pv4);
		break;
	case _T('c'):
	case _T('C'):
		_conv_text(pname, pv3, pv4);
		break;
	case _T('g'):
	case _T('G'):
		if(xsicmp(pv4, _T("ctl")) == 0)
			_make_ctl(pname, pv3);
		else if(xsicmp(pv4, _T("ddl")) == 0)
			_make_ddl(pname, pv3);
		else if(xsicmp(pv4, _T("sql")) == 0)
			_make_sql(pname, pv3);
		break;
	}

    xdk_process_uninit();

    return 0;
}
