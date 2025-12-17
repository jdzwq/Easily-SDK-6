
#include "_defi.h"

int main(int argc, const char * argv[]) {

    xdk_process_init(XDK_APARTMENT_PROCESS);

	if(argc > 1 && a_xsicmp(argv[1], "-acp") == 0)
	{
		acp_gb2312_unicode();

		acp_unicode_gb2312();
	} else if(argc > 1 && a_xsicmp(argv[1], "-dump") == 0)
	{
		dump_acp_gb2312();

		dump_acp_unicode();
	}else
	{
		_tprintf(_T("\
usage for generating acp table file: gen_acp -acp\n\
usage for dumping acp table: gen_acp -dump\n"));
	}

    xdk_process_uninit();

    return 0;
}
