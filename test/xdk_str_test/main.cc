
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif


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

