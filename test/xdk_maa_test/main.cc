
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif


int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	test_integer_array();

	test_numeric_array();

	test_string_array();

	xdk_process_uninit();

#ifdef _OS_WINDOWS
	getch();
#endif

	return 0;
}

