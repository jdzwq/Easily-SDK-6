
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif


int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//map_self_test();

	//matrix_self_test();

	//vector_self_test();

	//set_self_test();

	//variant_self_test();

	//message_self_test();

	object_self_test();

	xdk_process_uninit();
#ifdef _OS_WINDOWS
	getch();
#endif

	return 0;
}

