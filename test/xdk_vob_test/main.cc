
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif





int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//spinlock_self_test();

	//sequence_self_test();

	//queue_self_test();

	xdk_process_uninit();

	return 0;
}

