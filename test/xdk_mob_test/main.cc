
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif


int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//test_linear();

	//test_map();

	//test_matrix();

	//test_message();

	//test_queue();

	//test_set();

	//test_spinlock();

	//test_variant();

	//test_object();

	test_vector();

	xdk_process_uninit();
#ifdef _OS_WINDOWS
	getch();
#endif

	return 0;
}

