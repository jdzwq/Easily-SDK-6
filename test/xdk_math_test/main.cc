
#include <xdk.h>

void test_dbl()
{
	double x = INFINITE;

	bool_t b = dbl_is_nar(x);

	double y = dbl_pow(x, -1.);
	b = dbl_is_nar(y);

	y = dbl_pow(x, 2.);
	b = dbl_is_nar(y);
}

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	dbl_init();

	test_dbl();

	xdk_process_uninit();

	return 0;
}

