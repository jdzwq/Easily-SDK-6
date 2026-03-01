
#include <xdk.h>



int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//base64_self_test();

	//der_self_test();

	csv_encode_test();

	xdk_process_uninit();

	return 0;
}

