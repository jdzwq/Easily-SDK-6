
#include <xdk.h>


void test_memo_dump()
{
	void* p;

	for(int i = 0; i < 256; i++)
	{
		p = xmem_alloc(1024);

		xmem_assert(p);

		xmem_set(p, (byte_t)i, 1024);

		if(i % 2 == 0)
		{
			xmem_free(p);
		}
	}

	xmem_dump();
}

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//test_memo_dump();

	//error_self_test();

	//pmem_self_test();

	//xcache_self_test();

	//xshare_test_cli();

	//xshare_test_srv();

	//timer_self_test();

	xuncf_self_test();

	xdk_process_uninit();

	return 0;
}

