
#include <stdio.h>
#include <string.h>

#include <oem.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif

void test_zlib()
{
	char data[] = "Hello, World!";
	uint32_t len = strlen(data);
	unsigned char buf[100] = { 0 };
	uint32_t dw;
	unsigned char dst[100] = { 0 };

	dw = 100;
	if(Z_OK == compress(buf, (uLongf*)&dw, (unsigned char*)data, len))
	{
		printf("compress success\n");
	}
	else
	{
		printf("compress failed\n");
	}

	len = 100;
	if(Z_OK == uncompress(dst, (uLongf*)&len, buf, dw))
	{
		printf("uncompress success\n");
	}
	else
	{
		printf("uncompress failed\n");
	}
}

int main(int argc, char* argv[])
{

	test_zlib();

#ifdef _OS_WINDOWS
	getch();
#endif

	return 0;
}

