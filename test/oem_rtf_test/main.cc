
#include <oem.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif

int main(int argc, char* argv[])
{


#ifdef _OS_WINDOWS
	getch();
#endif

	return 0;
}

