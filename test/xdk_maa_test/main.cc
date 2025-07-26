
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif

void test_integer_array()
{
	int** sa = alloc_integer_array();
	int i;

	for (i = 0; i < 10; i++)
	{
		insert_integer(sa, i, i);
	}

	for (i = 0; i < 10; i++)
	{
		_tprintf(_T("%d\n"), get_integer(sa, i));
	}

	while (get_integer_array_size(sa))
	{
		delete_integer(sa, 0);
	}

	free_integer_array(sa);
}

void test_numeric_array()
{
	double** sa = alloc_numeric_array();
	int i;

	for (i = 0; i < 10; i++)
	{
		insert_numeric(sa, i, i);
	}

	for (i = 0; i < 10; i++)
	{
		_tprintf(_T("%f\n"), get_numeric(sa, i));
	}

	while (get_numeric_array_size(sa))
	{
		delete_numeric(sa, 0);
	}

	free_numeric_array(sa);
}

void test_string_array()
{
	tchar_t token[10];

	tchar_t** sa = alloc_string_array();

	for (int i = 0; i < 10; i++)
	{
		xsprintf(token, _T("token%d"), i);
		insert_string(sa, i, token, -1);
	}

	for (int i = 0; i < 10; i++)
	{
		_tprintf(_T("%s\n"), get_string_ptr(sa, i));
	}

	while (get_string_array_size(sa))
	{
		delete_string(sa, 0);
	}

	free_string_array(sa);
}

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

