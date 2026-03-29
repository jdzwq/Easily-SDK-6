/***********************************************************************
	Easily SDK 6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc integerarray document

	@module	integerarray.c | implement file

	@devnote 张文权 2021.01 - 2021.12	v6.0
***********************************************************************/

/**********************************************************************
This program is free software : you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
LICENSE.GPL3 for more details.
***********************************************************************/

#include "integerarray.h"

#include "../xdkimp.h"
#include "../xdkstd.h"

int** alloc_integer_array(void)
{
	int** sa;

	sa = (int**)xmem_alloc(2 * sizeof(int*));

	return sa;
}

int* realloc_integer_array(int** sa, int count)
{
	XDK_ASSERT(sa != NULL);

	*sa = (int*)xmem_realloc((void*)(*sa), (count * sizeof(int)));
	*(int*)(sa + 1) = count;

	return *sa;
}

void free_integer_array(int** sa)
{
	xmem_free(*sa);

	xmem_free(sa);
}

void clear_integer_array(int** sa)
{
	xmem_free(*sa);

	xmem_zero((void*)sa, 2 * sizeof(int*));
}

int get_integer_array_size(int** sa)
{
	return (int)(*(int*)(sa + 1));
}

int get_integer(int** sa, int index)
{
	int* pa = *sa;
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	return pa[index];
}

int get_integer_safe(int** sa, int index, int def)
{
	int* pa = *sa;
	int size;

	size = (int)(*(int*)(sa + 1));

	if(index >= 0 && index < size)
		return pa[index];
	else
		return def;
}

int copy_integer(int** sa, int index, int* buf, int max)
{
	int* pa = *sa;
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	max = (max < size - index)? max : (size - index);

	if(buf)
	{
		xmem_copy((void*)buf, (void*)(pa + index), max * sizeof(int));
	}

	return max;
}

void insert_integer(int** sa, int index, const int* pa, int count)
{
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index <= size);

	*sa = (int*)xmem_realloc((void*)*sa, (size + count) * sizeof(int));

	xmem_move((void*)(*sa + index), ((size - index) * sizeof(int)), (int)(count * sizeof(int)));
	xmem_copy((void*)(*sa + index), (void*)pa, count * sizeof(int));

	*(int*)(sa + 1) = (size + count);
}

void delete_integer(int** sa, int index, int count)
{
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	xmem_move((void*)(*sa + index + 1), ((size - index - 1) * sizeof(int)), -(int)(count * sizeof(int)));

	*sa = (int*)xmem_realloc((void*)*sa, (size - count) * sizeof(int));

	*(int*)(sa + 1) = (size - count);
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void test_integer_array()
{
	int** sa = alloc_integer_array();
	int i;

	for (i = 0; i < 10; i++)
	{
		insert_integer(sa, i, &i, 1);
	}

	for (i = 0; i < 10; i++)
	{
		_tprintf(_T("%d\n"), get_integer(sa, i));
	}

	while (get_integer_array_size(sa))
	{
		delete_integer(sa, 0, 1);
	}

	free_integer_array(sa);
}
#endif