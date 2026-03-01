/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc numericarray document

	@module	numericarray.c | implement file

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

#include "numericarray.h"

#include "../xdkimp.h"
#include "../xdkstd.h"

double** alloc_numeric_array(void)
{
	double** ptr;

	ptr = (double**)xmem_alloc(2 * sizeof(double*));

	return ptr;
}

double* realloc_numeric_array(double** sa, int count)
{
	XDK_ASSERT(sa != NULL);

	*sa = (double*)xmem_realloc((void*)(*sa), (count * sizeof(double)));
	*(int*)(sa + 1) = count;

	return *sa;
}

void free_numeric_array(double** sa)
{
	xmem_free(*sa);

	xmem_free(sa);
}

void clear_numeric_array(double** sa)
{
	xmem_free(*sa);

	xmem_zero((void*)sa, 2 * sizeof(double*));
}

int get_numeric_array_size(double** sa)
{
	return (int)(*(int*)(sa + 1));
}

double get_numeric(double** sa, int index)
{
	double* pa = *sa;
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	return pa[index];
}

int copy_numeric(double** sa, int index, double* buf, int max)
{
	double* pa = *sa;
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	max = (max < size - index)? max : (size - index);

	if(buf)
	{
		xmem_copy((void*)buf, (void*)(pa + index), max * sizeof(double));
	}

	return max;
}

void insert_numeric(double** sa, int index, const double* pa, int count)
{
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index <= size);

	*sa = (double*)xmem_realloc(*sa, (size + count) * sizeof(double));

	xmem_move((void*)(*sa + index), ((size - index) * sizeof(double)), (int)(count * sizeof(double)));
	xmem_copy((void*)(*sa + index), (void*)pa, count * sizeof(double));

	*(int*)(sa + 1) = (size + count);
}

void delete_numeric(double** sa, int index, int count)
{
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	xmem_move((void*)(*sa + index + 1), ((size - index - 1) * sizeof(double)), -(int)(count * sizeof(double)));

	*sa = (double*)xmem_realloc(*sa, (size - count) * sizeof(double));

	*(int*)(sa + 1) = (size - count);
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void test_numeric_array()
{
	double** sa = alloc_numeric_array();
	int i;
	double d;

	for (i = 0; i < 10; i++)
	{
		d = i;
		insert_numeric(sa, i, &d, 1);
	}

	for (i = 0; i < 10; i++)
	{
		_tprintf(_T("%f\n"), get_numeric(sa, i));
	}

	while (get_numeric_array_size(sa))
	{
		delete_numeric(sa, 0, 1);
	}

	free_numeric_array(sa);
}
#endif