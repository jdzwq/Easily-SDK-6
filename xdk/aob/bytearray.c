/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc variant bytes document

	@module	varbytes.c | implement file

	@devnote 张文权 2021.01 - 2021.12	v6.0
***********************************************************************/

/**********************************************************************
This program is free software : you can radistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
LICENSE.GPL3 for more details.
***********************************************************************/

#include "bytearray.h"

#include "../xdkimp.h"
#include "../xdkstd.h"

byte_t** bytes_alloc(void)
{
	byte_t** sa;

	sa = (byte_t**)xmem_alloc(2 * sizeof(byte_t*));

	return sa;
}

byte_t* bytes_realloc(byte_t** pp, int count)
{
	XDK_ASSERT(pp != NULL);

	*pp = (byte_t*)xmem_realloc((void*)(*pp), count * sizeof(byte_t));
	*(int*)(pp + 1) = count;

	return *pp;
}

void bytes_free(byte_t** sa)
{
	xmem_free(*sa);

	xmem_free(sa);
}

void bytes_clear(byte_t** sa)
{
	xmem_free(*sa);

	xmem_zero((void*)sa, 2 * sizeof(byte_t*));
}

int bytes_size(byte_t** sa)
{
	return (*(int*)(sa + 1));
}

byte_t bytes_byte(byte_t** sa, int index)
{
	byte_t* pa = *sa;
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	return pa[index];
}

int bytes_copy(byte_t** sa, int index, byte_t* buf, int max)
{
	byte_t* pa = *sa;
	int size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	max = (max < size - index)? max : (size - index);

	if(buf)
	{
		xmem_copy((void*)buf, (void*)(pa + index), max * sizeof(byte_t));
	}

	return max;
}

void bytes_insert(byte_t** sa, int index, const byte_t* pa, int count)
{
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index <= size);

	*sa = (byte_t*)xmem_realloc((void*)(*sa), (size + count) * sizeof(byte_t));

	xmem_move((void*)(*sa + index), ((size - index) * sizeof(byte_t)), (int)(count * sizeof(byte_t)));
	xmem_copy((void*)(*sa + index), (void*)pa, count * sizeof(byte_t));

	*(int*)(sa + 1) = (size + count);
}

void bytes_delete(byte_t** sa, int index, int count)
{
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	count = (count < size - index)? count : (size - index);
	xmem_move((void*)(*sa + index + 1), ((size - index - 1) * sizeof(byte_t)), -(int)(count * sizeof(byte_t)));

	*sa = (byte_t*)xmem_realloc((void*)*sa, (size - count) * sizeof(byte_t));

	*(int*)(sa + 1) = (size - count);
}

void bytes_attach(byte_t** pp, byte_t* p, int len)
{
	XDK_ASSERT(pp != NULL);

	xmem_free(*pp);
	*pp = p;
	*(int*)(pp + 1) = len;
}

byte_t* bytes_detach(byte_t** pp)
{
	byte_t* pb = *pp;

	XDK_ASSERT(pp != NULL);

	*pp = NULL;
	*(int*)(pp + 1) = 0;

	return pb;
}