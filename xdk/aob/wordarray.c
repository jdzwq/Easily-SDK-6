/***********************************************************************
	Easily SDK 6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc array object document

	@module	wordarray.c | implement file

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

#include "wordarray.h"

#include "../xdkimp.h"
#include "../xdkstd.h"

sword_t** words_alloc(void)
{
	sword_t** sa;

	sa = (sword_t**)xmem_alloc(2 * sizeof(sword_t*));

	return sa;
}

sword_t* words_realloc(sword_t** pp, int count)
{
	XDK_ASSERT(pp != NULL);

	*pp = (sword_t*)xmem_realloc((void*)(*pp), (count) * sizeof(sword_t));
	*(int*)(pp + 1) = count;

	return *pp;
}

void words_free(sword_t** sa)
{
	xmem_free(*sa);

	xmem_free(sa);
}

void words_clear(sword_t** sa)
{
	xmem_free(*sa);

	xmem_zero((void*)sa, 2 * sizeof(sword_t*));
}

int words_size(sword_t** sa)
{
	return (*(int*)(sa + 1));
}

sword_t get_words(sword_t** sa, int index)
{
	sword_t* pa = *sa;
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	return pa[index];
}

sword_t get_words_safe(sword_t** sa, int index, sword_t def)
{
	sword_t* pa = *sa;
	int size;

	size = (int)(*(int*)(sa + 1));

	if(index >= 0 && index < size)
		return pa[index];
	else
		return def;
}

int words_copy(sword_t** sa, int index, sword_t* buf, int max)
{
	sword_t* pa = *sa;
	int size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	max = (max < size - index)? max : (size - index);

	if(buf)
	{
		xmem_copy((void*)buf, (void*)(pa + index), max * sizeof(sword_t));
	}

	return max;
}

void words_insert(sword_t** sa, int index, const sword_t* pa, int count)
{
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index <= size);

	*sa = (sword_t*)xmem_realloc((void*)(*sa), (size + count) * sizeof(sword_t));

	xmem_move((void*)(*sa + index), ((size - index) * sizeof(sword_t)), (int)(count * sizeof(sword_t)));
	xmem_copy((void*)(*sa + index), (void*)pa, count * sizeof(sword_t));

	*(int*)(sa + 1) = (size + count);
}

void words_delete(sword_t** sa, int index, int count)
{
	int size;

	size = (int)(*(int*)(sa + 1));

	XDK_ASSERT(index >= 0 && index < size);

	count = (count < size - index)? count : (size - index);
	xmem_move((void*)(*sa + index + 1), ((size - index - 1) * sizeof(sword_t)), -(int)(count * sizeof(sword_t)));

	*sa = (sword_t*)xmem_realloc((void*)*sa, (size - count) * sizeof(sword_t));

	*(int*)(sa + 1) = (size - count);
}

void words_attach(sword_t** pp, sword_t* p, int len)
{
	XDK_ASSERT(pp != NULL);

	xmem_free(*pp);
	*pp = p;
	*(int*)(pp + 1) = len;
}

sword_t* words_detach(sword_t** pp)
{
	sword_t* pb = *pp;

	XDK_ASSERT(pp != NULL);

	*pp = NULL;
	*(int*)(pp + 1) = 0;

	return pb;
}