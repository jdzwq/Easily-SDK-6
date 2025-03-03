﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc global/heap/virtual memory system call document

	@module	_if_memo.c | linux implement file

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


#include "../xdkloc.h"


#ifdef XDK_SUPPORT_MEMO
/*****************************************************************************************/

void* _local_alloc(dword_t size)
{
    return calloc(1, (size_t)size);
}

void* _local_realloc(void* p, dword_t size)
{
    return realloc(p, (size_t)size);
}

void _local_free(void* p)
{
    free(p);
}

/******************************************************************************/
#ifdef XDK_SUPPORT_MEMO_HEAP

typedef struct _heap_head* _heap_head_ptr;

typedef struct _heap_head{
    _heap_head_ptr prev;
    _heap_head_ptr next;
}heap_head;

const heap_head proc_heap = {0};

res_heap_t _process_heapo(void)
{
	return (res_heap_t)&proc_heap;
}

res_heap_t _heapo_create(void)
{
    heap_head* phh;

    phh = (heap_head*)calloc(1, sizeof(heap_head));
    phh->next = phh->prev = phh;

	return (res_heap_t)phh;
}

void  _heapo_destroy(res_heap_t heap)
{
    heap_head* phh = (heap_head*)heap;
    heap_head* pnn;

    while((pnn = phh->next) != phh)
    {
        phh->next = pnn->next;
        (pnn->next)->prev = phh;

        free(pnn);
    }

    free(phh);
}

void* _heapo_alloc(res_heap_t heap, dword_t size)
{
    heap_head* phh = (heap_head*)heap;
    heap_head* pnn;

    if(!size) return NULL;

    if(heap == &proc_heap)
    {
        return calloc(1, size);
    }else
    {
        pnn = (heap_head*)calloc(1, sizeof(heap_head) + size);

        phh->next->prev = pnn;
        pnn->next = phh->next;
        phh->next = pnn;
        pnn->prev = phh;

        return (void*)((void*)pnn + sizeof(heap_head));
    }
}

void* _heapo_realloc(res_heap_t heap, void* p, dword_t size)
{
    heap_head* phh = (heap_head*)heap;
    heap_head* pnn;

    if(!p) return _heapo_alloc(heap, size);

    if(heap == &proc_heap)
    {
        return realloc(p, size);
    }else
    {
        pnn = (heap_head*)(p - sizeof(heap_head));
        pnn->prev->next = pnn->next;
        (pnn->next)->prev = pnn->prev;

        pnn = (heap_head*)realloc((void*)pnn, sizeof(heap_head) + size);
        phh->next->prev = pnn;
        pnn->next = phh->next;
        phh->next = pnn;
        pnn->prev = phh;

        return (void*)((void*)pnn + sizeof(heap_head));
    }
}

void _heapo_zero(res_heap_t heap, void* p, dword_t size)
{
    if(!p) return;
    
    memset(p, 0, size);
}

void _heapo_free(res_heap_t heap, void* p)
{
    heap_head* phh = (heap_head*)heap;
    heap_head* pnn;

    if(!p) return;

    if(heap == &proc_heap)
    {
        free(p);
    }else
    {
        pnn = (heap_head*)(p - sizeof(heap_head));
        pnn->prev->next = pnn->next;
        (pnn->next)->prev = pnn->prev;

        free(pnn);
    }
}

void _heapo_clean(res_heap_t heap)
{
   
}
#endif

/******************************************************************************/
#ifdef XDK_SUPPORT_MEMO_PAGE
void* _paged_alloc(dword_t size)
{
    void* p = NULL;
    dword_t dw;
    
    dw = size / PAGE_SIZE;
    if (size % PAGE_SIZE)
        dw++;
    
    return (posix_memalign(&p, PAGE_SIZE, (size_t)(dw * PAGE_SIZE)) < 0)? NULL : p;
}

void* _paged_realloc(void* p, dword_t size)
{
    void* pn;
    dword_t n;
    
    if (!p)
        return _paged_alloc(size);
    
    n = (dword_t)malloc_usable_size(p);
    
    if (n < size)
    {
        pn = _paged_alloc(size);
        
        n = _paged_size(p);
        n = (n < size) ? n : size;
        
        memcpy(pn, p, n);
        
        _paged_free(p);
        return pn;
    }
    else
    {
        memset((void*)((char*)p + size), 0, n - size);
        return p;
    }
}

void _paged_free(void* p)
{
    free(p);
}

dword_t _paged_size(void* p)
{
    return (dword_t)malloc_usable_size(p);
}

void* _paged_lock(void* p)
{
    size_t n;
    
    n = malloc_usable_size(p);

    mlock(p, n);
    
	return p;
}

void _paged_unlock(void* p)
{
    size_t n;
    
    n = malloc_usable_size(p);
    
    munlock(p, n);
}

bool_t _paged_protect(void* p, bool_t b)
{
    size_t n;
    
    n = malloc_usable_size(p);

    mprotect(p, n, PROT_READ);
	
	return 0;
}
#endif

/*****************************************************************************************/
#ifdef XDK_SUPPORT_MEMO_CACHE

void* _cache_open()
{
    void* p;
    
    p = mmap(NULL, PAGE_SPACE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    return (p == MAP_FAILED)? NULL : p;
}

void _cache_close(void* fh)
{
	munmap(fh, PAGE_SPACE);
}

bool_t _cache_write(void* fh, dword_t hoff, dword_t loff, void* buf, dword_t size, dword_t* pb)
{
    size_t off;

    off = MAKESIZE(loff, hoff);

    memcpy((void*)((char*)fh + off), buf, (size_t)size);

    if(pb)
        *pb = size;
    
    return 1;
}

bool_t _cache_read(void* fh, dword_t hoff, dword_t loff, void* buf, dword_t size, dword_t* pb)
{
    size_t off;

    off = MAKESIZE(loff, hoff);

    memcpy(buf, (void*)((char*)fh + off), (size_t)size);
    
    if(pb)
        *pb = size;
    
    return 1;
}
#endif

#endif //XDK_SUPPORT_MEMO