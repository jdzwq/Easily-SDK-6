/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc spin lock document

	@module	spinlock.c | implement file

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

#include "spinlock.h"

#include "../xdkobj.h"
#include "../xdkstd.h"
#include "../xdkimp.h"

#define SPINLOCK_MAPBITS		2

#define SPINLOCK_TAG_NONE		0x00
#define SPINLOCK_TAG_LOCK		0x01
#define SPINLOCK_TAG_WAIT		0x02
#define SPINLOCK_TAG_BITMASK	0x03

typedef struct _spinlock_context{
	memo_head head;

	xhand_t share;

	map_t map;
	dword_t map_size;
}spinlock_context;

/************************************************************************************/

spinlock_t alloc_spinlock(dword_t map_nums)
{
	spinlock_context* ppt = NULL;

	TRY_CATCH;

	ppt = (spinlock_context*)xmem_alloc(sizeof(spinlock_context));
	ppt->head.tag = MEM_SPINLOCK;

	ppt->map = map_alloc(map_nums, SPINLOCK_MAPBITS);
	if (!ppt->map)
	{
		raise_user_error(_T("create_spinlock"), _T("alloc map object failed"));
	}
	ppt->map_size = map_need_size(map_nums, SPINLOCK_MAPBITS);

	ppt->share = xshare_cli(SHARE_SPINLOCK, MAX_LONG, FILE_OPEN_CREATE);
	if (!ppt->share)
	{
		raise_user_error(_T("create_spinlock"), _T("alloc share object failed"));
	}

	END_CATCH;

	return &ppt->head;
ONERROR:

	if (ppt->share)
		xshare_close(ppt->share);

	if (ppt->map)
		map_free(ppt->map);

	if (ppt)
		xmem_free(ppt);

	return NULL;
}

void free_spinlock(spinlock_t pt)
{
	spinlock_context* ppt = TypePtrFromHead(spinlock_context, pt);
	
	tchar_t token[NUID_TOKEN_SIZE + 5] = { 0 };

	XDK_ASSERT(pt && pt->tag == MEM_SPINLOCK);

	xshare_close(ppt->share);

	map_free(ppt->map);

	xmem_free(ppt);
}

bool_t enter_spinlock(spinlock_t pt, dword_t map_ind, dword_t map_pos)
{
	spinlock_context* ppt = TypePtrFromHead(spinlock_context, pt);

	dword_t offs;
	byte_t *buff;
	byte_t tag;
	int tms = 1000;

	XDK_ASSERT(pt && pt->tag == MEM_SPINLOCK);

	offs = map_ind * ppt->map_size;
	buff = (byte_t*)xshare_lock(ppt->share, offs, ppt->map_size);

	XDK_ASSERT(buff != NULL);

	map_attach(ppt->map, (void*)buff);

	tag = map_get_bit(ppt->map, map_pos);
	tag &= SPINLOCK_TAG_BITMASK;

	switch(tag)
	{
		case SPINLOCK_TAG_NONE:
			tag = SPINLOCK_TAG_LOCK; //SPINLOCK_TAG_LOCK;
			map_set_bit(ppt->map, map_pos, tag);
			break;
		case SPINLOCK_TAG_LOCK:
			tag <<= 1; //SPINLOCK_TAG_WAIT;
			map_set_bit(ppt->map, map_pos, tag);
			break;
		case SPINLOCK_TAG_WAIT:
			while(tms -- && (tag = map_get_bit(ppt->map, map_pos) & SPINLOCK_TAG_BITMASK) == SPINLOCK_TAG_WAIT)
			{
				thread_yield();
			}
			tag <<= 1; 
			map_set_bit(ppt->map, map_pos, tag);
			break;
	}

	buff = (byte_t*)map_detach(ppt->map);

	xshare_unlock(ppt->share, offs, ppt->map_size, buff);

	return (tag == SPINLOCK_TAG_LOCK)? bool_true : bool_false;
}

void leave_spinlock(spinlock_t pt, dword_t map_ind, dword_t map_pos)
{
	spinlock_context* ppt = TypePtrFromHead(spinlock_context, pt);

	dword_t offs;
	byte_t *buff;
	byte_t tag;

	XDK_ASSERT(pt && pt->tag == MEM_SPINLOCK);

	offs = map_ind * ppt->map_size;
	buff = (byte_t*)xshare_lock(ppt->share, offs, ppt->map_size);

	XDK_ASSERT(buff != NULL);

	map_attach(ppt->map, (void*)buff);

	tag = map_get_bit(ppt->map, map_pos);
	tag &= SPINLOCK_TAG_BITMASK;
	tag <<= 1;
	map_set_bit(ppt->map, map_pos, tag);

	buff = (byte_t*)map_detach(ppt->map);

	xshare_unlock(ppt->share, offs, ppt->map_size, buff);
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
unsigned int STDCALL _spinlock_proc(void* param)
{
	int ti = *((int*)param);
	dword_t inds = 1;
	dword_t nums = 4096;
	spinlock_t lt;
	bool_t rt;
	dword_t ind, pos;
	int k;

	xdk_thread_init(0);

	TRY_CATCH;

	lt = alloc_spinlock(nums);
	XDK_ASSERT(lt != NULL);

	system_srand();

	for (ind = 0; ind < inds; ind++)
	{
		//pos = system_rand32() % nums;
		pos = 0;

		while (enter_spinlock(lt, ind, pos) == bool_false)
		{
			_tprintf(_T("thread:%d ind:%d pos:%d wait...\n"), ti, ind, pos);
			thread_yield();
		}

		_tprintf(_T("thread:%d ind:%d pos:%d enter...\n"), ti, ind, pos);
		//thread_sleep(100);
		thread_yield();

		leave_spinlock(lt, ind, pos);
		_tprintf(_T("thread:%d ind:%d pos:%d leav...\n"), ti, ind, pos);
	}

	free_spinlock(lt);

	END_CATCH;

	xdk_thread_uninit(0);

	return 0;

ONERROR:

	xdk_thread_uninit(0);

	return 0;
}

void spinlock_self_test()
{
	int maxt = 4;
	res_thread_t* pth;

	printf("test spinlock...\n");
    
	pth = (res_thread_t*)xmem_alloc(maxt * sizeof(res_thread_t));

	for (int i = 0; i < maxt; i++)
    {
        thread_start(&pth[i], (PF_THREADFUNC)_spinlock_proc, (void*)&i);
    }
    
	for (int i = 0; i < maxt; i++)
	{
		thread_join(pth[i]);
	}

	xmem_free(pth);
}
#endif