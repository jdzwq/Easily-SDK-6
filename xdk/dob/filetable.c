﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc filetable document

	@module	filetable.c | implement file

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

#include "filetable.h"

#include "../xdkimp.h"
#include "../xdkoem.h"
#include "../xdkstd.h"

#define FILETABLE_MAPBITS		1

#define FILETABLE_ALLOCED		0x01
#define FILETABLE_RELEASED		0x00

#define IS_FILETABLE_MAPBITS(n)		((n == 1 || n == 2 || n == 4 || n == 8)? 1 : 0)
#define IS_FILETABLE_PAGESIZE(n)	((n == 4096 || n == 8192)? 1 : 0)
#define IS_FILETABLE_BLOCKSIZE(n)	((n == 512 || n == 1024 || n == 2048 || n == 4096)? 1 : 0)

typedef struct _block_map_t{
	int tag; //map is loaded
	int pos; //map index
	int inc; //page counter
	map_t map;
}block_map_t;

typedef struct _file_table_context{
	link_t lk;

	xhand_t block;
	spinlock_t slock;
	dword_t mask;

	tchar_t file_guid[NUID_TOKEN_SIZE + 1];

	dword_t file_root;
	sword_t page_size;
	sword_t mask_bits;
	sword_t block_size;
	sword_t file_maps;

	block_map_t* block_table;
}file_table_context;

#define PageTableFromLink(p) TypePtrFromLink(file_table_context,p)

#define BLOCKS_PERMAP(pagesize, maskbits)	(pagesize * (8 / maskbits))

static void _alloc_block_map(block_map_t* pmt, int page_size, int mask_bits)
{
	pmt->tag = 0; //map have not persisted
	pmt->inc = BLOCKS_PERMAP(page_size, mask_bits);
	pmt->map = map_alloc(pmt->inc, mask_bits);
}

static bool_t _init_block_map(block_map_t* pmt, int block_size, bool_t write)
{
	int n;

	//blocks used for map
	n = map_size(pmt->map) / block_size;
	pmt->tag = n;
	pmt->pos = n;
	while (n--)
	{
		if (write)
		{
			map_set_bit(pmt->map, n, FILETABLE_ALLOCED);
		}
		else
		{
			if (map_get_bit(pmt->map, n) != FILETABLE_ALLOCED)
				return 0;
		}		
	}

	return 1;
}

static bool_t _flush_file_head(file_table_context* ppt, bool_t b_save)
{
	byte_t head[PAGE_SIZE] = { 0 };

	if (b_save)
	{
#if defined(_UNICODE) || defined(UNICODE)
		ucs_to_utf8(ppt->file_guid, NUID_TOKEN_SIZE, head, NUID_TOKEN_SIZE);
#else
		mbs_to_utf8(ppt->file_guid, NUID_TOKEN_SIZE, head, NUID_TOKEN_SIZE);
#endif
		PUT_DWORD_LOC(head, NUID_TOKEN_SIZE, ppt->file_root);
		PUT_SWORD_LOC(head, (NUID_TOKEN_SIZE + 4), ppt->page_size);
		PUT_SWORD_LOC(head, (NUID_TOKEN_SIZE + 6), ppt->mask_bits);
		PUT_SWORD_LOC(head, (NUID_TOKEN_SIZE + 8), ppt->block_size);
		PUT_SWORD_LOC(head, (NUID_TOKEN_SIZE + 10), ppt->file_maps);

		return xuncf_write_file_range(ppt->block, 0, 0, head, ppt->page_size);
	}
	else
	{
		if (!xuncf_read_file_range(ppt->block, 0, 0, head, PAGE_SIZE))
			return 0;

#if defined(_UNICODE) || defined(UNICODE)
		utf8_to_ucs(head, NUID_TOKEN_SIZE, ppt->file_guid, NUID_TOKEN_SIZE);
#else
		utf8_to_mbs(head, NUID_TOKEN_SIZE, ppt->file_guid, NUID_TOKEN_SIZE);
#endif
		ppt->file_root = GET_DWORD_LOC(head, NUID_TOKEN_SIZE);
		ppt->page_size = GET_SWORD_LOC(head, (NUID_TOKEN_SIZE + 4));
		ppt->mask_bits = GET_SWORD_LOC(head, (NUID_TOKEN_SIZE + 6));
		ppt->block_size = GET_SWORD_LOC(head, (NUID_TOKEN_SIZE + 8));
		ppt->file_maps = GET_SWORD_LOC(head, (NUID_TOKEN_SIZE + 10));

		return (IS_FILETABLE_PAGESIZE(ppt->page_size) &&  IS_FILETABLE_MAPBITS(ppt->mask_bits) && IS_FILETABLE_BLOCKSIZE(ppt->block_size)) ? 1 : 0;
	}
}

static res_file_t _lock_file_map(file_table_context* ppt, int map_ind)
{
	lword_t ll;
	dword_t hoff, loff;
	void* buff;
	sword_t bytes;
	int j;
	dword_t incr;
	res_file_t mh = 0;

	XDK_ASSERT(map_ind >= 0 && map_ind < ppt->file_maps);

	//skip the file table head (one-page size)
	incr = ppt->page_size / ppt->block_size;
	for (j = 0; j < map_ind; j++)
	{
		incr += ppt->block_table[j].inc;
	}

	ll = (lword_t)incr * (lword_t)(ppt->block_size);
	hoff = GETHDWORD(ll);
	loff = GETLDWORD(ll);

	if (ppt->slock)
	{
		while (!enter_spinlock(ppt->slock, map_ind, 0))
		{
			thread_yield();
		}
	}

	bytes = map_size(ppt->block_table[map_ind].map);

	if (ppt->mask & FILETABLE_DIRECT)
	{
		buff = xuncf_lock_file_range(ppt->block, hoff, loff, bytes, 1, &mh);
	}
	else
	{
		buff = xmem_alloc(bytes);
		xuncf_read_file_range(ppt->block, hoff, loff, buff, bytes);
		mh = (res_file_t)buff;
	}

	if (!buff)
	{
		if (ppt->slock)
		{
			leave_spinlock(ppt->slock, map_ind, 0);
		}

		return INVALID_FILE;
	}

	map_attach(ppt->block_table[map_ind].map, buff);

	return mh;
}

static void _unlock_file_map(file_table_context* ppt, int map_ind, res_file_t mh)
{
	lword_t ll;
	dword_t hoff, loff;
	void* buff;
	sword_t bytes;
	int j;
	dword_t incr;

	XDK_ASSERT(map_ind >= 0 && map_ind < ppt->file_maps);

	//skip the file table head (one-page size)
	incr = ppt->page_size / ppt->block_size;
	for (j = 0; j < map_ind; j++)
	{
		incr += ppt->block_table[j].inc;
	}

	ll = (lword_t)incr * (lword_t)(ppt->block_size);
	hoff = GETHDWORD(ll);
	loff = GETLDWORD(ll);

	bytes = map_size(ppt->block_table[map_ind].map);
	buff = map_detach(ppt->block_table[map_ind].map);

	XDK_ASSERT(buff != NULL);

	if (ppt->mask & FILETABLE_DIRECT)
	{
		xuncf_unlock_file_range(ppt->block, hoff, loff, bytes, mh, buff);
	}
	else
	{
		xuncf_write_file_range(ppt->block, hoff, loff, buff, bytes);
		xmem_free(buff);
	}

	if (ppt->slock)
	{
		leave_spinlock(ppt->slock, map_ind, 0);
	}
}

static bool_t _lock_file_table_block(file_table_context* ppt, int map_ind, int map_pos, dword_t size, bool_t write, res_file_t* pmh, void** pbuf)
{
	lword_t ll;
	dword_t hoff, loff;
	dword_t incr;
	int j;

	void* buff;
	bool_t rt;

	//skip the file table head (one-page size)
	incr = ppt->page_size / ppt->block_size;
	for (j = 0; j < map_ind; j++)
	{
		incr += ppt->block_table[j].inc;
	}

	ll = (lword_t)(incr + map_pos) * (lword_t)(ppt->block_size);
	hoff = GETHDWORD(ll);
	loff = GETLDWORD(ll);

	if (ppt->slock)
	{
		while (!enter_spinlock(ppt->slock, map_ind, map_pos))
		{
			thread_yield();
		}
	}

	if (ppt->mask & FILETABLE_DIRECT)
	{
		*pbuf = xuncf_lock_file_range(ppt->block, hoff, loff, size, write, pmh);
	}
	else
	{
		buff = xmem_alloc(size);

		if (write)
		{
			rt = xuncf_write_file_range(ppt->block, hoff, loff, buff, size);
		}
		else
		{
			rt = xuncf_read_file_range(ppt->block, hoff, loff, buff, size);
		}
		if (!rt)
		{
			xmem_free(buff);
			buff = NULL;
		}

		*pbuf = buff;
	}

	return (*pbuf == NULL) ? 0 : 1;
}

static bool_t _unlock_file_table_block(file_table_context* ppt, int map_ind, int map_pos, dword_t size, bool_t write, res_file_t mh, void* buf)
{
	lword_t ll;
	dword_t hoff, loff;
	dword_t incr;
	int j;

	bool_t rt;

	//skip the file table head (one-page size)
	incr = ppt->page_size / ppt->block_size;
	for (j = 0; j < map_ind; j++)
	{
		incr += ppt->block_table[j].inc;
	}

	ll = (lword_t)(incr + map_pos) * (lword_t)(ppt->block_size);
	hoff = GETHDWORD(ll);
	loff = GETLDWORD(ll);

	if (ppt->mask & FILETABLE_DIRECT)
	{
		xuncf_unlock_file_range(ppt->block, hoff, loff, size, mh, buf);
		rt = 1;
	}
	else
	{
		if (write)
			rt = xuncf_write_file_range(ppt->block, hoff, loff, buf, size);
		else
			rt = 1;

		xmem_free(buf);
	}

	if (ppt->slock)
	{
		leave_spinlock(ppt->slock, map_ind, map_pos);
	}

	return rt;
}

/************************************************************************************/

link_t_ptr create_file_table(const tchar_t* fname, int block, dword_t mask)
{
	file_table_context* ppt = NULL;

	dword_t dwh = 0,dwl = 0;
	int i;

	lword_t tms;
	nuid_t nuid = { 0 };

	res_file_t mh;

	TRY_CATCH;

	ppt = (file_table_context*)xmem_alloc(sizeof(file_table_context));
	ppt->lk.tag = lkFileTable;

	ppt->block = xuncf_open_file(NULL, fname, FILE_OPEN_APPEND | FILE_OPEN_RANDOM);
	if (!ppt->block)
	{
		raise_user_error(NULL, NULL);
	}

	xuncf_file_size(ppt->block, &dwh, &dwl);

	if (dwl && dwl < PAGE_SIZE)
	{
		raise_user_error(_T("open_file_table"), _T("invalid file size"));
	}

	if (dwl || dwh)
	{
		//load file table header
		if (!_flush_file_head(ppt, 0))
		{
			raise_user_error(_T("open_file_table"), _T("invalid file header"));
		}

		ppt->mask = mask;

		if (ppt->mask & FILETABLE_SHARE)
		{
			ppt->slock = alloc_spinlock(ppt->file_guid, BLOCKS_PERMAP(ppt->page_size, ppt->mask_bits));
			if (!ppt->slock)
			{
				raise_user_error(_T("open_file_table"), _T("create lock table failed"));
			}
		}

		ppt->block_table = (block_map_t*)xmem_alloc((ppt->file_maps) * sizeof(block_map_t));
		
		for (i = 0; i < ppt->file_maps; i++)
		{
			_alloc_block_map(&(ppt->block_table[i]), ppt->page_size, ppt->mask_bits);

			if ((mh = _lock_file_map(ppt, i)) == INVALID_FILE)
			{
				raise_user_error(_T("open_file_table"), _T("load file map failed"));
			}

			if (!_init_block_map(&(ppt->block_table[i]), ppt->block_size, 0))
			{
				raise_user_error(_T("open_file_table"), _T("read file map failed"));
			}

			_unlock_file_map(ppt, i, mh);
		}
	}
	else
	{
		if (!IS_FILETABLE_BLOCKSIZE(block))
		{
			raise_user_error(_T("open_file_table"), _T("invalid block size"));
		}

		//set default header
		ppt->file_root = 0;
		ppt->page_size = PAGE_SIZE;
		ppt->mask_bits = FILETABLE_MAPBITS;
		ppt->block_size = block;
		ppt->file_maps = 1;

		tms = get_timestamp();
		nuid_from_timestamp(&nuid, tms);
		nuid_format_string(&nuid, ppt->file_guid);

		ppt->mask = mask;

		//save file table header
		if (!_flush_file_head(ppt, 1))
		{
			raise_user_error(_T("open_file_table"), _T("save file header failed"));
		}

		if (ppt->mask & FILETABLE_SHARE)
		{
			ppt->slock = alloc_spinlock(ppt->file_guid, BLOCKS_PERMAP(ppt->page_size, ppt->mask_bits));
			if (!ppt->slock)
			{
				raise_user_error(_T("open_file_table"), _T("create lock table failed"));
			}
		}

		ppt->block_table = (block_map_t*)xmem_alloc((ppt->file_maps) * sizeof(block_map_t));
		_alloc_block_map(&(ppt->block_table[0]), ppt->page_size, ppt->mask_bits);

		if ((mh = _lock_file_map(ppt, 0)) == INVALID_FILE)
		{
			raise_user_error(_T("open_file_table"), _T("load file map failed"));
		}

		if(!_init_block_map(&(ppt->block_table[0]), ppt->block_size, 1))
		{
			raise_user_error(_T("open_file_table"), _T("write file map failed"));
		}

		_unlock_file_map(ppt, 0, mh);
	}

	END_CATCH;

	return &ppt->lk;
ONERROR:

	if (ppt->block)
		xuncf_close_file(ppt->block);

	if (ppt->slock)
		free_spinlock(ppt->slock);

	if (ppt->block_table)
	{
		for (i = 0; i < ppt->file_maps; i++)
		{
			if (ppt->block_table[i].map)
			{
				map_free(ppt->block_table[i].map);
			}
		}
		xmem_free(ppt->block_table);
	}

	if (ppt)
		xmem_free(ppt);

	return NULL;
}

void destroy_file_table(link_t_ptr pt)
{
	file_table_context* ppt = PageTableFromLink(pt);
	int i;

	XDK_ASSERT(pt && pt->tag == lkFileTable);

	xuncf_close_file(ppt->block);

	if (ppt->slock)
	{
		free_spinlock(ppt->slock);
	}

	for (i = 0; i < ppt->file_maps; i++)
	{
		map_free(ppt->block_table[i].map);
	}

	xmem_free(ppt->block_table);

	xmem_free(ppt);
}

int get_file_table_block(link_t_ptr pt)
{
	file_table_context* ppt = PageTableFromLink(pt);

	return ppt->block_size;
}

dword_t get_file_table_mask(link_t_ptr pt)
{
	file_table_context* ppt = PageTableFromLink(pt);

	return ppt->mask;
}

bool_t set_file_table_root(link_t_ptr pt, dword_t pos)
{
	file_table_context* ppt = PageTableFromLink(pt);

	if (pos)
	{
		if (!get_file_table_block_alloced(pt, pos))
			return 0;
	}

	ppt->file_root = pos;

	return _flush_file_head(ppt, 1);
}

dword_t get_file_table_root(link_t_ptr pt)
{
	file_table_context* ppt = PageTableFromLink(pt);

	if (ppt->file_root)
	{
		if (!get_file_table_block_alloced(pt, ppt->file_root))
			return 0;
	}

	return ppt->file_root;
}

dword_t alloc_file_table_block(link_t_ptr pt, dword_t size)
{
	file_table_context* ppt = PageTableFromLink(pt);
	int k, n, pos = 0;
	sword_t i;
	bool_t tag = 0;
	res_file_t mh;

	XDK_ASSERT(pt && pt->tag == lkFileTable);

	n = size / ppt->block_size;
	if (size % ppt->block_size)
		n++;

	XDK_ASSERT(n > 0);

	for (i = 0; i < ppt->file_maps; i++)
	{
		if ((mh = _lock_file_map(ppt, i)) == INVALID_FILE)
			continue;
		
		XDK_ASSERT(n <= (ppt->block_table[i].inc - ppt->block_table[i].tag));

		//skip map-used blocks
		pos = (n > 1) ? ppt->block_table[i].pos : ppt->block_table[i].tag;

		while (n)
		{
			pos = map_find_bit(ppt->block_table[i].map, pos, FILETABLE_RELEASED);
			if (pos == C_ERR)
				break;

			if (n == 1)
			{
				tag = 1;
				break;
			}

			k = map_test_bit(ppt->block_table[i].map, pos, FILETABLE_RELEASED, n);
			if (k == C_ERR)
				break;

			if (k == n)
			{
				tag = 1;
				break;
			}

			pos += (k + 1);
		}

		_unlock_file_map(ppt, i, mh);

		if (tag) break;
	}

	if (i == ppt->file_maps)
	{
		ppt->file_maps++;
		ppt->block_table = (block_map_t*)xmem_realloc(ppt->block_table, (ppt->file_maps) * sizeof(block_map_t));
		_alloc_block_map(&(ppt->block_table[i]), ppt->page_size, ppt->mask_bits);

		mh = _lock_file_map(ppt, i);
		XDK_ASSERT(mh != INVALID_FILE);

		_init_block_map(&(ppt->block_table[i]), ppt->block_size, 1);

		_unlock_file_map(ppt, i, mh);

		pos = ppt->block_table[i].pos;

		if (!_flush_file_head(ppt, 1))
			return 0;
	}

	XDK_ASSERT(pos > 0);

	//rotate the map pos
	ppt->block_table[i].pos = (pos + n) % (ppt->block_table[i].inc);
	if (ppt->block_table[i].pos == 0)
	{
		ppt->block_table[i].pos = ppt->block_table[i].tag;
	}

	mh = _lock_file_map(ppt, i);
	XDK_ASSERT(mh != INVALID_FILE);

	while (n--)
	{
		map_set_bit(ppt->block_table[i].map, pos + n, FILETABLE_ALLOCED);
	}

	_unlock_file_map(ppt, i, mh);

	return (dword_t)((pos & 0xFFFF) | (i << 16));
}

void free_file_table_block(link_t_ptr pt, dword_t pos, dword_t size)
{
	file_table_context* ppt = PageTableFromLink(pt);
	int n;
	sword_t i;
	res_file_t mh;

	XDK_ASSERT(pt && pt->tag == lkFileTable);

	i = (sword_t)((pos & 0xFFFF0000) >> 16);
	pos &= 0x0000FFFF;

	XDK_ASSERT(pos >= ppt->block_table[i].tag && i < ppt->file_maps);

	n = size / ppt->block_size;
	if (size % ppt->block_size)
		n++;

	mh = _lock_file_map(ppt, i);
	XDK_ASSERT(mh != INVALID_FILE);

	while (n--)
	{
		XDK_ASSERT(map_get_bit(ppt->block_table[i].map, pos + n) != FILETABLE_RELEASED);
		
		map_set_bit(ppt->block_table[i].map, pos + n, FILETABLE_RELEASED);
	}

	//cache the map pos
	ppt->block_table[i].pos = pos;

	_unlock_file_map(ppt, i, mh);
}

bool_t get_file_table_block_alloced(link_t_ptr pt, dword_t pos)
{
	file_table_context* ppt = PageTableFromLink(pt);
	sword_t i;
	bool_t rt;
	res_file_t mh;

	XDK_ASSERT(pt && pt->tag == lkFileTable);

	i = (sword_t)((pos & 0xFFFF0000) >> 16);
	pos &= 0x0000FFFF;

	XDK_ASSERT(pos >= ppt->block_table[i].tag && i < ppt->file_maps);

	mh = _lock_file_map(ppt, i);
	XDK_ASSERT(mh != INVALID_FILE);

	rt = (map_get_bit(ppt->block_table[i].map, pos) == FILETABLE_RELEASED)? 0 : 1;

	_unlock_file_map(ppt, i, mh);

	return rt;
}

bool_t lock_file_table_block(link_t_ptr pt, dword_t pos, dword_t size, bool_t write, res_file_t* pmh, void** pbuf)
{
	file_table_context* ppt = PageTableFromLink(pt);
	int i, j;
	res_file_t mh;

	XDK_ASSERT(pt && pt->tag == lkFileTable);

	i = (int)((pos & 0xFFFF0000) >> 16);
	j = (int)(pos & 0x0000FFFF);

	XDK_ASSERT(j >= ppt->block_table[i].tag && i < ppt->file_maps);
	XDK_ASSERT((ppt->block_table[i].tag) != 0);

#ifdef XDK_SUPPORT_TEST
	mh = _lock_file_map(ppt, i);
	XDK_ASSERT(mh != INVALID_FILE);
	
	XDK_ASSERT(map_get_bit(ppt->block_table[i].map, j) != FILETABLE_RELEASED);

	_unlock_file_map(ppt, i, mh);
#endif

	return _lock_file_table_block(ppt, i, j, size, write, pmh, pbuf);
}

bool_t unlock_file_table_block(link_t_ptr pt, dword_t pos, dword_t size, bool_t write, res_file_t hh, void* buf)
{
	file_table_context* ppt = PageTableFromLink(pt);
	int i, j;
	res_file_t mh;

	XDK_ASSERT(pt && pt->tag == lkFileTable);

	i = (int)((pos & 0xFFFF0000) >> 16);
	j = (int)(pos & 0x0000FFFF);

	XDK_ASSERT(j >= ppt->block_table[i].tag && i < ppt->file_maps);
	XDK_ASSERT((ppt->block_table[i].tag) != 0);

#ifdef XDK_SUPPORT_TEST
	mh = _lock_file_map(ppt, i);
	XDK_ASSERT(mh != INVALID_FILE);

	XDK_ASSERT(map_get_bit(ppt->block_table[i].map, j) != FILETABLE_RELEASED);

	_unlock_file_map(ppt, i, mh);
#endif

	return _unlock_file_table_block(ppt, i, j, size, write, hh, buf);
}

#if defined(XDK_SUPPORT_TEST)
#include <time.h>

void test_file_table_alloc(const tchar_t* fname, dword_t mask)
{
	link_t_ptr pt = create_file_table(fname, BLOCK_SIZE_4096, mask);

	file_table_context* ppt = PageTableFromLink(pt);

	Srand48((int)time(NULL));

	#define ARS 100
	int i, k, b;

	for (k = 0; k < 100; k++)
	{
		dword_t ind[ARS] = { 0 };
		int ext[ARS] = { 0 };
		for (i = 0; i < ARS; i++)
		{
			while (ext[i] == 0) ext[i] = Lrand48() % 1024;

			ind[i] = alloc_file_table_block(pt, ext[i] * PAGE_SIZE);

			b = (int)get_file_table_block_alloced(pt, ind[i]);

			_tprintf(_T("%d-%d-%d\t"), (ind[i] & 0x0000FFFF), ext[i], b);
		}

		_tprintf(_T("\n"));

		for (i = 0; i < ARS; i++)
		{
			free_file_table_block(pt, ind[i], ext[i] * PAGE_SIZE);

			b = (int)get_file_table_block_alloced(pt, ind[i]);

			_tprintf(_T("%d-%d-%d\t"), (ind[i] & 0x0000FFFF), ext[i], b);
		}

		_tprintf(_T("\n"));
	}

	destroy_file_table(pt);
}

void test_file_table_write(const tchar_t* fname, dword_t mask)
{
	link_t_ptr pt = create_file_table(fname, BLOCK_SIZE_512, mask);

	file_table_context* ppt = PageTableFromLink(pt);

	Srand48((int)time(NULL));

#define ARS 100
	int i, k, b;

	res_file_t mh;

	for (k = 0; k < 100; k++)
	{
		dword_t ind[ARS] = { 0 };
		int ext[ARS] = { 0 };
		vword_t adr[ARS] = { 0 };
		for (i = 0; i < ARS; i++)
		{
			while (ext[i] == 0) ext[i] = Lrand48() % 1024;

			ind[i] = alloc_file_table_block(pt, ext[i] * PAGE_SIZE);

			lock_file_table_block(pt, ind[i], ext[i] * PAGE_SIZE, 1, &mh, (void**)&(adr[i]));

			*((dword_t*)adr[i]) = ind[i];
			*((byte_t*)adr[i] + ext[i] * PAGE_SIZE - 1) = 'F';

			unlock_file_table_block(pt, ind[i], ext[i] * PAGE_SIZE, 1, mh, (void*)adr[i]);

			_tprintf(_T("%lu-%lu\t"), ind[i], ext[i]);
		}

		_tprintf(_T("\n"));

		for (i = 0; i < ARS; i++)
		{
			lock_file_table_block(pt, ind[i], ext[i] * PAGE_SIZE, 0, &mh, (void**)&(adr[i]));

			if(*((dword_t*)adr[i]) != ind[i])
				_tprintf(_T("pos %lu mistach\n"), ind[i]);

			if(*((byte_t*)adr[i] + ext[i] * PAGE_SIZE - 1) != 'F')
				_tprintf(_T("size %lu mistach\n"), ext[i]);

			unlock_file_table_block(pt, ind[i], ext[i] * PAGE_SIZE, 0, mh, (void*)adr[i]);

			free_file_table_block(pt, ind[i], ext[i] * PAGE_SIZE);

			b = (int)get_file_table_block_alloced(pt, ind[i]);
		}

		_tprintf(_T("\n"));
	}

	destroy_file_table(pt);

	_tprintf(_T("end\n"));
}

#endif