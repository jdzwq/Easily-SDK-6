/***********************************************************************
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

/**********************************************************************
file table: { {head area: one page} {table area: one more pages} }
head area: { {file guid: 36 bytes}
			{page size: 2 bytes}
			{map bits: 2 bytes} 
			{block size: 2 bytes} 
			{file maps: 2 bytes}
			{file root: 4 bytes} }
table area: { {map area: one page} {data area: (pagesize / map bits) * block size} 
			{ {map area} {data area} }
			{ ... } }
***********************************************************************/
#include "filetable.h"

#include "../xdkstd.h"
#include "../xdkobj.h"
#include "../xdkimp.h"

#define FILETABLE_MAPBITS		1

#define FILETABLE_ALLOCED_BIT	1
#define FILETABLE_UNALLOCED_BIT	0

#define FILETABLE_UNALLOCED_BYTE	0x00

#define IS_FILETABLE_MAPBITS(n)		((n == 1 || n == 2 || n == 4 || n == 8)? 1 : 0)
#define IS_FILETABLE_PAGESIZE(n)	((n == 4096 || n == 8192 || n == 16384)? 1 : 0)
#define IS_FILETABLE_BLOCKSIZE(n)	((n == 64 || n == 128 || n == 256 || n == 512)? 1 : 0)

typedef struct _file_table_context{
	link_t lk;

	xhand_t block;
	dword_t mask;

	tchar_t file_guid[NUID_TOKEN_SIZE + 1];

	dword_t page_size;
	dword_t mask_bits;
	dword_t block_size;
	dword_t file_maps;
	lword_t file_root;
}file_table_context;

#define PageTableFromLink(p) TypePtrFromLink(file_table_context,p)

#define BLOCKS_PERMAP(pagesize, maskbits)	(pagesize * (8 / maskbits))


static bool_t _flush_file_head(file_table_context* ppt, bool_t b_save)
{
	byte_t head[PAGE_SIZE];

	if (b_save)
	{
#if defined(_UNICODE) || defined(UNICODE)
		ucs_to_utf8(ppt->file_guid, NUID_TOKEN_SIZE, head, NUID_TOKEN_SIZE);
#else
		mbs_to_utf8(ppt->file_guid, NUID_TOKEN_SIZE, head, NUID_TOKEN_SIZE);
#endif
		PUT_DWORD_LOC(head, (NUID_TOKEN_SIZE), ppt->page_size);
		PUT_DWORD_LOC(head, (NUID_TOKEN_SIZE + 4), ppt->mask_bits);
		PUT_DWORD_LOC(head, (NUID_TOKEN_SIZE + 8), ppt->block_size);
		PUT_DWORD_LOC(head, (NUID_TOKEN_SIZE + 12), ppt->file_maps);
		PUT_LWORD_LOC(head, (NUID_TOKEN_SIZE + 16), ppt->file_root);

		return xuncf_write_file_range(ppt->block, 0, head, ppt->page_size);
	}
	else
	{
		if (!xuncf_read_file_range(ppt->block, 0, head, PAGE_SIZE))
			return 0;

#if defined(_UNICODE) || defined(UNICODE)
		utf8_to_ucs(head, NUID_TOKEN_SIZE, ppt->file_guid, NUID_TOKEN_SIZE);
#else
		utf8_to_mbs(head, NUID_TOKEN_SIZE, ppt->file_guid, NUID_TOKEN_SIZE);
#endif
		ppt->page_size = GET_DWORD_LOC(head, (NUID_TOKEN_SIZE));
		ppt->mask_bits = GET_DWORD_LOC(head, (NUID_TOKEN_SIZE + 4));
		ppt->block_size = GET_DWORD_LOC(head, (NUID_TOKEN_SIZE + 8));
		ppt->file_maps = GET_DWORD_LOC(head, (NUID_TOKEN_SIZE + 12));
		ppt->file_root = GET_LWORD_LOC(head, (NUID_TOKEN_SIZE + 16));

		return (IS_FILETABLE_PAGESIZE(ppt->page_size) 
			&&  IS_FILETABLE_MAPBITS(ppt->mask_bits) 
			&& IS_FILETABLE_BLOCKSIZE(ppt->block_size)) ? bool_true : bool_false;
	}
}

static res_file_t _lock_file_table_map(file_table_context* ppt, dword_t map_ind, map_t map)
{
	dword_t map_bytes, map_blocks;
	vword_t ll;
	res_file_t mh = 0;
	void* buff;

	//if map_ind equal file table maps count, the file table to be expanding
	XDK_ASSERT(map_ind >= 0 && map_ind <= ppt->file_maps);

	map_blocks = BLOCKS_PERMAP(ppt->page_size, ppt->mask_bits);
	map_bytes = map_need_size(map_blocks, ppt->mask_bits);

	//the file table map position is: head bytes + map index * (map bytes + blocks bytes)
	ll = ppt->page_size + map_ind * (map_bytes + map_blocks * ppt->block_size);

	buff = xuncf_lock_file_range(ppt->block, ll, map_bytes, bool_true, &mh);
	if(!buff)
	{
		return INVALID_FILE;
	}

	//init the new map alloced
	if (map_ind == ppt->file_maps)
	{
		xmem_set((void *)buff, FILETABLE_UNALLOCED_BYTE, map_bytes);
	}

	map_attach(map, buff);

	return mh;
}

static void _unlock_file_table_map(file_table_context* ppt, dword_t map_ind, res_file_t mh, map_t map)
{
	dword_t map_bytes, map_blocks;
	vword_t ll;
	void* buff;

	map_blocks = BLOCKS_PERMAP(ppt->page_size, ppt->mask_bits);
	map_bytes = map_need_size(map_blocks, ppt->mask_bits);

	//the file table map position is: head bytes + map index * (map bytes + blocks bytes)
	ll = ppt->page_size + map_ind * (map_bytes + map_blocks * ppt->block_size);

	buff = map_detach(map);
	XDK_ASSERT(buff != NULL);

	xuncf_unlock_file_range(ppt->block, ll, map_bytes, mh, buff);
}

static void* _lock_file_table_block(file_table_context* ppt, dword_t map_ind, dword_t map_pos, dword_t size, bool_t write, res_file_t* pmh)
{
	dword_t map_bytes, map_blocks;
	vword_t ll;
	bool_t b_write;
	void* buff;

	map_blocks = BLOCKS_PERMAP(ppt->page_size, ppt->mask_bits);
	map_bytes = map_need_size(map_blocks, ppt->mask_bits);

	//the file table block position is: head bytes + map index * (map bytes + blocks bytes) + map bytes + block index * blocks bytes
	ll = ppt->page_size + map_ind * (map_bytes + map_blocks * ppt->block_size) + (map_bytes + map_pos * ppt->block_size);

	return xuncf_lock_file_range(ppt->block, ll, size, write, pmh);
}

static void _unlock_file_table_block(file_table_context* ppt, dword_t map_ind, dword_t map_pos, dword_t size, bool_t write, res_file_t mh, void* buf)
{
	dword_t map_bytes, map_blocks;
	vword_t ll;
	bool_t b_write;
	void* buff;

	map_blocks = BLOCKS_PERMAP(ppt->page_size, ppt->mask_bits);
	map_bytes = map_need_size(map_blocks, ppt->mask_bits);

	//the file table block position is: head bytes + map index * (map bytes + blocks bytes) + map bytes + block index * blocks bytes
	ll = ppt->page_size + map_ind * (map_bytes + map_blocks * ppt->block_size) + (map_bytes + map_pos * ppt->block_size);

	xuncf_unlock_file_range(ppt->block, ll, size, mh, buf);
}

/************************************************************************************/

link_t_ptr create_file_table(const tchar_t* fname, int block, dword_t mask)
{
	file_table_context* ppt = NULL;

	vword_t ll;
	dword_t i, map_blocks;

	lword_t tms;
	nuid_t nuid = { 0 };

	res_file_t mh = 0;
	map_t map = NULL;

	TRY_CATCH;

	ppt = (file_table_context*)xmem_alloc(sizeof(file_table_context));
	ppt->lk.tag = lkFileTable;

	ppt->block = xuncf_open_file(NULL, fname, FILE_OPEN_APPEND | FILE_OPEN_RANDOM);
	if (!ppt->block)
	{
		raise_user_error(NULL, NULL);
	}

	xuncf_file_size(ppt->block, &ll);

	if (ll && ll < (vword_t)PAGE_SIZE)
	{
		raise_user_error(_T("open_file_table"), _T("invalid file size"));
	}

	ppt->mask = mask;

	if (ll)
	{	//open table file
		//load file table header
		if (!_flush_file_head(ppt, 0))
		{
			raise_user_error(_T("open_file_table"), _T("invalid file header"));
		}

		map_blocks = BLOCKS_PERMAP(ppt->page_size, ppt->mask_bits);
		map = map_alloc(map_blocks, ppt->mask_bits);
		//test file table maps
		for (i = 0; i < ppt->file_maps; i++)
		{
			mh = _lock_file_table_map(ppt, i, map);
			if(mh == INVALID_FILE)
			{
				raise_user_error(_T("open_file_table"), _T("load file map failed"));
			}

			_unlock_file_table_map(ppt, i, mh, map);
		}

		map_free(map);
		map = NULL;
	}
	else
	{
		//create table file
		if (!IS_FILETABLE_BLOCKSIZE(block))
		{
			raise_user_error(_T("open_file_table"), _T("invalid block size"));
		}

		//set default header
		ppt->page_size = PAGE_SIZE;
		ppt->mask_bits = FILETABLE_MAPBITS;
		ppt->block_size = block;
		ppt->file_maps = 0;
		ppt->file_root = INVALID_INDEX;

		tms = get_timestamp();
		nuid_from_timestamp(&nuid, tms);
		nuid_format_hash(&nuid, ppt->file_guid);

		//save file table header
		if (!_flush_file_head(ppt, 1))
		{
			raise_user_error(_T("open_file_table"), _T("save file header failed"));
		}
	}

	END_CATCH;

	return &ppt->lk;
ONERROR:
	if(map)
		map_free(map);

	if (ppt->block)
		xuncf_close_file(ppt->block);

	if (ppt)
		xmem_free(ppt);

	return NULL;
}

void destroy_file_table(link_t_ptr ptr)
{
	file_table_context* ppt = PageTableFromLink(ptr);
	int i;

	XDK_ASSERT(ptr && ptr->tag == lkFileTable);

	xuncf_close_file(ppt->block);

	xmem_free(ppt);
}

int get_file_table_page_size(link_t_ptr ptr)
{
	file_table_context* ppt = PageTableFromLink(ptr);

	return ppt->page_size;
}

int get_file_table_block_size(link_t_ptr ptr)
{
	file_table_context* ppt = PageTableFromLink(ptr);

	return ppt->block_size;
}

dword_t get_file_table_mask(link_t_ptr ptr)
{
	file_table_context* ppt = PageTableFromLink(ptr);

	return ppt->mask;
}

bool_t set_file_table_root(link_t_ptr ptr, lword_t bid)
{
	file_table_context* ppt = PageTableFromLink(ptr);

	if (bid != INVALID_INDEX)
	{
		if (!get_file_table_block_alloced(ptr, bid))
			return bool_false;
	}

	ppt->file_root = bid;

	return _flush_file_head(ppt, 1);
}

lword_t get_file_table_root(link_t_ptr ptr)
{
	file_table_context* ppt = PageTableFromLink(ptr);

	if (ppt->file_root != INVALID_INDEX)
	{
		if (!get_file_table_block_alloced(ptr, ppt->file_root))
			return INVALID_INDEX;
	}

	return ppt->file_root;
}

bool_t get_file_table_block_alloced(link_t_ptr ptr, lword_t bid)
{
	file_table_context* ppt = PageTableFromLink(ptr);
	dword_t ind, pos;
	dword_t map_blocks;
	res_file_t mh;
	map_t map;
	bool_t rt;

	XDK_ASSERT(ptr && ptr->tag == lkFileTable);
	XDK_ASSERT(bid != INVALID_INDEX);

	ind = GETHDWORD(bid);
	pos = GETLDWORD(bid);

	map_blocks = BLOCKS_PERMAP(ppt->page_size, ppt->mask_bits);
	XDK_ASSERT(ind < ppt->file_maps && pos < map_blocks);

	map = map_alloc(map_blocks, ppt->mask_bits);

	mh = _lock_file_table_map(ppt, ind, map);
	XDK_ASSERT(mh != INVALID_FILE);

	rt = (map_get_bit(map, pos) == FILETABLE_ALLOCED_BIT)? bool_true : bool_false;

	_unlock_file_table_map(ppt, ind, mh, map);

	map_free(map);

	return rt;
}

lword_t alloc_file_table_block(link_t_ptr ptr, dword_t size)
{
	file_table_context* ppt = PageTableFromLink(ptr);
	dword_t k, n, ind, pos = 0;
	bool_t tag = 0;
	res_file_t mh;
	map_t map = NULL;
	dword_t map_blocks;

	XDK_ASSERT(ptr && ptr->tag == lkFileTable);

	TRY_CATCH;

	n = size / ppt->block_size;
	if (size % ppt->block_size)
		n++;

	map_blocks = BLOCKS_PERMAP(ppt->page_size, ppt->mask_bits);
	XDK_ASSERT(n <= map_blocks);

	map = map_alloc(map_blocks, ppt->mask_bits);

	for (ind = 0; ind < ppt->file_maps; ind++)
	{
		if ((mh = _lock_file_table_map(ppt, ind, map)) == INVALID_FILE)
			continue;
		
		pos = 0;
		while (n)
		{
			pos = map_find_bit(map, pos, FILETABLE_UNALLOCED_BIT);
			if (pos == INVALID_BLOCK)
				break;

			if (n == 1)
			{
				tag = 1;
				break;
			}

			k = map_test_bit(map, pos, FILETABLE_UNALLOCED_BIT, n);
			if (k == INVALID_BLOCK)
				break;

			if (k == n)
			{
				tag = 1;
				break;
			}

			pos += (k + 1);
		}

		if(tag)
		{
			while (n--)
			{
				map_set_bit(map, pos + n, FILETABLE_ALLOCED_BIT);
			}
		}

		_unlock_file_table_map(ppt, ind, mh, map);

		if (tag) break;
	}

	if (ind == ppt->file_maps)
	{
		//expand file table map
		mh = _lock_file_table_map(ppt, ind, map);
		XDK_ASSERT(mh != INVALID_FILE);

		ppt->file_maps++;
		
		pos = 0;
		while (n--)
		{
			map_set_bit(map, pos + n, FILETABLE_ALLOCED_BIT);
		}

		_unlock_file_table_map(ppt, ind, mh, map);

		if (!_flush_file_head(ppt, 1))
		{
			raise_user_error(_T("alloc_file_table_block"), _T("save file header failed"));
		}
	}

	map_free(map);
	map = NULL;

	END_CATCH;

	return MAKELWORD(pos, ind);
ONERROR:

	if(map) map_free(map);

	return INVALID_INDEX;
}

void free_file_table_block(link_t_ptr ptr, lword_t bid, dword_t size)
{
	file_table_context* ppt = PageTableFromLink(ptr);
	dword_t n, map_blocks;
	dword_t ind, pos;
	res_file_t mh;
	map_t map;
	byte_t bit;

	XDK_ASSERT(ptr && ptr->tag == lkFileTable);

	ind = GETHDWORD(bid);
	pos = GETLDWORD(bid);

	map_blocks = BLOCKS_PERMAP(ppt->page_size, ppt->mask_bits);
	XDK_ASSERT(pos < map_blocks && ind < ppt->file_maps);

	n = size / ppt->block_size;
	if (size % ppt->block_size)
		n++;

	map = map_alloc(map_blocks, ppt->mask_bits);
	mh = _lock_file_table_map(ppt, ind, map);
	XDK_ASSERT(mh != INVALID_FILE);

	while (n--)
	{
		bit = map_get_bit(map, pos + n);
		XDK_ASSERT(bit != FILETABLE_UNALLOCED_BIT);
		
		map_set_bit(map, pos + n, FILETABLE_UNALLOCED_BIT);
	}

	_unlock_file_table_map(ppt, ind, mh, map);

	map_free(map);
}

void* lock_file_table_block(link_t_ptr ptr, lword_t bid, dword_t size, bool_t write, res_file_t* pmh)
{
	file_table_context* ppt = PageTableFromLink(ptr);
	dword_t ind, pos;

	XDK_ASSERT(ptr && ptr->tag == lkFileTable);

	ind = GETHDWORD(bid);
	pos = GETLDWORD(bid);

	return _lock_file_table_block(ppt, ind, pos, size, write, pmh);
}

void unlock_file_table_block(link_t_ptr ptr, lword_t bid, dword_t size, bool_t write, res_file_t mh, void* buf)
{
	file_table_context* ppt = PageTableFromLink(ptr);
	dword_t ind, pos;

	XDK_ASSERT(ptr && ptr->tag == lkFileTable);

	ind = GETHDWORD(bid);
	pos = GETLDWORD(bid);

	_unlock_file_table_block(ppt, ind, pos, size, write, mh, buf);
}

void trunc_file_table(link_t_ptr ptr)
{
	file_table_context* ppt = PageTableFromLink(ptr);
	dword_t ind, pos = 0;
	bool_t tag = 0;
	res_file_t mh;
	map_t map = NULL;
	dword_t map_blocks, map_bytes;
	vword_t ll;

	XDK_ASSERT(ptr && ptr->tag == lkFileTable);

	TRY_CATCH;

	map_blocks = BLOCKS_PERMAP(ppt->page_size, ppt->mask_bits);
	map_bytes = map_need_size(map_blocks, ppt->mask_bits);

	map = map_alloc(map_blocks, ppt->mask_bits);

	for (ind = ppt->file_maps - 1; (int)ind >= 0; ind--)
	{
		if ((mh = _lock_file_table_map(ppt, ind, map)) == INVALID_FILE)
			break;
		
		pos = map_blocks;
		while (pos--)
		{
			if(FILETABLE_UNALLOCED_BIT != map_get_bit(map, pos))
				break;
		}
		pos ++;

		//trunc file table blocks
		if(pos < map_blocks - 1)
		{
			ll = ppt->page_size + ind * (map_bytes + map_blocks * ppt->block_size) + (map_bytes + pos * ppt->block_size);

			xuncf_truncate(ppt->block, ll);
		}

		_unlock_file_table_map(ppt, ind, mh, map);

		if (pos) break;

		ppt->file_maps--;

		//trunc file table map
		ll = ppt->page_size + ppt->file_maps * (map_bytes + map_blocks * ppt->block_size);

		xuncf_truncate(ppt->block, ll);

		//save file table maps changed
		if (!_flush_file_head(ppt, 1))
		{
			raise_user_error(_T("trunc_file_table"), _T("save file header failed"));
		}
	}

	map_free(map);
	map = NULL;

	END_CATCH;

	return;
ONERROR:

	if(map) map_free(map);

	return;
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void file_table_self_test()
{
	printf("test file table...\n");

	tchar_t fname[PATH_LEN];

	get_curpath(fname, PATH_LEN);
	xscat(fname, _T("/filetable"));

	#define BLOCK_SIZE BLOCK_SIZE_512

	link_t_ptr ptr = create_file_table(fname, BLOCK_SIZE, FILETABLE_PRIVATE);

	system_srand();

	#define ARS 1000
	lword_t bid[ARS] = { 0 };
	dword_t ext[ARS] = { 0 };
	dword_t ind, pos, bytes;
	int i, k, b;
	void* buff;
	res_file_t mh;
	byte_t c = 0xFF;

	for (k = 0; k < 1; k++)
	{
		_tprintf(_T("test block alloc[map-block-size-tag]...\n"));

		for (i = 0; i < ARS; i++)
		{
			while (ext[i] == 0) ext[i] = system_rand32() % 1024;
			bytes = ext[i] * BLOCK_SIZE;

			bid[i] = alloc_file_table_block(ptr, bytes);
			XDK_ASSERT(bid[i] != INVALID_INDEX);

			b = (int)get_file_table_block_alloced(ptr, bid[i]);
			ind = GETHDWORD(bid[i]);
			pos = GETLDWORD(bid[i]);

			_tprintf(_T("%d-%d-%d-%d\t"), ind, pos, ext[i], b);

			if(pos && ind == GETHDWORD(bid[i-1]))
			{
				XDK_ASSERT(pos == GETLDWORD(bid[i-1] + ext[i-1]));
			}

			buff = lock_file_table_block(ptr, bid[i], bytes, 1, &mh);
			XDK_ASSERT(buff != NULL);
			xmem_set(buff, c, bytes);

			unlock_file_table_block(ptr, bid[i], bytes, 1, mh, buff);
		}

		_tprintf(_T("\ntest block free[map-block-size-tag]...\n"));

		for (i = 0; i < ARS; i++)
		{
			bytes = ext[i] * BLOCK_SIZE;

			buff = lock_file_table_block(ptr, bid[i], bytes, 0, &mh);
			XDK_ASSERT(buff != NULL);
			XDK_ASSERT(c == *((byte_t*)buff) && c == *((byte_t*)buff + bytes - 1));

			free_file_table_block(ptr, bid[i], bytes);

			b = (int)get_file_table_block_alloced(ptr, bid[i]);
			ind = GETHDWORD(bid[i]);
			pos = GETLDWORD(bid[i]);

			_tprintf(_T("%d-%d-%d-%d\t"), ind, pos, ext[i], b);

			ext[i] = 0;
		}

		_tprintf(_T("\ntest block end\n"));
	}

	trunc_file_table(ptr);

	destroy_file_table(ptr);
}
#endif