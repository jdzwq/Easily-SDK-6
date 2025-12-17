/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc map document

	@module	map.c | implement file

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

#include "map.h"

#include "../xdkobj.h"
#include "../xdkstd.h"
#include "../xdkimp.h"

typedef struct _map_context{
	memo_head head;

	int bits;
	dword_t nums;
	void* data;
}map_context;

#define MAP_CALC_COLS(bits)	(sizeof(dword_t) * 8 / bits)

static int map_calc_rows(int nums, int bits)
{
	int rows, cols;

	cols = MAP_CALC_COLS(bits);
	rows = nums / cols;
	if (nums % cols)
		rows++;

	return rows;
}

dword_t map_need_size(dword_t nums, int bits)
{
	dword_t rows, cols;

	cols = MAP_CALC_COLS(bits);
	rows = nums / cols;
	if (nums % cols)
		rows++;

	return (dword_t)(rows * cols * bits / 8);
}

map_t map_alloc(dword_t nums, int bits)
{
	map_context* pmm;

	if (nums <= 0)
		return NULL;

	if (bits != 1 && bits != 2 && bits != 4 && bits != 8)
		return NULL;

	pmm = (map_context*)xmem_alloc(sizeof(map_context));
	pmm->head.tag = MEM_MAP;
	PUT_THREEBYTE_LOC(pmm->head.len, 0, (sizeof(map_context) - 4));

	pmm->bits = bits;
	pmm->nums = nums;
	pmm->data = NULL;
	
	return (map_t)&(pmm->head);
}

void map_free(map_t map)
{
	map_context* pmm = TypePtrFromHead(map_context, map);

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);
	
	//must detach data buffer frist
	XDK_ASSERT(pmm->data == NULL);

	xmem_free(pmm);
}

void map_copy(map_t dst, map_t src)
{
	map_context* psrc = (map_context*)src;
	map_context* pdst = (map_context*)dst;
	dword_t n;

	XDK_ASSERT(psrc && psrc->head.tag == MEM_MAP && pdst && pdst->head.tag == MEM_MAP);
	XDK_ASSERT(psrc->nums == pdst->nums && psrc->bits == pdst->bits);

	if (psrc->data && pdst->data)
	{
		XDK_ASSERT(pdst->data != NULL);
		n = map_need_size(psrc->nums, psrc->bits);
		xmem_copy(pdst->data, psrc->data, n);
	}
}

dword_t map_size(map_t map)
{
	map_context* pmm = TypePtrFromHead(map_context, map);

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);

	return (pmm->data)? map_need_size(pmm->nums, pmm->bits) : 0;
}

int map_bits(map_t map)
{
	map_context* pmm = TypePtrFromHead(map_context, map);

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);

	return pmm->bits;
}

const void* map_data(map_t map)
{
	map_context* pmm = TypePtrFromHead(map_context, map);

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);

	return pmm->data;
}

void map_attach(map_t map, void* data)
{
	map_context* pmm = TypePtrFromHead(map_context, map);

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);
	XDK_ASSERT(pmm->data == NULL);

	pmm->data = data;
}

void* map_detach(map_t map)
{
	map_context* pmm = TypePtrFromHead(map_context, map);
	void* d;

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);

	d = pmm->data;
	pmm->data = NULL;

	return d;
}

void map_zero(map_t map)
{
	map_context* pmm = TypePtrFromHead(map_context, map);
	dword_t n;

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);

	n = map_need_size(pmm->nums, pmm->bits);

	if (pmm->data)
	{
		xmem_zero((void*)pmm->data, n);
	}
}

void map_set_bit(map_t map, dword_t i, byte_t b)
{
	map_context* pmm = TypePtrFromHead(map_context, map);
	dword_t* pd;
	dword_t n, rows, cols;
	dword_t row, col;
	int j;
	dword_t bit, msk;

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);
	XDK_ASSERT(pmm->data != NULL);
	
	pd = (dword_t*)pmm->data;
	cols = MAP_CALC_COLS(pmm->bits);
	rows = map_calc_rows(pmm->nums, pmm->bits);

	row = i / cols;

	XDK_ASSERT(pd != NULL && row < rows);

	msk = 1;
	for (j = 1; j < pmm->bits; j++)
	{
		msk <<= 1;
		msk += 1;
	}

	bit = (b & msk);

	col = i % cols;
	while (col--)
	{
		msk <<= pmm->bits;
		bit <<= pmm->bits;
	}

	pd[row] &= (~msk);
	pd[row] |= bit;
}

byte_t map_get_bit(map_t map, dword_t i)
{
	map_context* pmm = TypePtrFromHead(map_context, map);
	dword_t* pd;
	dword_t rows, cols;
	dword_t row, col;
	int j;
	dword_t msk;

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);
	XDK_ASSERT(pmm->data != NULL);
	
	pd = (dword_t*)pmm->data;
	cols = MAP_CALC_COLS(pmm->bits);
	rows = map_calc_rows(pmm->nums, pmm->bits);

	row = i / cols;

	XDK_ASSERT(pd != NULL && row < rows);

	msk = 1;
	for (j = 1; j < pmm->bits; j++)
	{
		msk <<= 1;
		msk += 1;
	}

	col = i % cols;
	for (j = 0; j < col; j++)
		msk <<= pmm->bits;

	msk &= pd[row];
	for (j = 0; j < col; j++)
		msk >>= pmm->bits;

	return (byte_t)(msk & 0xFF);
}

dword_t map_find_bit(map_t map, dword_t i, byte_t b)
{
	map_context* pmm = TypePtrFromHead(map_context, map);
	dword_t* pd;
	dword_t rows, cols;
	dword_t row, col;
	int j;
	dword_t fix, bit, msk;

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);
	XDK_ASSERT(pmm->data != NULL);
	
	pd = (dword_t*)pmm->data;
	cols = MAP_CALC_COLS(pmm->bits);
	rows = map_calc_rows(pmm->nums, pmm->bits);

	row = i / cols;
	if (!pd || row >= rows)
	{
		return INVALID_BLOCK;
	}

	fix = 1;
	for (j = 1; j < pmm->bits; j++)
	{
		fix <<= 1;
		fix += 1;
	}

	msk = fix;
	bit = (b & fix);

	col = i % cols;
	while (col--)
	{
		msk <<= pmm->bits;
		bit <<= pmm->bits;
	}

	while (row < rows)
	{
		if (bit == (pd[row] & msk))
			return i;

		i++;
		msk <<= pmm->bits;
		bit <<= pmm->bits;

		if (!(i % cols))
		{
			row++;
			msk = fix;
			bit = (b & fix);
		}
	}

	return INVALID_BLOCK;
}

dword_t map_test_bit(map_t map, dword_t i, byte_t b, dword_t n)
{
	map_context* pmm = TypePtrFromHead(map_context, map);
	dword_t* pd;
	dword_t rows, cols;
	dword_t row, col, k = 0;
	int j;
	dword_t fix, bit, msk;

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);
	XDK_ASSERT(pmm->data != NULL);

	pd = (dword_t*)pmm->data;
	cols = MAP_CALC_COLS(pmm->bits);
	rows = map_calc_rows(pmm->nums, pmm->bits);

	row = i / cols;
	if (!pd || row >= rows)
	{
		return INVALID_BLOCK;
	}

	fix = 1;
	for (j = 1; j < pmm->bits; j++)
	{
		fix <<= 1;
		fix += 1;
	}

	msk = fix;
	bit = (b & fix);

	col = i % cols;
	while (col--)
	{
		msk <<= pmm->bits;
		bit <<= pmm->bits;
	}

	while (k < n && row < rows)
	{
		if (bit != (pd[row] & msk))
			break;

		k++;
		i++;
		msk <<= pmm->bits;
		bit <<= pmm->bits;

		if (!(i % cols))
		{
			row++;
			msk = fix;
			bit = (b & fix);
		}
	}

	return k;
}

void map_parse(map_t map, const tchar_t* str, int len)
{
	map_context* pmm = TypePtrFromHead(map_context, map);
	dword_t* pd;
	dword_t rows, n, j;
	const tchar_t* token;

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);
	XDK_ASSERT(pmm->data != NULL);

	if (len < 0)
		len = xslen(str);

	if (!len)
		return;

	pd = (dword_t*)pmm->data;
	rows = map_calc_rows(pmm->nums, pmm->bits);

	token = str;

	while (*token != _T('{') && *token != _T('\0'))
		token++;

	if (*token == _T('\0'))
		return;

	if (*token == _T('{'))
		token++;

	for (j = 0; j < rows; j++)
	{
		n = 0;
		while (*token != _T(',') && *token != _T('}') && *token != _T('\0'))
		{
			n++;
			token++;
		}

		pd[j] = xsntol(token - n, n);

		if (*token == _T(','))
			token++;

		if (*token == _T('}') || *token == _T('\0'))
			break;
	}
}

int map_format(map_t map, tchar_t* buf, int max)
{
	map_context* pmm = TypePtrFromHead(map_context, map);
	dword_t* pd;
	dword_t rows;
	dword_t j, n;
	int total = 0;

	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);

	if (!pmm->data)
		return 0;

	pd = (dword_t*)pmm->data;
	rows = map_calc_rows(pmm->nums, pmm->bits);

	if (total + 1 > max)
		return total;

	if (buf)
	{
		buf[total] = _T('{');
	}
	total++;

	for (j = 0; j < rows; j++)
	{
		n = ltoxs(pd[j], ((buf) ? (buf + total) : NULL), NUM_LEN);
		if (total + n > max)
			return total;

		total += n;

		if (j < rows - 1)
		{
			if (total + 1 > max)
				return total;

			if (buf)
			{
				buf[total] = _T(',');
			}
			total++;
		}
	}

	if (total + 1 > max)
		return total;

	if (buf)
	{
		xsncat(buf + total, _T("}"), 1);
	}
	total++;

	return total;
}

/**********************************************************************
ASN.1 CER ENCODING
Map::=SEQUENCE{
	Head: BER_INTEGERS {bits: BYTE[1] nums: BYTE[3]}
	Data: BER_OCTET_STRING
}
**********************************************************************/
dword_t map_encode(map_t map, byte_t* buf)
{
	map_context* pmm = TypePtrFromHead(map_context, map);
	dword_t n, total = 0;
	dword_t mn, hn;
	byte_t* pos = NULL;
	
	XDK_ASSERT(map != NULL && map->tag == MEM_MAP);

	n = ver_write_sequence(((buf)? buf + total : NULL), &pos);
	if(!n)
	{
		set_last_error(_T("map_encode"), _T("ver_write_sequence"), -1);
		return 0;
	} 
	total += n;

	hn = ((pmm->bits) << 24) | (pmm->nums & 0x00FFFFFF);
	n = ver_write_int(((buf)? buf + total : NULL), (int)hn);
	if(!n)
	{
		set_last_error(_T("map_encode"), _T("ver_write_int"), -1);
		return 0;
	} 
	total += n;

	mn = map_need_size(pmm->nums, pmm->bits);
	if(pmm->data)
	{
		n = ver_write_byte_array(((buf) ? buf + total : NULL), (byte_t *)pmm->data, mn);
	}else
	{
		n = ver_write_byte_array(((buf) ? buf + total : NULL), NULL, 0);
	}
	if(!n)
	{
		set_last_error(_T("map_encode"), _T("ver_write_byte_array"), -1);
		return 0;
	} 
	total += n;

	if(pos) ver_write_sequence_length(pos, total);

	return total;
}

dword_t map_decode(map_t map, const byte_t* buf)
{
	map_context* pmm = TypePtrFromHead(map_context, map);
	dword_t len, n, total = 0;

	if (!buf) return total;

	n = ver_read_sequence(buf + total, &len);
	if(!n)
	{
		set_last_error(_T("map_decode"), _T("ver_read_sequence"), -1);
		return 0;
	}
	total += n;

	n = ver_read_int(buf + total, (int*)&len);
	if(!n)
	{
		set_last_error(_T("map_decode"), _T("ver_read_int"), -1);
		return 0;
	}
	total += n;

	if(pmm)
	{
		pmm->bits = (int)((len & 0xFF000000) >> 24);
		pmm->nums = (int)(len & 0x00FFFFFF);
	}

	len = map_need_size(pmm->nums, pmm->bits);
	n = ver_read_byte_array(buf + total, ((pmm)? pmm->data : NULL), ((pmm)? len : 0));
	if(!n)
	{
		set_last_error(_T("map_decode"), _T("ver_read_byte_array"), -1);
		return 0;
	}
	total += n;

	return total;
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void map_self_test(void)
{
	int items = 128;
	int b = 0x01;
	int i, k, n, size, len;
	map_t map;
	void* mb;
	dword_t bys;
	tchar_t bits[10] = {0};
	tchar_t* buf;

	printf("test map...\n");

	for (k = 1; k <= 8; k <<= 1)
	{
		size = map_need_size(items, k);
		mb = xmem_alloc(size);

		map = map_alloc(items, k);
		map_attach(map, mb);

		_tprintf(_T("items:%d bits:%d size:%d mask:%d\n"), items, k, size, b);

		for (i = 0; i < items; i++)
			map_set_bit(map, i, 0);

		int rows = items / 32;

		for (i = 0; i < rows; i++)
			map_set_bit(map, i * 32 + i % 32, b);

		len = map_format(map, NULL, MAX_LONG);
		buf = xsalloc(len + 1);
		map_format(map, buf, len);

		map_zero(map);
		map_parse(map, buf, len);
		xsfree(buf);

		bys = map_encode(map, NULL);
		mb = xmem_alloc(bys);
		map_encode(map, mb);
		bys = map_decode(map, mb);
		xmem_free(mb);

		for (i = 0; i < items; i++)
		{
			n = k;
			while(n--)
			{
				if (map_get_bit(map, i) == b)
					_tprintf(_T("1"));
				else
					_tprintf(_T("0"));
			}

			_tprintf(_T(" "));

			if (!((i + 1) % 32))
				_tprintf(_T("\n"));
		}

		b <<= 1;
		b |= 1;
		
		mb = map_detach(map);
		xmem_free(mb);
		map_free(map);
	}

	printf("test map end\n");
}
#endif