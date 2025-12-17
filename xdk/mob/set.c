/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc set document

	@module	set.c | implement file

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

#include "set.h"

#include "../xdkobj.h"
#include "../xdkstd.h"
#include "../xdkimp.h"

set_t* set_alloc()
{
	set_t* pvs;

	pvs = (set_t*)xmem_alloc(sizeof(set_t));

	// empty set
	pvs->type = _SET_SET;
	pvs->size = 0;
	pvs->pset = NULL;

	return pvs;
}

void set_free(set_t* pv)
{
	set_clear(pv);

	xmem_free(pv);
}

bool_t set_is_empty(set_t* pset)
{
	return (pset->type == _SET_SET && pset->size == 0 && pset->pset == NULL)? bool_true : bool_false;
}

void set_copy(set_t* pdst, const set_t* psrc)
{
	int i;

	XDK_ASSERT(set_is_empty(pdst));

	pdst->type = psrc->type;
	pdst->size = psrc->size;

	if (psrc->type == _SET_SET)
	{
		pdst->pset = (set_t*)xmem_alloc(pdst->size * sizeof(set_t));
		
		for (i = 0; i < pdst->size; i++)
		{
			set_copy(&(pdst->pset[i]), &(psrc->pset[i]));
		}
	}
	else
	{
		xmem_copy((void*)&(pdst->data), (void*)&(psrc->data), sizeof(double));
	}
}

void set_clear(set_t* pset)
{
	int i;

	if (pset->type == _SET_SET)
	{
		for (i = 0; i < pset->size; i++)
		{
			set_clear(&(pset->pset[i]));
		}
		xmem_free(pset->pset);
	}
	
	xmem_zero((void*)pset, sizeof(set_t));
	pset->type = _SET_SET;
}

int set_comp(const set_t* pv1, const set_t* pv2)
{
	int i;
	int rt;

	if (pv1->type < pv2->type)
		return -1;
	else if (pv1->type > pv2->type)
		return 1;

	if (pv1->type == _SET_SET)
	{
		if (pv1->size < pv2->size)
			return -1;
		else if (pv1->size > pv2->size)
			return 1;

		for (i = 0; i < pv1->size; i++)
		{
			rt = set_comp(&(pv1[i]), &(pv2[i]));
			if (rt)
				return rt;
		}
		return 0;
	}
	else
	{
		if (pv1->data == pv2->data)
			return 0;
		else if (pv1->data > pv2->data)
			return 1;
		else
			return -1;
	}
}

int set_find(set_t pa[], int min, int max, const set_t* p)
{
	int mid;
	int rt;

	while (min <= max)
	{
		mid = (min + max) / 2;

		if (pa[mid].type > p->type)
			return set_find(pa, min, mid - 1, p);
		else if (pa[mid].type < p->type)
			return set_find(pa, mid + 1, max, p);

		if (p->type == _SET_SET)
		{
			if (pa[mid].size > p->size)
				return set_find(pa, min, mid - 1, p);
			else if (pa[mid].size < p->size)
				return set_find(pa, mid + 1, max, p);
			
			rt = set_comp(&pa[mid], p);
			if (rt > 0)
				return set_find(pa, min, mid - 1, p);
			else if (rt < 0)
				return set_find(pa, mid + 1, max, p);
			else
				return mid;
		}
		else
		{
			if(pa[mid].data > p->data)
				return set_find(pa, min, mid - 1, p);
			else if (pa[mid].data < p->data)
				return set_find(pa, mid + 1, max, p);
			else
				return mid;
		}
	}

	return max;
}

void set_add(set_t* pset, const set_t* pv)
{
	int i, j;

	XDK_ASSERT(pset->type == _SET_SET);

	i = set_find(pset->pset, 0, pset->size - 1, pv);

	if (i >= 0 && set_comp(&(pset->pset[i]), pv) == 0)
		return;

	pset->pset = (set_t*)xmem_realloc(pset->pset, sizeof(set_t) * (pset->size + 1));

	for (j = pset->size; j > i + 1; j--)
	{
		xmem_copy((void*)&(pset->pset[j]), (void*)&(pset->pset[j-1]), sizeof(set_t));
	}
	pset->size++;

	set_copy(&(pset->pset[i + 1]), pv);
}

void set_del(set_t* pset, const set_t* pv)
{
	int i, j;

	i = set_find(pset->pset, 0, pset->size - 1, pv);
	if (i < 0)
		return;

	if (set_comp(&(pset->pset[i]), pv) != 0)
		return;
	
	set_clear(&(pset->pset[i]));

	for (j = i; j < pset->size - 1; j++)
	{
		xmem_copy((void*)&(pset->pset[j]), (void*)&(pset->pset[j+1]), sizeof(set_t));
	}

	pset->pset = (set_t*)xmem_realloc(pset->pset, sizeof(set_t) * (pset->size - 1));
	pset->size--;
}

bool_t set_in(set_t* pset, const set_t* pv)
{
	int i;

	i = set_find(pset->pset, 0, pset->size - 1, pv);

	return (i >= 0 && set_comp(&(pset->pset[i]), pv) == 0) ? 1 : 0;
}

int set_get_size(set_t* pset)
{
	return (int)pset->size;
}

void set_get(set_t* pset, int i, set_t* pv)
{
	if (i < 0 || i >= pset->size)
		return;

	set_copy(pv, &(pset->pset[i]));
}

static const tchar_t* _set_parse(set_t** ppv, dword_t* psize, const tchar_t* token, int len)
{
	int i, index, total = 0;
	dword_t size;
	set_t* pv = NULL;
	set_t* pa = NULL;
	bool_t b = 0;
	const tchar_t* tmp;

	if (len < 0)
		len = xslen(token);

	while (*token != _T('{') && *token != _T('\0') && total < len)
	{
		total++;
		token++;
	}
	if (*token == _T('{'))
	{
		total++;
		token++;
	}

	index = 0;
	i = 0;
	while (total <= len)
	{
		switch (*token)
		{
		case _T('{'):
			pa = NULL;
			size = 0;
			tmp = token;
			token = _set_parse(&pa, &size, token, len - total);
			total += (int)(token - tmp);
			b = 1;
			break;
		case _T(','):
		case _T('}'):
			index++;
			pv = (set_t*)xmem_realloc(pv, sizeof(set_t) * index);
			if (b)
			{
				pv[index - 1].type = _SET_SET;
				pv[index - 1].size = size;
				pv[index - 1].pset = pa;
			}
			else
			{
				pv[index - 1].type = _SET_ELE;
				pv[index - 1].size = 0;
				pv[index - 1].data = xsntonum(token - i, i);
			}
			b = 0;

			if (*token == _T('}'))
			{
				token++;
				goto RET;
			}

			total++;
			token++;
			i = 0;
			break;
		default:
			total++;
			token++;
			i++;
			break;
		}
	}

RET:

	*psize = index;
	*ppv = pv;

	return token;
}

void set_parse(set_t* pset, const tchar_t* token, int len)
{
	set_clear(pset);

	_set_parse(&(pset->pset), &(pset->size), token, len);
}

static int _set_format(const set_t* ppv, dword_t size, tchar_t* buf, int max)
{
	dword_t i;
	int total = 0;

	if (size)
	{
		if (total + 1 > max)
			return total;

		if (buf)
		{
			buf[total] = _T('{');
		}
		total += 1;
	}

	for (i = 0; i < size; i++)
	{
		if (ppv[i].type == _SET_SET)
		{
			total += _set_format(ppv[i].pset, ppv[i].size, (buf) ? (buf + total) : NULL, max - total);
		}
		else
		{
			total += xsprintf((buf) ? (buf + total) : NULL, _T("%.f"), ppv[i].data);
		}

		if (total + 1 > max)
			return total;

		if (buf)
		{
			buf[total] = _T(',');
		}
		total += 1;
	}

	if (size)
	{
		if (buf)
		{
			buf[total - 1] = _T('}');
		}
	}

	return total;
}

int set_format(const set_t* pset, tchar_t* buf, int max)
{
	XDK_ASSERT(pset->type == _SET_SET);
	
	return _set_format(pset->pset, pset->size, buf, max);
}


/**********************************************************************
ASN.1 CER ENCODING
Set::=SEQUENCE{
	Guider: BER_INTEGERS {BIT[31]: type BIT[30..0]: size}
	Array::={
		[CHIOCE:={
		ChildSet: Set
		Data: BER_OCTET_STRING
		}] ...
	}
}
**********************************************************************/
static dword_t _set_encode(const set_t* pset, dword_t size, byte_t* buf)
{
	dword_t hn, i;
	dword_t n, total = 0;
	schar_t snum[NUM_LEN] = {0};
	int len;

	hn = size & 0x7FFFFFFF;
	n = ver_write_int(((buf) ? (buf + total) : NULL), (int)hn);
	if (!n)
	{
		set_last_error(_T("_set_encode"), _T("ver_write_set"), -1);
		return 0;
	}
	total += n;

	for (i = 0; i < size; i++)
	{
		if (pset[i].type == _SET_SET)
		{
			n = _set_encode(pset[i].pset, pset[i].size, ((buf)? buf + total : NULL));
			if (!n)
			{
				set_last_error(_T("_set_encode"), _T("ver_write_set"), -1);
				return 0;
			}
			total += n;
		}
		else
		{
			len = a_numtoxs(pset[i].data, snum, NUM_LEN);
			hn = (0x80000000 | len);
			n = ver_write_int(((buf)? (buf + total) : NULL), (int)hn);
			if (!n)
			{
				set_last_error(_T("_set_encode"), _T("ver_write_set"), -1);
				return 0;
			}
			total += n;

			n = ver_write_byte_array(((buf) ? (buf + total) : NULL), (byte_t *)snum, len);
			if (!n)
			{
				set_last_error(_T("_set_encode"), _T("ver_write_set"), -1);
				return 0;
			}
			total += n;
		}
	}

	return total;
}

dword_t set_encode(const set_t* pset, byte_t* buf)
{
	dword_t n, total = 0;
	byte_t* pos = NULL;

	XDK_ASSERT(pset->type == _SET_SET);

	n = ver_write_set(((buf)? (buf + total) : NULL), &pos);
	if(!n)
	{
		set_last_error(_T("set_encode"), _T("ver_write_set"), -1);
		return 0;
	} 
	total += n;

	n = _set_encode(pset->pset, pset->size, ((buf)? (buf + total) : NULL));
	if(!n)
	{
		set_last_error(_T("set_encode"), _T("_set_encode"), -1);
		return 0;
	} 
	total += n;

	if(pos) ver_write_set_length(pos, total);

	return total;
}

static dword_t _set_decode(set_t** ppset, dword_t* psize, const byte_t* buf)
{
	dword_t i, len, n, total = 0;
	byte_t addr[NUM_LEN] = {0};

	if (ppset)
	{
		*ppset = (set_t *)xmem_realloc((void *)(*ppset), sizeof(set_t) * (*psize + 1));
		*psize = *psize + 1;
	}

	n = ver_read_int((buf + total), (int *)&len);
	if (!n)
	{
		set_last_error(_T("_set_decode"), _T("ver_read_int"), -1);
		return 0;
	}
	total += n;

	if(len & 0x80000000)
	{ //data node
		len &= 0x7FFFFFFF;
		n = ver_read_byte_array((buf + total), addr, len);
		if (!n)
		{
			set_last_error(_T("_set_decode"), _T("ver_read_byte_array"), -1);
			return 0;
		}
		total += n;

		if (ppset)
		{
			(*ppset)[*psize - 1].type = _SET_ELE;
			(*ppset)[*psize - 1].size = 0;
			(*ppset)[*psize - 1].data = a_xsntonum((schar_t *)addr, len);
		}
	}else
	{ //set node
		if(ppset)
		{
			(*ppset)[*psize - 1].type = _SET_SET;
			(*ppset)[*psize - 1].size = 0;
			(*ppset)[*psize - 1].pset = NULL;
		}

		for(i = 0; i < len; i++)
		{
			n = _set_decode(((ppset)? &((*ppset)[*psize - 1].pset) : NULL), ((ppset)? &((*ppset)[*psize - 1].size) : NULL), buf + total);
			if (!n)
			{
				set_last_error(_T("_set_decode"), _T("_set_decode"), -1);
				return 0;
			}
			total += n;
		}
	}

	return total;
}

dword_t set_decode(set_t* pset, const byte_t* buf)
{
	dword_t len, n, total = 0;

	if(!buf) return 0;

	n = ver_read_set((buf + total), &len);
	if(!n)
	{
		set_last_error(_T("set_decode"), _T("ver_read_set"), -1);
		return 0;
	}
	total += n;

	n = _set_decode(((pset)? &(pset->pset) : NULL), ((pset)? &(pset->size) : NULL), (buf + total));
	if(!n)
	{
		set_last_error(_T("set_decode"), _T("_set_decode"), -1);
		return 0;
	}
	total += n;

	return total;
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void set_self_test()
{
	tchar_t num[NUM_LEN + 1];

	set_t* pset;
	set_t ve;
	int i;

	void* mb;
	dword_t bys;
	tchar_t* buf;
	int len;

	printf("test set...\n");

	pset = set_alloc();

	for (i = 0; i < 10; i++)
	{
		xsprintf(num, _T("%d"), i);

		ve.type = _SET_ELE;
		ve.size = 1;
		ve.data = (double)i;

		set_add(pset, &ve);

		set_clear(&ve);
	}

	len = set_format(pset, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	set_format(pset, buf, len);

	_tprintf(_T("%s\n"), buf);

	xsfree(buf);

	set_clear(pset);

	set_parse(pset, _T("{1,2 ,3,{1,2},{1, 2 ,3}, {1, 2, {1, 2 ,3, 4}}}"), -1);

	len = set_format(pset, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	set_format(pset, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);

	bys = set_encode(pset, NULL);
	mb = xmem_alloc(bys);
	set_encode(pset, mb);
	set_clear(pset);
	bys = set_decode(pset, mb);
	xmem_free(mb);

	for (i = 0; i < pset->size; i++)
	{
		set_get(pset, i, &ve);

		len = set_format(&ve, NULL, MAX_LONG);
		buf = xsalloc(len + 1);
		set_format(&ve, buf, len);

		_tprintf(_T("%s\n"), buf);

		xsfree(buf);

		set_clear(&ve);
	}

	set_free(pset);

	printf("test set end\n");
}
#endif