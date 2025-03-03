﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc dicttable document

	@module	dicttable.c | implement file

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

#include "dicttable.h"

#include "../xdkimp.h"
#include "../xdkoem.h"
#include "../xdkstd.h"

typedef struct _dict_entity_t{
	link_t lk;			/* entity self link component*/

	lword_t code;
	variant_t key;
	object_t val;
	vword_t delta;
}dict_entity_t;

typedef struct _dict_table_t{
	link_t lk;			/* dict table self link component*/
	link_t* pp;			/* dict table master root link ptr array*/
	dword_t size;		/* root link ptr array size, is prim value*/
}dict_table_t;

/* restore dict table struct ptr from link ptr*/
#define DictTableFromLink(p) TypePtrFromLink(dict_table_t,p) 
/* restore dict entity struct ptr from link ptr*/
#define DictEntityFromLink(p) TypePtrFromLink(dict_entity_t,p)

#define DICTINDEX(code,prim)	(dword_t)(code % (key64_t)prim)

static int _insert_dict_entity(link_t_ptr root, link_t_ptr elk)
{
	dict_entity_t* pnew;
	dict_entity_t* phe;
	link_t_ptr plk;
	int count = 0;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	pnew = DictEntityFromLink(elk);
	plk = get_first_link(root);
	while (plk)
	{
		phe = DictEntityFromLink(plk);
		if (phe->code >= pnew->code)
			break;

		count++;
		plk = get_next_link(plk);
	}

	if (plk == NULL)
	{
		insert_link_after(root, LINK_LAST, elk);
	}
	else
	{
		insert_link_before(root, plk, elk);
	}

	while (elk)
	{
		count++;
		elk = get_next_link(elk);
	}

	return count;
}

void _expand_dict_table(dict_table_t* pht)
{
	dict_entity_t* phe;
	link_t_ptr plk, pnew;
	dword_t i, index, prim;
	key64_t code;

	prim = pht->size;

	i = 10;
	while (i--)
	{
		prim = next_prim(prim);
	}

	if (prim == MAX_PRIM)
		return;

	pnew = (link_t*)xmem_alloc(prim * sizeof(link_t));
	for (i = 0; i < prim; i++)
		init_root_link(&(pnew[i]));

	for (i = 0; i<pht->size; i++)
	{
		while (plk = delete_link(&((pht->pp)[i]), LINK_LAST))
		{
			phe = DictEntityFromLink(plk);

			variant_hash64(phe->key, &code);
			index = DICTINDEX(code, prim);

			_insert_dict_entity(&(pnew[index]), plk);
		}
	}

	xmem_free(pht->pp);
	pht->pp = pnew;
	pht->size = prim;
}


link_t_ptr create_dict_table()
{
	dict_table_t* pht;
	dword_t i;

	pht = (dict_table_t*)xmem_alloc(sizeof(dict_table_t));
	pht->lk.tag = lkDictTable;
	pht->lk.next = NULL;
	pht->lk.prev = NULL;
	pht->size = next_prim(MIN_PRIM);

	pht->pp = (link_t_ptr)xmem_alloc(pht->size * sizeof(link_t));
	for (i = 0; i<pht->size; i++)
		init_root_link(pht->pp + i);

	return &(pht->lk);
}

void destroy_dict_table(link_t_ptr ptr)
{
	dict_table_t* pht;

	XDK_ASSERT(ptr && ptr->tag == lkDictTable);

	clear_dict_table(ptr);

	pht = DictTableFromLink(ptr);

	xmem_free(pht->pp);
	xmem_free(pht);
}

void clear_dict_table(link_t_ptr ptr)
{
	dict_table_t* pht;
	dict_entity_t* phe;
	link_t_ptr plk;
	dword_t i;

	XDK_ASSERT(ptr && ptr->tag == lkDictTable);

	pht = DictTableFromLink(ptr);

	for (i = 0; i<pht->size; i++)
	{
		while (plk = delete_link(&(pht->pp[i]), LINK_FIRST))
		{
			phe = DictEntityFromLink(plk);

			variant_free(phe->key);

			object_free(phe->val);

			xmem_free(phe);
		}
	}
}

void copy_dict_table(link_t_ptr ptr_dest, link_t_ptr ptr_src)
{
	dict_table_t* pht;
	dict_entity_t* phe;
	link_t_ptr plk;
	dword_t i;

	XDK_ASSERT(ptr_dest && ptr_dest->tag == lkDictTable);
	XDK_ASSERT(ptr_src && ptr_src->tag == lkDictTable);

	pht = DictTableFromLink(ptr_src);
	for (i = 0; i<pht->size; i++)
	{
		plk = get_first_link(&((pht->pp)[i]));
		while (plk != NULL)
		{
			phe = DictEntityFromLink(plk);

			write_dict_entity(ptr_dest, phe->key, phe->val);

			plk = get_next_link(plk);
		}
	}
}

int get_dict_entity_count(link_t_ptr ptr)
{
	dict_table_t* pht;
	link_t_ptr plk;
	dword_t i;
	int count = 0;

	XDK_ASSERT(ptr && ptr->tag == lkDictTable);

	pht = DictTableFromLink(ptr);

	for (i = 0; i<pht->size; i++)
	{
		plk = get_first_link(&((pht->pp)[i]));
		while (plk != NULL)
		{
			count++;
			plk = get_next_link(plk);
		}
	}

	return count;
}

link_t_ptr get_dict_entity_at(link_t_ptr ptr, int index)
{
	dict_table_t* pht;
	link_t_ptr plk;
	dword_t i;
	int count = 0;

	XDK_ASSERT(ptr && ptr->tag == lkDictTable);

	pht = DictTableFromLink(ptr);

	for (i = 0; i<pht->size; i++)
	{
		plk = get_first_link(&((pht->pp)[i]));
		while (plk != NULL)
		{
			if (count == index)
				return plk;

			count++;
			plk = get_next_link(plk);
		}
	}
	return NULL;
}

int get_dict_entity_index(link_t_ptr ptr, link_t_ptr elk)
{
	dict_table_t* pht;
	link_t_ptr plk;
	dword_t i;
	int index = 0;

	XDK_ASSERT(ptr && ptr->tag == lkDictTable);

	pht = DictTableFromLink(ptr);

	for (i = 0; i<pht->size; i++)
	{
		plk = get_first_link(&((pht->pp)[i]));
		while (plk != NULL)
		{
			if (plk == elk)
				return index;

			index++;
			plk = get_next_link(plk);
		}
	}
	return -1;
}

link_t_ptr _dict_first_entity(dict_enum_t* pea)
{
	dict_table_t* pht;
	link_t_ptr plk;
	dword_t i, count = 0;

	pht = DictTableFromLink(pea->dict);

	for (i = 0; i<pht->size; i++)
	{
		plk = get_first_link(&((pht->pp)[i]));
		if (plk != NULL)
		{
			pea->index = i;
			pea->entity = plk;
			return pea->entity;
		}
	}
	return NULL;
}

link_t_ptr _dict_last_entity(dict_enum_t* pea)
{
	dict_table_t* pht;
	link_t_ptr plk;
	int i, count = 0;

	pht = DictTableFromLink(pea->dict);

	for (i = pht->size - 1; i >= 0; i--)
	{
		plk = get_last_link(&((pht->pp)[i]));
		if (plk != NULL)
		{
			pea->index = i;
			pea->entity = plk;
			return pea->entity;
		}
	}
	return NULL;
}

link_t_ptr get_dict_next_entity(dict_enum_t* pea)
{
	dict_table_t* pht;
	link_t_ptr plk;
	dword_t i, count = 0;

	XDK_ASSERT(pea->dict && pea->dict->tag == lkDictTable);

	if (pea->entity == LINK_FIRST)
		return _dict_first_entity(pea);
	else if (pea->entity == LINK_LAST)
		return NULL;

	plk = get_next_link(pea->entity);
	if (plk)
	{
		pea->entity = plk;
		return pea->entity;
	}

	pht = DictTableFromLink(pea->dict);

	for (i = pea->index + 1; i<pht->size; i++)
	{
		plk = get_first_link(&((pht->pp)[i]));
		if (plk)
		{
			pea->index = i;
			pea->entity = plk;
			return pea->entity;
		}
	}
	return NULL;
}

link_t_ptr get_dict_prev_entity(dict_enum_t* pea)
{
	dict_table_t* pht;
	link_t_ptr plk;
	int i, count = 0;

	XDK_ASSERT(pea->dict && pea->dict->tag == lkDictTable);

	if (pea->entity == LINK_FIRST)
		return NULL;
	else if (pea->entity == LINK_LAST)
		return _dict_last_entity(pea);

	plk = get_prev_link(pea->entity);
	if (plk)
	{
		pea->entity = plk;
		return pea->entity;
	}

	pht = DictTableFromLink(pea->dict);

	for (i = pea->index - 1; i >= 0; i--)
	{
		plk = get_last_link(&((pht->pp)[i]));
		if (plk)
		{
			pea->index = i;
			pea->entity = plk;
			return pea->entity;
		}
	}
	return NULL;
}

link_t_ptr	write_dict_entity(link_t_ptr ptr, variant_t key, object_t val)
{
	dict_table_t* pht;
	dict_entity_t* phe;
	link_t_ptr plk;
	key64_t code;
	dword_t count;

	XDK_ASSERT(ptr && ptr->tag == lkDictTable);

	if (variant_is_null(key))
		return NULL;

	pht = DictTableFromLink(ptr);
	/*first to find entity with the key*/
	plk = get_dict_entity(ptr, key);
	if (plk != NULL)		/*if exist then to replace the entiry value*/
	{
		phe = DictEntityFromLink(plk);

		if (val)
			object_copy(phe->val, val);
		else
			object_empty(phe->val);
	}
	else	/*if not exist then to add new entity with key and value*/
	{
		variant_hash64(key, &code);

		phe = (dict_entity_t*)xmem_alloc(sizeof(dict_entity_t));
		phe->lk.tag = lkDictEntity;
		phe->code = code;

		phe->key = variant_clone(key);
		phe->val = (val)? object_clone(val) : object_alloc();

		plk = &((pht->pp)[DICTINDEX(code, pht->size)]);

		/*insert entity to list by key's asc order*/
		count = _insert_dict_entity(plk, &phe->lk);
		if (count > pht->size)
		{
			_expand_dict_table(pht);
		}
	}

	return &(phe->lk);
}

bool_t read_dict_entity(link_t_ptr ptr, variant_t key, object_t val)
{
	link_t_ptr ent;

	ent = get_dict_entity(ptr, key);
	if (!ent)
		return 0;

	get_dict_entity_val(ent, val);
	return 1;
}

link_t_ptr get_dict_entity(link_t_ptr ptr, variant_t key)
{
	key64_t code;
	dict_entity_t* phe;
	dict_table_t* pht;
	link_t_ptr plk;

	XDK_ASSERT(ptr && ptr->tag == lkDictTable);

	if (variant_is_null(key))
		return NULL;

	pht = DictTableFromLink(ptr);

	/*first to calc master root link ptr array position by the key's dict code */
	variant_hash64(key, &code);
	/*then to compare the entity key in the ordered list*/
	plk = get_first_link(&((pht->pp)[DICTINDEX(code, pht->size)]));
	while (plk != NULL)
	{
		phe = DictEntityFromLink(plk);
		
		if (phe->code == code)
			return plk;
		
		plk = get_next_link(plk);
	}

	return NULL;
}

static void _delete_dict_entity(link_t_ptr elk)
{
	dict_entity_t* phe;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	phe = DictEntityFromLink(elk);
	/*delete link ptr from list*/
	delete_link(NULL, elk);

	variant_free(phe->key);
		
	object_free(phe->val);

	xmem_free(phe);
}

void delete_dict_entity(link_t_ptr ptr, variant_t key)
{
	link_t_ptr elk;

	elk = get_dict_entity(ptr, key);
	if (elk)
	{
		_delete_dict_entity(elk);
	}
}

const variant_t get_dict_entity_key_ptr(link_t_ptr elk)
{
	dict_entity_t* phe;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	phe = DictEntityFromLink(elk);
	return phe->key;
}

const object_t get_dict_entity_val_ptr(link_t_ptr elk)
{
	dict_entity_t* phe;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	phe = DictEntityFromLink(elk);
	return phe->val;
}

void get_dict_entity_key(link_t_ptr elk, variant_t key)
{
	dict_entity_t* phe;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	phe = DictEntityFromLink(elk);

	variant_copy(key, phe->key);
}

void get_dict_entity_val(link_t_ptr elk, object_t val)
{
	dict_entity_t* phe;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	phe = DictEntityFromLink(elk);

	object_copy(val, phe->val);
}

void set_dict_entity_key(link_t_ptr elk, variant_t key)
{
	dict_entity_t* phe;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	phe = DictEntityFromLink(elk);

	variant_copy(phe->key, key);
}

void set_dict_entity_val(link_t_ptr elk, object_t val)
{
	dict_entity_t* phe;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	phe = DictEntityFromLink(elk);

	if (phe->val && val)
		object_copy(phe->val, val);
	else if (val)
		object_empty(phe->val);
}

void attach_dict_entity_val(link_t_ptr elk, object_t val)
{
	dict_entity_t* phe;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	XDK_ASSERT(val != NULL);

	phe = DictEntityFromLink(elk);

	object_free(phe->val);

	phe->val = val;
}

object_t detach_dict_entity_val(link_t_ptr elk)
{
	dict_entity_t* phe;
	object_t val;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	phe = DictEntityFromLink(elk);

	val = phe->val;

	phe->val = object_alloc();

	return val;
}

vword_t get_dict_entity_delta(link_t_ptr elk)
{
	dict_entity_t* phe;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	phe = DictEntityFromLink(elk);

	return phe->delta;
}

void set_dict_entity_delta(link_t_ptr elk, vword_t delta)
{
	dict_entity_t* phe;

	XDK_ASSERT(elk && elk->tag == lkDictEntity);

	phe = DictEntityFromLink(elk);

	phe->delta = delta;
}

link_t_ptr enum_dict_entity(link_t_ptr ptr, ENUM_DICTTABLE_ENTITY pf, void* pv)
{
	dict_table_t* pht;
	dict_entity_t* phe;
	link_t_ptr plk = NULL;
	dword_t i;

	XDK_ASSERT(ptr && ptr->tag == lkDictTable);

	pht = DictTableFromLink(ptr);
	for (i = 0; i<pht->size; i++)
	{
		plk = get_first_link(&((pht->pp)[i]));
		while (plk != NULL)
		{
			phe = DictEntityFromLink(plk);

			if (pf == NULL)
			{
				plk = get_next_link(plk);
				continue;
			}

			if (!(*pf)(phe->key, plk, pv))
				break;

			plk = get_next_link(plk);
		}

		if (plk)
			break;
	}

	return plk;
}


#if defined(XDK_SUPPORT_TEST)
void test_dict_table()
{
	dword_t i,count,total = 0;
	dword_t min, max, zero = 0;
	link_t_ptr ptr;
	dict_table_t* pht;

	ptr = create_dict_table();

	variant_t key = variant_alloc(VV_INT);

	object_t val = object_alloc();

	for (i = 0x4E00; i <= 0x9FA5; i++)
	{
		variant_set_int(key, i);

		object_set_variant(val, key);
		write_dict_entity(ptr, key, val);
	}

	variant_t key2 = variant_alloc(VV_INT);

	for (i = 0x4E00; i <= 0x9FA5; i++)
	{
		variant_set_int(key, i);

		read_dict_entity(ptr, key, val);
		object_get_variant(val, key2);

		int rt = variant_comp(key, key2);
		XDK_ASSERT(rt == 0);
	}

	variant_free(key2);

	pht = DictTableFromLink(ptr);
	min = pht->size;
	max = 0;
	for (i = 0; i < pht->size; i++)
	{
		count = get_link_count(&((pht->pp)[i]));
		printf("entity size is:%d\n",  count);
		total += count;
		if (!count)
			zero++;
		if (min > count)
			min = count;
		if (max < count)
			max = count;
	}

	printf("table size is:%d\n", pht->size);
	printf("zero eintities is:%d\n", zero);
	printf("max eintities is:%d\n", max);
	printf("min eintities is:%d\n", min);
	printf("total entities is:%d\n", total);

	destroy_dict_table(ptr);

	variant_free(key);
	object_free(val);
}
#endif