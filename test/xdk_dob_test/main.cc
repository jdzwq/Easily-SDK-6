
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif


static bool_t printf_ac_node(const tchar_t* key, int len, vword_t delta, void* p)
{
	_tprintf(_T("%s\t%d\n"), key, (int)delta);

	return 1;
}

void test_ac_table()
{
	link_t_ptr tt;

	tt = create_ac_table();
	
	//test case 1
	insert_ac_table(tt, _T("AP"), -1, 1);
	insert_ac_table(tt, _T("BA"), -1, 2);
	insert_ac_table(tt, _T("ABC"), -1, 3);
	insert_ac_table(tt, _T("BCAP"), -1, 4);

	//test case 2
	/*insert_ac_table(tt, _T("POOL"), -1, 5);
	insert_ac_table(tt, _T("PRIZE"), -1, 6);
	insert_ac_table(tt, _T("PREVIEW"), -1, 7);
	insert_ac_table(tt, _T("PREPARE"), -1, 8);
	insert_ac_table(tt, _T("PRODUCE"), -1, 9);
	insert_ac_table(tt, _T("PROGRESS"), -1, 10);*/

	build_ac_table(tt);

	enum_ac_table(tt, printf_ac_node, NULL);

	destroy_ac_table(tt);
}

static int calc_bina_step(link_t_ptr ilk)
{
	int n = 0;

	while (ilk)
	{
		ilk = get_bina_parent_node(ilk);
		n++;
	}

	return n;
}

void _test_bina_tree(int level)
{
	int sum_0 = 0;
	int sum_1 = 0;
	int count_0 = 0;
	int count_1 = 0;
	float max_0 = 0;
	float max_1 = 0;
	int rnd;

	variant_t key = variant_alloc(VV_INT);

	object_t val = object_alloc();

	int i, j = (level)? 100 : 1;
	while (j--)
	{
		link_t_ptr ptr_0 = create_bina_tree(0);
		link_t_ptr ptr_1 = create_bina_tree(1);

		Srand48(time(NULL));

		link_t_ptr nlk;
		int total_0 = 0;
		int total_1 = 0;
		float max;
		int n0, n1, n = 1000;

		for (i = 0; i < n; i++)
		{
			rnd =  (level)? (Lrand48() % n) : i;
			variant_set_int(key, rnd);

			object_set_variant(val, key);

			insert_bina_node(ptr_0, key, val);

			insert_bina_node(ptr_1, key, val);
		}

		n0 = n1 = 0;
		for (i = 0; i < n; i++)
		{
			variant_set_int(key, i);

			nlk = find_bina_node(ptr_0, key, val);
			if (nlk)
			{
				n0++;
				total_0 += calc_bina_step(nlk);
			}

			nlk = find_bina_node(ptr_1, key, val);
			if (nlk)
			{
				n1++;
				total_1 += calc_bina_step(nlk);
			}
		}

		max = (float)total_0 / n0;
		max_0 = (max_0 < max) ? max : max_0;

		max = (float)total_1 / n1;
		max_1 = (max_1 < max) ? max : max_1;

		_tprintf(_T("nm total step %d, total node %d, aveage step %.4f\n"), total_0, n0, (float)total_0 / n0);
		_tprintf(_T("bd total step %d, total node %d, aveage step %.4f\n"), total_1, n1, (float)total_1 / n1);

		destroy_bina_tree(ptr_0);
		destroy_bina_tree(ptr_1);

		sum_0 += total_0;
		sum_1 += total_1;
		count_0 += n0;
		count_1 += n1;

		//Sleep(100);
	}

	_tprintf(_T("nm total step %d, count node %d, max step %.2f, aveage step %.4f\n"), sum_0, count_0, max_0, (float)sum_0 / count_0);
	_tprintf(_T("bd total step %d, count node %d, max step %.2f, aveage step %.4f\n"), sum_1, count_1, max_1, (float)sum_1 / count_1);

	variant_free(key);
	object_free(val);
}

void test_bina_tree()
{
	_test_bina_tree(0);

	//_test_bina_tree(1);
}

static bool_t print_node(link_t_ptr nlk, void* pa)
{
	bplus_tree_t* pbt = (bplus_tree_t*)pa;
	bplus_data_t* pbd = BplusDataFromLink(nlk);
	bplus_index_t* pbi;
	dword_t i,n;
	key64_t key;
	key64_t org;

	variant_t var = variant_alloc(VV_NULL);
	object_t val = object_alloc();
	_key_zero(&org);

	_tprintf(_T("{"));
	for (n = 0; n < pbd->count; n++)
	{
		_get_bplus_entity_val(pbt, pbd, n, var, val);
		_key_gen(var, &key);

		printf("%lu ", key);

		XDK_ASSERT(key > 0);
		XDK_ASSERT(_key_comp(&key, &org) > 0);
	
		_key_copy(&org, &key);
		variant_to_null(var, VV_NULL);
	}
	_tprintf(_T("}"));


	key64_t* pkey;
	link_t_ptr plk = _get_bplus_data_parent(nlk);
	while (plk)
	{
		pbi = BplusIndexFromLink(plk);

		if (pbt->ind_table)
		{
			_lock_bplus_index(pbt, pbi);
		}

		_tprintf(_T("("));
		for (i = 0; i < pbi->count; i++)
		{
			pkey = &(pbi->indices[i].key);

			if (pbd->index == pbi->indices[i].ind)
				_tprintf(_T("["));

			if (pbd->index == pbi->indices[i].ind)
				printf("%lu] ", *pkey);
			else
				printf("%lu ", *pkey);
		}
		_tprintf(_T(")"));

		if (pbt->ind_table)
		{
			_unlock_bplus_index(pbt, pbi, 0);
		}

		plk = _get_bplus_index_parent(plk);
	}

	variant_free(var);
	object_free(val);

	_tprintf(_T("\n"));

	return 1;
}

void test_bplus_tree_none_table()
{
	//tchar_t numset[] = _T("27 16 48 40 48 32 33 48 48 11 31 29 33 47 11 9 1 46 42 8 35 15 1 15 2 33 2 32 49 36 37 38 0 50 51 80 70 83 91 85 96 82 43 20 24 11 12 46 32 11 46 22 11 45 9 17 39 0 44 30 14 18 21 75 71 65 61 83 77 97 66 78 60 63 91 81 92 84");
	tchar_t numset[] = _T("136 82 188 91 130 20 27 152 84 182 42 5 29 78 180 32 173 107 10 191 164 83 139 1 99 100 87 172 181 46 69 35 5 8 69 170 24 118 9 79 126 6 5 174 56 171 44 56 175 124 1 73 133 144 115 34 172 160 108 198 54 119 133 74 193 76 172 188 176 29 51 76 64 9 57 132 37 125 91 196 91 111 184 199 64 114 58 150 14 38 7");// 23 167 51 151 138 121 194 9 175 1");

	link_t_ptr ptr = create_bplus_tree();

	variant_t v = variant_alloc(VV_INT);

	object_t val = object_alloc();

	key64_t org = { 0 };

	tchar_t* key;
	int len;
	int n, total = 0;
	while (n = parse_string_token((numset + total), -1, _T(' '), &key, &len))
	{
		total += n;
		n = xsntol(key, len);
		variant_set_int(v, n);
		_tprintf(_T("INS %d: "),n);

		object_set_variant(val, v);
		insert_bplus_entity(ptr, v, val);
	}

	_key_zero(&org);

	_enum_bplus_entity(ptr, print_node, (void*)BplusTreeFromLink(ptr));

	destroy_bplus_tree(ptr);

	variant_free(v);
	object_free(val);

	///////////////////////////////////
	ptr = create_bplus_tree();

	v = variant_alloc(VV_STRING_UTF8);
	val = object_alloc();
	variant_t v2 = variant_alloc(VV_STRING_UTF8);

	tchar_t str[NUM_LEN + 1];
	int i;
	bool_t rt;
	n = 100000;
	for (i = 0; i < n; i++)
	{
		xsprintf(str, _T("key%d"), i);
		variant_from_string(v, str, -1);
		object_set_variant(val, v);

		insert_bplus_entity(ptr, v, val);
	}

	for (i = 0; i < n; i++)
	{
		xsprintf(str, _T("key%d"), i);
		variant_from_string(v, str, -1);
		object_set_variant(val, v);

		rt = find_bplus_entity(ptr, v, val);
		if (!rt)
		{
			_tprintf(_T("missing %s\n"), str);
		}
		else
		{
			object_get_variant(val, v2);
			XDK_ASSERT(variant_comp(v, v2) == 0);
		}
	}

	_tprintf(_T("end\n"), str);

	variant_free(v2);
	variant_free(v);
	object_free(val);
	destroy_bplus_tree(ptr);
}

void test_bplus_tree_file_table(const tchar_t* tname, dword_t tmask)
{
	tchar_t iname[PATH_LEN + 1] = { 0 };
	tchar_t dname[PATH_LEN + 1] = { 0 };

	xsprintf(iname, _T("%s.ind"), tname);
	xsprintf(dname, _T("%s.dat"), tname);

	int i, j = 10;
	while (j--)
	{
		link_t_ptr pt_index = create_file_table(iname, BLOCK_SIZE_4096, tmask);
		link_t_ptr pt_data = create_file_table(dname, BLOCK_SIZE_512, tmask);

		link_t_ptr ptr = create_bplus_file_table(pt_index, pt_data);

		Srand48((int)time(NULL));

		variant_t v = variant_alloc(VV_INT);

		object_t val = object_alloc();

		int n = 1000;
		int m;

		for (i = 0; i < n; i++)
		{
			while ((m = Lrand48() % n) == 0);
			//_tprintf(_T("04d "), m);
			variant_set_int(v, m);

			object_set_variant(val, v);
			insert_bplus_entity(ptr, v, val);
		}

		_tprintf(_T("\n"));

		_enum_bplus_entity(ptr, print_node, (void*)BplusTreeFromLink(ptr));

		Srand48((int)time(NULL));

		for (i = 0; i < n; i++)
		{
			while ((m = Lrand48() % n) == 0);
			//_tprintf(_T("04d "), m);
			variant_set_int(v, m);

			delete_bplus_entity(ptr, v);
		}

		_tprintf(_T("\n"));

		variant_free(v);
		object_free(val);

		_enum_bplus_entity(ptr, print_node, (void*)BplusTreeFromLink(ptr));

		destroy_file_table(pt_index);

		destroy_file_table(pt_data);

		destroy_bplus_tree(ptr);
	}
}

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


void test_hash_table()
{
	key32_t i,total = 0;
	int min,max,count, zero = 0;
	link_t_ptr ptr;
	hash_table_t* pht;

	ptr = create_hash_table();

	for (i = 0x4E00; i <= 0x9FA5; i++)
	{
		write_hash_attr(ptr, (tchar_t*)&i, 1, NULL, 0);
	}

	pht = HashTableFromLink(ptr);
	min = pht->size;
	max = 0;

	for (i = 0; i < pht->size; i++)
	{
		count = get_link_count(&((pht->pp)[i]));
		printf("entity size is:%d\n", count);
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

	destroy_hash_table(ptr);
}

static bool_t print_leaf(const tchar_t* key, link_t_ptr nlk, void* p)
{
	object_t ob = get_trie_node_val_ptr(nlk);

	string_t vs = string_alloc();
	object_get_string(ob, vs);

	_tprintf(_T("%s %s\n"), key, string_ptr(vs));

	string_free(vs);

	return 1;
}

void test_trie_tree()
{
	object_t v = object_alloc();

	string_t vs = string_alloc();
	string_cpy(vs, _T("trie"), -1);
	object_set_string(v, vs);
	string_free(vs);

	link_t_ptr ptr = create_trie_tree(_T('.'));

	link_t_ptr ilk = write_trie_node(ptr, _T("1.111.1111"), -1, v);

	ilk = write_trie_node(ptr, _T("1.111"), -1, v);

	ilk = write_trie_node(ptr, _T("1.11.111"), -1, v);

	ilk = write_trie_node(ptr, _T("1.11.222"), -1, v);

	ilk = write_trie_node(ptr, _T("1.11.111.11"), -1, v);

	ilk = write_trie_node(ptr, _T("1.1.11.11"), -1, v);

	ilk = write_trie_node(ptr, _T("1.2.3"), -1, v);

	enum_trie_tree(ptr, print_leaf, NULL);

	delete_trie_node(ptr, _T("1.111"), -1);

	delete_trie_node(ptr, _T("1.11.111.11"), -1);

	delete_trie_node(ptr, _T("1.2.3.4"), -1);

	delete_trie_node(ptr, _T("1.2.3"), -1);

	delete_trie_node(ptr, _T("1.11.111"), -1);

	delete_trie_node(ptr, _T("1.11.222"), -1);

	delete_trie_node(ptr, _T("1.1.11.11"), -1);

	delete_trie_node(ptr, _T("1.111.1111"), -1);

	enum_trie_tree(ptr, print_leaf, NULL);

	object_free(v);

	destroy_trie_tree(ptr);
}


int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	test_ac_table();

	xdk_process_uninit();
#ifdef _OS_WINDOWS
	getch();
#endif

	return 0;
}

