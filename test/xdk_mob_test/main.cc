
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif

void test_linear()
{
	linear_t lin = alloc_linear(3);

	byte_t* buf;
	dword_t len;

	int i;

	for (i = 0; i < 10; i++)
	{
		buf = insert_linear_frame(lin, i + 1, 8);

		a_xsprintf((schar_t*)buf, "%08X", (i + 1));

		if (!((i+1) % 3))
			clean_linear_frame(lin, i+1);
	}

	for (i = 0; i < 10; i++)
	{
		buf = get_linear_frame(lin, (i+1), &len);
		printf("linear: %s\n", (const char*)buf);
	}

	free_linear(lin);
}

void test_map(void)
{
	int items = 128;
	int b = 0x01;
	int i, k, size, len;
	map_t pvt;
	tchar_t* buf;

	for (k = 1; k <= 8; k <<= 1)
	{
		pvt = map_alloc(items, k);
		size = map_size(pvt);

		_tprintf(_T("items:%d bits:%d size:%d mask:%d\n"), items, k, size, b);

		for (i = 0; i < items; i++)
			map_set_bit(pvt, i, b);

		int rows = items / (32 / k);

		for (i = 0; i < rows; i++)
			map_set_bit(pvt, i * (32 / k) + i % (32 / k), 0);

		len = map_format(pvt, NULL, MAX_LONG);
		buf = xsalloc(len + 1);
		map_format(pvt, buf, len);

		map_zero(pvt);
		map_parse(pvt, buf, len);
		xsfree(buf);

		for (i = 0; i < items; i++)
		{
			if (map_get_bit(pvt, i) == b)
				_tprintf(_T("1"));
			else
				_tprintf(_T("0"));

			if (!((i + 1) % (32 / k)))
				_tprintf(_T("\n"));
		}

		b <<= 1;
		map_free(pvt);
	}
}

void test_matrix(void)
{
	tchar_t* buf;
	int len;

	matrix_t pvt = matrix_alloc(2, 10);

	matrix_parse(pvt, _T("{ [0, 1, 2,3, 4, 5, 6, 7, 8,9 ],[9,8,7,6,5,4,3,2,1,0] }"), -1);

	len = matrix_format(pvt, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	matrix_format(pvt, buf, len);

	_tprintf(_T("%s\n"), buf);

	xsfree(buf);

	matrix_free(pvt);
}

void test_message(void)
{
	byte_t buf[] = "hello world!";

	msg_hdr_t hdr = { 0 };

	message_t msg = message_alloc();

	hdr.ver = MSGVER_SENSOR;
	hdr.qos = 0x02;
	
	byte_t tmp[100] = { 0 };
	int i;

	for (i = 0; i < 100; i++)
	{
		hdr.seq = i;
		hdr.utc = get_timestamp();

		message_write(msg, &hdr, buf, a_xslen((schar_t*)buf));

		message_read(msg, &hdr, tmp, 100);

		printf("ver:0x%08x qos:%c seq:%d utc:%llu msg:%s\n", hdr.ver, hdr.qos, hdr.seq, hdr.utc,tmp);
	}

	message_free(msg);
}

void test_queue(void)
{
	byte_t buf[] = "hello world!";

	msg_hdr_t hdr = { 0 };

	message_t msg = message_alloc();

	hdr.ver = MSGVER_SENSOR;
	hdr.qos = 0x02;

	byte_t tmp[100] = { 0 };

	queue_t que = queue_alloc();
	int i;

	for (i = 0; i < 100; i++)
	{
		hdr.seq = i;
		hdr.utc = get_timestamp();

		message_write(msg, &hdr, buf, a_xslen((schar_t*)buf));

		queue_write(que, msg);

		printf("write: ver:0x%08x qos:%c seq:%d utc:%llu msg:%s\n", hdr.ver, hdr.qos, hdr.seq, hdr.utc, buf);
	}

	while (queue_read(que, msg))
	{
		message_read(msg, &hdr, tmp, 100);

		printf("read: ver:0x%08x qos:%c seq:%d utc:%llu msg:%s\n", hdr.ver, hdr.qos, hdr.seq, hdr.utc, tmp);
	}

	message_free(msg);

	queue_free(que);
}

void test_set()
{
	tchar_t num[NUM_LEN + 1];

	set_t* pset = set_alloc();
	set_t ve;
	int i;

	for (i = 0; i < 10; i++)
	{
		xsprintf(num, _T("%d"), i);

		ve.type = _SET_ELE;
		ve.size = 1;
		ve.data = (double)i;

		set_add(pset, &ve);

		set_reset(&ve);
	}

	int len = set_format(pset, NULL, MAX_LONG);
	tchar_t* buf = xsalloc(len + 1);
	set_format(pset, buf, len);

	_tprintf(_T("%s\n"), buf);

	xsfree(buf);

	set_reset(pset);

	set_parse(pset, _T("{1,2 ,3,{1,2},{1 2 3}, {1, 2, {1 2 3 4}}}"), -1);

	len = set_format(pset, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	set_format(pset, buf, len);

	_tprintf(_T("%s\n"), buf);

	xsfree(buf);

	for (i = 0; i < pset->size; i++)
	{
		set_get(pset, i, &ve);

		len = set_format(&ve, NULL, MAX_LONG);
		buf = xsalloc(len + 1);
		set_format(&ve, buf, len);

		_tprintf(_T("%s\n"), buf);

		xsfree(buf);

		set_reset(&ve);
	}

	set_free(pset);
}

void test_spinlock()
{
	lword_t tms;
	nuid_t nuid = { 0 };
	tchar_t token[NUID_TOKEN_SIZE + 1] = { 0 };

	tms = get_timestamp();
	nuid_from_timestamp(&nuid, tms);
	nuid_format_string(&nuid, token);

	int nums = 4096;
	spinlock_t lt = alloc_spinlock(token, nums);
	bool_t rt;
	int i, k, j;

	for (k = 0; k < 1024; k++)
	{
		for (i = 0; i < nums; i++)
		{
			for (j = 0; j < 2; j++)
			{
				rt = enter_spinlock(lt, k, i);
				_tprintf(_T("map:%d pos:%d return:%d\n"), k, i, rt);
				//if (j % 2 && rt)
					//goto err;
				leave_spinlock(lt, k, i);
			}
		}
	}

//err:

	free_spinlock(lt);
}

void test_variant(void)
{
	variant_t v1 = variant_alloc(VV_STRING_UTF8);
	variant_t v2 = variant_alloc(VV_STRING_UTF8);

	XDK_ASSERT(variant_comp(v1, v2) == 0);

	variant_from_string(v1, _T("test1"), -1);
	variant_from_string(v2, _T("test2"), -1);

	XDK_ASSERT(variant_comp(v1, v2) < 0);

	variant_free(v1);
	variant_free(v2);

	v1 = variant_alloc(VV_INT);
	v2 = variant_alloc(VV_INT);
	variant_from_string(v1, _T("123456789"), -1);

	tchar_t token[NUM_LEN + 1];
	variant_to_string(v1, token, NUM_LEN);

	variant_from_string(v2, token, -1);

	XDK_ASSERT(variant_comp(v1, v2) == 0);

	byte_t* buf;
	dword_t len;
	len = variant_encode(v1, NULL, MAX_LONG);
	buf = (byte_t*)xmem_alloc(len);
	variant_encode(v1, buf, len);

	variant_decode(v2, buf);

	XDK_ASSERT(variant_comp(v1, v2) == 0);

	xmem_free(buf);

	variant_free(v1);
	variant_free(v2);
}

void test_object(void)
{
	object_t obj = object_alloc();

	tchar_t* str;
	int len;

	string_t s = string_alloc();
	string_cpy(s, _T("object test 字符对象测试"), -1);
	len = string_len(s);
	str = (tchar_t*)string_ptr(s);
	_tprintf(_T("string object test: %s\n"), str);

	object_set_string(obj, s);
	object_set_commpress(obj, 1);
	len = object_size(obj);
	_tprintf(_T("string object compressed:%d\n"), len);

	string_empty(s);
	object_get_string(obj, s);
	len = string_len(s);
	str = (tchar_t*)string_ptr(s);
	_tprintf(_T("string object unconpressed: %s\n"), str);
	
	string_cpy(s, _T("object test 变体对象测试"), -1);
	len = string_len(s);
	str = (tchar_t*)string_ptr(s);
	_tprintf(_T("variant object test: %s\n"), str);

	variant_t v = variant_alloc(VV_STRING_UTF8);
	variant_from_string(v, string_ptr(s), string_len(s));

	object_set_variant(obj, v);
	object_set_commpress(obj, 1);
	len = object_size(obj);
	_tprintf(_T("variant object compressed:%d\n"), len);

	variant_to_null(v, VV_STRING_UTF8);
	object_get_variant(obj, v);
	len = variant_to_string(v, NULL, MAX_LONG);
	str = xsalloc(len + 1);
	variant_to_string(v, str, len);
	_tprintf(_T("variant object unconpressed: %s\n"), str);
	xsfree(str);

	byte_t* buf;
	dword_t dw;
	dw = object_encode(obj, NULL, MAX_LONG);
	buf = (byte_t*)xmem_alloc(dw);
	object_encode(obj, buf, dw);

	object_empty(obj);
	object_decode(obj, buf);
	xmem_free(buf);

	object_get_variant(obj, v);
	len = variant_to_string(v, NULL, MAX_LONG);
	str = xsalloc(len + 1);
	variant_to_string(v, str, len);
	xsfree(str);

	string_free(s);
	variant_free(v);
	object_free(obj);
}

void test_vector()
{
	tchar_t* buf;
	int len;

	vector_t pvt;

	pvt = vector_alloc(10, 1);
	vector_parse(pvt, _T("{(0),(1), (2),(3), (4) ,(5)(6), (7) ,(8),(9)}"), -1);
	len = vector_format(pvt, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(pvt, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	vector_free(pvt);

	pvt = vector_alloc(5,2);
	vector_parse(pvt, _T(" {(0,1) ,(2,3),(4, 5) ,(6, 7) ,(8,9)}"), -1);
	len = vector_format(pvt, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(pvt, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	vector_free(pvt);

	pvt = vector_alloc(4,3);
	vector_parse(pvt, _T(" {(0,1, 2), (3,4,5),(6,7), (8))}"), -1);
	len = vector_format(pvt, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(pvt, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);

	vector_t pv = vector_shift(pvt, (double)1, (double)2, (double)3);
	len = vector_format(pv, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(pv, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	vector_free(pv);

	vector_free(pvt);

	pvt = vector_alloc(4,2);
	vector_parse(pvt, _T(" {(1,1) ,(-1,1),(-1, -1) ,(1, -1)}"), -1);
	len = vector_format(pvt, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(pvt, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);

	pv = vector_rotate(pvt, XPI / 4);
	len = vector_format(pv, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(pv, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	vector_free(pv);

	pv = vector_scale(pvt, 2.0, 0.5);
	len = vector_format(pv, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(pv, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	vector_free(pv);

	pv = vector_shear(pvt, 1.0, 0.5);
	len = vector_format(pv, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(pv, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	vector_free(pv);

	vector_free(pvt);

}

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//test_linear();

	//test_map();

	//test_matrix();

	//test_message();

	//test_queue();

	//test_set();

	//test_spinlock();

	//test_variant();

	//test_object();

	test_vector();

	xdk_process_uninit();
#ifdef _OS_WINDOWS
	getch();
#endif

	return 0;
}

