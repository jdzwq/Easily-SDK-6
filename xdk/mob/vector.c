/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc vector document

	@module	vector.c | implement file

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

#include "vector.h"

#include "../xdkobj.h"
#include "../xdkstd.h"
#include "../xdkimp.h"

typedef struct _vector_context{
	memo_head head;

	int count;
	int dimen;
	void* data;
}vector_context;

#define VECTOR_CALC_SIZE(count, dimen)		(count * dimen * sizeof(double))

dword_t vector_need_size(int count, int dimen)
{
	return (count * dimen * sizeof(double));
}

vector_t vector_alloc(int count, int dimen)
{
	vector_context* pmv;

	XDK_ASSERT(count >= 0 && dimen >= 0);

	pmv = (vector_context*)xmem_alloc(sizeof(vector_context));
	pmv->head.tag = MEM_VECTOR;
	PUT_THREEBYTE_LOC((pmv->head.len), 0, (sizeof(vector_context) - 4));

	pmv->count = count;
	pmv->dimen = dimen;
	pmv->data = NULL;

	return (vector_t)&(pmv->head);
}

void vector_free(vector_t vec)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);
	
	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);
	XDK_ASSERT(pmv->data == NULL);

	xmem_free(pmv);
}

const void* vector_data(vector_t vec)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);

	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);

	return pmv->data;
}

void vector_attach(vector_t vec, void* data)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);

	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);
	XDK_ASSERT(pmv->data == NULL);

	pmv->data = data;
}

void* vector_detach(vector_t vec)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);
	void* d;

	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);

	d = pmv->data;
	pmv->data = NULL;

	return d;
}

void vector_copy(vector_t dst, vector_t src)
{
	vector_context* psrc = TypePtrFromHead(vector_context, src);
	vector_context* pdst = TypePtrFromHead(vector_context, dst);
	int n;

	XDK_ASSERT(psrc && psrc->head.tag == MEM_VECTOR && pdst && pdst->head.tag == MEM_VECTOR);
	XDK_ASSERT(psrc->count == pdst->count && psrc->dimen == pdst->dimen);

	if (psrc->data)
	{
		XDK_ASSERT(pdst->data != NULL);
		n = VECTOR_CALC_SIZE(psrc->count, psrc->dimen);
		xmem_copy(pdst->data, psrc->data, n);
	}
}

int vector_get_count(vector_t vec)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);

	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);

	return pmv->count;
}

int vector_get_dimen(vector_t vec)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);

	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);

	return pmv->dimen;
}

void vector_zero(vector_t vec)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);
	int n;

	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);

	n = VECTOR_CALC_SIZE(pmv->count, pmv->dimen);

	if (pmv->data)
	{
		xmem_zero(pmv->data, n);
	}
}

void vector_unit(vector_t vec)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);
	double* pd;
	int i;

	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);
	XDK_ASSERT(pmv->data != NULL);

	pd = (double*)pmv->data;
	i = pmv->count * pmv->dimen;
	while (i--)
	{
		*pd++ = 1.0;
	}
}

void vector_set_value(vector_t vec, int i, ...)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);
	double* pd;
	int n, j;
	va_list arg;

	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);
	XDK_ASSERT(i >= 0 && i < pmv->count);
	XDK_ASSERT(pmv->data != NULL);

	va_start(arg, i);

	pd = (double*)pmv->data;

	for (j = 0; j < pmv->dimen; j++)
	{
		pd[i * pmv->dimen + j] = va_arg(arg, double);
	}

	va_end(arg);
}

void vector_get_value(vector_t vec, int i, ...)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);
	double *pd;
	int j;
	bool_t b = 0;
	double *pv;
	va_list arg;

	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);
	XDK_ASSERT(pmv->data != NULL);

	va_start(arg, i);

	if (i < 0 || i >= pmv->count)
		b = 1;

	pd = (double*)pmv->data;

	for (j = 0; j < pmv->dimen; j++)
	{
		pv = va_arg(arg, double*);
		if (b)
			*pv = MAXDBL;
		else
			*pv = pd[i * pmv->dimen + j];
	}

	va_end(arg);
}

//x'= x * ShiftX
//y'= y * ShiftY
void vector_shift(vector_t dst, vector_t src, ...)
{
	vector_context* psrc = TypePtrFromHead(vector_context, src);
	vector_context* pdst = TypePtrFromHead(vector_context, dst);
	double *pd;
	int i, j;
	bool_t b = 0;
	double *pb;
	va_list arg;

	XDK_ASSERT(psrc && psrc->head.tag == MEM_VECTOR);
	XDK_ASSERT(pdst && pdst->head.tag == MEM_VECTOR);
	XDK_ASSERT(psrc->data && pdst->data);

	pb = (double*)xmem_alloc(psrc->dimen * sizeof(double));

	va_start(arg, dst);

	for (i = 0; i < psrc->dimen; i++)
	{
		pb[i] = va_arg(arg, double);
	}

	va_end(arg);

	pd = (double*)pdst->data;

	for (i = 0; i < psrc->count; i++)
	{
		for (j = 0; j < psrc->dimen; j++)
		{
			pd[i * psrc->dimen + j] += pb[j];
		}
	}

	xmem_free(pb);
}

//x'= x * cosα+ y * sinα
//y'= x * sinα+ y * cosα
void vector_rotate(vector_t dst, vector_t src, double ang)
{
	vector_context* psrc = TypePtrFromHead(vector_context, src);
	vector_context* pdst = TypePtrFromHead(vector_context, dst);
	int i;
	matrix_t mat;
	void* buff;

	XDK_ASSERT(psrc && psrc->head.tag == MEM_VECTOR);
	XDK_ASSERT(pdst && pdst->head.tag == MEM_VECTOR);
	XDK_ASSERT(psrc->data && pdst->data);
	
	mat = matrix_alloc(psrc->dimen, psrc->dimen);
	buff = xmem_alloc(matrix_need_size(psrc->dimen, psrc->dimen));
	matrix_attach(mat, buff);

	matrix_set_value(mat, 0, 0, cos(ang));
	matrix_set_value(mat, 0, 1, sin(ang));
	matrix_set_value(mat, 1, 0, -sin(ang));
	matrix_set_value(mat, 1, 1, cos(ang));

	for (i = 2; i < psrc->dimen; i++)
	{
		matrix_set_value(mat, i, i, 1.0);
	}

	matrix_mul((matrix_t)dst, (matrix_t)src, mat);

	buff = matrix_detach(mat);
	xmem_free(buff);
	matrix_free(mat);
}

//x'= x * ScallX
//y'= y * ScallY
void vector_scale(vector_t dst, vector_t src, ...)
{
	vector_context* psrc = TypePtrFromHead(vector_context, src);
	vector_context* pdst = TypePtrFromHead(vector_context, dst);

	int i;
	bool_t b = 0;
	double *pb;
	void* buff;
	matrix_t mat;
	va_list arg;

	XDK_ASSERT(psrc && psrc->head.tag == MEM_VECTOR);
	XDK_ASSERT(pdst && pdst->head.tag == MEM_VECTOR);
	XDK_ASSERT(psrc->data && pdst->data);

	pb = (double*)xmem_alloc(psrc->dimen * sizeof(double));

	va_start(arg, dst);

	for (i = 0; i < psrc->dimen; i++)
	{
		pb[i] = va_arg(arg, double);
	}

	va_end(arg);

	mat = matrix_alloc(psrc->dimen, psrc->dimen);
	buff = xmem_alloc(matrix_need_size(psrc->dimen, psrc->dimen));
	matrix_attach(mat, buff);

	for (i = 0; i < psrc->dimen; i++)
	{
		matrix_set_value(mat, i, i, pb[i]);
	}

	xmem_free(pb);

	matrix_mul((matrix_t)dst, (matrix_t)src, mat);

	buff = matrix_detach(mat);
	xmem_free(buff);
	matrix_free(mat);
}

//x' = x + y * ShearX
//y' = y + x * ShearY
void vector_shear(vector_t dst, vector_t src, double sx, double sy)
{
	vector_context* psrc = TypePtrFromHead(vector_context, src);
	vector_context* pdst = TypePtrFromHead(vector_context, dst);

	int i;
	matrix_t mat;
	void* buff;

	XDK_ASSERT(psrc && psrc->head.tag == MEM_VECTOR);
	XDK_ASSERT(pdst && pdst->head.tag == MEM_VECTOR);
	XDK_ASSERT(psrc->data && pdst->data);

	mat = matrix_alloc(psrc->dimen, psrc->dimen);
	buff = xmem_alloc(matrix_need_size(psrc->dimen, psrc->dimen));
	matrix_attach(mat, buff);

	matrix_set_value(mat, 0, 0, 1.0);
	matrix_set_value(mat, 0, 1, sy);
	matrix_set_value(mat, 1, 0, sx);
	matrix_set_value(mat, 1, 1, 1.0);

	for (i = 2; i < psrc->dimen; i++)
	{
		matrix_set_value(mat, i, i, 1.0);
	}

	matrix_mul((matrix_t)dst, (matrix_t)src, mat);

	buff = matrix_detach(mat);
	xmem_free(buff);
	matrix_free(mat);
}

void vector_trans(vector_t dst, vector_t src, matrix_t mat)
{
	matrix_mul((matrix_t)dst, (matrix_t)src, mat);
}

void vector_parse(vector_t vec, const tchar_t* str, int len)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);
	double *pd;
	int i, j, n;
	const tchar_t* token;

	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);
	XDK_ASSERT(pmv->data != NULL);

	if (len < 0)
		len = xslen(str);

	if (!len)
		return;

	pd = (double*)pmv->data;

	token = str;
	
	while (*token != _T('{') && *token != _T('\0'))
	{
		token++;
		len--;
	}

	if (*token == _T('\0'))
		return;

	token++; //skip '{'
	len--;

	for (i = 0; i < pmv->count && len; i++)
	{
		while (*token != _T('(') && *token != _T('}') && *token != _T('\0'))
		{
			token++;
			len--;
		}

		if (*token == _T('}') || *token == _T('\0'))
			break;

		token++; //skip '('
		len--;

		for (j = 0; j < pmv->dimen; j++)
		{
			n = 0;
			while (*token != _T(',') && *token != _T(')') && *token != _T('}') && *token != _T('\0'))
			{
				n++;
				token++;
				len--;
			}

			pd[i * pmv->dimen + j] = xsntonum(token - n, n);

			if (*token == _T(')') || *token == _T('}') || *token == _T('\0'))
				break;

			token++; //skip ','
			len--;
		}

		if (*token == _T('}') || *token == _T('\0'))
			break;

		token++; //skip ')'
		len--;
	}
}

int vector_format(vector_t vec, tchar_t* buf, int max)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);
	double *pd;
	int i, j, n;
	int total = 0;

	XDK_ASSERT(pmv && pmv->head.tag == MEM_VECTOR);

	if (!pmv->data)
	{
		return 0;
	}

	pd = (double*)pmv->data;

	if (!pmv->count)
	{
		if (buf)
		{
			buf[0] = _T('\0');
		}
		return 0;
	}

	if (total + 1 > max)
		return total;

	if (buf)
	{
		buf[total] = _T('{');
	}
	total++;

	for (i = 0; i < pmv->count; i++)
	{
		if (total + 1 > max)
			return total;

		if (buf)
		{
			buf[total] = _T('(');
		}
		total++;

		for (j = 0; j < pmv->dimen; j++)
		{
			n = numtoxs(pd[i * pmv->dimen + j], ((buf) ? (buf + total) : NULL), NUM_LEN);
			if (total + n > max)
				return total;
			total += n;

			if (total + 1 > max)
				return total;

			if (buf)
			{
				buf[total] = _T(',');
			}
			total++;
		}

		//reppace the last ','
		if (buf)
		{
			buf[total-1] = _T(')');
		}

		if (total + 1 > max)
			return total;

		if (buf)
		{
			buf[total] = _T(',');
		}
		total++;
	}
	
	//reppace the last ','
	if (buf)
	{
		buf[total-1] = _T('}');
		buf[total] = _T('\0');
	}

	return total;
}


/**********************************************************************
ASN.1 CER ENCODING
Vector::=SEQUENCE{
	Count: BER_INTEGERS
	Dimen: BER_INTEGERS
	Data: BER_OCTET_STRING
}
**********************************************************************/
dword_t vector_encode(vector_t vec, byte_t* buf)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);
	dword_t n, total = 0;
	dword_t mn, hn;
	byte_t* pos = NULL;

	XDK_ASSERT(vec != NULL && vec->tag == MEM_VECTOR);

	n = ver_write_sequence(((buf)? buf + total : NULL), &pos);
	if(!n)
	{
		set_last_error(_T("vector_encode"), _T("ver_write_sequence"), -1);
		return 0;
	} 
	total += n;

	n = ver_write_int(((buf)? buf + total : NULL), (int)pmv->count);
	if(!n)
	{
		set_last_error(_T("vector_encode"), _T("ver_write_int"), -1);
		return 0;
	} 
	total += n;

	n = ver_write_int(((buf)? buf + total : NULL), (int)pmv->dimen);
	if(!n)
	{
		set_last_error(_T("vector_encode"), _T("ver_write_int"), -1);
		return 0;
	} 
	total += n;

	mn = VECTOR_CALC_SIZE(pmv->count, pmv->dimen);

	if(pmv->data)
	{
		n = ver_write_byte_array(((buf) ? buf + total : NULL), (byte_t *)pmv->data, mn);
	}else
	{
		n = ver_write_byte_array(((buf) ? buf + total : NULL), NULL, 0);
	}
	if(!n)
	{
		set_last_error(_T("vector_encode"), _T("ver_write_byte_array"), -1);
		return 0;
	} 
	total += n;

	if(pos) ver_write_sequence_length(pos, total);

	return total;
}

dword_t vector_decode(vector_t vec, const byte_t* buf)
{
	vector_context* pmv = TypePtrFromHead(vector_context, vec);
	dword_t len, n, total = 0;

	if (!buf) return 0;

	n = ver_read_sequence(buf + total, &len);
	if(!n)
	{
		set_last_error(_T("vector_decode"), _T("ver_read_sequence"), -1);
		return 0;
	} 
	total += n;

	n = ver_read_int(buf + total, (int*)&len);
	if(!n)
	{
		set_last_error(_T("vector_decode"), _T("ver_read_int"), -1);
		return 0;
	} 
	total += n;

	if(pmv) pmv->count = len;
	
	n = ver_read_int(buf + total, (int*)&len);
	if(!n)
	{
		set_last_error(_T("vector_decode"), _T("ver_read_int"), -1);
		return 0;
	} 
	total += n;

	if(pmv) pmv->dimen = len;

	len = VECTOR_CALC_SIZE(pmv->count, pmv->dimen);

	n = ver_read_byte_array(buf + total, ((pmv)? pmv->data : NULL), ((pmv)? len : 0));
	if(!n)
	{
		set_last_error(_T("vector_decode"), _T("ver_read_byte_array"), -1);
		return 0;
	} 
	total += n;

	return total;
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void vector_self_test()
{
	tchar_t* buf;
	int len;

	vector_t vec, vec2;
	void* buff;
	void* buff2;

	void* mb;
	dword_t bys;

	printf("test vector...\n");

	buff = xmem_alloc(vector_need_size(10,1));
	vec = vector_alloc(10, 1);
	vector_attach(vec, buff);
	vector_parse(vec, _T("{(0),(1), (2),(3), (4) ,(5)(6), (7) ,(8),(9)}"), -1);
	len = vector_format(vec, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(vec, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	buff = vector_detach(vec);
	xmem_free(buff);
	vector_free(vec);

	buff = xmem_alloc(vector_need_size(5,2));
	vec = vector_alloc(5,2);
	vector_attach(vec, buff);
	vector_parse(vec, _T(" {(0,1) ,(2,3),(4, 5) ,(6, 7) ,(8,9)}"), -1);
	len = vector_format(vec, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(vec, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	buff = vector_detach(vec);
	xmem_free(buff);
	vector_free(vec);

	buff = xmem_alloc(vector_need_size(4,3));
	vec = vector_alloc(4,3);
	vector_attach(vec, buff);
	vector_parse(vec, _T(" {(0,1, 2), (3,4,5),(6,7), (8))}"), -1);
	len = vector_format(vec, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(vec, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);

	buff2 = xmem_alloc(vector_need_size(4,3));
	vec2 = vector_alloc(4,3);
	vector_attach(vec2, buff2);
	vector_shift(vec2, vec, (double)1, (double)2, (double)3);
	len = vector_format(vec2, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(vec2, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	buff2 = vector_detach(vec2);
	xmem_free(buff2);
	vector_free(vec2);
	buff = vector_detach(vec);
	xmem_free(buff);
	vector_free(vec);

	buff = xmem_alloc(vector_need_size(4,2));
	vec = vector_alloc(4,2);
	vector_attach(vec, buff);
	vector_parse(vec, _T(" {(1,1) ,(-1,1),(-1, -1) ,(1, -1)}"), -1);
	len = vector_format(vec, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(vec, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);

	buff2 = xmem_alloc(vector_need_size(4,2));
	vec2 = vector_alloc(4,2);
	vector_attach(vec2, buff2);
	vector_rotate(vec2, vec, XPI / 4);
	len = vector_format(vec2, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(vec2, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	buff2 = vector_detach(vec2);
	xmem_free(buff2);
	vector_free(vec2);

	buff2 = xmem_alloc(vector_need_size(4,2));
	vec2 = vector_alloc(4,2);
	vector_attach(vec2, buff2);
	vector_scale(vec2, vec, 2.0, 0.5);
	len = vector_format(vec2, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(vec2, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	buff2 = vector_detach(vec2);
	xmem_free(buff2);
	vector_free(vec2);

	buff2 = xmem_alloc(vector_need_size(4,2));
	vec2 = vector_alloc(4,2);
	vector_attach(vec2, buff2);
	vector_shear(vec2, vec, 1.0, 0.5);
	len = vector_format(vec2, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	vector_format(vec2, buf, len);
	_tprintf(_T("%s\n"), buf);
	xsfree(buf);
	buff2 = vector_detach(vec2);
	xmem_free(buff2);
	vector_free(vec2);

	bys = vector_encode(vec, NULL);
	mb = xmem_alloc(bys);
	vector_encode(vec, mb);
	bys = vector_decode(vec, mb);
	xmem_free(mb);

	buff = vector_detach(vec);
	xmem_free(buff);
	vector_free(vec);

	printf("test vector end\n");
}
#endif