/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc matrix document

	@module	matrix.c | implement file

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

#include "matrix.h"

#include "../xdkobj.h"
#include "../xdkstd.h"
#include "../xdkimp.h"

typedef struct _matrix_context{
	memo_head head;

	int rows;
	int cols;
	void* data;
}matrix_context;


#define MATRIX_CALC_SIZE(rows, cols)	(rows * cols * sizeof(double))

dword_t matrix_need_size(int rows, int cols)
{
	return (rows * cols * sizeof(double));
}

matrix_t matrix_alloc(int rows, int cols)
{
	matrix_context* pmt;

	XDK_ASSERT(rows >= 0 && cols >= 0);

	pmt = (matrix_context*)xmem_alloc(sizeof(matrix_context));
	pmt->head.tag = MEM_MATRIX;
	PUT_THREEBYTE_LOC((pmt->head.len), 0, (sizeof(matrix_context) - 4));

	pmt->rows = rows;
	pmt->cols = cols;
	pmt->data = NULL;

	return (matrix_t)&(pmt->head);
}

void matrix_free(matrix_t mat)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt->data == NULL);
	
	xmem_free(pmt);
}

int matrix_get_rows(matrix_t mat)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);

	return pmt->rows;
}

int matrix_get_cols(matrix_t mat)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);

	return pmt->cols;
}

const void* matrix_data(matrix_t mat)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);

	return pmt->data;
}

void matrix_attach(matrix_t mat, void* data)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt->data == NULL);

	pmt->data = data;
}

void* matrix_detach(matrix_t mat)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	void* d;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);

	d = pmt->data;
	pmt->data = NULL;

	return d;
}

void matrix_zero(matrix_t mat)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	int n;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt->data != NULL);

	n = MATRIX_CALC_SIZE(pmt->rows, pmt->cols);

	xmem_zero((void*)pmt->data, n);
}

void matrix_set_value(matrix_t mat, int row, int col, double db)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	double* pd;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(row >= 0 && row < pmt->rows && col >= 0 && col < pmt->cols);
	XDK_ASSERT(pmt->data != NULL);

	pd = (double*)pmt->data;
	pd[row * pmt->cols + col] = db;
}

double matrix_get_value(matrix_t mat, int row, int col)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	double* pd;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(row >= 0 && row < pmt->rows && col >= 0 && col < pmt->cols);
	XDK_ASSERT(pmt->data != NULL);
	
	pd = (double*)pmt->data;

	return pd[row * pmt->cols + col];
}

void matrix_set_bit(matrix_t mat, int i, int j, bool_t b)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	byte_t* pd;
	int n;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt->data != NULL);

	pd = (byte_t*)pmt->data;

	j >>= 3;
	n = j % 8;

	XDK_ASSERT(i >= 0 && i < pmt->rows && j >= 0 && (j < pmt->cols * 8));

	if (b)
		pd[i * pmt->cols * 8 + j] |= (1 << n);
	else
		pd[i * pmt->cols * 8 + j] &= ~(1 << n);
}

bool_t matrix_get_bit(matrix_t mat, int i, int j)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	byte_t* pd;
	int n;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt->data != NULL);

	pd = (byte_t*)pmt->data;

	j >>= 3;
	n = j % 8;

	XDK_ASSERT(i >= 0 && i < pmt->rows && j >= 0 && (j < pmt->cols * 8));

	return (pd[i * pmt->cols * 8 + j] & (1<<n))? 1 : 0;
}

void matrix_unit(matrix_t mat)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	double* pd;
	int i;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt->data != NULL);

	pd = (double*)pmt->data;

	i = pmt->rows * pmt->cols;
	while (i--)
	{
		*pd++ = 1.0;
	}
}

void matrix_trans(matrix_t dst, matrix_t src)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, src);
	double dbl;
	int i, j;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt->data != NULL);

	for (i = 0; i < pmt->cols; i++)
	{
		for (j = 0; j < pmt->rows; j++)
		{
			dbl = matrix_get_value(src, j, i);
			matrix_set_value(dst, i, j, dbl);
		}
	}
}

void matrix_plus(matrix_t dst, matrix_t src, double n)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, src);
	double dbl;
	int i, j;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt->data != NULL);

	for (i = 0; i < pmt->rows; i++)
	{
		for (j = 0; j < pmt->cols; j++)
		{
			dbl = matrix_get_value(src, i, j) * n;
			matrix_set_value(dst, i, j, dbl);
		}
	}
}

void matrix_add(matrix_t dst, matrix_t mat1, matrix_t mat2)
{
	matrix_context* pmt1 = TypePtrFromHead(matrix_context, mat1);
	matrix_context* pmt2 = TypePtrFromHead(matrix_context, mat2);
	double dbl;
	int i, j;

	XDK_ASSERT(pmt1 && pmt1->head.tag == MEM_MATRIX && pmt2 && pmt2->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt1->rows == pmt2->rows && pmt1->cols == pmt2->cols);
	XDK_ASSERT(pmt1->data != NULL && pmt2->data != NULL);

	for (i = 0; i < pmt1->rows; i++)
	{
		for (j = 0; j < pmt2->cols; j++)
		{
			dbl = matrix_get_value(mat1, i, j) + matrix_get_value(mat2, i, j);
			matrix_set_value(dst, i, j, dbl);
		}
	}
}

void matrix_mul(matrix_t dst, matrix_t mat1, matrix_t mat2)
{
	matrix_context* pmt1 = TypePtrFromHead(matrix_context, mat1);
	matrix_context* pmt2 = TypePtrFromHead(matrix_context, mat2);
	double dbl;
	int i, j, k;

	XDK_ASSERT(pmt1 && pmt1->head.tag == MEM_MATRIX && pmt2 && pmt2->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt1->cols == pmt2->rows);
	XDK_ASSERT(pmt1->data != NULL && pmt2->data != NULL);
	
	for (i = 0; i < pmt1->rows; i++)
	{
		for (j = 0; j < pmt2->cols; j++)
		{
			dbl = 0.0;
			for (k = 0; k < pmt1->cols; k++)
			{
				dbl += matrix_get_value(mat1, i, k) * matrix_get_value(mat2, k, j);
			}
			matrix_set_value(dst, i, j, dbl);
		}
	}
}

double matrix_det(matrix_t mat)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	double dbl, n1, n2;
	int i, j, k;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt->data != NULL);

	n1 = 0.0;
	for (k = 0; k < pmt->cols; k++)
	{
		dbl = 1.0;
		for (i = 0, j = k; i < pmt->rows; i++, j++)
		{
			dbl *= matrix_get_value(mat, i, j);

			j %= pmt->cols;
		}
		n1 += dbl;
	}

	n2 = 0.0;
	for (k = pmt->cols - 1; k >= 0; k--)
	{
		dbl = 1.0;
		for (i = 0, j = k; i < pmt->rows; i++, j--)
		{
			dbl *= matrix_get_value(mat, i, j);

			j = (j + pmt->cols) % pmt->cols;
		}
		n2 += dbl;
	}

	return (n1 - n2);
}

void matrix_parse(matrix_t mat, const tchar_t* str, int len)
{	
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	double* pd;
	const tchar_t* token;
	int i, j, n;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);
	XDK_ASSERT(pmt->data != NULL);

	if (len < 0)
		len = xslen(str);

	if (!len)
		return;

	pd = (double*)pmt->data;

	token = str;

	while (*token != _T('{') && *token != _T('\0'))
		token++;

	if (*token == _T('\0'))
		return;

	if (*token == _T('{'))
		token++;

	for (i = 0; i < pmt->rows; i++)
	{
		while (*token != _T('[') && *token != _T('}') && *token != _T('\0'))
			token++;

		if (*token == _T('}') || *token == _T('\0'))
			break;

		//skip '['
		token++;

		for (j = 0; j < pmt->cols; j++)
		{
			n = 0;
			while (*token != _T(',') && *token != _T(']') && *token != _T('}') && *token != _T('\0'))
			{
				n++;
				token++;
			}

			pd[i * pmt->cols + j] = xsntonum(token - n, n);

			if (*token == _T(','))
				token++;

			if (*token == _T(']') || *token == _T('}') || *token == _T('\0'))
				break;
		}

		if (*token == _T('}') || *token == _T('\0'))
			break;

		//skip ']'
		token++;
	}
}

int matrix_format(matrix_t mat, tchar_t* buf, int max)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	double* pd;
	int i, j, n;
	int total = 0;

	XDK_ASSERT(pmt && pmt->head.tag == MEM_MATRIX);

	if (!pmt->data)
		return 0;

	pd = (double*)pmt->data;

	if (total + 1 > max)
		return total;

	if (buf)
	{
		buf[total] = _T('{');
	}
	total++;

	for (i = 0; i < pmt->rows; i++)
	{
		if (total + 1 > max)
			return total;

		if (buf)
		{
			buf[total] = _T('[');
		}
		total++;

		for (j = 0; j < pmt->cols; j++)
		{
			n = numtoxs(pd[i * pmt->cols + j], ((buf)? (buf + total) : NULL), NUM_LEN);
			if (total + n > max)
				return total;

			total += n;

			if (j < pmt->cols - 1)
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
			buf[total] = _T(']');
		}
		total++;

		if (i < pmt->rows - 1)
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
Matrix::=SEQUENCE{
	Rows: BER_INTEGERS
	Cols: BER_INTEGERS
	Data: BER_OCTET_STRING
}
**********************************************************************/
dword_t matrix_encode(matrix_t mat, byte_t* buf)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	dword_t n, total = 0;
	dword_t mn, hn;
	byte_t* pos = NULL;
	
	XDK_ASSERT(mat != NULL && mat->tag == MEM_MATRIX);

	mn = MATRIX_CALC_SIZE(pmt->rows, pmt->cols);

	n = ver_write_sequence(((buf)? buf + total : NULL), &pos);
	if(!n)
	{
		set_last_error(_T("matrix_encode"), _T("ver_write_sequence"), -1);
		return 0;
	} 
	total += n;

	n = ver_write_int(((buf)? buf + total : NULL), (int)pmt->rows);
	if(!n)
	{
		set_last_error(_T("matrix_encode"), _T("ver_write_int"), -1);
		return 0;
	} 
	total += n;

	n = ver_write_int(((buf)? buf + total : NULL), (int)pmt->cols);
	if(!n)
	{
		set_last_error(_T("matrix_encode"), _T("ver_write_int"), -1);
		return 0;
	} 
	total += n;

	if(pmt->data)
	{
		n = ver_write_byte_array(((buf) ? buf + total : NULL), (byte_t *)pmt->data, mn);
	}else
	{
		n = ver_write_byte_array(((buf) ? buf + total : NULL), NULL, 0);
	}
	if(!n)
	{
		set_last_error(_T("matrix_encode"), _T("ver_write_byte_array"), -1);
		return 0;
	} 
	total += n;

	if(pos) ver_write_sequence_length(pos, total);

	return total;
}

dword_t matrix_decode(matrix_t mat, const byte_t* buf)
{
	matrix_context* pmt = TypePtrFromHead(matrix_context, mat);
	dword_t len, n, total = 0;

	if (!buf) return total;

	n = ver_read_sequence(buf + total, &len);
	if(!n)
	{
		set_last_error(_T("matrix_decode"), _T("ver_read_sequence"), -1);
		return 0;
	} 
	total += n;

	n = ver_read_int(buf + total, (int*)&len);
	if(!n)
	{
		set_last_error(_T("matrix_decode"), _T("ver_read_int"), -1);
		return 0;
	} 
	total += n;

	if(pmt) pmt->rows = len;
	
	n = ver_read_int(buf + total, (int*)&len);
	if(!n)
	{
		set_last_error(_T("matrix_decode"), _T("ver_read_int"), -1);
		return 0;
	} 
	total += n;

	if(pmt) pmt->cols = len;

	len = MATRIX_CALC_SIZE(pmt->rows, pmt->cols);
	n = ver_read_byte_array(buf + total, ((pmt)? pmt->data : NULL), ((pmt)? len : 0));
	if(!n)
	{
		set_last_error(_T("matrix_decode"), _T("ver_read_byte_array"), -1);
		return 0;
	} 
	total += n;

	return total;
}

/**********************************************************************/
#if defined (DEBUG) || defined (_DEBUG)
void matrix_self_test(void)
{
	tchar_t* buf;
	int len;

	void* mb;
	dword_t bys;
	void* buff;
	matrix_t mat;

	printf("test matrix...\n");
	
	buff = xmem_alloc(matrix_need_size(2, 10));
	mat = matrix_alloc(2, 10);
	matrix_attach(mat, buff);

	matrix_parse(mat, _T("{ [0, 1, 2,3, 4, 5, 6, 7, 8,9 ],[9,8,7,6,5,4,3,2,1,0] }"), -1);

	len = matrix_format(mat, NULL, MAX_LONG);
	buf = xsalloc(len + 1);
	matrix_format(mat, buf, len);

	_tprintf(_T("%s\n"), buf);

	xsfree(buf);

	bys = matrix_encode(mat, NULL);
	mb = xmem_alloc(bys);
	matrix_encode(mat, mb);
	bys = matrix_decode(mat, mb);
	xmem_free(mb);

	buff = matrix_detach(mat);
	xmem_free(buff);
	matrix_free(mat);

	printf("test matrix end\n");
}
#endif