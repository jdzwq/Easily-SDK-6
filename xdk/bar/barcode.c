
#include "bar.h"

#include <oem.h>

dword_t pdf417_encode(const byte_t* token, dword_t len, byte_t* buf, dword_t max, int* prows, int* pcols)
{
	pdf417param pp = { 0 };

	pdf417init(&pp);

	pp.text = (char*)token;
	pp.lenText = len;
	pp.options = PDF417_INVERT_BITMAP;

	paintCode(&pp);

	if (pp.error)
	{
		pdf417free(&pp);
		return 0;
	}

	if (prows)
	{
		*prows = pp.codeRows;
	}

	if (pcols)
	{
		*pcols = pp.bitColumns / 8 + 1;
	}

	if (buf)
	{
		max = (max < (dword_t)(pp.lenBits)) ? max : (dword_t)(pp.lenBits);
		memcpy((void*)buf, (void*)(pp.outBits), max);
	}
	else
	{
		max = pp.lenBits;
	}

	pdf417free(&pp);

	return max;
}

int pdf417_units(const byte_t* bar_buf, int rows, int cols)
{
	return rows * cols * 8;
}

dword_t code128_encode(const byte_t* token, dword_t len, byte_t* buf, dword_t max)
{
	code128param pp = { 0 };
	dword_t size;

	code128init(&pp);

	pp.inText = (char*)token;
	pp.lenText = len;

	code128exec(&pp);

	if (pp.error)
	{
		code128free(&pp);
		return 0;
	}

	size = pp.lenBytes;

	if (buf)
	{
		max = (max < size) ? max : size;
		memcpy((void*)buf, (void*)pp.outBytes, max);
	}

	code128free(&pp);

	return size;
}

int code128_units(const byte_t* bar_buf, dword_t bar_len)
{
	int n = 0;

	while (bar_len--)
	{
		n += (int)(bar_buf[bar_len] - '0');
	}

	return n;
}
