/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc memory driver for Monochrome image document

	@module	mdrv_mono.c | implement file

	@devnote 张文权 2021.01 - 2021.12 v6.0
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

#include "mdrv.h"

#include "../xdgmgc.h"

typedef struct _mono_driver_t{
	handle_head head;

	int	width;		/* horz reslution */
	int	height;		/* vert reslution */
	dword_t line_bytes; /* bytes per line */

	int frame_width;	/* points of frame per line */
	dword_t	frame_stride;	/* bytes of frame per line */
	byte_t* frame_addr;	/* frame buffer address */

	PIXELVAL table[2]; /* monochrome color table */
}mono_driver_t;

#define VALID_COORDINATE(x, y) (x >= 0 && x < pdrv->width && x < pdrv->frame_width && y >= 0 && y < pdrv->height)
#define POINT_ADDRESS(x, y) ((ADDR8)(pdrv->frame_addr) + ((y * pdrv->frame_width + x) >> 3))

static const unsigned char bitmask[8] = { 0x7f, 0xbf, 0xdf, 0xef, 0xf7, 0xfb, 0xfd, 0xfe };

static byte_t _find_table_index(mono_driver_t* pdrv, PIXELVAL c)
{
	int ind;

	for (ind = 0; ind < 2; ind++)
	{
		if (c == pdrv->table[ind])
			return (byte_t)ind;
	}

	return 1;
}

static dword_t need_size(int width, int height)
{
	int line_bytes = BMP_POINTS_BYTES(width, 1);
	
	return (line_bytes * height);
}

static driver_t open_driver(int width, int height)
{
	mono_driver_t* pdrv;
	bitmap_quad_t quad[2];

	pdrv = (mono_driver_t*)xmem_alloc(sizeof(mono_driver_t));
	pdrv->head.tag = _DRIVER_MONOCHROME;

	pdrv->width = width;
	pdrv->height = height;
	pdrv->line_bytes = BMP_POINTS_BYTES(pdrv->width, 1);

	xbmp_fill_quad(1, 2, (unsigned char*)(quad), 2 * sizeof(bitmap_quad_t));
	pdrv->table[0] = PUT_PIXVAL(0, quad[0].red, quad[0].green, quad[0].blue);
	pdrv->table[1] = PUT_PIXVAL(0, quad[1].red, quad[1].green, quad[1].blue);

	return &(pdrv->head);
}

static void close_driver(driver_t drv)
{
	mono_driver_t* pdrv = (mono_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_MONOCHROME);

	xmem_free(pdrv);
}

static void attach_buffer(driver_t drv, byte_t* addr, dword_t stride)
{
	mono_driver_t* pdrv = (mono_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_MONOCHROME);

	pdrv->frame_width = BMP_BYTES_POINTS(stride, 1);
	pdrv->frame_stride = stride;
	pdrv->frame_addr = (byte_t*)addr;
}

static int get_width(driver_t drv)
{
	mono_driver_t* pdrv = (mono_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_MONOCHROME);

	return  pdrv->width;
}

static int get_height(driver_t drv)
{
	mono_driver_t* pdrv = (mono_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_MONOCHROME);

	return  pdrv->height;
}

static bool_t valid_coordinate(driver_t drv, int x, int y)
{
	mono_driver_t* pdrv = (mono_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_MONOCHROME);

	return  (x >= 0 && x < pdrv->width && x < pdrv->frame_width && y >= 0 && y < pdrv->height) ? 1 : 0;
}

static dword_t get_bytes(driver_t drv)
{
	mono_driver_t* pdrv = (mono_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_MONOCHROME);

	return (pdrv->line_bytes * pdrv->height);
}

static dword_t copy_bytes(driver_t drv, byte_t* buf, dword_t max)
{
	mono_driver_t* pdrv = (mono_driver_t*)drv;
	dword_t total = 0;
	int y;

	XDK_ASSERT(drv && drv->tag == _DRIVER_MONOCHROME);

	for (y = 0; y < pdrv->height && total < max; y++)
	{
		if(buf)
		{
			xmem_copy((void *)(buf + y * pdrv->line_bytes), (void *)(pdrv->frame_addr + y * pdrv->frame_stride), pdrv->line_bytes);
		}
		total += pdrv->line_bytes;
	}

	return total;
}

static PIXELVAL get_pixel(driver_t drv, int x, int y)
{
	mono_driver_t* pdrv = (mono_driver_t*)drv;

	register ADDR8 addr;
	int pos;
	byte_t ind;

	XDK_ASSERT(drv && drv->tag == _DRIVER_MONOCHROME);

	y = (pdrv->height - 1 - y);

	if (VALID_COORDINATE(x, y))
	{
		addr = POINT_ADDRESS(x, y);
		pos = (x & 7);
		ind = ((*addr >> (7 - pos))) & 0x01;

		return pdrv->table[ind];
	}
	else
	{
		return 0;
	}
}

static PIXELVAL put_pixel(driver_t drv, int x, int y, PIXELVAL v, int rop)
{
	mono_driver_t* pdrv = (mono_driver_t*)drv;

	register ADDR8 addr;
	int pos;
	byte_t ind;
	PIXELVAL c = 0;

	XDK_ASSERT(drv && drv->tag == _DRIVER_MONOCHROME);

	y = (pdrv->height - 1 - y);

	if (VALID_COORDINATE(x, y))
	{
		addr = POINT_ADDRESS(x, y);

		pos = (x & 7);
		ind = ((*addr >> (7 - pos))) & 0x01;

		c = raster_opera((RASTER_MODE)rop, pdrv->table[ind], v);
		ind = _find_table_index(pdrv, c);
		ind <<= (7 - pos);

		*addr = (*addr & bitmask[pos]) | (ind & 0xFF);
	}

	return c;
}

static int get_pixels(driver_t drv, int x, int y, int w, int h, PIXELVAL* val, int n, int rop)
{
	mono_driver_t* pdrv = (mono_driver_t*)drv;

	register ADDR8 addr;
	register int pos;
	byte_t ind;
	int dx, dy, total = 0;

	XDK_ASSERT(drv && drv->tag == _DRIVER_MONOCHROME);
	XDK_ASSERT(val != NULL);

	dy = (pdrv->height - 1 - y);
	while (dy > (pdrv->height - 1 - y - h))
	{
		if (dy < 0)
		{
			total += (y + h - pdrv->height) * w;
			break;
		}

		dx = x;
		while (dx < x + w)
		{
			if (dx >= pdrv->width)
			{
				total += (x + w - pdrv->width);
				break;
			}
			if (VALID_COORDINATE(dx, dy))
			{
				addr = POINT_ADDRESS(dx, dy);
				if (total < n)
				{
					pos = (dx & 7);
					ind = ((*addr >> (7 - pos))) & 0x01;
					val[total] = raster_opera((RASTER_MODE)rop, val[total], pdrv->table[ind]);
				}
			}
			total++;
			dx++;
		}
		dy--;
	}

	return total;
}

static void set_pixels(driver_t drv, int x, int y, int w, int h, const PIXELVAL* val, int n, int rop)
{
	mono_driver_t* pdrv = (mono_driver_t*)drv;

	register ADDR8 addr;
	register int pos;
	byte_t ind;
	int dx, dy, total = 0;
	PIXELVAL a;
	
	XDK_ASSERT(drv && drv->tag == _DRIVER_MONOCHROME);
	XDK_ASSERT(val != NULL);

	dy = (pdrv->height - 1 - y);
	while (dy > (pdrv->height - 1 - y - h))
	{
		if (dy < 0)
		{
			total += (y + h - pdrv->height) * w;
			break;
		}

		dx = x;
		while (dx < x + w)
		{
			if (dx >= pdrv->width)
			{
				total += (x + w - pdrv->width);
				break;
			}
			if (VALID_COORDINATE(dx, dy))
			{
				addr = POINT_ADDRESS(dx, dy);

				pos = (dx & 7);
				ind = ((*addr >> (7 - pos))) & 0x01;

				a = raster_opera((RASTER_MODE)rop, pdrv->table[ind], ((total < n) ? val[total] : val[n - 1]));
				ind = _find_table_index(pdrv, a);
				ind <<= (7 - pos);

				*addr = (*addr & bitmask[pos]) | (ind & 0xFF);
			}
			total++;
			dx++;
		}
		dy--;
	}
}

/*****************************************************************************************************************/

mem_driver_interface monochrome_driver = {
	MGC_DRIVER_MONOCHROME, /*the driver name*/

	1,		/* planes */
	1,		/* pixel depth 1,2,4,8, 16, 18, 24, 32 */
	(2 << 1),		/* summary colors */
	PIXEL_DEPTH_PALETTE1,	/* format of pixel value */

	need_size,
	open_driver,
	close_driver,
	attach_buffer,
	get_height,
	get_width,
	get_bytes,
	copy_bytes,
	valid_coordinate,
	get_pixel,
	put_pixel,
	get_pixels,
	set_pixels
};


