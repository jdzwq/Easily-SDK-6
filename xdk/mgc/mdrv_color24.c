/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc memory driver for Gray image document

	@module	mdev_bitmap.c | implement file

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

#include "../xdkimp.h"
#include "../xdkstd.h"
#include "../xdkinit.h"
#include "../xdkoem.h"

typedef struct _color24_driver_t{
	handle_head head;

	int	width;		/* X real reslution */
	int	height;		/* Y real reslution */

	dword_t	size;		/* bytes of frame buffer */
	byte_t* addr;		/* address of frame buffer */

	int	line_bytes;	/* line length in bytes */
}color24_driver_t;

#define VALID_COORDINATE(x, y) (x >= 0 && x < pdrv->width && y >= 0 && y < pdrv->height)

static driver_t open_driver(int width, int height)
{
	color24_driver_t* pdrv;

	pdrv = (color24_driver_t*)xmem_alloc(sizeof(color24_driver_t));
	pdrv->head.tag = _DRIVER_COLOR888;

	pdrv->width = width;
	pdrv->height = height;
	pdrv->line_bytes = BMP_LINE_BYTES(pdrv->width, 24);

	pdrv->size = pdrv->line_bytes * height;
	pdrv->addr = (byte_t*)xmem_alloc(pdrv->size);

	return &(pdrv->head);
}

static void close_driver(driver_t drv)
{
	color24_driver_t* pdrv = (color24_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR888);

	xmem_free(pdrv->addr);
	xmem_free(pdrv);
}

static int get_points_perline(driver_t drv)
{
	color24_driver_t* pdrv = (color24_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR888);

	return  pdrv->line_bytes;
}

static int get_width(driver_t drv)
{
	color24_driver_t* pdrv = (color24_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR888);

	return  pdrv->width;
}

static int get_height(driver_t drv)
{
	color24_driver_t* pdrv = (color24_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR888);

	return  pdrv->height;
}

static bool_t valid_coordinate(driver_t drv, int x, int y)
{
	color24_driver_t* pdrv = (color24_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR888);

	return  (x >= 0 && x < pdrv->width && y >= 0 && y < pdrv->height) ? 1 : 0;
}

static dword_t get_bytes(driver_t drv)
{
	color24_driver_t* pdrv = (color24_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR888);

	return pdrv->size;
}

static dword_t copy_bytes(driver_t drv, byte_t* buf, dword_t max)
{
	color24_driver_t* pdrv = (color24_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR888);

	max = (max < pdrv->size) ? max : pdrv->size;

	if (buf)
	{
		xmem_copy((void*)(buf), (void*)(pdrv->addr), max);
	}

	return max;
}

static PIXELVAL get_pixel(driver_t drv, int x, int y)
{
	color24_driver_t* pdrv = (color24_driver_t*)drv;

	register ADDR8 addr;
	byte_t r, g, b;
	PIXELVAL c = 0;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR888);

	y = (pdrv->height - 1 - y);

	if (VALID_COORDINATE(x, y))
	{
		addr = ((ADDR8)pdrv->addr) + x * 3 + y * pdrv->line_bytes;

		b = addr[0];
		g = addr[1];
		r = addr[2];

		c = PUT_PIXVAL(0, r, g, b);
	}

	return c;
}

static PIXELVAL put_pixel(driver_t drv, int x, int y, PIXELVAL v, int rop)
{
	color24_driver_t* pdrv = (color24_driver_t*)drv;

	register ADDR8 addr;
	byte_t r, g, b;
	PIXELVAL c = 0;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR888);

	y = (pdrv->height - 1 - y);

	if (VALID_COORDINATE(x, y))
	{
		addr = ((ADDR8)pdrv->addr) + x * 3 + y * pdrv->line_bytes;

		b = addr[0];
		g = addr[1];
		r = addr[2];
		c = PUT_PIXVAL(0, r, g, b);

		c = raster_opera(rop, c, v);

		r = GET_PIXVAL_R(c);
		g = GET_PIXVAL_G(c);
		b = GET_PIXVAL_B(c);
		c = PUT_PIXVAL(0, r, g, b);

		addr[0] = b;
		addr[1] = g;
		addr[2] = r;
	}

	return c;
}

static int get_pixels(driver_t drv, int x, int y, int w, int h, PIXELVAL* val, int n, int rop)
{
	color24_driver_t* pdrv = (color24_driver_t*)drv;

	register ADDR8 addr;
	byte_t r, g, b;
	PIXELVAL c;
	int dx, dy, total = 0;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR888);
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
				addr = ((ADDR8)pdrv->addr) + dx * 3 + dy * pdrv->line_bytes;
				if (total < n)
				{
					b = addr[0];
					g = addr[1];
					r = addr[2];

					c = PUT_PIXVAL(0, r, g, b);
					val[total] = raster_opera(rop, val[total], c);
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
	color24_driver_t* pdrv = (color24_driver_t*)drv;

	register ADDR8 addr;
	byte_t r, g, b;
	int dx, dy, total = 0;
	PIXELVAL c;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR888);
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
				addr = ((ADDR8)pdrv->addr) + dx * 3 + dy * pdrv->line_bytes;

				b = addr[0];
				g = addr[1];
				r = addr[2];

				c = raster_opera(rop, PUT_PIXVAL(0, r, g, b), ((total < n) ? val[total] : val[n - 1]));

				r = GET_PIXVAL_R(c);
				g = GET_PIXVAL_G(c);
				b = GET_PIXVAL_B(c);

				addr[0] = b;
				addr[1] = g;
				addr[2] = r;
			}
			total++;
			dx++;
		}
		dy--;
	}
}

/*****************************************************************************************************************/

mem_driver_t color888_driver = {
	MGC_DRIVER_COLOR888, /*the driver name*/

	1,		/* planes */
	24,		/* pixel depth 1,2,4,8, 16, 18, 24, 32 */
	0,		/* summary colors */
	PIXEL_DEPTH_COLOR24,	/* format of pixel value */

	open_driver,
	close_driver,
	get_points_perline,
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


