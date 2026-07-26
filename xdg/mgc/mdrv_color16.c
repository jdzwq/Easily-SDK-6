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

#include "../xdgmgc.h"

typedef struct _color16_driver_t{
	handle_head head;

	int	width;		/* horz reslution */
	int	height;		/* vert reslution */
	dword_t line_bytes; /* bytes per line */

	int frame_width;	/* points of frame per line */
	dword_t	frame_stride;	/* bytes of frame per line */
	byte_t* frame_addr;	/* frame buffer address */
}color16_driver_t;

#define VALID_COORDINATE(x, y) (x >= 0 && x < pdrv->width && x < pdrv->frame_width && y >= 0 && y < pdrv->height)
#define POINT_ADDRESS(x, y) (((ADDR16)((byte_t*)pdrv->frame_addr)) + y * pdrv->frame_width + x)

#define BLUE_MASK		0x001F
#define GREEN_MASK		0x03E0
#define RED_MASK		0x7C00

#define GET_COLOR16_R(c) (byte_t)(((c) & RED_MASK) >> 10)
#define GET_COLOR16_G(c) (byte_t)(((c) & GREEN_MASK) >> 5)
#define GET_COLOR16_B(c) (byte_t)((c) & BLUE_MASK)

#define PUT_COLOR16(r, g, b)	((((sword_t)r << 10) & RED_MASK) | (((sword_t)g << 5) & GREEN_MASK) | ((sword_t)b & BLUE_MASK))

static dword_t need_size(int width, int height)
{
	int line_bytes = BMP_POINTS_BYTES(width, 16);
	
	return (line_bytes * height);
}

static driver_t open_driver(int width, int height)
{
	color16_driver_t* pdrv;

	pdrv = (color16_driver_t*)xmem_alloc(sizeof(color16_driver_t));
	pdrv->head.tag = _DRIVER_COLOR555;

	pdrv->width = width;
	pdrv->height = height;
	pdrv->line_bytes = BMP_POINTS_BYTES(width, 16);

	return &(pdrv->head);
}

static void close_driver(driver_t drv)
{
	color16_driver_t* pdrv = (color16_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR555);

	xmem_free(pdrv);
}

static void attach_buffer(driver_t drv, byte_t* addr, dword_t stride)
{
	color16_driver_t* pdrv = (color16_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR555);

	pdrv->frame_width = BMP_BYTES_POINTS(stride, 16);
	pdrv->frame_stride = stride;
	pdrv->frame_addr = addr;
}

static int get_width(driver_t drv)
{
	color16_driver_t* pdrv = (color16_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR555);

	return  pdrv->width;
}

static int get_height(driver_t drv)
{
	color16_driver_t* pdrv = (color16_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR555);

	return  pdrv->height;
}

static bool_t valid_coordinate(driver_t drv, int x, int y)
{
	color16_driver_t* pdrv = (color16_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR555);

	return  (x >= 0 && x < pdrv->width && x < pdrv->frame_width && y >= 0 && y < pdrv->height) ? 1 : 0;
}

static dword_t get_bytes(driver_t drv)
{
	color16_driver_t* pdrv = (color16_driver_t*)drv;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR555);

	return (pdrv->line_bytes * pdrv->height);
}

static dword_t copy_bytes(driver_t drv, byte_t* buf, dword_t max)
{
	color16_driver_t* pdrv = (color16_driver_t*)drv;
	dword_t total = 0;
	int y;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR555);

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
	color16_driver_t* pdrv = (color16_driver_t*)drv;

	register ADDR16 addr;
	byte_t r, g, b;
	PIXELVAL c = 0;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR555);

	y = (pdrv->height - 1 - y);

	if (VALID_COORDINATE(x, y))
	{
		addr = POINT_ADDRESS(x, y);

		r = GET_COLOR16_R(*addr);
		g = GET_COLOR16_G(*addr);
		b = GET_COLOR16_B(*addr);

		c = PUT_PIXVAL(0, r, g, b);
	}
	
	return c;
}

static PIXELVAL put_pixel(driver_t drv, int x, int y, PIXELVAL v, int rop)
{
	color16_driver_t* pdrv = (color16_driver_t*)drv;

	register ADDR16 addr;
	byte_t r, g, b;
	PIXELVAL c = 0;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR555);

	y = (pdrv->height - 1 - y);

	if (VALID_COORDINATE(x, y))
	{
		addr = POINT_ADDRESS(x, y);

		r = GET_COLOR16_R(*addr);
		g = GET_COLOR16_G(*addr);
		b = GET_COLOR16_B(*addr);
		c = PUT_PIXVAL(0, r, g, b);

		c = raster_opera((RASTER_MODE)rop, c, v);

		r = GET_PIXVAL_R(c);
		g = GET_PIXVAL_G(c);
		b = GET_PIXVAL_B(c);
		c = PUT_PIXVAL(0, r, g, b);

		*addr = PUT_COLOR16(r, g, b);
	}

	return c;
}

static int get_pixels(driver_t drv, int x, int y, int w, int h, PIXELVAL* val, int n, int rop)
{
	color16_driver_t* pdrv = (color16_driver_t*)drv;

	register ADDR16 addr;
	byte_t r, g, b;
	PIXELVAL c;
	int dx, dy, total = 0;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR555);
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
					r = GET_COLOR16_R(*addr);
					g = GET_COLOR16_G(*addr);
					b = GET_COLOR16_B(*addr);

					c = PUT_PIXVAL(0, r, g, b);
					val[total] = raster_opera((RASTER_MODE)rop, val[total], c);
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
	color16_driver_t* pdrv = (color16_driver_t*)drv;

	register ADDR16 addr;
	byte_t r, g, b;
	int dx, dy, total = 0;
	PIXELVAL c;

	XDK_ASSERT(drv && drv->tag == _DRIVER_COLOR555);
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

				r = GET_COLOR16_R(*addr);
				g = GET_COLOR16_G(*addr);
				b = GET_COLOR16_B(*addr);

				c = raster_opera((RASTER_MODE)rop, PUT_PIXVAL(0, r, g, b), ((total < n) ? val[total] : val[n - 1]));

				r = GET_PIXVAL_R(c);
				g = GET_PIXVAL_G(c);
				b = GET_PIXVAL_B(c);

				*addr = PUT_COLOR16(r, g, b);
			}
			total++;
			dx++;
		}
		dy--;
	}
}

/*****************************************************************************************************************/

mem_driver_interface color555_driver = {
	MGC_DRIVER_COLOR555, /*the driver name*/

	1,		/* planes */
	16,		/* pixel depth 1,2,4,8, 16, 18, 24, 32 */
	0,		/* summary colors */
	PIXEL_DEPTH_COLOR16,	/* format of pixel value */

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


