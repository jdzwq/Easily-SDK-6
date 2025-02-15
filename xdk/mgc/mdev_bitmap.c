/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc memory device for bitmap document

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

#include "mdev.h"

#include "../xdkimp.h"
#include "../xdkstd.h"
#include "../xdkinit.h"
#include "../xdkimg.h"
#include "../xdkutil.h"

typedef struct _bitmap_device_t{
	handle_head head;

	mem_driver_ptr driver;
	driver_t handle;

	int dpi;
	int horz_size, vert_size;
	int horz_res, vert_res;
	int logic_sx, logic_sy;
	int physi_sx, physi_sy;

	bitmap_info_head_t bitmap_info;
	
}bitmap_device_t;

#define PTINRECT(x1,y1,x,y,w,h)	(((x1) > (x) && (x1) < (x + w) && (y1) > (y) && (y1) < (y + h))? 1 : 0)

static const mem_driver_ptr select_driver(const tchar_t* devName)
{
	if (xsicmp(devName, MGC_DEVICE_BITMAP_MONOCHROME) == 0)
		return &monochrome_driver;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_GRAYSCALE) == 0)
		return &grayscale_driver;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_TRUECOLOR16) == 0)
		return &color555_driver;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_TRUECOLOR24) == 0)
		return &color888_driver;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_TRUECOLOR32) == 0)
		return &color8888_driver;
	else
	{
		set_last_error(_T("select_driver"), _T("unknown memory device"), -1);
		return NULL;
	}
}

static device_t open_device(const dev_prn_t* devPrint, int dpi)
{
	bitmap_device_t* pdev;

	XDK_ASSERT(devPrint != NULL);

	TRY_CATCH;

	pdev = (bitmap_device_t*)xmem_alloc(sizeof(bitmap_device_t));
	pdev->head.tag = _DEVICE_BITMAP;

	pdev->driver = select_driver(devPrint->devname);
	if (!pdev->driver)
	{
		raise_user_error(_T("open_device"), _T("openDriver"));
	}

	pdev->horz_size = (int)((float)(devPrint->paper_width) / 10);
	pdev->vert_size = (int)((float)(devPrint->paper_height) / 10);

	pdev->horz_res = (int)((float)(pdev->horz_size) * PTPERMM);
	pdev->vert_res = (int)((float)(pdev->vert_size) * PTPERMM);

	pdev->logic_sx = (int)((pdev->horz_res * 10.0 * MMPERINCH) / (float)(devPrint->paper_width));
	pdev->logic_sy = (int)((pdev->vert_res * 10.0 * MMPERINCH) / (float)(devPrint->paper_height));

	pdev->physi_sx = (int)(((float)(devPrint->paper_width) / (10.0 * MMPERINCH)) * dpi);
	pdev->physi_sy = (int)(((float)(devPrint->paper_height) / (10.0 * MMPERINCH)) * dpi);

	pdev->handle = (*(pdev->driver->openDriver))(pdev->horz_res, pdev->vert_res);
	if (!pdev->handle)
	{
		raise_user_error(_T("open_device"), _T("openDriver"));
	}

	pdev->bitmap_info.isize = BMP_INFOHEADER_SIZE;
	pdev->bitmap_info.width = pdev->horz_res;
	pdev->bitmap_info.height = pdev->vert_res;
	pdev->bitmap_info.planes = 1;
	pdev->bitmap_info.clrbits = pdev->driver->bits_per_pixel;
	pdev->bitmap_info.compress = 0;
	pdev->bitmap_info.bytes = BMP_LINE_BYTES(pdev->bitmap_info.width, pdev->bitmap_info.clrbits) * pdev->bitmap_info.height;
	pdev->bitmap_info.xpelsperm = 0;
	pdev->bitmap_info.ypelsperm = 0;
	pdev->bitmap_info.clrused = (pdev->bitmap_info.clrbits <= 8)? (1 << pdev->bitmap_info.clrbits) : 0;
	pdev->bitmap_info.clrimport = 0;

	END_CATCH;

	return &(pdev->head);
ONERROR:
	XDK_TRACE_LAST;

	if (pdev)
	{
		xmem_free(pdev);
	}

	return NULL;
}

static void close_device(device_t dev)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);

	if (pdev->handle)
	{
		(*(pdev->driver->closeDriver))(pdev->handle);
	}

	xmem_free(pdev);
}

static int get_device_width(device_t dev)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);

	return pdev->bitmap_info.width;
}

static int get_device_height(device_t dev)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);

	return pdev->bitmap_info.height;
}

static void get_device_caps(device_t dev, dev_cap_t* pcap)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);

	pcap->horz_res = pdev->horz_res;
	pcap->vert_res = pdev->vert_res;

	pcap->horz_pixels = pdev->logic_sx;
	pcap->vert_pixels = pdev->logic_sy;

	pcap->horz_size = pdev->horz_size;
	pcap->vert_size = pdev->vert_size;

	pcap->horz_feed = 0;
	pcap->vert_feed = 0;
}

static void get_point(device_t dev, const xpoint_t* ppt, xcolor_t* pxc)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	PIXELVAL c;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(ppt != NULL && pxc != NULL);
	XDK_ASSERT(pdev->handle != NULL);

	c = (*(pdev->driver->getPixel))(pdev->handle, ppt->x, ppt->y);

	pxc->a = GET_PIXVAL_A(c);
	pxc->b = GET_PIXVAL_B(c);
	pxc->g = GET_PIXVAL_G(c);
	pxc->r = GET_PIXVAL_R(c);
}

static void set_point(device_t dev, const xpoint_t* ppt, const xcolor_t* pxc, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	PIXELVAL c;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(ppt != NULL && pxc != NULL);
	XDK_ASSERT(pdev->handle != NULL);

	c = PUT_PIXVAL(pxc->a, pxc->r, pxc->g, pxc->b);

	(*(pdev->driver->putPixel))(pdev->handle, ppt->x, ppt->y, c, rop);
}

static void draw_points(device_t dev, const xpoint_t* ppt, int n, const xcolor_t* pxc, int m, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	PIXELVAL c;
	int i, j = 0;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(ppt != NULL && pxc != NULL);
	XDK_ASSERT(pdev->handle != NULL);

	for (i = 0; i < n; i++)
	{
		c = PUT_PIXVAL(pxc[j].a, pxc[j].r, pxc[j].g, pxc[j].b);
		if (j < m - 1) j++;

		(*(pdev->driver->putPixel))(pdev->handle, ppt[i].x, ppt[i].y, c, rop);
	}
}

static void fill_points(device_t dev, int x, int y, int w, int h, const xcolor_t* pxc, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	PIXELVAL c;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pxc != NULL);
	XDK_ASSERT(pdev->handle != NULL);

	c = PUT_PIXVAL(pxc->a, pxc->r, pxc->g, pxc->b);

	(*(pdev->driver->setPixels))(pdev->handle, x, y, w, h, &c, 1, rop);
}

static void get_bitmap_size(device_t dev, dword_t* pTotal, dword_t* pPixel)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pdev->handle != NULL);

	*pPixel = (*(pdev->driver->getWidth))(pdev->handle) *  (*(pdev->driver->getHeight))(pdev->handle);
	*pTotal = BMP_INFOHEADER_SIZE + pdev->bitmap_info.clrused * BMP_RGBQUAD_SIZE + *pPixel;
}

static dword_t get_bitmap(device_t dev, byte_t* buf, dword_t max)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;
	dword_t total = 0;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pdev->handle != NULL);

	total += xbmp_set_info(&pdev->bitmap_info, ((buf) ? (buf + total) : NULL), (max - total));
	total += xbmp_fill_quad(pdev->bitmap_info.clrbits, pdev->bitmap_info.clrused, ((buf) ? (buf + total) : NULL), (max - total));
	total += (*(pdev->driver->copyBytes))(pdev->handle, ((buf) ? (buf + total) : NULL), (max - total));

	return total;
}

static void horz_line(device_t dev, const xpoint_t* ppt, int w, const xcolor_t* pxc, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	PIXELVAL c;
	int x, y, dx;
	bool_t b;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(ppt != NULL && pxc != NULL);
	XDK_ASSERT(pdev->handle != NULL);

	c = PUT_PIXVAL(0, pxc->r, pxc->g, pxc->b);

	x = ppt->x, y = ppt->y;
	if (w < 0)
		dx = -1, w = 0 - w;
	else
		dx = 1;

	b = (pdev->driver->validCoordinate)(pdev->handle, x, y);

	while (b && w--) {
		(pdev->driver->putPixel)(pdev->handle, x, y, c, rop);

		x += dx;
		b = (pdev->driver->validCoordinate)(pdev->handle, x, y);
	}
}

static void vert_line(device_t dev, const xpoint_t* ppt, int h, const xcolor_t* pxc, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	PIXELVAL c;
	int x, y, dy;
	bool_t b;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(ppt != NULL && pxc != NULL);
	XDK_ASSERT(pdev->handle != NULL);

	c = PUT_PIXVAL(0, pxc->r, pxc->g, pxc->b);

	x = ppt->x, y = ppt->y;
	if (h < 0)
		dy = -1, h = 0-h;
	else
		dy = 1;

	b = (pdev->driver->validCoordinate)(pdev->handle, x, y);

	while (b && h--) {
		(pdev->driver->putPixel)(pdev->handle, x, y, c, rop);
	
		y+= dy;
		b = (pdev->driver->validCoordinate)(pdev->handle, x, y);
	}
}

static void vert_linear(device_t dev, const xrect_t* pxr, const xpoint_t* ppt, const xcolor_t* pxc, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	byte_t r0, g0, b0, r1, g1, b1, r2, g2, b2;
	PIXELVAL org, dst, src;
	int i, j, lx, rx, w, h;
	bool_t b;
	double f;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pxr != NULL && ppt != NULL && pxc != NULL);

	i = ppt->x, j = ppt->y;

	b = (pdev->driver->validCoordinate)(pdev->handle, i, j);
	if (!b)
		return;

	f = 2.0 / (float)pxr->h;

	w = (pdev->driver->getWidth)(pdev->handle);
	h = (pdev->driver->getHeight)(pdev->handle);

	r1 = pxc[0].r, g1 = pxc[0].g, b1 = pxc[0].b;
	r2 = pxc[1].r, g2 = pxc[1].g, b2 = pxc[1].b;

	//save (x, y) color first
	org = (pdev->driver->getPixel)(pdev->handle, i, j);

	//fill top half
	r0 = r2, g0 = g2, b0 = b2;
	while (j-- > 0)
	{
		i = ppt->x;
		lx = rx = -1;
		while (i-- > 0)
		{
			if (0 == PTINRECT(i, j, pxr->x, pxr->y, pxr->w, pxr->h))
			{
				lx = i + 1;
				break;
			}
			else
			{
				src = (pdev->driver->getPixel)(pdev->handle, i, j);
				if (src != org)
				{
					lx = i + 1;
					break;
				}
			}
		}

		i = ppt->x;
		while (++i < w)
		{
			if (0 == PTINRECT(i, j, pxr->x, pxr->y, pxr->w, pxr->h))
			{
				rx = i - 1;
				break;
			}
			else
			{
				src = (pdev->driver->getPixel)(pdev->handle, i, j);
				if (src != org)
				{
					rx = i - 1;
					break;
				}
			}
		}

		if (lx < 0 || rx >= w || lx == rx)
			break;

		r0 = r2 + (unsigned char)((float)(ppt->y - j) * f * (float)(r1 - r2));
		g0 = g2 + (unsigned char)((float)(ppt->y - j) * f * (float)(g1 - g2));
		b0 = b2 + (unsigned char)((float)(ppt->y - j) * f * (float)(b1 - b2));

		for (lx; lx <= rx; lx++)
		{
			dst = PUT_PIXVAL(0, r0, g0, b0);

			(pdev->driver->putPixel)(pdev->handle, lx, j, dst, rop);
		}
	}

	j = ppt->y - 1;
	//fill bottom half
	r0 = r2, g0 = g2, b0 = b2;
	while (++j < h)
	{
		i = ppt->x;
		lx = rx = -1;
		while (i-- > 0)
		{
			if (0 == PTINRECT(i, j, pxr->x, pxr->y, pxr->w, pxr->h))
			{
				lx = i + 1;
				break;
			}
			else
			{
				src = (pdev->driver->getPixel)(pdev->handle, i, j);
				if (src != org)
				{
					lx = i + 1;
					break;
				}
			}
		}

		i = ppt->x;
		while (++i < w)
		{
			if (0 == PTINRECT(i, j, pxr->x, pxr->y, pxr->w, pxr->h))
			{
				rx = i - 1;
				break;
			}
			else
			{
				src = (pdev->driver->getPixel)(pdev->handle, i, j);
				if (src != org)
				{
					rx = i - 1;
					break;
				}
			}
		}

		if (lx < 0 || rx >= w || lx == rx)
			break;

		for (lx; lx <= rx; lx++)
		{
			dst = PUT_PIXVAL(0, r0, g0, b0);

			(pdev->driver->putPixel)(pdev->handle, lx, j, dst, rop);
		}

		r0 = r2 + (unsigned char)((float)(j - ppt->y + 1) * f * (float)(r1 - r2));
		g0 = g2 + (unsigned char)((float)(j - ppt->y + 1) * f * (float)(g1 - g2));
		b0 = b2 + (unsigned char)((float)(j - ppt->y + 1) * f * (float)(b1 - b2));
	}
}

static void horz_linear(device_t dev, const xrect_t* pxr, const xpoint_t* ppt, const xcolor_t* pxc, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	byte_t r0, g0, b0, r1, g1, b1, r2, g2, b2;
	PIXELVAL org, dst, src;
	int i, j, ty, by, w, h;
	bool_t b;
	double f;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pxr != NULL && ppt != NULL && pxc != NULL);

	i = ppt->x, j = ppt->y;
	b = (pdev->driver->validCoordinate)(pdev->handle, i, j);
	if (!b)
		return;

	f = 2.0 / (float)pxr->w;

	w = (pdev->driver->getWidth)(pdev->handle);
	h = (pdev->driver->getHeight)(pdev->handle);

	r1 = pxc[0].r, g1 = pxc[0].g, b1 = pxc[0].b;
	r2 = pxc[1].r, g2 = pxc[1].g, b2 = pxc[1].b;

	//save (x, y) color first
	org = (pdev->driver->getPixel)(pdev->handle, i, j);

	//fill left half
	r0 = r2, g0 = g2, b0 = b2;
	while (i-- > 0)
	{
		j = ppt->y;
		ty = by = -1;
		while (j-- > 0)
		{
			if (0 == PTINRECT(i, j, pxr->x, pxr->y, pxr->w, pxr->h))
			{
				ty = j + 1;
				break;
			}
			else
			{
				src = (pdev->driver->getPixel)(pdev->handle, i, j);
				if (src != org)
				{
					ty = j + 1;
					break;
				}
			}
		}

		j = ppt->y;
		while (++j < h)
		{
			if (0 == PTINRECT(i, j, pxr->x, pxr->y, pxr->w, pxr->h))
			{
				by = j - 1;
				break;
			}
			else
			{
				src = (pdev->driver->getPixel)(pdev->handle, i, j);
				if (src != org)
				{
					by = j - 1;
					break;
				}
			}
		}

		if (ty < 0 || by >= h || ty == by)
			break;

		r0 = r2 + (unsigned char)((ppt->x - i) * f * (r1 - r2));
		g0 = g2 + (unsigned char)((ppt->x - i) * f * (g1 - g2));
		b0 = b2 + (unsigned char)((ppt->x - i) * f * (b1 - b2));

		for (; ty <= by; ty++)
		{
			dst = PUT_PIXVAL(0, r0, g0, b0);

			(pdev->driver->putPixel)(pdev->handle, i, ty, dst, rop);
		}
	}

	i = ppt->x - 1;
	//fill right half
	r0 = r2, g0 = g2, b0 = b2;
	while (++i < w)
	{
		j = ppt->y;
		ty = by = -1;
		while (j-- > 0)
		{
			if (0 == PTINRECT(i, j, pxr->x, pxr->y, pxr->w, pxr->h))
			{
				ty = j + 1;
				break;
			}
			else
			{
				src = (pdev->driver->getPixel)(pdev->handle, i, j);
				if (src != org)
				{
					ty = j + 1;
					break;
				}
			}
		}

		j = ppt->y;
		while (++j < h)
		{
			if (0 == PTINRECT(i, j, pxr->x, pxr->y, pxr->w, pxr->h))
			{
				by = j - 1;
				break;
			}
			else
			{
				src = (pdev->driver->getPixel)(pdev->handle, i, j);
				if (src != org)
				{
					by = j - 1;
					break;
				}
			}
		}

		if (ty < 0 || by >= h || ty == by)
			break;

		for (; ty <= by; ty++)
		{
			dst = PUT_PIXVAL(0, r0, g0, b0);

			(pdev->driver->putPixel)(pdev->handle, i, ty, dst, rop);
		}

		r0 = r2 + (unsigned char)((i - ppt->x + 1) * f * (r1 - r2));
		g0 = g2 + (unsigned char)((i - ppt->x + 1) * f * (g1 - g2));
		b0 = b2 + (unsigned char)((i - ppt->x + 1) * f * (b1 - b2));
	}
}

static void mask_rect(device_t dev, const xrect_t* pxr, const xcolor_t* pxc, int opacity)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	PIXELVAL src, dst;
	BYTE r, g, b;
	int x, y;
	float f;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pxr != NULL && pxc != NULL);
	XDK_ASSERT(pdev->handle != NULL);

	f = (float)opacity / 255;

	for (x = pxr->x; x <= pxr->x + pxr->w; x++)
	{
		for (y = pxr->y; y <= pxr->y + pxr->h; y++)
		{
			if ((pdev->driver->validCoordinate)(pdev->handle, x, y))
			{
				src = (pdev->driver->getPixel)(pdev->handle, x, y);

				r = (BYTE)((float)GET_PIXVAL_R(src) * (1.0-f) + (float)pxc->r * f);
				g = (BYTE)((float)GET_PIXVAL_G(src) * (1.0-f) + (float)pxc->g * f);
				b = (BYTE)((float)GET_PIXVAL_B(src) * (1.0-f) + (float)pxc->b * f);

				dst = PUT_PIXVAL(0, r, g, b);
				(pdev->driver->putPixel)(pdev->handle, x, y, dst, ROP_COPY);
			}
		}
	}
}

typedef struct __link_posion{
	link_t lk;
	int i, j;
}_link_posion;

static int negh_off[4][2] = { { -1, 0 }, { 0, 1 }, { 1, 0 }, { 0, -1 } };

static void flood_fill(device_t dev, const xrect_t* pxr, const xpoint_t* ppt, const xcolor_t* pxc, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	int i, j, n, dx, dy;
	PIXELVAL c, v0, v1;
	bool_t b;
	link_t lk_root;
	_link_posion* ptr_pos;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pxr!= NULL && ppt != NULL && pxc != NULL);

	i = ppt->x, j = ppt->y;
	b = (pdev->driver->validCoordinate)(pdev->handle, i, j);
	if (!b)
		return;

	c = PUT_PIXVAL(pxc->a, pxc->r, pxc->g, pxc->b);

	init_root_link(&lk_root);

	ptr_pos = (_link_posion*)xmem_alloc(sizeof(_link_posion));
	ptr_pos->i = i, ptr_pos->j = j;
	push_link(&lk_root, (link_t_ptr)ptr_pos);

	//save (x, y) color first
	v0 = (pdev->driver->getPixel)(pdev->handle, i, j);
	
	while (!is_empty_link(&lk_root))
	{
		ptr_pos = (_link_posion*)pop_link(&lk_root);
		i = ptr_pos->i; j = ptr_pos->j;
		xmem_free(ptr_pos);

		(pdev->driver->putPixel)(pdev->handle, i, j, c, rop);

		//test for neghouring
		for (n = 0; n < 4; n++)
		{
			dx = i + negh_off[n][0];
			dy = j + negh_off[n][1];

			if (pxr)
				b = PTINRECT(dx, dy, pxr->x, pxr->y, pxr->w, pxr->h);
			else
				b = 1;

			if (b)
			{
				b = (pdev->driver->validCoordinate)(pdev->handle, dx, dy);
			}

			if (b)
			{
				v1 = (pdev->driver->getPixel)(pdev->handle, dx, dy);

				if (v1 == v0)
				{
					ptr_pos = (_link_posion*)xmem_alloc(sizeof(_link_posion));
					ptr_pos->i = dx, ptr_pos->j = dy;
					push_link(&lk_root, (link_t_ptr)ptr_pos);
				}
			}
		}// end for
	}// end while
}

static void radial_linear(device_t dev, const xrect_t* pxr, const xpoint_t* ppt, const xcolor_t* pxc, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	int i, j, n, dx, dy;
	byte_t r0, g0, b0, r1, g1, b1, r2, g2, b2;
	PIXELVAL c, v0, v1;
	float f, df;
	bool_t b;
	link_t lk_root;
	_link_posion* ptr_pos;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pxr != NULL && ppt != NULL && pxc != NULL);

	i = ppt->x, j = ppt->y;
	b = (pdev->driver->validCoordinate)(pdev->handle, i, j);
	if (!b)
		return;

	df = 2.0 / (float)sqrt(pxr->w * pxr->w + pxr->h * pxr->h);

	r1 = pxc[0].r, g1 = pxc[0].g, b1 = pxc[0].b;
	r2 = pxc[1].r, g2 = pxc[1].g, b2 = pxc[1].b;

	//save (x, y) color first
	v0 = (pdev->driver->getPixel)(pdev->handle, i, j);

	init_root_link(&lk_root);

	ptr_pos = (_link_posion*)xmem_alloc(sizeof(_link_posion));
	ptr_pos->i = i, ptr_pos->j = j;
	push_link(&lk_root, (link_t_ptr)ptr_pos);

	//save (x, y) color first
	v0 = (pdev->driver->getPixel)(pdev->handle, i, j);

	while (!is_empty_link(&lk_root))
	{
		ptr_pos = (_link_posion*)pop_link(&lk_root);
		i = ptr_pos->i; j = ptr_pos->j;
		xmem_free(ptr_pos);

		f = (float)sqrt((i - ppt->x) * (i - ppt->x) + (j - ppt->y) * (j - ppt->y)) * df;
		r0 = r2 + (unsigned char)(f * (r1 - r2));
		g0 = g2 + (unsigned char)(f * (g1 - g2));
		b0 = b2 + (unsigned char)(f * (b1 - b2));

		c = PUT_PIXVAL(0, r0, g0, b0);

		(pdev->driver->putPixel)(pdev->handle, i, j, c, rop);

		//test for neghouring
		for (n = 0; n < 4; n++)
		{
			dx = i + negh_off[n][0];
			dy = j + negh_off[n][1];

			if (pxr)
				b = PTINRECT(dx, dy, pxr->x, pxr->y, pxr->w, pxr->h);
			else
				b = 1;

			if (b)
			{
				b = (pdev->driver->validCoordinate)(pdev->handle, dx, dy);
			}

			if (b)
			{
				v1 = (pdev->driver->getPixel)(pdev->handle, dx, dy);

				if (v1 == v0)
				{
					ptr_pos = (_link_posion*)xmem_alloc(sizeof(_link_posion));
					ptr_pos->i = dx, ptr_pos->j = dy;
					push_link(&lk_root, (link_t_ptr)ptr_pos);
				}
			}
		}// end for
	}// end while
}

/* takes a pixmap, each line is byte aligned, and copies it
* to the screen using fg_color and bg_color to replace a 1
* and 0 in the pixmap.
*
* The bitmap is ordered how you'd expect, with the MSB used
* for the leftmost of the 8 pixels controlled by each byte.
*
* Variables used in the gc:
*       dstx, dsty, dsth, dstw   Destination rectangle
*       srcx, srcy               Source rectangle
*       src_linelen              Linesize in bytes of source
*       data					 Pixmap data
*       fg_color                 Color of a '1' bit
*       bg_color                 Color of a '0' bit
*       usebg					If set, bg_color is used.  If zero,
*                                then '0' bits are transparentz.
*/
static void draw_pixmap(device_t dev, int dstx, int dsty, int w, int h, mem_pixmap_ptr pxm, int srcx, int srcy, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	ADDR8	src, s;
	int		i, dx, dy, sx, sp;
	int		slinelen;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pxm != NULL);
	XDK_ASSERT(pdev->handle != NULL);

	slinelen = (pxm->width + 7) / 8;
	src = ((ADDR8)pxm->data) + (srcx >> 3) + srcy * slinelen;
	dy = dsty;

	while (h-- > 0) {
		s = src;
		dx = dstx;
		sx = srcx;

		for (i = 0; i < w; ++i) {
			if (!(pdev->driver->validCoordinate)(pdev->handle, dx, dy))
				break;
			
			sp = sx & 7;
			if ((*s >> (7 - sp)) & 01)
			{
				(pdev->driver->putPixel)(pdev->handle, dx, dy, pxm->fg_color, rop);
			}
			else if (pxm->bg_used)
			{
				(pdev->driver->putPixel)(pdev->handle, dx, dy, pxm->bg_color, rop);
			}

			++dx;
			if ((++sx & 7) == 0)
				++s;
		}

		src += slinelen;
		++dy;
	}
}

static void stretch_pixmap(device_t dev, int dstx, int dsty, int dstw, int dsth, mem_pixmap_ptr pxm, int srcx, int srcy, int srcw, int srch, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pxm != NULL);
	XDK_ASSERT(pdev->handle != NULL);

	int		i, j, dx, dy, sx, sy;
	int		bit, bit1, bit2, bit3, bit4;
	float bw, bh;

	bw = (float)srcw / (float)dstw;
	bh = (float)srch / (float)dsth;

	dy = dsty;

	for (j = dsth - 1; j >= 0; j--){
		dx = dstx;

		for (i = 0; i < dstw; i++) {
			if (!(pdev->driver->validCoordinate)(pdev->handle, dx, dy))
				break;

			sx = srcx + ROUNDINT((float)(dx - dstx) * bw);
			sy = srcy + ROUNDINT((float)(dy - dsty) * bh);

			bit1 = pxm->getPixbit(pxm, sx, sy);
			if (sx == pxm->width - 1)
				bit2 = bit1;
			else
				bit2 = pxm->getPixbit(pxm, sx + 1, sy);
			if (sy == pxm->height - 1)
				bit3 = bit1;
			else
				bit3 = pxm->getPixbit(pxm, sx, sy + 1);
			if (sx == pxm->width - 1)
				bit4 = bit3;
			else if (sy == pxm->height - 1)
				bit4 = bit2;
			else
				bit4 = pxm->getPixbit(pxm, sx + 1, sy + 1);

			//Double Linear Interpolate: f(x,y) = f(0,0)(1-x)(1-y) + f(1,0)x(1-y) + f(0,1)(1-x)y + f(1,1)xy
			bit = bit1 * (1 - (dx - sx)) * (1 - (dy - sy)) + bit2 * (dx - sx) * (1 - (dy - sy)) + bit3 * (1 - (dx - sx)) * (dy - sy) + bit4 * (dx - sx) * (dy - sy);
			if (bit) bit = 1;

			if (bit & 0x01)
			{
				(pdev->driver->putPixel)(pdev->handle, dx, dy, pxm->fg_color, rop);
			}
			else if (pxm->bg_used)
			{
				(pdev->driver->putPixel)(pdev->handle, dx, dy, pxm->bg_color, rop);
			}

			dx++;
		}

		dy++;
	}
}

static void draw_bitmap(device_t dev, int dstx, int dsty, int dstw, int dsth, const byte_t* pbm, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	int	row, col;
	int dx, dy;
	PIXELVAL c;
	xsize_t xs;
	xcolor_t* pxc;

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pbm != NULL);
	XDK_ASSERT(pdev->handle != NULL);

	xbmp_get_size(pbm, 0, &xs);

	dstw += dstx;
	dsth += dsty;

	pxc = (xcolor_t*)xmem_alloc(xs.w * sizeof(xcolor_t));

	dy = dsty;
	for (row = 0; (row < xs.h && dy < dsth); row++)
	{
		xbmp_get_rgbs(pbm, 0, row, pxc, xs.w);

		dx = dstx;
		for (col = 0; (col < xs.w && dx < dstw); col++)
		{
			c = PUT_PIXVAL(pxc->a, pxc[col].r, pxc[col].g, pxc[col].b);

			(pdev->driver->putPixel)(pdev->handle, dx, dy, c, rop);
			dx++;
		}
		dy++;
	}

	xmem_free(pxc);
}

static void stretch_bitmap(device_t dev, int dstx, int dsty, int dstw, int dsth, const byte_t* pbm, int rop)
{
	bitmap_device_t* pdev = (bitmap_device_t*)dev;

	int	row, col, sr, sc, x, y;
	float fx, fy, dx, dy;
	PIXELVAL c;
	xsize_t xs;
	xcolor_t xc[2][2];

	XDK_ASSERT(dev && dev->tag == _DEVICE_BITMAP);
	XDK_ASSERT(pbm != NULL);
	XDK_ASSERT(pdev->handle != NULL);

	xbmp_get_size(pbm, 0, &xs);

	fx = (float)xs.w / (float)dstw;
	fy = (float)xs.h / (float)dsth;

	for (x = dstx; x <= dstx + dstw; x++)
	{
		dx = (float)((float)(x - dstx) * fx);
		col = (int)dx;
		dx -= col;

		for (y = dsty; y <= dsty + dsth; y++)
		{
			dy = (float)((float)(y - dsty) * fy);
			row = (int)dy;
			dy -= row;

			sr = (row < 0) ? 0 : row;
			sr = (row < xs.h) ? row : xs.h;
			sc = (col < 0) ? 0 : col;
			sc = (col < xs.w) ? col : xs.w;
			xbmp_get_rgb(pbm, 0, sr, sc, &xc[0][0]);

			sr = (row < 0) ? 0 : row;
			sr = (row < xs.h) ? row : xs.h;
			sc = (col+1 < 0) ? 0 : col+1;
			sc = (col+1 < xs.w) ? col+1 : xs.w;
			xbmp_get_rgb(pbm, 0, sr, sc, &xc[0][1]);

			sr = (row+1 < 0) ? 0 : row+1;
			sr = (row+1 < xs.h) ? row+1 : xs.h;
			sc = (col < 0) ? 0 : col;
			sc = (col < xs.w) ? col : xs.w;
			xbmp_get_rgb(pbm, 0, sr, sc, &xc[1][0]);

			sr = (row+1 < 0) ? 0 : row+1;
			sr = (row+1 < xs.h) ? row+1 : xs.h;
			sc = (col+1 < 0) ? 0 : col+1;
			sc = (col+1 < xs.w) ? col+1 : xs.w;
			xbmp_get_rgb(pbm, 0, sr, sc, &xc[1][1]);

			xc[0][1].r = (byte_t)((float)xc[0][0].r * dx + (float)xc[0][1].r * (1.0 - dx));
			xc[0][1].g = (byte_t)((float)xc[0][0].g * dx + (float)xc[0][1].g * (1.0 - dx));
			xc[0][1].b = (byte_t)((float)xc[0][0].b * dx + (float)xc[0][1].b * (1.0 - dx));

			xc[1][1].r = (byte_t)((float)xc[1][0].r * dx + (float)xc[1][1].r * (1.0 - dx));
			xc[1][1].g = (byte_t)((float)xc[1][0].g * dx + (float)xc[1][1].g * (1.0 - dx));
			xc[1][1].b = (byte_t)((float)xc[1][0].b * dx + (float)xc[1][1].b * (1.0 - dx));

			xc[1][1].r = (byte_t)((float)xc[0][1].r * dy + (float)xc[1][1].r * (1.0 - dy));
			xc[1][1].g = (byte_t)((float)xc[0][1].g * dy + (float)xc[1][1].g * (1.0 - dy));
			xc[1][1].b = (byte_t)((float)xc[0][1].b * dy + (float)xc[1][1].b * (1.0 - dy));

			c = PUT_PIXVAL(0, xc[1][1].r, xc[1][1].g, xc[1][1].b);

			(pdev->driver->putPixel)(pdev->handle, x, y, c, rop);
		}
	}
}
/**************************************************************************************************/

mem_device_t monochrome_bitmap_device = {
	MGC_DEVICE_BITMAP_MONOCHROME,

	&monochrome_driver,
	PIXEL_DEPTH_PALETTE1,

	open_device,
	close_device,
	get_device_width,
	get_device_height,
	get_device_caps,

	get_point,
	set_point,
	draw_points,
	fill_points,
	draw_pixmap,
	stretch_pixmap,
	get_bitmap_size,
	get_bitmap,
	horz_line,
	vert_line,
	mask_rect,
	flood_fill,
	horz_linear,
	vert_linear,
	radial_linear,
	draw_bitmap,
	stretch_bitmap
};

mem_device_t grayscale_bitmap_device = {
	MGC_DEVICE_BITMAP_GRAYSCALE,

	&grayscale_driver,
	PIXEL_DEPTH_PALETTE8,

	open_device,
	close_device,
	get_device_width,
	get_device_height,
	get_device_caps,

	get_point,
	set_point,
	draw_points,
	fill_points,
	draw_pixmap,
	stretch_pixmap,
	get_bitmap_size,
	get_bitmap,
	horz_line,
	vert_line,
	mask_rect,
	flood_fill,
	horz_linear,
	vert_linear,
	radial_linear,
	draw_bitmap,
	stretch_bitmap
};

mem_device_t truecolor16_bitmap_device = {
	MGC_DEVICE_BITMAP_TRUECOLOR16,

	&color555_driver,
	PIXEL_DEPTH_COLOR16,

	open_device,
	close_device,
	get_device_width,
	get_device_height,
	get_device_caps,

	get_point,
	set_point,
	draw_points,
	fill_points,
	draw_pixmap,
	stretch_pixmap,
	get_bitmap_size,
	get_bitmap,
	horz_line,
	vert_line,
	mask_rect,
	flood_fill,
	horz_linear,
	vert_linear,
	radial_linear,
	draw_bitmap,
	stretch_bitmap
};

mem_device_t truecolor24_bitmap_device = {
	MGC_DEVICE_BITMAP_TRUECOLOR24,

	&color888_driver,
	PIXEL_DEPTH_COLOR24,

	open_device,
	close_device,
	get_device_width,
	get_device_height,
	get_device_caps,

	get_point,
	set_point,
	draw_points,
	fill_points,
	draw_pixmap,
	stretch_pixmap,
	get_bitmap_size,
	get_bitmap,
	horz_line,
	vert_line,
	mask_rect,
	flood_fill,
	horz_linear,
	vert_linear,
	radial_linear,
	draw_bitmap,
	stretch_bitmap
};

mem_device_t truecolor32_bitmap_device = {
	MGC_DEVICE_BITMAP_TRUECOLOR32,

	&color8888_driver,
	PIXEL_DEPTH_COLOR32,

	open_device,
	close_device,
	get_device_width,
	get_device_height,
	get_device_caps,

	get_point,
	set_point,
	draw_points,
	fill_points,
	draw_pixmap,
	stretch_pixmap,
	get_bitmap_size,
	get_bitmap,
	horz_line,
	vert_line,
	mask_rect,
	flood_fill,
	horz_linear,
	vert_linear,
	radial_linear,
	draw_bitmap,
	stretch_bitmap
};