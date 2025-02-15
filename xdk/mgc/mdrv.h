﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc memory context driver document

	@module	mdrv.h | interface file

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
#ifndef _MEMDRV_H
#define _MEMDRV_H

#include "mdef.h"
#include "mpix.h"

#define MGC_DRIVER_MONOCHROME	_T("Monochrome Driver")
#define MGC_DRIVER_GRAYSCALE	_T("Grayscale Driver")
#define MGC_DRIVER_COLOR555		_T("Color555 Driver")
#define MGC_DRIVER_COLOR888		_T("Color888 Driver")
#define MGC_DRIVER_COLOR8888	_T("Color8888 Driver")

typedef struct _mem_driver_t* mem_driver_ptr;

typedef struct _mem_driver_t{
	tchar_t drv_name[MAX_DEVICE_NAME];

	int	planes;			/* planes must be 1 */
	int	bits_per_pixel;	/* pixel depth 1,2,4,8, 16, 18, 24, 32 */
	int	num_colors;		/* summary colors equal 2^bits_per_pixel */
	int pixel_format;	/* format of pixel pack into bytes */

	driver_t(*openDriver)(int width, int height);
	void(*closeDriver)(driver_t drv);

	int(*getPointsPerline)(driver_t drv);
	int(*getHeight)(driver_t drv);
	int(*getWidth)(driver_t drv);
	dword_t(*getBytes)(driver_t drv);
	dword_t(*copyBytes)(driver_t drv, byte_t* buf, dword_t max);

	bool_t(*validCoordinate)(driver_t drv, int x, int y);
	PIXELVAL(*getPixel)(driver_t drv, int x, int y);
	PIXELVAL(*putPixel)(driver_t drv, int x, int y, PIXELVAL v, int rop);

	int(*getPixels)(driver_t drv, int x, int y, int w, int h, PIXELVAL* val, int n, int rop);
	void(*setPixels)(driver_t drv, int x, int y, int w, int h, const PIXELVAL* val, int n, int rop);
} mem_driver_t;

extern mem_driver_t monochrome_driver;
extern mem_driver_t grayscale_driver;
extern mem_driver_t color555_driver;
extern mem_driver_t color888_driver;
extern mem_driver_t color8888_driver;

LOC_API PIXELVAL raster_opera(RASTER_MODE rop, PIXELVAL dst, PIXELVAL src);

#ifdef	__cplusplus
extern "C" {
#endif


#ifdef	__cplusplus
}
#endif

#endif /*_MDRV_H*/
