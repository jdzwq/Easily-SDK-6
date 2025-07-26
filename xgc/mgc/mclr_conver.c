/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc other utility for image document

	@module	moth_pixel.c | implement file

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

#include "mclr.h"

#include "../gob/clrext.h"

PIXELVAL lighten_pixel(PIXELVAL v, int n)
{
	unsigned char r, g, b;

	r = GET_PIXVAL_R(v);
	g = GET_PIXVAL_G(v);
	b = GET_PIXVAL_R(v);

	lighten_rgb(n, &r, &g, &b);

	return PUT_PIXVAL(0, r, g, b);
}