/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc dot ellipse document

	@module	dot_ellipse.c | implement file

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

#include "dot.h"

#include "../xdkimp.h"
#include "../xdkstd.h"
#include "../xdkinit.h"

#include "../g2/g2.h"

/**********************************************************************
* Bresenham Alogorithm (x0, y0) line to (x1, y1)
* dx = |x1 - x0|, dy = |y1 - y0|
* when dy/dx < 1 then:
* p = dx - 2 * dy, y = y1
* for x = x1 to x2 do
*    plot(x, y)
*    if(p>0)
*	    p += - dy
*    else
*      p += dx - dy, y++
*    end if
* end for
* when dy/dx > 1 then:
* p = dy - 2 * dx, x = x1
* for y = y1 to y2 do
*    plot(x, y)
*    if(p>0)
*	    p += - dx
*    else
*      p += dy - dx, x++
*    end if
* end for
***********************************************************************/

static int _dot_neghbour(int width, xpoint_t pt_center, xpoint_t* ppt_buffer, int size_buffer)
{
	int x, y, n = 0;
	int dx, dy, p = 0;
	int outer_width, inner_width, center_index;

	//the ellipse center is world coordinate origin ,so the line's slope is from source point to origin.
	dx = pt_center.x;
	dy = pt_center.y;
	p = (dy < dx) ? (dx - 2 * dy) : (dy - 2 * dx);

	if (width % 2)
		center_index = width / 2, outer_width = inner_width = width / 2;
	else
		center_index = width / 2 - 1, outer_width = width / 2 - 1, inner_width = width / 2;

	x = pt_center.x;
	y = pt_center.y;

	if (ppt_buffer)
	{
		ppt_buffer[center_index].x = x;
		ppt_buffer[center_index].y = y;
	}

	for (n = 0; n < outer_width; n++)
	{
		if (dy < dx)
		{
			x++; //moveto (x+1,...)

			if (p > 0)
				p += -dy; //moveto (...,y)
			else
				p += dx - dy, y += 1; //moveto(...,y+1)
		}
		else
		{
			y++; //moveto (...,y+1)

			if (p > 0)
				p += -dx; //moveto (x,...)
			else
				p += dy - dx, x += 1; //moveto(x+1,...)
		}

		if (ppt_buffer)
		{
			ppt_buffer[center_index - n - 1].x = x;
			ppt_buffer[center_index - n - 1].y = y;
		}
	}

	x = pt_center.x;
	y = pt_center.y;

	for (n = 0; n < inner_width; n++)
	{
		if (dy < dx)
		{
			x--; //moveto (x-1,...)

			if (p > 0)
				p += -dy; //moveto (...,y)
			else
				p += dx - dy, y -= 1; //moveto(...,y-1)
		}
		else
		{
			y--; //moveto (...,y-1)

			if (p > 0)
				p += -dx; //moveto (x,...)
			else
				p += dy - dx, x -= 1; //moveto(x-1,...)
		}

		if (ppt_buffer)
		{
			ppt_buffer[center_index + n + 1].x = x;
			ppt_buffer[center_index + n + 1].y = y;
		}
	}

	return width;
}

/**********************************************************************
* Bresenham Alogorithm for first quadrant ellipse in rect (x1, y1, x2, y2)
* the orginal point at center of rect, x increasing to right, y increasing to down
* the ellipse to be fited clockwise
* rx = (x2 - x1) / 2, ry = (y2 - y1) / 2
* x0 = 0, y0 = ry
* for x0 = 0 to rx
*  dif = (x0 + 1)^2 * ry^2 + (y0 - 1)^2 * rx^2 - rx^2 * ry^2
*  if diff < 0
*    det = |(x0 + 1)^2 * ry^2 + (y0)^2 * rx^2 - rx^2 * ry^2| - |(x0 + 1)^2 * ry^2 + (y0 - 1)^2 * rx^2 - rx^2 * ry^2| = 2 * (dif + y0 * rx^2) -  rx^2
*    if det < 0  x0 = x0 + 1, y0 = y0
*    else x0 = x0 + 1, y0 = y0 - 1
*   endif
*  else
*    det = |(x0 + 1)^2 * ry^2 + (y0 - 1)^2 * rx^2 - rx^2 * ry^2| - |(x0)^2 * ry^2 + (y0 - 1)^2 * rx^2 - rx^2 * ry^2| = 2 * (dif - x0 * ry^2) +  ry^2
*    if det < 0 x0 = x0 + 1, y0 = y0 - 1
*    else x0 = x0, y0 = y0 - 1
*    endif
*  endif
* endfor
***********************************************************************/

int dot_ellipse(int dot_width, int dot_mode, int rx, int ry, xpoint_t* ppt_buffer, int size_buffer)
{
	int x, y, sx, sy, n = 0;
	int dif, det, mask, mask_count = 0;
	xpoint_t org;

	sx = rx * rx;
	sy = ry * ry;
	
	//the dash mask
	mask = (byte_t)(dot_mode & 0x00ff);

	//generate the first quadrant arc
	x = 0;
	y = ry;
	while (y >=0 && n < size_buffer)
	{
		org.x = x, org.y = y;

		if (!(mask & 0x80))
		{
			//fill neghbour points by width
			if (ppt_buffer)
			{
				_dot_neghbour(dot_width, org, ppt_buffer + n, dot_width);
			}
			n += dot_width;
		}

		mask <<= 1;
		if (++mask_count == 8)
		{
			mask_count = 0;
			mask = (byte_t)(dot_mode & 0x00ff);
		}

		dif = (x + 1) * (x + 1) * sy + (y - 1) * (y - 1) * sx - sx * sy;
		if (dif < 0)
		{
			det = 2 * (dif + y * sx) - sx;
			if (det <= 0)
				x++;
			else
				x++, y--;
		}
		else if (dif > 0)
		{
			det = 2 * (dif - x * sy) + sy;
			if (det <= 0)
				x++, y--;
			else
				y--;
		}
		else
		{
			x++, y--;
		}
	}

	// translate the second, third, fourth quadrant arc
	if (ppt_buffer)
	{
		org.x = 0;
		org.y = 0;

		pt_xaxis_symmetric(org, ppt_buffer, n, (ppt_buffer + n), n);
		pt_origin_symmetric(org, ppt_buffer, n, (ppt_buffer + 2 * n), n);
		pt_yaxis_symmetric(org, ppt_buffer, n, (ppt_buffer + 3 * n), n);
	}
	n *= 4;

	return n;
}
