/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc dot line document

	@module	dot_line.c | implement file

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

static int _dot_neghbour(int width, xpoint_t pt_center, int pt_dx, int pt_dy, int pt_sx, int pt_sy, xpoint_t* ppt_buffer, int size_buffer)
{
	int x, y;
	int dx, dy, p = 0;
	int sx = 0, sy = 0, n = 0;
	int outer_width, inner_width, center_index;

	//neghbour point along the normal line, if source line's slope is k, then normal line's slope is 1/k.
	dx = pt_dy;
	dy = pt_dx;
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

	//the direction for outer neghbour
	if (pt_sx == 1 && pt_sy == -1)
		sx = 1, sy = 1;
	else if (pt_sx == -1 && pt_sy == -1)
		sx = 1, sy = -1;
	else if (pt_sx == -1 && pt_sy == 1)
		sx = -1, sy = -1;
	else if (pt_sx == 1 && pt_sy == 1)
		sx = -1, sy = 1;

	for (n = 0; n < outer_width; n++)
	{
		if (dy < dx)
		{
			x += sx; //moveto (x+1|x-1,...)
	
			if (p > 0)
				p += -dy; //moveto (...,y)
			else
				p += dx - dy, y += sy; //moveto(...,y+1|y-1)
		}
		else
		{
			y += sy; //moveto (...,y+1|y-1)

			if (p > 0)
				p += -dx; //moveto (x,...)
			else
				p += dy - dx, x += sx; //moveto(x+1|x-1,...)
		}

		if (ppt_buffer)
		{
			ppt_buffer[center_index-n-1].x = x;
			ppt_buffer[center_index-n-1].y = y;
		}
	}

	x = pt_center.x;
	y = pt_center.y;

	//the direction for inner neghbour
	if (pt_sx == 1 && pt_sy == -1)
		sx = -1, sy = -1;
	else if (pt_sx == -1 && pt_sy == -1)
		sx = -1, sy = 1;
	else if (pt_sx == -1 && pt_sy == 1)
		sx = 1, sy = 1;
	else if (pt_sx == 1 && pt_sy == 1)
		sx = 1, sy = -1;

	for (n = 0; n < inner_width; n++)
	{
		if (dy < dx)
		{
			x += sx; //moveto (x+1|x-1,...)

			if (p > 0)
				p += -dy; //moveto (...,y)
			else
				p += dx - dy, y += sy; //moveto(...,y+1|y-1)
		}
		else
		{
			y += sy; //moveto (...,y+1|y-1)

			if (p > 0)
				p += -dx; //moveto (x,...)
			else
				p += dy - dx, x += sx; //moveto(x+1|x-1,...)
		}

		if (ppt_buffer)
		{
			ppt_buffer[center_index + n + 1].x = x;
			ppt_buffer[center_index + n + 1].y = y;
		}
	}

	return width;
}

int dot_line(int dot_width, int dot_mode, int xoff, int yoff, xpoint_t* ppt_buffer, int size_buffer)
{
	int x, y;
	int dx, dy, p = 0;
	int sx, sy, n = 0;
	byte_t mask = 0;
	int mask_count = 0;

	xpoint_t pt_center;

	dx = (xoff > 0) ? xoff : -xoff;
	dy = (yoff > 0) ? yoff : -yoff;
	
	if (xoff > 0)
		sx = 1;
	else if (xoff < 0)
		sx = -1;
	else
		sx = 0;

	if (yoff > 0)
		sy = 1;
	else if (yoff < 0)
		sy = -1;
	else
		sy = 0;

	p = (dy < dx) ? (dx - 2 * dy) : (dy - 2 * dx);

	//the dash mask
	mask = (byte_t)(dot_mode & 0x00ff);

	x = 0; 
	y = 0;

	while (n < size_buffer)
	{
		pt_center.x = x, pt_center.y = y;

		if (!(mask & 0x80))
		{
			if (ppt_buffer)
			{
				//fill neghbour points by width
				_dot_neghbour(dot_width, pt_center, dx, dy, sx, sy, ppt_buffer + n, dot_width);
			}
			n += dot_width;
		}

		mask <<= 1;
		if (++mask_count == 8)
		{
			mask_count = 0;
			mask = (byte_t)(dot_mode & 0x00ff);
		}

		if (dy < dx)
		{
			x += sx;
			if((sx > 0 && x > xoff) || (sx < 0 && x < xoff) || !sx)
				break;

			if (p > 0)
				p += -dy; //moveto (...,y)
			else
				p += dx - dy, y += sy; //moveto(...,y+1|y-1)
		}
		else
		{
			y += sy;
			if ((sy > 0 && y > yoff) || (sy < 0 && y < yoff) || !sy)
				break;

			if (p > 0)
				p += -dx; //moveto (x,...)
			else
				p += dy-dx, x += sx; //moveto(x+1|x-1,...)
		}
	}

	return n;
}

