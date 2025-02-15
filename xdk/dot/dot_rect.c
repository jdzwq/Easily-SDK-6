/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc dot rect document

	@module	dot_rect.c | implement file

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

static int _dot_neghbour(int width, xpoint_t pt_center, int pt_sx, int pt_sy, xpoint_t* ppt_buffer, int size_buffer)
{
	int x, y, sx, sy, n = 0;
	int outer_width, inner_width, center_index;

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
	if (pt_sx == 1 && !pt_sy) //top horz edge
		sx = 0, sy = 1;
	else if (!pt_sx && pt_sy == -1) //right vert edge
		sx = 1, sy = 0;
	else if (pt_sx == -1 && !pt_sy) //bottom horz edge
		sx = 0, sy = -1;
	else if (!pt_sx && pt_sy == 1) //left vert edge
		sx = -1, sy = 0;

	for (n = 0; n < outer_width; n++)
	{
		x += sx, y += sy;

		if (ppt_buffer)
		{
			ppt_buffer[center_index-n-1].x = x;
			ppt_buffer[center_index-n-1].y = y;
		}
	}

	x = pt_center.x;
	y = pt_center.y;

	//the direction for inner neghbour
	if (pt_sx == 1 && !pt_sy) //top horz edge
		sx = 0, sy = -1;
	else if (!pt_sx && pt_sy == -1) //right vert edge
		sx = -1, sy = 0;
	else if (pt_sx == -1 && !pt_sy) //bottom horz edge
		sx = 0, sy = 1;
	else if (!pt_sx && pt_sy == 1) //left vert edge
		sx = 1, sy = 0;

	for (n = 0; n < inner_width; n++)
	{
		x += sx, y += sy;

		if (ppt_buffer)
		{
			ppt_buffer[center_index + n + 1].x = x;
			ppt_buffer[center_index + n + 1].y = y;
		}
	}

	return width;
}

int dot_rect(int dot_width, int dot_mode, int width, int height, xpoint_t* ppt_buffer, int size_buffer)
{
	int x, y, n = 0;
	byte_t mask = 0;
	int rx, ry, mask_count = 0;
	xpoint_t org;

	//the dash mask
	mask = (byte_t)(dot_mode & 0x00ff);

	//dot horz edge from left to right
	rx = width / 2;
	ry = height / 2;
	x = 0;
	y = ry - 1;
	while (x < rx && n < size_buffer)
	{
		org.x = x, org.y = y;

		if (!(mask & 0x80))
		{
			if (ppt_buffer)
			{
				//fill neghbour points by width
				_dot_neghbour(dot_width, org, 1, 0, ppt_buffer + n, dot_width);
			}
			n += dot_width;
		}

		mask <<= 1;
		if (++mask_count == 8)
		{
			mask_count = 0;
			mask = (byte_t)(dot_mode & 0x00ff);
		}

		x++;
	}

	//dot vert edge from top to bottom
	x = rx - 1;
	y = ry - 1;
	while (y >= 0 && n < size_buffer)
	{
		org.x = x, org.y = y;

		if (!(mask & 0x80))
		{
			if (ppt_buffer)
			{
				//fill neghbour points by width
				_dot_neghbour(dot_width, org, 0, -1, ppt_buffer + n, dot_width);
			}
			n += dot_width;
		}

		mask <<= 1;
		if (++mask_count == 8)
		{
			mask_count = 0;
			mask = (byte_t)(dot_mode & 0x00ff);
		}

		y--;
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

