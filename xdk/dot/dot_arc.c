/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc dot arc document

	@module	dot_arc.c | implement file

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
#include "../g2/g2.h"

#include "../xdkimp.h"
#include "../xdkstd.h"
#include "../xdkutil.h"
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

static int clip_arc(int dot_width, int dot_mode, double a1, double a2, bool_t clockwise, const xpoint_t* ppt_ellipse, int n_points, xpoint_t* ppt_buffer, int size_buffer)
{
	int x, y, i, n = 0;
	int mask, mask_count = 0;
	double a;
	float d0, d1, d2;
	xpoint_t org;

	//the dash mask
	mask = (byte_t)(dot_mode & 0x00ff);

	if (clockwise)
	{
		//colosewise, d1 is positive
		radian_to_degree(a1, a2, &d0, &d1);

		for (i = 0; i < n_points; i++)
		{
			x = ppt_ellipse[i].x, y = ppt_ellipse[i].y;

			if (!x && y > 0)
				a = (a1 < 0) ? -3 * XPI / 2 : XPI / 2;
			else if (!x && y < 0)
				a = (a1 < 0) ? -XPI / 2 : 3 * XPI / 2;
			else
			{
				a = atan((double)y / (double)x);

				if (x < 0 && y > 0)
					a += (a1 < 0) ? -XPI : XPI;
				else if (x < 0 && y < 0)
					a += (a1 < 0) ? -XPI : XPI;
			}

			radian_to_degree(a1, a, NULL, &d2);
			if (d2 < 0) d2 += 360;

			if (d2 <= d1)
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
			}
		}
	}
	else
	{
		//anti-closewise, d1 is negative
		radian_to_degree(a1, a2, &d0, &d1);

		for (i = n_points -1; i >= 0; i--)
		{
			x = ppt_ellipse[i].x, y = ppt_ellipse[i].y;

			if (!x && y > 0)
				a = (a1 < 0)? -3 * XPI / 2 : XPI / 2;
			else if (!x && y < 0)
				a =(a1 < 0)?  -XPI / 2 : 3 * XPI / 2;
			else
			{
				a = atan((double)y / (double)x);

				if (x < 0 && y > 0) 
					a += (a1 < 0)? -XPI : XPI;
				else if (x < 0 && y < 0) 
					a += (a1 < 0)? -XPI : XPI;
			}

			radian_to_degree(a1, a, NULL, &d2);
			if (d2 > 0) d2 -= 360;
			
			if (d2 >= d1)
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
			}
		}
	}

	return n;
}


int dot_arc(int dot_width, int dot_mode, int rx, int ry, double angle_from, double angle_to, bool_t clockwise, xpoint_t* ppt_buffer, int size_buffer)
{
	int x1, y1, x2, y2;
	double r1, r2, rr;

	int sx, sy, n = 0;
	xpoint_t* ppt;

	sx = rx * rx;
	sy = ry * ry;
	rr = (double)(sx * sy) / (double)(sx * sin(angle_from) * sin(angle_from) + sy * cos(angle_from) * cos(angle_from));
	r1 = sqrt(rr);
	rr = (double)(sx * sy) / (double)(sx * sin(angle_to) * sin(angle_to) + sy * cos(angle_to) * cos(angle_to));
	r2 = sqrt(rr);

	x1 = ROUNDINT(r1 * cos(angle_from));
	y1 = ROUNDINT(r1 * sin(angle_from));
	x2 = ROUNDINT(r2 * cos(angle_to));
	y2 = ROUNDINT(r2 * sin(angle_to));

	n = dot_ellipse(1, DOT_SOLID, rx, ry, NULL, MAX_LONG);
	ppt = (xpoint_t*)xmem_alloc(n * sizeof(xpoint_t));
	n = dot_ellipse(1, DOT_SOLID, rx, ry, ppt, n);

	n = clip_arc(dot_width, dot_mode, angle_from, angle_to, clockwise, ppt, n, ppt_buffer, size_buffer);

	xmem_free(ppt);

	return n;
}
