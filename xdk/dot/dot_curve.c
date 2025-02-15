/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc dot curve document

	@module	dot_curve.c | implement file

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

typedef struct __link_point3{
	link_t lk;
	xpoint_t pt[3];
}_link_point3;

int dot_curve2_123(int dot_width, int dot_mode, const xpoint_t* ppt1, const xpoint_t* ppt2, xpoint_t* ppt_buffer, int size_buffer)
{
	int xoff, yoff;
	int dx, dy, sx, sy, n = 0;
	int  mask, mask_count = 0;

	link_t lk_root;
	_link_point3* ptr_t, *ptr_l, *ptr_r;
	xpoint_t pt1, pt2, pt_dot;

	//the dash mask
	mask = (byte_t)(dot_mode & 0x00ff);

	ptr_t = (_link_point3*)xmem_alloc(sizeof(_link_point3));
	ptr_t->pt[0].x = 0, ptr_t->pt[0].y = 0;
	ptr_t->pt[1].x = ppt1->x, ptr_t->pt[1].y = ppt1->y;
	ptr_t->pt[2].x = ppt2->x, ptr_t->pt[2].y = ppt2->y;

	init_root_link(&lk_root);
	push_link(&lk_root, (link_t_ptr)ptr_t);
	
	while (!is_empty_link(&lk_root))
	{
		//get the top vertex
		ptr_t = (_link_point3*)peek_link(&lk_root);
		pt1.x = (ptr_t->pt[0].x + ptr_t->pt[1].x) / 2;
		pt1.y = (ptr_t->pt[0].y + ptr_t->pt[1].y) / 2;
		pt2.x = (ptr_t->pt[1].x + ptr_t->pt[2].x) / 2;
		pt2.y = (ptr_t->pt[1].y + ptr_t->pt[2].y) / 2;
		pt_dot.x = (pt1.x + pt2.x) / 2;
		pt_dot.y = (pt1.y + pt2.y) / 2;

		xoff = pt2.x - pt1.x, yoff = pt2.y - pt1.y;

		if (xoff * xoff > 1 || yoff * yoff > 1)
		{
			//save the left child vertex
			ptr_l = (_link_point3*)xmem_alloc(sizeof(_link_point3));
			ptr_l->pt[0].x = ptr_t->pt[0].x, ptr_l->pt[0].y = ptr_t->pt[0].y;
			ptr_l->pt[1].x = pt1.x, ptr_l->pt[1].y = pt1.y;
			ptr_l->pt[2].x = pt_dot.x, ptr_l->pt[2].y = pt_dot.y;
			push_link(&lk_root, (link_t_ptr)ptr_l);
		}else
		{
			if (!(mask & 0x80))
			{
				//first generate the leaf vertex point
				if (ppt_buffer)
				{
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

					//fill neghbour points by width
					_dot_neghbour(dot_width, pt_dot, dx, dy, sx, sy, ppt_buffer + n, dot_width);
				}
				n += dot_width;
			}
			mask <<= 1;
			if (++mask_count == 8)
			{
				mask_count = 0;
				mask = (byte_t)(dot_mode & 0x00ff);
			}

			//discard the left leaf vertex point
			ptr_t = (_link_point3*)pop_link(&lk_root);
			xmem_free(ptr_t);

			//popup the father vertex
			ptr_t = (_link_point3*)pop_link(&lk_root);
			if (!ptr_t)
				break;

			pt1.x = (ptr_t->pt[0].x + ptr_t->pt[1].x) / 2;
			pt1.y = (ptr_t->pt[0].y + ptr_t->pt[1].y) / 2;
			pt2.x = (ptr_t->pt[1].x + ptr_t->pt[2].x) / 2;
			pt2.y = (ptr_t->pt[1].y + ptr_t->pt[2].y) / 2;
			pt_dot.x = (pt1.x + pt2.x) / 2;
			pt_dot.y = (pt1.y + pt2.y) / 2;

			xoff = pt2.x - pt1.x, yoff = pt2.y - pt1.y;

			if (!(mask & 0x80))
			{
				//then generate the father vertex point
				if (ppt_buffer)
				{
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

					//fill neghbour points by width
					_dot_neghbour(dot_width, pt_dot, dx, dy, sx, sy, ppt_buffer + n, dot_width);
				}
				n += dot_width;
			}
			mask <<= 1;
			if (++mask_count == 8)
			{
				mask_count = 0;
				mask = (byte_t)(dot_mode & 0x00ff);
			}

			if (xoff * xoff > 1 || yoff * yoff > 1)
			{
				//save the right child vertex
				ptr_r = (_link_point3*)xmem_alloc(sizeof(_link_point3));
				ptr_r->pt[0].x = pt_dot.x, ptr_r->pt[0].y = pt_dot.y;
				ptr_r->pt[1].x = pt2.x, ptr_r->pt[1].y = pt2.y;
				ptr_r->pt[2].x = ptr_t->pt[2].x, ptr_r->pt[2].y = ptr_t->pt[2].y;
				push_link(&lk_root, (link_t_ptr)ptr_r);
			}

			xmem_free(ptr_t);
			ptr_t = NULL;
		}
	}

	return n;
}

int dot_curve2(int dot_width, int dot_mode, const xpoint_t* ppt1, const xpoint_t* ppt2, xpoint_t* ppt_buffer, int size_buffer)
{
	int xoff, yoff;
	int dx, dy, sx, sy, n = 0;

	link_t lk_root;
	_link_point3* ptr_t, *ptr_l, *ptr_r;
	xpoint_t pt1, pt2, pt_dot, pt_ins;

	ptr_t = (_link_point3*)xmem_alloc(sizeof(_link_point3));
	ptr_t->pt[0].x = 0, ptr_t->pt[0].y = 0;
	ptr_t->pt[1].x = ppt1->x, ptr_t->pt[1].y = ppt1->y;
	ptr_t->pt[2].x = ppt2->x, ptr_t->pt[2].y = ppt2->y;

	init_root_link(&lk_root);
	push_link(&lk_root, (link_t_ptr)ptr_t);

	while (!is_empty_link(&lk_root))
	{
		ptr_t = (_link_point3*)pop_link(&lk_root);

		pt1.x = (ptr_t->pt[0].x + ptr_t->pt[1].x) / 2;
		pt1.y = (ptr_t->pt[0].y + ptr_t->pt[1].y) / 2;
		pt2.x = (ptr_t->pt[1].x + ptr_t->pt[2].x) / 2;
		pt2.y = (ptr_t->pt[1].y + ptr_t->pt[2].y) / 2;

		pt_dot.x = (pt1.x + pt2.x) / 2;
		pt_dot.y = (pt1.y + pt2.y) / 2;

		xoff = pt2.x - pt1.x, yoff = pt2.y - pt1.y;

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

		if (ppt_buffer)
		{
			//fill neghbour points by width
			_dot_neghbour(dot_width, pt_dot, dx, dy, sx, sy, ppt_buffer + n, dot_width);
		}
		n += dot_width;

		xoff = pt_dot.x - pt1.x;
		yoff = pt_dot.y - pt1.y;
		if (xoff * xoff > 1 || yoff * yoff > 1)
		{
			ptr_l = (_link_point3*)xmem_alloc(sizeof(_link_point3));
			ptr_l->pt[0].x = ptr_t->pt[0].x, ptr_l->pt[0].y = ptr_t->pt[0].y;
			ptr_l->pt[1].x = pt1.x, ptr_l->pt[1].y = pt1.y;
			ptr_l->pt[2].x = pt_dot.x, ptr_l->pt[2].y = pt_dot.y;
			push_link(&lk_root, (link_t_ptr)ptr_l);
		}
		else
		{
			pt_ins.x = (ptr_t->pt[0].x + pt_dot.x) / 2;
			pt_ins.y = (ptr_t->pt[0].y + pt_dot.y) / 2;

			if (ppt_buffer)
			{
				//fill neghbour points by width
				_dot_neghbour(dot_width, pt_ins, dx, dy, sx, sy, ppt_buffer + n, dot_width);
			}
			n += dot_width;
		}

		xoff = pt2.x - pt_dot.x;
		yoff = pt2.y - pt_dot.y;
		if (xoff * xoff > 1 || yoff * yoff > 1)
		{
			ptr_r = (_link_point3*)xmem_alloc(sizeof(_link_point3));
			ptr_r->pt[0].x = pt_dot.x, ptr_r->pt[0].y = pt_dot.y;
			ptr_r->pt[1].x = pt2.x, ptr_r->pt[1].y = pt2.y;
			ptr_r->pt[2].x = ptr_t->pt[2].x, ptr_r->pt[2].y = ptr_t->pt[2].y;
			push_link(&lk_root, (link_t_ptr)ptr_r);
		}
		else
		{
			pt_ins.x = (ptr_t->pt[2].x + pt_dot.x) / 2;
			pt_ins.y = (ptr_t->pt[2].y + pt_dot.y) / 2;

			if (ppt_buffer)
			{
				//fill neghbour points by width
				_dot_neghbour(dot_width, pt_ins, dx, dy, sx, sy, ppt_buffer + n, dot_width);
			}
			n += dot_width;
		}

		xmem_free(ptr_t);
	}

	return n;
}

typedef struct __link_point4{
	link_t lk;
	xpoint_t pt[4];
}_link_point4;

int dot_curve3_123(int dot_width, int dot_mode, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, xpoint_t* ppt_buffer, int size_buffer)
{
	int xoff, yoff;
	int dx, dy, sx, sy, n = 0;
	int  mask, mask_count = 0;

	link_t lk_root;
	_link_point4* ptr_t, *ptr_l, *ptr_r;
	xpoint_t pt1, pt2, pt3, pt4, pt5, pt_dot;

	//the dash mask
	mask = (byte_t)(dot_mode & 0x00ff);

	ptr_t = (_link_point4*)xmem_alloc(sizeof(_link_point4));
	ptr_t->pt[0].x = 0, ptr_t->pt[0].y = 0;
	ptr_t->pt[1].x = ppt1->x, ptr_t->pt[1].y = ppt1->y;
	ptr_t->pt[2].x = ppt2->x, ptr_t->pt[2].y = ppt2->y;
	ptr_t->pt[3].x = ppt3->x, ptr_t->pt[3].y = ppt3->y;

	init_root_link(&lk_root);
	push_link(&lk_root, (link_t_ptr)ptr_t);

	while (!is_empty_link(&lk_root))
	{
		ptr_t = (_link_point4*)peek_link(&lk_root);

		pt1.x = (ptr_t->pt[0].x + ptr_t->pt[1].x) / 2;
		pt1.y = (ptr_t->pt[0].y + ptr_t->pt[1].y) / 2;
		pt2.x = (ptr_t->pt[1].x + ptr_t->pt[2].x) / 2;
		pt2.y = (ptr_t->pt[1].y + ptr_t->pt[2].y) / 2;
		pt3.x = (ptr_t->pt[2].x + ptr_t->pt[3].x) / 2;
		pt3.y = (ptr_t->pt[2].y + ptr_t->pt[3].y) / 2;

		pt4.x = (pt1.x + pt2.x) / 2;
		pt4.y = (pt1.y + pt2.y) / 2;
		pt5.x = (pt2.x + pt3.x) / 2;
		pt5.y = (pt3.y + pt3.y) / 2;

		pt_dot.x = (pt4.x + pt5.x) / 2;
		pt_dot.y = (pt4.y + pt5.y) / 2;

		xoff = pt5.x - pt4.x, yoff = pt5.y - pt4.y;

		if (xoff * xoff > 1 || yoff * yoff > 1)
		{
			ptr_l = (_link_point4*)xmem_alloc(sizeof(_link_point4));
			ptr_l->pt[0].x = ptr_t->pt[0].x, ptr_l->pt[0].y = ptr_t->pt[0].y;
			ptr_l->pt[1].x = pt1.x, ptr_l->pt[1].y = pt1.y;
			ptr_l->pt[2].x = pt4.x, ptr_l->pt[2].y = pt4.y;
			ptr_l->pt[3].x = pt_dot.x, ptr_l->pt[3].y = pt_dot.y;
			push_link(&lk_root, (link_t_ptr)ptr_l);
		}
		else
		{
			if (!(mask & 0x80))
			{
				if (ppt_buffer)
				{
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

					//fill neghbour points by width
					_dot_neghbour(dot_width, pt_dot, dx, dy, sx, sy, ppt_buffer + n, dot_width);
				}
				n += dot_width;
			}
			mask <<= 1;
			if (++mask_count == 8)
			{
				mask_count = 0;
				mask = (byte_t)(dot_mode & 0x00ff);
			}

			//discard the left leaf vertex point
			ptr_t = (_link_point4*)pop_link(&lk_root);
			xmem_free(ptr_t);

			//popup the father vertex
			ptr_t = (_link_point4*)pop_link(&lk_root);
			if (!ptr_t)
				break;

			pt1.x = (ptr_t->pt[0].x + ptr_t->pt[1].x) / 2;
			pt1.y = (ptr_t->pt[0].y + ptr_t->pt[1].y) / 2;
			pt2.x = (ptr_t->pt[1].x + ptr_t->pt[2].x) / 2;
			pt2.y = (ptr_t->pt[1].y + ptr_t->pt[2].y) / 2;
			pt3.x = (ptr_t->pt[2].x + ptr_t->pt[3].x) / 2;
			pt3.y = (ptr_t->pt[2].y + ptr_t->pt[3].y) / 2;

			pt4.x = (pt1.x + pt2.x) / 2;
			pt4.y = (pt1.y + pt2.y) / 2;
			pt5.x = (pt2.x + pt3.x) / 2;
			pt5.y = (pt3.y + pt3.y) / 2;

			pt_dot.x = (pt4.x + pt5.x) / 2;
			pt_dot.y = (pt4.y + pt5.y) / 2;

			xoff = pt5.x - pt4.x, yoff = pt5.y - pt4.y;

			if (!(mask & 0x80))
			{
				if (ppt_buffer)
				{
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

					//fill neghbour points by width
					_dot_neghbour(dot_width, pt_dot, dx, dy, sx, sy, ppt_buffer + n, dot_width);
				}
				n += dot_width;
			}
			mask <<= 1;
			if (++mask_count == 8)
			{
				mask_count = 0;
				mask = (byte_t)(dot_mode & 0x00ff);
			}

			if (xoff * xoff > 1 || yoff * yoff > 1)
			{
				ptr_r = (_link_point4*)xmem_alloc(sizeof(_link_point4));
				ptr_r->pt[0].x = pt_dot.x, ptr_r->pt[0].y = pt_dot.y;
				ptr_r->pt[1].x = pt5.x, ptr_r->pt[1].y = pt5.y;
				ptr_r->pt[2].x = pt3.x, ptr_r->pt[2].y = pt3.y;
				ptr_r->pt[3].x = ptr_t->pt[3].x, ptr_r->pt[3].y = ptr_t->pt[3].y;
				push_link(&lk_root, (link_t_ptr)ptr_r);
			}

			xmem_free(ptr_t);
			ptr_t = NULL;
		}
	}

	return n;
}

int dot_curve3(int dot_width, int dot_mode, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, xpoint_t* ppt_buffer, int size_buffer)
{
	int xoff, yoff;
	int dx, dy, sx, sy, n = 0;

	link_t lk_root;
	_link_point4* ptr_t, *ptr_l, *ptr_r;
	xpoint_t pt1, pt2, pt3, pt4, pt5, pt_dot, pt_ins;

	ptr_t = (_link_point4*)xmem_alloc(sizeof(_link_point4));
	ptr_t->pt[0].x = 0, ptr_t->pt[0].y = 0;
	ptr_t->pt[1].x = ppt1->x, ptr_t->pt[1].y = ppt1->y;
	ptr_t->pt[2].x = ppt2->x, ptr_t->pt[2].y = ppt2->y;
	ptr_t->pt[3].x = ppt3->x, ptr_t->pt[3].y = ppt3->y;

	init_root_link(&lk_root);
	push_link(&lk_root, (link_t_ptr)ptr_t);

	while (!is_empty_link(&lk_root))
	{
		ptr_t = (_link_point4*)pop_link(&lk_root);

		pt1.x = (ptr_t->pt[0].x + ptr_t->pt[1].x) / 2;
		pt1.y = (ptr_t->pt[0].y + ptr_t->pt[1].y) / 2;
		pt2.x = (ptr_t->pt[1].x + ptr_t->pt[2].x) / 2;
		pt2.y = (ptr_t->pt[1].y + ptr_t->pt[2].y) / 2;
		pt3.x = (ptr_t->pt[2].x + ptr_t->pt[3].x) / 2;
		pt3.y = (ptr_t->pt[2].y + ptr_t->pt[3].y) / 2;

		pt4.x = (pt1.x + pt2.x) / 2;
		pt4.y = (pt1.y + pt2.y) / 2;
		pt5.x = (pt2.x + pt3.x) / 2;
		pt5.y = (pt3.y + pt3.y) / 2;

		pt_dot.x = (pt4.x + pt5.x) / 2;
		pt_dot.y = (pt4.y + pt5.y) / 2;

		xoff = pt5.x - pt4.x, yoff = pt5.y - pt4.y;

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

		if (ppt_buffer)
		{
			//fill neghbour points by width
			_dot_neghbour(dot_width, pt_dot, dx, dy, sx, sy, ppt_buffer + n, dot_width);
		}
		n += dot_width;

		xoff = pt_dot.x - pt4.x;
		yoff = pt_dot.y - pt4.y;
		if (xoff * xoff > 1 || yoff * yoff > 1)
		{
			ptr_l = (_link_point4*)xmem_alloc(sizeof(_link_point4));
			ptr_l->pt[0].x = ptr_t->pt[0].x, ptr_l->pt[0].y = ptr_t->pt[0].y;
			ptr_l->pt[1].x = pt1.x, ptr_l->pt[1].y = pt1.y;
			ptr_l->pt[2].x = pt4.x, ptr_l->pt[2].y = pt4.y;
			ptr_l->pt[3].x = pt_dot.x, ptr_l->pt[3].y = pt_dot.y;
			push_link(&lk_root, (link_t_ptr)ptr_l);
		}
		else
		{
			pt_ins.x = (pt1.x + pt_dot.x) / 2;
			pt_ins.y = (pt1.y + pt_dot.y) / 2;

			if (ppt_buffer)
			{
				//fill neghbour points by width
				_dot_neghbour(dot_width, pt_ins, dx, dy, sx, sy, ppt_buffer + n, dot_width);
			}
			n += dot_width;

			pt_ins.x = (ptr_t->pt[0].x + pt4.x) / 2;
			pt_ins.y = (ptr_t->pt[0].y + pt4.y) / 2;

			if (ppt_buffer)
			{
				//fill neghbour points by width
				_dot_neghbour(dot_width, pt_ins, dx, dy, sx, sy, ppt_buffer + n, dot_width);
			}
			n += dot_width;
		}

		xoff = pt5.x - pt_dot.x;
		yoff = pt5.y - pt_dot.y;
		if (xoff * xoff > 1 || yoff * yoff > 1)
		{
			ptr_r = (_link_point4*)xmem_alloc(sizeof(_link_point4));
			ptr_r->pt[0].x = pt_dot.x, ptr_r->pt[0].y = pt_dot.y;
			ptr_r->pt[1].x = pt5.x, ptr_r->pt[1].y = pt5.y;
			ptr_r->pt[2].x = pt3.x, ptr_r->pt[2].y = pt3.y;
			ptr_r->pt[3].x = ptr_t->pt[3].x, ptr_r->pt[3].y = ptr_t->pt[3].y;
			push_link(&lk_root, (link_t_ptr)ptr_r);
		}
		else
		{
			pt_ins.x = (pt3.x + pt_dot.x) / 2;
			pt_ins.y = (pt3.y + pt_dot.y) / 2;

			if (ppt_buffer)
			{
				//fill neghbour points by width
				_dot_neghbour(dot_width, pt_ins, dx, dy, sx, sy, ppt_buffer + n, dot_width);
			}
			n += dot_width;

			pt_ins.x = (ptr_t->pt[3].x + pt5.x) / 2;
			pt_ins.y = (ptr_t->pt[3].y + pt5.y) / 2;

			if (ppt_buffer)
			{
				//fill neghbour points by width
				_dot_neghbour(dot_width, pt_ins, dx, dy, sx, sy, ppt_buffer + n, dot_width);
			}
			n += dot_width;
		}

		xmem_free(ptr_t);
	}

	return n;
}
