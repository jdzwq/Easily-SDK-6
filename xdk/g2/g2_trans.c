/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc 2D coordinate space document

	@module	g2_trans.c | implement file

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

#include "g2.h"

#include "../xdkstd.h"
#include "../xdkinit.h"
#include "../xdkutil.h"

void pt_world_to_screen(xpoint_t pt_origin, xpoint_t* ppt_points, int count_points)
{
	int n;

	for (n = 0; n < count_points; n++)
	{
		ppt_points[n].x += pt_origin.x;
		ppt_points[n].y = pt_origin.y - ppt_points[n].y;
	}
}

void ft_world_to_screen(xpoint_t pt_origin, xpoint_t* ppt_points, int count_points)
{
	int n;

	for (n = 0; n < count_points; n++)
	{
		ppt_points[n].fx += pt_origin.fx;
		ppt_points[n].fy = pt_origin.fy - ppt_points[n].fy;
	}
}

void pt_screen_to_world(xpoint_t pt_origin, xpoint_t* ppt_points, int count_points)
{
	int n;

	for (n = 0; n < count_points; n++)
	{
		ppt_points[n].x -= pt_origin.x;
		ppt_points[n].y = pt_origin.y - ppt_points[n].y;
	}
}

void ft_screen_to_world(xpoint_t pt_origin, xpoint_t* ppt_points, int count_points)
{
	int n;

	for (n = 0; n < count_points; n++)
	{
		ppt_points[n].fx -= pt_origin.fx;
		ppt_points[n].fy = pt_origin.fy - ppt_points[n].fy;
	}
}

void radian_to_degree(double arc_from, double arc_to, float* ang_from, float* ang_sweep)
{
	//as sweep
	arc_to -= arc_from;

	if (ang_from)
		*ang_from = (compare_double(arc_from, 0.0, MAX_DOUBLE_DIGI) > 0) ? (float)((2 - arc_from / XPI) * 180) : (float)((0 - arc_from / XPI) * 180);
	if (ang_sweep)
		*ang_sweep =  (float)((0 - arc_to / XPI) * 180);
}