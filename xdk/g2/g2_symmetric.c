/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc 2D coordinate space document

	@module	g2_symmetric.c | implement file

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


/**********************************************************************
Coordiate Transform along the x-axis symmetric
****         |1, 0|   
****|x, y| * |0,-1| = |x*1 + y*0, x*0 + y*-1|
****
***********************************************************************/

int pt_xaxis_symmetric(xpoint_t pt_org, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max)
{
	int i = 0;

	for (i = 0; i < n && i < max; i++)
	{
		if (ppt_dst)
		{
			ppt_dst[n-i-1].x = (ppt_src[i].x - pt_org.x) + pt_org.x;
			ppt_dst[n-i-1].y = 0 - (ppt_src[i].y - pt_org.y) + pt_org.y;
		}
	}

	return i;
}

int ft_xaxis_symmetric(xpoint_t pt_org, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max)
{
	int i = 0;

	for (i = 0; i < n && i < max; i++)
	{
		if (ppt_dst)
		{
			ppt_dst[n - i - 1].fx = (ppt_src[i].fx - pt_org.fx) + pt_org.fx;
			ppt_dst[n - i - 1].fy = 0 - (ppt_src[i].fy - pt_org.fy) + pt_org.fy;
		}
	}

	return i;
}

/**********************************************************************
Coordiate Transform along the y-axis symmetric
****         |-1, 0|
****|x, y| * | 0, 1| = |x*-1 + y*0, x*0 + y*1|
****
***********************************************************************/

int pt_yaxis_symmetric(xpoint_t pt_org, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max)
{
	int i = 0;

	for (i = 0; i < n && i < max; i++)
	{
		if (ppt_dst)
		{
			ppt_dst[n - i - 1].x = 0 - (ppt_src[i].x - pt_org.x) + pt_org.x;
			ppt_dst[n - i - 1].y = (ppt_src[i].y - pt_org.y) + pt_org.y;
		}
	}

	return i;
}

int ft_yaxis_symmetric(xpoint_t pt_org, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max)
{
	int i = 0;

	for (i = 0; i < n && i < max; i++)
	{
		if (ppt_dst)
		{
			ppt_dst[n - i - 1].fx = 0.0f - (ppt_src[i].fx - pt_org.fx) + pt_org.fx;
			ppt_dst[n - i - 1].fy = (ppt_src[i].fy - pt_org.fy) + pt_org.fy;
		}
	}

	return i;
}

/**********************************************************************
Coordiate Transform along the origin symmetric
****         |-1, 0|
****|x, y| * | 0,-1| = |x*-1 + y*0, x*0 + y*-1|
****
***********************************************************************/

int pt_origin_symmetric(xpoint_t pt_org, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max)
{
	int i = 0;

	for (i = 0; i < n && i < max; i++)
	{
		if (ppt_dst)
		{
			ppt_dst[i].x = 0 - (ppt_src[i].x - pt_org.x) + pt_org.x;
			ppt_dst[i].y = 0 - (ppt_src[i].y - pt_org.y) + pt_org.y;
		}
	}

	return i;
}

int ft_origin_symmetric(xpoint_t pt_org, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max)
{
	int i = 0;

	for (i = 0; i < n && i < max; i++)
	{
		if (ppt_dst)
		{
			ppt_dst[i].fx = 0.0f - (ppt_src[i].fx - pt_org.fx) + pt_org.fx;
			ppt_dst[i].fy = 0.0f - (ppt_src[i].fy - pt_org.fy) + pt_org.fy;
		}
	}

	return i;
}
