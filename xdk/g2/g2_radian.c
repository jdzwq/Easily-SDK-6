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

int arc_quadrant(double arc)
{
	while (arc < MAXDBL && compare_double(arc, 2 * XPI, MAX_DOUBLE_DIGI) > 0)
		arc -= 2 * XPI;

	while (arc > MINDBL && compare_double(arc, -2 * XPI, MAX_DOUBLE_DIGI) < 0)
		arc += 2 * XPI;

	if (compare_double(arc, 0.0, MAX_DOUBLE_DIGI) >= 0 && compare_double(arc, XPI / 2, MAX_DOUBLE_DIGI) <= 0)
		return 1;
	else if (compare_double(arc, XPI / 2, MAX_DOUBLE_DIGI) >= 0 && compare_double(arc, XPI, MAX_DOUBLE_DIGI) <= 0)
		return 2;
	else if (compare_double(arc, XPI, MAX_DOUBLE_DIGI) >= 0 && compare_double(arc, 3 * XPI / 2, MAX_DOUBLE_DIGI) <= 0)
		return 3;
	else if (compare_double(arc, 3 * XPI / 2, MAX_DOUBLE_DIGI) >= 0 && compare_double(arc, 2 * XPI, MAX_DOUBLE_DIGI) <= 0)
		return 4;
	else if (compare_double(arc, -XPI / 2, MAX_DOUBLE_DIGI) >= 0 && compare_double(arc, 0.0, MAX_DOUBLE_DIGI) <= 0)
		return 4;
	else if (compare_double(arc, -XPI, MAX_DOUBLE_DIGI) >= 0 && compare_double(arc, -XPI / 2, MAX_DOUBLE_DIGI) <= 0)
		return 3;
	else if (compare_double(arc, -3 * XPI / 2, MAX_DOUBLE_DIGI) >= 0 && compare_double(arc, -XPI, MAX_DOUBLE_DIGI) <= 0)
		return 2;
	else if (compare_double(arc, -2 * XPI, MAX_DOUBLE_DIGI) >= 0 && compare_double(arc, -3 * XPI / 2, MAX_DOUBLE_DIGI) <= 0)
		return 1;
	else
		return 0;
}

int pt_quadrant(const xpoint_t* ppo, const xpoint_t* ppt, bool_t sflag)
{
	int dx, dy;

	dx = ppt->x - ppo->x;
	dy = ppt->y - ppo->y;

	if (!dx && !dy)
		return 0;

	if (dx >= 0 && dy >= 0)
		return (sflag) ? 1 : 4;
	else if (dx <= 0 && dy >= 0)
		return (sflag) ? 2 : 3;
	else if (dx <= 0 && dy <= 0)
		return (sflag) ? 3 : 2;
	else
		return (sflag) ? 4 : 1;
}

int ft_quadrant(const xpoint_t* ppo, const xpoint_t* ppt, bool_t sflag)
{
	float dx, dy;

	dx = ppt->fx - ppo->fx;
	dy = ppt->fy - ppo->fy;

	if (IS_ZERO_FLOAT(dx) && IS_ZERO_FLOAT(dy))
		return 0;

	if (dx >= 0.0f && dy >= 0.0f)
		return (sflag) ? 1 : 4;
	else if (dx <= 0.0f && dy >= 0.0f)
		return (sflag) ? 2 : 3;
	else if (dx <= 0.0f && dy <= 0.0f)
		return (sflag) ? 3 : 2;
	else
		return (sflag) ? 4 : 1;
}

bool_t pt_calc_radian(bool_t clockwise, bool_t largearc, int rx, int ry, const xpoint_t* ppt1, const xpoint_t* ppt2, xpoint_t* ppt_center, double* arc_from, double* arc_to)
{
	xpoint_t pt[3] = { 0 };
	double k, len, fx, fy, arc, arc1, arc2;
	bool_t cw;

	if (ppt1->x <= ppt2->x)
	{
		pt[0].x = ppt1->x;
		pt[0].y = ppt1->y;
		pt[1].x = ppt2->x;
		pt[1].y = ppt2->y;
	}
	else
	{
		pt[0].x = ppt2->x;
		pt[0].y = ppt2->y;
		pt[1].x = ppt1->x;
		pt[1].y = ppt1->y;
		clockwise = (clockwise) ? 0 : 1;
	}
	cw = clockwise;

	if (ppt1->x <= ppt2->x)
		pt_screen_to_world(*ppt1, pt, 2);
	else
		pt_screen_to_world(*ppt2, pt, 2);

	k = (double)ry / (double)rx;

	//ellipse to circle
	pt[0].fx = (float)pt[0].x;
	pt[0].fy = (float)(pt[0].y / k);
	pt[1].fx = (float)pt[1].x;
	pt[1].fy = (float)(pt[1].y / k);

	fx = pt[1].fx - pt[0].fx;
	fy = pt[1].fy - pt[0].fy;

	//the half line length (ppt1 to ppt2)
	len = sqrt(pow(fx, 2) + pow(fy, 2)) / 2;

	//the included angle from point1 to point2
	arc = asin(len / rx) * 2;
	arc1 = acos(len / rx);
	arc2 = XPI / 2 + atan(fy / fx);

	if (clockwise && largearc)
	{
		*arc_from = arc2 + XPI / 2 + arc1;
		*arc_to = -2 * XPI + *arc_from + arc;
	}
	else if (!clockwise && !largearc)
	{
		*arc_from = -2 * XPI + arc2 + XPI / 2 + arc1;
		*arc_to = *arc_from + arc;
	}
	else if (clockwise && !largearc)
	{
		*arc_from = arc2 + XPI / 2 - arc1;
		*arc_to = *arc_from - arc;
	}
	else //(!clockwise && largearc)
	{
		*arc_from = -2 * XPI + arc2 + XPI / 2 - arc1;
		*arc_to = 2 * XPI + *arc_from - arc;
	}

	//the center point
	pt[2].fx = (float)(pt[0].fx - rx * cos(*arc_from));
	pt[2].fy = (float)(pt[0].fy - rx * sin(*arc_from));

	pt[2].fx = (float)(pt[1].fx - rx * cos(*arc_to));
	pt[2].fy = (float)(pt[1].fy - rx * sin(*arc_to));

	//restore ellipse from circle
	pt[0].fy = (float)(pt[0].fy * k);
	pt[1].fy = (float)(pt[1].fy * k);
	pt[2].fy = (float)(pt[2].fy * k);

	//recalc ellipse arc from
	fx = pt[0].fx - pt[2].fx;
	fy = pt[0].fy - pt[2].fy;
	arc = atan(fy / fx);

	if (arc_quadrant(*arc_from) == 1)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) > 0 && compare_double(arc, XPI / 2, DEF_DOUBLE_DIGI) < 0)
			*arc_from = arc;
	}
	else if (arc_quadrant(*arc_from) == 2)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) < 0 && compare_double(arc, -XPI/2, DEF_DOUBLE_DIGI) > 0)
			*arc_from = XPI + arc;
	}
	else if (arc_quadrant(*arc_from) == 3)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) > 0 && compare_double(arc, XPI/2, DEF_DOUBLE_DIGI) < 0)
			*arc_from = XPI + arc;
	}
	else
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) < 0 && compare_double(arc, -XPI/2, DEF_DOUBLE_DIGI) > 0)
			*arc_from = 2 * XPI + arc;
	}

	//recalc ellipse arc to
	fx = pt[1].fx - pt[2].fx;
	fy = pt[1].fy - pt[2].fy;
	arc = atan(fy / fx);

	if (arc_quadrant(*arc_to) == 1)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) > 0 && compare_double(arc, XPI / 2, DEF_DOUBLE_DIGI) < 0)
			*arc_to = arc;
	}
	else if (arc_quadrant(*arc_to) == 2)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) < 0 && compare_double(arc, -XPI / 2, DEF_DOUBLE_DIGI) > 0)
			*arc_to = XPI + arc;
	}
	else  if (arc_quadrant(*arc_to) == 3)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) > 0 && compare_double(arc, XPI / 2, DEF_DOUBLE_DIGI) < 0)
			*arc_to = XPI + arc;
	}
	else 
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) < 0 && compare_double(arc, -XPI / 2, DEF_DOUBLE_DIGI) > 0)
			*arc_to = 2 * XPI + arc;
	}

	if (clockwise && compare_double(*arc_from, *arc_to, DEF_DOUBLE_DIGI) < 0)
	{
		if (*arc_from < 0)
			*arc_from += 2 * XPI;
		else
			*arc_to += -2 * XPI;
	}
	else if (!clockwise && compare_double(*arc_from, *arc_to, DEF_DOUBLE_DIGI) > 0)
	{
		if (*arc_from > 0)
			*arc_from += -2 * XPI;
		else
			*arc_to += 2 * XPI;
	}

	ppt_center->x = ROUNDINT(pt[2].fx);
	ppt_center->y = ROUNDINT(pt[2].fy);

	if (ppt1->x <= ppt2->x)
		pt_world_to_screen(*ppt1, ppt_center, 1);
	else
		pt_world_to_screen(*ppt2, ppt_center, 1);

	return cw;
}

bool_t ft_calc_radian(bool_t clockwise, bool_t largearc, float rx, float ry, const xpoint_t* ppt1, const xpoint_t* ppt2, xpoint_t* ppt_center, double* arc_from, double* arc_to)
{
	xpoint_t pt[3] = { 0 };
	double k, len, fx, fy, arc, arc1, arc2;
	bool_t cw;

	if (compare_float(ppt1->fx, ppt2->fx, DEF_FLOAT_DIGI) <= 0)
	{
		pt[0].fx = ppt1->fx;
		pt[0].fy = ppt1->fy;
		pt[1].fx = ppt2->fx;
		pt[1].fy = ppt2->fy;
	}
	else
	{
		pt[0].fx = ppt2->fx;
		pt[0].fy = ppt2->fy;
		pt[1].fx = ppt1->fx;
		pt[1].fy = ppt1->fy;
		clockwise = (clockwise) ? 0 : 1;
	}
	cw = clockwise;

	if (compare_float(ppt1->fx, ppt2->fx, DEF_FLOAT_DIGI) <= 0)
		ft_screen_to_world(*ppt1, pt, 2);
	else
		ft_screen_to_world(*ppt2, pt, 2);

	k = (double)ry / (double)rx;

	//ellipse to circle
	pt[0].fx = (float)pt[0].fx;
	pt[0].fy = (float)(pt[0].fy / k);
	pt[1].fx = (float)pt[1].fx;
	pt[1].fy = (float)(pt[1].fy / k);

	fx = pt[1].fx - pt[0].fx;
	fy = pt[1].fy - pt[0].fy;

	//the half line length (ppt1 to ppt2)
	len = sqrt(pow(fx, 2) + pow(fy, 2)) / 2;

	//the included angle from point1 to point2
	arc = asin(len / rx) * 2;
	arc1 = acos(len / rx);
	arc2 = XPI / 2 + atan(fy / fx);

	if (clockwise && largearc)
	{
		*arc_from = arc2 + XPI / 2 + arc1;
		*arc_to = -2 * XPI + *arc_from + arc;
	}
	else if (!clockwise && !largearc)
	{
		*arc_from = -2 * XPI + arc2 + XPI / 2 + arc1;
		*arc_to = *arc_from + arc;
	}
	else if (clockwise && !largearc)
	{
		*arc_from = arc2 + XPI / 2 - arc1;
		*arc_to = *arc_from - arc;
	}
	else //(!clockwise && largearc)
	{
		*arc_from = -2 * XPI + arc2 + XPI / 2 - arc1;
		*arc_to = 2 * XPI + *arc_from - arc;
	}

	//the center point
	pt[2].fx = (float)(pt[0].fx - rx * cos(*arc_from));
	pt[2].fy = (float)(pt[0].fy - rx * sin(*arc_from));

	pt[2].fx = (float)(pt[1].fx - rx * cos(*arc_to));
	pt[2].fy = (float)(pt[1].fy - rx * sin(*arc_to));

	//restore ellipse from circle
	pt[0].fy = (float)(pt[0].fy * k);
	pt[1].fy = (float)(pt[1].fy * k);
	pt[2].fy = (float)(pt[2].fy * k);

	//recalc ellipse arc from
	fx = pt[0].fx - pt[2].fx;
	fy = pt[0].fy - pt[2].fy;
	arc = atan(fy / fx);

	if (arc_quadrant(*arc_from) == 1)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) > 0 && compare_double(arc, XPI / 2, DEF_DOUBLE_DIGI) < 0)
			*arc_from = arc;
	}
	else if (arc_quadrant(*arc_from) == 2)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) < 0 && compare_double(arc, -XPI / 2, DEF_DOUBLE_DIGI) > 0)
			*arc_from = XPI + arc;
	}
	else if (arc_quadrant(*arc_from) == 3)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) > 0 && compare_double(arc, XPI / 2, DEF_DOUBLE_DIGI) < 0)
			*arc_from = XPI + arc;
	}
	else
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) < 0 && compare_double(arc, -XPI / 2, DEF_DOUBLE_DIGI) > 0)
			*arc_from = 2 * XPI + arc;
	}

	//recalc ellipse arc to
	fx = pt[1].fx - pt[2].fx;
	fy = pt[1].fy - pt[2].fy;
	arc = atan(fy / fx);

	if (arc_quadrant(*arc_to) == 1)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) > 0 && compare_double(arc, XPI / 2, DEF_DOUBLE_DIGI) < 0)
			*arc_to = arc;
	}
	else if (arc_quadrant(*arc_to) == 2)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) < 0 && compare_double(arc, -XPI / 2, DEF_DOUBLE_DIGI) > 0)
			*arc_to = XPI + arc;
	}
	else  if (arc_quadrant(*arc_to) == 3)
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) > 0 && compare_double(arc, XPI / 2, DEF_DOUBLE_DIGI) < 0)
			*arc_to = XPI + arc;
	}
	else
	{
		if (compare_double(arc, 0.0, DEF_DOUBLE_DIGI) < 0 && compare_double(arc, -XPI / 2, DEF_DOUBLE_DIGI) > 0)
			*arc_to = 2 * XPI + arc;
	}

	if (clockwise && compare_double(*arc_from, *arc_to, DEF_DOUBLE_DIGI) < 0)
	{
		if (*arc_from < 0)
			*arc_from += 2 * XPI;
		else
			*arc_to += -2 * XPI;
	}
	else if (!clockwise && compare_double(*arc_from, *arc_to, DEF_DOUBLE_DIGI) > 0)
	{
		if (*arc_from > 0)
			*arc_from += -2 * XPI;
		else
			*arc_to += 2 * XPI;
	}

	ppt_center->fx = (pt[2].fx);
	ppt_center->fy = (pt[2].fy);

	if (compare_float(ppt1->fx, ppt2->fx, DEF_FLOAT_DIGI) <= 0)
		ft_world_to_screen(*ppt1, ppt_center, 1);
	else
		ft_world_to_screen(*ppt2, ppt_center, 1);

	return cw;
}

void pt_calc_points(const xpoint_t* ppt_center, int rx, int ry, double arc_from, double arc_to, bool_t* clockwise, bool_t* largearc, xpoint_t* ppt1, xpoint_t* ppt2)
{
	double fx1, fy1, fx2, fy2, ff;

	ff = tan(arc_from);
	fx1 = 1 / pow(rx, 2);
	fy1 = pow(ff / ry, 2);
	fx1 = sqrt(1.0 / (fx1 + fy1));
	if (arc_quadrant(arc_from) == 2 || arc_quadrant(arc_from) == 3)
	{
		fx1 = 0 - fx1;
	}
	fy1 = fx1 * ff;

	ff = tan(arc_to);
	fx2 = 1 / pow(rx, 2);
	fy2 = pow(ff / ry, 2);
	fx2 = sqrt(1.0 / (fx2 + fy2));
	if (arc_quadrant(arc_to) == 2 || arc_quadrant(arc_to) == 3)
	{
		fx2 = 0 - fx2;
	}
	fy2 = fx2 * ff;

	ff = arc_from - arc_to;
	if (compare_double(ff, 0.0, DEF_DOUBLE_DIGI) > 0)
	{
		*clockwise = 1;
		*largearc = (ff < XPI) ? 0 : 1;
	}
	else
	{
		*clockwise = 0;
		*largearc = (ff > -XPI) ? 0 : 1;
	}

	ppt1->x = ROUNDINT(fx1);
	ppt1->y = ROUNDINT(fy1);
	ppt2->x = ROUNDINT(fx2);
	ppt2->y = ROUNDINT(fy2);

	pt_world_to_screen(*ppt_center, ppt1, 1);
	pt_world_to_screen(*ppt_center, ppt2, 1);
}

void ft_calc_points(const xpoint_t* ppt_center, float rx, float ry, double arc_from, double arc_to, bool_t* clockwise, bool_t* largearc, xpoint_t* ppt1, xpoint_t* ppt2)
{
	double fx1, fy1, fx2, fy2, ff;

	ff = tan(arc_from);
	fx1 = 1 / pow(rx, 2);
	fy1 = pow(ff / ry, 2);
	fx1 = sqrt(1.0 / (fx1 + fy1));
	if (arc_quadrant(arc_from) == 2 || arc_quadrant(arc_from) == 3)
	{
		fx1 = 0 - fx1;
	}
	fy1 = fx1 * ff;

	ff = tan(arc_to);
	fx2 = 1 / pow(rx, 2);
	fy2 = pow(ff / ry, 2);
	fx2 = sqrt(1.0 / (fx2 + fy2));
	if (arc_quadrant(arc_to) == 2 || arc_quadrant(arc_to) == 3)
	{
		fx2 = 0 - fx2;
	}
	fy2 = fx2 * ff;

	ff = arc_from - arc_to;
	if (compare_double(ff, 0.0, DEF_DOUBLE_DIGI) > 0)
	{
		*clockwise = 1;
		*largearc = (ff < XPI) ? 0 : 1;
	}
	else
	{
		*clockwise = 0;
		*largearc = (ff > -XPI) ? 0 : 1;
	}

	ppt1->fx = (float)fx1;
	ppt1->fy = (float)fy1;
	ppt2->fx = (float)fx2;
	ppt2->fy = (float)fy2;

	ft_world_to_screen(*ppt_center, ppt1, 1);
	ft_world_to_screen(*ppt_center, ppt2, 1);
}

void pt_calc_sector(const xpoint_t* ppt, int sl, int ss, double arc_from, double arc_to, xpoint_t* pa, int n)
{
	if (n > 0)
	{
		pa[0].x = (int)((float)sl * cos(arc_from));
		pa[0].y = (int)((float)sl * sin(arc_from));
	}

	if (n > 1)
	{
		pa[1].x = (int)((float)sl * cos(arc_to));
		pa[1].y = (int)((float)sl * sin(arc_to));
	}

	if (n > 2)
	{
		pa[2].x = (int)((float)ss * cos(arc_to));
		pa[2].y = (int)((float)ss * sin(arc_to));
	}

	if (n > 3)
	{
		pa[3].x = (int)((float)ss * cos(arc_from));
		pa[3].y = (int)((float)ss * sin(arc_from));
	}

	pt_world_to_screen(*ppt, pa, n);
}

void ft_calc_sector(const xpoint_t* ppt, float sl, float ss, double arc_from, double arc_to, xpoint_t* pa, int n)
{
	if (n > 0)
	{
		pa[0].fx = (float)((float)sl * cos(arc_from));
		pa[0].fy = (float)((float)sl * sin(arc_from));
	}

	if (n > 1)
	{
		pa[1].fx = (float)((float)sl * cos(arc_to));
		pa[1].fy = (float)((float)sl * sin(arc_to));
	}

	if (n > 2)
	{
		pa[2].fx = (float)((float)ss * cos(arc_to));
		pa[2].fy = (float)((float)ss * sin(arc_to));
	}

	if (n > 3)
	{
		pa[3].fx = (float)((float)ss * cos(arc_from));
		pa[3].fy = (float)((float)ss * sin(arc_from));
	}

	ft_world_to_screen(*ppt, pa, n);
}

void pt_calc_equilater(const xpoint_t* ppt_center, int span, xpoint_t* pa, int n)
{
	double a;
	int i, j;

	if (n < 3) return;

	a = 2 * XPI / n;

	if (n % 2)
	{
		pa[0].x = 0;
		pa[0].y = span;

		for (i = 1; i <= n / 2; i++)
		{
			pa[i].x = (int)(span * cos(a * i + XPI / 2));
			pa[i].y = (int)(span * sin(a * i + XPI / 2));
		}

		for (j = i; j < n; j++)
		{
			pa[j].x = - pa[i - 1].x;
			pa[j].y = pa[i - 1].y;
			i--;
		}
	}
	else
	{
		for (i = 0; i < n / 2; i++)
		{
			pa[i].x = (int)(span * cos(a * i + a / 2 + XPI / 2));
			pa[i].y = (int)(span * sin(a * i + a / 2 + XPI / 2));
		}

		for (j = i; j < n; j++)
		{
			pa[j].x = -pa[i - 1].x;
			pa[j].y = pa[i - 1].y;
			i--;
		}
	}

	pt_world_to_screen(*ppt_center, pa, n);
}

void ft_calc_equilater(const xpoint_t* ppt, float span, xpoint_t* pa, int n)
{
	double a;
	int i, j;

	if (n < 3) return;

	a = 2 * XPI / n;

	if (n % 2)
	{
		pa[0].fx = ppt->fx;
		pa[0].fy = ppt->fy - span;

		for (i = 1; i <= n / 2; i++)
		{
			pa[i].fx = ppt->fx + (int)(span * cos(a * i + XPI / 2));
			pa[i].fy = ppt->fy - (int)(span * sin(a * i + XPI / 2));
		}

		for (j = i; j < n; j++)
		{
			pa[j].fx = ppt->fx - (pa[i - 1].fx - ppt->fx);
			pa[j].fy = pa[i - 1].fy;
			i--;
		}
	}
	else
	{
		for (i = 0; i < n / 2; i++)
		{
			pa[i].fx = ppt->fx + (int)(span * cos(a * i + a / 2 + XPI / 2));
			pa[i].fy = ppt->fy - (int)(span * sin(a * i + a / 2 + XPI / 2));
		}

		for (j = i; j < n; j++)
		{
			pa[j].fx = ppt->fx - (pa[i - 1].fx - ppt->fx);
			pa[j].fy = pa[i - 1].fy;
			i--;
		}
	}
}
