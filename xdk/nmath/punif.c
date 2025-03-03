﻿/*
*  Mathlib : A C Library of Special Functions
*  Copyright (C) 1998 Ross Ihaka
*  Copyright (C) 2000-2006 The R Core Team
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, a copy is available at
*  https://www.R-project.org/Licenses/
*
*  DESCRIPTION
*
*    The distribution function of the uniform distribution.
*/

#include "Rmath.h"
#include "dpq.h"

double punif(double x, double a, double b, int lower_tail, int log_p)
{
#ifdef IEEE_754
	if (ISNAN(x) || ISNAN(a) || ISNAN(b))
		return x + a + b;
#endif
	if (b < a) return ML_NAN;
	if (!R_FINITE(a) || !R_FINITE(b)) return ML_NAN;

	if (x >= b)
		return R_DT_1;
	if (x <= a)
		return R_DT_0;
	if (lower_tail) return R_D_val((x - a) / (b - a));
	else return R_D_val((b - x) / (b - a));
}

