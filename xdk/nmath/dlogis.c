﻿/*
*  R : A Computer Language for Statistical Data Analysis
*  Copyright (C) 1995, 1996  Robert Gentleman and Ross Ihaka
*  Copyright (C) 2000 The R Core Team
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
*/

#include "Rmath.h"
#include "dpq.h"

double dlogis(double x, double location, double scale, int give_log)
{
	double e, f;
#ifdef IEEE_754
	if (ISNAN(x) || ISNAN(location) || ISNAN(scale))
		return x + location + scale;
#endif
	if (scale <= 0.0)
		return ML_NAN;

	x = fabs((x - location) / scale);
	e = exp(-x);
	f = 1.0 + e;
	return give_log ? -(x + log(scale * f * f)) : e / (scale * f * f);
}

