﻿/*
*  Mathlib : A C Library of Special Functions
*  Copyright (C) 2002 The R Core Team
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
*  SYNOPSIS
*
*	#include <Rmath.h>
*	double expm1(double x);
*
*  DESCRIPTION
*
*	Compute the Exponential minus 1
*
*			exp(x) - 1
*
*      accurately also when x is close to zero, i.e. |x| << 1
*
*  NOTES
*
*	As log1p(), this is a C99 standard function
*	particularly GNU and BSD (but is neither ISO/ANSI C nor POSIX).
*
*  We supply a substitute for the case when there is no system one
*  (which should not be the case any more).
*/


#include "Rmath.h"


#ifndef MATH_HAVE_EXPM1
double expm1(double x)
{
	double y, a = fabs(x);

	if (a < DBL_EPSILON) return x;
	if (a > 0.697) return exp(x) - 1;  /* negligible cancellation */

	if (a > 1e-8)
		y = exp(x) - 1;
	else /* Taylor expansion, more accurate in this range */
		y = (x / 2 + 1) * x;

	/* Newton step for solving   log(1 + y) = x   for y : */
	/* WARNING: does not work for y ~ -1: bug in 1.5.0 */
	y -= (1 + y) * (log1p(y) - x);
	return y;
}
#endif
