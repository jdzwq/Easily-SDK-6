﻿/*
*  Mathlib : A C Library of Special Functions
*  Copyright (C) 1998 Ross Ihaka
*  Copyright (C) 2013 The R Core Team
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
*    #include <Rmath.h>
*    double ftrunc(double x);
*
*  DESCRIPTION
*
*    Truncation toward zero.
*/

#include "Rmath.h"

#ifdef OLD
double ftrunc(double x)
{
	if (x >= 0) return floor(x);
	else return ceil(x);
}
#else
// use C99 function
double ftrunc(double x)
{
	return trunc(x);
}
#endif

