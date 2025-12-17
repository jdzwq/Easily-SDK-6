/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc math document

	@module	arith.c | implement file

	@devnote 张文权 2021.01 - 2021.12	v6.0
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

#include "arith.h"

#include "../xdkimp.h"
#include "../xdkstd.h"

double DBL_NAN;
double DBL_POSINF;
double DBL_NEGINF;
double NA_REAL;
int	 NA_INTEGER;

#define NAN_HIGH	0x7ff00000
#define NAN_LOW		1954

void dbl_init()
{
    NA_INTEGER = INT_MIN;
    NA_REAL = (double)MAKELWORD(NAN_LOW, NAN_HIGH);
    DBL_NAN = NAN;
    DBL_POSINF = INFINITY;
    DBL_NEGINF = -INFINITY;
}

bool_t dbl_isnar(double x)
{
	lword_t y;

    if (isnan(x)) 
	{
		y = (lword_t)x;
		return (GETLDWORD(y) == NAN_LOW)? bool_true : bool_false;
    }

    return bool_false;
}

static double _dbl_fmod(double x1, double x2)
{
	double x, t;

	if (x2 == 0.0) 
		return DBL_NAN;

	x = x1 / x2;
	t = x1 - floor(x) * x2;
	x = floor(t / x2);
	t -= x * x2;

	return t;
}

static double _dbl_floor(double x1, double x2)
{
	double x, t;

	x = x1 / x2;
	if (x2 == 0.0) 
		return x;
	
	t = x1 - floor(x) * x2;
	x = floor(x);
	t = floor(t / x2);

	return (x + t);
}

// = x ^ y 
double dbl_pow(double x, double y) 
{
    if(y == 2.0)
		return (x * x);

    if(x == 1. || y == 0.)
		return(1.);

    if(x == 0.) 
	{
		if(y > 0.)
			return(0.);
		else if(y < 0) 
			return(DBL_POSINF);
		else 
			return (y); 
    }

    if (isfinite(x) && isfinite(y)) 
   		return pow(x, y);

    if (isnan(x) || isnan(y))
		return (x + y);

    if(!isfinite(x)) 
	{
		if(x > 0)
		{	// Inf ^ y 
	    	return (y < 0.)? 0. : DBL_POSINF;
		}
		else 
		{	// (-Inf) ^ y 
	    	if(isfinite(y) && y == floor(y))
			{	// (-Inf) ^ n 
				if(y < 0.)
					return (0.);
				else if(_dbl_fmod(y, 2.) != 0)
					return (x);
				else
					return (-x);
			}
		}
    }

    if(!isfinite(y)) 
	{
		if(x >= 0) 
		{
	    	if(y > 0)
			{	// y == +Inf 
				return (x >= 1) ? DBL_POSINF : 0.;
			}
	    	else
			{
				// y == -Inf
				return (x < 1) ? DBL_POSINF : 0.;
			}
		}
    }

	// (-Inf)^{+-Inf, non-int}; (neg)^{+-Inf}
    return DBL_NAN; 
}

double dbl_pow_di(double x, int n)
{
    double xn = 1.0;
	bool_t is_neg;

    if (isnan(x)) 
		return x;
	
    if (n == NA_INTEGER) 
		return NA_REAL;

	if(!n)
		return (1.0);

	if (!isfinite(x)) 
		return dbl_pow(x, (double)n);

	is_neg = (n < 0)? 1 : 0;
	if(is_neg) n = -n;
	for(;;) 
	{
	    if(n & 01) xn *= x;
	    if(n >>= 1) x *= x; else break;
	}

	if(is_neg) xn = 1. / xn;

    return xn;
}

static int _int_plus(int x, int y, int *isna)
{
    if (x == NA_INTEGER || y == NA_INTEGER)
	{
		if(isna) *isna = 1;
		return NA_INTEGER;
	}

    if (((y > 0) && (x > (INT_MAX - y))) || ((y < 0) && (x < (INT_MIN - y)))) 
	{
		if(isna) *isna = 1;
		return NA_INTEGER;
    }

	if(isna) *isna = 0;
    return (x + y);
}

static int _int_minus(int x, int y, int *isna)
{
    if (x == NA_INTEGER || y == NA_INTEGER)
	{
		if(isna) *isna = 1;
		return NA_INTEGER;
	}

    if (((y < 0) && (x > (INT_MAX + y))) || ((y > 0) && (x < (INT_MIN + y)))) 
	{
		if(isna) *isna = 1;
		return NA_INTEGER;
    }

	if(isna) *isna = 0;
    return (x - y);
}

#define GOODIPROD(x, y, z) ((double) (x) * (double) (y) == (z))
static int _int_times(int x, int y, int *isna)
{
	int z;

    if (x == NA_INTEGER || y == NA_INTEGER)
	{
		if(isna) *isna = 1;
		return NA_INTEGER;
	}

	z = x * y;
	if (GOODIPROD(x, y, z) && z != NA_INTEGER)
	{
		if(isna) *isna = 0;
	    return z;
	}
	else 
	{
	    if(isna) *isna = 1;
	    return NA_INTEGER;
	}
}

static double _int_divide(int x, int y)
{
    if (x == NA_INTEGER || y == NA_INTEGER)
	{
		return NA_INTEGER;
	}

	return (double) x / (double) y;
}

