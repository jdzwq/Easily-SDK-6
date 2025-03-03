﻿/*
 *  Mathlib : A C Library of Special Functions
 *  Copyright (C) 2003-2007     The R Foundation
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
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
 *
 *  SYNOPSIS
 *
 *	#include <Rmath.h>
 *	void rmultinom(int n, double* prob, int K, int* rN);
 *
 *  DESCRIPTION
 *
 *	Random Vector from the multinomial distribution.
 *             ~~~~~~
 *  NOTE
 *	Because we generate random _vectors_ this doesn't fit easily
 *	into the do_random[1-4](.) framework setup in ../main/random.c
 *	as that is used only for the univariate random generators.
 *      Multivariate distributions typically have too complex parameter spaces
 *	to be treated uniformly.
 *	=> Hence also can have  int arguments.
 */

#include "Rmath.h"
#include <stdlib.h>


void rmultinom(int n, double* prob, int K, int* rN)
/* `Return' vector  rN[1:K] {K := length(prob)}
 *  where rN[j] ~ Bin(n, prob[j]) ,  sum_j rN[j] == n,  sum_j prob[j] == 1,
 */
{
    int k;
    double pp;
    LDOUBLE p_tot = 0.;
    /* This calculation is sensitive to exact values, so we try to
       ensure that the calculations are as accurate as possible
       so different platforms are more likely to give the same
       result. */

#ifdef MATHLIB_STANDALONE
	if (K < 1) { MATHLIB_ERROR; return; }
	if (n < 0) { rN[0] = -1; return; }
#else
    if (K == NA_INTEGER || K < 1) { /*ML_ERROR(ME_DOMAIN, "rmultinom"); */return;}
	if (n == NA_INTEGER || n < 0) {rN[0]=-1; return;}
#endif

    /* Note: prob[K] is only used here for checking  sum_k prob[k] = 1 ;
     *       Could make loop one shorter and drop that check !
     */
    for(k = 0; k < K; k++) {
	pp = prob[k];
	if (!R_FINITE(pp) || pp < 0. || pp > 1.) { rN[k] = -1; return; }
	p_tot += pp;
	rN[k] = 0;
    }
	if (fabs((double)(p_tot - 1.)) > 1e-7)
	{
		//MATHLIB_ERROR(_("rbinom: probability sum should be 1, but is %g"), (double)p_tot);
	}
    if (n == 0) return;
    if (K == 1 && p_tot == 0.) return;/* trivial border case: do as rbinom */

    /* Generate the first K-1 obs. via binomials */

    for(k = 0; k < K-1; k++) { /* (p_tot, n) are for "remaining binomial" */
	if(prob[k] != 0.) {
	    pp = (double)(prob[k] / p_tot);
	    /* printf("[%d] %.17f\n", k+1, pp); */
	    rN[k] = ((pp < 1.) ? (int) rbinom((double) n,  pp) :
		     /*>= 1; > 1 happens because of rounding */
		     n);
	    n -= rN[k];
	}
	else rN[k] = 0;
	if(n <= 0) /* we have all*/ return;
	p_tot -= prob[k]; /* i.e. = sum(prob[(k+1):K]) */
    }
    rN[K-1] = n;
    return;
}

