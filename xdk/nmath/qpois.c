﻿/*
 *  Mathlib : A C Library of Special Functions
 *  Copyright (C) 1998 Ross Ihaka
 *  Copyright (C) 2000-2016 The R Core Team
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
 *	The quantile function of the Poisson distribution.
 *
 *  METHOD
 *
 *	Uses the Cornish-Fisher Expansion to include a skewness
 *	correction to a normal approximation.  This gives an
 *	initial value which never seems to be off by more than
 *	1 or 2.	 A search is then conducted of values close to
 *	this initial start point.
 */

#include "Rmath.h"
#include "dpq.h"

static double
do_search(double y, double *z, double p, double lambda, double incr)
{
    if(*z >= p) {
			/* search to the left */
	for(;;) {
	    if(y == 0 ||
	       (*z = ppois(y - incr, lambda, /*l._t.*/1, /*log_p*/0)) < p)
		return y;
	    y = fmax2(0, y - incr);
	}
    }
    else {		/* search to the right */

	for(;;) {
	    y = y + incr;
	    if((*z = ppois(y, lambda, /*l._t.*/1, /*log_p*/0)) >= p)
		return y;
	}
    }
}

double qpois(double p, double lambda, int lower_tail, int log_p)
{
    double mu, sigma, gamma, z, y;
#ifdef IEEE_754
    if (ISNAN(p) || ISNAN(lambda))
	return p + lambda;
#endif
    if(!R_FINITE(lambda))
	return ML_NAN;
    if(lambda < 0) return ML_NAN;
    R_Q_P01_check(p);
    if(lambda == 0) return 0;
    if(p == R_DT_0) return 0;
    if(p == R_DT_1) return ML_POSINF;

    mu = lambda;
    sigma = sqrt(lambda);
    /* gamma = sigma; PR#8058 should be kurtosis which is mu^-0.5 */
    gamma = 1.0/sigma;

    /* Note : "same" code in qpois.c, qbinom.c, qnbinom.c --
     * FIXME: This is far from optimal [cancellation for p ~= 1, etc]: */
    if(!lower_tail || log_p) {
	p = R_DT_qIv(p); /* need check again (cancellation!): */
	if (p == 0.) return 0;
	if (p == 1.) return ML_POSINF;
    }
    /* temporary hack --- FIXME --- */
    if (p + 1.01*DBL_EPSILON >= 1.) return ML_POSINF;

    /* y := approx.value (Cornish-Fisher expansion) :  */
    z = qnorm(p, 0., 1., /*lower_tail*/1, /*log_p*/0);
#ifdef HAVE_NEARBYINT
    y = nearbyint(mu + sigma * (z + gamma * (z*z - 1) / 6));
#else
    y = round(mu + sigma * (z + gamma * (z*z - 1) / 6));
#endif

    z = ppois(y, lambda, /*lower_tail*/1, /*log_p*/0);

    /* fuzz to ensure left continuity; 1 - 1e-7 may lose too much : */
    p *= 1 - 64*DBL_EPSILON;

    /* If the mean is not too large a simple search is OK */
    if(lambda < 1e5) return do_search(y, &z, p, lambda, 1);
    /* Otherwise be a bit cleverer in the search */
    {
	double incr = floor(y * 0.001), oldincr;
	do {
	    oldincr = incr;
	    y = do_search(y, &z, p, lambda, incr);
	    incr = fmax2(1, floor(incr/100));
	} while(oldincr > 1 && incr > lambda*1e-15);
	return y;
    }
}
