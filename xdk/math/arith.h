/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc math document

	@module	arith.h | interface file

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

#ifndef _ARITH_H
#define _ARITH_H

#include "../xdkdef.h"

extern double DBL_NAN;		/* IEEE NaN */
extern double DBL_POSINF;	/* IEEE Inf */
extern double DBL_NEGINF;	/* IEEE -Inf */
extern double NA_REAL;		/* IEEE NA_REAL */
extern int	 NA_INTEGER;	/* IEEE NA_INTEGER */

#ifdef	__cplusplus
extern "C" {
#endif

EXP_API void dbl_init(void);

EXP_API bool_t dbl_is_nar(double x);

EXP_API double dbl_pow(double x, double y);

EXP_API double dbl_pow_di(double x, int n);

#ifdef	__cplusplus
}
#endif

#endif /*_ARITH_H*/
