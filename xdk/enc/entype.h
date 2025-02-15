/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc data type defination document

	@module	entype.h | interface file

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


#ifndef _ENTYPE_H
#define	_ENTYPE_H


#if defined(_UNICODE) || defined(UNICODE)
typedef wchar_t			tchar_t;
#else
typedef char			tchar_t;
#endif

#ifndef schar_t
typedef char			schar_t;
#endif

#ifndef byte_t
typedef unsigned char	byte_t;
#endif

#ifndef bool_t
typedef unsigned int	bool_t;

#define bool_true		((bool_t)1)
#define bool_false		((bool_t)0)
#endif

#ifndef sword_t
typedef unsigned short	sword_t;
#endif

#ifndef dword_t
typedef unsigned int	dword_t;
#endif

#ifndef lword_t
typedef unsigned long long lword_t;
#endif

#ifdef _OS_64
typedef unsigned long long	vword_t;
#else
typedef unsigned int		vword_t;
#endif

#ifndef stamp_t
typedef long long		stamp_t;
#endif

#ifndef wait_t
typedef int				wait_t;
#endif

/*define return code*/
typedef enum{
	C_OK = 0,
	C_ERR = -1,
	C_INFO = 100
}RET_CODE;

/*define waiting code*/
typedef enum{
	WAIT_TMO = -1,
	WAIT_ERR = 0,
	WAIT_RET = 1
}WAT_CODE;


typedef dword_t		key32_t;
typedef lword_t		key64_t;
typedef struct{
	lword_t l;
	lword_t h;
}key128_t;

#endif	/* _ENTYPE_H */

