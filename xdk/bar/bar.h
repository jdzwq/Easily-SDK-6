
#ifndef _BAR_H
#define	_BAR_H

/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc codepage document

	@module	acp.h | interface file

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

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/***********************************************************************
@FUNCTION: encode binary sequence to code128 sequence.
@INPUT: bytes sequence.
@INPUT: bytes size.
@OUTPUT: byte buffer for returning code128 sequence.
@INPUT: the buffer bytes size.
@RETURN: the bytes of actual code128-encoded sequence.
@NOTE: the parameter buf set to NULL and max set to MAX_LONG, 
	can be used to test the bytes of code128-encoded sequence may be returned.
***********************************************************************/
EXP_API dword_t code128_encode(const byte_t* token, dword_t len, byte_t* buf, dword_t max);

/***********************************************************************
@FUNCTION: get code128 sequence drawing units.
@INPUT: code128-encoded sequence.
@INPUT: column indicated.
@RETURN: the count of code128 drawing units.
***********************************************************************/
EXP_API int code128_units(const byte_t* bar_buf, int cols);

/***********************************************************************
@FUNCTION: encode binary sequence to pdf417 sequence.
@INPUT: bytes sequence.
@INPUT: bytes size.
@OUTPUT: byte buffer for returning pdf417 sequence.
@OUTPUT: rows for returning pdf417 encoded.
@OUTPUT: clos for returning pdf417 encoded.
@INPUT: the buffer bytes size.
@RETURN: the bytes of actual pdf417-encoded sequence.
@NOTE: the parameter buf set to NULL and max set to MAX_LONG, 
	can be used to test the bytes of pdf417-encoded sequence may be returned.
***********************************************************************/
EXP_API dword_t pdf417_encode(const byte_t* token, dword_t len, byte_t* buf, dword_t max, int* prows, int* pcols);

/***********************************************************************
@FUNCTION: get pdf417 sequence drawing units.
@INPUT: pdf417-encoded sequence.
@INPUT: row indicated.
@INPUT: column indicated.
@RETURN: the count of pdf417 drawing units.
***********************************************************************/
EXP_API int pdf417_units(const byte_t* bar_buf, int rows, int cols);

/***********************************************************************
@FUNCTION: encode binary sequence to qrcode sequence.
@INPUT: bytes sequence.
@INPUT: bytes size.
@OUTPUT: byte buffer for returning qrcode sequence.
@OUTPUT: rows for returning qrcode encoded.
@OUTPUT: clos for returning qrcode encoded.
@INPUT: the buffer bytes size.
@RETURN: the bytes of actual qrcode-encoded sequence.
@NOTE: the parameter buf set to NULL and max set to MAX_LONG, 
	can be used to test the bytes of qrcode-encoded sequence may be returned.
***********************************************************************/
EXP_API dword_t qr_encode(const byte_t* token, dword_t len, byte_t* buf, dword_t max, int* prows, int* pcols);

/***********************************************************************
@FUNCTION: get qrcode sequence drawing units.
@INPUT: qrcode-encoded sequence.
@INPUT: row indicated.
@INPUT: column indicated.
@RETURN: the count of qrcode drawing units.
***********************************************************************/
EXP_API int qr_units(const byte_t* bar_buf, int rows, int cols);

#ifdef	__cplusplus
}
#endif


#endif	/*BAR_H */

