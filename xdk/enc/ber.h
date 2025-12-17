/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc ASN.1 BER document

	@module	ber.h | interface file

	@devnote 张文权 2021.01 - 2021.12	v6.0
***********************************************************************/

/**********************************************************************
This program is free software : you can redistribute it and/or modify
it unber the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
LICENSE.GPL3 for more details.
***********************************************************************/

#ifndef _BER_H
#define _BER_H

#include "../xdkdef.h"

/**
* These constants comply with the BER encoded ASN.1 type tags.
* BER encoding uses hexadecimal representation.
* An example BER sequence is: TLV
* - 0x02 -- tag indicating INTEGER
* - 0x01 -- length in octets
* - 0x05 -- value
*/
#define BER_BOOLEAN                 0x01 // 1 primitive
#define BER_INTEGER                 0x02 // 2 primitive
#define BER_BIT_STRING              0x03 // 3 primitive or constructed
#define BER_OCTET_STRING            0x04 // 4 primitive or constructed
#define BER_NULL                    0x05 // 5 primitive
#define BER_OID                     0x06 // 6 primitive
#define BER_OBJECT_DESCRIPTOR		0x07 // 7 primitive or constructed
#define BER_EXTERNAL				0x08 // 8 constructed
#define BER_REAL					0x09 // 9 primitive
#define BER_ENUMERATED 				0x0A // 10 primitive
#define BER_EMBEDDED_PDV			0x0B // 11 constructed
#define BER_UTF8_STRING             0x0C // 12 primitive or constructed
#define BER_SEQUENCE                0x10 // 16 constructed
#define BER_SET                     0x11 // 17 constructed
#define BER_NUMERIC_STRING 			0x12 // 18 primitive or constructed
#define BER_PRINTABLE_STRING        0x13 // 19 primitive or constructed
#define BER_T61_STRING              0x14 // 20 primitive or constructed
#define BER_IA5_STRING              0x16 // 22 primitive or constructed
#define BER_UTC_TIME                0x17 // 23 primitive or constructed
#define BER_GENERALIZED_TIME        0x18 // 24 primitive or constructed
#define BER_ISO646_STRING 			0x1A // 26 primitive or constructed
#define BER_GENERAL_STRING 			0x1B // 27 primitive or constructed
#define BER_UNIVERSAL_STRING        0x1C // 28 primitive or constructed
#define BER_BMP_STRING              0x1E // 30 constructed
#define BER_PRIMITIVE               0x00
#define BER_CONSTRUCTED             0x20
#define BER_APPLICATION        		0x40
#define BER_CONTEXT_SPECIFIC        0x80

/*
* Bit masks for each of the components of an ASN.1 tag as specified in
* ITU X.690 (08/2015), section 8.1 "General rules for encoding",
* paragraph 8.1.2.2:
*
* Bit  8     7   6   5          1
*     +-------+-----+------------+
*     | Class | P/C | Tag number |
*     +-------+-----+------------+
*/
#define BER_TAG_CLASS_MASK          0xC0
#define BER_TAG_PC_MASK             0x20
#define BER_TAG_VALUE_MASK          0x1F


#ifdef	__cplusplus
extern "C" {
#endif

EXP_API dword_t ber_write_tag(byte_t *buf, byte_t cls, const byte_t* tag, int bys);

EXP_API dword_t ber_read_tag(const byte_t *buf, byte_t *pcls, byte_t* ptag, int bys);

EXP_API dword_t ber_write_length(byte_t *buf, dword_t len);

EXP_API dword_t ber_read_length(const byte_t *buf, dword_t* plen);

#ifdef	__cplusplus
}
#endif

#endif /*_BER_H*/

