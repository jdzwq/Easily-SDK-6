/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc ber document

	@module	ber.c | implement file

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

#include "ber.h"

#include "../xdkimp.h"
#include "../xdkstd.h"

/**********************************************************************
ASN.1 BER::= SEQUENCE{ {Identifier} {Length} {Contents} }
	Identifier::= CHIOCE[ {ShortForm} {LongForm} ]
		ShortForm::= {
			Class: BITS[7..6] 
			P/C: BITS[5] 
			BaseType: BITS[4..0] 
		}
		LongForm::= {
			Class: BITS[7..6] 
			P/C: BITS[5] 
			ExtenFlag: BITS[4..0]
			ExtenType: OCTETS
		}
		Class::= ENUM[ Universal：0x00 Application：0x01 Context-specific：0x10 Private：0x11 ]
		P/C::= ENUM[ Primitive: 0x0 Constructed: 0x1 ]
		BaseType::= SET[0x01..0x1E]
		ExtenFlag::= 0x1F
		ExtenType::= { LeadByte ... TailByte }
		LeadByte::= 0x80 | BITS[6..0] ;High Byte of Type value
		TailByte::= 0x00 | BITS[6..0] ;Lower Byte of Type value
	Length::= CHIOCE[ {ShortLength} {UnknownLength} {LongLength} ]
		ShortLength::= SET[0x00..0x7F]
		UnknownLength::= 0x80
		LongLength::= { SomeBytes NumerByte ... NumerByte }
			SomeBytes::= 0x80 | BITS[6..0] ;have some NumerBytes
			NumerByte::= SET[0x00..0xFF] ;in BigEdian order
	Contents::={
		Data: OCTETS
		[OPTIONS]EndofContent::= {0x00 0x00} ;appended response to UnknownLength in Length field
***********************************************************************/

dword_t ber_write_tag(byte_t *buf, byte_t cls, const byte_t* tag, int bys)
{
	dword_t n, total = 0;
	byte_t b;

	//Identifier class
	b = cls & BER_TAG_CLASS_MASK;

	switch(bys)
	{
	case 1:
		if (buf)
		{
			b |= tag[0];
			PUT_BYTE(buf, total, b);
		}
		total++;
		break;
	case 2:
		if (buf)
		{
			b |= 0x1F;
			PUT_BYTE(buf, total, b);

			b = tag[0] | 0x80;
			PUT_BYTE(buf, (total + 1), b);

			b = tag[1] & 0x7F;
			PUT_BYTE(buf, (total + 2), b);
		}
		total += 3;
		break;
	case 4:
		if (buf)
		{
			b |= 0x1F;
			PUT_BYTE(buf, total, b);

			b = tag[0] | 0x80;
			PUT_BYTE(buf, (total + 1), b);

			b = tag[1] | 0x80;
			PUT_BYTE(buf, (total + 2), b);

			b = tag[2] | 0x80;
			PUT_BYTE(buf, (total + 3), b);

			b = tag[3] & 0x7F;
			PUT_BYTE(buf, (total + 4), b);
		}
		total += 5;
		break;
	}

	return total;
}

dword_t ber_read_tag(const byte_t *buf, byte_t* pcls, byte_t *ptag, int bys)
{
	dword_t total = 0;

	XDK_ASSERT(buf != NULL);

	//Identifier cleass
	if(pcls) *pcls = (buf[total] & BER_TAG_CLASS_MASK);
	
	//Identifgier tag
	if((buf[total] & BER_TAG_VALUE_MASK) > 30)
	{ //Long tag
		XDK_ASSERT(buf[total] & BER_TAG_VALUE_MASK == BER_TAG_VALUE_MASK);
		total ++;

		while((buf[total] & 0x80) && bys)
		{
			if (ptag) *ptag++ = (buf[total] & 0x7F);
			bys--;
			total ++;
		}

		if (ptag && bys) *ptag++ = (buf[total] & 0x7F);
		bys--;
		total ++;
	}else
	{ //Short tag
		if (ptag && bys) *ptag = buf[total] & 0x1F;
		bys--;
		total ++;
	}

	return total;
}

dword_t ber_write_length(byte_t *buf, dword_t len)
{
	dword_t total = 0;

	//Length
	if(!len)
	{	//UnknownLength
		if (buf) PUT_BYTE(buf, total, 0x80);
		total++;
	}
	else if (len < 0x80)
	{	//ShortLength
		if (buf) PUT_BYTE(buf, total, (byte_t)len);
		total++;
	}
	else if (len <= 0xFF)
	{	//LongLength: one byte
		if (buf)
		{
			PUT_BYTE(buf, total, 0x81);
			PUT_BYTE(buf, (total + 1), (byte_t)len);
		}
		total += 2;
	}
	else if (len <= 0xFFFF)
	{	//LongLength: two byte
		if (buf)
		{
			PUT_BYTE(buf, total, 0x82);
			PUT_SWORD_NET(buf, (total + 1), (sword_t)len);
		}
		total += 3;
	}
	else if (len <= 0xFFFFFF)
	{	//LongLength: three byte
		if (buf)
		{
			PUT_BYTE(buf, total, 0x83);
			PUT_THREEBYTE_NET(buf, (total + 1), (dword_t)len);
		}
		total += 4;
	}
	else if (len <= 0xFFFFFFFF)
	{	//LongLength: four byte
		if (buf)
		{
			PUT_BYTE(buf, total, 0x84);
			PUT_DWORD_NET(buf, (total + 1), (dword_t)len);
		}
		total += 5;
	}

	return total;
}

dword_t ber_read_length(const byte_t *buf, dword_t* plen)
{
	dword_t len, total = 0;

	XDK_ASSERT(buf != NULL);

	//Length
	if (!(buf[total] & 0x80))
	{	//ShortLength
		if (plen) *plen = buf[total];
		total++;
	}
	else
	{	//LongLength
		switch (buf[total] & 0x7F)
		{
		case 0: //Undefined Length
			if (plen) *plen = 0;
			total += 1;
			break;
		case 1: //one byte octecs
			if (plen) *plen = (int)GET_BYTE(buf, (total + 1));
			total += 2;
			break;
		case 2: //two byte octecs
			if (plen) *plen = (int)GET_SWORD_NET(buf, (total + 1));
			total += 3;
			break;
		case 3: //three byte octecs
			if (plen) *plen = (int)GET_THREEBYTE_NET(buf, (total + 1));
			total += 4;
			break;
		case 4: //four byte octecs
			if (plen) *plen = (int)GET_DWORD_NET(buf, (total + 1));
			total += 5;
			break;
		default:
			total = 0;
			break;
		}
	}

	return total;
}
