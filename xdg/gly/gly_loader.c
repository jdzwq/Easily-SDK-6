/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc glyph loader document

	@module	gly_loader.c | implement file

	@devnote 张文权 2021.01 - 2021.12 v6.0
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

#include "gly.h"

#include "../xdgobj.h"

glyph_info_t a_glyph_list[a_glyph_list_length] = {
	{_T("EN-ARI-M-R-5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-M-R-5.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-M-R-6.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-R-7.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-R-9"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("9"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-R-10.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-R-12"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("12"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-R-14"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("14"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-R-15"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("15"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-R-16"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("16"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-R-18"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("18"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-R-22"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("22"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-M-R-24"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("24"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-M-R-26"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("26"), 40, 40, 40, 0, 0x20, 0x20, 223, 5, NULL, NULL },
	{_T("EN-ARI-M-R-36"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("36"), 48, 48, 48, 0, 0x20, 0x20, 223, 6, NULL, NULL },
	{_T("EN-ARI-M-R-42"), _T("ASCII"), _T("Arial"), _T("medium"), _T("regular"), _T("42"), 56, 56, 56, 0, 0x20, 0x20, 223, 7, NULL, NULL },
	{_T("EN-ARI-B-R-5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-B-R-5.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-B-R-6.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-R-7.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-R-9"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("9"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-R-10.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-R-12"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("12"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-R-14"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("14"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-R-15"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("15"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-R-16"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("16"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-R-18"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("18"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-R-22"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("22"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-B-R-24"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("24"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-B-R-26"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("26"), 40, 40, 40, 0, 0x20, 0x20, 223, 5, NULL, NULL },
	{_T("EN-ARI-B-R-36"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("36"), 48, 48, 48, 0, 0x20, 0x20, 223, 6, NULL, NULL },
	{_T("EN-ARI-B-R-42"), _T("ASCII"), _T("Arial"), _T("bold"), _T("regular"), _T("42"), 56, 56, 56, 0, 0x20, 0x20, 223, 7, NULL, NULL },
	{_T("EN-ARI-M-I-5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-M-I-5.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-M-I-6.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-I-7.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-I-9"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("9"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-I-10.5"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-I-12"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("12"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-M-I-14"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("14"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-I-15"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("15"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-I-16"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("16"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-I-18"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("18"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-M-I-22"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("22"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-M-I-24"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("24"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-M-I-26"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("26"), 40, 40, 40, 0, 0x20, 0x20, 223, 5, NULL, NULL },
	{_T("EN-ARI-M-I-36"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("36"), 48, 48, 48, 0, 0x20, 0x20, 223, 6, NULL, NULL },
	{_T("EN-ARI-M-I-42"), _T("ASCII"), _T("Arial"), _T("medium"), _T("italic"), _T("42"), 56, 56, 56, 0, 0x20, 0x20, 223, 7, NULL, NULL },
	{_T("EN-ARI-B-I-5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-B-I-5.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0x20, 0x20, 223, 1, NULL, NULL },
	{_T("EN-ARI-B-I-6.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-I-7.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-I-9"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("9"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-I-10.5"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-I-12"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("12"), 16, 16, 16, 0, 0x20, 0x20, 223, 2, NULL, NULL },
	{_T("EN-ARI-B-I-14"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("14"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-I-15"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("15"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-I-16"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("16"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-I-18"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("18"), 24, 24, 24, 0, 0x20, 0x20, 223, 3, NULL, NULL },
	{_T("EN-ARI-B-I-22"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("22"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-B-I-24"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("24"), 32, 32, 32, 0, 0x20, 0x20, 223, 4, NULL, NULL },
	{_T("EN-ARI-B-I-26"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("26"), 40, 40, 40, 0, 0x20, 0x20, 223, 5, NULL, NULL },
	{_T("EN-ARI-B-I-36"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("36"), 48, 48, 48, 0, 0x20, 0x20, 223, 6, NULL, NULL },
	{_T("EN-ARI-B-I-42"), _T("ASCII"), _T("Arial"), _T("bold"), _T("italic"), _T("42"), 56, 56, 56, 0, 0x20, 0x20, 223, 7, NULL, NULL },
};

#ifdef XGC_USE_GB2312_GLYPH
glyph_info_t c_glyph_list[c_glyph_list_length] = {
	{_T("CN-ARI-M-R-5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-5.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-6.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-7.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-9"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("9"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-10.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-12"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("12"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-14"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("14"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-15"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("15"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-16"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("16"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-18"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("18"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-22"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("22"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-24"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("24"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-26"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("26"), 40, 40, 40, 0, 0xA1A1, 0xA1A1, 8836, 5, NULL, NULL },
	{_T("CN-ARI-M-R-36"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("36"), 48, 48, 48, 0, 0xA1A1, 0xA1A1, 8836, 6, NULL, NULL },
	{_T("CN-ARI-M-R-42"), _T("GB2312"), _T("Arial"), _T("medium"), _T("regular"), _T("42"), 56, 56, 56, 0, 0xA1A1, 0xA1A1, 8836, 7, NULL, NULL },
	{_T("CN-ARI-M-R-5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-5.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-6.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-7.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-9"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("9"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-10.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-12"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("12"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-14"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("14"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-15"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("15"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-16"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("16"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-18"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("18"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-22"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("22"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-24"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("24"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-26"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("26"), 40, 40, 40, 0, 0xA1A1, 0xA1A1, 8836, 5, NULL, NULL },
	{_T("CN-ARI-M-R-36"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("36"), 48, 48, 48, 0, 0xA1A1, 0xA1A1, 8836, 6, NULL, NULL },
	{_T("CN-ARI-M-R-42"), _T("GB2312"), _T("Arial"), _T("bold"), _T("regular"), _T("42"), 56, 56, 56, 0, 0xA1A1, 0xA1A1, 8836, 7, NULL, NULL },
	{_T("CN-ARI-M-R-5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-5.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-6.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-7.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-9"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("9"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-10.5"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-12"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("12"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-14"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("14"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-15"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("15"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-16"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("16"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-18"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("18"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-22"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("22"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-24"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("24"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-26"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("26"), 40, 40, 40, 0, 0xA1A1, 0xA1A1, 8836, 5, NULL, NULL },
	{_T("CN-ARI-M-R-36"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("36"), 48, 48, 48, 0, 0xA1A1, 0xA1A1, 8836, 6, NULL, NULL },
	{_T("CN-ARI-M-R-42"), _T("GB2312"), _T("Arial"), _T("medium"), _T("italic"), _T("42"), 56, 56, 56, 0, 0xA1A1, 0xA1A1, 8836, 7, NULL, NULL },
	{_T("CN-ARI-M-R-5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-5.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0xA1A1, 0xA1A1, 8836, 1, NULL, NULL },
	{_T("CN-ARI-M-R-6.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-7.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-9"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("9"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-10.5"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-12"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("12"), 16, 16, 16, 0, 0xA1A1, 0xA1A1, 8836, 2, NULL, NULL },
	{_T("CN-ARI-M-R-14"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("14"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-15"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("15"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-16"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("16"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-18"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("18"), 24, 24, 24, 0, 0xA1A1, 0xA1A1, 8836, 3, NULL, NULL },
	{_T("CN-ARI-M-R-22"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("22"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-24"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("24"), 32, 32, 32, 0, 0xA1A1, 0xA1A1, 8836, 4, NULL, NULL },
	{_T("CN-ARI-M-R-26"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("26"), 40, 40, 40, 0, 0xA1A1, 0xA1A1, 8836, 5, NULL, NULL },
	{_T("CN-ARI-M-R-36"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("36"), 48, 48, 48, 0, 0xA1A1, 0xA1A1, 8836, 6, NULL, NULL },
	{_T("CN-ARI-M-R-42"), _T("GB2312"), _T("Arial"), _T("bold"), _T("italic"), _T("42"), 56, 56, 56, 0, 0xA1A1, 0xA1A1, 8836, 7, NULL, NULL },
};
#else
glyph_info_t c_glyph_list[c_glyph_list_length] = {
	{_T("CN-ARI-M-R-5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-M-R-5.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-M-R-6.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-R-7.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-R-9"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("9"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-R-10.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-R-12"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("12"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-R-14"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("14"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-R-15"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("15"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-R-16"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("16"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-R-18"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("18"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-R-22"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("22"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-M-R-24"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("24"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-M-R-26"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("26"), 40, 40, 40, 0, 0x4E00, 0x20, 20902, 5, NULL, NULL },
	{_T("CN-ARI-M-R-36"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("36"), 48, 48, 48, 0, 0x4E00, 0x20, 20902, 6, NULL, NULL },
	{_T("CN-ARI-M-R-42"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("regular"), _T("42"), 56, 56, 56, 0, 0x4E00, 0x20, 20902, 7, NULL, NULL },
	{_T("CN-ARI-B-R-5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-B-R-5.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("5.5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-B-R-6.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("6.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-R-7.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("7.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-R-9"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("9"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-R-10.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("10.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-R-12"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("12"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-R-14"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("14"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-R-15"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("15"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-R-16"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("16"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-R-18"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("18"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-R-22"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("22"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-B-R-24"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("24"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-B-R-26"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("26"), 40, 40, 40, 0, 0x4E00, 0x20, 20902, 5, NULL, NULL },
	{_T("CN-ARI-B-R-36"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("36"), 48, 48, 48, 0, 0x4E00, 0x20, 20902, 6, NULL, NULL },
	{_T("CN-ARI-B-R-42"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("regular"), _T("42"), 56, 56, 56, 0, 0x4E00, 0x20, 20902, 7, NULL, NULL },
	{_T("CN-ARI-M-I-5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-M-I-5.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-M-I-6.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-I-7.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-I-9"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("9"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-I-10.5"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-I-12"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("12"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-M-I-14"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("14"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-I-15"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("15"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-I-16"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("16"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-I-18"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("18"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-M-I-22"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("22"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-M-I-24"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("24"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-M-I-26"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("26"), 40, 40, 40, 0, 0x4E00, 0x20, 20902, 5, NULL, NULL },
	{_T("CN-ARI-M-I-36"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("36"), 48, 48, 48, 0, 0x4E00, 0x20, 20902, 6, NULL, NULL },
	{_T("CN-ARI-M-I-42"),  _T("UNICODE"), _T("Arial"), _T("medium"), _T("italic"), _T("42"), 56, 56, 56, 0, 0x4E00, 0x20, 20902, 7, NULL, NULL },
	{_T("CN-ARI-B-I-5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-B-I-5.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("5.5"), 8, 8, 8, 0, 0x4E00, 0x20, 20902, 1, NULL, NULL },
	{_T("CN-ARI-B-I-6.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("6.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-I-7.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("7.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-I-9"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("9"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-I-10.5"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("10.5"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-I-12"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("12"), 16, 16, 16, 0, 0x4E00, 0x20, 20902, 2, NULL, NULL },
	{_T("CN-ARI-B-I-14"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("14"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-I-15"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("15"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-I-16"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("16"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-I-18"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("18"), 24, 24, 24, 0, 0x4E00, 0x20, 20902, 3, NULL, NULL },
	{_T("CN-ARI-B-I-22"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("22"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-B-I-24"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("24"), 32, 32, 32, 0, 0x4E00, 0x20, 20902, 4, NULL, NULL },
	{_T("CN-ARI-B-I-26"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("26"), 40, 40, 40, 0, 0x4E00, 0x20, 20902, 5, NULL, NULL },
	{_T("CN-ARI-B-I-36"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("36"), 48, 48, 48, 0, 0x4E00, 0x20, 20902, 6, NULL, NULL },
	{_T("CN-ARI-B-I-42"),  _T("UNICODE"), _T("Arial"), _T("bold"), _T("italic"), _T("42"), 56, 56, 56, 0, 0x4E00, 0x20, 20902, 7, NULL, NULL },
};
#endif

static int ascii_glyph_index(byte_t* pch)
{
	return ASCII_GLYPH_INDEX(pch);
}

static int gb2312_glyph_index(byte_t* pch)
{
	return GB2312_GLYPH_INDEX(pch);
}

static int unicode_glyph_index(byte_t* pch)
{
	return UNICODE_GLYPH_INDEX(pch);
}

static dword_t load_glyph_header(byte_t* buf, dword_t len, glyph_info_t* gpm)
{
	byte_t* pre;
	dword_t n, total = 0;

	//glyph encode
	pre = buf;
	n = 0;
	while (*buf != ',' && *buf != '\n' && *buf != '\0')
	{
		buf++;
		n++;
	}
#if defined(_UNICODE) || defined(UNICODE)
	utf8_to_ucs(pre, n, gpm->charset, 31);
#else
	utf8_to_mbs(pre, n, gpm->charset, 31);
#endif

	if (*buf == ',')
	{
		buf++;
		n++;
	}
	total += n;

	//glyph count
	pre = buf;
	n = 0;
	while (*buf != ',' && *buf != '\n' && *buf != '\0')
	{
		buf++;
		n++;
	}
	gpm->characters = a_xsntol((schar_t*)pre, n);

	if (*buf == ',')
	{
		buf++;
		n++;
	}
	total += n;

	//pixel width
	pre = buf;
	n = 0;
	while (*buf != ',' && *buf != '\n' && *buf != '\0')
	{
		buf++;
		n++;
	}
	gpm->width = a_xsntol((schar_t*)pre, n);

	if (*buf == ',')
	{
		buf++;
		n++;
	}
	total += n;

	//pixel heght
	pre = buf;
	n = 0;
	while (*buf != ',' && *buf != '\n' && *buf != '\0')
	{
		buf++;
		n++;
	}
	gpm->height = a_xsntol((schar_t*)pre, n);

	if (*buf == ',')
	{
		buf++;
		n++;
	}
	total += n;

	//name
	pre = buf;
	n = 0;
	while (*buf != ',' && *buf != '\n' && *buf != '\0')
	{
		buf++;
		n++;
	}
#if defined(_UNICODE) || defined(UNICODE)
	utf8_to_ucs(pre, n, gpm->family, 31);
#else
	utf8_to_mbs(pre, n, gpm->family, 31);
#endif

	if (*buf == ',')
	{
		buf++;
		n++;
	}
	total += n;


	//weight
	pre = buf;
	n = 0;
	while (*buf != ',' && *buf != '\n' && *buf != '\0')
	{
		buf++;
		n++;
	}
#if defined(_UNICODE) || defined(UNICODE)
	utf8_to_ucs(pre, n, gpm->weight, 31);
#else
	utf8_to_mbs(pre, n, gpm->weight, 31);
#endif

	if (*buf == ',')
	{
		buf++;
		n++;
	}
	total += n;

	//style
	pre = buf;
	n = 0;
	while (*buf != ',' && *buf != '\n' && *buf != '\0')
	{
		buf++;
		n++;
	}
#if defined(_UNICODE) || defined(UNICODE)
	utf8_to_ucs(pre, n, gpm->style, 31);
#else
	utf8_to_mbs(pre, n, gpm->style, 31);
#endif

	if (*buf == ',')
	{
		buf++;
		n++;
	}
	total += n;

	//size
	pre = buf;
	n = 0;
	while (*buf != ',' && *buf != '\n' && *buf != '\0')
	{
		buf++;
		n++;
	}
#if defined(_UNICODE) || defined(UNICODE)
	utf8_to_ucs(pre, n, gpm->size, 31);
#else
	utf8_to_mbs(pre, n, gpm->size, 31);
#endif

	if (*buf == ',')
	{
		buf++;
		n++;
	}
	total += n;

	//end header
	if (*buf == '\n')
	{
		buf++;
		total++;
	}

	return total;
}

static dword_t save_glyph_header(byte_t* buf, dword_t len, glyph_info_t* gpm)
{
		tchar_t title[1024] = { 0 };
		dword_t dw;
		int n;

		n = xsprintf(title, _T("%s,%d,%d,%d,%s,%s,%s,%s\n"), 
			gpm->charset, 
			gpm->characters, 
			gpm->width, 
			gpm->height,
			gpm->family,
			gpm->weight,
			gpm->style,
			gpm->size);

#if defined(_UNICODE) || defined(UNICODE)
		dw = ucs_to_utf8(title, n, ((buf)? buf : NULL), len);
#else
		dw = mbs_to_utf8(title, n, ((buf)? buf : NULL), len);
#endif
		if(buf) buf[dw] = '\0';

		return dw;
}

static dword_t load_glyph_pixmap(byte_t* buf, dword_t len, glyph_info_t* gpm)
{
	byte_t* pre;
	dword_t m, n, total = 0;
	byte_t pch[3] = { 0 };
	sword_t sw;
	int w, h;
	int i, j, k;
	byte_t *pp, *pb;
	int ind;
	bool_t a;

	//width + pixmap
	m = (2 + gpm->bytesperline * gpm->height);
	gpm->glyph = xshare_cli(gpm->code, m * gpm->characters, FILE_OPEN_CREATE);
	if (!gpm->glyph) return 0;

	pp = (byte_t*)xshare_lock(gpm->glyph, 0, m * gpm->characters);
	if (!pp) return 0;

	a = (xsicmp(gpm->charset, CHARSET_ASCII) == 0)? 1 : 0;

	if(a)
	{
		gpm->pf_index = (GLYPH_INDEX)ascii_glyph_index;
	}else
	{
#ifdef XGC_USE_GB2312_GLYPH
		gpm->pf_index = (GLYPH_INDEX)gb2312_glyph_index;
#else
		gpm->pf_index = (GLYPH_INDEX)unicode_glyph_index;
#endif
	}

	while (total < len && *buf != '\0')
	{
		//char code
		pre = buf;
		n = 0;
		while (*buf != ',' && *buf != '\n' && *buf != '\0')
		{
			buf++;
			n++;
		}
		sw = a_hexntol((schar_t*)pre, n);
		pch[0] = GETHBYTE(sw);
		pch[1] = GETLBYTE(sw);

		if (*buf == ',')
		{
			buf++;
			n++;
		}
		total += n;

		//char width
		pre = buf;
		n = 0;
		while (*buf != ',' && *buf != '\n' && *buf != '\0')
		{
			buf++;
			n++;
		}
		w = a_xsntol((schar_t*)pre, n);

		if (*buf == ',')
		{
			buf++;
			n++;
		}
		total += n;

		//char height
		pre = buf;
		n = 0;
		while (*buf != ',' && *buf != '\n' && *buf != '\0')
		{
			buf++;
			n++;
		}
		h = a_xsntol((schar_t*)pre, n);

		if (*buf == '\n')
		{
			buf++;
			n++;
		}
		total += n;

		//glyph index
		ind = (*gpm->pf_index)(pch);
		if (ind < 0) ind = 0;

		pb = pp + ind * m;
		PUT_SWORD_LOC(pb, 0, (sword_t)w);

		pb += 2;
		//char pixmap
		for (i = 0; i < gpm->height; i++)
		{
			k = i * gpm->bytesperline;
			for (j = 0; j < gpm->bytesperline; j++)
			{
				pre = buf;
				n = 0;
				while (*buf != ' ' && *buf != '\n' && *buf != '\0')
				{
					buf++;
					n++;
				}
				pb[k++] = (byte_t)a_hexntol((schar_t*)pre, n);

				if (*buf == ' ')
				{
					buf++;
					n++;
				}
				total += n;
			}

			if (*buf == '\n')
			{
				buf++;
				total++;
			}
		}
	}

	xshare_unlock(gpm->glyph, 0, m * gpm->characters, pp);

	return total;
}

static dword_t save_glyph_pixmap(byte_t* buf, dword_t len, glyph_info_t* gpm)
{
	bool_t a;
	byte_t pch[2];
	int ind;
	dword_t m;
	byte_t *pp, *pb;
	dword_t dw, total = 0;
	xsize_t xs;
	tchar_t title[1024] = { 0 };
	int n, i, j, k;

	if (!gpm->glyph) return 0;

	// width + pixmap
	m = (2 + gpm->bytesperline * gpm->height);

	pp = (byte_t *)xshare_lock(gpm->glyph, 0, m * gpm->characters);
	if (!pp) return 0;

	a = (xsicmp(gpm->charset, CHARSET_ASCII) == 0)? 1 : 0;

	pch[0] = GETHBYTE(gpm->firstchar);
	pch[1] = GETLBYTE(gpm->firstchar);

	do
	{
		//glyph index
		if (a)
		{
			ind = pch[1] - gpm->firstchar;
		}
		else
		{
#ifdef XGC_USE_GB2312_GLYPH
			ind = GB2312_GLYPH_INDEX(pch);
			if (ind < 0 || ind >= CHS_GB2312_COUNT) ind = 0;
#else
			ind = UNICODE_GLYPH_INDEX(pch);
			if (ind < 0 || ind >= CHS_UNICODE_COUNT) ind = 0;
#endif
		}

		pb = pp + ind * m;
		xs.w = GET_SWORD_LOC(pb, 0);
		xs.h = gpm->height;

		if (a)
			n = xsprintf(title, _T("0x%02X,%d,%d\n"), pch[1], xs.w, xs.h);
		else
			n = xsprintf(title, _T("0x%02X%02X,%d,%d\n"), pch[0], pch[1], xs.w, xs.h);

#if defined(_UNICODE) || defined(UNICODE)
		dw = ucs_to_utf8(title, n, ((buf)? buf : NULL), len);
#else
		dw = mbs_to_utf8(title, n, ((buf)? buf : NULL), len);
#endif
		if(buf) buf[dw] = '\0';
		total += dw;

		pb += 2;
		//char pixmap
		for (i = 0; i < gpm->height; i++)
		{
			k = i * gpm->bytesperline;
			for (j = 0; j < gpm->bytesperline; j++)
			{
				dw = a_xsprintf((schar_t*)((buf)? (buf + total) : NULL), "0x%02X", pb[k++]);
				total += dw;

				if (j == gpm->bytesperline - 1)
				{
					if(buf) buf[total] = '\n';
				}else
				{
					if(buf) buf[total] = ' ';
				}
				total ++;
			}
		}

		if (a)
		{
			acp_next_ascii_char(pch);
		}
		else
		{
#ifdef XGC_USE_GB2312_GLYPH
			acp_next_gb2312_char(pch);
#else
			acp_next_unicode_char(pch);
#endif
		}

	} while (pch[0] || pch[1]);

	xshare_unlock(gpm->glyph, 0, m * gpm->characters, pp);

	return total;
}

bool_t load_glyph_info(const tchar_t* fpath, glyph_info_t* gpm)
{
	tchar_t fname[PATH_LEN + 1] = { 0 };
	tchar_t fsize[INT_LEN + 1] = { 0 };
	xhand_t fhand = NULL;
	dword_t dw, off;
	byte_t* buf = NULL;

	TRY_CATCH;

	if(!is_null(fpath)) 
	{
		xscpy(fname, fpath);
		xscat(fname, _T("/"));
	}

	xsappend(fname, _T("%s-%s-%s-%s-%s.gly"),
					 gpm->charset,
					 gpm->family,
					 gpm->weight,
					 gpm->style,
					 gpm->size);

	if (!xuncf_file_info(NULL, fname, NULL, fsize, NULL, NULL))
	{
		raise_user_error(_T("load_glyph"), _T("xuncf_file_info"));
	}

	fhand = xuncf_open_file(NULL, fname, FILE_OPEN_READ);
	if (!fhand)
	{
		raise_user_error(_T("load_glyph"), _T("xuncf_open_file"));
	}

	dw = xstol(fsize);
	buf = (byte_t*)xmem_alloc(dw);

	if (!xuncf_read_file(fhand, buf, &dw))
	{
		raise_user_error(_T("load_glyph"), _T("xuncf_read_file"));
	}

	xuncf_close_file(fhand);
	fhand = NULL;

	off = load_glyph_header(buf, dw, gpm);

	load_glyph_pixmap((buf + off), (dw - off), gpm);

	xmem_free(buf);
	buf = NULL;

	END_CATCH;

	return bool_true;
ONERROR:
	if (fhand) xuncf_close_file(fhand);
	if (buf) xmem_free(buf);

	return bool_false;
}

bool_t save_glyph_info(const tchar_t* fpath, glyph_info_t* gpm)
{
	tchar_t fname[PATH_LEN + 1] = { 0 };
	xhand_t fhand = NULL;
	dword_t dw;
	byte_t* buf = NULL;

	TRY_CATCH;

	dw = save_glyph_header(NULL, MAX_LONG, gpm);
	dw += save_glyph_pixmap(NULL, MAX_LONG, gpm);

	buf = (byte_t*)xmem_alloc(dw);
	dw = save_glyph_header(buf, MAX_LONG, gpm);
	dw += save_glyph_pixmap((buf + dw), MAX_LONG, gpm);

	if(!is_null(fpath)) 
	{
		xscpy(fname, fpath);
		xscat(fname, _T("/"));
	}

	xsappend(fname, _T("%s-%s-%s-%s-%s.gly"),
					 gpm->charset,
					 gpm->family,
					 gpm->weight,
					 gpm->style,
					 gpm->size);

	fhand = xuncf_open_file(NULL, fname, FILE_OPEN_CREATE);
	if (!fhand)
	{
		raise_user_error(_T("save_glyph"), _T("xuncf_open_file"));
	}

	if (!xuncf_write_file(fhand, buf, &dw))
	{
		raise_user_error(_T("load_glyph"), _T("xuncf_read_file"));
	}

	xmem_free(buf);
	buf = NULL;

	xuncf_close_file(fhand);
	fhand = NULL;

	END_CATCH;

	return bool_true;
ONERROR:
	if (fhand) xuncf_close_file(fhand);
	if (buf) xmem_free(buf);

	return bool_false;
}

bool_t gly_init()
{
	int n,i;
	tchar_t fpath[PATH_LEN + 1] = { 0 };

	get_runpath(NULL, fpath, PATH_LEN);
	xscat(fpath, _T("/gly"));

	n = sizeof(a_glyph_list) / sizeof(glyph_info_t);
	for (i = 0; i < n; i++)
	{
		load_glyph_info(fpath, &(a_glyph_list[i]));
	}

	n = sizeof(c_glyph_list) / sizeof(glyph_info_t);
	for (i = 0; i < n; i++)
	{
		load_glyph_info(fpath, &(c_glyph_list[i]));
	}

	return bool_true;
}

void gly_uninit()
{
	int n, i;

	n = sizeof(a_glyph_list) / sizeof(glyph_info_t);
	for (i = 0; i < n; i++)
	{
		if (a_glyph_list[i].glyph)
		{
			xshare_close(a_glyph_list[i].glyph);
			a_glyph_list[i].glyph = NULL;
		}
	}

	n = sizeof(c_glyph_list) / sizeof(glyph_info_t);
	for (i = 0; i < n; i++)
	{
		if (c_glyph_list[i].glyph)
		{
			xshare_close(c_glyph_list[i].glyph);
			c_glyph_list[i].glyph = NULL;
		}
	}
}

#if defined(DEBUG) || defined(_DEBUG)
bool_t gly_export()
{
	int n,i;
	tchar_t fpath[PATH_LEN + 1] = { 0 };

	get_runpath(NULL, fpath, PATH_LEN);

	n = sizeof(a_glyph_list) / sizeof(glyph_info_t);
	for (i = 0; i < n; i++)
	{
		save_glyph_info(fpath, &(a_glyph_list[i]));
	}

	n = sizeof(c_glyph_list) / sizeof(glyph_info_t);
	for (i = 0; i < n; i++)
	{
		save_glyph_info(fpath, &(c_glyph_list[i]));
	}

	return bool_true;
}
#endif