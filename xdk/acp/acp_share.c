/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc code page document

	@module	acp_codepage.c | implement file

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

#include "acp.h"

#include "../xdkstd.h"
#include "../xdkimp.h"

bool_t share_gb2312_seek_unicode(unsigned short gbk, unsigned short* ucs)
{
	int ind;
	byte_t* pb;

	if (!acp_gb2312) return bool_false;

	ind = GB2312_CODE_INDEX(gbk);
	if (ind < 0 || ind >= CHS_GB2312_COUNT) return bool_false;

	pb = (byte_t*)xshare_lock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t));
	if (!pb) return bool_false;
	
	*ucs = GET_SWORD_LOC(pb, 0);
	xshare_unlock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t), pb);

	return bool_true;
}

bool_t share_gb2312_seek_help(unsigned short gbk, unsigned short* hlp)
{
	int ind;
	byte_t* pb;

	if (!acp_gb2312) return bool_false;

	ind = GB2312_CODE_INDEX(gbk);
	if (ind < 0 || ind >= CHS_GB2312_COUNT) return bool_false;

	pb = (byte_t*)xshare_lock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t));
	if (!pb) return bool_false;
	
	*hlp = GET_SWORD_LOC(pb, 2);
	xshare_unlock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t), pb);

	return bool_true;
}

vword_t share_get_gb2312_code_addr(unsigned short gbk)
{
	int ind;
	byte_t* pb;
	vword_t bc;

	if (!acp_gb2312) return 0;
	
	ind = GB2312_CODE_INDEX(gbk);
	if (ind < 0 || ind >= CHS_GB2312_COUNT) return 0;

	pb = (byte_t*)xshare_lock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t));
	if (!pb) return 0;

	bc = (vword_t)GET_VOID_LOC(pb, 4);
	xshare_unlock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t), pb);

	return bc;
}

bool_t share_set_gb2312_code_addr(unsigned short gbk, vword_t addr)
{
	int ind;
	byte_t* pb;

	if (!acp_gb2312) return bool_false;

	ind = GB2312_CODE_INDEX(gbk);
	if (ind < 0 || ind >= CHS_GB2312_COUNT) return bool_false;

	pb = (byte_t*)xshare_lock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t));
	if (!pb) return bool_false;

	PUT_VOID_LOC(pb, 4, addr);
	xshare_unlock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t), pb);

	return bool_true;
}

bool_t share_unicode_seek_gb2312(unsigned short ucs, unsigned short* gbk)
{
	int ind;
	byte_t* pb;
	unsigned short ch;

	if (!acp_unicode) return bool_false;

	ind = UNICODE_CODE_INDEX(ucs);
	if (ind < 0 || ind >= CHS_UNICODE_COUNT) return bool_false;
	
	pb = (byte_t*)xshare_lock(acp_unicode, ind * sizeof(acp_table_t), sizeof(acp_table_t));
	if (!pb) return bool_false;
	
	*gbk = GET_SWORD_LOC(pb, 0);
	
	xshare_unlock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t), pb);

	return bool_true;
}

bool_t share_unicode_seek_help(unsigned short ucs, unsigned short* hlp)
{
	int ind;
	byte_t* pb;
	unsigned short bc;

	if (!acp_unicode) return bool_false;

	ind = UNICODE_CODE_INDEX(ucs);
	if (ind < 0 || ind >= CHS_UNICODE_COUNT) return bool_false;
	
	pb = (byte_t*)xshare_lock(acp_unicode, ind * sizeof(acp_table_t), sizeof(acp_table_t));
	if (!pb) return bool_false;
	
	bc = GET_SWORD_LOC(pb, 2);
	xshare_unlock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t), pb);

	if (bc && hlp) *hlp = bc;

	return (bc) ? bool_true : bool_false;
}

vword_t share_get_unicode_code_addr(unsigned short ucs)
{
	int ind;
	byte_t* pb;
	vword_t bc;

	if (!acp_unicode) return 0;
	
	ind = UNICODE_CODE_INDEX(ucs);
	if (ind < 0 || ind >= CHS_UNICODE_COUNT) return 0;

	pb = (byte_t*)xshare_lock(acp_unicode, ind * sizeof(acp_table_t), sizeof(acp_table_t));
	if (!pb) return 0;

	bc = GET_VOID_LOC(pb, 4);
	xshare_unlock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t), pb);

	return bc;
}

bool_t share_set_unicode_code_addr(unsigned short ucs, vword_t addr)
{
	int ind;
	byte_t* pb;

	if (!acp_unicode) return bool_false;

	ind = UNICODE_CODE_INDEX(ucs);
	if (ind < 0 || ind >= CHS_UNICODE_COUNT) return bool_false;

	pb = (byte_t*)xshare_lock(acp_unicode, ind * sizeof(acp_table_t), sizeof(acp_table_t));
	if (!pb) return bool_false;

	PUT_VOID_LOC(pb, 4, addr);
	xshare_unlock(acp_gb2312, ind * sizeof(acp_table_t), sizeof(acp_table_t), pb);

	return bool_true;
}

