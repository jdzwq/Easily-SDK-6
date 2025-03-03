﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xml text io document

	@module	xmlopera.h | interface file

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

#ifndef XMLTIO_H
#define XMLTIO_H

#include "../xdldef.h"


//定义注解符
#define A_CMTOKEN			"--"
#define W_CMTOKEN			L"--"
#define CMTOKEN				_T("--")
#define CMTOKEN_LEN			2

//定义界段符前缀
#define A_CDATA_HEAD		"[CDATA["
#define W_CDATA_HEAD		L"[CDATA["
#define CDATA_HEAD			_T("[CDATA[")
#define CDATA_HEAD_LEN		7
//定义界段符尾缀
#define A_CDATA_TAIL		"]]"
#define W_CDATA_TAIL		L"]]"
#define CDATA_TAIL			_T("]]")
#define CDATA_TAIL_LEN		2


//判断是否需转义的字符
//#define _IsEscapeChar(ch) ((ch == _T('<') || ch == _T('>') || ch == _T('&') || ch == _T('\"') || ch == _T('\'') || ch == _T('/') || ch == _T('\f'))? 1 : 0)
#define _IsEscapeChar(ch) ((ch == _T('<') || ch == _T('>') || ch == _T('&') || ch == _T('\"') || ch == _T('\''))? 1 : 0)

typedef struct _xml_opera_context{
	link_t_ptr doc;
	link_t_ptr nlk;

	link_t_ptr stack;
}xml_opera_context;

#ifdef	__cplusplus
extern "C" {
#endif

LOC_API void call_write_xml_begin(void* p_obj);

LOC_API bool_t call_write_xml_head_attr(void* p_obj, const tchar_t* key, int klen, const tchar_t* val, int vlen);

LOC_API bool_t call_write_xml_node_begin(void* p_obj);

LOC_API bool_t call_write_xml_node_retain(void* pv);

LOC_API bool_t call_write_xml_node_end(void* p_obj);

LOC_API bool_t call_write_xml_node_name(void* p_obj, const tchar_t* ns, int nslen, const tchar_t* na, int nalen);

LOC_API bool_t call_write_xml_node_attr(void* p_obj, const tchar_t* key, int klen, const tchar_t* val, int vlen);

LOC_API bool_t call_write_xml_node_xmlns(void* p_obj, const tchar_t* key, int klen, const tchar_t* val, int vlen);

LOC_API bool_t call_write_xml_node_text(void* p_obj, bool_t b_cdata, const tchar_t* text, int len);

LOC_API bool_t call_write_xml_node_mask(void* pv, dword_t mask, bool_t b_check);

LOC_API link_t_ptr call_peek_xml_node(void* pv);

LOC_API bool_t call_peek_xml_node_mask(void* pv, dword_t mask);

LOC_API const tchar_t* call_peek_xml_node_name(void* pv);

LOC_API void call_write_xml_end(void* p_obj, int code);

LOC_API bool_t call_write_xml_has_node(void* p_obj);


LOC_API bool_t call_read_xml_head_begin(void* pv);

LOC_API bool_t call_read_xml_head_attr(void* pv, const tchar_t* key, const tchar_t* val);

LOC_API bool_t call_read_xml_head_end(void* pv);

LOC_API bool_t call_read_xml_node_attr(void* pv, const tchar_t* key, const tchar_t* val);

LOC_API bool_t call_read_xml_node_begin(void* pv, int indent, bool_t b_parent, const tchar_t* ns, const tchar_t* nn);

LOC_API bool_t call_read_xml_node_close(void* pv, int indent, bool_t b_parent);

LOC_API bool_t call_read_xml_node_text(void* pv, bool_t b_cdata, const tchar_t* text, int len);

LOC_API bool_t call_read_xml_node_end(void* pv, int indent, bool_t b_parent, bool_t b_close, const tchar_t* ns, const tchar_t* nn);

#ifdef	__cplusplus
}
#endif


#endif /*XMLOPERA_H*/
