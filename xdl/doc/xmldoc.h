﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xml document

	@module	xmldoc.h | interface file

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

#ifndef _XMLDOC_H
#define _XMLDOC_H

#include "../xdldef.h"


#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION create_xml_doc: create a xml document.
@RETURN link_t_ptr: return the xml document link component.
*/
EXP_API link_t_ptr create_xml_doc(void);

/*
@FUNCTION destroy_xml_doc: destroy a xml document.
@INPUT link_t_ptr ptr: the xml link component.
@RETURN void: none.
*/
EXP_API void destroy_xml_doc(link_t_ptr ptr);

/*
@FUNCTION clear_xml_doc: clear the xml document, all of child nodes in dom body of the xml document will be emptied.
@INPUT link_t_ptr ptr: the xml link component.
@RETURN void: none.
*/
EXP_API void clear_xml_doc(link_t_ptr ptr);

/*
@FUNCTION get_xml_encode: get the xml document encode, it can be _UTF8, _UTF16_BIG, UTF16_LIT, _GB2312.
@INPUT link_t_ptr ptr: the xml link component.
@RETURN int: return the xml document encode.
*/
EXP_API int get_xml_encode(link_t_ptr ptr);

/*
@FUNCTION set_xml_encode: set the xml document encode, it can be _UTF8, _UTF16_BIG, UTF16_LIT, _GB2312.
@INPUT link_t_ptr ptr: the xml link component.
@INPUT int encode: the xml document encode.
@RETURN void: none.
*/
EXP_API void set_xml_encode(link_t_ptr ptr, int encode);

/*
@FUNCTION get_xml_encoding: get the xml document encode token, it can be "UTF-8", "UTF-16", "GB2312".
@INPUT link_t_ptr ptr: the xml link component.
@OUTPUT tchar_t* buf: string buffer for returning encode token.
@RETURN int: return the characters of encode token.
*/
EXP_API int get_xml_encoding(link_t_ptr ptr, tchar_t* buf, int max);

/*
@FUNCTION set_xml_encoding: set the xml document encode token, it can be "UTF-8", "UTF-16", "GB2312".
@INPUT link_t_ptr ptr: the xml link component.
@INPUT const tchar_t* token: the encode string token.
@INPUT int len: the encode token length in characters.
@RETURN void: none.
*/
EXP_API void set_xml_encoding(link_t_ptr ptr, const tchar_t* token, int len);

/*
@FUNCTION get_xml_version: get the xml document version token.
@INPUT link_t_ptr ptr: the xml link component.
@OUTPUT tchar_t* buf: string buffer for returning version token.
@RETURN int: return the characters of version token.
*/
EXP_API int get_xml_version(link_t_ptr ptr, tchar_t* buf, int max);

/*
@FUNCTION set_xml_version: set the xml document version token.
@INPUT link_t_ptr ptr: the xml link component.
@INPUT const tchar_t* token: the version string token.
@INPUT int len: the version token length in characters.
@RETURN void: none.
*/
EXP_API void set_xml_version(link_t_ptr ptr, const tchar_t* token, int len);

/*
@FUNCTION get_xml_attr_table: get the xml document attribute hash table.
@INPUT link_t_ptr ptr: the xml link component.
@RETURN link_t_ptr: the hash table link component.
*/
EXP_API link_t_ptr get_xml_attr_table(link_t_ptr ptr);

/*
@FUNCTION get_xml_dom_node: get the xml document dom body.
@INPUT link_t_ptr ptr: the xml link component.
@RETURN link_t_ptr: the dom document link component.
*/
EXP_API link_t_ptr get_xml_dom_node(link_t_ptr ptr);

/*
@FUNCTION upcast_dom_to_xml: upcast a dom document to xml document.
@INPUT link_t_ptr dom: the dom link component.
@RETURN link_t_ptr: the xml document link component.
*/
EXP_API link_t_ptr upcast_dom_to_xml(link_t_ptr dom);

/*
@FUNCTION downcast_xml_to_dom: downcast a xml document to dom document.
@INPUT link_t_ptr xml: the xml link component.
@RETURN link_t_ptr: the dom document link component.
*/
EXP_API link_t_ptr downcast_xml_to_dom(link_t_ptr xml);


#ifdef	__cplusplus
}
#endif


#endif	/*_XMLDOC_H*/