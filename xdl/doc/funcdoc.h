﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc func document

	@module	funcdoc.h | interface file

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

#ifndef _FUNCDOC_H
#define _FUNCDOC_H

#include "../xdldef.h"


/**********************************************Properties**********************************************/

/*
@PROPER name: string.
@SET set_func_name: set the function node name.
*/
#define set_func_name(ptr,val)								set_dom_node_attr(ptr,ATTR_NAME,-1,val,-1)
/*
@PROPER name: string.
@GET get_func_name_ptr: get the function node node name.
*/
#define get_func_name_ptr(ptr)								get_dom_node_attr_ptr(ptr,ATTR_NAME,-1)
/*
@PROPER dataType: string.
@SET set_func_data_type: set the function data type.
*/
#define set_func_data_type(ptr,val)							set_dom_node_attr(ptr,ATTR_DATA_TYPE,-1,val,-1)
/*
@PROPER dataType: string.
@GET get_func_data_type_ptr: get the function node data type.
*/
#define get_func_data_type_ptr(ptr)							get_dom_node_attr_ptr(ptr,ATTR_DATA_TYPE,-1)
/*
@PROPER text: string.
@SET set_func_return_text: set the function return text.
*/
#define set_func_return_text(ptr,val)						set_dom_node_attr(ptr,ATTR_RETURN,-1,val,-1)
/*
@PROPER text: string.
@GET get_func_return_text_ptr: get the function return text.
*/
#define get_func_return_text_ptr(ptr)						get_dom_node_attr_ptr(ptr,ATTR_RETURN,-1)

#define set_func_return_integer(ptr,val)					set_dom_node_attr_integer(ptr,ATTR_RETURN,val)

#define get_func_return_integer(ptr)						get_dom_node_attr_integer(ptr,ATTR_RETURN)

#define set_func_return_boolean(ptr,val)					set_dom_node_attr_boolean(ptr,ATTR_RETURN,val)

#define get_func_return_boolean(ptr)						get_dom_node_attr_boolean(ptr,ATTR_RETURN)

#define set_func_return_numeric(ptr,val)					set_dom_node_attr_numeric(ptr,ATTR_RETURN,val)

#define get_func_return_numeric(ptr)						get_dom_node_attr_numeric(ptr,ATTR_RETURN)
/*
@PROPER param: string.
@SET set_func_param_name: set the function param name.
*/
#define set_func_param_name(nlk,val)						set_dom_node_attr(nlk,ATTR_NAME,-1,val,-1)
/*
@PROPER param: string.
@GET get_func_param_name_ptr: get the function param name.
*/
#define get_func_param_name_ptr(nlk)						get_dom_node_attr_ptr(nlk,ATTR_NAME,-1)
/*
@PROPER type: string.
@SET set_func_param_type: set the function param type.
*/
#define set_func_param_type(nlk,val)						set_dom_node_attr(nlk,ATTR_PARAM_TYPE,-1,val,-1)
/*
@PROPER type: string.
@GET get_func_param_type_ptr: get the function param type.
*/
#define get_func_param_type_ptr(nlk)						get_dom_node_attr_ptr(nlk,ATTR_PARAM_TYPE,-1)
/*
@PROPER dataType: string.
@SET set_func_param_data_type: set the function param data type.
*/
#define set_func_param_data_type(nlk,val)					set_dom_node_attr(nlk,ATTR_DATA_TYPE,-1,val,-1)
/*
@PROPER dataType: string.
@GET get_func_param_data_type_ptr: get the function param data type.
*/
#define get_func_param_data_type_ptr(nlk)					get_dom_node_attr_ptr(nlk,ATTR_DATA_TYPE,-1)
/*
@PROPER dataLen: integer.
@GET get_func_param_data_len: get the function param data length.
*/
#define get_func_param_data_len(nlk)						get_dom_node_attr_integer(nlk,ATTR_DATA_LEN)
/*
@PROPER dataLen: integer.
@SET set_func_param_data_len: set the function param data length.
*/
#define set_func_param_data_len(nlk,n)						set_dom_node_attr_integer(nlk,ATTR_DATA_LEN,n)
/*
@PROPER digital: integer.
@GET get_func_param_data_dig: get the function param data digital.
*/
#define get_func_param_data_dig(nlk)						get_dom_node_attr_integer(nlk,ATTR_DATA_DIG)
/*
@PROPER digital: integer.
@GET set_func_param_data_dig: set the function param data digital.
*/
#define set_func_param_data_dig(nlk,n)						set_dom_node_attr_integer(nlk,ATTR_DATA_DIG,n)
/*
@PROPER text: string.
@GET get_func_param_text_ptr: set the function param text.
*/
#define get_func_param_text_ptr(nlk)						get_dom_node_text_ptr(nlk)


#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************Functions**********************************************/

/*
@FUNCTION create_func_doc: create a function document.
@RETURN link_t_ptr: return the function document link component.
*/
EXP_API link_t_ptr create_func_doc(void);

/*
@FUNCTION destroy_func_doc: destroy a function document.
@INPUT link_t_ptr ptr: the function document link component.
@RETURN void: none.
*/
EXP_API void destroy_func_doc(link_t_ptr ptr);

/*
@FUNCTION get_func_paramset: get the function parameter set node.
@INPUT link_t_ptr ptr: the function link component.
@RETURN link_t_ptr: return the function paramter set link component if exists otherwise return NULL.
*/
EXP_API link_t_ptr get_func_paramset(link_t_ptr ptr);

/*
@FUNCTION clear_func_doc: clear function document, the parameter set will be emptied.
@INPUT link_t_ptr ptr: the function link component.
@RETURN void: node.
*/
EXP_API void clear_func_doc(link_t_ptr ptr);

/*
@FUNCTION is_func_doc: test is function document.
@INPUT link_t_ptr ptr: the function link component.
@RETURN bool_t: return nonzero if being a function, otherwise return zero.
*/
EXP_API bool_t is_func_doc(link_t_ptr ptr);

/*
@FUNCTION get_func_param: find function paramter node by name.
@INPUT link_t_ptr ptr: the function link component.
@INPUT const tchar_t* key: the paramter name string token.
@INPUT int keylen: the name token length in characters.
@RETURN link_t_ptr: return parameter node link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr	get_func_param(link_t_ptr ptr, const tchar_t* key, int keylen);

/*
@FUNCTION insert_func_param: add a function paramter node at position.
@INPUT link_t_ptr ptr: the function link component.
@INPUT link_t_ptr pos: the paramter link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the new parameter node link.
*/
EXP_API link_t_ptr insert_func_param(link_t_ptr ptr,link_t_ptr pos);

/*
@FUNCTION get_func_param_count: counting the function paramter nodes.
@INPUT link_t_ptr ptr: the function link component.
@RETURN int: return the number of parameters
*/
EXP_API int get_func_param_count(link_t_ptr ptr);

/*
@FUNCTION delete_func_param: delete the function paramter node.
@INPUT link_t_ptr nlk: the function parameter link component.
@RETURN void: none.
*/
EXP_API void delete_func_param(link_t_ptr nlk);

/*
@FUNCTION get_func_next_param: get next function paramter node.
@INPUT link_t_ptr ptr: the function link component.
@INPUT link_t_ptr pos: the parameter link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the next parameter link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_func_next_param(link_t_ptr ptr, link_t_ptr pos);

/*
@FUNCTION get_func_prev_param: get previous function paramter node.
@INPUT link_t_ptr ptr: the function link component.
@INPUT link_t_ptr pos: the parameter link component or link indicator: LINK_FIRST, LINK_LAST.
@RETURN link_t_ptr: return the previous parameter link component if exists, otherwise return NULL.
*/
EXP_API link_t_ptr get_func_prev_param(link_t_ptr ptr, link_t_ptr pos);

/*
@FUNCTION set_func_param_text: set the function paramter node text.
@INPUT link_t_ptr nlk: the parameter link component.
@INPUT const tchar_t* token: the text string token.
@INPUT int len: the length of text token in characters.
@RETURN void: none.
*/
EXP_API void set_func_param_text(link_t_ptr nlk, const tchar_t* token, int len);

/*
@FUNCTION get_func_param_text: copy the function paramter node text.
@INPUT link_t_ptr nlk: the parameter link component.
@OUTPUT tchar_t* buf: the string buffer.
@INPUT int max: the string buffer size in characters.
@RETURN int: return the characters copyed.
*/
EXP_API int get_func_param_text(link_t_ptr nlk, tchar_t* buf, int max);

/*
@FUNCTION set_func_param_boolean: set the function paramter node a boolean value.
@INPUT link_t_ptr nlk: the parameter link component.
@INPUT bool_t b: the boolean value.
@RETURN void: none.
*/
EXP_API void set_func_param_boolean(link_t_ptr nlk, bool_t b);

/*
@FUNCTION get_func_param_boolean: get the function paramter node boolean value.
@INPUT link_t_ptr nlk: the parameter link component.
@RETURN bool_t: return the parameter node boolean value.
*/
EXP_API bool_t get_func_param_boolean(link_t_ptr nlk);

/*
@FUNCTION set_func_param_integer: set the function paramter node a integer value.
@INPUT link_t_ptr nlk: the parameter link component.
@INPUT int n: the integer value.
@RETURN void: none.
*/
EXP_API void set_func_param_integer(link_t_ptr nlk, int n);

/*
@FUNCTION get_func_param_integer: get the function paramter node integer value.
@INPUT link_t_ptr nlk: the parameter link component.
@RETURN int: return the parameter node integer value.
*/
EXP_API int get_func_param_integer(link_t_ptr nlk);

/*
@FUNCTION set_func_param_numeric: set the function paramter node a double value.
@INPUT link_t_ptr nlk: the parameter link component.
@INPUT double n: the double value.
@RETURN void: none.
*/
EXP_API void set_func_param_numeric(link_t_ptr nlk, double n);

/*
@FUNCTION get_func_param_numeric: get the function paramter node double value.
@INPUT link_t_ptr nlk: the parameter link component.
@RETURN double: return the parameter node double value.
*/
EXP_API double get_func_param_numeric(link_t_ptr nlk);

/*
@FUNCTION merge_func_return: merge the source paramter set into destination parameter set, then source paramter set will be empty.
@INPUT link_t_ptr dst: the destination function link component.
@INPUT link_t_ptr src: the source function link component.
@RETURN void: none
*/
EXP_API void merge_func_return(link_t_ptr dst, link_t_ptr src);

/*
@FUNCTION import_func_param: import paramter set from variant array.
@INPUT link_t_ptr ptr: the function link component.
@INPUT const variant_t* pv: the variant array.
@INPUT int n: the number of variant array item.
@RETURN void: none
*/
EXP_API void import_func_param(link_t_ptr ptr, const variant_t* pv, int n);

/*
@FUNCTION export_func_param: export paramter set to variant array.
@INPUT link_t_ptr ptr: the function link component.
@OUTPUT variant_t* pv: the variant array buffer.
@INPUT int n: the variant array size..
@RETURN int: return the number of variant item copied.
*/
EXP_API int export_func_param(link_t_ptr ptr, variant_t* pv, int n);

#ifdef	__cplusplus
}
#endif


#endif /*FUNCDOC_H*/
