/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc tag text doc document

	@module	tagdoc.h | interface file

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

#ifndef _TAGDOC_H
#define _TAGDOC_H

#include "../xdldef.h"


/************************************************Properties***************************************************************************/

/*
@PROPER name: string.
@GET get_tag_node_name_ptr: get the tag node name.
*/
#define get_tag_node_name_ptr(nlk)				get_dom_node_name_ptr(nlk)
/*
@PROPER name: string.
@SET set_tag_node_name: set the tag node name.
*/
#define set_tag_node_name(nlk,token)			set_dom_node_name(nlk,token,-1)

/*
@PROPER text: string.
@GET set_tag_words_text: get the tag node text.
*/
#define set_tag_chapter_title(nlk,token,len)		set_dom_node_text(nlk,token,len)
/*
@PROPER text: string.
@SET get_tag_words_text_ptr: set the tag joint text.
*/
#define get_tag_chapter_title_ptr(nlk)				get_dom_node_text_ptr(nlk)

/*
@PROPER text: string.
@GET set_tag_words_text: get the tag node text.
*/
#define set_tag_phrase_text(nlk,token,len)		set_dom_node_text(nlk,token,len)
/*
@PROPER text: string.
@SET get_tag_words_text_ptr: set the tag joint text.
*/
#define get_tag_phrase_text_ptr(nlk)				get_dom_node_text_ptr(nlk)

#define tag_phrase_text_set_chars(nlk,pos,pch,n)			dom_node_text_set_chars(nlk, pos, pch,n)

#define tag_phrase_text_ins_chars(nlk,pos,pch,n)			dom_node_text_ins_chars(nlk, pos, pch,n)

#define tag_phrase_text_del_chars(nlk,pos,n)				dom_node_text_del_chars(nlk, pos,n)

#ifdef	__cplusplus
extern "C" {
#endif

/************************************************Fonctions***************************************************************************/

/*
@FUNCTION create_tag_doc: create a tag document.
@RETURN link_t_ptr: return the tag document link component.
*/
EXP_API link_t_ptr create_tag_doc(void);

/*
@FUNCTION destroy_tag_doc: destroy a tag document.
@INPUT link_t_ptr ptr: the tag link component.
@RETURN void: none.
*/
EXP_API void destroy_tag_doc(link_t_ptr ptr);

/*
@FUNCTION is_tag_doc: test is tag document.
@INPUT link_t_ptr ptr: the tag link component.
@RETURN bool_t: return nonzero for being a tag document, otherwise return zero.
*/
EXP_API bool_t is_tag_doc(link_t_ptr ptr);

/*
@FUNCTION clear_tag_doc: clear the tag document.
@INPUT link_t_ptr ptr: the tag link component.
@RETURN void: none.
*/
EXP_API void clear_tag_doc(link_t_ptr ptr);

EXP_API link_t_ptr tag_doc_from_node(link_t_ptr nlk);

EXP_API bool_t is_tag_chapter(link_t_ptr plk);

EXP_API int get_tag_chapter_count(link_t_ptr ptr);

EXP_API link_t_ptr insert_tag_chapter(link_t_ptr ptr, link_t_ptr pos);

EXP_API link_t_ptr get_tag_next_chapter(link_t_ptr ptr, link_t_ptr pos);

EXP_API link_t_ptr get_tag_prev_chapter(link_t_ptr ptr, link_t_ptr pos);

EXP_API bool_t is_tag_paragraph(link_t_ptr plk);

EXP_API int get_tag_paragraph_count(link_t_ptr plk);

EXP_API link_t_ptr insert_tag_paragraph(link_t_ptr plk, link_t_ptr pos);

EXP_API link_t_ptr get_tag_next_paragraph(link_t_ptr ptr, link_t_ptr pos);

EXP_API link_t_ptr get_tag_prev_paragraph(link_t_ptr ptr, link_t_ptr pos);

EXP_API bool_t is_tag_sentence(link_t_ptr plk);

EXP_API int get_tag_sentence_count(link_t_ptr plk);

EXP_API link_t_ptr insert_tag_sentence(link_t_ptr plk, link_t_ptr pos);

EXP_API link_t_ptr get_tag_next_sentence(link_t_ptr plk, link_t_ptr pos);

EXP_API link_t_ptr get_tag_prev_sentence(link_t_ptr plk, link_t_ptr pos);

EXP_API bool_t is_tag_phrase(link_t_ptr plk);

EXP_API int get_tag_phrase_count(link_t_ptr plk);

EXP_API link_t_ptr insert_tag_phrase(link_t_ptr plk, link_t_ptr pos);

EXP_API link_t_ptr get_tag_next_phrase(link_t_ptr plk, link_t_ptr pos);

EXP_API link_t_ptr get_tag_prev_phrase(link_t_ptr plk, link_t_ptr pos);

EXP_API void delete_tag_node(link_t_ptr nlk);

EXP_API link_t_ptr get_tag_next_leaf_node(link_t_ptr ptr, link_t_ptr pos, bool_t add);

EXP_API link_t_ptr get_tag_prev_leaf_node(link_t_ptr ptr, link_t_ptr pos, bool_t add);

EXP_API link_t_ptr merge_tag_chapter(link_t_ptr plk);

EXP_API link_t_ptr split_tag_chapter(link_t_ptr plk, link_t_ptr nlk);

EXP_API link_t_ptr merge_tag_paragraph(link_t_ptr plk);

EXP_API link_t_ptr split_tag_paragraph(link_t_ptr plk, link_t_ptr nlk);

EXP_API link_t_ptr merge_tag_sentence(link_t_ptr plk);

EXP_API link_t_ptr split_tag_sentence(link_t_ptr plk, link_t_ptr nlk);

EXP_API link_t_ptr merge_tag_phrase(link_t_ptr nlk);

EXP_API link_t_ptr split_tag_phrase(link_t_ptr nlk, int pos);

EXP_API int format_tag_doc(link_t_ptr ptr, tchar_t* buf, int max);

EXP_API bool_t parse_tag_doc(link_t_ptr ptr, const tchar_t* buf, int len);

EXP_API bool_t is_tag_text_reserve(tchar_t ch);

#ifdef	__cplusplus
}
#endif


#endif /*_TAGDOC_H*/
