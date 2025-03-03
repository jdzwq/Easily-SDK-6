﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc JSON parse document

	@module	jsonparser.c | implement file

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

#include "jsonparser.h"

#include "../xdldoc.h"



#define _IsSkipChar(ch) ((ch == _T(' ') || ch == _T('\t') || ch == _T('\n')  || ch == _T('\r'))? 1 : 0)

#define idle		while(0 == 1)

#if defined(UNICODE) || defined(_UNICODE)
#define _IsBomChar(pch)	((*pch == _UTF16_LIT || *pch == _UTF16_LIT)? 1 : 0)
#else
#define _IsBomChar(pch)	((pch[0] == 0xEF && pch[1] == 0xBB && pch[2] == 0xBF)? 1 : 0)
#endif

//以下定义自动机的状态
typedef enum{
	JSON_FAILED	= -1,		//错误中断
	JSON_SUCCEED = 0,		//解析正常结束

	JSON_SKIP = 1,
	JSON_OPEN = 10,			//标记打开{
	JSON_CLOSE = 11,			//标记关闭}

	JSON_ITEM_BEGIN = 110,
	JSON_ITEM_END = 111,
	JSON_ITEM_RET = 112,
	JSON_NAME_QUOT = 120,	//元素名括号
	JSON_NAME_BEGIN = 121,	//元素名开始
	JSON_NAME_END = 122,		//元素名结束
	JSON_ASIGN = 160,		//元素属性赋值
	JSON_ARRAY_BEGIN = 170,	//元素属性数组开始
	JSON_ARRAY_END = 171,	//元素属性数组开始
	JSON_QUOT_BEGIN = 180,	//元素属性值括号开始
	JSON_QUOT_END = 181,	//元素属性值括号结束
	JSON_VALUE_BEGIN = 182,	//元素属性值开始
	JSON_VALUE_ESCAPE = 183,	//元素属性值转义
	JSON_VALUE_END = 184,	//元素属性值结束
}JSONSTATUS;

//以下定义读写头动作
typedef enum{
	PAUSE = 0,	//暂停于当前字符
	NEXT = 1,	//读取当前字符
	SKIP = 2,	//略过当前字符
	STOP = -1	//停机	
}JSONACTION;

//以下定义栈动作
typedef enum{
	NOO = 0,	//无操作
	PUSH = 1,	//入栈
	POP = 2		//出栈
}JSONOPERA;

//定义自动机
typedef struct _MATA{
	int ma;		//读写头动作
	int mo;		//栈动作
	int ms;		//当前状态

	bool_t quot; //值是否有引号
	tchar_t org[ESC_LEN + 1];//上一字
	tchar_t cur[ESC_LEN + 1];//当前字
	int bytes;	//扫描字节数
}JSONMATA;


//解析JSON文本
bool_t parse_json_doc_from_object(link_t_ptr ptr, opera_interface* pbo)
{
	string_t vs_name, vs_val;
	JSONMATA ma = { 0 };
	bool_t b_ret = 0;
	int pos;

	link_t_ptr st = NULL;
	link_t_ptr nlk;

	tchar_t errtext[ERR_LEN + 1] = { 0 };

	clear_json_doc(ptr);

	vs_name = string_alloc();
	vs_val = string_alloc();

	st = create_stack_table();
	
	//自动机初始化
	ma.ma = NEXT;
	ma.mo = NOO;
	ma.ms = JSON_SKIP;
	ma.bytes = 0;

	nlk = ptr;
	pos = 0;
	while(ma.ma != STOP)
	{
		if (ma.ma == NEXT || ma.ma == SKIP)
		{
			ma.bytes += pos;

			xscpy(ma.org, ma.cur);
			xmem_zero((void*)ma.cur, sizeof(ma.cur));

			//读取下一字符
			pos = (*pbo->pf_read_char)(pbo->ctx, pbo->max, ma.bytes, pbo->encode, ma.cur);
			if (pos <= 0)
			{
				ma.cur[0] = _T('\0');
				pos = 0;
			}

			//忽略BOM
			if (_IsBomChar(ma.cur))
			{
				xmem_zero((void*)ma.cur, sizeof(ma.cur));
				ma.cur[0] = _T(' ');
			}
		}

		//根据自动机状态跳转
		switch (ma.ms)
		{
		case JSON_SKIP: //空闲略过
			if (_IsSkipChar(ma.cur[0])){ ma.mo = NOO; ma.ms = JSON_SKIP; ma.ma = NEXT; }	//忽略起始空格
			else if (ma.cur[0] == _T('{')){ ma.mo = NOO; ma.ms = JSON_OPEN; ma.ma = PAUSE; } //遇到标记
			else if (ma.cur[0] == _T('\0')) { ma.mo = NOO; ma.ms = JSON_SUCCEED, ma.ma = STOP; }	//终结符
			else { ma.mo = NOO; ma.ms = JSON_SKIP; ma.ma = NEXT; }	//无效字符
			break;
		case JSON_OPEN: //标记打开
			if (ma.cur[0] == _T('{')){ ma.mo = PUSH; ma.ms = JSON_OPEN; ma.ma = NEXT; } //遇到标记
			else if (_IsSkipChar(ma.cur[0])){ ma.mo = NOO; ma.ms = JSON_OPEN; ma.ma = NEXT; } //忽略空格
			else if (ma.cur[0] == _T('\"')){ ma.mo = NOO; ma.ms = JSON_ITEM_BEGIN; ma.ma = PAUSE; } //元素名括号
			else if (ma.cur[0] == _T('}')){ ma.mo = NOO; ma.ms = JSON_CLOSE; ma.ma = PAUSE; } //元素关闭
			else { ma.mo = NOO; ma.ms = JSON_FAILED; ma.ma = STOP; } //无效字符
			break;
		case JSON_ITEM_BEGIN: //元素命名开始
			if (ma.cur[0] == _T('\"')){ ma.mo = NOO; ma.ms = JSON_NAME_QUOT; ma.ma = NEXT; } //元素名括号
			else { ma.mo = NOO; ma.ms = JSON_FAILED; ma.ma = STOP; } //无效字符
			break;
		case JSON_NAME_QUOT: //元素命名开始
			{ma.mo = NOO; ma.ms = JSON_NAME_BEGIN; ma.ma = PAUSE; } //过渡到元素名
			break;
		case JSON_NAME_BEGIN: //元素命名开始
			if (ma.cur[0] == _T('\"')){ ma.mo = NOO; ma.ms = JSON_NAME_END; ma.ma = PAUSE; }//元素名结束
			else { ma.mo = NOO; ma.ms = JSON_NAME_BEGIN; ma.ma = NEXT; } //元素名继续
			break;
		case JSON_NAME_END: //元素命名结束
			if (ma.cur[0] == _T('\"')){ ma.mo = NOO; ma.ms = JSON_NAME_END; ma.ma = NEXT; }//元素名结束
			else if (_IsSkipChar(ma.cur[0])){ ma.mo = NOO; ma.ms = JSON_NAME_END; ma.ma = NEXT; } //忽略空格
			else if (ma.cur[0] == _T(':')){ ma.mo = NOO; ma.ms = JSON_ASIGN; ma.ma = NEXT; } //元素名结束
			else { ma.mo = NOO; ma.ms = JSON_FAILED; ma.ma = STOP; } //无效字符
			break;
		case JSON_ASIGN: //元素属性赋值
			if (_IsSkipChar(ma.cur[0])){ ma.mo = NOO; ma.ms = JSON_ASIGN; ma.ma = NEXT; } //忽略空格
			else if (ma.cur[0] == _T('{')){ ma.mo = NOO; ma.ms = JSON_OPEN; ma.ma = PAUSE; } //数组开始
			else if (ma.cur[0] == _T('[')){ ma.mo = NOO; ma.ms = JSON_ARRAY_BEGIN; ma.ma = PAUSE; } //数组开始
			else if (ma.cur[0] == _T('\"')){ ma.mo = NOO; ma.ms = JSON_QUOT_BEGIN; ma.ma = NEXT; } //过渡到属性值开始
			else { ma.mo = NOO; ma.ms = JSON_VALUE_BEGIN; ma.ma = PAUSE; } //
			break;
		case JSON_ARRAY_BEGIN:
			if (ma.cur[0] == _T('[')){ ma.mo = NOO; ma.ms = JSON_ARRAY_BEGIN; ma.ma = NEXT; } //数组开始
			else if (_IsSkipChar(ma.cur[0])){ ma.mo = NOO; ma.ms = JSON_ARRAY_BEGIN; ma.ma = NEXT; } //忽略空格
			else if (ma.cur[0] == _T('{')){ ma.mo = NOO; ma.ms = JSON_OPEN; ma.ma = PAUSE; } //对象开始
			else if (ma.cur[0] == _T('\"')){ ma.mo = NOO; ma.ms = JSON_QUOT_BEGIN; ma.ma = NEXT; } //过渡到属性值开始
			else if (ma.cur[0] == _T(',')){ ma.mo = NOO; ma.ms = JSON_VALUE_END; ma.ma = PAUSE; } //过渡到属性值结束
			else if (ma.cur[0] == _T(']')){ ma.mo = NOO; ma.ms = JSON_VALUE_END; ma.ma = PAUSE; } //过渡到属性值结束
			else if (ma.cur[0] == _T('}')){ ma.mo = NOO; ma.ms = JSON_VALUE_END; ma.ma = PAUSE; } //过渡到属性值结束
			else { ma.mo = NOO; ma.ms = JSON_VALUE_BEGIN; ma.ma = PAUSE; } 
			break;
		case JSON_QUOT_BEGIN: //元素属性引号开始
			{ ma.mo = NOO; ma.ms = JSON_VALUE_BEGIN; ma.ma = PAUSE; ma.quot = 1; } //过渡到属性值开始
			break;
		case JSON_VALUE_BEGIN: //元素属性值开始
			if (ma.quot == 1 && ma.cur[0] == _T('\"')){ ma.mo = NOO; ma.ms = JSON_QUOT_END; ma.ma = NEXT; } //过渡到属性值结束
			else if (ma.quot == 1 && ma.cur[0] == _T('\\')){ ma.mo = NOO; ma.ms = JSON_VALUE_ESCAPE; ma.ma = SKIP; } //过渡到属性值转义
			else if (ma.quot == 2 && ma.cur[0] == _T('\\')){ ma.mo = NOO; ma.ms = JSON_VALUE_ESCAPE; ma.ma = SKIP; } //过渡到属性值转义
			else if (!ma.quot && ma.cur[0] == _T(',')){ ma.mo = NOO; ma.ms = JSON_VALUE_END; ma.ma = PAUSE; } //过渡到属性值结束
			else if (!ma.quot && ma.cur[0] == _T(']')){ ma.mo = NOO; ma.ms = JSON_VALUE_END; ma.ma = PAUSE; } //过渡到属性值结束
			else if (!ma.quot && ma.cur[0] == _T('}')){ ma.mo = NOO; ma.ms = JSON_VALUE_END; ma.ma = PAUSE; } //过渡到属性值结束
			else { ma.mo = NOO; ma.ms = JSON_VALUE_BEGIN; ma.ma = NEXT; } //继续属性值
			break;
		case JSON_VALUE_ESCAPE: //元素属性转义
			if (ma.quot == 1 && ma.cur[0] == _T('\"')){ ma.mo = NOO; ma.ms = JSON_VALUE_BEGIN; ma.ma = NEXT; ma.quot++; } //继续属性值
			else if (ma.quot == 2 && ma.cur[0] == _T('\"')){ ma.mo = NOO; ma.ms = JSON_VALUE_BEGIN; ma.ma = NEXT; ma.quot--; } //继续属性值
			else { ma.mo = NOO; ma.ms = JSON_VALUE_BEGIN; ma.ma = SKIP; } //继续属性值
			break;
		case JSON_QUOT_END: //元素属性引号结束
			{ ma.mo = NOO; ma.ms = JSON_VALUE_END; ma.ma = PAUSE; } //过渡到属性值开始
			break;
		case JSON_VALUE_END: //元素属性值结束
			if (ma.cur[0] == _T(',')){ ma.mo = NOO; ma.ms = JSON_ITEM_END; ma.ma = PAUSE; } //属性值结束
			else if (ma.cur[0] == _T(']')){ ma.mo = NOO; ma.ms = JSON_ITEM_END; ma.ma = PAUSE; } //属性值结束
			else if (ma.cur[0] == _T('}')){ ma.mo = NOO; ma.ms = JSON_ITEM_END; ma.ma = PAUSE; } //属性值结束
			else if (_IsSkipChar(ma.cur[0])){ ma.mo = NOO; ma.ms = JSON_VALUE_END; ma.ma = NEXT; } //忽略空格
			else { ma.mo = NOO; ma.ms = JSON_FAILED; ma.ma = STOP; } //无效字符
			break;
		case JSON_ITEM_END: //元素命名中断
			if (ma.cur[0] == _T(',')){ ma.mo = NOO; ma.ms = (b_ret) ? JSON_ITEM_RET : JSON_ITEM_END; ma.ma = (b_ret) ? PAUSE : NEXT; } //属性结束
			else if (_IsSkipChar(ma.cur[0])){ ma.mo = NOO; ma.ms = JSON_ITEM_END; ma.ma = NEXT; } //忽略空格
			else if (ma.cur[0] == _T('\"')){ ma.mo = NOO; ma.ms = JSON_ITEM_BEGIN; ma.ma = PAUSE; } //属性结束
			else if (ma.cur[0] == _T(']')){ ma.mo = NOO; ma.ms = JSON_ARRAY_END; ma.ma = PAUSE; } //属性结束
			else if (ma.cur[0] == _T('}')){ ma.mo = NOO; ma.ms = JSON_CLOSE; ma.ma = PAUSE; } //属性结束
			else { ma.mo = NOO; ma.ms = JSON_FAILED; ma.ma = STOP; } //无效字符
			break;
		case JSON_ITEM_RET:
			if (ma.cur[0] == _T(',')){ ma.mo = NOO; ma.ms = JSON_ITEM_RET; ma.ma = NEXT; } //属性结束
			else if (_IsSkipChar(ma.cur[0])){ ma.mo = NOO; ma.ms = JSON_ITEM_RET; ma.ma = NEXT; } //忽略空格
			else if (ma.cur[0] == _T('{')){ ma.mo = NOO; ma.ms = JSON_OPEN; ma.ma = PAUSE; } //过渡到属性值开始
			else if (ma.cur[0] == _T('\"')){ ma.mo = NOO; ma.ms = JSON_QUOT_BEGIN; ma.ma = NEXT; } //过渡到属性值开始
			else { ma.mo = NOO; ma.ms = JSON_VALUE_BEGIN; ma.ma = PAUSE; } //过渡到元素值
			break;
		case JSON_ARRAY_END:
			if (ma.cur[0] == _T(']')){ ma.mo = NOO; ma.ms = JSON_ARRAY_END; ma.ma = NEXT; } //属性结束
			else if (_IsSkipChar(ma.cur[0])){ ma.mo = NOO; ma.ms = JSON_ARRAY_END; ma.ma = NEXT; } //忽略空格
			else if (ma.cur[0] == _T(',')){ ma.mo = NOO; ma.ms = JSON_ITEM_END; ma.ma = PAUSE; } //属性结束
			else if (ma.cur[0] == _T('}')){ ma.mo = NOO; ma.ms = JSON_ITEM_END; ma.ma = PAUSE; } //属性结束
			else { ma.mo = NOO; ma.ms = JSON_FAILED; ma.ma = STOP; } //无效字符
			break;
		case JSON_CLOSE: //元素关闭
			if (ma.cur[0] == _T('}')){ ma.mo = POP; ma.ms = JSON_CLOSE; ma.ma = NEXT; } //属性结束
			else if (_IsSkipChar(ma.cur[0])){ ma.mo = NOO; ma.ms = JSON_CLOSE; ma.ma = NEXT; } //忽略空格
			else if (ma.cur[0] == _T(']')){ ma.mo = NOO; ma.ms = JSON_ARRAY_END; ma.ma = PAUSE; } //属性结束
			else if (ma.cur[0] == _T(',')){ ma.mo = NOO; ma.ms = JSON_ITEM_END; ma.ma = PAUSE; } //属性结束
			else {ma.mo = NOO; ma.ms = JSON_SKIP; ma.ma = PAUSE; } //
			break;
		default:
			{ma.mo = NOO; ma.ms = JSON_FAILED; ma.ma = STOP; } //无效字符
			break;
		}
	
		//根据自动机的状态决定是否退出
		if (ma.ms == JSON_FAILED || ma.ms == JSON_SUCCEED)
			break;

		if (ma.ms == JSON_ARRAY_BEGIN && ma.ma == PAUSE)
		{
			b_ret = 1;
			set_json_item_array(nlk, b_ret);
		}
		if (ma.ms == JSON_ARRAY_END && ma.ma == PAUSE)
		{
			b_ret = 0;
		}

		if ((ma.ms == JSON_NAME_BEGIN || ma.ms == JSON_ITEM_RET) && ma.ma == PAUSE)
		{
			nlk = (link_t_ptr)peek_stack_node(st, -1);
			nlk = insert_json_item(((nlk)? nlk : ptr), LINK_LAST);

			if (ma.ms == JSON_ITEM_RET)
			{
				set_json_item_array(nlk, b_ret);
			}
		}

		//根据自动机状态处置
		if(ma.ms == JSON_OPEN)
		{
			idle;
		}
		else if (ma.ms == JSON_ITEM_BEGIN)
		{
			idle;
		}
		else if (ma.ms == JSON_NAME_BEGIN)
		{
			switch(ma.ma)
			{
			case PAUSE:
				string_empty(vs_name);
				break;
			case NEXT:
				string_cat(vs_name, ma.cur, -1);
				break;
			}
		}else if(ma.ms == JSON_NAME_END)
		{
			switch(ma.ma)
			{
			case PAUSE:
				set_json_item_name(nlk, string_ptr(vs_name));
				break;
			case NEXT:
				break;
			}
		}
		else if (ma.ms == JSON_ITEM_RET)
		{
			switch (ma.ma)
			{
			case PAUSE:
				set_json_item_name(nlk, string_ptr(vs_name));
				break;
			case NEXT:
				break;
			}
		}
		else if (ma.ma == JSON_ASIGN)
		{
			idle;
		}else if(ma.ms == JSON_VALUE_BEGIN)
		{
			switch(ma.ma)
			{
			case PAUSE:
				string_empty(vs_val);
				break;
			case NEXT:
				string_cat(vs_val, ma.cur, -1);
				break;
			}
		}else if(ma.ms == JSON_VALUE_END)
		{
			switch(ma.ma)
			{
			case PAUSE:
				if (!ma.quot && xsicmp(string_ptr(vs_val), _T("null")) == 0)
					set_json_item_null(nlk, 1);
				else
					set_json_item_value(nlk, string_ptr(vs_val));

				if (!ma.quot)
					set_json_item_number(nlk, 1);
				else
					ma.quot = 0;
				break;
			case NEXT:
				break;
			}
		}
		else if (ma.ms == JSON_ITEM_END)
		{
			idle;
		}
		else if(ma.ms == JSON_CLOSE)
		{
			idle;
		}

		if (ma.mo == PUSH)
		{
			push_stack_node(st, (void*)nlk);
			
			ma.mo = NOO;

			b_ret = 0;
		}
		else if (ma.mo == POP)
		{
			nlk = (link_t_ptr)pop_stack_node(st);

			ma.mo = NOO;

			b_ret = get_json_item_array(nlk);

			string_cpy(vs_name, get_json_item_name_ptr(nlk), -1);

			if (peek_stack_node(st, 0) == NULL && ma.cur[0] == _T('}'))
			{
				ma.ma = STOP;
				ma.ms = JSON_SUCCEED;
			}
		}

	}

	destroy_stack_table(st);

	string_free(vs_name);
	string_free(vs_val);

	if (ma.ms != JSON_SUCCEED)
	{
		xsprintf(errtext, _T("json parse break at bytes: %d, the last byte is %s\n"), ma.bytes, ma.org);

		set_last_error(_T("-1"), errtext, -1);
	}

	//自动机的最终状态
	return (ma.ms == JSON_SUCCEED)? 1 : 0;
}


/***********************************************************************************************/
#define JSON_ARRAY_NONE		0
#define JSON_ARRAY_FIRST	1
#define JSON_ARRAY_NEXT		2
#define JSON_ARRAY_LAST		3
#define JSON_ARRAY_ONCE		4

static int _test_json_item(link_t_ptr nlk)
{
	link_t_ptr pre, nxt;
	const tchar_t *fname, *nname, *lname;

	pre = get_json_prev_sibling_item(nlk);
	nxt = get_json_next_sibling_item(nlk);

	fname = (pre) ? get_json_item_name_ptr(pre) : NULL;
	nname = get_json_item_name_ptr(nlk);
	lname = (nxt) ? get_json_item_name_ptr(nxt) : NULL;

	if (compare_text(nname, -1, fname, -1, 0) == 0 && compare_text(nname, -1, lname, -1, 0) == 0)
		return JSON_ARRAY_NEXT;
	else if (compare_text(nname, -1, fname, -1, 0) == 0)
		return JSON_ARRAY_LAST;
	else if (compare_text(nname, -1, lname, -1, 0) == 0)
		return JSON_ARRAY_FIRST;
	else
		return get_json_item_array(nlk)? JSON_ARRAY_ONCE : JSON_ARRAY_NONE;
}

static bool_t is_json_escape(const tchar_t* val)
{
	while (val && *val != _T('\0'))
	{
		if (*val++ == _T('\"'))
			return 1;
	}

	return 0;
}

bool_t format_json_doc_to_object(link_t_ptr ptr, opera_interface* pbo)
{
	link_t_ptr nlk;
	link_t_ptr st = NULL;
	const tchar_t *sz_name, *sz_val;
	bool_t b_ret = 0;
	tchar_t pch[2] = { 0 };
	int pos;
	int n, indent = 0;

	st = create_stack_table();

	pch[0] = _T('{');
	pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
	if (pos == C_ERR)
	{
		pbo->pos = C_ERR;

		destroy_stack_table(st);
		return 0;
	}
	pbo->pos += pos;

	if (pbo->pf_write_carriage)
	{
		pos = (*pbo->pf_write_carriage)(pbo->ctx, pbo->max, pbo->pos, pbo->encode);
		if (pos == C_ERR)
		{
			pbo->pos = C_ERR;

			destroy_stack_table(st);
			return 0;
		}
		pbo->pos += pos;
	}

	n = ++indent;
	while (n-- && pbo->pf_write_indent)
	{
		pos = (*pbo->pf_write_indent)(pbo->ctx, pbo->max, pbo->pos, pbo->encode);
		if (pos == C_ERR)
		{
			pbo->pos = C_ERR;

			destroy_stack_table(st);
			return 0;
		}
		pbo->pos += pos;
	}

	nlk = get_json_first_child_item(ptr);
	while (nlk)
	{
		b_ret = _test_json_item(nlk);
		if (b_ret != JSON_ARRAY_NEXT && b_ret != JSON_ARRAY_LAST)
		{
			sz_name = get_json_item_name_ptr(nlk);

			pch[0] = _T('\"');
			pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
			if (pos == C_ERR)
			{
				pbo->pos = C_ERR;
				
				destroy_stack_table(st);
				return 0;
			}
			pbo->pos += pos;

			pos = (*pbo->pf_write_token)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, sz_name, -1);
			if (pos == C_ERR)
			{
				pbo->pos = C_ERR;

				destroy_stack_table(st);
				return 0;
			}
			pbo->pos += pos;

			pos = (*pbo->pf_write_token)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, _T("\" : "), -1);
			if (pos == C_ERR)
			{
				pbo->pos = C_ERR;

				destroy_stack_table(st);
				return 0;
			}
			pbo->pos += pos;
		}

		if (b_ret == JSON_ARRAY_FIRST || b_ret == JSON_ARRAY_ONCE)
		{
			pch[0] = _T('[');
			pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
			if (pos == C_ERR)
			{
				pbo->pos = C_ERR;

				destroy_stack_table(st);
				return 0;
			}
			pbo->pos += pos;
		}

		if (get_dom_first_child_node(nlk))
		{
			pch[0] = _T('{');
			pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
			if (pos == C_ERR)
			{
				pbo->pos = C_ERR;

				destroy_stack_table(st);
				return 0;
			}
			pbo->pos += pos;

			if (pbo->pf_write_carriage)
			{
				pos = (*pbo->pf_write_carriage)(pbo->ctx, pbo->max, pbo->pos, pbo->encode);
				if (pos == C_ERR)
				{
					pbo->pos = C_ERR;

					destroy_stack_table(st);
					return 0;
				}
				pbo->pos += pos;
			}

			n = ++indent;
			while (n-- && pbo->pf_write_indent)
			{
				pos = (*pbo->pf_write_indent)(pbo->ctx, pbo->max, pbo->pos, pbo->encode);
				if (pos == C_ERR)
				{
					pbo->pos = C_ERR;

					destroy_stack_table(st);
					return 0;
				}
				pbo->pos += pos;
			}

			push_stack_node(st, (void*)nlk);
			nlk = get_dom_first_child_node(nlk);
			continue;
		}

		if (!get_json_item_number(nlk))
		{
			pch[0] = _T('\"');
			pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
			if (pos == C_ERR)
			{
				pbo->pos = C_ERR;

				destroy_stack_table(st);
				return 0;
			}
			pbo->pos += pos;
		}

		sz_val = get_json_item_value_ptr(nlk);
		if (is_json_escape(sz_val))
		{
			while (sz_val && *sz_val != _T('\0'))
			{
				if (*sz_val == _T('\"'))
				{
					pch[0] = _T('\\');
					pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
					if (pos == C_ERR)
					{
						pbo->pos = C_ERR;

						destroy_stack_table(st);
						return 0;
					}
					pbo->pos += pos;
				}

				pch[0] = *sz_val++;
				pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
				if (pos == C_ERR)
				{
					pbo->pos = C_ERR;

					destroy_stack_table(st);
					return 0;
				}
				pbo->pos += pos;
			}
		}
		else
		{
			pos = (*pbo->pf_write_token)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, sz_val, -1);
			if (pos == C_ERR)
			{
				pbo->pos = C_ERR;

				destroy_stack_table(st);
				return 0;
			}
			pbo->pos += pos;
		}

		if (!get_json_item_number(nlk))
		{
			pch[0] = _T('\"');
			pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
			if (pos == C_ERR)
			{
				pbo->pos = C_ERR;

				destroy_stack_table(st);
				return 0;
			}
			pbo->pos += pos;
		}

		while (nlk)
		{
			if (get_dom_first_child_node(nlk))
			{
				if (pbo->pf_write_carriage)
				{
					pos = (*pbo->pf_write_carriage)(pbo->ctx, pbo->max, pbo->pos, pbo->encode);
					if (pos == C_ERR)
					{
						pbo->pos = C_ERR;

						destroy_stack_table(st);
						return 0;
					}
					pbo->pos += pos;
				}

				n = --indent;
				while (n-- && pbo->pf_write_indent)
				{
					pos = (*pbo->pf_write_indent)(pbo->ctx, pbo->max, pbo->pos, pbo->encode);
					if (pos == C_ERR)
					{
						pbo->pos = C_ERR;

						destroy_stack_table(st);
						return 0;
					}
					pbo->pos += pos;
				}

				pch[0] = _T('}');
				pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
				if (pos == C_ERR)
				{
					pbo->pos = C_ERR;

					destroy_stack_table(st);
					return 0;
				}
				pbo->pos += pos;
			}

			b_ret = _test_json_item(nlk);
			if (b_ret == JSON_ARRAY_NONE)
			{
				if (get_dom_next_sibling_node(nlk))
				{
					pch[0] = _T(',');
					pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
					if (pos == C_ERR)
					{
						pbo->pos = C_ERR;

						destroy_stack_table(st);
						return 0;
					}
					pbo->pos += pos;
				}
			}
			else if (b_ret == JSON_ARRAY_NEXT || b_ret == JSON_ARRAY_FIRST)
			{
				pch[0] = _T(',');
				pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
				if (pos == C_ERR)
				{
					pbo->pos = C_ERR;

					destroy_stack_table(st);
					return 0;
				}
				pbo->pos += pos;
			}
			else if (b_ret == JSON_ARRAY_LAST || b_ret == JSON_ARRAY_ONCE)
			{
				pch[0] = _T(']');
				pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
				if (pos == C_ERR)
				{
					pbo->pos = C_ERR;

					destroy_stack_table(st);
					return 0;
				}
				pbo->pos += pos;

				if (get_dom_next_sibling_node(nlk))
				{
					pch[0] = _T(',');
					pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
					if (pos == C_ERR)
					{
						pbo->pos = C_ERR;

						destroy_stack_table(st);
						return 0;
					}
					pbo->pos += pos;
				}
			}

			nlk = get_dom_next_sibling_node(nlk);
			if (nlk)
				break;

			nlk = (st) ? (link_t_ptr)pop_stack_node(st) : NULL;
			if (!nlk)
				break;
		}
	}

	if (pbo->pf_write_carriage)
	{
		pos = (*pbo->pf_write_carriage)(pbo->ctx, pbo->max, pbo->pos, pbo->encode);
		if (pos == C_ERR)
		{
			pbo->pos = C_ERR;

			destroy_stack_table(st);
			return 0;
		}
		pbo->pos += pos;
	}

	n = --indent;
	while (n-- && pbo->pf_write_indent)
	{
		pos = (*pbo->pf_write_indent)(pbo->ctx, pbo->max, pbo->pos, pbo->encode);
		if (pos == C_ERR)
		{
			pbo->pos = C_ERR;

			destroy_stack_table(st);
			return 0;
		}
		pbo->pos += pos;
	}

	pch[0] = _T('}');
	pos = (*pbo->pf_write_char)(pbo->ctx, pbo->max, pbo->pos, pbo->encode, pch);
	if (pos == C_ERR)
	{
		pbo->pos = C_ERR;

		destroy_stack_table(st);
		return 0;
	}
	pbo->pos += pos;

	destroy_stack_table(st);

	return 1;
}
