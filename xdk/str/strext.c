/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc string document

	@module	strext.c | implement file

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

#include "strext.h"

#include "../xdkstd.h"


//%[flag] [width] [.precision] [{h | l | I64 | L}]type
//flags: -,+,' ',#,0
//width:
//precision
//type:c,C,d,i,o,u,x,X,e,E,f,g,s,S,T,t

typedef enum{
	XS_SKIP = 0,
	XS_FLAG = 1,
	XS_WIDTH = 2,
	XS_PREC = 3,
	XS_SIZE= 4,
	XS_TYPE = 5,
	XS_PROC = 6,
	XS_TERM = 7,
	XS_END = 8
}XF_STATUS;

typedef enum{
	XO_PAUSE = 0,
	XO_CONTINUE = 1
}XF_OPERA;

#define a_is_flag(ch)	((ch == '+' || ch == '#')? 1 : 0)
#define a_is_digit(ch)	((ch >= '0' && ch <= '9')? 1 : 0)
#define a_is_hex(ch)	(((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'))? 1 : 0)
#define a_is_size(ch)	((*token == 'h' || *token == 'l')? 1 : 0)
#define a_is_type(ch)	((ch == 'c' || ch == 'd' || ch == 'u' || ch == 'x' || ch == 'X' || ch == 'f'|| ch == 's' || ch == 'S')? 1 : 0)

#define w_is_flag(ch)	((ch == L'+' || ch == L'#')? 1 : 0)
#define w_is_digit(ch)	((ch >= L'0' && ch <= L'9')? 1 : 0)
#define w_is_hex(ch)	(((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z'))? 1 : 0)
#define w_is_size(ch)	((*token == L'h' || *token == L'l')? 1 : 0)
#define w_is_type(ch)	((ch == L'c' || ch == L'd' || ch == L'u' || ch == L'x' || ch == L'X' || ch == L'f'|| ch == L's' || ch == L'S')? 1 : 0)

int a_tk_printf(schar_t* buf,schar_t flag,int width,int prec,schar_t size,schar_t type,va_list* parg)
{
	schar_t ch;
	int len,pos;
	short s;
	unsigned short us;
	int i;
	unsigned int ui;
	long long l;
	unsigned long long ul;
	double dbl;
	schar_t* sz;
	wchar_t* wz;

	switch(type)
	{
	case 'c':
		ch = (schar_t)va_arg(*parg,int);
		if(buf)
		{
			*buf = ch;
			*(buf + 1) = '\0';
		}
		return 1;
	case 'd':
		if(size == 'h')
		{
			pos = 0;
			s = (short)va_arg(*parg,int);
			if (flag == '+')
			{
				if (s < 0)
				{
					if (buf)
					{
						buf[pos] = '-';
					}
					s = 0 - s;
				}
				else
				{
					if (buf)
					{
						buf[pos] = '+';
					}
				}
				pos++;
			}
			else
			{
				if (s < 0)
				{
					if (buf)
					{
						buf[pos] = '-';
					}
					s = 0 - s;
					pos++;
				}
			}
			if (width)
			{
				len = width - a_stoxs(s, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = '0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + a_stoxs(s, ((buf) ? buf + pos : NULL),width);
		}else if (size == 'l')
		{
			pos = 0;
			l = va_arg(*parg, long long);
			if (flag == '+')
			{
				if (l < 0)
				{
					if (buf)
					{
						buf[pos] = '-';
					}
					l = 0 - l;
				}
				else
				{
					if (buf)
					{
						buf[pos] = '+';
					}
				}
				pos++;
			}
			else
			{
				if (l < 0)
				{
					if (buf)
					{
						buf[pos] = '-';
					}
					l = 0 - l;
					pos++;
				}
			}
			if (width)
			{
				len = width - a_lltoxs(l, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = '0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + a_lltoxs(l, ((buf) ? buf + pos : NULL), width);
		}
		else
		{
			pos = 0;
			i = va_arg(*parg,int);
			if (flag == '+')
			{
				if (i < 0)
				{
					if (buf)
					{
						buf[pos] = '-';
					}
					i = 0 - i;
				}
				else
				{
					if (buf)
					{
						buf[pos] = '+';
					}
				}
				pos++;
			}
			else
			{
				if (i < 0)
				{
					if (buf)
					{
						buf[pos] = '-';
					}
					i = 0 - i;
					pos++;
				}
			}
			if (width)
			{
				len = width - a_ltoxs(i, NULL,width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = '0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + a_ltoxs(i, ((buf) ? buf + pos : NULL),width);
		}
		break;
	case 'u':
		if (size == 'h')
		{
			pos = 0;
			us = (unsigned short)va_arg(*parg, int);
			if (width)
			{
				len = width - a_ustoxs(us, NULL,width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = '0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + a_ustoxs(us, ((buf)? buf + pos : NULL),width);
		}
		else if (size == 'l')
		{
			pos = 0;
			ul = (unsigned long long)va_arg(*parg, long long);
			if (width)
			{
				len = width - a_ulltoxs(ul, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = '0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + a_ulltoxs(ul, ((buf) ? buf + pos : NULL), width);
		}
		else
		{
			pos = 0;
			ui = (unsigned int)va_arg(*parg, int);
			if (width)
			{
				len = width - a_ultoxs(ui, NULL,width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = '0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + a_ultoxs(ui, ((buf) ? buf + pos : NULL),width);
		}
	case 'x':
	case 'X':
		if (size == 'h')
		{
			us = (unsigned short)va_arg(*parg, int);
			pos = 0;
			if (flag == '#')
			{
				if (buf)
				{
					buf[0] = '0';
					buf[1] = 'x';
				}
				pos += 2;
			}
			if (width)
			{
				len = width - a_stohex(us, type, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = '0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + a_stohex(us, type, ((buf) ? (buf + pos) : NULL), width);
		}
		else if (size == 'l')
		{
			ul = (unsigned long long)va_arg(*parg, long long);
			pos = 0;
			if (flag == '#')
			{
				if (buf)
				{
					buf[0] = '0';
					buf[1] = 'x';
				}
				pos += 2;
			}
			if (width)
			{
				len = width - a_lltohex(ul, type, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = '0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + a_lltohex(ul, type, ((buf) ? (buf + pos) : NULL), width);
		}
		else
		{
			ui = (unsigned int)va_arg(*parg, int);
			pos = 0;
			if (flag == '#')
			{
				if (buf)
				{
					buf[0] = '0';
					buf[1] = 'x';
				}
				pos += 2;
			}
			if (width)
			{
				len = width - a_ltohex(ui, type, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = '0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + a_ltohex(ui, type, ((buf) ? (buf + pos) : NULL), width);
		}
	case 'f':
		dbl = va_arg(*parg, double);
		if (!width)
		{
			width = NUM_LEN;
		}
		if (!prec)
		{
			prec = MAX_DOUBLE_DIGI;
		}
		return a_numtoxs_dig(dbl, prec, buf, width);
	case 's':
		sz = va_arg(*parg,schar_t*);
		len = a_xslen(sz);

		if (!width)
			width = len;
		else
			width = (width < len) ? width : len;
		
		if (buf)
		{
			a_xsncpy(buf, sz, width);
		}

		return width;
	case 'S':
		wz = va_arg(*parg, wchar_t*);
		len = ucs_to_mbs(wz, -1, NULL, MAX_LONG);

		if (!width)
			width = len;
		else
			width = (width < len) ? width : len;

		if (buf)
		{
			ucs_to_mbs(wz, -1, buf, width);
			buf[width] = '\0';
		}

		return width;

	}

	return 0;
}


int w_tk_printf(wchar_t* buf,wchar_t flag,int width,int prec,wchar_t size,wchar_t type,va_list* parg)
{
	wchar_t ch;
	int len, pos;
	short s;
	unsigned short us;
	int i;
	unsigned int ui;
	long long l;
	unsigned long long ul;
	double dbl;
	wchar_t* sz;
	schar_t* az;

	switch (type)
	{
	case L'c':
		ch = (wchar_t)va_arg(*parg, int);
		if (buf)
		{
			*buf = ch;
			*(buf + 1) = L'\0';
		}
		return 1;
	case L'd':
		if (size == L'h')
		{
			pos = 0;
			s = (short)va_arg(*parg, int);
			if (flag == L'+')
			{
				if (s < 0)
				{
					if (buf)
					{
						buf[pos] = L'-';
					}
					s = 0 - s;
				}
				else
				{
					if (buf)
					{
						buf[pos] = L'+';
					}
				}
				pos++;
			}
			else
			{
				if (s < 0)
				{
					if (buf)
					{
						buf[pos] = L'-';
					}
					s = 0 - s;
					pos++;
				}
			}
			if (width)
			{
				len = width - w_stoxs(s, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = L'0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + w_stoxs(s, ((buf) ? buf + pos : NULL), width);
		}
		else if (size == L'l')
		{
			pos = 0;
			l = va_arg(*parg, long long);
			if (flag == L'+')
			{
				if (l < 0)
				{
					if (buf)
					{
						buf[pos] = L'-';
					}
					l = 0 - l;
				}
				else
				{
					if (buf)
					{
						buf[pos] = L'+';
					}
				}
				pos++;
			}
			else
			{
				if (l < 0)
				{
					if (buf)
					{
						buf[pos] = L'-';
					}
					l = 0 - l;
					pos++;
				}
			}
			if (width)
			{
				len = width - w_lltoxs(l, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = L'0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + w_lltoxs(l, ((buf) ? buf + pos : NULL), width);
		}
		else
		{
			pos = 0;
			i = va_arg(*parg, int);
			if (flag == L'+')
			{
				if (i < 0)
				{
					if (buf)
					{
						buf[pos] = L'-';
					}
					i = 0 - i;
				}
				else
				{
					if (buf)
					{
						buf[pos] = L'+';
					}
				}
				pos++;
			}
			else
			{
				if (i < 0)
				{
					if (buf)
					{
						buf[pos] = L'-';
					}
					i = 0 - i;
					pos++;
				}
			}
			if (width)
			{
				len = width - w_ltoxs(i, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = L'0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + w_ltoxs(i, ((buf) ? buf + pos : NULL), width);
		}
		break;
	case L'u':
		if (size == L'h')
		{
			pos = 0;
			us = (unsigned short)va_arg(*parg, int);
			if (width)
			{
				len = width - w_ustoxs(us, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = L'0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + w_ustoxs(us, ((buf) ? buf + pos : NULL), width);
		}
		else if (size == L'l')
		{
			pos = 0;
			ul = (unsigned long long)va_arg(*parg, long long);
			if (width)
			{
				len = width - w_ulltoxs(ul, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = L'0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + w_ulltoxs(ul, ((buf) ? buf + pos : NULL), width);
		}
		else
		{
			pos = 0;
			ui = (unsigned int)va_arg(*parg, int);
			if (width)
			{
				len = width - w_ultoxs(ui, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = L'0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + w_ultoxs(ui, ((buf) ? buf + pos : NULL), width);
		}
	case L'x':
	case L'X':
		if (size == L'h')
		{
			us = (unsigned short)va_arg(*parg, int);
			pos = 0;
			if (flag == L'#')
			{
				if (buf)
				{
					buf[0] = L'0';
					buf[1] = L'x';
				}
				pos += 2;
			}
			if (width)
			{
				len = width - w_stohex(us, type, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = L'0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + w_stohex(us, type, ((buf) ? (buf + pos) : NULL), width);
		}else if (size == L'l')
		{
			ul = (unsigned long long)va_arg(*parg, long long);
			pos = 0;
			if (flag == L'#')
			{
				if (buf)
				{
					buf[0] = L'0';
					buf[1] = L'x';
				}
				pos += 2;
			}
			if (width)
			{
				len = width - w_lltohex(ul, type, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = L'0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + w_lltohex(ul, type, ((buf) ? (buf + pos) : NULL), width);
		}else
		{
			ui = (unsigned int)va_arg(*parg, int);
			pos = 0;
			if (flag == L'#')
			{
				if (buf)
				{
					buf[0] = L'0';
					buf[1] = L'x';
				}
				pos += 2;
			}
			if (width)
			{
				len = width - w_ltohex(ui, type, NULL, width);
				while (len > 0)
				{
					if (buf)
					{
						buf[pos] = L'0';
					}
					pos++;
					len--;
				}
			}
			else
			{
				width = NUM_LEN;
			}
			return pos + w_ltohex(ui, type, ((buf) ? (buf + pos) : NULL), width);
		}
	case L'f':
		dbl = va_arg(*parg, double);
		if (!width)
		{
			width = NUM_LEN;
		}
		if (!prec)
		{
			prec = MAX_DOUBLE_DIGI;
		}
		return w_numtoxs_dig(dbl, prec, buf, width);
	case L's':
		sz = va_arg(*parg, wchar_t*);

		len = w_xslen(sz);

		if (!width)
			width = len;
		else
			width = (width < len) ? width : len;

		if (buf)
		{
			w_xsncpy(buf, sz, width);
		}
		return width;
	case L'S':
		az = va_arg(*parg, schar_t*);
		len = mbs_to_ucs(az, -1, NULL, MAX_LONG);

		if (!width)
			width = len;
		else
			width = (width < len) ? width : len;

		if (buf)
		{
			mbs_to_ucs(az, -1, buf, width);
			buf[width] = L'\0';
		}
		return width;
	}
	return 0;
}

int a_xsprintf(schar_t* buf,const schar_t* fmt,...)
{
	int rt;
	va_list arg;
	
	va_start(arg,fmt);
	rt = a_xsprintf_arg(buf,fmt,&arg);
	va_end(arg);

	return rt;
}

int a_xsprintf_arg(schar_t* buf,const schar_t* fmt,va_list* parg)
{
	int total = 0;
	schar_t xf_flag = 0;
	int xf_width = 0;
	int xf_prec = 0;
	schar_t xf_size = 0;
	schar_t xf_type = 0;
	schar_t tk_width[NUM_LEN + 1],tk_prec[NUM_LEN + 1];
	int width_count = 0;
	int prec_count = 0;
	int tk_count = 0;


	XF_STATUS xs = XS_SKIP;
	XF_OPERA xo = XO_PAUSE;

	schar_t* token = (schar_t*)fmt;

	while(xs != XS_END)
	{
		switch(xs)
		{
		case XS_SKIP:
			if(*token == '%' && *(token + 1) != '%')
			{
				if(!tk_count)
				{
					xs = XS_FLAG;
					xo = XO_CONTINUE;
				}else
				{
					xs = XS_PROC;
					xo = XO_PAUSE;
				}
			}else if(*token == '\0')
			{
				xs = XS_PROC;
				xo = XO_PAUSE; 
			}else
			{
				xs = XS_SKIP;
				xo = XO_CONTINUE; 
			}
			break;
		case XS_FLAG:
			if(a_is_flag(*token)) 
			{
				xf_flag = *token;
				xs = XS_FLAG;
				xo = XO_CONTINUE;
			}else
			{
				xs = XS_WIDTH;
				xo = XO_PAUSE;
			}
			break;
		case XS_WIDTH:
			if(a_is_digit(*token))
			{
				tk_width[width_count ++] = *token;
				xs = XS_WIDTH;
				xo = XO_CONTINUE;
			}else if(*token == '.')
			{
				xs = XS_PREC;
				xo = XO_CONTINUE;
			}else
			{
				xs = XS_SIZE;
				xo = XO_PAUSE;
			}
			break;
		case XS_PREC:
			if(a_is_digit(*token))
			{
				tk_prec[prec_count ++] = *token;
				xs = XS_PREC;
				xo = XO_CONTINUE;
			}else
			{
				xs = XS_SIZE;
				xo = XO_PAUSE;
			}
			break;
		case XS_SIZE:
			if(a_is_size(*token))
			{
				xf_size = *token;
				xs = XS_TYPE;
				xo = XO_CONTINUE;
			}else
			{
				xs = XS_TYPE;
				xo = XO_PAUSE;
			}
			break;
		case XS_TYPE:
			if(a_is_type(*token))
			{
				xf_type = *token;
				xs = XS_PROC;
				xo = XO_CONTINUE;
			}else
			{
				xs = XS_PROC;
				xo = XO_CONTINUE;
			}
			break;
		case XS_PROC:
			if(xf_type)
			{
				tk_width[width_count] = '\0';
				xf_width = a_xstol(tk_width);

				tk_prec[prec_count] = '\0';
				xf_prec = a_xstol(tk_prec);

				total += a_tk_printf((buf)? (buf + total) : NULL,xf_flag,xf_width,xf_prec,xf_size,xf_type,parg);

				if(*token == '\0')
					xs = XS_END;
				else
					xs = XS_SKIP;

				xo = XO_PAUSE;
			}else
			{
				if(buf)
				{
					a_xsncpy(buf + total, token - tk_count, tk_count);
				}
				total += tk_count;

				if(*token == '\0')
					xs = XS_END;
				else
					xs = XS_SKIP;

				xo = XO_PAUSE;
			}

			xf_flag = 0;
			xf_width = 0;
			xf_prec = 0;
			xf_size = 0;
			xf_type = 0;
			width_count = prec_count = tk_count = 0;

			break;
		}

		if(xo == XO_CONTINUE && *token != '\0')
		{
			token ++;
			tk_count ++;
		}
	}

	return total;
}

int w_xsprintf(wchar_t* buf,const wchar_t* fmt,...)
{
	int rt;
	va_list arg;
	
	va_start(arg,fmt);
	rt = w_xsprintf_arg(buf,fmt,&arg);
	va_end(arg);

	return rt;
}

int w_xsprintf_arg(wchar_t* buf,const wchar_t* fmt,va_list* parg)
{
	int total = 0;
	wchar_t xf_flag = 0;
	int xf_width = 0;
	int xf_prec = 0;
	wchar_t xf_size = 0;
	wchar_t xf_type = 0;
	wchar_t tk_width[NUM_LEN + 1],tk_prec[NUM_LEN + 1];
	int width_count = 0;
	int prec_count = 0;
	int tk_count = 0;


	XF_STATUS xs = XS_SKIP;
	XF_OPERA xo = XO_PAUSE;

	wchar_t* token = (wchar_t*)fmt;

	while(xs != XS_END)
	{
		switch(xs)
		{
		case XS_SKIP:
			if(*token == L'%' && *(token + 1) != L'%')
			{
				if(!tk_count)
				{
					xs = XS_FLAG;
					xo = XO_CONTINUE;
				}else
				{
					xs = XS_PROC;
					xo = XO_PAUSE;
				}
			}else if(*token == L'\0')
			{
				xs = XS_PROC;
				xo = XO_PAUSE; 
			}else
			{
				xs = XS_SKIP;
				xo = XO_CONTINUE; 
			}
			break;
		case XS_FLAG:
			if(w_is_flag(*token)) 
			{
				xf_flag = *token;
				xs = XS_FLAG;
				xo = XO_CONTINUE;
			}else
			{
				xs = XS_WIDTH;
				xo = XO_PAUSE;
			}
			break;
		case XS_WIDTH:
			if(w_is_digit(*token))
			{
				tk_width[width_count ++] = *token;
				xs = XS_WIDTH;
				xo = XO_CONTINUE;
			}else if(*token == L'.')
			{
				xs = XS_PREC;
				xo = XO_CONTINUE;
			}else
			{
				xs = XS_SIZE;
				xo = XO_PAUSE;
			}
			break;
		case XS_PREC:
			if(w_is_digit(*token))
			{
				tk_prec[prec_count ++] = *token;
				xs = XS_PREC;
				xo = XO_CONTINUE;
			}else
			{
				xs = XS_SIZE;
				xo = XO_PAUSE;
			}
			break;
		case XS_SIZE:
			if(w_is_size(*token))
			{
				xf_size = *token;
				xs = XS_TYPE;
				xo = XO_CONTINUE;
			}else
			{
				xs = XS_TYPE;
				xo = XO_PAUSE;
			}
			break;
		case XS_TYPE:
			if(w_is_type(*token))
			{
				xf_type = *token;
				xs = XS_PROC;
				xo = XO_CONTINUE;
			}else
			{
				xs = XS_PROC;
				xo = XO_CONTINUE;
			}
			break;
		case XS_PROC:
			if(xf_type)
			{
				tk_width[width_count] = L'\0';
				xf_width = w_xstol(tk_width);

				tk_prec[prec_count] = L'\0';
				xf_prec = w_xstol(tk_prec);

				total += w_tk_printf((buf)? (buf + total) : NULL,xf_flag,xf_width,xf_prec,xf_size,xf_type,parg);

				if(*token == L'\0')
					xs = XS_END;
				else
					xs = XS_SKIP;

				xo = XO_PAUSE;
			}else
			{
				if(buf)
				{
					w_xsncpy(buf + total, token - tk_count, tk_count);
				}
				total += tk_count;

				if(*token == L'\0')
					xs = XS_END;
				else
					xs = XS_SKIP;

				xo = XO_PAUSE;
			}

			xf_flag = 0;
			xf_width = 0;
			xf_prec = 0;
			xf_size = 0;
			xf_type = 0;
			width_count = prec_count = tk_count = 0;

			break;
		}

		if(xo == XO_CONTINUE && *token != L'\0')
		{
			token ++;
			tk_count ++;
		}
	}

	return total;
}

static int a_test_numeric(const schar_t* token, int len)
{
	int pos = 0;

	if (!token)
		return 0;

	if (len < 0)
		len = a_xslen(token);

	while (pos < len)
	{
		if (*token == '+' || *token == '-' || *token == '.' || (*token >= '0' && *token <= '9'))
		{
			token++;
			pos++;
		}else
			break;
	}

	return pos;
}

static int w_test_numeric(const wchar_t* token, int len)
{
	int pos = 0;

	if (!token)
		return 0;

	if (len < 0)
		len = w_xslen(token);

	while (pos < len)
	{
		if (*token == L'+' || *token == L'-' || *token == L'.' || (*token >= L'0' && *token <= L'9'))
		{
			token++;
			pos++;
		}
		else
			break;
	}

	return pos;
}

static int a_test_hex(const schar_t* token, int len)
{
	int pos = 0;

	if (!token)
		return 0;

	if (len < 0)
		len = a_xslen(token);

	while (pos < len)
	{
		if (*token == 'x' || *token == 'X' || (*token >= '0' && *token <= '9') || (*token >= 'A' && *token <= 'F') || (*token >= 'a' && *token <= 'f'))
		{
			token++;
			pos++;
		}else
			break;
	}

	return pos;
}

static int w_test_hex(const wchar_t* token, int len)
{
	int pos = 0;

	if (!token)
		return 0;

	if (len < 0)
		len = w_xslen(token);

	while (pos < len)
	{
		if (*token == L'x' || *token == L'X' || (*token >= L'0' && *token <= L'9') || (*token >= L'A' && *token <= L'F') || (*token >= L'a' && *token <= L'f'))
		{
			token++;
			pos++;
		}
		else
			break;
	}

	return pos;
}

const schar_t* a_tk_scanf(const schar_t* token, schar_t size, schar_t type, va_list* parg)
{
	int pos;
	schar_t* pch;
	short *ps;
	unsigned short *pus;
	int *pi;
	unsigned int *pui;
	long long *pl;
	unsigned long long *pul;
	double *pdb;
	schar_t* psstr;
	wchar_t* pwstr;

	switch (type)
	{
	case 'c':
		pch = va_arg(*parg, schar_t*);
		*pch = *token;
		return token + 1;
	case 'd':
		if (size == 'h')
		{
			pos = 0;
			ps = va_arg(*parg, short*);

			pos = a_test_numeric(token, -1);
			*ps = a_xsntos(token, pos);
			return token + pos;
		}
		else if (size == 'l')
		{
			pos = 0;
			pl = va_arg(*parg, long long*);

			pos = a_test_numeric(token, -1);
			*pl = a_xsntoll(token, pos);
			return token + pos;
		}
		else
		{
			pos = 0;
			pi = va_arg(*parg, int*);

			pos = a_test_numeric(token, -1);
			*pi = a_xsntol(token, pos);
			return token + pos;
		}
		break;
	case 'u':
		if (size == 'h')
		{
			pos = 0;
			pus = va_arg(*parg, unsigned short*);

			pos = a_test_numeric(token, -1);
			*pus = (unsigned short)a_xsntos(token, pos);
			return token + pos;
		}else if (size == 'l')
		{
			pos = 0;
			pul = va_arg(*parg, unsigned long long*);

			pos = a_test_numeric(token, -1);
			*pul = (unsigned long long)a_xsntoll(token, pos);
			return token + pos;
		}
		else
		{
			pos = 0;
			pui = va_arg(*parg, unsigned int*);

			pos = a_test_numeric(token, -1);
			*pui = (unsigned int)a_xsntol(token, pos);
			return token + pos;
		}
		break;
	case 'x':
	case 'X':
		if (size == 'h')
		{
			pos = 0;
			pus = va_arg(*parg, unsigned short *);

			pos = a_test_hex(token, -1);
			*pus = a_hexntos(token, pos);
			return token + pos;
		}
		else if (size == 'l')
		{
			pos = 0;
			pul = va_arg(*parg, unsigned long long *);

			pos = a_test_hex(token, -1);
			*pul = a_hexntoll(token, pos);
			return token + pos;
		}
		else
		{
			pos = 0;
			pui = va_arg(*parg, unsigned int *);

			pos = a_test_hex(token, -1);
			*pui = a_hexntol(token, pos);
			return token + pos;
		}
	case 'f':
		pos = 0;
		pdb = va_arg(*parg, double*);

		pos = a_test_numeric(token, -1);
		*pdb = a_xsntonum(token, pos);
		return token + pos;
	}

	return NULL;
}

const wchar_t* w_tk_scanf(const wchar_t* token, wchar_t size, wchar_t type, va_list* parg)
{
	int pos;
	wchar_t* pch;
	short *ps; 
	unsigned short *pus;
	int *pi;
	unsigned int *pui;
	long long *pl;
	unsigned long long* pul;
	double *pdb;
	schar_t* psstr;
	wchar_t* pwstr;

	switch (type)
	{
	case L'c':
		pch = va_arg(*parg, wchar_t*);
		*pch = *token;
		return token + 1;
	case L'd':
		if (size == L'h')
		{
			pos = 0;
			ps = va_arg(*parg, short*);

			pos = w_test_numeric(token, -1);
			*ps = w_xsntos(token, pos);
			return token + pos;
		}
		else if (size == L'l')
		{
			pos = 0;
			pl = va_arg(*parg, long long*);

			pos = w_test_numeric(token, -1);
			*pl = w_xsntoll(token, pos);
			return token + pos;
		}
		else
		{
			pos = 0;
			pi = va_arg(*parg, int*);

			pos = w_test_numeric(token, -1);
			*pi = w_xsntol(token, pos);
			return token + pos;
		}
		break;
	case L'u':
		if (size == L'h')
		{
			pos = 0;
			pus = va_arg(*parg, unsigned short*);

			pos = w_test_numeric(token, -1);
			*pus = (unsigned short)w_xsntos(token, pos);
			return token + pos;
		}else if (size == L'l')
		{
			pos = 0;
			pul = va_arg(*parg, unsigned long long*);

			pos = w_test_numeric(token, -1);
			*pul = (unsigned short)w_xsntoll(token, pos);
			return token + pos;
		}
		else
		{
			pos = 0;
			pui = va_arg(*parg, unsigned int*);

			pos = w_test_numeric(token, -1);
			*pui = (unsigned int)w_xsntol(token, pos);
			return token + pos;
		}
		break;
	case L'x':
	case L'X':
		if (size == L'h')
		{
			pos = 0;
			pus = va_arg(*parg, unsigned short *);

			pos = w_test_hex(token, -1);
			*pus = w_hexntos(token, pos);
			return token + pos;
		}
		else if (size == L'l')
		{
			pos = 0;
			pul = va_arg(*parg, unsigned long long *);

			pos = w_test_hex(token, -1);
			*pul = w_hexntoll(token, pos);
			return token + pos;
		}
		else
		{
			pos = 0;
			pui = va_arg(*parg, unsigned int *);

			pos = w_test_hex(token, -1);
			*pui = w_hexntol(token, pos);
			return token + pos;
		}
	case L'f':
		pos = 0;
		pdb = va_arg(*parg, double*);

		pos = w_test_numeric(token, -1);
		*pdb = w_xsntonum(token, pos);
		return token + pos;
	}

	return NULL;
}

const schar_t* a_xsscanf_arg(const schar_t* str, const schar_t* fmt, va_list* parg)
{
	int total = 0;
	schar_t xf_flag = 0;
	int xf_width = 0;
	int xf_prec = 0;
	schar_t xf_size = 0;
	schar_t xf_type = 0;
	schar_t tk_width[NUM_LEN + 1], tk_prec[NUM_LEN + 1];
	int width_count = 0;
	int prec_count = 0;
	int tk_count = 0;

	XF_STATUS xs = XS_SKIP;
	XF_OPERA xo = XO_PAUSE;

	schar_t* token = (schar_t*)fmt;

	if (a_is_null(str))
		return NULL;

	while (xs != XS_END)
	{
		switch (xs)
		{
		case XS_SKIP:
			if (*token == '%' && *(token + 1) != '%')
			{
				if (!tk_count)
				{
					xs = XS_FLAG;
					xo = XO_CONTINUE;
				}
				else
				{
					xs = XS_PROC;
					xo = XO_PAUSE;
				}
			}
			else if (*token == '\0')
			{
				xs = XS_PROC;
				xo = XO_PAUSE;
			}
			else
			{
				xs = XS_SKIP;
				xo = XO_CONTINUE;
			}
			break;
		case XS_FLAG:
			if (a_is_flag(*token))
			{
				xf_flag = *token;
				xs = XS_FLAG;
				xo = XO_CONTINUE;
			}
			else
			{
				xs = XS_WIDTH;
				xo = XO_PAUSE;
			}
			break;
		case XS_WIDTH:
			if (a_is_digit(*token))
			{
				tk_width[width_count++] = *token;
				xs = XS_WIDTH;
				xo = XO_CONTINUE;
			}
			else if (*token == '.')
			{
				xs = XS_PREC;
				xo = XO_CONTINUE;
			}
			else
			{
				xs = XS_SIZE;
				xo = XO_PAUSE;
			}
			break;
		case XS_PREC:
			if (a_is_digit(*token))
			{
				tk_prec[prec_count++] = *token;
				xs = XS_PREC;
				xo = XO_CONTINUE;
			}
			else
			{
				xs = XS_SIZE;
				xo = XO_PAUSE;
			}
			break;
		case XS_SIZE:
			if (a_is_size(*token))
			{
				xf_size = *token;
				xs = XS_TYPE;
				xo = XO_CONTINUE;
			}
			else
			{
				xs = XS_TYPE;
				xo = XO_PAUSE;
			}
			break;
		case XS_TYPE:
			if (a_is_type(*token))
			{
				xf_type = *token;
				xs = XS_PROC;
				xo = XO_CONTINUE;
			}
			else
			{
				xs = XS_PROC;
				xo = XO_CONTINUE;
			}
			break;
		case XS_PROC:
			if (xf_type)
			{
				tk_width[width_count] = '\0';
				xf_width = a_xstol(tk_width);

				tk_prec[prec_count] = '\0';
				xf_prec = a_xstol(tk_prec);

				str = a_tk_scanf(str, xf_size, xf_type, parg);

				if (*token == '\0')
					xs = XS_END;
				else
					xs = XS_SKIP;

				xo = XO_PAUSE;
			}
			else
			{
				while (*str && tk_count)
				{
					if (*str == *(token - tk_count))
					{
						str++;
						tk_count--;
					}else
					{
						xs = XS_END;
						break;
					}
				}

				if (*token == '\0')
					xs = XS_END;
				else
					xs = XS_SKIP;

				xo = XO_PAUSE;
			}

			xf_flag = 0;
			xf_width = 0;
			xf_prec = 0;
			xf_size = 0;
			xf_type = 0;
			width_count = prec_count = tk_count = 0;

			break;
		}

		if (xo == XO_CONTINUE)
		{
			token++;
			tk_count++;
		}
	}

	return str;
}

const wchar_t* w_xsscanf_arg(const wchar_t* str, const wchar_t* fmt, va_list* parg)
{
	int total = 0;
	wchar_t xf_flag = 0;
	int xf_width = 0;
	int xf_prec = 0;
	wchar_t xf_size = 0;
	wchar_t xf_type = 0;
	wchar_t tk_width[NUM_LEN + 1], tk_prec[NUM_LEN + 1];
	int width_count = 0;
	int prec_count = 0;
	int tk_count = 0;

	XF_STATUS xs = XS_SKIP;
	XF_OPERA xo = XO_PAUSE;

	wchar_t* token = (wchar_t*)fmt;

	if (w_is_null(str))
		return NULL;

	while (xs != XS_END)
	{
		switch (xs)
		{
		case XS_SKIP:
			if (*token == L'%' && *(token + 1) != L'%')
			{
				if (!tk_count)
				{
					xs = XS_FLAG;
					xo = XO_CONTINUE;
				}
				else
				{
					xs = XS_PROC;
					xo = XO_PAUSE;
				}
			}
			else if (*token == L'\0')
			{
				xs = XS_PROC;
				xo = XO_PAUSE;
			}
			else
			{
				xs = XS_SKIP;
				xo = XO_CONTINUE;
			}
			break;
		case XS_FLAG:
			if (w_is_flag(*token))
			{
				xf_flag = *token;
				xs = XS_FLAG;
				xo = XO_CONTINUE;
			}
			else
			{
				xs = XS_WIDTH;
				xo = XO_PAUSE;
			}
			break;
		case XS_WIDTH:
			if (w_is_digit(*token))
			{
				tk_width[width_count++] = *token;
				xs = XS_WIDTH;
				xo = XO_CONTINUE;
			}
			else if (*token == L'.')
			{
				xs = XS_PREC;
				xo = XO_CONTINUE;
			}
			else
			{
				xs = XS_SIZE;
				xo = XO_PAUSE;
			}
			break;
		case XS_PREC:
			if (w_is_digit(*token))
			{
				tk_prec[prec_count++] = *token;
				xs = XS_PREC;
				xo = XO_CONTINUE;
			}
			else
			{
				xs = XS_SIZE;
				xo = XO_PAUSE;
			}
			break;
		case XS_SIZE:
			if (w_is_size(*token))
			{
				xf_size = *token;
				xs = XS_TYPE;
				xo = XO_CONTINUE;
			}
			else
			{
				xs = XS_TYPE;
				xo = XO_PAUSE;
			}
			break;
		case XS_TYPE:
			if (w_is_type(*token))
			{
				xf_type = *token;
				xs = XS_PROC;
				xo = XO_CONTINUE;
			}
			else
			{
				xs = XS_PROC;
				xo = XO_CONTINUE;
			}
			break;
		case XS_PROC:
			if (xf_type)
			{
				tk_width[width_count] = L'\0';
				xf_width = w_xstol(tk_width);

				tk_prec[prec_count] = L'\0';
				xf_prec = w_xstol(tk_prec);

				str = w_tk_scanf(str, xf_size, xf_type, parg);

				if (*token == L'\0')
					xs = XS_END;
				else
					xs = XS_SKIP;

				xo = XO_PAUSE;
			}
			else
			{
				while (*str && tk_count)
				{
					if (*str == *(token - tk_count))
					{
						str++;
						tk_count--;
					}else
					{
						xs = XS_END;
						break;
					}
				}

				if (*token == L'\0')
					xs = XS_END;
				else
					xs = XS_SKIP;

				xo = XO_PAUSE;
			}

			xf_flag = 0;
			xf_width = 0;
			xf_prec = 0;
			xf_size = 0;
			xf_type = 0;
			width_count = prec_count = tk_count = 0;

			break;
		}

		if (xo == XO_CONTINUE)
		{
			token++;
			tk_count++;
		}
	}

	return str;
}

const schar_t* a_xsscanf(const schar_t* str, const schar_t* fmt, ...)
{
	const schar_t* token;
	va_list arg;

	va_start(arg, fmt);
	token = a_xsscanf_arg(str, fmt, &arg);
	va_end(arg);

	return token;
}

const wchar_t* w_xsscanf(const wchar_t* str, const wchar_t* fmt, ...)
{
	const wchar_t* token;
	va_list arg;

	va_start(arg, fmt);
	token = w_xsscanf_arg(str, fmt, &arg);
	va_end(arg);

	return token;
}

int a_xsappend(schar_t* buf, const schar_t* fmt, ...)
{
	int len;
	va_list arg;

	len = a_xslen(buf);

	va_start(arg, fmt);
	len += a_xsprintf_arg(buf + len, fmt, &arg);
	va_end(arg);

	return len;
}

int w_xsappend(wchar_t* buf, const wchar_t* fmt, ...)
{
	int len;
	va_list arg;

	len = w_xslen(buf);

	va_start(arg, fmt);
	len += w_xsprintf_arg(buf + len, fmt, &arg);
	va_end(arg);

	return len;
}

