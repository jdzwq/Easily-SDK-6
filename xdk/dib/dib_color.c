/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc DIB document

	@module	dib.c | implement file

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
#include "dib.h"

#include "../xdkutil.h"

/**********************************************************************
PixelFormat1bppIndexed，每个像素占用1位, 需要使用查找表以映射到真实颜色
PixelFormat4bppIndexed，每个像素占用4位, 需要使用查找表以映射到真实颜色
PixelFormat8bppIndexed，每个像素占用8位, 需要使用查找表以映射到真实颜色
PixelFormat8bppGrayScale 每个像素占用8位, 为256级灰度图像
PixelFormat16bppGrayScale 每个像素占用16位, 为1024级灰度图像
PixelFormat16bppRGB555 每个像素占用16位的彩色图像，每个RGB分量占用5位，剩下1位内存未使用
PixelFormat16bppRGB565 每个像素占用16位的彩色图像， B分量占用5位，G分量占用6位，R分量占用5位
PixelFormat24bppRGB 每个像素占用24位的真彩色图像，每个RGB分量占用8位
PixelFormat32bppARGB 每个像素占用32位的真彩色图像，增加了alpha通道描述透明色
PixelFormat32bppPARGB 是每个像素占用32位的真彩色图像，P表示RBG分量被预乘以alpha透明分量
***********************************************************************/

static _find_quad(const bitmap_quad_t* pbq, int n, const xcolor_t* pxc)
{
	int i;

	for (i = n-1; i >= 0; i--)
	{
		if (pbq[i].red == pxc->r && pbq[i].green == pxc->g && pbq[i].blue == pxc->b)
			break;
	}

	return (i < 0) ? 0 : i;
}

dword_t fill_color_dibbits(const xcolor_t* pxc, const bitmap_info_head_t* pbi, const bitmap_quad_t* pbq, byte_t* buf, dword_t max)
{
	dword_t bytes_per_row, total = 0;
	int row, col, quad, ind;
	byte_t bit;
	unsigned short rgb16;

	switch(pbi->clrbits)
	{
	case 1:
		quad = _find_quad(pbq, 2, pxc);
		break;
	case 4:
		quad = _find_quad(pbq, 16, pxc);
		break;
	case 8:
		quad = _find_quad(pbq, 216, pxc);
		break;
	default:
		quad = 0;
	}

	bytes_per_row = BMP_LINE_BYTES(pbi->width, pbi->clrbits);

	for (row = (int)pbi->height - 1; (row >= 0) && (total + bytes_per_row <= max); row--)
	{
		for (col = 0; col < (int)pbi->width; col++)
		{
			switch (pbi->clrbits)
			{
			case 1: //black and white bitmap
				ind = col / 8;
				bit = 1 << (col % 8);
				if (!buf)
					break;

				if (quad)
					buf[total + ind] |= bit;
				else
					buf[total + ind] &= ~bit;
				break;
			case 4: //
				ind = col / 2;
				bit = col % 2;
				if (!buf)
					break;

				if (bit)
					buf[total + ind] |= ((quad << 4) & 0xF0);
				else
					buf[total + ind] |= (quad & 0x0F);
				break;
			case 8: //
				ind = col;
				if (!buf)
					break;

				buf[total + ind] = quad;
				break;
			case 16:
				ind = col * 2;
				if (!buf)
					break;

				rgb16 = 0;
				if (!pbi->compress) //rgb555
					rgb16 = ((unsigned short)(pxc->r & RGB_MASK_5B) << 10) | ((unsigned short)(pxc->g & RGB_MASK_5B) << 5) | (unsigned short)(pxc->b & RGB_MASK_5B);
				else //rgb565
					rgb16 = ((unsigned short)(pxc->r & RGB_MASK_5B) << 11) | ((unsigned short)(pxc->g & RGB_MASK_6B) << 5) | (unsigned short)(pxc->b & RGB_MASK_5B);

				//PUT_SWORD_LIT((buf + total + ind), 0, rgb16);
				buf[total + ind] = LIT_GETLBYTE(rgb16);
				buf[total + ind + 1] = LIT_GETHBYTE(rgb16);
				break;
			case 24:
				ind = col * 3;
				if (!buf)
					break;

				buf[total + ind] = pxc->b;
				buf[total + ind + 1] = pxc->g;
				buf[total + ind + 2] = pxc->r;
				break;
			case 32:
				ind = col * 4;
				if (!buf)
					break;

				buf[total + ind] = pxc->b;
				buf[total + ind + 1] = pxc->g;
				buf[total + ind + 2] = pxc->r;
				buf[total + ind + 3] = 0;
				break;
			}
		}
		total += bytes_per_row;
	}

	return total;
}

dword_t fill_pattern_dibbits(const xcolor_t* pxc_front, const xcolor_t* pxc_back, const bitmap_info_head_t* pbi, const bitmap_quad_t* pbq, byte_t* buf, dword_t max)
{
	dword_t bytes_per_row, total = 0;
	int row, col, quad_front, quad_back, ind;
	int dot_row, dot_col;
	byte_t bit;
	unsigned short rgb16;

	dot_row = pbi->height / 2;
	dot_col = pbi->width / 2;

	switch (pbi->clrbits)
	{
	case 1:
		quad_back = _find_quad(pbq, 2, pxc_back);
		quad_front = _find_quad(pbq, 2, pxc_front);
		break;
	case 4:
		quad_back = _find_quad(pbq, 16, pxc_back);
		quad_front = _find_quad(pbq, 16, pxc_front);
		break;
	case 8:
		quad_back = _find_quad(pbq, 216, pxc_back);
		quad_front = _find_quad(pbq, 216, pxc_front);
		break;
	default:
		quad_back = 0;
		quad_front = 0;
	}

	bytes_per_row = BMP_LINE_BYTES(pbi->width, pbi->clrbits);

	for (row = (int)pbi->height - 1; (row >= 0) && (total + bytes_per_row <= max); row--)
	{
		for (col = 0; col < (int)pbi->width; col++)
		{
			switch (pbi->clrbits)
			{
			case 1: //black and white bitmap
				ind = col / 8;
				bit = 1 << (col % 8);
				if (!buf)
					break;

				if (dot_row == row && dot_col == col)
					buf[total + ind] |= bit;
				else
					buf[total + ind] &= ~bit;
				break;
			case 4: //
				ind = col / 2;
				bit = col % 2;
				if (!buf)
					break;

				if (dot_row == row && dot_col == col)
				{
					if (bit)
						buf[total + ind] |= ((quad_front << 4) & 0xF0);
					else
						buf[total + ind] |= (quad_front & 0x0F);
				}
				else
				{
					if (bit)
						buf[total + ind] |= ((quad_back << 4) & 0xF0);
					else
						buf[total + ind] |= (quad_back & 0x0F);
				}
				break;
			case 8: //
				ind = col;
				if (!buf)
					break;

				if (dot_row == row && dot_col == col)
					buf[total + ind] = quad_front;
				else
					buf[total + ind] = quad_back;
				break;
			case 16:
				ind = col * 2;
				if (!buf)
					break;

				if (dot_row == row && dot_col == col)
				{
					rgb16 = 0;
					if (!pbi->compress) //rgb555
						rgb16 = ((unsigned short)(pxc_front->r & RGB_MASK_5B) << 10) | ((unsigned short)(pxc_front->g & RGB_MASK_5B) << 5) | (unsigned short)(pxc_front->b & RGB_MASK_5B);
					else //rgb565
						rgb16 = ((unsigned short)(pxc_front->r & RGB_MASK_5B) << 11) | ((unsigned short)(pxc_front->g & RGB_MASK_6B) << 5) | (unsigned short)(pxc_front->b & RGB_MASK_5B);
				}
				else
				{
					rgb16 = 0;
					if (!pbi->compress) //rgb555
						rgb16 = ((unsigned short)(pxc_back->r & RGB_MASK_5B) << 10) | ((unsigned short)(pxc_back->g & RGB_MASK_5B) << 5) | (unsigned short)(pxc_back->b & RGB_MASK_5B);
					else //rgb565
						rgb16 = ((unsigned short)(pxc_back->r & RGB_MASK_5B) << 11) | ((unsigned short)(pxc_back->g & RGB_MASK_6B) << 5) | (unsigned short)(pxc_back->b & RGB_MASK_5B);
				}

				//PUT_SWORD_LIT((buf + total + ind), 0, rgb16);
				buf[total + ind] = LIT_GETLBYTE(rgb16);
				buf[total + ind + 1] = LIT_GETHBYTE(rgb16);
				break;
			case 24:
				ind = col * 3;
				if (!buf)
					break;

				if (dot_row == row && dot_col == col)
				{
					buf[total + ind] = pxc_front->b;
					buf[total + ind + 1] = pxc_front->g;
					buf[total + ind + 2] = pxc_front->r;
				}
				else
				{
					buf[total + ind] = pxc_back->b;
					buf[total + ind + 1] = pxc_back->g;
					buf[total + ind + 2] = pxc_back->r;
				}
				break;
			case 32:
				ind = col * 4;
				if (!buf)
					break;

				if (dot_row == row && dot_col == col)
				{
					buf[total + ind] = pxc_front->b;
					buf[total + ind + 1] = pxc_front->g;
					buf[total + ind + 2] = pxc_front->r;
					buf[total + ind + 3] = 0;
				}
				else
				{
					buf[total + ind] = pxc_back->b;
					buf[total + ind + 1] = pxc_back->g;
					buf[total + ind + 2] = pxc_back->r;
					buf[total + ind + 3] = 0;
				}
				break;
			}
		}
		total += bytes_per_row;
	}

	return total;
}

static void _put_color_bits(int row, int col, const xcolor_t* pxc, const bitmap_quad_t* pbq, int w, int h, int clrbits, byte_t* pb)
{
	dword_t bytes_per_row;
	int ind;
	byte_t quad, bits;
	unsigned short rgb16;
	unsigned int rgb32;

	bytes_per_row = BMP_LINE_BYTES(w, clrbits);

	pb += (h - row - 1)* bytes_per_row;

	switch (clrbits)
	{
	case 1:
		ind = col / 8;
		bits = 1 << (col % 8);
		quad = (byte_t)_find_quad(pbq, 2, pxc);
		if (quad)
			pb[ind] |= bits;
		else
			pb[ind] &= ~bits;
		break;
	case 4:
		ind = col / 2;
		quad = (byte_t)_find_quad(pbq, 16, pxc);
		if (col % 2)
			pb[ind] |= ((quad << 4) & 0xF0);
		else
			pb[ind] |= (quad & 0x0F);
		break;
	case 8:
		ind = col;
		quad = (byte_t)_find_quad(pbq, 216, pxc);
		pb[ind] = quad;
		break;
	case 16:
		ind = col * 2;
		rgb16 = ((unsigned short)(pxc->r & RGB_MASK_5B) << 10) | ((unsigned short)(pxc->g & RGB_MASK_5B) << 5) | (unsigned short)(pxc->b & RGB_MASK_5B);
		PUT_SWORD_LIT(pb, ind, rgb16);
		break;
	case 24:
		ind = col * 3;
		rgb32 = ((unsigned int)(pxc->r) << 16) | ((unsigned int)(pxc->g) << 8) | (unsigned int)(pxc->b);
		PUT_THREEBYTE_LIT(pb, ind, rgb32);
		break;
	case 32:
		ind = col * 4;
		rgb32 = ((unsigned int)(pxc->a) << 24) | ((unsigned int)(pxc->r) << 16) | ((unsigned int)(pxc->g) << 8) | (unsigned int)(pxc->b);
		PUT_DWORD_LIT(pb, ind, rgb32);
		break;
	}
}

dword_t fill_gradient_dibbits(const xcolor_t* pxc_brim, const xcolor_t* pxc_core, const tchar_t* lay, const bitmap_info_head_t* pbi, byte_t* buf, dword_t max)
{
	dword_t bytes_per_row;
	int row, col;
	xcolor_t xc;
	float f;

	bytes_per_row = BMP_LINE_BYTES(pbi->width, pbi->clrbits);

	if (compare_text(lay, -1, GDI_ATTR_GRADIENT_HORZ, -1, 1) == 0)
	{
		xc.r = pxc_brim->r, xc.g = pxc_brim->g, xc.b = pxc_brim->b;
		for (col = 0; col < (int)pbi->width / 2; col++)
		{
			for (row = 0; row < (int)pbi->height; row++)
			{
				_put_color_bits(row, col, &xc, NULL, pbi->width, pbi->height, pbi->clrbits, buf);
			}
			f = (float)(col + 1) / (float)(pbi->width / 2);
			xc.r = pxc_brim->r + (unsigned char)(f * (pxc_core->r - pxc_brim->r));
			xc.g = pxc_brim->g + (unsigned char)(f * (pxc_core->g - pxc_brim->g));
			xc.b = pxc_brim->b + (unsigned char)(f * (pxc_core->b - pxc_brim->b));
		}

		xc.r = pxc_core->r, xc.g = pxc_core->g, xc.b = pxc_core->b;
		f = 1.0 / (pbi->width / 2);
		for (col = (int)pbi->width / 2; col < (int)pbi->width; col++)
		{
			for (row = 0; row < (int)pbi->height; row++)
			{
				_put_color_bits(row, col, &xc, NULL, pbi->width, pbi->height, pbi->clrbits, buf);
			}
			f = (float)(col - pbi->width / 2 + 1) / (float)(pbi->width / 2);
			xc.r = pxc_core->r + (unsigned char)(f * (pxc_brim->r - pxc_core->r));
			xc.g = pxc_core->g + (unsigned char)(f * (pxc_brim->g - pxc_core->g));
			xc.b = pxc_core->b + (unsigned char)(f * (pxc_brim->b - pxc_core->b));
		}
	}
	else if (compare_text(lay, -1, GDI_ATTR_GRADIENT_VERT, -1, 1) == 0)
	{
		xc.r = pxc_brim->r, xc.g = pxc_brim->g, xc.b = pxc_brim->b;
		for (row = 0; row < (int)pbi->height / 2; row++)
		{
			for (col = 0; col < (int)pbi->width; col++)
			{
				_put_color_bits(row, col, &xc, NULL, pbi->width, pbi->height, pbi->clrbits, buf);
			}
			f = (float)(row + 1) / (float)(pbi->height / 2);
			xc.r = pxc_brim->r + (unsigned char)(f * (pxc_core->r - pxc_brim->r));
			xc.g = pxc_brim->g + (unsigned char)(f * (pxc_core->g - pxc_brim->g));
			xc.b = pxc_brim->b + (unsigned char)(f * (pxc_core->b - pxc_brim->b));
		}

		xc.r = pxc_core->r, xc.g = pxc_core->g, xc.b = pxc_core->b;
		for (row = (int)pbi->height / 2; row < (int)pbi->height; row++)
		{
			for (col = 0; col < (int)pbi->width; col++)
			{
				_put_color_bits(row, col, &xc, NULL, pbi->width, pbi->height, pbi->clrbits, buf);
			}
			f = (float)(row - pbi->height / 2 + 1) / (float)(pbi->height / 2);
			xc.r = pxc_core->r + (unsigned char)(f * (pxc_brim->r - pxc_core->r));
			xc.g = pxc_core->g + (unsigned char)(f * (pxc_brim->g - pxc_core->g));
			xc.b = pxc_core->b + (unsigned char)(f * (pxc_brim->b - pxc_core->b));
		}
	}
	
	return (bytes_per_row * pbi->height);
}

dword_t fill_code128_dibbits(const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols, int unit, const bitmap_info_head_t* pbi, const bitmap_quad_t* pbq, byte_t* buf, dword_t max)
{
	dword_t total = 0;
	int row, col, len;
	int dw;
	bool_t front;

	front = 1;
	col = 0;
	for (dw = 0; dw < bar_cols; dw++)
	{
		len = (bar_buf[dw] - '0') * unit;

		while (len--)
		{
			for (row = 0; row < (int)pbi->height; row++)
			{
				if (front)
					_put_color_bits(row, col, pxc_front, pbq, pbi->width, pbi->height, pbi->clrbits, buf);
				else
					_put_color_bits(row, col, pxc_back, pbq, pbi->width, pbi->height, pbi->clrbits, buf);

				total++;
			}
			col++;
		}

		front = (front) ? 0 : 1;
	}

	return total;
}

dword_t fill_pdf417_dibbits(const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_row, int bar_col, int unit, const bitmap_info_head_t* pbi, const bitmap_quad_t* pbq, byte_t* buf, dword_t max)
{
	dword_t total = 0;
	int row, col, i, j, ur, uc;
	byte_t c, b;
	bool_t front;

	row = 0;
	for (i = 0; i < bar_row; i++)
	{
		col = 0;
		for (j = 0; j < bar_col; j++)
		{
			c = *(bar_buf + i * bar_col + j);
			b = 0x80;

			while (b)
			{
				front = (c & b) ? 0 : 1;

				for (ur = 0; ur < unit;ur++)
				{
					for (uc = 0; uc < unit; uc++)
					{
						if (front)
							_put_color_bits(row + ur, col + uc, pxc_front, pbq, pbi->width, pbi->height, pbi->clrbits, buf);
						else
							_put_color_bits(row + ur, col + uc, pxc_back, pbq, pbi->width, pbi->height, pbi->clrbits, buf);

						total++;
					}
				}
				b = b >> 1;
				col += unit;
			}
		}
		row += unit;
	}

	return total;
}

dword_t fill_qrcode_dibbits(const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_row, int bar_col, int unit, const bitmap_info_head_t* pbi, const bitmap_quad_t* pbq, byte_t* buf, dword_t max)
{
	dword_t total = 0;
	int row, col, i, j, ur, uc;
	byte_t c, b;
	bool_t front;

	row = 0;
	for (i = 0; i < bar_row; i++)
	{
		col = 0;
		for (j = 0; j < bar_col; j++)
		{
			c = *(bar_buf + i * bar_col + j);
			b = 0x80;

			while (b)
			{
				front = (c & b) ? 1 : 0;

				for (ur = 0; ur < unit; ur++)
				{
					for (uc = 0; uc < unit; uc++)
					{
						if (front)
							_put_color_bits(row + ur, col + uc, pxc_front, pbq, pbi->width, pbi->height, pbi->clrbits, buf);
						else
							_put_color_bits(row + ur, col + uc, pxc_back, pbq, pbi->width, pbi->height, pbi->clrbits, buf);

						total++;
					}
				}
				b = b >> 1;
				col += unit;
			}
		}
		row += unit;
	}

	return total;
}