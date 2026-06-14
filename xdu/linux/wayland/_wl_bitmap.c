/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc bitmap document

	@module	wl_bitmap.c | wayland implement file

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

#include "_if_wayland.h"

static void _CenterRect(xrect_t* pRect, int src_width, int src_height)
{
	if (pRect->w > (unsigned short)src_width)
	{
		pRect->x = pRect->x + (pRect->w - (unsigned short)src_width) / 2;
		pRect->w = (unsigned short)src_width;
	}
	if (pRect->h > (unsigned short)src_height)
	{
		pRect->y = pRect->y + (pRect->h - (unsigned short)src_height) / 2;
		pRect->h = (unsigned short)src_height;
	}
}

void wlDestroyBitmap(bitmap_t rbm)
{
    NOP;
}

void wlGetBitmapSize(bitmap_t rbm, int* pw, int* ph)
{
   NOP;
}

bitmap_t wlCreateContextBitmap(visual_t rdc)
{
	return NULL;
}

bitmap_t wlCreateColorBitmap(visual_t rdc, const xcolor_t* pxc, int w, int h)
{
	return NULL;
}

bitmap_t wlCreatePatternBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h)
{
	wayland_context_t* ctx = TypePtrFromHead(wayland_context_t, rdc);
    wayland_bitmap_t* bmp;

	return NULL;
}

bitmap_t wlCreateGradientBitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type)
{
	wayland_context_t* ctx = TypePtrFromHead(wayland_context_t, rdc);
    wayland_bitmap_t* bmp;

	return NULL;
}

bitmap_t wlCreateCode128Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols)
{
	wayland_context_t* ctx = TypePtrFromHead(wayland_context_t, rdc);
    wayland_bitmap_t* bmp;

	return NULL;
}

bitmap_t wlCreatePDF417Bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
	wayland_context_t* ctx = TypePtrFromHead(wayland_context_t, rdc);
    wayland_bitmap_t* bmp;

	return NULL;
}

bitmap_t wlCreateQRCodeBitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
	wayland_context_t* ctx = TypePtrFromHead(wayland_context_t, rdc);
    wayland_bitmap_t* bmp;

	return NULL;
} 

bitmap_t wlCreateStorageBitmap(visual_t rdc, const tchar_t* fname)
{
	wayland_context_t* ctx = TypePtrFromHead(wayland_context_t, rdc);
	wayland_bitmap_t* bmp;

	return NULL;
}

//ZPixmap width * height * ((depth + 7) / 8) width * ((depth + 7) / 8)  
//XYPixmap ((width + 7) / 8) * height * depth (width + 7) / 8  
//XYBitmap ((width + 7) / 8) * height * 1   (width + 7) / 8  
/*******************************************************************************/
#pragma pack (2)
typedef struct _bitmap_filehead_t
{
    unsigned short type;		//bitmap file type
    unsigned int size;		//bitmap file size
    unsigned short reserved1;
    unsigned short reserved2;
    unsigned int offset;		//bitmap data offset from file header
}bitmap_filehead_t;		//14 bytes
#pragma pack ()

typedef struct _bitmap_infohead_t{
    unsigned int size;		//struct size
    unsigned int width;		//bitmap point width
    unsigned int height;		//bitmap point height
    unsigned short planes;		//number of planes for the target device, set to 1
    unsigned short bitcount;	//the number of bits-per-pixel. 1:is monochrome; 4:maximum of 16 colors; 8:maximum of 256 colors; 16:maximum of 2^16 colors; 24~; 32~;
    unsigned int compression; //type of compression.0: uncompressed format; 1: RLE format for bitmaps with 8 bpp; 2:RLE format for bitmaps with 4 bpp.
    unsigned int imagesize;	// the size, in bytes, of the image
    unsigned int horzpixels;	//the horizontal resolution, in pixels-per-meter
    unsigned int vertpixels;	//the vertical resolution, in pixels-per-meter
    unsigned int clrused;	// the number of color indexes in the color table  that are actually used by the bitmap
    unsigned int clrimportant;//the number of color indexes that are required for displaying the bitmap
}bitmap_infohead_t;			//40 bytes

typedef struct _bitmap_rgbquad_t{
    unsigned char blue;		//blue lighten(0-255)
    unsigned char green;		//green lighten(0-255)
    unsigned char red;			//red lighten(0-255)
    unsigned char reserved;	//set to zero
}bitmap_rgbquad_t;


dword_t wlGetBitmapBytes(bitmap_t rb)
{
    return 0;
}

bitmap_t wlLoadBitmapFromBytes(visual_t rdc, const unsigned char* pb, dword_t bytes)
{
	wayland_context_t* ctx = TypePtrFromHead(wayland_context_t, rdc);

	return NULL;
}

dword_t wlSaveBitmapToBytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max)
{
	return 0;
}

bitmap_t wlLoadBitmapFromIcon(visual_t rdc, const tchar_t* iname)
{
    return NULL;
}

bitmap_t wlLoadBitmapFromThumb(visual_t rdc, const tchar_t* file)
{    
    return NULL;
}

