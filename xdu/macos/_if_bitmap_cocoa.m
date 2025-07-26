/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc bitmap document

	@module	if_bitmap_cocoa.m | macos implement file

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

#include "../xduloc.h"

#ifdef XDU_SUPPORT_CONTEXT_BITMAP


static void _CenterRect(CGRect* pRect, int src_width, int src_height)
{
	if (pRect->size.width > (unsigned short)src_width)
	{
		pRect->origin.x = pRect->origin.x + (pRect->size.width - (unsigned short)src_width) / 2;
		pRect->size.width = (unsigned short)src_width;
	}
	if (pRect->size.height > (unsigned short)src_height)
	{
		pRect->origin.y = pRect->origin.y + (pRect->size.height - (unsigned short)src_height) / 2;
		pRect->size.height = (unsigned short)src_height;
	}
}

void _destroy_bitmap(bitmap_t rbm)
{
    cocoa_bitmap_t* bmp = (cocoa_bitmap_t*)rbm;
    
	CGImageRelease(bmp->image);

	free(bmp);
}

void _get_bitmap_size(bitmap_t rbm, int* pw, int* ph)
{
   cocoa_bitmap_t* bmp = (cocoa_bitmap_t*)rbm;

    if(pw) *pw = CGImageGetWidth(bmp->image);
    
    if(ph) *ph = CGImageGetHeight(bmp->image);
}

bitmap_t _create_context_bitmap(visual_t rdc)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;
	cocoa_bitmap_t* bmp;

	bmp = (cocoa_bitmap_t*)xmem_alloc(sizeof(cocoa_bitmap_t));
	
	bmp->image = CGBitmapContextCreateImage(ctx->context);

	return &(bmp->head);
}

bitmap_t _create_color_bitmap(visual_t rdc, const xcolor_t* pxc, int w, int h)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;
    cocoa_bitmap_t* bmp;

	int bytes_per_line;
	bitmap_info_head_t bih = { 0 };
	byte_t* pbb = NULL;

	bytes_per_line = BMP_LINE_BYTES(w, 32);

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = 32;
	bih.compress = 0;
	bih.bytes = bytes_per_line * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	pbb = (byte_t*)xmem_alloc(bih.bytes);

	fill_color_dibbits(pxc, &bih, NULL, pbb, bih.bytes);

	CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);

	CGContextRef context = CGBitmapContextCreate(
        pbb,
        w,
        h,
        8,
        bytes_per_line,
        colorSpace,
        kCGImageAlphaPremultipliedLast
    );

	bmp = (cocoa_bitmap_t*)xmem_alloc(sizeof(cocoa_bitmap_t));
	bmp->image = CGBitmapContextCreateImage(context);
    
	CGColorSpaceRelease(colorSpace);
	CGContextRelease(context);

    return &(bmp->head);
}

bitmap_t _create_pattern_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;
    cocoa_bitmap_t* bmp;

	int bytes_per_line;
	bitmap_info_head_t bih = { 0 };
	byte_t* pbb = NULL;

	bytes_per_line = BMP_LINE_BYTES(w, 32);

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = 32;
	bih.compress = 0;
	bih.bytes = bytes_per_line * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	pbb = (byte_t*)xmem_alloc(bih.bytes);

	fill_pattern_dibbits(pxc_front, pxc_back, &bih, NULL, pbb, bih.bytes);

	CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);

	CGContextRef context = CGBitmapContextCreate(
        pbb,
        w,
        h,
        8,
        bytes_per_line,
        colorSpace,
        kCGImageAlphaPremultipliedLast
    );

	bmp = (cocoa_bitmap_t*)xmem_alloc(sizeof(cocoa_bitmap_t));
	bmp->image = CGBitmapContextCreateImage(context);
    
	CGColorSpaceRelease(colorSpace);
	CGContextRelease(context);

    return &(bmp->head);
}

bitmap_t _create_gradient_bitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;
    cocoa_bitmap_t* bmp;

	int bytes_per_line;
	bitmap_info_head_t bih = { 0 };
	byte_t* pbb = NULL;

	bytes_per_line = BMP_LINE_BYTES(w, 32);

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = 32;
	bih.compress = 0;
	bih.bytes = bytes_per_line * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	pbb = (byte_t*)xmem_alloc(bih.bytes);

	fill_gradient_dibbits(pxc_brim, pxc_core, type, &bih, pbb, bih.bytes);

	CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);

	CGContextRef context = CGBitmapContextCreate(
        pbb,
        w,
        h,
        8,
        bytes_per_line,
        colorSpace,
        kCGImageAlphaPremultipliedLast
    );

	bmp = (cocoa_bitmap_t*)xmem_alloc(sizeof(cocoa_bitmap_t));
	bmp->image = CGBitmapContextCreateImage(context);
    
	CGColorSpaceRelease(colorSpace);
	CGContextRelease(context);
    
    return &(bmp->head);
}

bitmap_t _create_code128_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;
    cocoa_bitmap_t* bmp;

	int bytes_per_line;
	int w, h, unit = 2;
	bitmap_info_head_t bih = { 0 };
	byte_t* pbb = NULL;

	w = code128_units(bar_buf, bar_cols) * unit;
	h = 10 * unit;

	bytes_per_line = BMP_LINE_BYTES(w, 32);

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = 32;
	bih.compress = 0;
	bih.bytes = bytes_per_line * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	pbb = (byte_t*)xmem_alloc(bih.bytes);

	fill_code128_dibbits(pxc_front, pxc_back, bar_buf, bar_cols, unit, &bih, NULL, pbb, bih.bytes);

	CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);

	CGContextRef context = CGBitmapContextCreate(
        pbb,
        w,
        h,
        8,
        bytes_per_line,
        colorSpace,
        kCGImageAlphaPremultipliedLast
    );

	bmp = (cocoa_bitmap_t*)xmem_alloc(sizeof(cocoa_bitmap_t));
	bmp->image = CGBitmapContextCreateImage(context);
    
	CGColorSpaceRelease(colorSpace);
	CGContextRelease(context);
    
    return &(bmp->head);
}

bitmap_t _create_pdf417_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;
    cocoa_bitmap_t* bmp;

	int bytes_per_line;
	int w, h, unit = 2;
	bitmap_info_head_t bih = { 0 };
	byte_t* pbb = NULL;

	w = (pdf417_units(bar_buf, bar_rows, bar_cols) / bar_rows) * unit;
	h = bar_rows * unit;

	bytes_per_line = BMP_LINE_BYTES(w, 32);

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = 32;
	bih.compress = 0;
	bih.bytes = bytes_per_line * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	pbb = (byte_t*)xmem_alloc(bih.bytes);

	fill_pdf417_dibbits(pxc_front, pxc_back, bar_buf, bar_rows, bar_cols, unit, &bih, NULL, pbb, bih.bytes);

	CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);

	CGContextRef context = CGBitmapContextCreate(
        pbb,
        w,
        h,
        8,
        bytes_per_line,
        colorSpace,
        kCGImageAlphaPremultipliedLast
    );

	bmp = (cocoa_bitmap_t*)xmem_alloc(sizeof(cocoa_bitmap_t));
	bmp->image = CGBitmapContextCreateImage(context);
    
	CGColorSpaceRelease(colorSpace);
	CGContextRelease(context);

    return &(bmp->head);
}

bitmap_t _create_qrcode_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;
    cocoa_bitmap_t* bmp;

	int bytes_per_line;
	int w, h, unit = 2;
	bitmap_info_head_t bih = { 0 };
	byte_t* pbb = NULL;

	w = (qr_units(bar_buf, bar_rows, bar_cols) / bar_rows) * unit;
	h = bar_rows * unit;

	bytes_per_line = BMP_LINE_BYTES(w, 32);

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = 32;
	bih.compress = 0;
	bih.bytes = bytes_per_line * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	pbb = (byte_t*)xmem_alloc(bih.bytes);

	fill_qrcode_dibbits(pxc_front, pxc_back, bar_buf, bar_rows, bar_cols, unit, &bih, NULL, pbb, bih.bytes);

	CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);

	CGContextRef context = CGBitmapContextCreate(
        pbb,
        w,
        h,
        8,
        bytes_per_line,
        colorSpace,
        kCGImageAlphaPremultipliedLast
    );

	bmp = (cocoa_bitmap_t*)xmem_alloc(sizeof(cocoa_bitmap_t));
	bmp->image = CGBitmapContextCreateImage(context);
    
	CGColorSpaceRelease(colorSpace);
	CGContextRelease(context);

    return &(bmp->head);
} 

bitmap_t _create_storage_bitmap(visual_t rdc, const tchar_t* fname)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;
    cocoa_bitmap_t* bmp;
	tchar_t fpath[PATH_LEN * 2] = { 0 };

	if(is_null(fname)) return NULL;

	if(*fname == _T('.') && *(fname + 1) == _T('/'))
	{
		get_runpath(NULL, fpath, PATH_LEN);
		xscat(fpath, fname + 1);
	}else if(*fname != _T('/'))
	{
		get_runpath(NULL, fpath, PATH_LEN);
		xsncat(fpath, _T("/"), 1);
		xscat(fpath, fname);
	}else
	{
		xscpy(fpath, fname);
	}

	CFStringRef cfPath = CFStringCreateWithCString(NULL, fpath, kCFStringEncodingUTF8);
    CFURLRef cfURL = CFURLCreateWithFileSystemPath(NULL, cfPath, kCFURLPOSIXPathStyle, false);
    if(cfPath) CFRelease(cfPath);
    CGImageSourceRef source = CGImageSourceCreateWithURL(cfURL, NULL);
    if(cfURL) CFRelease(cfURL);

    if (!source) return NULL;

	bmp = (cocoa_bitmap_t*)xmem_alloc(sizeof(cocoa_bitmap_t));
    bmp->image = CGImageSourceCreateImageAtIndex(source, 0, NULL);
    CFRelease(source);

	return &(bmp->head);
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


dword_t _get_bitmap_bytes(bitmap_t rb)
{
    cocoa_bitmap_t* bmp = (cocoa_bitmap_t*)rb;
    
	size_t width = CGImageGetWidth(bmp->image);
    size_t height = CGImageGetHeight(bmp->image);
    size_t bitsPerComponent = CGImageGetBitsPerComponent(bmp->image);
    size_t bitsPerPixel = CGImageGetBitsPerPixel(bmp->image);
    size_t bytesPerRow = CGImageGetBytesPerRow(bmp->image);

	unsigned int dwClrUsed = 0;
	unsigned int dwSizeImage;
	unsigned int dwTotal;

    dwSizeImage = ((width * bitsPerPixel + 31) & ~31) / 8 * height;

	dwTotal = (unsigned int)(sizeof(bitmap_filehead_t) + sizeof(bitmap_infohead_t) + dwClrUsed * sizeof(bitmap_rgbquad_t) + dwSizeImage);

	return dwTotal;
}

bitmap_t _load_bitmap_from_bytes(visual_t rdc, const unsigned char* pb, dword_t bytes)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;

	bitmap_infohead_t* pbmi;
	bitmap_filehead_t bfh;
	char* lpBits;
    
    cocoa_bitmap_t* bmp;

	if (!pb)
		return NULL;

	if ((unsigned int)bytes < sizeof(bitmap_filehead_t) + sizeof(bitmap_infohead_t))
		return NULL;

	memcpy((void*)&bfh, (void*)pb, sizeof(bitmap_filehead_t));

	if (bfh.type != 0x4d42)
		return NULL;

	if ((unsigned int)bytes < bfh.size)
		return NULL;

	pbmi = (bitmap_infohead_t*)(pb + sizeof(bitmap_filehead_t));
    size_t bytes_per_line = ((pbmi->width * pbmi->bitcount + 31) & ~31) / 8;

	lpBits = (char*)(pb + bfh.offset);
    
	CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);

	CGContextRef context = CGBitmapContextCreate(
        lpBits,
        pbmi->width,
		pbmi->height,
        8,
        bytes_per_line,
        colorSpace,
        kCGImageAlphaPremultipliedLast
    );

	bmp->image = CGBitmapContextCreateImage(context);
    
	CGColorSpaceRelease(colorSpace);
	CGContextRelease(context);

    return &(bmp->head);
}

dword_t _save_bitmap_to_bytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;
	cocoa_bitmap_t* bmp = (cocoa_bitmap_t*)rb;
    
	bitmap_infohead_t* pbmi;
	unsigned short    cClrBits;
	bitmap_filehead_t bfh;
	char* lpBits;
	unsigned int dwTotal;

	size_t width = CGImageGetWidth(bmp->image);
    size_t height = CGImageGetHeight(bmp->image);
    size_t bitsPerComponent = CGImageGetBitsPerComponent(bmp->image);
    size_t bitsPerPixel = CGImageGetBitsPerPixel(bmp->image);
    size_t bytesPerRow = CGImageGetBytesPerRow(bmp->image);
	CGColorSpaceRef colorSpace = CGImageGetColorSpace(bmp->image);
    CGBitmapInfo bitmapInfo = CGImageGetBitmapInfo(bmp->image);

	unsigned char *data = (unsigned char*)calloc(height, bytesPerRow);
   CGContextRef context = CGBitmapContextCreate(
        data,                   // Memory buffer
        width,                  // Width of the bitmap
        height,                 // Height of the bitmap
        bitsPerComponent,       // Bits per component
        bytesPerRow,            // Bytes per row
        colorSpace,             // Color space
        bitmapInfo              // Bitmap info
    );

	CGContextDrawImage(context, CGRectMake(0, 0, width, height), bmp->image);

	data = (unsigned char *)CGBitmapContextGetData(context);

	if (bitsPerPixel < 24)
		pbmi = (bitmap_infohead_t*)calloc(1, sizeof(bitmap_infohead_t) + sizeof(bitmap_rgbquad_t) * (unsigned int)(1 << bitsPerPixel));
	else
		pbmi = (bitmap_infohead_t*)calloc(1, sizeof(bitmap_infohead_t));

	pbmi->size = sizeof(bitmap_infohead_t);
	pbmi->width = width;
	pbmi->height = height;
	pbmi->planes = 1;
	pbmi->bitcount = bitsPerPixel;
	if (bitsPerPixel < 24)
		pbmi->clrused = (1 << bitsPerPixel);
	else
		pbmi->clrused = 0;
	pbmi->compression = 0;
	pbmi->imagesize = ((pbmi->width * bitsPerPixel + 31) & ~31) / 8 * pbmi->height;
	pbmi->clrimportant = 0;

	bfh.type = 0x4d42;        // 0x42 = "B" 0x4d = "M"
	bfh.size = (unsigned int)(sizeof(bitmap_filehead_t) + sizeof(bitmap_infohead_t) + pbmi->clrused * sizeof(bitmap_rgbquad_t) + pbmi->imagesize);
	bfh.reserved1 = 0;
	bfh.reserved2 = 0;
	bfh.offset = (unsigned int)(sizeof(bitmap_filehead_t) + sizeof(bitmap_infohead_t) + pbmi->clrused * sizeof(bitmap_rgbquad_t));

	dwTotal = 0;
	if (buf)
	{
		memcpy((void*)(buf + dwTotal), (void*)&bfh, sizeof(bitmap_filehead_t));
	}
	dwTotal += sizeof(bitmap_filehead_t);

	if (buf)
	{
		memcpy((void*)(buf + dwTotal), (void*)pbmi, sizeof(bitmap_infohead_t) + pbmi->clrused * sizeof(bitmap_rgbquad_t));
	}
	dwTotal += sizeof(bitmap_infohead_t) + pbmi->clrused * sizeof(bitmap_rgbquad_t);

	if (buf)
	{
		lpBits = (char*)(buf + dwTotal);
	}
	else
	{
		lpBits = NULL;
	}
	dwTotal += pbmi->imagesize;

	if (buf)
	{
        memcpy(lpBits, data, pbmi->imagesize);
	}

	CGContextRelease(context);

	free(pbmi);

	return dwTotal;
}

#ifdef XDU_SUPPORT_SHELL
bitmap_t _load_bitmap_from_icon(visual_t rdc, const tchar_t* iname)
{
    return NULL;
}

bitmap_t _load_bitmap_from_thumb(visual_t rdc, const tchar_t* file)
{    
    return NULL;
}
#endif //XDU_SUPPORT_SHELL

#endif //XDU_SUPPORT_CONTEXT_BITMAP
