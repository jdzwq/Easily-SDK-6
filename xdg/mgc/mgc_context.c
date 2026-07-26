/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc mgc gdi document

	@module	mgcgdi.c | implement file

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

#include "mctx.h"

#include "mdrv.h"
#include "mdev.h"
#include "mpap.h"
#include "mfnt.h"
#include "mclr.h"

#include "../xdgmgc.h"
#include "../xdgutil.h"


typedef struct _memo_context_t
{
	handle_head head;

	mem_device_ptr device;
	device_t handle;

	int rop; /*raster operation mode*/
	bitmap_file_head_t bitmap_head;
	void* bitmap_buffer;
	dword_t bitmap_stride;

	mem_font_ptr font_inf;
	fontset_t ft;
	xfont_t xf;
} memo_context_t;

/*********************************************************************/

static const mem_device_ptr select_device(const tchar_t *devName)
{
	if (xsicmp(devName, MGC_DEVICE_BITMAP_MONOCHROME) == 0)
		return &monochrome_bitmap_device;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_GRAYSCALE) == 0)
		return &grayscale_bitmap_device;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_TRUECOLOR16) == 0)
		return &truecolor16_bitmap_device;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_TRUECOLOR24) == 0)
		return &truecolor24_bitmap_device;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_TRUECOLOR32) == 0)
		return &truecolor32_bitmap_device;
	else
	{
		set_last_error(_T("select_device"), _T("unknown memory device"), -1);
		return NULL;
	}
}

visual_t create_mgc_visual(const tchar_t *devName, const tchar_t *formName, int width, int height, int dpi)
{
	memo_context_t *pmgc;
	dev_prn_t prn = {0};
	dword_t dwHead, dwQuad, dwData;
	xfont_t xf;

	TRY_CATCH;

	pmgc = (memo_context_t *)xmem_alloc(sizeof(memo_context_t));
	pmgc->head.tag = _VISUAL_MEMORY;

	pmgc->device = select_device(devName);
	if (!pmgc->device)
	{
		raise_user_error(_T("create_mgc_visual"), _T("select_device"));
	}

	if (!select_paper(formName, &prn))
	{
		prn.paper_width = (int)((float)width * 10.0f);
		prn.paper_height = (int)((float)height * 10.0f);
	}else
	{
		width = (int)((float)prn.paper_width / 10.0f);
		height = (int)((float)prn.paper_height / 10.0f);
	}

	xscpy(prn.devname, devName);
	prn.dpi = dpi;

	pmgc->handle = (*(pmgc->device->openDevice))(&prn);
	if (!pmgc->handle)
	{
		raise_user_error(_T("create_mgc_visual"), _T("openDevice"));
	}

	(*(pmgc->device->getBitmapInfo))(pmgc->handle, &dwHead, &dwQuad, &dwData);

	pmgc->bitmap_head.flag = BMP_FLAG;
	pmgc->bitmap_head.fsize = BMP_FILEHEADER_SIZE + dwHead + dwQuad + dwData;
	pmgc->bitmap_head.offset = BMP_FILEHEADER_SIZE + dwHead + dwQuad;

	pmgc->bitmap_buffer = (byte_t*)xmem_alloc(dwData);
	pmgc->bitmap_stride = dwData / height;
	
	(*(pmgc->device->setDeviceBuffer))(pmgc->handle, pmgc->bitmap_buffer, pmgc->bitmap_stride);

	pmgc->font_inf = &font_Internal;	
	default_xfont(&xf);
	mgc_set_xfont(&(pmgc->head), &xf);

	END_CATCH;

	return &(pmgc->head);

ONERROR:
	XDK_TRACE_LAST;

	if (pmgc)
	{
		if(pmgc->bitmap_buffer)
			xmem_free(pmgc->bitmap_buffer);

		xmem_free(pmgc);
	}

	return NULL;
}

visual_t create_shm_visual(const tchar_t *devName, int width, int height, int dpi, void* shmBuffer, dword_t shmStride)
{
	memo_context_t *pmgc;
	dev_prn_t prn = {0};
	dword_t dwHead, dwQuad, dwData;
	xfont_t xf;

	TRY_CATCH;

	pmgc = (memo_context_t *)xmem_alloc(sizeof(memo_context_t));
	pmgc->head.tag = _VISUAL_MEMORY;

	pmgc->device = select_device(devName);
	if (!pmgc->device)
	{
		raise_user_error(_T("create_shm_visual"), _T("select_device"));
	}

	xscpy(prn.devname, devName);
	prn.paper_width = (int)((float)width * 10.0f);
	prn.paper_height = (int)((float)height * 10.0f);
	prn.dpi = dpi;

	pmgc->handle = (*(pmgc->device->openDevice))(&prn);
	if (!pmgc->handle)
	{
		raise_user_error(_T("create_shm_visual"), _T("openDevice"));
	}

	(*(pmgc->device->getBitmapInfo))(pmgc->handle, &dwHead, &dwQuad, &dwData);

	pmgc->bitmap_head.flag = BMP_FLAG;
	pmgc->bitmap_head.fsize = BMP_FILEHEADER_SIZE + dwHead + dwQuad + dwData;
	pmgc->bitmap_head.offset = BMP_FILEHEADER_SIZE + dwHead + dwQuad;

	pmgc->bitmap_buffer = NULL;
	pmgc->bitmap_stride = 0;

	(*(pmgc->device->setDeviceBuffer))(pmgc->handle, shmBuffer, shmStride);

	pmgc->font_inf = &font_Internal;
	default_xfont(&xf);
	mgc_set_xfont(&(pmgc->head), &xf);

	END_CATCH;

	return &(pmgc->head);

ONERROR:
	XDK_TRACE_LAST;

	if (pmgc)
	{
		xmem_free(pmgc);
	}

	return NULL;
}

void destroy_mgc_visual(visual_t mgc)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	if(pmgc->font_inf && pmgc->ft)
	{
		(*(pmgc->font_inf->destroyFontSet))(pmgc->ft);
	}

	if (pmgc->device)
	{
		(*(pmgc->device->closeDevice))(pmgc->handle);
	}

	if(pmgc->bitmap_buffer)
	{
		xmem_free(pmgc->bitmap_buffer);
	}

	xmem_free(pmgc);
}

void mgc_set_xfont_raw(visual_t mgc, const xfont_t* pxf)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	mem_font_ptr pmf;

	pmf = pmgc->font_inf;
	if (!pmf) return;

	if(!pxf) return;
	if(compare_xfont(&(pmgc->xf), pxf) == 0) return;

	xmem_copy((void *)&(pmgc->xf), (void*)pxf, sizeof(xfont_t));

	if(pmgc->ft)
	{
		(*pmf->destroyFontSet)(pmgc->ft);
	}

	pmgc->ft = (*pmf->createFontSet)(&(pmgc->xf));
}

void mgc_get_xfont_raw(visual_t mgc, xfont_t* pxf)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	xmem_copy((void*)pxf, (void *)&(pmgc->xf), sizeof(xfont_t));
}

void mgc_set_rop(visual_t mgc, int rop)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	pmgc->rop = rop;
}

int mgc_get_rop(visual_t mgc)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	return (pmgc->rop);
}

mem_device_ptr mgc_get_device_interface(visual_t mgc, device_t* phand)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	if(phand) *phand = pmgc->handle;

	return (pmgc->device);
}

mem_font_ptr mgc_get_font_interface(visual_t mgc, fontset_t* phand)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	if(phand) *phand = pmgc->ft;

	return (pmgc->font_inf);
}

void mgc_get_device_caps(visual_t mgc, dev_cap_t* pcap)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	dev_cap_t cap;
	double ptpermm;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	(*pmgc->device->getDeviceCaps)(pmgc->handle, pcap);
}

float mgc_pixel_metric(visual_t mgc)
{
	return LOGMMPERPT;
}

float mgc_font_metric(visual_t mgc, const tchar_t* xf_size)
{
	const tchar_t* tk;
	int len;
	float pt, pm = 0.0f;

	tk = xsistr(xf_size, _T("px"));
	if(tk)
	{
		pt = xsntof(xf_size, (int)(tk - xf_size));
		font_metric_by_px(pt, &pm, NULL);
	}
	else
	{
		pt = xstof(xf_size);
		font_metric_by_pt(pt, &pm, NULL);
	}

	return pm;
}

dword_t mgc_save_bytes(visual_t mgc, byte_t *buf, dword_t max)
{
	memo_context_t *pgc = (memo_context_t *)mgc;
	dword_t total = 0;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	total += xbmp_set_head(&pgc->bitmap_head, ((buf) ? (buf + total) : NULL), (max - total));
	total += (*(pgc->device->getBitmap))(pgc->handle, ((buf) ? (buf + total) : NULL), (max - total));

	return total;
}
