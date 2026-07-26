/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc mgc context document

	@module	mctx.h | interface file

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

#ifndef _MCTX_H
#define _MCTX_H

#include "../xdgdef.h"
#include "mdev.h"
#include "mfnt.h"


#ifdef	__cplusplus
extern "C" {
#endif

EXP_API visual_t create_mgc_visual(const tchar_t* devName, const tchar_t* formName, int width, int height, int dpi);

EXP_API visual_t create_shm_visual(const tchar_t *devName, int width, int height, int dpi, void* shmBuffer, dword_t shmStride);

EXP_API void destroy_mgc_visual(visual_t mgc);

EXP_API mem_device_ptr mgc_get_device_interface(visual_t mgc, device_t* phand);

EXP_API mem_font_ptr mgc_get_font_interface(visual_t mgc, fontset_t* phand);

EXP_API void mgc_get_device_caps(visual_t mgc, dev_cap_t* pcap);

EXP_API void mgc_set_rop(visual_t mgc, int rop);

EXP_API int mgc_get_rop(visual_t mgc);

EXP_API dword_t mgc_save_bytes(visual_t mgc, byte_t *buf, dword_t max);

EXP_API float mgc_pixel_metric(visual_t mgc);

EXP_API float mgc_font_metric(visual_t mgc, const tchar_t* xf_size);

#ifdef	__cplusplus
}
#endif


#endif /*_MCTX_H*/