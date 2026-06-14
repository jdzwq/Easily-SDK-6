/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc editor document

	@module	editor.h | interface file

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

#ifndef _EDITOR_H
#define _EDITOR_H

#include "../xdcdef.h"

LOC_API int editor_sub_child_command(widget_t widget, int code, vword_t data, uid_t sid, vword_t delta);

LOC_API int editor_sub_keydown(widget_t widget, dword_t ks, int nKey, uid_t sid, vword_t delta);

LOC_API int editor_sub_wchar(widget_t widget, wchar_t nChar, uid_t sid, vword_t delta);

LOC_API int editor_sub_scroll(widget_t widget, bool_t bHorz, int nLine, uid_t sid, vword_t delta);

LOC_API int editor_sub_wheel(widget_t widget, bool_t bHorz, int nDelta, uid_t sid, vword_t delta);

#ifdef	__cplusplus
extern "C" {
#endif

EXP_API void hand_editor_create(widget_t widget, const editor_interface* pei);

EXP_API void hand_editor_destroy(widget_t widget);

#ifdef	__cplusplus
}
#endif

#endif /*_EDITOR_H*/
