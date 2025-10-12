/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc lang document

	@module	lang_.h | interface file

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


#ifndef _XDLANSI_H
#define _XDLANSI_H

#ifdef LANG_CN

/*redefine xdlattr*/
#ifdef DOC_RICH_TITLE
#undef DOC_RICH_TITLE
#define DOC_RICH_TITLE		_T("标题")
#endif

/*redefine gdiattr*/
#ifdef GDI_ATTR_FONT_SIZE_OPTIONS
#undef GDI_ATTR_FONT_SIZE_OPTIONS
#define GDI_ATTR_FONT_SIZE_OPTIONS		_T("5~八号;5.5~七号;6.5~小六;7.5~六号;9~小五;10.5~五号;12~小四;14~四号;15~小三;16~三号;18~小二;24~小一;26~一号;36~小初;42~初号;54~特号;63~特大号;72~一英寸;")
#endif

#ifdef GDI_ATTR_FONT_FAMILY_OPTIONS
#undef GDI_ATTR_FONT_FAMILY_OPTIONS
#define GDI_ATTR_FONT_FAMILY_OPTIONS	_T("隶书~隶书;楷体~楷体;宋体~宋体;微软雅黑~微软雅黑;")
#endif

/*redefine xdldef*/
#ifdef PAGENUM_GUID
#undef PAGENUM_GUID
#define PAGENUM_GUID		_T("第%d页")
#endif

#ifdef AGES_YEAR
#undef AGES_YEAR
#define AGES_YEAR			_T("岁")
#endif

#ifdef AGES_MONTH
#undef AGES_MONTH
#define AGES_MONTH			_T("月")
#endif

#ifdef AGES_DAY
#undef AGES_DAY
#define AGES_DAY			_T("天")
#endif

#ifdef WARNING_OPTIONS
#undef WARNING_OPTIONS
#define WARNING_OPTIONS		_T("1~红色预警;2~橙色预警;3~黄色预警;4~蓝色预警;")
#endif


#endif /*LANG_CN*/


#endif /*_XDLANSI_H*/
