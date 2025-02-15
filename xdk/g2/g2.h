/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc 2D coordinate space document

	@module	g2.h | interface file

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

#ifndef _G2_H
#define _G2_H

#include "../xdkdef.h"


#ifdef	__cplusplus
extern "C" {
#endif

	EXP_API void pt_world_to_screen(xpoint_t pt_origin, xpoint_t* ppt_points, int count_points);
	EXP_API void ft_world_to_screen(xpoint_t pt_origin, xpoint_t* ppt_points, int count_points);

	EXP_API void pt_screen_to_world(xpoint_t pt_origin, xpoint_t* ppt_points, int count_points);
	EXP_API void ft_screen_to_world(xpoint_t pt_origin, xpoint_t* ppt_points, int count_points);

	EXP_API int pt_xaxis_symmetric(xpoint_t pt_origin, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max);
	EXP_API int ft_xaxis_symmetric(xpoint_t pt_origin, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max);

	EXP_API int pt_yaxis_symmetric(xpoint_t pt_origin, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max);
	EXP_API int ft_yaxis_symmetric(xpoint_t pt_origin, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max);

	EXP_API int pt_origin_symmetric(xpoint_t pt_origin, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max);
	EXP_API int ft_origin_symmetric(xpoint_t pt_origin, const xpoint_t* ppt_src, int n, xpoint_t* ppt_dst, int max);

	EXP_API int arc_quadrant(double arc);
	EXP_API int pt_quadrant(const xpoint_t* pt_origin, const xpoint_t* pt_end, bool_t clockwise);
	EXP_API int ft_quadrant(const xpoint_t* pt_origin, const xpoint_t* pt_end, bool_t clockwise);

	EXP_API bool_t pt_calc_radian(bool_t clockwise, bool_t largearc, int rx, int ry, const xpoint_t* ppt1, const xpoint_t* ppt2, xpoint_t* ppt_center, double* arc_from, double* arc_to);
	EXP_API bool_t ft_calc_radian(bool_t clockwise, bool_t largearc, float rx, float ry, const xpoint_t* ppt1, const xpoint_t* ppt2, xpoint_t* ppt_center, double* arc_from, double* arc_to);

	EXP_API void pt_calc_points(const xpoint_t* ppt_center, int rx, int ry, double arc_from, double arc_to, bool_t* clockwise, bool_t* largearc, xpoint_t* ppt1, xpoint_t* ppt2);
	EXP_API void ft_calc_points(const xpoint_t* ppt_center, float rx, float ry, double arc_from, double arc_to, bool_t* clockwise, bool_t* largearc, xpoint_t* ppt1, xpoint_t* ppt2);

	EXP_API void pt_calc_sector(const xpoint_t* ppt, int r_large, int r_short, double arc_from, double arc_to, xpoint_t* pa, int n);
	EXP_API void ft_calc_sector(const xpoint_t* ppt, float r_large, float r_short, double arc_from, double arc_to, xpoint_t* pa, int n);

	EXP_API void pt_calc_equilater(const xpoint_t* ppt, int span, xpoint_t* pa, int n);
	EXP_API void ft_calc_equilater(const xpoint_t* ppt, float span, xpoint_t* pa, int n);

	EXP_API bool_t ft_inside(float x, float y, float x1, float y1, float x2, float y2);
	EXP_API bool_t pt_inside(int x, int y, int x1, int y1, int x2, int y2);

	EXP_API bool_t ft_in_rect(const xpoint_t* ppt, const xrect_t* prt);
	EXP_API bool_t pt_in_rect(const xpoint_t* ppt, const xrect_t* prt);

	EXP_API void ft_offset_point(xpoint_t* ppt, float cx, float cy);
	EXP_API void pt_offset_point(xpoint_t* ppt, int cx, int cy);

	EXP_API void ft_center_rect(xrect_t* pxr, float cx, float cy);
	EXP_API void pt_center_rect(xrect_t* pxr, int cx, int cy);

	EXP_API void ft_expand_rect(xrect_t* pxr, float cx, float cy);
	EXP_API void pt_expand_rect(xrect_t* pxr, int cx, int cy);

	EXP_API void ft_offset_rect(xrect_t* pxr, float cx, float cy);
	EXP_API void pt_offset_rect(xrect_t* pxr, int cx, int cy);

	EXP_API void ft_merge_rect(xrect_t* pxr, const xrect_t* pxr_nxt);
	EXP_API void pt_merge_rect(xrect_t* pxr, const xrect_t* pxr_nxt);

	EXP_API bool_t ft_clip_rect(xrect_t* pxr, const xrect_t* pxr_sub);
	EXP_API bool_t pt_clip_rect(xrect_t* pxr, const xrect_t* pxr_sub);

	EXP_API void ft_inter_rect(xrect_t* pxr, const xrect_t* pxr_sub);
	EXP_API void pt_inter_rect(xrect_t* pxr, const xrect_t* pxr_sub);

	EXP_API void pt_inter_square(xrect_t* pxr, const xrect_t* pxr_org);
	EXP_API void ft_inter_square(xrect_t* pxr, const xrect_t* pxr_org);

	EXP_API void ft_cell_rect(xrect_t* pxr, bool_t horz, int rows, int cols, int index);
	EXP_API void pt_cell_rect(xrect_t* pxr, bool_t horz, int rows, int cols, int index);

	EXP_API bool_t rect_is_empty(const xrect_t* pxr);
	EXP_API void empty_rect(xrect_t* pxr);

	EXP_API void pt_adjust_rect(xrect_t* pxr, int src_width, int src_height, const tchar_t* horz_align, const tchar_t* vert_align);
	EXP_API void ft_adjust_rect(xrect_t* pxr, float src_width, float src_height, const tchar_t* horz_align, const tchar_t* vert_align);

	EXP_API void radian_to_degree(double arc_from, double arc_to, float* ang_from, float* ang_sweep);

	EXP_API void pt_gravity_point(const xpoint_t* ppt, int n, xpoint_t* pg);

	EXP_API void ft_gravity_point(const xpoint_t* ppt, int n, xpoint_t* pg);

	EXP_API void pt_polygon_rect(const xpoint_t* ppt, int n, xrect_t* pr);

	EXP_API void ft_polygon_rect(const xpoint_t* ppt, int n, xrect_t* pr);

#ifdef	__cplusplus
}
#endif

#endif /*_2DS_H*/
