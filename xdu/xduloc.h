/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu system call interface document

	@module	xduiml.h | interface file

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

#ifndef _XDULOC_H
#define	_XDULOC_H

#include "xdudef.h"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef XDU_SUPPORT_BLUT
LOC_API int	_enum_blut_device(dev_blt_t* pdb, int max);
LOC_API res_file_t _blut_open(const tchar_t* addr, int chan, dword_t fmode);
LOC_API void	_blut_close(res_file_t fh);
LOC_API bool_t	_blut_read(res_file_t fh, void* buf, dword_t size, async_t* pb);
LOC_API bool_t	_blut_write(res_file_t fh, void* buf, dword_t size, async_t* pb);
LOC_API bool_t	_blut_flush(res_file_t fh);
LOC_API dword_t	_blut_listen(res_file_t fh, async_t* pb);
#endif

#ifdef XDU_SUPPORT_SHELL
LOC_API bool_t	_shell_get_runpath(tchar_t* pathbuf, int pathlen);
LOC_API bool_t	_shell_get_curpath(tchar_t* pathbuf, int pathlen);
LOC_API bool_t	_shell_get_apppath(tchar_t* pathbuf, int pathlen);
LOC_API bool_t	_shell_get_docpath(tchar_t* pathbuf, int pathlen);
LOC_API bool_t	_shell_get_tmppath(tchar_t* pathbuf, int pathlen);
LOC_API bool_t	_shell_get_filename(widget_t owner, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen);
LOC_API bool_t	_shell_get_pathname(widget_t owner, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen);
#endif /*XDU_SUPPORT_SHELL*/
/***************************************************************************************************************************/
#ifdef XDU_SUPPORT_CONTEXT
LOC_API int		_context_startup(void);
LOC_API void	_context_cleanup(void);
LOC_API visual_t _create_display_context(widget_t wt);
LOC_API visual_t _create_compatible_context(visual_t rdc, int cx, int cy);
LOC_API void	_destroy_context(visual_t rdc);
LOC_API void	_get_device_caps(visual_t rdc, dev_cap_t* pcap);
LOC_API void	_render_context(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth);
LOC_API float	_pixel_metric(visual_t rdc);
LOC_API float	_font_metric(visual_t rdc, const xfont_t* pxf);

#ifdef XDU_SUPPORT_CONTEXT_BITMAP
LOC_API bitmap_t _create_context_bitmap(visual_t rdc);
LOC_API bitmap_t _create_color_bitmap(visual_t rdc, const xcolor_t* pxc, int w, int h);
LOC_API bitmap_t _create_pattern_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h);
LOC_API bitmap_t _create_gradient_bitmap(visual_t rdc, const xcolor_t* pxc_near, const xcolor_t* pxc_center,int w, int h, const tchar_t* lay);
LOC_API bitmap_t _create_code128_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols);
LOC_API bitmap_t _create_pdf417_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
LOC_API bitmap_t _create_qrcode_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols);
LOC_API bitmap_t _create_storage_bitmap(visual_t rdc, const tchar_t* filename);
LOC_API bitmap_t _load_bitmap_from_bytes(visual_t rdc, const unsigned char* pb, dword_t len);
LOC_API dword_t	_save_bitmap_to_bytes(visual_t rdc, bitmap_t rb, unsigned char* pb, dword_t max);
LOC_API dword_t	_get_bitmap_bytes(bitmap_t rdc);
LOC_API void	_get_bitmap_size(bitmap_t rb, int* pw, int* ph);
LOC_API void	_destroy_bitmap(bitmap_t bmp);
#ifdef XDU_SUPPORT_SHELL
LOC_API bitmap_t _load_bitmap_from_icon(visual_t rdc, const tchar_t* iname);
LOC_API bitmap_t _load_bitmap_from_thumb(visual_t rdc, const tchar_t* fname);
#endif
#endif
#ifdef XDU_SUPPORT_CONTEXT_PRINTER
LOC_API bool_t _default_printer_mode(dev_prn_t* pmod);
LOC_API bool_t _setup_printer_mode(widget_t wnd, dev_prn_t* pmod);
LOC_API visual_t _create_printer_context(const dev_prn_t* pmod);
LOC_API void	_destroy_printer_context(visual_t rdc);
LOC_API void	_begin_page(visual_t rdc);
LOC_API void	_end_page(visual_t rdc);
LOC_API void	_begin_doc(visual_t rdc, const tchar_t* docname);
LOC_API void	_end_doc(visual_t rdc);
#endif

#ifdef XDU_SUPPORT_CONTEXT_GDI
LOC_API void _gdi_init(int osv);
LOC_API void _gdi_uninit(void);
LOC_API void _gdi_get_point(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt);
LOC_API void _gdi_set_point(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt);
LOC_API void _gdi_draw_points(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n);
LOC_API void _gdi_draw_line(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2);
LOC_API void _gdi_draw_arc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t clockwise, bool_t largearc);
LOC_API void _gdi_draw_polyline(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int n);
LOC_API void _gdi_draw_path(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn);
LOC_API void _gdi_draw_polygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n);
LOC_API void _gdi_draw_bezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4);
LOC_API void _gdi_draw_curve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int n);
LOC_API void _gdi_draw_rect(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt);
LOC_API void _gdi_draw_round(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt, const xsize_t* pxs);
LOC_API void _gdi_draw_ellipse(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt);
LOC_API void _gdi_draw_pie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt, double arc_from, double arc_to);
LOC_API void _gdi_draw_text(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const xrect_t* prt, const tchar_t* txt, int len);
LOC_API void _gdi_text_out(visual_t rdc, const xfont_t* pxf, const xpoint_t* ppt, const tchar_t* txt, int len);
LOC_API void _gdi_text_size(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs);
LOC_API void _gdi_font_size(visual_t rdc, const xfont_t* pxf, xsize_t* pxs);
#ifdef XDU_SUPPORT_CONTEXT_BITMAP
LOC_API void _gdi_draw_image(visual_t rdc, bitmap_t bmp, const xcolor_t* clr, const xrect_t* prt);
LOC_API void _gdi_draw_bitmap(visual_t rdc, bitmap_t bmp, const xpoint_t* ppt);
#endif
LOC_API void _gdi_invert_rect(visual_t rdc, const xrect_t* prt);
LOC_API void _gdi_gradient_rect(visual_t rdc, const xcolor_t* xc_brim, const xcolor_t* xc_core, const tchar_t* gradient, const xrect_t* prt);
LOC_API void _gdi_alphablend_rect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity);
LOC_API void _gdi_exclude_rect(visual_t rdc, const xrect_t* pxr);
LOC_API void _gdi_inclip_rect(visual_t rdc, const xrect_t* pxr);
#endif //XDU_SUPPORT_CONTEXT_GDI

#ifdef XDU_SUPPORT_CONTEXT_OPENGL
LOC_API res_glc_t	_widget_get_glctx(widget_t wt);
#endif

LOC_API fontset_t _gdi_create_fontset(const xfont_t* pxf);
LOC_API void _gdi_destroy_fontset(fontset_t ft);
LOC_API void _gdi_word_size(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs);

#endif /*XDU_SUPPORT_CONTEXT*/

#ifdef XDU_SUPPORT_CLIPBOARD
LOC_API bool_t	_clipboard_put(widget_t win, int fmt, const byte_t* data, dword_t size);
LOC_API dword_t _clipboard_get(widget_t win, int fmt, byte_t* buf, dword_t max);
#endif

#ifdef XDU_SUPPORT_WIDGET
LOC_API void	_widget_startup(int ver);
LOC_API void	_widget_cleanup(void);
LOC_API widget_t _widget_create(const tchar_t* wname, dword_t wstyle, const xrect_t* wrect, widget_t wparent, const if_dispatch_t* pev);
LOC_API void	_widget_destroy(widget_t wt);
LOC_API void	_widget_close(widget_t wt, int ret);
LOC_API const if_dispatch_t* _widget_get_dispatch(widget_t wt);
LOC_API void	_widget_set_core_delta(widget_t wt, vword_t pd);
LOC_API vword_t	_widget_get_core_delta(widget_t wt);
LOC_API void	_widget_set_user_delta(widget_t wt, vword_t pd);
LOC_API vword_t	_widget_get_user_delta(widget_t wt);
LOC_API void	_widget_set_user_id(widget_t wt, uid_t uid);
LOC_API uid_t	_widget_get_user_id(widget_t wt);
LOC_API void	_widget_set_user_prop(widget_t wt, const tchar_t* pname, vword_t pval);
LOC_API vword_t	_widget_get_user_prop(widget_t wt, const tchar_t* pname);
LOC_API vword_t	_widget_del_user_prop(widget_t wt, const tchar_t* pname);
LOC_API void	_widget_set_user_result(widget_t wt, int code);
LOC_API int		_widget_get_user_result(widget_t wt);
LOC_API void	_widget_set_style(widget_t wt, dword_t ws);
LOC_API dword_t	_widget_get_style(widget_t wt);
LOC_API void	_widget_set_accel(widget_t wt, const accel_table_t* pact, int n);
LOC_API void	_widget_set_owner(widget_t wt, widget_t win);
LOC_API widget_t _widget_get_owner(widget_t wt);
LOC_API widget_t _widget_get_child(widget_t wt, uid_t uid);
LOC_API widget_t _widget_get_parent(widget_t wt);
LOC_API void	_widget_set_capture(widget_t wt, bool_t b);
LOC_API void	_widget_create_caret(widget_t wt, int w, int h);
LOC_API void	_widget_destroy_caret(widget_t wt);
LOC_API void	_widget_show_caret(widget_t wt, int x, int y);

LOC_API visual_t _widget_client_context(widget_t wt);
LOC_API visual_t _widget_window_context(widget_t wt);
LOC_API void	_widget_release_context(widget_t wt, visual_t dc);
LOC_API void	_widget_get_client_rect(widget_t wt, xrect_t* prt);
LOC_API void	_widget_get_window_rect(widget_t wt, xrect_t* prt);
LOC_API void	_widget_client_to_screen(widget_t wt, xpoint_t* ppt);
LOC_API void	_widget_screen_to_client(widget_t wt, xpoint_t* ppt);
LOC_API void	_widget_client_to_window(widget_t wt, xpoint_t* ppt);
LOC_API void	_widget_window_to_client(widget_t wt, xpoint_t* ppt);
LOC_API void	_widget_center_window(widget_t wt, widget_t owner);
LOC_API void	_widget_set_cursor(widget_t wt, int curs);
LOC_API void	_widget_set_capture(widget_t wt, bool_t b);
LOC_API void	_widget_set_imm(widget_t wt, bool_t b);
LOC_API bool_t	_widget_get_imm(widget_t wt);
LOC_API void	_widget_set_focus(widget_t wt);
LOC_API bool_t	_widget_key_state(widget_t wt, int key);
LOC_API bool_t	_widget_is_valid(widget_t wt);
LOC_API bool_t	_widget_is_child(widget_t wt);
LOC_API bool_t	_widget_is_focus(widget_t wt);
LOC_API void	_widget_size(widget_t wt, const xsize_t* pxs);
LOC_API void	_widget_move(widget_t wt, const xpoint_t* ppt);
LOC_API void	_widget_take(widget_t wt, int zor);
LOC_API void	_widget_show(widget_t wt, dword_t sw);
LOC_API void	_widget_layout(widget_t wt);
LOC_API void	_widget_erase(widget_t wt, const xrect_t* prt);
LOC_API void	_widget_enable(widget_t wt, bool_t b);
LOC_API void	_widget_active(widget_t wt);

LOC_API void	_widget_set_title(widget_t wt, const tchar_t* token);
LOC_API int		_widget_get_title(widget_t wt, tchar_t* buf, int max);
LOC_API bool_t	_widget_enum_child(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv);

LOC_API bool_t	_widget_is_maximized(widget_t wt);
LOC_API bool_t	_widget_is_minimized(widget_t wt);

LOC_API const if_subproc_t* _widget_get_subproc(widget_t wt, uid_t sid);
LOC_API bool_t	_widget_set_subproc(widget_t wt, uid_t sid, if_subproc_t* sub);
LOC_API void	_widget_del_subproc(widget_t wt, uid_t sid);
LOC_API bool_t	_widget_set_subproc_delta(widget_t wt, uid_t sid, vword_t delta);
LOC_API vword_t _widget_get_subproc_delta(widget_t wt, uid_t sid);
LOC_API bool_t	_widget_has_subproc(widget_t wt);

LOC_API void	_widget_post_wchar(widget_t wt, wchar_t ch);
LOC_API void	_widget_post_key(widget_t wt, int key);
LOC_API void	_widget_post_notice(widget_t wt, NOTICE* pnc);
LOC_API int		_widget_send_notice(widget_t wt, NOTICE* pnc);
LOC_API void	_widget_post_command(widget_t wt, int code, uid_t cid, vword_t data);
LOC_API int		_widget_send_command(widget_t wt, int code, uid_t cid, vword_t data);

LOC_API vword_t _widget_set_timer(widget_t wt, int ms);
LOC_API void	_widget_kill_timer(widget_t wt, vword_t tid);

LOC_API void	_widget_scroll(widget_t wt, bool_t horz, int line);
LOC_API void	_widget_get_scroll_info(widget_t wt, bool_t horz, scroll_t* psl);
LOC_API void	_widget_set_scroll_info(widget_t wt, bool_t horz, const scroll_t* psl);
LOC_API void	_widget_noti_xfont(widget_t wt, const xfont_t* pxf);
LOC_API void	_widget_noti_xface(widget_t wt, const xface_t* pxa);
LOC_API void	_widget_noti_xbrush(widget_t wt, const xbrush_t* pxb);
LOC_API void	_widget_noti_xpen(widget_t wt, const xpen_t* pxp);
LOC_API void	_widget_set_color_mode(widget_t wt, const color_mod_t* pclr);
LOC_API void	_widget_get_color_mode(widget_t wt, color_mod_t* pclr);
LOC_API void	_widget_set_diaph(widget_t, float a);
LOC_API float	_widget_get_diaph(widget_t wt);

LOC_API int		_widget_do_main(widget_t wt);
LOC_API int		_widget_do_modal(widget_t wt);
LOC_API void	_widget_do_track(widget_t wt);

LOC_API void	_message_position(xpoint_t* pxp);
LOC_API void	_message_quit(int code);

LOC_API void	_adjust_widget_size(dword_t wstyle, xsize_t* pxs);
LOC_API void	_calc_widget_border(dword_t wstyle, border_t* pbd);
LOC_API void	_get_screen_size(xsize_t* pxs);
LOC_API void	_get_desktop_size(xsize_t* pxs);
LOC_API void	_screen_size_to_pt(xsize_t* pls);
LOC_API void	_screen_size_to_mm(xsize_t* pxs);

#endif /*XDU_SUPPORT_WIDGET*/


#ifdef	__cplusplus
}
#endif


#endif	/* _XDUIML_H */

