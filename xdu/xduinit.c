/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc initialize document

	@module	xduinit.c | implement file

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


#include "xduinit.h"
#include "xduloc.h"

//xdu_mou_t g_xdu_mou = { 0 };

xdu_mou_t g_xdu_mou = {
	.if_ok = 0,

#ifdef XDU_SUPPORT_CONTEXT
	.ctx_ver = 0,

	.if_context.pf_context_startup = _context_startup,
	.if_context.pf_context_cleanup = _context_cleanup,
	.if_context.pf_create_compatible_context = _create_compatible_context,
	.if_context.pf_create_display_context = _create_display_context,
	.if_context.pf_destroy_context = _destroy_context,
	.if_context.pf_get_device_caps = _get_device_caps,
	.if_context.pf_render_context = _render_context,
	.if_context.pf_pixel_metric = _pixel_metric,
	.if_context.pf_font_metric = _font_metric,
#ifdef XDU_SUPPORT_CONTEXT_BITMAP
	.if_context.pf_destroy_bitmap = _destroy_bitmap,
	.if_context.pf_get_bitmap_size = _get_bitmap_size,
	.if_context.pf_create_context_bitmap = _create_context_bitmap,
	.if_context.pf_create_color_bitmap = _create_color_bitmap,
	.if_context.pf_create_gradient_bitmap = _create_gradient_bitmap,
	.if_context.pf_create_pattern_bitmap = _create_pattern_bitmap,
	.if_context.pf_create_code128_bitmap = _create_code128_bitmap,
	.if_context.pf_create_pdf417_bitmap = _create_pdf417_bitmap,
	.if_context.pf_create_qrcode_bitmap = _create_qrcode_bitmap,
	.if_context.pf_create_storage_bitmap = _create_storage_bitmap,
	.if_context.pf_save_bitmap_to_bytes = _save_bitmap_to_bytes,
	.if_context.pf_load_bitmap_from_bytes = _load_bitmap_from_bytes,
	.if_context.pf_get_bitmap_bytes = _get_bitmap_bytes,
#ifdef XDU_SUPPORT_SHELL
	.if_context.pf_load_bitmap_from_thumb = _load_bitmap_from_thumb,
	.if_context.pf_load_bitmap_from_icon = _load_bitmap_from_icon,
#endif
#endif //XDU_SUPPORT_CONTEXT_BITMAP
#ifdef XDU_SUPPORT_CONTEXT_PRINTER
	.if_context.pf_create_printer_context = _create_printer_context,
	.if_context.pf_destroy_printer_context = _destroy_printer_context,
	.if_context.pf_setup_printer_mode = _setup_printer_mode,
	.if_context.pf_default_printer_mode = _default_printer_mode,
	.if_context.pf_begin_doc = _begin_doc,
	.if_context.pf_begin_page = _begin_page,
	.if_context.pf_end_page = _end_page,
	.if_context.pf_end_doc = _end_doc,
#endif
#ifdef XDU_SUPPORT_CONTEXT_GDI
	.if_context.pf_gdi_set_point = _gdi_set_point,
	.if_context.pf_gdi_get_point = _gdi_get_point,
	.if_context.pf_gdi_draw_points = _gdi_draw_points,
	.if_context.pf_gdi_draw_ellipse = _gdi_draw_ellipse,
	.if_context.pf_gdi_draw_line = _gdi_draw_line,
	.if_context.pf_gdi_draw_path = _gdi_draw_path,
	.if_context.pf_gdi_draw_pie = _gdi_draw_pie,
	.if_context.pf_gdi_draw_arc = _gdi_draw_arc,
	.if_context.pf_gdi_draw_polygon = _gdi_draw_polygon,
	.if_context.pf_gdi_draw_polyline = _gdi_draw_polyline,
	.if_context.pf_gdi_draw_bezier = _gdi_draw_bezier,
	.if_context.pf_gdi_draw_curve = _gdi_draw_curve,
	.if_context.pf_gdi_draw_rect = _gdi_draw_rect,
	.if_context.pf_gdi_draw_round = _gdi_draw_round,
	.if_context.pf_gdi_get_xfont = _gdi_get_xfont,
	.if_context.pf_gdi_set_xfont = _gdi_set_xfont,
	.if_context.pf_gdi_font_size = _gdi_font_size,
	.if_context.pf_gdi_draw_text = _gdi_draw_text,
	.if_context.pf_gdi_text_out = _gdi_text_out,
	.if_context.pf_gdi_text_size = _gdi_text_size,
	.if_context.pf_gdi_text_rect = _gdi_text_rect,
	.if_context.pf_gdi_gradient_rect = _gdi_gradient_rect,
	.if_context.pf_gdi_alphablend_rect = _gdi_alphablend_rect,
	.if_context.pf_gdi_invert_rect = _gdi_invert_rect,
	.if_context.pf_gdi_exclude_rect = _gdi_exclude_rect,
	.if_context.pf_gdi_inclip_rect = _gdi_inclip_rect,
#ifdef XDU_SUPPORT_CONTEXT_BITMAP
	.if_context.pf_gdi_draw_bitmap = _gdi_draw_bitmap,
	.if_context.pf_gdi_draw_image = _gdi_draw_image,
#endif
#endif //XDU_SUPPORT_CONTEXT_GDI
#endif //XDU_SUPPORT_CONTEXT

#ifdef XDU_SUPPORT_WIDGET
	.if_widget.pf_widget_startup = _widget_startup,
	.if_widget.pf_widget_cleanup = _widget_cleanup,
	.if_widget.pf_widget_create = _widget_create,
	.if_widget.pf_widget_destroy = _widget_destroy,
	.if_widget.pf_widget_close = _widget_close,
	.if_widget.pf_widget_get_dispatch = _widget_get_dispatch,
	.if_widget.pf_widget_get_style = _widget_get_style,
	.if_widget.pf_widget_set_style = _widget_set_style,
	.if_widget.pf_widget_set_accel = _widget_set_accel,
	.if_widget.pf_widget_get_owner = _widget_get_owner,
	.if_widget.pf_widget_set_owner = _widget_set_owner,
	.if_widget.pf_widget_get_core_delta = _widget_get_core_delta,
	.if_widget.pf_widget_set_core_delta = _widget_set_core_delta,
	.if_widget.pf_widget_get_user_delta = _widget_get_user_delta,
	.if_widget.pf_widget_set_user_delta = _widget_set_user_delta,
	.if_widget.pf_widget_get_user_id = _widget_get_user_id,
	.if_widget.pf_widget_set_user_id = _widget_set_user_id,
	.if_widget.pf_widget_get_child = _widget_get_child,
	.if_widget.pf_widget_get_parent = _widget_get_parent,
	.if_widget.pf_widget_get_user_prop = _widget_get_user_prop,
	.if_widget.pf_widget_set_user_prop = _widget_set_user_prop,
	.if_widget.pf_widget_del_user_prop = _widget_del_user_prop,
	.if_widget.pf_widget_get_user_result = _widget_get_user_result,
	.if_widget.pf_widget_set_user_result = _widget_set_user_result,
	.if_widget.pf_widget_client_context = _widget_client_context,
	.if_widget.pf_widget_window_context = _widget_window_context,
	.if_widget.pf_widget_release_context = _widget_release_context,
	.if_widget.pf_widget_center_window = _widget_center_window,
	.if_widget.pf_widget_screen_to_client = _widget_screen_to_client,
	.if_widget.pf_widget_client_to_screen = _widget_client_to_screen,
	.if_widget.pf_widget_window_to_client = _widget_window_to_client,
	.if_widget.pf_widget_client_to_window = _widget_client_to_window,
	.if_widget.pf_widget_get_client_rect = _widget_get_client_rect,
	.if_widget.pf_widget_get_window_rect = _widget_get_window_rect,
	.if_widget.pf_widget_is_child = _widget_is_child,
	.if_widget.pf_widget_is_valid = _widget_is_valid,
	.if_widget.pf_widget_is_focus = _widget_is_focus,
	.if_widget.pf_widget_key_state = _widget_key_state,
	.if_widget.pf_widget_size = _widget_size,
	.if_widget.pf_widget_move = _widget_move,
	.if_widget.pf_widget_take = _widget_take,
	.if_widget.pf_widget_show = _widget_show,
	.if_widget.pf_widget_layout = _widget_layout,
	.if_widget.pf_widget_erase = _widget_erase,
	.if_widget.pf_widget_set_capture = _widget_set_capture,
	.if_widget.pf_widget_set_cursor = _widget_set_cursor,
	.if_widget.pf_widget_set_focus = _widget_set_focus,
	.if_widget.pf_widget_set_title = _widget_set_title,
	.if_widget.pf_widget_get_title = _widget_get_title,
	.if_widget.pf_widget_create_caret = _widget_create_caret,
	.if_widget.pf_widget_destroy_caret = _widget_destroy_caret,
	.if_widget.pf_widget_show_caret = _widget_show_caret,
	.if_widget.pf_widget_enable = _widget_enable,
	.if_widget.pf_widget_active = _widget_active,
	.if_widget.pf_widget_post_wchar = _widget_post_wchar,
	.if_widget.pf_widget_post_key = _widget_post_key,
	.if_widget.pf_widget_post_notice = _widget_post_notice,
	.if_widget.pf_widget_send_notice = _widget_send_notice,
	.if_widget.pf_widget_post_command = _widget_post_command,
	.if_widget.pf_widget_send_command = _widget_send_command,
	.if_widget.pf_widget_set_timer = _widget_set_timer,
	.if_widget.pf_widget_kill_timer = _widget_kill_timer,
	.if_widget.pf_widget_enum_child = _widget_enum_child,
	.if_widget.pf_widget_is_maximized = _widget_is_maximized,
	.if_widget.pf_widget_is_minimized = _widget_is_minimized,
	.if_widget.pf_widget_get_subproc = _widget_get_subproc,
	.if_widget.pf_widget_set_subproc = _widget_set_subproc,
	.if_widget.pf_widget_del_subproc = _widget_del_subproc,
	.if_widget.pf_widget_get_subproc_delta = _widget_get_subproc_delta,
	.if_widget.pf_widget_set_subproc_delta = _widget_set_subproc_delta,
	.if_widget.pf_widget_has_subproc = _widget_has_subproc,
	.if_widget.pf_widget_scroll = _widget_scroll,
	.if_widget.pf_widget_set_scroll_info = _widget_set_scroll_info,
	.if_widget.pf_widget_get_scroll_info = _widget_get_scroll_info,
	.if_widget.pf_widget_set_color_mode = _widget_set_color_mode,
	.if_widget.pf_widget_get_color_mode = _widget_get_color_mode,
	.if_widget.pf_widget_get_color_mode_ptr = _widget_get_color_mode_ptr,
	.if_widget.pf_widget_set_diaph = _widget_set_diaph,
	.if_widget.pf_widget_get_diaph = _widget_get_diaph,
	.if_widget.pf_widget_do_main = _widget_do_main,
	.if_widget.pf_widget_do_modal = _widget_do_modal,
	.if_widget.pf_widget_do_track = _widget_do_track,
	.if_widget.pf_message_position = _message_position,
	.if_widget.pf_message_quit = _message_quit,
	.if_widget.pf_calc_widget_border = _calc_widget_border,
	.if_widget.pf_adjust_widget_size = _adjust_widget_size,
	.if_widget.pf_get_screen_size = _get_screen_size,
	.if_widget.pf_get_desktop_size = _get_desktop_size,
	.if_widget.pf_screen_size_to_pt = _screen_size_to_pt,
	.if_widget.pf_screen_size_to_mm = _screen_size_to_mm,
#ifdef XDU_SUPPORT_CONTEXT_OPENGL
	.if_widget.pf_widget_get_glctx = _widget_get_glctx,
#endif
#endif //XDU_SUPPORT_WIDGET

#ifdef XDU_SUPPORT_CLIPBOARD
	.if_clipboard.pf_clipboard_get = _clipboard_get,
	.if_clipboard.pf_clipboard_put = _clipboard_put,
#endif //XDU_SUPPORT_CLIPBOARD

#ifdef XDU_SUPPORT_SHELL
	.if_shell.pf_shell_get_curpath = _shell_get_curpath,
	.if_shell.pf_shell_get_runpath = _shell_get_runpath,
	.if_shell.pf_shell_get_docpath = _shell_get_docpath,
	.if_shell.pf_shell_get_apppath = _shell_get_apppath,
	.if_shell.pf_shell_get_tmppath = _shell_get_tmppath,
	.if_shell.pf_shell_get_filename = _shell_get_filename,
	.if_shell.pf_shell_get_pathname = _shell_get_pathname,
#endif //XDU_SUPPORT_SHELL
};

//mount system call
void xdu_process_init()
{
	if (g_xdu_mou.if_ok)
		return;

    g_xdu_mou.if_ok = 1;

#ifdef XDU_SUPPORT_CONTEXT
	if (g_xdu_mou.if_context.pf_context_startup)
	{
		g_xdu_mou.ctx_ver = (*g_xdu_mou.if_context.pf_context_startup)();
	}
#endif //XDU_SUPPORT_CONTEXT


#ifdef XDU_SUPPORT_WIDGET
	//start widget context
	if (g_xdu_mou.if_widget.pf_widget_startup)
	{
		(*(g_xdu_mou.if_widget.pf_widget_startup))(g_xdu_mou.ctx_ver);
	}
#endif //XDU_SUPPORT_WIDGET
}

//unmount system call
void xdu_process_uninit()
{
	if (!g_xdu_mou.if_ok)
		return;

#ifdef XDU_SUPPORT_WIDGET
	//clean widget context
	(*g_xdu_mou.if_widget.pf_widget_cleanup)();
#endif

#ifdef XDU_SUPPORT_CONTEXT
	//clean gdi context
	(*g_xdu_mou.if_context.pf_context_cleanup)();
#endif

	g_xdu_mou.if_ok = 0;
	g_xdu_mou.ctx_ver = 0;
}



