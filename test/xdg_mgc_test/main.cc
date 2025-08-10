
#include <xdk.h>
#include <xdg.h>


void test_mgc_font(visual_t mgc)
{
	xcolor_t xc;
	parse_xcolor(&xc, GDI_ATTR_RGB_RED);

	xpoint_t pt;

	int i, j;

	for (i = 0;  i < 100; i++)
	{
		for (j = 0; j < 100; j++)
		{
			pt.x = i; pt.y = j;
			xc.r = (i == j)? 1 : 0;
			xc.g = 0;// j;
			xc.b = 0;// i + j;
			if (i == j)
			{
				//mgc_set_point(mgc, &xc, &pt, ROP_COPY);
			}
		}
	}

	xfont_t xf;
	default_xfont(&xf);
	xscpy(xf.color, GDI_ATTR_RGB_LIGHTWHITE);

	const tchar_t* str = _T("abcd,中文汉字，$￥");
	//const tchar_t* str = _T("abcd");
	//const tchar_t* str = _T("啊");
	
	tchar_t fs[16][5] = { _T("5"), _T("5.5"),_T("6.5"), _T("7.5"), _T("9"), _T("10.5"), _T("12"), _T("14"), _T("15"), _T("16"), _T("18"), _T("22"), _T("24"), _T("26"), _T("36"), _T("42") };
	xsize_t xs = { 0 };

	mgc_set_rop(mgc, ROP_COPY);

	pt.x = pt.y = 0;
	for (i = 0; i < 16; i++)
	{
		xscpy(xf.size, fs[i]);
		mgc_text_size_raw(mgc, &xf, str, -1, &xs);

		pt.y += xs.h;
		mgc_text_out_raw(mgc, &xf, &pt, str, -1);
	}
}

void test_draw_line(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);
	xscpy(xp.size, _T("3"));
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);


	xpoint_t pt[10];

	pt[0].x = 100;
	pt[0].y = 170;
	pt[1].x = 200;
	pt[1].y = 200;
	pt[2].x = 180;
	pt[2].y = 250;
	pt[3].x = 10;
	pt[3].y = 200;

	mgc_draw_line_raw(mgc, &xp, &pt[0], &pt[1]);
	mgc_draw_line_raw(mgc, &xp, &pt[1], &pt[2]);
	mgc_draw_line_raw(mgc, &xp, &pt[2], &pt[3]);
	mgc_draw_line_raw(mgc, &xp, &pt[3], &pt[0]);
}

void test_draw_text(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);
	xscpy(xp.size, _T("1"));
	//xscpy(xp.style, GDI_ATTR_STROKE_STYLE_DASH);

	xfont_t xf;
	default_xfont(&xf);
	xscpy(xf.color, GDI_ATTR_RGB_LIGHTWHITE);
	xscpy(xf.size, _T("12"));

	xface_t xa;
	default_xface(&xa);
	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_NEAR);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_NEAR);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_LINEBREAK);

	//const tchar_t* str = _T("abcd,中文汉字，\n$￥");
	const tchar_t* str = _T("abcd,中文汉字\n$");
	xsize_t xs = { 0 };
	xspan_t s, l;

	xpoint_t pt[10];

	pt[0].x = 10;
	pt[0].y = 10;
	pt[1].x = 100;
	pt[1].y = 10;

	mgc_draw_line_raw(mgc, &xp, &pt[0], &pt[1]);
	mgc_text_out_raw(mgc, &xf, &pt[0], str, -1);

	xrect_t xr;
	xr.x = 10;
	xr.y = 30;
	xr.w = 200;
	xr.h = 0;

	mgc_text_rect_raw(mgc, &xf, &xa, str, -1, &xr);
	xr.h = 100;
	mgc_draw_rect_raw(mgc, &xp, NULL, &xr);
	mgc_draw_text_raw(mgc, &xf, &xa, &xr, str, -1);
}

void test_draw_polyline(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);

	xpoint_t pt[10];

	pt[0].x = 50;
	pt[0].y = 100;
	pt[1].x = 80;
	pt[1].y = 50;
	pt[2].x = 150;
	pt[2].y = 100;
	pt[3].x = 80;
	pt[3].y = 150;

	mgc_draw_polyline_raw(mgc, &xp, pt, 4);
}

void test_draw_polygon(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);

	xbrush_t xb;
	default_xbrush(&xb);
	xscpy(xb.style, GDI_ATTR_FILL_STYLE_GRADIENT);
	xscpy(xb.gradient, GDI_ATTR_GRADIENT_HORZ);
	xscpy(xb.color, GDI_ATTR_RGB_RED);
	xscpy(xb.linear, GDI_ATTR_RGB_WHITE);

	xpoint_t pt[10];

	pt[0].x = 50;
	pt[0].y = 100;
	pt[1].x = 80;
	pt[1].y = 50;
	pt[2].x = 150;
	pt[2].y = 100;
	pt[3].x = 80;
	pt[3].y = 150;

	mgc_draw_polygon_raw(mgc, &xp, &xb, pt, 4);
}

void test_draw_triangle(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);

	xbrush_t xb;
	default_xbrush(&xb);
	xscpy(xb.style, GDI_ATTR_FILL_STYLE_SOLID);
	xscpy(xb.gradient, GDI_ATTR_GRADIENT_HORZ);
	xscpy(xb.color, GDI_ATTR_RGB_RED);
	xscpy(xb.linear, GDI_ATTR_RGB_WHITE);

	xrect_t xr;
	xr.x = 10;
	xr.y = 10;
	xr.w = 100;
	xr.h = 100;
	mgc_draw_triangle_raw(mgc, &xp, &xb, &xr, GDI_ATTR_ORIENT_TOP);
}

void test_draw_rect(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);
	
	xpen_t xp;
	default_xpen(&xp);
	xscpy(xp.size, _T("1"));
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);

	xbrush_t xb;
	default_xbrush(&xb);
	xscpy(xb.style, GDI_ATTR_FILL_STYLE_GRADIENT);
	xscpy(xb.gradient, GDI_ATTR_GRADIENT_HORZ);
	xscpy(xb.color, GDI_ATTR_RGB_RED);
	xscpy(xb.linear, GDI_ATTR_RGB_WHITE);

	xrect_t xr;

	xr.x = 200;
	xr.y = 200;
	xr.w = 100;
	xr.h = 100;
	mgc_draw_rect_raw(mgc, &xp, &xb, &xr);
}

void test_gradient_rect(visual_t mgc)
{
	xcolor_t xc[2];
	parse_xcolor(&xc[0], GDI_ATTR_RGB_RED);
	parse_xcolor(&xc[1], GDI_ATTR_RGB_GREEN);

	mgc_set_rop(mgc, ROP_COPY);

	xrect_t xr;
	xr.x = 200;
	xr.y = 200;
	xr.w = 100;
	xr.h = 100;
	
	mgc_gradient_rect_raw(mgc, &xc[0], &xc[1], GDI_ATTR_GRADIENT_VERT, &xr);
}

void test_alphablend_rect(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xcolor_t xc[2];
	parse_xcolor(&xc[0], GDI_ATTR_RGB_GREEN);
	parse_xcolor(&xc[1], GDI_ATTR_RGB_BLACK);

	xrect_t xr;
	xr.x = 200;
	xr.y = 200;
	xr.w = 100;
	xr.h = 100;
	
	mgc_alphablend_rect_raw(mgc, &xc[0], &xr, 100);
}

void test_draw_ellipse(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);

	xbrush_t xb;
	default_xbrush(&xb);
	xscpy(xb.style, GDI_ATTR_FILL_STYLE_GRADIENT);
	xscpy(xb.gradient, GDI_ATTR_GRADIENT_HORZ);
	xscpy(xb.color, GDI_ATTR_RGB_RED);
	xscpy(xb.linear, GDI_ATTR_RGB_WHITE);

	xrect_t xr;
	xr.x = 200;
	xr.y = 100;
	xr.w = 100;
	xr.h = 180;
	mgc_draw_ellipse_raw(mgc, &xp, &xb, &xr);
}

void test_draw_round(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);

	xbrush_t xb;
	default_xbrush(&xb);
	xscpy(xb.style, GDI_ATTR_FILL_STYLE_GRADIENT);
	xscpy(xb.gradient, GDI_ATTR_GRADIENT_HORZ);
	xscpy(xb.color, GDI_ATTR_RGB_RED);
	xscpy(xb.linear, GDI_ATTR_RGB_WHITE);

	xrect_t xr;
	xsize_t xs;

	xr.x = 200;
	xr.y = 100;
	xr.w = 100;
	xr.h = 120;
	xs.w = 10;
	xs.h = 10;
	mgc_draw_round_raw(mgc, &xp, &xb, &xr, &xs);
}

void test_draw_pie(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);

	xbrush_t xb;
	default_xbrush(&xb);
	xscpy(xb.style, GDI_ATTR_FILL_STYLE_GRADIENT);
	xscpy(xb.gradient, GDI_ATTR_GRADIENT_HORZ);
	xscpy(xb.color, GDI_ATTR_RGB_RED);
	xscpy(xb.linear, GDI_ATTR_RGB_WHITE);

	xrect_t xr;
	xr.x = 200;
	xr.y = 100;
	xr.w = 100;
	xr.h = 120;
	mgc_draw_pie_raw(mgc, &xp, &xb, &xr, XPI, XPI * 7 / 4);
}

void test_draw_equilagon(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);

	xbrush_t xb;
	default_xbrush(&xb);
	xscpy(xb.style, GDI_ATTR_FILL_STYLE_GRADIENT);
	xscpy(xb.gradient, GDI_ATTR_GRADIENT_HORZ);
	xscpy(xb.color, GDI_ATTR_RGB_RED);
	xscpy(xb.linear, GDI_ATTR_RGB_WHITE);

	xpoint_t pt[2];
	pt[0].x = 100;
	pt[0].y = 100;

	xspan_t s, l;
	s.s = 50;

	mgc_draw_equilagon_raw(mgc, &xp, &xb, pt, &s, 5);
}

void test_draw_sector(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);

	xbrush_t xb;
	default_xbrush(&xb);
	xscpy(xb.style, GDI_ATTR_FILL_STYLE_GRADIENT);
	xscpy(xb.gradient, GDI_ATTR_GRADIENT_HORZ);
	xscpy(xb.color, GDI_ATTR_RGB_RED);
	xscpy(xb.linear, GDI_ATTR_RGB_WHITE);

	xpoint_t pt[2];
	pt[0].x = 100;
	pt[0].y = 100;

	xspan_t s, l;
	s.s = 20;
	l.s = 50;
	mgc_draw_sector_raw(mgc, &xp, &xb, pt, &l, &s, XPI / 4, XPI / 2);
}

void test_draw_arc(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);

	xpoint_t pt[2];
	pt[0].x = 100;
	pt[0].y = 100;
	pt[1].x = 50;
	pt[1].y = 50;

	xsize_t xs;
	xs.w = 50;
	xs.h = 50;

	mgc_draw_line_raw(mgc, &xp, &pt[0], &pt[1]);
	mgc_draw_arc_raw(mgc, &xp, &pt[0], &pt[1], &xs, 0, 0);
}

void test_draw_curve(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);

	xpoint_t pt[3];

	pt[0].x = 20;
	pt[0].y = 100;
	pt[1].x = 60;
	pt[1].y = 40;
	pt[2].x = 100;
	pt[2].y = 80;
	
	mgc_draw_line_raw(mgc, &xp, &pt[0], &pt[1]);
	mgc_draw_line_raw(mgc, &xp, &pt[1], &pt[2]);
	mgc_draw_curve_raw(mgc, &xp, pt, 3);
}

void test_draw_curve2(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	xpen_t xp;
	default_xpen(&xp);
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);

	xpoint_t pt[4];

	pt[0].x = 20;
	pt[0].y = 100;
	pt[1].x = 60;
	pt[1].y = 40;
	pt[2].x = 100;
	pt[2].y = 50;
	pt[3].x = 120;
	pt[3].y = 90;

	mgc_draw_line_raw(mgc, &xp, &pt[0], &pt[1]);
	mgc_draw_line_raw(mgc, &xp, &pt[1], &pt[2]);
	mgc_draw_line_raw(mgc, &xp, &pt[2], &pt[3]);
	mgc_draw_curve_raw(mgc, &xp, pt, 4);
}

void test_draw_image(visual_t mgc)
{
	mgc_set_rop(mgc, ROP_COPY);

	tchar_t fname[256];
	get_runpath(0, fname, 255);
	xscat(fname, _T("/title.jpg"));

	ximage_t xi = { 0 };
	xi.source = fname;
	xscpy(xi.color, GDI_ATTR_RGB_WHITE);

	xrect_t xr;
	xr.x = 100;
	xr.y = 100;
	xr.w = 300;
	xr.h = 300;

	mgc_draw_image_raw(mgc, &xi, &xr);
}

void test_draw()
{
	visual_t mgc = NULL;
	byte_t* buf = NULL;
	dword_t n;

	tchar_t fname[256];
	xhand_t fh = NULL;

	TRY_CATCH;
	
	mgc = create_mgc_visual(MGC_DEVICE_BITMAP_TRUECOLOR32, MGC_PAPER_P6, 100, 800, SDPI);
	if(!mgc)
	{
		raise_user_error(_T("test_draw"), _T("create_mgc_visual"));
	}

	//test_mgc_font(mgc);

	//test_draw_line(mgc);

	test_draw_text(mgc);

	//test_draw_polyline(mgc);

	//test_draw_polygon(mgc);

	//test_draw_triangle(mgc);

	//test_draw_rect(mgc);

	//test_gradient_rect(mgc);

	//test_alphablend_rect(mgc);

	//test_draw_ellipse(mgc);

	//test_draw_round(mgc);

	//test_draw_pie(mgc);

	//test_draw_equilagon(mgc);

	//test_draw_sector(mgc);

	//test_draw_arc(mgc);

	//test_draw_curve(mgc);

	//test_draw_curve2(mgc);

	//test_draw_image(mgc);

	n = mgc_save_bytes(mgc, NULL, MAX_LONG);
	buf = (byte_t*)xmem_alloc(n);
	mgc_save_bytes(mgc, buf, n);

	destroy_mgc_visual(mgc);
	mgc = NULL;

	get_runpath(0, fname, 255);
	xscat(fname, _T("/draw.bmp"));

	fh = xuncf_open_file(NULL, fname, FILE_OPEN_CREATE);
	if(!fh)
	{
		raise_user_error(_T("test_draw"), _T("xuncf_open_file"));
	}

	xuncf_write_file(fh, buf, &n);
	xuncf_close_file(fh);
	fh = NULL;

	xmem_free(buf);
	buf = NULL;

	END_CATCH;

	return;
ONERROR:
	XDK_TRACE_LAST;

	if(mgc) destroy_mgc_visual(mgc);
	
	if(fh) xuncf_close_file(fh);

	if(buf) xmem_free(buf);

	return;
}

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//test_ttf();

	gly_init();

	test_draw();

	gly_uninit();

	xdk_process_uninit();

	return 0;
}

