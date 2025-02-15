
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif

void test_ttf()
{
	FILE* fp = fopen("arial.ttf", "rb");

	fseek(fp, 0, SEEK_END);
	long int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	byte_t* buf = (byte_t*)xmem_alloc(size);
	fread(buf, 1, size, fp);
	fclose(fp);

	ttf_file_head_t ttf_file = { 0 };
	ttf_load_file_head(&ttf_file, buf, size);

	ttf_head_table_t ttf_head = { 0 };
	ttf_load_head_table(&ttf_file, &ttf_head, buf, size);
	int locaFormat = ttf_head.indexToLocFormat;
	ttf_clear_head_table(&ttf_head);

	ttf_name_table_t ttf_name = { 0 };
	ttf_load_name_table(&ttf_file, &ttf_name, buf, size);
	ttf_clear_name_table(&ttf_name);

	ttf_cmap_table_t ttf_cmap = { 0 };
	ttf_load_cmap_table(&ttf_file, &ttf_cmap, buf, size);
	int i;
	for (i = 0; i < ttf_cmap.numTables; i++)
	{

	}
	ttf_clear_cmap_table(&ttf_cmap);

	ttf_maxp_table_t ttf_maxp = { 0 };
	ttf_load_maxp_table(&ttf_file, &ttf_maxp, buf, size);
	int numGlyphs = ttf_maxp.numGlyphs;
	ttf_clear_maxp_table(&ttf_maxp);

	ttf_loca_table_t ttf_loca = { 0 };
	ttf_load_loca_table(&ttf_file, locaFormat, numGlyphs, &ttf_loca, buf, size);

	ttf_glyf_table_t* pglyf = (ttf_glyf_table_t*)xmem_alloc((numGlyphs + 1) * sizeof(ttf_glyf_table_t));
	ttf_load_glyf_table(&ttf_file, &ttf_loca, pglyf, numGlyphs, buf, size);
	for (i = 0; i <= numGlyphs; i++)
	{
		ttf_clear_glyf_table(&pglyf[i]);
	}
	xmem_free(pglyf);

	ttf_clear_loca_table(&ttf_loca);
	ttf_clear_file_head(&ttf_file);

	xmem_free(buf);
}

void test_mgc()
{
	visual_t mgc = create_mgc_visual(MGC_DEVICE_BITMAP_TRUECOLOR32, MGC_PAPER_P6, 100, 800, SDPI);

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
		mgc_text_size(mgc, &xf, str, -1, &xs);

		pt.y += xs.h;
		mgc_text_out(mgc, &xf, &pt, str, -1);
	}

	dword_t n = mgc_save_bytes(mgc, NULL, MAX_LONG);
	byte_t* buf = (byte_t*)xmem_alloc(n);
	mgc_save_bytes(mgc, buf, n);

	destroy_mgc_visual(mgc);

	FILE* fp = fopen("demo.bmp", "wb+");
	fwrite(buf, n, 1, fp);
	fclose(fp);

	xmem_free(buf);
}

void test_draw()
{
	visual_t mgc = create_mgc_visual(MGC_DEVICE_BITMAP_TRUECOLOR32, MGC_PAPER_P6, 100, 800, SDPI);

	xcolor_t xc[2];
	parse_xcolor(&xc[0], GDI_ATTR_RGB_RED);
	parse_xcolor(&xc[1], GDI_ATTR_RGB_GREEN);

	mgc_set_rop(mgc, ROP_COPY);

	xpoint_t pt[10];

	xpen_t xp;
	default_xpen(&xp);

	xscpy(xp.size, _T("3"));
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);
	pt[0].x = 100;
	pt[0].y = 170;
	pt[1].x = 200;
	pt[1].y = 200;
	pt[2].x = 180;
	pt[2].y = 250;
	pt[3].x = 10;
	pt[3].y = 200;
	//mgc_draw_line_raw(mgc, &xp, &pt[0], &pt[1]);
	//mgc_draw_line_raw(mgc, &xp, &pt[1], &pt[2]);
	//mgc_draw_line_raw(mgc, &xp, &pt[2], &pt[3]);
	//mgc_draw_line_raw(mgc, &xp, &pt[3], &pt[0]);

	xfont_t xf;
	default_xfont(&xf);
	xscpy(xf.color, GDI_ATTR_RGB_LIGHTWHITE);
	xscpy(xf.size, _T("12"));
	xface_t xa;
	default_xface(&xa);
	xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_NEAR);
	xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_NEAR);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_LINEBREAK);

	const tchar_t* str = _T("abcd,中文汉字，\n$￥");
	xsize_t xs = { 0 };
	xspan_t s, l;

	xscpy(xp.size, _T("1"));
	//xscpy(xp.style, GDI_ATTR_STROKE_STYLE_DASH);

	pt[0].x = 10;
	pt[0].y = 10;
	pt[1].x = 100;
	pt[1].y = 10;

	//mgc_draw_line_raw(mgc, &xp, &pt[0], &pt[1]);
	//mgc_text_out_raw(mgc, &xf, &pt[0], str, -1);

	xrect_t xr;
	xr.x = 10;
	xr.y = 10;
	xr.w = 100;
	xr.h = 0;

	mgc_text_rect_raw(mgc, &xf, &xa, str, -1, &xr);
	xr.h = 100;
	//mgc_draw_rect_raw(mgc, &xp, NULL, &xr);
	//mgc_draw_text_raw(mgc, &xf, &xa, &xr, str, -1);

	xbrush_t xb;
	default_xbrush(&xb);
	xscpy(xb.style, GDI_ATTR_FILL_STYLE_GRADIENT);
	xscpy(xb.gradient, GDI_ATTR_GRADIENT_HORZ);
	xscpy(xb.color, GDI_ATTR_RGB_RED);
	xscpy(xb.linear, GDI_ATTR_RGB_WHITE);

	pt[0].x = 50;
	pt[0].y = 100;
	pt[1].x = 80;
	pt[1].y = 50;
	pt[2].x = 150;
	pt[2].y = 100;
	pt[3].x = 80;
	pt[3].y = 150;

	//mgc_draw_polyline_raw(mgc, &xp, pt, 4);
	//mgc_draw_polygon_raw(mgc, &xp, &xb, pt, 4);

	xr.x = 10;
	xr.y = 10;
	xr.w = 100;
	xr.h = 100;
	//mgc_draw_triangle_raw(mgc, &xp, &xb, &xr, GDI_ATTR_ORIENT_TOP);

	parse_xcolor(&xc[0], GDI_ATTR_RGB_GRAY);
	parse_xcolor(&xc[1], GDI_ATTR_RGB_BLACK);
	//mgc_gradient_rect_raw(mgc, &xc[0], &xc[1], GDI_ATTR_GRADIENT_VERT, &xr);

	parse_xcolor(&xc[0], GDI_ATTR_RGB_GREEN);
	//mgc_alphablend_rect_raw(mgc, &xc[0], &xr, 100);

	xscpy(xp.size, _T("1"));
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);
	xr.x = 200;
	xr.y = 200;
	xr.w = 100;
	xr.h = 100;
	//mgc_draw_rect_raw(mgc, &xp, &xb, &xr);

	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);
	xr.x = 200;
	xr.y = 100;
	xr.w = 100;
	xr.h = 180;
	//mgc_draw_ellipse_raw(mgc, &xp, &xb, &xr);

	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);
	xr.x = 200;
	xr.y = 100;
	xr.w = 100;
	xr.h = 120;
	xs.w = 10;
	xs.h = 10;
	//mgc_draw_round_raw(mgc, &xp, &xb, &xr, &xs);

	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);
	xr.x = 200;
	xr.y = 100;
	xr.w = 100;
	xr.h = 120;
	//mgc_draw_pie_raw(mgc, &xp, &xb, &xr, XPI / 4, XPI);

	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);
	pt[0].x = 100;
	pt[0].y = 100;
	s.s = 50;
	//mgc_draw_equilagon_raw(mgc, &xp, &xb, pt, &s, 5);

	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);
	pt[0].x = 100;
	pt[0].y = 100;
	pt[1].x = 50;
	pt[1].y = 50;
	xs.w = 50;
	xs.h = 50;
	//mgc_draw_line_raw(mgc, &xp, &pt[0], &pt[1]);
	//mgc_draw_arc_raw(mgc, &xp, &pt[0], &pt[1], &xs, 0, 0);

	xscpy(xp.size, _T("1"));
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);
	pt[0].x = 100;
	pt[0].y = 100;
	s.s = 20;
	l.s = 50;
	//mgc_draw_sector_raw(mgc, &xp, &xb, pt, &l, &s, XPI / 4, XPI / 2);

	xscpy(xp.size, _T("1"));
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_SOLID);
	pt[0].x = 20;
	pt[0].y = 100;
	pt[1].x = 60;
	pt[1].y = 40;
	pt[2].x = 100;
	pt[2].y = 80;
	//mgc_draw_line_raw(mgc, &xp, &pt[0], &pt[1]);
	//mgc_draw_line_raw(mgc, &xp, &pt[1], &pt[2]);
	//mgc_draw_curve_raw(mgc, &xp, pt, 3);

	pt[0].x = 20;
	pt[0].y = 100;
	pt[1].x = 60;
	pt[1].y = 40;
	pt[2].x = 100;
	pt[2].y = 50;
	pt[3].x = 120;
	pt[3].y = 90;
	//mgc_draw_line_raw(mgc, &xp, &pt[0], &pt[1]);
	//mgc_draw_line_raw(mgc, &xp, &pt[1], &pt[2]);
	//mgc_draw_line_raw(mgc, &xp, &pt[2], &pt[3]);
	//mgc_draw_curve_raw(mgc, &xp, pt, 4);

	ximage_t xi = { 0 };
	xi.source =  _T("title.jpg");
	xscpy(xi.color, GDI_ATTR_RGB_WHITE);

	xr.x = 100;
	xr.y = 100;
	xr.w = 300;
	xr.h = 300;
	//mgc_draw_image_raw(mgc, &xi, &xr);

	dword_t n = mgc_save_bytes(mgc, NULL, MAX_LONG);
	byte_t* buf = (byte_t*)xmem_alloc(n);
	mgc_save_bytes(mgc, buf, n);

	destroy_mgc_visual(mgc);

	FILE* fp = fopen("draw.bmp", "wb+");
	fwrite(buf, n, 1, fp);
	fclose(fp);

	xmem_free(buf);
}

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//test_mgc();

	test_draw();

	//test_ttf();

xdk_process_uninit();

#ifdef _OS_WINDOWS
	//getch();
#endif

	return 0;
}

