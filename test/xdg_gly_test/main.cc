
#include <xdk.h>
#include <xdg.h>

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

void test_gly()
{
	gly_init();

	xfont_t xf;
	default_xfont(&xf);

	int w, h;

	calc_glyph_size(&xf, &w, &h);

	const glyph_info_t* pgi_a = find_glyph_info(CHARSET_ASCII, &xf);
	glyph_metrix_t gm_a;
	get_glyph_metrix(pgi_a, _T("z"), &gm_a);
	byte_t buf_a[100];
	get_glyph_pixmap(pgi_a, _T("z"),buf_a);

	const glyph_info_t* pgi_c = find_glyph_info(CHARSET_GB2312, &xf);
	glyph_metrix_t gm_c;
	get_glyph_metrix(pgi_c, _T("中"), &gm_c);
	byte_t buf_c[100];
	get_glyph_pixmap(pgi_c, _T("中"),buf_c);

	gly_uninit();
}

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	test_gly();

	xdk_process_uninit();

	return 0;
}

