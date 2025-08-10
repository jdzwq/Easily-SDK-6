
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

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	test_ttf();

	xdk_process_uninit();

	return 0;
}

