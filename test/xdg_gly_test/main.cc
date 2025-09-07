
#include <xdk.h>
#include <xdn.h>
#include <xdg.h>


void test_gly()
{
	xfont_t xf;
	default_xfont(&xf);

	int w, h;

	calc_glyph_size(&xf, &w, &h);

	const glyph_info_t* pgi_a = find_glyph_info(CHARSET_ASCII, &xf);
	glyph_metrix_t gm_a;
	get_glyph_metrix(pgi_a, _T("A"), &gm_a);
	byte_t buf_a[100];
	get_glyph_pixmap(pgi_a, _T("A"),buf_a);

	tchar_t token[10] = {0};

	_tprintf(_T("character: A\n"));
	for (int i = 0; i < pgi_a->height;i++)
	{
		for(int j =0; j< pgi_a->bytesperline;j++)
		{
			uctobin(buf_a[i * pgi_a->bytesperline + j], token, 8);
			_tprintf(token);
		}
		_tprintf(_T("\n"));
	}

	const glyph_info_t *pgi_c = find_glyph_info(CHARSET_GB2312, &xf);
	glyph_metrix_t gm_c;
	get_glyph_metrix(pgi_c, _T("中"), &gm_c);
	byte_t buf_c[100];
	get_glyph_pixmap(pgi_c, _T("中"),buf_c);

	_tprintf(_T("character: 中\n"));
	for (int i = 0; i < pgi_c->height;i++)
	{
		for(int j =0; j< pgi_c->bytesperline;j++)
		{
			uctobin(buf_c[i * pgi_c->bytesperline + j], token, 8);
			_tprintf(token);
		}
		_tprintf(_T("\n"));
	}
}

int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	gly_init();

	test_gly();

	gly_uninit();

	xdk_process_uninit();

	return 0;
}

