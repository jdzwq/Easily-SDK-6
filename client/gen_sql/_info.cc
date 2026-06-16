
#include "_appdef.h"

/********************************************************************************/

void _show_info(const tchar_t* fname)
{
	tchar_t fsize[NUM_LEN] = {0};
	tchar_t fencode[RES_LEN] = {0};

	if(xfile_info(NULL, fname, NULL, fsize, NULL, fencode))
	{
		_tprintf(_T("Size: %sBytes, Encode: %s\n"), fsize, fencode);
	}else
	{
		_tprintf(_T("Get file information falied\n"));
	}
}

void _show_lines(const tchar_t* fname, int lines, const tchar_t* fenc)
{
	int src_enc;
	dword_t dw;
	xhand_t fhd_src = NULL;
	stream_t stm_src = NULL;
	bio_interface bio_src = { 0 };
	string_t vs_txt = NULL;

	TRY_CATCH;

	fhd_src = xuncf_open_file(NULL, fname, FILE_OPEN_READ);
	if (!fhd_src)
	{
		raise_user_error(_T("_show_lines"), _T("open file failed"));
	}

	src_enc = parse_encode(fenc);

	get_bio_interface(fhd_src, &bio_src);
	stm_src = stream_alloc(&bio_src);
	stream_set_encode(stm_src, src_enc);
	stream_read_utfbom(stm_src, &dw);
	stream_set_mode(stm_src, LINE_OPERA);

	vs_txt = string_alloc();

	while (lines--)
	{
		string_empty(vs_txt);
		stream_read_line(stm_src, vs_txt, &dw);
		if (!dw)
			break;

		_tprintf(_T("%s"), string_ptr(vs_txt));
	}

	stream_free(stm_src);
	stm_src = NULL;

	xuncf_close_file(fhd_src);
	fhd_src = NULL;

	string_free(vs_txt);
	vs_txt = NULL;

	END_CATCH;

	return;

ONERROR:
	_tprintf(_T("Read file falied\n"));

	if (stm_src)
		stream_free(stm_src);

	if (fhd_src)
		xuncf_close_file(fhd_src);

	if (vs_txt)
		string_free(vs_txt);

	return;
}