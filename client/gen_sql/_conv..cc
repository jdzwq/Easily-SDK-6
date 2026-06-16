
#include "_appdef.h"

/********************************************************************************/

void _conv_text(const tchar_t* srcfile, const tchar_t* src_chs, const tchar_t* dst_chs)
{
	int src_enc, dst_enc;
	dword_t dw;
	xhand_t fhd_src = NULL, fhd_dst = NULL;
	stream_t stm_src = NULL, stm_dst = NULL;
	bio_interface bio_src = { 0 };
	bio_interface bio_dst = { 0 };

	string_t vs_txt = NULL;
	tchar_t dstfile[PATH_LEN] = { 0 };

	TRY_CATCH;

	if (xsicmp(src_chs, _T("UNK")) == 0)
		src_enc = 0;
	else
		src_enc = parse_encode(src_chs);

	if (xsicmp(dst_chs, _T("UNK")) == 0)
		dst_enc = _UTF8_BOM;
	else
		dst_enc = parse_encode(dst_chs);

	if (!src_enc)
		src_enc = xuncf_file_encode(NULL, srcfile);

	fhd_src = xuncf_open_file(NULL, srcfile, FILE_OPEN_READ);
	if (!fhd_src)
	{
		raise_user_error(_T("conv_text"), _T("open file failed"));
	}

	get_bio_interface(fhd_src, &bio_src);
	stm_src = stream_alloc(&bio_src);
	stream_set_encode(stm_src, src_enc);
	stream_read_utfbom(stm_src, &dw);
	stream_set_mode(stm_src, LINE_OPERA);

	xscpy(dstfile, srcfile);
	xscat(dstfile, _T("~"));

	fhd_dst = xuncf_open_file(NULL, dstfile, FILE_OPEN_CREATE | FILE_OPEN_WRITE);
	if (!fhd_dst)
	{
		raise_user_error(_T("conv_text"), _T("create file failed"));
	}

	get_bio_interface(fhd_dst, &bio_dst);
	stm_dst = stream_alloc(&bio_dst);
	stream_set_encode(stm_dst, dst_enc);
	stream_write_utfbom(stm_dst, &dw);
	stream_set_mode(stm_dst, LINE_OPERA);

	vs_txt = string_alloc();

	while (1)
	{
		string_empty(vs_txt);
		stream_read_line(stm_src, vs_txt, &dw);
		if (!dw)
			break;

		stream_write_line(stm_dst, vs_txt, &dw);
	}

	if (stm_dst)
	{
		stream_flush(stm_dst);
		stream_free(stm_dst);
		stm_dst = NULL;
	}

	if (fhd_dst)
	{
		xuncf_close_file(fhd_dst);
		fhd_dst = NULL;
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
	_tprintf(_T("Convert file falied\n"));

	if (stm_src)
		stream_free(stm_src);

	if (fhd_src)
		xuncf_close_file(fhd_src);

	if (stm_dst)
		stream_free(stm_dst);

	if (fhd_dst)
		xuncf_close_file(fhd_dst);

	if (vs_txt)
		string_free(vs_txt);

	return;
}
