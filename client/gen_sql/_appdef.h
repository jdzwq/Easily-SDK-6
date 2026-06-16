
#pragma once

#include <xdk.h>


void _show_info(const tchar_t* fname);
void _show_lines(const tchar_t* fname, int lines, const tchar_t* fenc);

void _conv_text(const tchar_t* srcfile, const tchar_t* src_chs, const tchar_t* dst_chs);

void make_ddl(const tchar_t* fname, const tchar_t* fencode, const tchar_t* item_feed);
void make_sql(const tchar_t* fname, const tchar_t* fencode);