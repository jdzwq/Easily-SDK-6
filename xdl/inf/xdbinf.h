/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdl db document

	@module	dbinf.h | interface file

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

#ifndef _XDBINF_H
#define _XDBINF_H


typedef bool_t(STDCALL *PF_DB_PARSE_DSN)(const tchar_t*, tchar_t*, int, tchar_t*, int, tchar_t*, int, tchar_t*, int);
typedef xdb_t(STDCALL *PF_DB_OPEN)(const tchar_t*, const tchar_t*, const tchar_t*, const tchar_t*);
typedef xdb_t(STDCALL *PF_DB_OPEN_DSN)(const tchar_t*);
typedef void(STDCALL *PF_DB_CLOSE)(xdb_t);
typedef bool_t(STDCALL *PF_DB_EXEC)(xdb_t, const tchar_t*, int);
typedef bool_t(STDCALL *PF_DB_SELECT)(xdb_t, link_t_ptr, const tchar_t*);
typedef bool_t(STDCALL *PF_DB_SCHEMA)(xdb_t, link_t_ptr, const tchar_t*);
typedef bool_t(STDCALL *PF_DB_FETCH)(xdb_t, link_t_ptr);
typedef bool_t(STDCALL *PF_DB_UPDATE)(xdb_t, link_t_ptr);
typedef bool_t(STDCALL *PF_DB_DATETIME)(xdb_t, int, tchar_t*);
typedef int(STDCALL *PF_DB_ROWS)(xdb_t);
typedef int(STDCALL *PF_DB_ERROR)(xdb_t, tchar_t*, int);
typedef bool_t(STDCALL *PF_DB_CALL_FUNC)(xdb_t, link_t_ptr);
typedef bool_t(STDCALL *PF_DB_CALL_JSON)(xdb_t, const tchar_t*, link_t_ptr);
typedef bool_t(STDCALL *PF_DB_EXPORT)(xdb_t, stream_t, const tchar_t*);
typedef bool_t(STDCALL *PF_DB_IMPORT)(xdb_t, stream_t, const tchar_t*);
typedef bool_t(STDCALL *PF_DB_BATCH)(xdb_t, stream_t);
typedef bool_t(STDCALL *PF_DB_WRITE_BLOB)(xdb_t, stream_t, const tchar_t*);
typedef bool_t(STDCALL *PF_DB_READ_BLOB)(xdb_t, stream_t, const tchar_t*);
typedef bool_t(STDCALL *PF_DB_WRITE_CLOB)(xdb_t, string_t, const tchar_t*);
typedef bool_t(STDCALL *PF_DB_READ_CLOB)(xdb_t, string_t, const tchar_t*);
typedef bool_t(STDCALL *PF_DB_WRITE_XDOC)(xdb_t, link_t_ptr, const tchar_t*);
typedef bool_t(STDCALL *PF_DB_READ_XDOC)(xdb_t, link_t_ptr, const tchar_t*);

typedef int(*PF_DB_CALL_ARGV)(xdb_t, const tchar_t*, const tchar_t*, ...);

typedef struct _xdb_interface{
	res_modu_t lib;
	xdb_t xdb;

	PF_DB_PARSE_DSN	pf_db_parse_dsn;
	PF_DB_OPEN_DSN	pf_db_open_dsn;
	PF_DB_OPEN		pf_db_open;
	PF_DB_CLOSE		pf_db_close;

	PF_DB_EXEC		pf_db_exec;
	PF_DB_SELECT	pf_db_select;
	PF_DB_SCHEMA	pf_db_schema;
	PF_DB_FETCH		pf_db_fetch;
	PF_DB_UPDATE	pf_db_update;
	PF_DB_CALL_FUNC	pf_db_call_func;
	PF_DB_CALL_JSON	pf_db_call_json;
	PF_DB_EXPORT	pf_db_export;
	PF_DB_IMPORT	pf_db_import;
	PF_DB_BATCH		pf_db_batch;
	PF_DB_WRITE_BLOB	pf_db_write_blob;
	PF_DB_READ_BLOB		pf_db_read_blob;
	PF_DB_WRITE_CLOB	pf_db_write_clob;
	PF_DB_READ_CLOB		pf_db_read_clob;
	PF_DB_WRITE_XDOC	pf_db_write_xdoc;
	PF_DB_READ_XDOC		pf_db_read_xdoc;

	PF_DB_DATETIME	pf_db_datetime;
	PF_DB_ROWS		pf_db_rows;
	PF_DB_ERROR		pf_db_error;

}xdb_interface;



#endif /*XDBINF_H*/
