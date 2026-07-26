/***********************************************************************
	Easily xDesign v3.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, China ZheJiang HangZhou JianDe, Mail: powersuite@hotmaol.com

	@doc xDesign document

	@module	xDesign implement file

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


#include "FormPanel.h"

#include "_Define.h"
#include "_Module.h"
#include "_Frame.h"

#define IDC_FORMPANEL_FORM			201
#define IDC_FORMPANEL_PROPER		202
#define IDC_FORMPANEL_TITLE			203
#define IDC_FORMPANEL_MENU			204
#define IDC_FORMPANEL_FONTNAME		210
#define IDC_FORMPANEL_FONTSIZE		211
#define IDC_FORMPANEL_FONTCOLOR		212
#define IDC_FORMPANEL_PAINTCOLOR	213
#define IDC_FORMPANEL_DRAWCOLOR		214
#define IDC_FORMPANEL_FIELDSHAPE	215

#define FORMPANEL_GROUPITEM_WIDTH		(float)7
#define FORMPANEL_GROUPITEM_HEIGHT		(float)7
#define FORMPANEL_TITLEITEM_WIDTH		(float)15
#define FORMPANEL_TITLEITEM_HEIGHT		(float)10

typedef struct tagFormPanelDelta{
	widget_t hProper;
	widget_t hTitle;
	widget_t hForm;

	tchar_t szFile[PATH_LEN + 1];
	uio_interface uiof;
	METADATA meta;
}FormPanelDelta;

#define GETFORMPANELDELTA(ph) 		(FormPanelDelta*)widget_get_user_delta(ph)
#define SETFORMPANELDELTA(ph,ptd)	widget_set_user_delta(ph,(vword_t)ptd)

#define FORMPANEL_ACCEL_COUNT	5
accel_table_t	FORMPANEL_ACCEL[FORMPANEL_ACCEL_COUNT] = {
	KEY_CONTROL, _T('C'), IDA_EDIT_COPY,
	KEY_CONTROL, _T('X'), IDA_EDIT_CUT,
	KEY_CONTROL, _T('V'), IDA_EDIT_PASTE,
	0,KEY_DELETE, IDA_EDIT_DELETE,
	KEY_CONTROL, _T('Z'), IDA_EDIT_UNDO,
};

/***************************************************************************************/
void FormPanel_SetDirty(widget_t widget, bool_t bDirty)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	designer_set_dirty(pdt->hForm, bDirty);
}

bool_t FormPanel_GetDirty(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	return designer_get_dirty(pdt->hForm);
}

void FormPanel_Switch(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	if (!FormPanel_GetDirty(widget))
		return;

	dword_t rt = ShowMsg(MSGBTN_YES | MSGBTN_NO | MSGBTN_CANCEL | MSGICO_TIP, _T("文件尚未保存，是否保存文件？"));
	
	switch (rt)
	{
	case MSGBTN_YES:
		widget_send_command(widget, 0, IDA_FILE_SAVE, NULL);
		break;
	case MSGBTN_NO:
		FormPanel_SetDirty(widget, 0);
		break;
	}
}


LINKPTR FormPanel_GetDocument(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	return formctrl_fetch(pdt->hForm);
}

bool_t FormPanel_OpenFile(widget_t widget, const tchar_t* szFile)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrMeta = create_meta_doc();
	if (!load_dom_doc_from_file(ptrMeta, NULL, szFile))
	{
		destroy_meta_doc(ptrMeta);
		ShowMsg(MSGICO_ERR, _T("导入表单失败！"));

		return 0;
	}

	if (compare_text(get_meta_doc_name_ptr(ptrMeta), -1, DOC_FORM, -1, 1) != 0)
	{
		destroy_meta_doc(ptrMeta);
		ShowMsg(MSGICO_ERR, _T("非表单文档！"));

		return 0;
	}

	get_meta_head_meta(ptrMeta, ATTR_AUTHOR, -1, pdt->meta.Author, RES_LEN);
	get_meta_head_meta(ptrMeta, ATTR_COMPANY, -1, pdt->meta.Company, RES_LEN);

	LINKPTR newForm = detach_meta_body_node(ptrMeta);
	destroy_meta_doc(ptrMeta);

	LINKPTR orgForm = formctrl_detach(pdt->hForm);
	destroy_form_doc(orgForm);

	set_form_design(newForm, 1);
	formctrl_attach(pdt->hForm, newForm);

	xscpy(pdt->szFile, szFile);

	tchar_t undoFile[PATH_LEN] = {0};

	xscpy(undoFile, pdt->szFile);
	xsncat(undoFile, _T("~"), 1);

	pdt->uiof.fd = xuncf_open_file(NULL, undoFile, FILE_OPEN_CREATE | FILE_OPEN_WRITE | FILE_OPEN_READ);
	if(pdt->uiof.fd)
	{
		get_uio_interface(pdt->uiof.fd, &(pdt->uiof));
	}

	return 1;
}

bool_t FormPanel_SaveFile(widget_t widget, const tchar_t* szFile)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	reset_form_taborder(ptrForm);

	LINKPTR ptrMeta = create_meta_doc();

	set_meta_head_meta(ptrMeta, ATTR_AUTHOR, -1, pdt->meta.Author, -1);
	set_meta_head_meta(ptrMeta, ATTR_COMPANY, -1, pdt->meta.Company, -1);

	attach_meta_body_node(ptrMeta, ptrForm);

	bool_t rt = save_dom_doc_to_file(ptrMeta, NULL, szFile);

	ptrForm = detach_meta_body_node(ptrMeta);
	destroy_meta_doc(ptrMeta);

	if (!rt)
	{
		ShowMsg(MSGICO_ERR, _T("保存XML文档错误"));
		return 0;
	}

	xscpy(pdt->szFile, szFile);

	tchar_t szName[RES_LEN + 1] = { 0 };

	split_path(pdt->szFile, NULL, szName, NULL);

	MainFrame_UpdatePanel(g_hMain, widget, szName);

	if(pdt->uiof.fd)
	{
		(*pdt->uiof.pf_close)(pdt->uiof.fd);
		pdt->uiof.fd = 0;
	}

	return 1;
}

void FormPanel_SelectAttr(widget_t widget, const tchar_t* attr_name, const tchar_t* attr_val)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	tchar_t style[CSS_LEN + 1] = { 0 };
	tchar_t token[RES_LEN + 1] = { 0 };

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		if (flk == ptrField || get_field_selected(flk))
		{
			if (compare_text(attr_name, -1, GDI_ATTR_FONT_WEIGHT, -1, 1) == 0)
			{
				read_style_attr(get_field_style_ptr(flk), -1, attr_name, -1, token, RES_LEN);
				if (compare_text(attr_val,-1,token,-1,1) == 0)
					write_style_attr(get_field_style_ptr(flk), -1, attr_name, -1, NULL, 0, style, CSS_LEN);
				else
					write_style_attr(get_field_style_ptr(flk), -1, attr_name, -1, attr_val, -1, style, CSS_LEN);
			}
			else
			{
				write_style_attr(get_field_style_ptr(flk), -1, attr_name, -1, attr_val, -1, style, CSS_LEN);
			}
			set_field_style(flk, style);
		}

		flk = get_next_field(ptrForm, flk);
	}

	formctrl_redraw(pdt->hForm, 1);
}

void FormPanel_SelectShape(widget_t widget, const tchar_t* attr_val)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		if (flk == ptrField || get_field_selected(flk))
		{
			set_field_shape(flk, attr_val);
		}

		flk = get_next_field(ptrForm, flk);
	}

	formctrl_redraw(pdt->hForm, 1);
}

/*********************************************************************************************************/

void FormPanel_OnSave(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	tchar_t szFile[PATH_LEN + 1] = { 0 };

	if (xsisnil(pdt->szFile))
	{
		tchar_t szPath[PATH_LEN + 1] = { 0 };

		shell_get_curpath(szPath, PATH_LEN);

		if (!shell_get_filename(widget, szPath, _T("Form Meta File(*.sheet)\0*.sheet\0"), _T("sheet"), 1, szPath, PATH_LEN, szFile, PATH_LEN))
			return;

		xsncat(szPath, SLASH_CHAR, 1);
		xscat(szPath, szFile);
		xscpy(szFile, szPath);
	}
	else
	{
		xscpy(szFile, pdt->szFile);
	}

	if (FormPanel_SaveFile(widget, szFile))
	{
		FormPanel_SetDirty(widget, 0);
	}
}

void FormPanel_OnSaveAs(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	tchar_t szPath[PATH_LEN + 1] = { 0 };
	tchar_t szFile[PATH_LEN + 1] = { 0 };
	tchar_t szType[RES_LEN + 1] = { 0 };
	bool_t rt;

	shell_get_curpath(szPath, PATH_LEN);

	if (!shell_get_filename(widget, szPath, _T("Form Meta File(*.sheet)\0*.sheet\0svg image file(*.svg)\0*.svg\0"), _T("sheet"), 1, szPath, PATH_LEN, szFile, PATH_LEN))
		return;

	xsncat(szPath, SLASH_CHAR, 1);
	xscat(szPath, szFile);
	xscpy(szFile, szPath);

	split_path(szFile, NULL, NULL, szType);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	if (compare_text(szType, -1, _T("svg"), -1, 1) == 0)
	{
		LINKPTR ptrSvg = create_svg_doc();

		int page = formctrl_get_cur_page(pdt->hForm);

		set_form_design(ptrForm, 0);

		svg_print_form(ptrSvg, ptrForm, page);

		set_form_design(ptrForm, 1);

		rt = save_dom_doc_to_file(ptrSvg, NULL, szFile);

		destroy_svg_doc(ptrSvg);
	}
	else
	{
		LINKPTR ptrMeta = create_meta_doc();

		set_meta_head_meta(ptrMeta, ATTR_AUTHOR, -1, pdt->meta.Author, -1);
		set_meta_head_meta(ptrMeta, ATTR_COMPANY, -1, pdt->meta.Company, -1);

		attach_meta_body_node(ptrMeta, ptrForm);

		rt = save_dom_doc_to_file(ptrMeta, NULL, szFile);

		ptrForm = detach_meta_body_node(ptrMeta);
		destroy_meta_doc(ptrMeta);
	}

	if (!rt)
		ShowMsg(MSGICO_ERR, _T("保存文件错误！"));
}

void FormPanel_OnPrint(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	//print_form(NULL, ptrForm);
}

void FormPanel_OnPreview(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	int page = formctrl_get_cur_page(pdt->hForm);

	widget_t hPreviewDlg = previewdlg_create(_T("打印预览"), g_hMain);
	
	LINKPTR svg = create_svg_doc();

	svg_print_form(svg, ptrForm, page);

	LINKPTR ptr_arch = previewdlg_get_arch(hPreviewDlg);

	LINKPTR ilk = insert_arch_document(ptr_arch, LINK_LAST, svg);

	tchar_t token[1024] = { 0 };
	xsprintf(token, _T("%s 第%d页"), get_form_title_ptr(ptrForm), page);
	set_arch_item_title(ilk, token);

	previewdlg_redraw(hPreviewDlg);

	widget_show(hPreviewDlg, WS_SHOW_FULLSCREEN);
}

void FormPanel_OnSchema(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	tchar_t szPath[PATH_LEN + 1] = { 0 };
	tchar_t szFile[PATH_LEN + 1] = { 0 };

	shell_get_curpath(szPath, PATH_LEN);

	if (!shell_get_filename(widget, szPath, _T("xml schema file(*.schema)\0*.schema\0"), _T("schema"), 1, szPath, PATH_LEN, szFile, PATH_LEN))
		return;

	xsncat(szPath, SLASH_CHAR, 1);
	xscat(szPath, szFile);
	xscpy(szFile, szPath);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrSch = create_schema_doc();

	export_form_schema(ptrForm, ptrSch);

	if (!save_dom_doc_to_file(ptrSch, NULL, szFile))
	{
		ShowMsg(MSGICO_ERR, _T("保存模式文件失败！"));
	}

	destroy_schema_doc(ptrSch);
}

void FormPanel_OnExport(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	tchar_t szPath[PATH_LEN + 1] = { 0 };
	tchar_t szFile[PATH_LEN + 1] = { 0 };

	shell_get_curpath(szPath, PATH_LEN);

	if (!shell_get_filename(widget, szPath, _T("xml data file(*.xml)\0*.xml\0"), _T("xml"), 1, szPath, PATH_LEN, szFile, PATH_LEN))
		return;

	xsncat(szPath, SLASH_CHAR, 1);
	xscat(szPath, szFile);
	xscpy(szFile, szPath);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	LINKPTR ptrDom = create_dom_doc();

	export_form_data(ptrForm, NULL, ptrDom);

	if (!save_dom_doc_to_file(ptrDom, NULL, szFile))
	{
		destroy_dom_doc(ptrDom);

		ShowMsg(MSGICO_ERR, _T("保存模式数据失败！"));
		return;
	}

	destroy_dom_doc(ptrDom);
}

void FormPanel_OnImport(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	tchar_t szPath[PATH_LEN + 1] = { 0 };
	tchar_t szFile[PATH_LEN + 1] = { 0 };

	shell_get_curpath(szPath, PATH_LEN);

	if (!shell_get_filename(widget, szPath, _T("xml data file(*.xml)\0*.xml\0"), _T("xml"), 0, szPath, PATH_LEN, szFile, PATH_LEN))
		return;

	xsncat(szPath, SLASH_CHAR, 1);
	xscat(szPath, szFile);
	xscpy(szFile, szPath);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	LINKPTR ptrDom = create_dom_doc();

	if (!load_dom_doc_from_file(ptrDom, NULL, szFile))
	{
		destroy_dom_doc(ptrDom);

		ShowMsg(MSGICO_ERR, _T("导入模式数据失败！"));
		return;
	}

	import_form_data(ptrForm, NULL, ptrDom);

	destroy_dom_doc(ptrDom);

	formctrl_redraw(pdt->hForm, 1);
}

void FormPanel_OnExec(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptr_form = formctrl_fetch(pdt->hForm);;

	xrect_t xr = { 0 };
	xr.fw = get_form_width(ptr_form);
	xr.fh = get_form_height(ptr_form) / 2;

	screen_size_to_pt(RECTSIZE(&xr));
	adjust_widget_size(WD_STYLE_DIALOG, RECTSIZE(&xr));

	widget_t win = formctrl_create(NULL, WD_STYLE_DIALOG | WD_STYLE_PAGING, &xr, widget);
	formctrl_set_lock(win, 0);

	color_mod_t clr = { 0 };
	
	parse_xcolor(&clr.clr_bkg, g_face[g_indFace].bkg);
	parse_xcolor(&clr.clr_frg, g_face[g_indFace].frg);
	parse_xcolor(&clr.clr_txt, g_face[g_indFace].txt);
	parse_xcolor(&clr.clr_msk, g_face[g_indFace].msk);
	parse_xcolor(&clr.clr_ico, g_face[g_indFace].ico);
	
	widget_set_color_mode(win, &clr);

	set_form_design(ptr_form, 0);
	formctrl_attach(win, ptr_form);

	widget_center_window(win, widget);
	widget_show(win, WS_SHOW_NORMAL);

	widget_do_modal(win);

	set_form_design(ptr_form, 1);
}

void FormPanel_OnSelectAll(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	XDK_ASSERT(ptrForm);

	LINKPTR flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		set_field_selected(flk, 1);

		flk = get_next_field(ptrForm, flk);
	}

	formctrl_redraw(pdt->hForm, 1);
}

void FormPanel_OnDelete(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	XDK_ASSERT(ptrForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);
	designer_set_focused(pdt->hForm, NULL);

	bool_t bRedraw = 0;
	LINKPTR nlk,flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		nlk = get_next_field(ptrForm, flk);
		if (get_field_selected(flk) || ptrField == flk)
		{
			delete_field(flk);
			flk = nlk;

			bRedraw = 1;
			continue;
		}

		flk = nlk;
	}

	if (bRedraw)
		formctrl_redraw(pdt->hForm,1);
}

void FormPanel_OnCopy(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	widget_post_command(pdt->hForm, COMMAND_COPY, IDC_EDITMENU, 0);
}

void FormPanel_OnCut(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	widget_post_command(pdt->hForm, COMMAND_CUT, IDC_EDITMENU, 0);
}

void FormPanel_OnPaste(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	widget_post_command(pdt->hForm, COMMAND_PASTE, IDC_EDITMENU, 0);
}


void FormPanel_OnRedo(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

}

void FormPanel_OnUndo(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	widget_post_command(pdt->hForm, COMMAND_UNDO, IDC_EDITMENU, 0);
}

void FormPanel_OnAttach(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR flk = (LINKPTR)designer_get_focused(pdt->hForm);
	if (!flk)
		return;

	tchar_t szPath[PATH_LEN + 1] = { 0 };
	tchar_t szFile[PATH_LEN + 1] = { 0 };
	tchar_t szExt[10] = { 0 };

	const tchar_t* szFilter = NULL; 

	const tchar_t* fclass = get_field_class_ptr(flk);
	if (compare_text(fclass, -1, DOC_FORM_GRID, -1, 0) == 0)
	{
		szFilter = _T("Grid Sheet File(*.sheet)\0*.sheet\0");
		xscpy(szExt, _T("sheet"));
	}
	else if (compare_text(fclass, -1, DOC_FORM_STATIS, -1, 0) == 0)
	{
		szFilter = _T("Statis Sheet File(*.sheet)\0*.sheet\0");
		xscpy(szExt, _T("sheet"));
	}
	else if (compare_text(fclass, -1, DOC_FORM_FORM, -1, 0) == 0)
	{
		szFilter = _T("Form Sheet File(*.sheet)\0*.sheet\0");
		xscpy(szExt, _T("sheet"));
	}
	else if (compare_text(fclass, -1, DOC_FORM_RICH, -1, 0) == 0)
	{
		szFilter = _T("Rich Sheet File(*.sheet)\0*.sheet\0");
		xscpy(szExt, _T("sheet"));
	}
	else if (compare_text(fclass, -1, DOC_FORM_IMAGES, -1, 0) == 0)
	{
		szFilter = _T("Image List File(*.images)\0*.images\0");
		xscpy(szExt, _T("images"));
	}
	else if (compare_text(fclass, -1, DOC_FORM_PLOT, -1, 0) == 0)
	{
		szFilter = _T("Plot XML File(*.plot)\0*.plot\0");
		xscpy(szExt, _T("plot"));
	}
	else if (compare_text(fclass, -1, DOC_FORM_MEMO, -1, 0) == 0)
	{
		szFilter = _T("Text File(*.txt)\0*.txt\0");
		xscpy(szExt, _T("txt"));
	}
	else if (compare_text(fclass, -1, DOC_FORM_TAG, -1, 0) == 0)
	{
		szFilter = _T("Text File(*.txt)\0*.txt\0");
		xscpy(szExt, _T("txt"));
	}
	else if (compare_text(fclass, -1, DOC_FORM_PHOTO, -1, 0) == 0)
	{
		szFilter = _T("JPG File(*.jpg)\0*.jpg\0PNG File(*.png)\0*.png\0Bitmap File(*.bmp)\0*.bmp\0");
		xscpy(szExt, _T("jpg"));
	}else if (compare_text(fclass, -1, DOC_FORM_HREF, -1, 0) == 0)
	{
		szFilter = _T("All File(*.*)\0*.*\0");
	}

	shell_get_curpath(szPath, PATH_LEN);

	if (!shell_get_filename(widget, szPath, szFilter, szExt, 0, szPath, PATH_LEN, szFile, PATH_LEN))
		return;

	xsncat(szPath, SLASH_CHAR, 1);
	xscat(szPath, szFile);

	if (compare_text(fclass, -1, DOC_FORM_HREF, -1, 0) == 0)
	{
		set_field_text(flk, szPath, -1);
	}
	else
	{
		if (!load_field_object_from_file(flk, NULL, szPath))
		{
			ShowMsg(MSGICO_ERR, _T("附加文档错误"));
			return;
		}
	}
	
	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnDetach(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR flk = (LINKPTR)designer_get_focused(pdt->hForm);
	if (!flk)
		return;

	const tchar_t* cls = get_field_class_ptr(flk);

	if (IS_EMBED_FIELD(cls) != 0)
	{
		clear_field_embed(flk);
	}
	else if (compare_text(cls, -1, DOC_FORM_PHOTO, -1, 0) == 0)
	{
		set_field_text(flk, NULL, 0);
	}
	else if (compare_text(cls, -1, DOC_FORM_HREF, -1, 0) == 0)
	{
		set_field_text(flk, NULL, 0);
	}
	else if (compare_text(cls, -1, DOC_FORM_MEMO, -1, 0) == 0)
	{
		set_field_text(flk, NULL, 0);
	}
	else if (compare_text(cls, -1, DOC_FORM_TAG, -1, 0) == 0)
	{
		set_field_text(flk, NULL, 0);
	}

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnEditEx(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR flk = (LINKPTR)designer_get_focused(pdt->hForm);
	if (!flk)
		return;

	if (compare_text(get_field_class_ptr(flk), -1, DOC_FORM_PHOTO, -1, 0) == 0)
	{
		string_t vs_img = string_alloc();

		string_cpy(vs_img, get_field_text_ptr(flk), -1);

		widget_t hAnnoDlg = annodlg_create(_T("标注图像"), vs_img, g_hMain);

		widget_show(hAnnoDlg, WS_SHOW_NORMAL);

		if (!widget_do_modal(hAnnoDlg))
		{
			string_free(vs_img);
			return;
		}

		set_field_text(flk, string_ptr(vs_img), string_len(vs_img));

		string_free(vs_img);
	}

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnCSSProper(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptr_proper = create_proper_doc();

	LINKPTR ptr = formctrl_fetch(pdt->hForm);
	LINKPTR flk = (LINKPTR)designer_get_focused(pdt->hForm);

	if (flk)
		properbag_parse_stylesheet(ptr_proper, get_field_style_ptr(flk));
	else
		properbag_parse_stylesheet(ptr_proper, get_form_style_ptr(ptr));

	widget_t hProperDlg = properdlg_create(_T("绘制样式"), ptr_proper, g_hMain);
	
	widget_show(hProperDlg, WS_SHOW_NORMAL);

	int nRet = widget_do_modal(hProperDlg);

	if (nRet)
	{
		tchar_t sz_style[CSS_LEN + 1] = { 0 };
		properbag_format_stylesheet(ptr_proper, sz_style, CSS_LEN);

		if (flk)
		{
			set_field_style(flk, sz_style);
			formctrl_redraw_field(pdt->hForm, flk, 0);
		}
		else
		{
			set_form_style(ptr, sz_style);
			formctrl_redraw(pdt->hForm, 0);
		}

		FormPanel_SetDirty(widget, 1);
	}

	destroy_proper_doc(ptr_proper);
}

void FormPanel_OnFontName(widget_t widget, void* pv)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);
	xpoint_t pt;
	
	pt.x = GETLWORDL((vword_t)pv);
	pt.y = GETLWORDH((vword_t)pv);

	fontname_menu(widget, IDC_FORMPANEL_FONTNAME, &pt, WS_LAYOUT_RIGHTBOTTOM);
}

void FormPanel_OnFontSize(widget_t widget, void* pv)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);
	xpoint_t pt;
	
	pt.x = GETLWORDL((vword_t)pv);
	pt.y = GETLWORDH((vword_t)pv);

	fontsize_menu(widget, IDC_FORMPANEL_FONTSIZE, &pt, WS_LAYOUT_RIGHTBOTTOM);
}

void FormPanel_OnTextColor(widget_t widget, void* pv)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);
	xpoint_t pt;
	
	pt.x = GETLWORDL((vword_t)pv);
	pt.y = GETLWORDH((vword_t)pv);

	color_menu(widget, IDC_FORMPANEL_FONTCOLOR, &pt, WS_LAYOUT_RIGHTBOTTOM);
}

void FormPanel_OnPaintColor(widget_t widget, void* pv)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);
	xpoint_t pt;
	
	pt.x = GETLWORDL((vword_t)pv);
	pt.y = GETLWORDH((vword_t)pv);

	color_menu(widget, IDC_FORMPANEL_PAINTCOLOR, &pt, WS_LAYOUT_RIGHTBOTTOM);
}

void FormPanel_OnDrawColor(widget_t widget, void* pv)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);
	xpoint_t pt;
	
	pt.x = GETLWORDL((vword_t)pv);
	pt.y = GETLWORDH((vword_t)pv);

	color_menu(widget, IDC_FORMPANEL_DRAWCOLOR, &pt, WS_LAYOUT_RIGHTBOTTOM);
}

void FormPanel_OnFieldShape(widget_t widget, void* pv)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);
	xpoint_t pt;
	
	pt.x = GETLWORDL((vword_t)pv);
	pt.y = GETLWORDH((vword_t)pv);

	shape_menu(widget, IDC_FORMPANEL_FIELDSHAPE, &pt, WS_LAYOUT_RIGHTBOTTOM);
}

void FormPanel_OnTextNear(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	if (!get_field_selected_count(ptrForm))
		return;

	FormPanel_SelectAttr(widget, GDI_ATTR_TEXT_ALIGN, GDI_ATTR_TEXT_ALIGN_NEAR);
}

void FormPanel_OnTextBold(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	if (!get_field_selected_count(ptrForm))
		return;

	FormPanel_SelectAttr(widget, GDI_ATTR_FONT_WEIGHT, GDI_ATTR_FONT_WEIGHT_BOLD);
}

void FormPanel_OnTextCenter(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	if (!get_field_selected_count(ptrForm))
		return;

	FormPanel_SelectAttr(widget, GDI_ATTR_TEXT_ALIGN, GDI_ATTR_TEXT_ALIGN_CENTER);
}

void FormPanel_OnTextFar(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	FormPanel_SelectAttr(widget, GDI_ATTR_TEXT_ALIGN, GDI_ATTR_TEXT_ALIGN_FAR);
}

void FormPanel_OnAlignNear(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	if (!ptrField)
		return;

	if (!get_field_selected_count(ptrForm))
		return;

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		if (flk != ptrField && get_field_selected(flk))
		{
			set_field_x(flk, get_field_x(ptrField));
		}

		flk = get_next_field(ptrForm, flk);
	}

	formctrl_redraw(pdt->hForm,1);
}

void FormPanel_OnAlignCenter(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	if (!ptrField)
		return;

	if (!get_field_selected_count(ptrForm))
		return;

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		if (flk != ptrField && get_field_selected(flk))
		{
			set_field_x(flk, get_field_x(ptrField) + get_field_width(ptrField) / 2 - get_field_width(flk) / 2);
		}

		flk = get_next_field(ptrForm, flk);
	}

	formctrl_redraw(pdt->hForm,1);
}

void FormPanel_OnAlignFar(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	if (!ptrField)
		return;

	if (!get_field_selected_count(ptrForm))
		return;

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		if (flk != ptrField && get_field_selected(flk))
		{
			set_field_x(flk, get_field_x(ptrField) + get_field_width(ptrField) - get_field_width(flk));
		}

		flk = get_next_field(ptrForm, flk);
	}

	formctrl_redraw(pdt->hForm,1);
}

void FormPanel_OnSizeHeight(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	if (!ptrField)
		return;

	if (!get_field_selected_count(ptrForm))
		return;

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		if (flk != ptrField && get_field_selected(flk))
		{
			set_field_height(flk, get_field_height(ptrField));
		}

		flk = get_next_field(ptrForm, flk);
	}

	formctrl_redraw(pdt->hForm,1);
}

void FormPanel_OnSizeWidth(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	if (!ptrField)
		return;

	if (!get_field_selected_count(ptrForm))
		return;

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		if (flk != ptrField && get_field_selected(flk))
		{
			set_field_width(flk, get_field_width(ptrField));
		}

		flk = get_next_field(ptrForm, flk);
	}

	formctrl_redraw(pdt->hForm,1);
}

void FormPanel_OnSizeHorz(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	int count = get_field_selected_count(ptrForm);
	if (count <= 1)
		return;

	FormPanel_SetDirty(widget, 1);

	xsort_t* pxs = (xsort_t*)xmem_alloc(sizeof(xsort_t) * count);

	float f_min,f_max,f_total = 0;
	count = 0;
	LINKPTR flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		if (get_field_selected(flk))
		{
			pxs[count].fact = (int)(get_field_x(flk) * 10);
			pxs[count].data = (void*)flk;
			count++;

			f_total += get_field_width(flk);
		}

		flk = get_next_field(ptrForm, flk);
	}

	bubble_xsort(pxs, count);

	f_min = get_field_x((link_t_ptr)pxs[0].data);
	f_max = get_field_x((link_t_ptr)pxs[count - 1].data) + get_field_width((link_t_ptr)pxs[count - 1].data);

	float f_avg = (f_max - f_min - f_total) / (count - 1);
	if (f_avg < 0)
		f_avg = 0;

	f_min = get_field_x((link_t_ptr)pxs[0].data) + get_field_width((link_t_ptr)pxs[0].data);
	for (int i = 1; i < count; i++)
	{
		set_field_x((link_t_ptr)pxs[i].data, f_min + f_avg);
		f_min = get_field_x((link_t_ptr)pxs[i].data) + get_field_width((link_t_ptr)pxs[i].data);
	}

	xmem_free(pxs);

	formctrl_redraw(pdt->hForm,1);
}

void FormPanel_OnSizeVert(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	int count = get_field_selected_count(ptrForm);
	if (count <= 1)
		return;

	FormPanel_SetDirty(widget, 1);

	xsort_t* pxs = (xsort_t*)xmem_alloc(sizeof(xsort_t) * count);

	float f_min, f_max, f_total = 0;
	count = 0;
	LINKPTR flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		if (get_field_selected(flk))
		{
			pxs[count].fact = (int)(get_field_y(flk) * 10);
			pxs[count].data = (void*)flk;
			count++;

			f_total += get_field_height(flk);
		}

		flk = get_next_field(ptrForm, flk);
	}

	bubble_xsort(pxs, count);

	f_min = get_field_y((link_t_ptr)pxs[0].data);
	f_max = get_field_y((link_t_ptr)pxs[count - 1].data) + get_field_height((link_t_ptr)pxs[count - 1].data);

	float f_avg = (f_max - f_min - f_total) / (count - 1);
	if (f_avg < 0)
		f_avg = 0;

	f_min = get_field_y((link_t_ptr)pxs[0].data) + get_field_height((link_t_ptr)pxs[0].data);
	for (int i = 1; i < count; i++)
	{
		set_field_y((link_t_ptr)pxs[i].data, f_min + f_avg);
		f_min = get_field_y((link_t_ptr)pxs[i].data) + get_field_height((link_t_ptr)pxs[i].data);
	}

	xmem_free(pxs);

	formctrl_redraw(pdt->hForm,1);
}

void FormPanel_OnGroup(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	bool_t bGroup = 1;
	if (ptrField)
		bGroup = (get_field_group(ptrField)) ? 0 : 1;

	if (bGroup && !get_field_selected_count(ptrForm))
		return;

	FormPanel_SetDirty(widget, 1);

	int n_max = 0;
	if (bGroup)
		n_max = get_field_max_group(ptrForm) + 1;
	else
		n_max = get_field_group(ptrField);

	LINKPTR flk = get_next_field(ptrForm, LINK_FIRST);
	while (flk)
	{
		if (bGroup && !get_field_group(flk) && get_field_selected(flk))
		{
			set_field_group(flk, n_max);
		}

		if (!bGroup && get_field_group(flk) == n_max)
		{
			set_field_group(flk, 0);
		}

		flk = get_next_field(ptrForm, flk);
	}

	formctrl_redraw(pdt->hForm,1);
}

void FormPanel_OnSendBack(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	if (!ptrField)
		return;

	FormPanel_SetDirty(widget, 1);

	set_field_taborder(ptrField, 0);

	LINKPTR root = get_dom_child_node_root(get_form_fieldset(ptrForm));
	switch_link_first(root, ptrField);

	formctrl_redraw(pdt->hForm,1);
}

void FormPanel_OnLabelField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_LABEL);

	set_field_x(flk, 1);
	set_field_y(flk, 1);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_LABEL);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("label%d"), count);

	set_field_name(flk, token);
	set_field_text(flk, token, -1);

	formctrl_redraw_field(pdt->hForm,flk,1);
}

void FormPanel_OnTextField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_TEXT);

	set_field_x(flk, 1);
	set_field_y(flk, 1);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_TEXT);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("text%d"), count);

	set_field_name(flk, token);
	set_field_text(flk, token, -1);

	formctrl_redraw_field(pdt->hForm,flk,1);
}

void FormPanel_OnRichField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_RICH);

	set_field_x(flk, 1);
	set_field_y(flk, 1);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_RICH);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("rich%d"), count);

	set_field_name(flk, token);
	set_field_text(flk, token, -1);

	formctrl_redraw_field(pdt->hForm,flk,1);
}

void FormPanel_OnMemoField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_MEMO);

	set_field_x(flk, 1);
	set_field_y(flk, 1);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_MEMO);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("memo%d"), count);

	set_field_name(flk, token);
	set_field_text(flk, token, -1);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnTagField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_TAG);

	set_field_x(flk, 1);
	set_field_y(flk, 1);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_TAG);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("tag%d"), count);

	set_field_name(flk, token);
	set_field_text(flk, token, -1);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnCheckField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_CHECK);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_CHECK);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("check%d"), count);

	set_field_name(flk, token);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnCodeField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_CODE);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_CODE);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("code%d"), count);

	set_field_name(flk, token);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnPhotoField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_PHOTO);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_PHOTO);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("photo%d"), count);

	set_field_name(flk, token);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnShapeField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_SHAPE);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_SHAPE);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("shape%d"), count);

	set_field_name(flk, token);
	set_field_text(flk, token, -1);

	formctrl_redraw_field(pdt->hForm,flk,1);
}

void FormPanel_OnPageNumField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_PAGENUM);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	set_field_name(flk, PAGENUM_NAME);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnHrefField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	FormPanel_SetDirty(widget, 1);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_HREF);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_HREF);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("href%d"), count);

	set_field_name(flk, token);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnTableField(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	FormPanel_SetDirty(widget, 1);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_TABLE);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_TABLE);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("table%d"), count);

	set_field_name(flk, token);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnEmbedGrid(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_GRID);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_GRID);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("grid%d"), count);

	set_field_name(flk, token);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnEmbedStatis(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_STATIS);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_STATIS);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("statis%d"), count);

	set_field_name(flk, token);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnEmbedImages(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_IMAGES);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_IMAGES);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("images%d"), count);

	set_field_name(flk, token);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnEmbedForm(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_FORM);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_FORM);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("form%d"), count);

	set_field_name(flk, token);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnEmbedPlot(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);

	FormPanel_SetDirty(widget, 1);

	LINKPTR flk = insert_field(ptrForm, DOC_FORM_PLOT);

	set_field_x(flk, 10);
	set_field_y(flk, 10);

	int count = get_field_count_by_class(ptrForm, DOC_FORM_PLOT);

	tchar_t token[RES_LEN + 1];
	xsprintf(token, _T("plot%d"), count);

	set_field_name(flk, token);

	formctrl_redraw_field(pdt->hForm, flk, 1);
}

void FormPanel_OnAttributes(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	properctrl_accept(pdt->hProper, 0);

	LINKPTR ptrProper = properctrl_fetch(pdt->hProper);
	clear_proper_doc(ptrProper);
	properctrl_redraw(pdt->hProper);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	if (ptrField)
		properbag_write_field_attributes(ptrProper, ptrField);
	else
		properbag_write_form_attributes(ptrProper, ptrForm);

	properctrl_redraw(pdt->hProper);
}

void FormPanel_OnStyleSheet(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	properctrl_accept(pdt->hProper, 0);

	LINKPTR ptrProper = properctrl_fetch(pdt->hProper);
	clear_proper_doc(ptrProper);
	properctrl_redraw(pdt->hProper);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	if (ptrField)
		properbag_parse_stylesheet(ptrProper, get_field_style_ptr(ptrField));
	else
		properbag_parse_stylesheet(ptrProper, get_form_style_ptr(ptrForm));

	properctrl_redraw(pdt->hProper);
}

void FormPanel_Proper_OnEntityUpdate(widget_t widget, NOTICE_PROPER* pnp)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrItem = titlectrl_get_focus_item(pdt->hTitle);
	if (!ptrItem)
		return;

	int n_id = xstol(get_title_item_id_ptr(ptrItem));

	LINKPTR ptrProper = properctrl_fetch(pnp->widget);

	LINKPTR ptrForm = formctrl_fetch(pdt->hForm);
	LINKPTR ptrField = (LINKPTR)designer_get_focused(pdt->hForm);

	tchar_t sz_style[CSS_LEN + 1] = { 0 };

	if (ptrField)
	{
		if (n_id == IDA_ATTRIBUTES)
		{
			properbag_read_field_attributes(ptrProper, ptrField);
		}
		else if (n_id == IDA_STYLESHEET)
		{
			properbag_format_stylesheet(ptrProper, sz_style, CSS_LEN);
			set_field_style(ptrField, sz_style);
		}
		formctrl_redraw_field(pdt->hForm, ptrField, 1);
	}
	else
	{
		if (n_id == IDA_ATTRIBUTES)
		{
			properbag_read_form_attributes(ptrProper, ptrForm);
		}
		else if (n_id == IDA_STYLESHEET)
		{
			properbag_format_stylesheet(ptrProper, sz_style, CSS_LEN);
			set_form_style(ptrForm, sz_style);
		}
		formctrl_redraw(pdt->hForm, 1);
	}
}

void FormPanel_Title_OnItemChanging(widget_t widget, NOTICE_TITLE* pnt)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	properctrl_accept(pdt->hProper, 0);

	LINKPTR ptrProper = properctrl_fetch(pdt->hProper);
	clear_proper_doc(ptrProper);
	properctrl_redraw(pdt->hProper);
}

void FormPanel_Title_OnItemChanged(widget_t widget, NOTICE_TITLE* pnt)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	int n_id = xstol(get_title_item_id_ptr(pnt->item));

	widget_post_command(widget, 0, n_id, NULL);
}

void FormPanel_Form_OnRBClick(widget_t widget, NOTICE_DESIGNER* pnf)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);
	LINKPTR flk = (LINKPTR)pnf->object;

	if (!flk)
		return;

	xpoint_t* ppt = (xpoint_t*)pnf->data;

	xrect_t xr = { 0 };
	xpoint_t pt = { 0 };

	widget_t hMenu = menubox_create(widget, WD_STYLE_POPUP, &xr);
	widget_set_user_id(hMenu, IDC_FORMPANEL_MENU);
	widget_set_owner(hMenu, widget);

	color_mod_t clr;
	widget_get_color_mode(widget, &clr);

	widget_set_color_mode(hMenu, &clr);

	LINKPTR ptrMenu = create_menu_doc();

	LINKPTR mlk = insert_menu_item(ptrMenu, LINK_LAST);
	set_menu_item_iid(mlk, IDA_EDIT_COPY);
	set_menu_item_title(mlk, _T("拷贝字段"));

	mlk = insert_menu_item(ptrMenu, LINK_LAST);
	set_menu_item_iid(mlk, IDA_EDIT_CUT);
	set_menu_item_title(mlk, _T("剪切字段"));

	mlk = insert_menu_item(ptrMenu, LINK_LAST);
	set_menu_item_iid(mlk, IDA_EDIT_PASTE);
	set_menu_item_title(mlk, _T("粘贴字段"));

	mlk = insert_menu_item(ptrMenu, LINK_LAST);
	set_menu_item_iid(mlk, IDA_EDIT_DELETE);
	set_menu_item_title(mlk, _T("删除字段"));

	const tchar_t* fclass = get_field_class_ptr(flk);

	if (IS_EMBED_FIELD(fclass) || compare_text(fclass, -1, DOC_FORM_MEMO, -1, 0) == 0 || compare_text(fclass, -1, DOC_FORM_TAG, -1, 0) == 0 || compare_text(fclass, -1, DOC_FORM_HREF, -1, 0) == 0)
	{
		mlk = insert_menu_item(ptrMenu, LINK_LAST);
		set_menu_item_iid(mlk, IDA_EDIT_ATTACH);
		set_menu_item_title(mlk, _T("附加文档"));

		mlk = insert_menu_item(ptrMenu, LINK_LAST);
		set_menu_item_iid(mlk, IDA_EDIT_DETACH);
		set_menu_item_title(mlk, _T("撤离文档"));
	}
	else if (compare_text(fclass, -1, DOC_FORM_PHOTO, -1, 0) == 0)
	{
		mlk = insert_menu_item(ptrMenu, LINK_LAST);
		set_menu_item_iid(mlk, IDA_EDIT_ATTACH);
		set_menu_item_title(mlk, _T("附加图像"));

		mlk = insert_menu_item(ptrMenu, LINK_LAST);
		set_menu_item_iid(mlk, IDA_EDIT_EDITEX);
		set_menu_item_title(mlk, _T("编辑图像"));
	}

	menubox_set_data(hMenu, ptrMenu);

	pt.x = ppt->x;
	pt.y = ppt->y;
	widget_client_to_screen(pdt->hForm, &pt);

	menubox_layout(hMenu, &pt, WS_LAYOUT_RIGHTBOTTOM);

	widget_do_track(hMenu);

	destroy_menu_doc(ptrMenu);
}

void FormPanel_Form_OnLBClick(widget_t widget, NOTICE_DESIGNER* pnf)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrItem = titlectrl_get_focus_item(pdt->hTitle);
	if (!ptrItem)
		return;

	int n_id = xstol(get_title_item_id_ptr(ptrItem));
	widget_post_command(widget, 0, n_id, NULL);
}

void FormPanel_Form_OnSized(widget_t widget, NOTICE_DESIGNER* pnf)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrItem = titlectrl_get_focus_item(pdt->hTitle);
	if (!ptrItem)
		return;

	int n_id = xstol(get_title_item_id_ptr(ptrItem));
	widget_post_command(widget, 0, n_id, NULL);
}

void FormPanel_Form_OnMoved(widget_t widget, NOTICE_DESIGNER* pnf)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptrItem = titlectrl_get_focus_item(pdt->hTitle);
	if (!ptrItem)
		return;

	int n_id = xstol(get_title_item_id_ptr(ptrItem));
	widget_post_command(widget, 0, n_id, NULL);
}

/***********************************************************************************************************/
int FormPanel_OnCreate(widget_t widget, void* data)
{
	FormPanelDelta* pdt = (FormPanelDelta*)xmem_alloc(sizeof(FormPanelDelta));
	xrect_t xr;
	const tchar_t* szParam;

	widget_hand_create(widget);

	SETFORMPANELDELTA(widget, pdt);

	widget_set_accel(widget, FORMPANEL_ACCEL, FORMPANEL_ACCEL_COUNT);

	szParam = (tchar_t*)data;

	LINKPTR ptrSplit = create_split_doc();

	split_item(ptrSplit, 0);
	set_split_item_ratio(ptrSplit, _T("80%"));

	LINKPTR ilkForm = get_split_first_child_item(ptrSplit);
	LINKPTR ilkRight = get_split_last_child_item(ptrSplit);

	tchar_t token[INT_LEN + 1];
	xsprintf(token, _T("%fmm"), -FORMPANEL_TITLEITEM_HEIGHT);

	split_item(ilkRight, 1);
	set_split_item_ratio(ilkRight, token);
	set_split_item_fixed(ilkRight, 1);

	LINKPTR ilkProper = get_split_first_child_item(ilkRight);
	LINKPTR ilkTitle = get_split_last_child_item(ilkRight);

	widget_get_client_rect(widget, &xr);
	pdt->hForm = formctrl_create(_T("FormPanel"), WD_STYLE_CONTROL | WD_STYLE_PAGING, &xr, widget);
	widget_set_user_id(pdt->hForm, IDC_FORMPANEL_FORM);
	widget_set_owner(pdt->hForm, widget);

	hand_designer_create(pdt->hForm, &desg_formctrl);

	set_split_item_delta(ilkForm, pdt->hForm);
	widget_show(pdt->hForm, WS_SHOW_NORMAL);

	LINKPTR ptrForm = create_form_doc();
	set_form_design(ptrForm, 1);
	formctrl_attach(pdt->hForm, ptrForm);

	widget_get_client_rect(widget, &xr);
	pdt->hProper = properctrl_create(_T("FormProper"), WD_STYLE_CONTROL, &xr, widget);
	widget_set_user_id(pdt->hProper, IDC_FORMPANEL_PROPER);
	widget_set_owner(pdt->hProper, widget);

	LINKPTR ptrProper = create_proper_doc();
	properctrl_attach(pdt->hProper, ptrProper);

	hand_editor_create(pdt->hProper, &edit_properctrl);

	set_split_item_delta(ilkProper, pdt->hProper);
	widget_show(pdt->hProper, WS_SHOW_NORMAL);

	widget_get_client_rect(widget, &xr);
	pdt->hTitle = titlectrl_create(_T("FormTitle"), WD_STYLE_CONTROL | WD_STYLE_OWNERNC, &xr, widget);
	widget_set_user_id(pdt->hTitle, IDC_FORMPANEL_TITLE);
	widget_set_owner(pdt->hTitle, widget);

	set_split_item_delta(ilkTitle, pdt->hTitle);
	widget_show(pdt->hTitle, WS_SHOW_NORMAL);

	LINKPTR ptrTitle = create_title_doc();

	LINKPTR tlk = insert_title_item(ptrTitle, LINK_LAST);
	set_title_item_title(tlk, _T("属性"));
	xsprintf(token, _T("%d"), IDA_ATTRIBUTES);
	set_title_item_id(tlk, token);
	set_title_item_width(tlk, FORMPANEL_TITLEITEM_WIDTH);
	set_title_item_icon(tlk, GDI_ATTR_GIZMO_PROPER);
	set_title_item_locked(tlk, 1);

	tlk = insert_title_item(ptrTitle, LINK_LAST);
	set_title_item_title(tlk, _T("样式"));
	xsprintf(token, _T("%d"), IDA_STYLESHEET);
	set_title_item_id(tlk, token);
	set_title_item_width(tlk, FORMPANEL_TITLEITEM_WIDTH);
	set_title_item_icon(tlk, GDI_ATTR_GIZMO_STYLE);
	set_title_item_locked(tlk, 1);

	titlectrl_attach(pdt->hTitle, ptrTitle);
	titlectrl_set_focus_item(pdt->hTitle, get_title_next_item(ptrTitle, LINK_FIRST));

	widget_attach_splitor(widget, ptrSplit);
	widget_layout_splitor(widget);

	if (!xsisnil(szParam))
	{
		if (!FormPanel_OpenFile(widget, szParam))
			return -1;

		formctrl_redraw(pdt->hForm, 1);
	}

	return 0;
}

void FormPanel_OnDestroy(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	link_t_ptr split = widget_detach_splitor(widget);
	if (split)
		destroy_split_doc(split);

	if (widget_is_valid(pdt->hForm))
	{
		hand_designer_destroy(pdt->hForm);

		LINKPTR ptrForm = formctrl_detach(pdt->hForm);
		if (ptrForm)
			destroy_form_doc(ptrForm);

		widget_destroy(pdt->hForm);
	}

	if (widget_is_valid(pdt->hProper))
	{
		hand_editor_destroy(pdt->hProper);

		LINKPTR ptrProper = properctrl_detach(pdt->hProper);
		if (ptrProper)
			destroy_proper_doc(ptrProper);

		widget_destroy(pdt->hProper);
	}

	if (widget_is_valid(pdt->hTitle))
	{
		LINKPTR ptrTitle = titlectrl_detach(pdt->hTitle);
		if (ptrTitle)
			destroy_title_doc(ptrTitle);

		widget_destroy(pdt->hTitle);
	}

	xmem_free(pdt);

	widget_hand_destroy(widget);
}

void FormPanel_OnShow(widget_t widget, bool_t bShow)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	if (bShow)
	{
		LINKPTR ptrTool = create_tool_doc();
		LINKPTR glk, ilk;

		tchar_t token[NUM_LEN + 1];

		glk = insert_tool_group(ptrTool, LINK_LAST);
		set_tool_group_name(glk, MAINFRAME_TOOLGROUP_EDIT);
		set_tool_group_title(glk, _T("编辑"));
		set_tool_group_item_width(glk, FORMPANEL_GROUPITEM_WIDTH);
		set_tool_group_item_height(glk, FORMPANEL_GROUPITEM_HEIGHT);
		set_tool_group_show(glk, ATTR_SHOW_IMAGEONLY);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_EDIT_SELECTALL);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("全选"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SELECTALL);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_EDIT_DELETE);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("删除"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DELETE);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_EDIT_COPY);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("拷贝"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_COPY);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_EDIT_CUT);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("剪切"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_CUT);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_EDIT_PASTE);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("粘贴"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_PASTE);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_EDIT_UNDO);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("撤销"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_UNDO);

		glk = insert_tool_group(ptrTool, LINK_LAST);
		set_tool_group_name(glk, MAINFRAME_TOOLGROUP_STYLE);
		set_tool_group_title(glk, _T("排版"));
		set_tool_group_item_width(glk, FORMPANEL_GROUPITEM_WIDTH);
		set_tool_group_item_height(glk, FORMPANEL_GROUPITEM_HEIGHT);
		set_tool_group_show(glk, ATTR_SHOW_IMAGEONLY);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_FONT_NAME);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("字体名称"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_FONTNAME);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_FONT_SIZE);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("字号大小"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_FONTSIZE);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_FONT_WEIGHT);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("字体加黑"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_FONTWEIGHT);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_TEXT_COLOR);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("字体颜色"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_FONTCOLOR);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_PAINT_COLOR);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("背景颜色"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_BACKGROUND);

		/*ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_DRAW_COLOR);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("前景"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_STYLE);*/

		/*ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_PROPER);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("CSS属性"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_PROPER);*/

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_TEXT_NEAR);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("左对齐"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_ALIGNNEAR);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_TEXT_CENTER);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("居中对齐"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_ALIGNCENTER);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_TEXT_FAR);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("右对齐"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_ALIGNFAR);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_ALIGN_NEAR);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("左对齐"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_ARRANGELEFT);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_ALIGN_CENTER);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("居中对齐"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_ARRANGECENTER);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_ALIGN_FAR);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("右对齐"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_ARRANGERIGHT);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_SIZE_WIDTH);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("等宽"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SIZEHORZ);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_SIZE_HEIGHT);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("等高"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SIZEVERT);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_SIZE_HORZ);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("水平等距"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SPACEHORZ);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_SIZE_VERT);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("垂直等距"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SPACEVERT);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_GROUP);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("组合"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_GROUP);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_SENDBACK);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("置于后端"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_ORDER);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_STYLE_FIELD_SHAPE);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("形状"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_BORDER);

		glk = insert_tool_group(ptrTool, LINK_LAST);
		set_tool_group_name(glk, MAINFRAME_TOOLGROUP_ELEMENT);
		set_tool_group_title(glk, _T("表单"));
		set_tool_group_item_width(glk, FORMPANEL_GROUPITEM_WIDTH);
		set_tool_group_item_height(glk, FORMPANEL_GROUPITEM_HEIGHT);
		set_tool_group_show(glk, ATTR_SHOW_IMAGEONLY);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_SHAPE);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("形状字段"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SHAPE);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_LABEL);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("标签字段"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_LABEL);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_CHECK);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("选项字段"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_CHECK);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_TEXT);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("单文本字段"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SINGLETEXT);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_MEMO);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("多文本字段"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_MEMO);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_CODE);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("条码字段"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_CODE);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_PHOTO);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("图像字段"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_PHOTO);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_HREF);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("链接字段"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_HERF);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_TABLE);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("字符表字段"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_TABLE);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_RICH);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("富文本字段"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_RICH);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_EMBED_GRID);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("嵌入网格"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_GRID);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_EMBED_STATIS);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("嵌入统计"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_GRAPH);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_EMBED_FORM);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("嵌入表单"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DOC);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_EMBED_PLOT);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("嵌入图表"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_PANTO);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_EMBED_IMAGES);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("图像列表"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_IMAGES);

		ilk = insert_tool_group_item(glk, LINK_LAST);
		xsprintf(token, _T("%d"), IDA_APPEND_PAGENUM);
		set_tool_item_id(ilk, token);
		set_tool_item_title(ilk, _T("页码字段"));
		set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SUM);

		MainFrame_MergeTool(g_hMain, ptrTool);

		destroy_tool_doc(ptrTool);
	}
	else
	{
		MainFrame_ClearTool(g_hMain);
	}
}

int FormPanel_OnClose(widget_t widget)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	FormPanel_Switch(widget);

	return (FormPanel_GetDirty(widget)) ? 1 : 0;
}

void FormPanel_OnCommandFind(widget_t widget, str_find_t* pfd)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	LINKPTR ptr_form = formctrl_fetch(pdt->hForm);
	LINKPTR flk = get_next_field(ptr_form, LINK_FIRST);
	while (flk)
	{
		if (compare_text(pfd->sub_str, -1, get_field_name_ptr(flk), -1, 1) == 0)
		{
			formctrl_set_focus_field(pdt->hForm, flk);
			break;
		}
		flk = get_next_field(ptr_form, flk);
	}
}

void FormPanel_OnParentCommand(widget_t widget, int code, vword_t data)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	if (code == COMMAND_QUERYINFO)
	{
		QUERYOBJECT* pqo = (QUERYOBJECT*)data;
		xscpy(pqo->szDoc, DOC_FORM);
		pqo->ptrDoc = formctrl_fetch(pdt->hForm);
	}
	else if (code == COMMAND_RENAME)
	{
		tchar_t szPath[PATH_LEN + 1], szExt[INT_LEN + 1];
		const tchar_t* nname = (const tchar_t*)data;

		if (!xsisnil(pdt->szFile) && !xsisnil(nname))
		{
			split_path(pdt->szFile, szPath, NULL, szExt);
			xsprintf(pdt->szFile, _T("%s\\%s.%s"), szPath, nname, szExt);
		}
	}
	else if (code == COMMAND_REMOVE)
	{
		FormPanel_SetDirty(widget, 0);
	}
}

void FormPanel_OnMenuCommand(widget_t widget, int code, int cid, vword_t data)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	tchar_t token[RES_LEN + 1];

	switch (cid)
	{
	case IDA_FILE_SAVE:
		FormPanel_OnSave(widget);
		break;
	case IDA_FILE_SAVEAS:
		FormPanel_OnSaveAs(widget);
		break;
	case IDA_FILE_PRINT:
		FormPanel_OnPrint(widget);
		break;
	case IDA_FILE_PREVIEW:
		FormPanel_OnPreview(widget);
		break;
	case IDA_FILE_SCHEMA:
		FormPanel_OnSchema(widget);
		break;
	case IDA_FILE_EXPORT:
		FormPanel_OnExport(widget);
		break;
	case IDA_FILE_IMPORT:
		FormPanel_OnImport(widget);
		break;
	case IDA_FILE_EXEC:
		FormPanel_OnExec(widget);
		break;

	case IDA_EDIT_SELECTALL:
		FormPanel_OnSelectAll(widget);
		break;
	case IDA_EDIT_DELETE:
		FormPanel_OnDelete(widget);
		break;
	case IDA_EDIT_COPY:
		FormPanel_OnCopy(widget);
		break;
	case IDA_EDIT_CUT:
		FormPanel_OnCut(widget);
		break;
	case IDA_EDIT_PASTE:
		FormPanel_OnPaste(widget);
		break;
	case IDA_EDIT_UNDO:
		FormPanel_OnUndo(widget);
		break;
	case IDA_EDIT_ATTACH:
		FormPanel_OnAttach(widget);
		break;
	case IDA_EDIT_DETACH:
		FormPanel_OnDetach(widget);
		break;
	case IDA_EDIT_EDITEX:
		FormPanel_OnEditEx(widget);
		break;
	case IDA_STYLE_PROPER:
		FormPanel_OnCSSProper(widget);
		break;
	case IDA_STYLE_FONT_NAME:
		FormPanel_OnFontName(widget, (void*)data);
		break;
	case IDA_STYLE_FONT_SIZE:
		FormPanel_OnFontSize(widget, (void*)data);
		break;
	case IDA_STYLE_FONT_WEIGHT:
		FormPanel_OnTextBold(widget);
		break;
	case IDA_STYLE_TEXT_COLOR:
		FormPanel_OnTextColor(widget, (void*)data);
		break;
	case IDA_STYLE_PAINT_COLOR:
		FormPanel_OnPaintColor(widget, (void*)data);
		break;
	case IDA_STYLE_DRAW_COLOR:
		FormPanel_OnDrawColor(widget, (void*)data);
		break;
	case IDA_STYLE_TEXT_NEAR:
		FormPanel_OnTextNear(widget);
		break;
	case IDA_STYLE_TEXT_CENTER:
		FormPanel_OnTextCenter(widget);
		break;
	case IDA_STYLE_TEXT_FAR:
		FormPanel_OnTextFar(widget);
		break;
	case IDA_STYLE_ALIGN_NEAR:
		FormPanel_OnAlignNear(widget);
		break;
	case IDA_STYLE_ALIGN_CENTER:
		FormPanel_OnAlignCenter(widget);
		break;
	case IDA_STYLE_ALIGN_FAR:
		FormPanel_OnAlignFar(widget);
		break;
	case IDA_STYLE_SIZE_HORZ:
		FormPanel_OnSizeHorz(widget);
		break;
	case IDA_STYLE_SIZE_VERT:
		FormPanel_OnSizeVert(widget);
		break;
	case IDA_STYLE_SIZE_WIDTH:
		FormPanel_OnSizeWidth(widget);
		break;
	case IDA_STYLE_SIZE_HEIGHT:
		FormPanel_OnSizeHeight(widget);
		break;
	case IDA_STYLE_GROUP:
		FormPanel_OnGroup(widget);
		break;
	case IDA_STYLE_SENDBACK:
		FormPanel_OnSendBack(widget);
		break;
	case IDA_STYLE_FIELD_SHAPE:
		FormPanel_OnFieldShape(widget, (void*)data);
		break;

	case IDA_APPEND_LABEL:
		FormPanel_OnLabelField(widget);
		break;
	case IDA_APPEND_TEXT:
		FormPanel_OnTextField(widget);
		break;
	case IDA_APPEND_RICH:
		FormPanel_OnRichField(widget);
		break;
	case IDA_APPEND_MEMO:
		FormPanel_OnMemoField(widget);
		break;
	case IDA_APPEND_CHECK:
		FormPanel_OnCheckField(widget);
		break;
	case IDA_APPEND_CODE:
		FormPanel_OnCodeField(widget);
		break;
	case IDA_APPEND_PHOTO:
		FormPanel_OnPhotoField(widget);
		break;
	case IDA_APPEND_SHAPE:
		FormPanel_OnShapeField(widget);
		break;
	case IDA_APPEND_PAGENUM:
		FormPanel_OnPageNumField(widget);
		break;
	case IDA_APPEND_HREF:
		FormPanel_OnHrefField(widget);
		break;
	case IDA_APPEND_TABLE:
		FormPanel_OnTableField(widget);
		break;
	case IDA_APPEND_EMBED_GRID:
		FormPanel_OnEmbedGrid(widget);
		break;
	case IDA_APPEND_EMBED_STATIS:
		FormPanel_OnEmbedStatis(widget);
		break;
	case IDA_APPEND_EMBED_IMAGES:
		FormPanel_OnEmbedImages(widget);
		break;
	case IDA_APPEND_EMBED_FORM:
		FormPanel_OnEmbedForm(widget);
		break;
	case IDA_APPEND_EMBED_PLOT:
		FormPanel_OnEmbedPlot(widget);
		break;

	case IDA_ATTRIBUTES:
		FormPanel_OnAttributes(widget);
		break;
	case IDA_STYLESHEET:
		FormPanel_OnStyleSheet(widget);
		break;

	case IDC_FORMPANEL_MENU:
		if (code)
		{
			widget_post_command(widget, 0, code, NULL);
		}
		break;
	case IDC_FORMPANEL_FONTNAME:
		if (code)
		{
			fontname_menu_item(code, token, RES_LEN);
			FormPanel_SelectAttr(widget, GDI_ATTR_FONT_FAMILY, token);
		}
		break;
	case IDC_FORMPANEL_FONTSIZE:
		if (code)
		{
			fontsize_menu_item(code, token, RES_LEN);
			FormPanel_SelectAttr(widget, GDI_ATTR_FONT_SIZE, token);
		}
		break;
	case IDC_FORMPANEL_FONTCOLOR:
		if (code)
		{
			color_menu_item(code, token, RES_LEN);
			FormPanel_SelectAttr(widget, GDI_ATTR_TEXT_COLOR, token);
		}
		break;
	case IDC_FORMPANEL_PAINTCOLOR:
		if (code)
		{
			color_menu_item(code, token, RES_LEN);
			FormPanel_SelectAttr(widget, GDI_ATTR_FILL_COLOR, token);
		}
		break;
	case IDC_FORMPANEL_DRAWCOLOR:
		if (code)
		{
			color_menu_item(code, token, RES_LEN);
			FormPanel_SelectAttr(widget, GDI_ATTR_STROKE_COLOR, token);
		}
		break;
	case IDC_FORMPANEL_FIELDSHAPE:
		if (code)
		{
			shape_menu_item(code, token, RES_LEN);
			FormPanel_SelectShape(widget, token);
		}
		break;
	}
}

void FormPanel_OnNotice(widget_t widget, LPNOTICE phdr)
{
	FormPanelDelta* pdt = GETFORMPANELDELTA(widget);

	if (phdr->user == IDC_FORMPANEL_FORM)
	{
		NOTICE_DESIGNER* pnf = (NOTICE_DESIGNER*)phdr;
		switch (pnf->code)
		{
		case NC_OBJECT_RBCLICK:
			FormPanel_Form_OnRBClick(widget, pnf);
			break;
		case NC_OBJECT_LBCLICK:
			FormPanel_Form_OnLBClick(widget, pnf);
			break;
		case NC_OBJECT_SIZED:
			FormPanel_Form_OnSized(widget, pnf);
			break;
		case NC_OBJECT_DROP:
			FormPanel_Form_OnMoved(widget, pnf);
			break;
		}
	}
	else if (phdr->user == IDC_FORMPANEL_PROPER)
	{
		NOTICE_PROPER* pnp = (NOTICE_PROPER*)phdr;
		switch (pnp->code)
		{
		case NC_ENTITYCOMMIT:
			FormPanel_SetDirty(widget, 1);
			break;
		case NC_ENTITYUPDATE:
			FormPanel_Proper_OnEntityUpdate(widget, pnp);
			break;

		}
	}
	else if (phdr->user == IDC_FORMPANEL_TITLE)
	{
		NOTICE_TITLE* pnt = (NOTICE_TITLE*)phdr;
		switch (pnt->code)
		{
		case NC_TITLECALCED:
			break;
		case NC_TITLEITEMCHANGING:
			FormPanel_Title_OnItemChanging(widget, pnt);
			break;
		case NC_TITLEITEMCHANGED:
			FormPanel_Title_OnItemChanged(widget, pnt);
			break;
		}
	}
}

/**************************************************************************************************************/
widget_t FormPanel_Create(const tchar_t* wname, const xrect_t* pxr, const tchar_t* fpath)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(FormPanel_OnCreate)
		EVENT_ON_DESTROY(FormPanel_OnDestroy)
		EVENT_ON_CLOSE(FormPanel_OnClose)
		EVENT_ON_SHOW(FormPanel_OnShow)

		EVENT_ON_NOTICE(FormPanel_OnNotice)
		EVENT_ON_COMMAND_FIND(FormPanel_OnCommandFind)
		EVENT_ON_PARENT_COMMAND(FormPanel_OnParentCommand)
		EVENT_ON_MENU_COMMAND(FormPanel_OnMenuCommand)

		
		EVENT_ON_SPLITOR_IMPLEMENT
	EVENT_END_DISPATH

	ev.param = (void*)fpath;

	return widget_create(wname, WD_STYLE_CONTROL, pxr, g_hMain, &ev);
}