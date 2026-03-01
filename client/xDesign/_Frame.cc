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



#include "_Frame.h"
#include "_Define.h"
#include "_Project.h"

#include "FormPanel.h"
#include "GridPanel.h"
#include "StatisPanel.h"
#include "SchemaPanel.h"
#include "TopogPanel.h"
#include "ImagePanel.h"
#include "RichPanel.h"
#include "DialogPanel.h"
#include "SQLPanel.h"
#include "XMLPanel.h"
#include "JsonPanel.h"
#include "PlotPanel.h"

#define MAINFRAME_TOOLBAR_HEIGHT	(float)25
#define MAINFRAME_TREEBAR_WIDTH		(float)50
#define MAINFRAME_TITLEBAR_HEIGHT	(float)8
#define MAINFRAME_STATUSBAR_HEIGHT	(float)8
#define MAINFRAME_CATEBAR_HEIGHT	(float)10

#define MAINFRAME_GROUPITEM_HEIGHT		(float)7
#define MAINFRAME_GROUPITEM_MAXWIDTH	(float)18
#define MAINFRAME_GROUPITEM_MINWIDTH	(float)8
#define MAINFRAME_TITLEITEM_WIDTH		(float)15
#define MAINFRAME_STATUSITEM_WIDTH		(float)20

#define MAINFRAME_TREE_OBJECT		_T("item")
#define MAINFRAME_TREE_RESOURCE		_T("resource")

#define IDC_MAINFRAME_TOOLBAR		100
#define IDC_MAINFRAME_TITLEBAR		101
#define IDC_MAINFRAME_RESBAR		102
#define IDC_MAINFRAME_OBJBAR		104
#define IDC_MAINFRAME_STATUSBAR		105
#define IDC_MAINFRAME_CATEBAR		106
#define IDC_MAINFRAME_MENUBOX		110
#define IDC_MAINFRAME_FACEMENU		111

#define IDC_MAINFRAME_FORMPANEL		110
#define IDC_MAINFRAME_GRIDPANEL		111
#define IDC_MAINFRAME_STATISPANEL	112
#define IDC_MAINFRAME_SCHEMAPANEL	113
#define IDC_MAINFRAME_TOPOGPANEL	114
#define IDC_MAINFRAME_IMAGESPANEL	115
#define IDC_MAINFRAME_RICHPANEL		116
#define IDC_MAINFRAME_DIALOGPANEL	117
#define IDC_MAINFRAME_PANORAMAPANEL	118
#define IDC_MAINFRAME_SQLPANEL		121
#define IDC_MAINFRAME_XMLPANEL		122
#define IDC_MAINFRAME_JSONPANEL		123
#define IDC_MAINFRAME_PLOTPANEL		124

#define MAINFRAME_ACCEL_COUNT		4

accel_table_t	MAINFRAME_ACCEL[MAINFRAME_ACCEL_COUNT] = {
	0, KEY_F10, IDA_PROJECT_OPEN,
	KEY_CONTROL, _T('O'), IDA_FILE_OPEN,
	KEY_CONTROL, _T('S'), IDA_FILE_SAVE,
	KEY_CONTROL, _T('N'), IDA_FILE_CREATE,
};

typedef struct tagMainFrameDelta{	
	widget_t hToolBar;
	widget_t hTitleBar;
	widget_t hResBar;
	widget_t hObjBar;
	widget_t hCateBar;
	widget_t hClientWnd;
	widget_t hStatusBar;

	widget_t hToolTip;
	widget_t hKeyBox;
	widget_t hNaviBox;

	bool_t bDirty;
	bool_t bMode;

	LINKPTR ptrProject;
	tchar_t szFile[PATH_LEN + 1];
}MainFrameDelta;

#define GETMAINFRAMEDELTA(widget) 			(MainFrameDelta*)widget_get_user_delta(widget)
#define SETMAINFRAMEDELTA(widget,ptd)		widget_set_user_delta(widget,(vword_t)ptd)

widget_t	_MainFrame_CreatePanel(widget_t widget, const tchar_t* wclass, const tchar_t* fpath);
bool_t		_MainFrame_FindPanel(widget_t widget, const tchar_t* wclass, const tchar_t* fpath);
void		_MainFrame_RenamePanel(widget_t widget, const tchar_t* wclass, const tchar_t* wname, const tchar_t* nname);

/***********************************************************************************************/
void MainFrame_Switch(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if (!pdt->bDirty)
		return;

	dword_t rt = ShowMsg(MSGBTN_YES | MSGBTN_NO | MSGICO_TIP, _T("工程文件尚未保存，是否保存？"));

	switch (rt)
	{
	case MSGBTN_YES:
		widget_post_command(widget, IDA_PROJECT_SAVE, 0, NULL);
		break;
	case MSGBTN_NO:
		pdt->bDirty = FALSE;
		break;
	}
}

void MainFrame_MergeTool(widget_t widget, LINKPTR subTool)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrTool = toolctrl_fetch(pdt->hToolBar);

	merge_tool_doc(ptrTool, subTool);

	toolctrl_redraw(pdt->hToolBar);
}

void MainFrame_ClearTool(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrTool = toolctrl_fetch(pdt->hToolBar);
	LINKPTR nxt, glk = get_tool_next_group(ptrTool, LINK_FIRST);
	while (glk)
	{
		nxt = get_tool_next_group(ptrTool, glk);

		if (compare_text(get_tool_group_name_ptr(glk), -1, MAINFRAME_TOOLGROUP_PROJECT, -1, 0) != 0 && compare_text(get_tool_group_name_ptr(glk), -1, MAINFRAME_TOOLGROUP_FILE, -1, 0) != 0 && compare_text(get_tool_group_name_ptr(glk), -1, MAINFRAME_TOOLGROUP_SETTING, -1, 0) != 0)
			delete_tool_group(glk);

		glk = nxt;
	}

	toolctrl_redraw(pdt->hToolBar);
}


void MainFrame_SaveProject(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if (!pdt->bDirty)
		return;

	if (is_null(pdt->szFile))
	{
		tchar_t szPath[PATH_LEN + 1] = { 0 };
		tchar_t szFile[PATH_LEN + 1] = { 0 };

		shell_get_curpath(szPath, PATH_LEN);

		if (!shell_get_filename(widget, szPath, _T("Project File(*.project)\0*.project\0"), _T("project"), 0, szPath, PATH_LEN, szFile, PATH_LEN))
			return;

		xsprintf(pdt->szFile, _T("%s/%s"), szPath, szFile);
	}

	if (!pdt->ptrProject)
	{
		pdt->ptrProject = Project_Alloc();
	}

	LINKPTR ptrResTree = treectrl_fetch(pdt->hResBar);
	Project_SetResource(pdt->ptrProject, ptrResTree);

	if (!Project_Save(pdt->ptrProject, pdt->szFile))
	{
		ShowMsg(MSGICO_ERR, _T("保存工程文件错误！"));
		return;
	}

	pdt->bDirty = FALSE;
}

void MainFrame_CloseProject(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if (pdt->bDirty)
	{
		MainFrame_SaveProject(widget);
	}

	if (pdt->bDirty)
		return;

	if (pdt->ptrProject)
	{
		Project_Free(pdt->ptrProject);
		pdt->ptrProject = NULL;
	}

	xscpy(pdt->szFile, _T(""));

	LINKPTR ptrResTree = treectrl_fetch(pdt->hResBar);
	clear_tree_doc(ptrResTree);
	treectrl_redraw(pdt->hResBar);

	LINKPTR ptrObjTree = treectrl_fetch(pdt->hObjBar);
	clear_tree_doc(ptrObjTree);
	treectrl_redraw(pdt->hObjBar);

	widget_set_title(widget, _T("xDesign"));
}

void MainFrame_CreateProject(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	MainFrame_CloseProject(widget);

	if (pdt->bDirty)
		return;

	tchar_t szPath[PATH_LEN + 1] = { 0 };
	tchar_t szFile[PATH_LEN + 1] = { 0 };

	shell_get_curpath(szPath, PATH_LEN);

	if (!shell_get_filename(widget, szPath, _T("Project File(*.project)\0*.project\0"), _T("project"), 1, szPath, PATH_LEN, szFile, PATH_LEN))
		return;

	xscat(szPath, _T("/"));
	xscat(szPath, szFile);

	pdt->ptrProject = Project_Alloc();

	if (!save_dom_doc_to_file(pdt->ptrProject, NULL, szPath))
	{
		Project_Free(pdt->ptrProject);
		pdt->ptrProject = NULL;
		ShowMsg(MSGICO_ERR, _T("保存工程文件错误！"));
		return;
	}

	xscpy(pdt->szFile, szPath);

	LINKPTR ptrResTree = treectrl_fetch(pdt->hResBar);
	Project_GetResource(pdt->ptrProject, ptrResTree);
	treectrl_redraw(pdt->hResBar);

	tchar_t token[RES_LEN + 1] = { 0 };
	xscpy(token, _T("xDesign ["));
	int len = xslen(token);

	split_path(pdt->szFile, NULL, token + len, NULL);
	xscat(token, _T("]"));

	widget_set_title(widget, token);
}

void MainFrame_OpenProject(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	MainFrame_CloseProject(widget);

	if (pdt->bDirty)
		return;

	tchar_t szPath[PATH_LEN + 1] = { 0 };
	tchar_t szFile[PATH_LEN + 1] = { 0 };

	shell_get_curpath(szPath, PATH_LEN);

	if (!shell_get_filename(widget, szPath, _T("Project File(*.project)\0*.project\0"), _T("project"), 0, szPath, PATH_LEN, szFile, PATH_LEN))
		return;

	xscat(szPath, _T("/"));
	xscat(szPath, szFile);

	pdt->ptrProject = Project_Alloc();

	if (!Project_Load(pdt->ptrProject, szPath))
	{
		Project_Free(pdt->ptrProject);
		pdt->ptrProject = NULL;

		ShowMsg(MSGICO_ERR, _T("打开工程文件错误！"));
		return;
	}

	xscpy(pdt->szFile, szPath);

	LINKPTR ptrResTree = treectrl_fetch(pdt->hResBar);
	Project_GetResource(pdt->ptrProject, ptrResTree);
	treectrl_redraw(pdt->hResBar);

	tchar_t token[RES_LEN + 1] = { 0 };
	xscpy(token, _T("xDesign ["));
	int len = xslen(token);

	split_path(pdt->szFile, NULL, token + len, NULL);
	xscat(token, _T("]"));

	widget_set_title(widget, token);
}

static void _MainFrame_FileClass(const tchar_t* szPath, tchar_t* szClass)
{
	LINKPTR ptrDom = create_dom_doc();

	if (!load_dom_doc_from_file(ptrDom, NULL, szPath))
	{
		destroy_dom_doc(ptrDom);
		return;
	}

	if (is_form_doc(ptrDom))
		xscpy(szClass, PANEL_CLASS_FORM);
	else if (is_grid_doc(ptrDom))
		xscpy(szClass, PANEL_CLASS_GRID);
	else if (is_statis_doc(ptrDom))
		xscpy(szClass, PANEL_CLASS_STATIS);
	else if (is_rich_doc(ptrDom))
		xscpy(szClass, PANEL_CLASS_RICH);
	else if (is_topog_doc(ptrDom))
		xscpy(szClass, PANEL_CLASS_TOPOG);
	else if (is_images_doc(ptrDom))
		xscpy(szClass, PANEL_CLASS_IMAGE);
	else if (is_dialog_doc(ptrDom))
		xscpy(szClass, PANEL_CLASS_DIALOG);
	else if (is_plot_doc(ptrDom))
		xscpy(szClass, PANEL_CLASS_PLOT);
	else if (is_schema_doc(ptrDom))
		xscpy(szClass, PANEL_CLASS_SCHEMA);

	destroy_dom_doc(ptrDom);
}

void MainFrame_CreateFile(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrList = create_list_doc();

	tchar_t szID[NUM_LEN + 1];

	LINKPTR llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_FORMPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("空白表单"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_MEMO);

	llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_GRIDPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("空白网格"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_GRID);

	llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_RICHPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("空白富文本"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_RICH);

	llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_STATISPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("空白图表"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_GRAPH);

	llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_SCHEMAPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("空白模式"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_SCHEMA);

	llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_TOPOGPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("空白地形"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_GROUP);

	llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_IMAGESPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("图像列表"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_IMAGES);

	llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_PLOTPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("空白图形"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_PANTO);

	llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_DIALOGPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("对话框"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_DIALOG);

	llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_SQLPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("SQL"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_EDIT);

	llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_XMLPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("XML"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_EDIT);

	llk = insert_list_item(ptrList, LINK_LAST);
	xsprintf(szID, _T("%d"), IDC_MAINFRAME_JSONPANEL);
	set_list_item_id(llk, szID);
	set_list_item_title(llk, _T("JSON"));
	set_list_item_icon(llk, GDI_ATTR_GIZMO_EDIT);

	widget_t hNewFileDlg = listdlg_create(_T("选择文档类型"), ptrList, widget);
	
	widget_show(hNewFileDlg, WS_SHOW_NORMAL);

	int ret = (int)widget_do_modal(hNewFileDlg);

	destroy_list_doc(ptrList);

	switch (ret)
	{
	case IDC_MAINFRAME_FORMPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_FORM, NULL);
		break;
	case IDC_MAINFRAME_GRIDPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_GRID, NULL);
		break;
	case IDC_MAINFRAME_STATISPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_STATIS, NULL);
		break;
	case IDC_MAINFRAME_RICHPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_RICH, NULL);
		break;
	case IDC_MAINFRAME_SCHEMAPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_SCHEMA, NULL);
		break;
	case IDC_MAINFRAME_TOPOGPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_TOPOG, NULL);
		break;
	case IDC_MAINFRAME_IMAGESPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_IMAGE, NULL);
		break;
	case IDC_MAINFRAME_PLOTPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT, NULL);
		break;
	case IDC_MAINFRAME_DIALOGPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_DIALOG, NULL);
		break;
	case IDC_MAINFRAME_PANORAMAPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PANORAMA, NULL);
		break;
	case IDC_MAINFRAME_SQLPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_SQL, NULL);
		break;
	case IDC_MAINFRAME_XMLPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_XML, NULL);
		break;
	case IDC_MAINFRAME_JSONPANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_JSON, NULL);
		break;
	}
}

void MainFrame_OpenFile(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	tchar_t szPath[PATH_LEN + 1] = { 0 };
	tchar_t szFile[PATH_LEN + 1] = { 0 };
	tchar_t szFilter[] = _T("Sheet File(*.sheet)\0*.sheet\0Schema File(*.schema)\0*.schema\0Text File(*.txt)\0*.txt\0SQL File(*.sql)\0*.sql\0Xml File(*.xml)\0*.xml\0Json File(*.json)\0*.json\0");

	shell_get_curpath(szPath, PATH_LEN);

	if (!shell_get_filename(widget, szPath, szFilter, _T("sheet"), 0, szPath, PATH_LEN, szFile, PATH_LEN))
		return;

	xscat(szPath, _T("\\"));
	xscat(szPath, szFile);

	tchar_t szClass[RES_LEN + 1] = { 0 };

	split_path(szPath, NULL, NULL, szClass);

	if (compare_text(szClass, -1, _T("sheet"), -1, 1) == 0 || compare_text(szClass, -1, _T("schema"), -1, 1) == 0)
	{
		xszero(szClass, RES_LEN);
		_MainFrame_FileClass(szPath, szClass);
	}
	else
	{
		if (compare_text(szClass, -1, _T("sql"), -1, 1) == 0)
			xscpy(szClass, PANEL_CLASS_SQL);
		else if (compare_text(szClass, -1, _T("xml"), -1, 1) == 0)
			xscpy(szClass, PANEL_CLASS_XML);
		else if (compare_text(szClass, -1, _T("json"), -1, 1) == 0)
			xscpy(szClass, PANEL_CLASS_JSON);
	}

	if (is_null(szClass))
	{
		ShowMsg(MSGICO_ERR, _T("未知文档类型"));
		return;
	}

	_MainFrame_CreatePanel(widget, szClass, szPath);
}

void MainFrame_CloseFile(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
}

LINKPTR _MainFrame_FindTreeNode(LINKPTR ptrTree, const tchar_t* nname)
{
	LINKPTR tlk = get_tree_first_child_item(ptrTree);

	while (tlk)
	{
		if (compare_text(get_tree_item_name_ptr(tlk), -1, nname, -1, 1) == 0)
			return tlk;

		tlk = get_tree_next_sibling_item(tlk);
	}

	return NULL;
}


void MainFrame_AppendFile(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if (is_null(pdt->szFile))
	{
		ShowMsg(MSGICO_TIP, _T("请先新建或打开工程！"));
		return;
	}

	tchar_t szPath[PATH_LEN * 10] = { 0 };
	tchar_t szFile[PATH_LEN * 10] = { 0 };
	tchar_t szFilter[] = _T("Sheet File(*.sheet)\0*.sheet\0Schema File(*.schema)\0*.schema\0Text File(*.txt)\0*.txt\0SQL File(*.sql)\0*.sql\0Xml File(*.xml)\0*.xml\0Json File(*.json)\0*.json\0");

	split_path(pdt->szFile, szPath, NULL, NULL);

	if (!shell_get_filename(widget, szPath, szFilter, _T("sheet"), 0, szPath, PATH_LEN * 10, szFile, PATH_LEN * 10))
		return;

	LINKPTR ptr_tree = treectrl_fetch(pdt->hResBar);
	LINKPTR tlk_parent = NULL;

	tchar_t szName[PATH_LEN + 1], szTitle[PATH_LEN + 1], szType[RES_LEN + 1];

	tchar_t* szToken = szFile;
	while (*szToken)
	{
		split_path(szToken, NULL, szTitle, szType);
		xscpy(szName, szTitle);
		xscat(szName, _T("."));
		xscat(szName, szType);

		tlk_parent = find_tree_item_by_name(ptr_tree, szType);
		if (!tlk_parent)
		{
			tlk_parent = insert_tree_item(ptr_tree, LINK_LAST);
			set_tree_item_name(tlk_parent, szType);
			set_tree_item_title(tlk_parent, szType);
			set_tree_item_icon(tlk_parent, GDI_ATTR_GIZMO_NOTE);

			pdt->bDirty = TRUE;
		}

		LINKPTR tlk_child = find_tree_item_by_name(tlk_parent, szName);
		if (!tlk_child)
		{
			tlk_child = insert_tree_item(tlk_parent, LINK_LAST);
			set_tree_item_name(tlk_child, szName);
			set_tree_item_title(tlk_child, szTitle);
			set_tree_item_icon(tlk_child, GDI_ATTR_GIZMO_SCHEMA);

			pdt->bDirty = TRUE;
		}

		szToken += (xslen(szToken) + 1);
	}

	treectrl_redraw(pdt->hResBar);
}

bool_t MainFrame_RenameFile(widget_t widget, const tchar_t* nname)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR tlk = treectrl_get_focus_item(pdt->hResBar);

	tchar_t szNew[PATH_LEN + 1], szOrg[PATH_LEN + 1], szExt[INT_LEN + 1];
	tchar_t szClass[RES_LEN + 1] = { 0 };

	split_path(pdt->szFile, szOrg, NULL, NULL);
	xscat(szOrg, _T("\\"));
	xscat(szOrg, get_tree_item_name_ptr(tlk));

	_MainFrame_FileClass(szOrg, szClass);

	split_path(get_tree_item_name_ptr(tlk), NULL, NULL, szExt);

	split_path(pdt->szFile, szNew, NULL, NULL);
	xscat(szNew, _T("\\"));
	xscat(szNew, nname);
	xscat(szNew, _T("."));
	xscat(szNew, szExt);

	if (!xfile_rename(NULL, szOrg, szNew))
	{
		return 0;
	}

	xscpy(szOrg, get_tree_title_ptr(tlk));

	xscpy(szNew, nname);
	xscat(szNew, _T("."));
	xscat(szNew, szExt);
	set_tree_item_name(tlk, szNew);

	xscpy(szNew, nname);

	_MainFrame_RenamePanel(widget, szClass, szOrg, szNew);

	return 1;
}

void MainFrame_RemoveFile(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR tlk = treectrl_get_focus_item(pdt->hResBar);
	if (!tlk)
		return;

	if (is_tree_doc(get_tree_parent_item(tlk)))
		return;

	delete_tree_item(tlk);
	treectrl_redraw(pdt->hResBar);

	pdt->bDirty = TRUE;
}

void MainFrame_ShowFile(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR tlk = treectrl_get_focus_item(pdt->hResBar);
	if (!tlk)
		return;

	if (is_tree_doc(get_tree_parent_item(tlk)))
		return;

	tchar_t szPath[PATH_LEN + 1] = { 0 };
	tchar_t szFile[PATH_LEN + 1] = { 0 };
	tchar_t szClass[RES_LEN + 1] = { 0 };

	xscpy(szFile, get_tree_item_name_ptr(tlk));

	split_path(pdt->szFile, szPath, NULL, NULL);
	xscat(szPath, _T("\\"));
	xscat(szPath, szFile);

	_MainFrame_FileClass(szPath, szClass);

	if (is_null(szClass))
	{
		ShowMsg(MSGICO_ERR, _T("未知XML文档类型"));
		return;
	}

	if (_MainFrame_FindPanel(widget, szClass, szPath))
		return;

	_MainFrame_CreatePanel(widget, szClass, szPath);
}

void MainFrame_SyncFile(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if (!pdt->ptrProject)
		return;

	tchar_t szSYN[PATH_LEN + 1] = { 0 };

	secu_desc_t sd = { 0 };

	Project_GetConfig(pdt->ptrProject, _T("SYN"), szSYN, PATH_LEN);

	LINKPTR ptr_str = create_string_table(0);

	string_table_parse_attrset(ptr_str, szSYN, -1);

	LINKPTR slk = get_string_next_entity(ptr_str, LINK_FIRST);
	while (slk)
	{
		if (compare_text(get_string_entity_key_ptr(slk), -1, _T("SERVICE"), -1, 1) == 0)
		{
			get_string_entity_val(slk, szSYN, PATH_LEN);
		}
		else if (compare_text(get_string_entity_key_ptr(slk), -1, _T("SECRET-ID"), -1, 1) == 0)
		{
			get_string_entity_val(slk, sd.scr_uid, KEY_LEN);
		}
		else if (compare_text(get_string_entity_key_ptr(slk), -1, _T("SECRET-KEY"), -1, 1) == 0)
		{
			get_string_entity_val(slk, sd.scr_key, KEY_LEN);
		}

		slk = get_string_next_entity(ptr_str, slk);
	}

	destroy_string_table(ptr_str);

	if (is_null(szSYN))
	{
		ShowMsg(MSGICO_ERR, _T("未设置文档同步服务！"));
		return;
	}

	int rt = ShowMsg(MSGICO_TIP | MSGBTN_YES | MSGBTN_NO, _T("您确认将文件发布到服务端吗？"));
	if (!(rt & MSGBTN_YES))
		return;

	tchar_t szSrv[PATH_LEN + 1] = { 0 };
	tchar_t szLoc[PATH_LEN + 1] = { 0 };

	tchar_t locTime[DATE_LEN + 1] = { 0 };
	tchar_t srvTime[DATE_LEN + 1] = { 0 };

	statusctrl_show_step(pdt->hStatusBar, 1);
	widget_set_cursor(g_hMain, CURSOR_WAIT);

	LINKPTR ptr_tree = treectrl_fetch(pdt->hResBar);
	LINKPTR tlk_ext = get_tree_first_child_item(ptr_tree);
	while (tlk_ext)
	{
		LINKPTR tlk_file = get_tree_first_child_item(tlk_ext);
		while (tlk_file)
		{
			split_path(pdt->szFile, szLoc, NULL, NULL);

			xscat(szLoc, _T("\\"));
			xscat(szLoc, get_tree_item_name_ptr(tlk_file));

			xscpy(szSrv, szSYN);
			xscat(szSrv, _T("/"));
			xscat(szSrv, get_tree_item_name_ptr(tlk_file));

			if (xfile_info(NULL, szLoc, locTime, NULL, NULL, NULL))
			{
				xfile_copy(&sd, szLoc, szSrv, FILE_SINCE_TIME);
			}

			statusctrl_step_it(pdt->hStatusBar, 1, get_tree_item_name_ptr(tlk_file));

			tlk_file = get_tree_next_sibling_item(tlk_file);
		}

		tlk_ext = get_tree_next_sibling_item(tlk_ext);
	}

	statusctrl_show_step(pdt->hStatusBar, 0);
	widget_set_cursor(g_hMain, CURSOR_ARROW);

	ShowMsg(MSGICO_TIP, _T("文件发布完成！"));
}

void MainFrame_SortFile(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR tlk = treectrl_get_focus_item(pdt->hResBar);
	if (!tlk)
		return;

	sort_dom_child_node_by_attr(tlk, ATTR_NAME, 0);

	pdt->bDirty = TRUE;

	treectrl_redraw(pdt->hResBar);
}

void MainFrame_FreshObject(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptr_tree = treectrl_fetch(pdt->hObjBar);

	delete_tree_child_items(ptr_tree);
	treectrl_redraw(pdt->hObjBar);

	widget_t hPanel = MainFrame_GetActivePanel(widget);
	if (!hPanel)
		return;

	QUERYOBJECT qo = { 0 };

	widget_send_command(hPanel, COMMAND_QUERYINFO, IDC_PARENT, (vword_t)&qo);

	tchar_t token[1024];

	if (compare_text(qo.szDoc, -1, DOC_FORM, -1, 0) == 0)
	{
		LINKPTR flk = get_next_field(qo.ptrDoc, LINK_FIRST);
		while (flk)
		{
			LINKPTR tlk = insert_tree_item(ptr_tree, LINK_LAST);

			xsprintf(token, _T("%s [%s]"), get_field_name_ptr(flk), get_field_class_ptr(flk));

			set_tree_item_name(tlk, get_field_name_ptr(flk));
			set_tree_item_title(tlk, token);
			set_tree_item_icon(tlk, GDI_ATTR_GIZMO_NOTE);

			flk = get_next_field(qo.ptrDoc, flk);
		}
	}
	else if (compare_text(qo.szDoc, -1, DOC_GRID, -1, 0) == 0)
	{
		LINKPTR clk = get_next_col(qo.ptrDoc, LINK_FIRST);
		while (clk)
		{
			LINKPTR tlk = insert_tree_item(ptr_tree, LINK_LAST);

			xsprintf(token, _T("%s [%s]"), get_col_title_ptr(clk), get_col_name_ptr(clk));

			set_tree_item_name(tlk, get_col_name_ptr(clk));
			set_tree_item_title(tlk, token);

			clk = get_next_col(qo.ptrDoc, clk);
		}
	}
	else if (compare_text(qo.szDoc, -1, DOC_STATIS, -1, 0) == 0)
	{
		LINKPTR ylk = get_next_yax(qo.ptrDoc, LINK_FIRST);
		while (ylk)
		{
			LINKPTR tlk = insert_tree_item(ptr_tree, LINK_LAST);

			xsprintf(token, _T("%s [%s]"), get_yax_title_ptr(ylk), get_yax_name_ptr(ylk));

			set_tree_item_name(tlk, get_yax_name_ptr(ylk));
			set_tree_item_title(tlk, token);

			ylk = get_next_yax(qo.ptrDoc, ylk);
		}
	}
	else if (compare_text(qo.szDoc, -1, DOC_RICH, -1, 0) == 0)
	{
		LINKPTR nlk = get_rich_next_anch(qo.ptrDoc, LINK_FIRST);
		while (nlk)
		{
			LINKPTR tlk = insert_tree_item(ptr_tree, LINK_LAST);

			xsprintf(token, _T("%s [%s]"), get_rich_anch_title_ptr(nlk), get_rich_anch_name_ptr(nlk));

			set_tree_item_name(tlk, get_rich_anch_name_ptr(nlk));
			set_tree_item_title(tlk, token);

			nlk = get_rich_next_anch(qo.ptrDoc, nlk);
		}
	}
	else if (compare_text(qo.szDoc, -1, DOC_TOPOG, -1, 0) == 0)
	{
		LINKPTR slk = get_topog_next_spot(qo.ptrDoc, LINK_FIRST);
		while (slk)
		{
			LINKPTR tlk = insert_tree_item(ptr_tree, LINK_LAST);

			xsprintf(token, _T("%s [%s]"), get_topog_spot_title_ptr(slk), get_topog_spot_name_ptr(slk));

			set_tree_item_name(tlk, get_topog_spot_name_ptr(slk));
			set_tree_item_title(tlk, token);

			slk = get_topog_next_spot(qo.ptrDoc, slk);
		}
	}
	else if (compare_text(qo.szDoc, -1, DOC_IMAGES, -1, 0) == 0)
	{
		LINKPTR ilk = get_images_next_item(qo.ptrDoc, LINK_FIRST);
		while (ilk)
		{
			LINKPTR tlk = insert_tree_item(ptr_tree, LINK_LAST);

			xsprintf(token, _T("%s"), get_images_item_alt_ptr(ilk));

			set_tree_item_name(tlk, get_images_item_alt_ptr(ilk));
			set_tree_item_title(tlk, token);

			ilk = get_images_next_item(qo.ptrDoc, ilk);
		}
	}
	else if (compare_text(qo.szDoc, -1, DOC_DIALOG, -1, 0) == 0)
	{
		LINKPTR ilk = get_dialog_next_item(qo.ptrDoc, LINK_FIRST);
		while (ilk)
		{
			LINKPTR tlk = insert_tree_item(ptr_tree, LINK_LAST);

			xsprintf(token, _T("%s [%s]"), get_dialog_item_name_ptr(ilk), get_dialog_item_id_ptr(ilk));

			set_tree_item_name(tlk, get_dialog_item_name_ptr(ilk));
			set_tree_item_title(tlk, token);

			ilk = get_dialog_next_item(qo.ptrDoc, ilk);
		}
	}
	else if (compare_text(qo.szDoc, -1, DOC_DIAGRAM, -1, 0) == 0)
	{
		LINKPTR ilk = get_diagram_next_entity(qo.ptrDoc, LINK_FIRST);
		while (ilk)
		{
			LINKPTR tlk = insert_tree_item(ptr_tree, LINK_LAST);

			xsprintf(token, _T("%s [%s]"), get_diagram_entity_name_ptr(ilk), get_diagram_entity_id_ptr(ilk));

			set_tree_item_name(tlk, get_diagram_entity_name_ptr(ilk));
			set_tree_item_title(tlk, token);

			ilk = get_diagram_next_entity(qo.ptrDoc, ilk);
		}
	}

	treectrl_redraw(pdt->hObjBar);
}

void MainFrame_CheckObject(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptr_tree = treectrl_fetch(pdt->hObjBar);

	LINKPTR tlk = treectrl_get_focus_item(pdt->hObjBar);
	if (!tlk)
		return;

	widget_t hPanel = MainFrame_GetActivePanel(widget);
	if (!hPanel)
		return;

	str_find_t fd = { 0 };
	fd.sub_str = get_tree_item_name_ptr(tlk);
	if (is_null(fd.sub_str))
		return;

	widget_send_command(hPanel, COMMAND_FIND, IDC_PARENT, (vword_t)&fd);
}

void MainFrame_SetDataSource(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if (!pdt->ptrProject)
		return;

	tchar_t szRDS[PATH_LEN + 1] = { 0 };

	Project_GetConfig(pdt->ptrProject, _T("RDS"), szRDS, PATH_LEN);

	LINKPTR ptr_str = create_string_table(0);

	if (is_null(szRDS))
	{
		write_string_entity(ptr_str, _T("SERVICE"), -1, NULL, 0);
		write_string_entity(ptr_str, _T("DATABASE"), -1, NULL, 0);
		write_string_entity(ptr_str, _T("SECRET-ID"), -1, NULL, 0);
		write_string_entity(ptr_str, _T("SECRET-KEY"), -1, NULL, 0);
	}
	else
	{
		string_table_parse_attrset(ptr_str, szRDS, -1);
	}

	LINKPTR elk = get_string_next_entity(ptr_str, LINK_FIRST);
	while (elk)
	{
		set_string_entity_dirty(elk, 1);
		elk = get_string_next_entity(ptr_str, elk);
	}

	widget_t hTableDlg = tabledlg_create(_T("设置数据服务"), ptr_str, widget);

	widget_show(hTableDlg, WS_SHOW_NORMAL);

	int nRet = (int)widget_do_modal(hTableDlg);
	if (!nRet)
	{
		destroy_string_table(ptr_str);
		return;
	}

	string_table_format_attrset(ptr_str, szRDS, PATH_LEN);

	destroy_string_table(ptr_str);

	Project_SetConfig(pdt->ptrProject, _T("RDS"), szRDS, -1);

	pdt->bDirty = TRUE;
}

void MainFrame_SetDocServer(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if (!pdt->ptrProject)
		return;

	tchar_t szSYN[PATH_LEN + 1] = { 0 };

	Project_GetConfig(pdt->ptrProject, _T("SYN"), szSYN, PATH_LEN);

	LINKPTR ptr_str = create_string_table(0);

	if (is_null(szSYN))
	{
		write_string_entity(ptr_str, _T("SERVICE"), -1, NULL, 0);
		write_string_entity(ptr_str, _T("SECRET-ID"), -1, NULL, 0);
		write_string_entity(ptr_str, _T("SECRET-KEY"), -1, NULL, 0);
	}
	else
	{
		string_table_parse_attrset(ptr_str, szSYN, -1);
	}

	LINKPTR elk = get_string_next_entity(ptr_str, LINK_FIRST);
	while (elk)
	{
		set_string_entity_dirty(elk, 1);
		elk = get_string_next_entity(ptr_str, elk);
	}

	widget_t hTableDlg = tabledlg_create(_T("设置文档服务"), ptr_str, widget);

	widget_show(hTableDlg, WS_SHOW_NORMAL);

	int nRet = (int)widget_do_modal(hTableDlg);
	if (!nRet)
	{
		destroy_string_table(ptr_str);
		return;
	}

	string_table_format_attrset(ptr_str, szSYN, PATH_LEN);

	destroy_string_table(ptr_str);

	Project_SetConfig(pdt->ptrProject, _T("SYN"), szSYN, -1);

	pdt->bDirty = TRUE;
}

void MainFrame_ChangeFace(widget_t widget, int ind)
{
	g_indFace = ind;

	color_mod_t clr;
	parse_xcolor(&clr.clr_bkg, g_face[g_indFace].bkg);
	parse_xcolor(&clr.clr_frg, g_face[g_indFace].frg);
	parse_xcolor(&clr.clr_txt, g_face[g_indFace].txt);
	parse_xcolor(&clr.clr_msk, g_face[g_indFace].msk);
	parse_xcolor(&clr.clr_ico, g_face[g_indFace].ico);

	widget_set_color_mode(widget, &clr);
}
/************************************************************************************/
void MainFrame_ToolBar_OnLBClick(widget_t widget, NOTICE_TOOL* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
	xrect_t xr = { 0 };
	xpoint_t pt = { 0 };

	if (!pnt->item)
		return;

	int code = xstol(get_tool_item_id_ptr(pnt->item));
	int cid = widget_get_user_id(widget);

	toolctrl_get_item_rect(pdt->hToolBar, pnt->item, &xr);
	pt.x = xr.x;
	pt.y = xr.y + xr.h;
	widget_client_to_screen(pdt->hToolBar, &pt);
	
	vword_t vv = MAKELWORD(pt.x, pt.y);

	widget_post_command(widget, code, cid, vv);
}

void MainFrame_ToolBar_OnItemHover(widget_t widget, NOTICE_TOOL* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xpoint_t xp,*ppt;
	ppt = (xpoint_t*)pnt->data;

	xp.x = ppt->x + 10;
	xp.y = ppt->y + 10;

	widget_client_to_screen(pnt->widget, &xp);

	if (widget_is_valid(pdt->hToolTip))
		reset_toolbox(pdt->hToolTip, &xp, get_tool_item_title_ptr(pnt->item));
	else
		pdt->hToolTip = show_toolbox(&xp, get_tool_item_title_ptr(pnt->item));
}

void MainFrame_TitleBar_OnItemInsert(widget_t widget, NOTICE_TITLE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
}

void MainFrame_TitleBar_OnItemDelete(widget_t widget, NOTICE_TITLE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_t hPanel = (widget_t)get_title_item_delta(pnt->item);

	if (!widget_is_valid(hPanel))
		return;

	widget_show(hPanel, WS_SHOW_HIDE);
	widget_close(hPanel, 0);

	if (widget_is_valid(hPanel))
	{
		pnt->ret = 1;
		return;
	}
}

void MainFrame_TitleBar_OnItemChanging(widget_t widget, NOTICE_TITLE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_t hPanel = (widget_t)get_title_item_delta(pnt->item);

	if (widget_is_valid(hPanel))
	{
		widget_show(hPanel, WS_SHOW_HIDE);

		LINKPTR ptr_obj = treectrl_fetch(pdt->hObjBar);
		clear_tree_doc(ptr_obj);
		treectrl_redraw(pdt->hObjBar);
	}
}

void MainFrame_TitleBar_OnItemChanged(widget_t widget, NOTICE_TITLE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_t hPanel = (widget_t)get_title_item_delta(pnt->item);

	if (widget_is_valid(hPanel))
	{
		color_mod_t clr;
		widget_get_color_mode(widget, &clr);

		widget_set_color_mode(hPanel, &clr);

		widget_show(hPanel, WS_SHOW_NORMAL);

		widget_post_command(widget, IDA_OBJECT_FRESH, 0, NULL);
	}
}

void MainFrame_TitleBar_OnItemHover(widget_t widget, NOTICE_TITLE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xpoint_t xp, *ppt;
	ppt = (xpoint_t*)pnt->data;

	xp.x = ppt->x + 10;
	xp.y = ppt->y + 10;

	widget_client_to_screen(pnt->widget, &xp);

	if (widget_is_valid(pdt->hToolTip))
		reset_toolbox(pdt->hToolTip, &xp, get_title_item_title_ptr(pnt->item));
	else
		pdt->hToolTip = show_toolbox(&xp, get_title_item_title_ptr(pnt->item));
}

void MainFrame_ResBar_OnLBClick(widget_t widget, NOTICE_TREE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_post_command(widget, IDA_FILE_SHOW, 0, NULL);
}

void MainFrame_ResBar_OnDBClick(widget_t widget, NOTICE_TREE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

}

void MainFrame_ResBar_OnRBClick(widget_t widget, NOTICE_TREE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xpoint_t* ppt = (xpoint_t*)pnt->data;

	xrect_t xr = { 0 };
	xpoint_t pt = { 0 };

	widget_t hMenu = menubox_create(widget, WD_STYLE_POPUP, &xr);
	widget_set_user_id(hMenu, IDC_MAINFRAME_MENUBOX);
	widget_set_owner(hMenu, widget);

	color_mod_t clr;
	widget_get_color_mode(widget, &clr);

	widget_set_color_mode(hMenu, &clr);

	LINKPTR ptrMenu = create_menu_doc();

	LINKPTR mlk = insert_menu_item(ptrMenu, LINK_LAST);
	set_menu_item_iid(mlk, IDA_FILE_APPEND);
	set_menu_item_title(mlk, _T("添加文件"));
	set_menu_item_icon(mlk, GDI_ATTR_GIZMO_PLUS);

	mlk = insert_menu_item(ptrMenu, LINK_LAST);
	set_menu_item_iid(mlk, IDA_FILE_REMOVE);
	set_menu_item_title(mlk, _T("移除文件"));
	set_menu_item_icon(mlk, GDI_ATTR_GIZMO_MINUS);

	mlk = insert_menu_item(ptrMenu, LINK_LAST);
	set_menu_item_iid(mlk, IDA_FILE_SHOW);
	set_menu_item_title(mlk, _T("显示文件"));

	mlk = insert_menu_item(ptrMenu, LINK_LAST);
	set_menu_item_iid(mlk, IDA_FILE_SYNC);
	set_menu_item_title(mlk, _T("发布文件"));

	if (pnt->item && get_tree_child_item_count(pnt->item))
	{
		mlk = insert_menu_item(ptrMenu, LINK_LAST);
		set_menu_item_iid(mlk, IDA_FILE_SORT);
		set_menu_item_title(mlk, _T("重新排序"));
	}

	menubox_set_data(hMenu, ptrMenu);

	pt.x = ppt->x;
	pt.y = ppt->y;
	widget_client_to_screen(pdt->hResBar, &pt);

	menubox_layout(hMenu, &pt, WS_LAYOUT_RIGHTBOTTOM);

	widget_do_track(hMenu);

	destroy_menu_doc(ptrMenu);
}

void MainFrame_ResBar_OnCommit(widget_t widget, NOTICE_TREE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR plk = get_tree_parent_item(pnt->item);
	if (!plk)
	{
		pnt->ret = 1;
		return;
	}
	else if (is_tree_doc(plk))
	{
		pnt->ret = 1;
		return;
	}

	const tchar_t* token = (const tchar_t*)pnt->data;

	if (compare_text(token, -1, get_tree_item_title_ptr(pnt->item), -1, 1) == 0)
	{
		pnt->ret = 1;
		return;
	}
	
	if (!MainFrame_RenameFile(widget, token))
	{
		pnt->ret = 1;
		return;
	}
}

void MainFrame_ObjBar_OnLBClick(widget_t widget, NOTICE_TREE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_post_command(widget, IDA_OBJECT_CHECK, 0, NULL);
}

void MainFrame_ObjBar_OnDBClick(widget_t widget, NOTICE_TREE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

}

void MainFrame_ObjBar_OnRBClick(widget_t widget, NOTICE_TREE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xpoint_t* ppt = (xpoint_t*)pnt->data;

	xrect_t xr = { 0 };
	xpoint_t pt = { 0 };

	widget_t hMenu = menubox_create(widget, WD_STYLE_POPUP, &xr);
	widget_set_user_id(hMenu, IDC_MAINFRAME_MENUBOX);
	widget_set_owner(hMenu, widget);

	color_mod_t clr;
	widget_get_color_mode(widget, &clr);

	widget_set_color_mode(hMenu, &clr);

	LINKPTR ptrMenu = create_menu_doc();

	LINKPTR mlk;

	mlk = insert_menu_item(ptrMenu, LINK_LAST);
	set_menu_item_iid(mlk, IDA_OBJECT_FRESH);
	set_menu_item_title(mlk, _T("刷新对象"));
	set_menu_item_icon(mlk, GDI_ATTR_GIZMO_FRESH);

	mlk = insert_menu_item(ptrMenu, LINK_LAST);
	set_menu_item_iid(mlk, IDA_OBJECT_CHECK);
	set_menu_item_title(mlk, _T("选中对象"));
	set_menu_item_icon(mlk, GDI_ATTR_GIZMO_CHECK);

	menubox_set_data(hMenu, ptrMenu);

	pt.x = ppt->x;
	pt.y = ppt->y;
	widget_client_to_screen(pdt->hObjBar, &pt);

	menubox_layout(hMenu, &pt, WS_LAYOUT_RIGHTBOTTOM);

	widget_do_track(hMenu);

	destroy_menu_doc(ptrMenu);
}


/**************************************************************************************************/
void _MainFrame_CalcToolBar(widget_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
	
	widget_get_dock_rect(widget, WS_DOCK_TOP, pxr);
}

void _MainFrame_CalcStatusBar(widget_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_get_dock_rect(widget, WS_DOCK_BOTTOM, pxr);
}

void _MainFrame_CalcResBar(widget_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
	xsize_t xs;

	xs.fw = 0;
	xs.fh = MAINFRAME_CATEBAR_HEIGHT;
	widget_size_to_pt(widget, &xs);

	widget_get_dock_rect(widget, WS_DOCK_LEFT, pxr);
	pxr->h -= xs.h;
}

void _MainFrame_CalcObjBar(widget_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
	xsize_t xs;

	xs.fw = 0;
	xs.fh = MAINFRAME_CATEBAR_HEIGHT;
	widget_size_to_pt(widget, &xs);

	widget_get_dock_rect(widget, WS_DOCK_LEFT, pxr);
	pxr->h -= xs.h;
}

void _MainFrame_CalcCateBar(widget_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
	xsize_t xs;

	xs.fw = 0;
	xs.fh = MAINFRAME_CATEBAR_HEIGHT;
	widget_size_to_pt(widget, &xs);

	widget_get_dock_rect(widget, WS_DOCK_LEFT, pxr);
	pxr->y = pxr->y + pxr->h - xs.h;
	pxr->h = xs.h;
}

void _MainFrame_CalcTitleBar(widget_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
	xsize_t xs;

	xs.fw = 0;
	xs.fh = MAINFRAME_TITLEBAR_HEIGHT;
	widget_size_to_pt(widget, &xs);

	widget_get_dock_rect(widget, 0, pxr);
	pxr->h = xs.h;
}

void _MainFrame_CalcPanelBar(widget_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
	xsize_t xs;

	xs.fw = 0;
	xs.fh = MAINFRAME_TITLEBAR_HEIGHT;
	widget_size_to_pt(widget, &xs);

	widget_get_dock_rect(widget, 0, pxr);
	pxr->y += xs.h;
	pxr->h -= xs.h;
}

void _MainFrame_CreateToolBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr = { 0 };

	_MainFrame_CalcToolBar(widget, &xr);

	pdt->hToolBar = toolctrl_create(_T("ToolBar"), WD_STYLE_CONTROL | WD_STYLE_HOTOVER, &xr, widget);
	widget_set_user_id(pdt->hToolBar, IDC_MAINFRAME_TOOLBAR);
	widget_set_owner(pdt->hToolBar, widget);

	LINKPTR ptrTool = create_tool_doc();

	LINKPTR glk = insert_tool_group(ptrTool, LINK_LAST);
	set_tool_group_name(glk, MAINFRAME_TOOLGROUP_PROJECT);
	set_tool_group_title(glk, _T("工程"));
	set_tool_group_item_width(glk, MAINFRAME_GROUPITEM_MAXWIDTH);
	set_tool_group_item_height(glk, MAINFRAME_GROUPITEM_HEIGHT);

	tchar_t token[NUM_LEN + 1] = { 0 };

	LINKPTR ilk = insert_tool_group_item(glk, LINK_LAST);
	set_tool_group_show(glk, ATTR_SHOW_TEXTONLY);
	xsprintf(token, _T("%d"), IDA_PROJECT_CREATE);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("新建工程"));

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PROJECT_OPEN);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("打开工程"));

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PROJECT_SAVE);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("保存工程"));

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PROJECT_CLOSE);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("关闭工程"));

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_CONFIG_RDS);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("数据服务"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_IMPORT);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_CONFIG_DOC);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("文档服务"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_IMPORT);

	glk = insert_tool_group(ptrTool, LINK_LAST);
	set_tool_group_show(glk, ATTR_SHOW_IMAGEONLY);
	set_tool_group_name(glk, MAINFRAME_TOOLGROUP_FILE);
	set_tool_group_title(glk, _T("文件"));
	set_tool_group_item_width(glk, MAINFRAME_GROUPITEM_MINWIDTH);
	set_tool_group_item_height(glk, MAINFRAME_GROUPITEM_HEIGHT);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_FILE_CREATE);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("新建文件"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_NEW);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_FILE_OPEN);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("打开文件"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_OPEN);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_FILE_SAVE);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("保存文件"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SAVE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_FILE_SAVEAS);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("另存文件"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SAVEAS);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_FILE_SCHEMA);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("导出模式"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SCHEMA);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_FILE_EXPORT);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("导出数据"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_OUTPUT);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_FILE_IMPORT);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("导入数据"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_INPUT);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_FILE_PRINT);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("打印文件"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_PRINT);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_FILE_PREVIEW);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("预览文件"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SCREEN);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_FILE_EXEC);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("测试运行"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_NEXT);

	toolctrl_attach(pdt->hToolBar, ptrTool);
	widget_show(pdt->hToolBar, WS_SHOW_NORMAL);
}

void _MainFrame_CreateTitleBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr = { 0 };

	_MainFrame_CalcTitleBar(widget, &xr);
	
	pdt->hTitleBar = titlectrl_create(_T("TitleBar"), WD_STYLE_CONTROL | WD_STYLE_HOTOVER, &xr, widget);
	widget_set_user_id(pdt->hTitleBar, IDC_MAINFRAME_TITLEBAR);
	widget_set_owner(pdt->hTitleBar, widget);

	LINKPTR ptrTitle = create_title_doc();

	set_title_oritation(ptrTitle, ATTR_ORITATION_BOTTOM);

	titlectrl_attach(pdt->hTitleBar, ptrTitle);

	widget_show(pdt->hTitleBar, WS_SHOW_NORMAL);
}

void _MainFrame_CreateResBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr = { 0 };

	_MainFrame_CalcResBar(widget, &xr);

	pdt->hResBar = treectrl_create(_T("ResBar"), WD_STYLE_CONTROL, &xr, widget);
	widget_set_user_id(pdt->hResBar, IDC_MAINFRAME_RESBAR);
	widget_set_owner(pdt->hResBar, widget);

	LINKPTR ptrTree = create_tree_doc();

	set_tree_title(ptrTree, _T("资源列表"));
	set_tree_title_icon(ptrTree, GDI_ATTR_GIZMO_PROPER);
	treectrl_attach(pdt->hResBar, ptrTree);
	treectrl_set_lock(pdt->hResBar, 0);

	//widget_show(pdt->hResBar, WS_SHOW_NORMAL);
}

void _MainFrame_CreateObjBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr = { 0 };

	_MainFrame_CalcObjBar(widget, &xr);

	pdt->hObjBar = treectrl_create(_T("ObjBar"), WD_STYLE_CONTROL, &xr, widget);
	widget_set_user_id(pdt->hObjBar, IDC_MAINFRAME_OBJBAR);
	widget_set_owner(pdt->hObjBar, widget);

	LINKPTR ptrTree = create_tree_doc();

	treectrl_attach(pdt->hObjBar, ptrTree);
	treectrl_set_lock(pdt->hObjBar, 1);

	//widget_show(pdt->hObjBar, WS_SHOW_NORMAL);
}

void _MainFrame_CreateCateBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr = { 0 };

	_MainFrame_CalcCateBar(widget, &xr);

	pdt->hCateBar = titlectrl_create(_T("CateBar"), WD_STYLE_CONTROL, &xr, widget);
	widget_set_user_id(pdt->hCateBar, IDC_MAINFRAME_CATEBAR);
	widget_set_owner(pdt->hCateBar, widget);

	LINKPTR ptrTitle = create_title_doc();

	set_title_oritation(ptrTitle, ATTR_ORITATION_TOP);
	set_title_item_width(ptrTitle, MAINFRAME_TITLEITEM_WIDTH);

	LINKPTR tlk = insert_title_item(ptrTitle, LINK_LAST);
	set_title_item_title(tlk, _T("文件"));
	set_title_item_name(tlk, MAINFRAME_TREE_RESOURCE);
	set_title_item_locked(tlk, 1);
	set_title_item_icon(tlk, GDI_ATTR_GIZMO_NEW);

	tlk = insert_title_item(ptrTitle, LINK_LAST);
	set_title_item_title(tlk, _T("对象"));
	set_title_item_name(tlk, MAINFRAME_TREE_OBJECT);
	set_title_item_locked(tlk, 1);
	set_title_item_icon(tlk, GDI_ATTR_GIZMO_LIST);

	titlectrl_attach(pdt->hCateBar, ptrTitle);

	titlectrl_set_focus_item(pdt->hCateBar, get_title_next_item(ptrTitle, LINK_FIRST));

	widget_show(pdt->hCateBar, WS_SHOW_NORMAL);
}

void _MainFrame_CreateStatusBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr = { 0 };

	_MainFrame_CalcStatusBar(widget, &xr);

	pdt->hStatusBar = statusctrl_create(_T("StatusBar"), WD_STYLE_CONTROL, &xr, widget);
	widget_set_user_id(pdt->hStatusBar, IDC_MAINFRAME_STATUSBAR);
	widget_set_owner(pdt->hStatusBar, widget);

	LINKPTR ptrStatus = create_status_doc();

	set_status_alignment(ptrStatus, ATTR_ALIGNMENT_FAR);

	LINKPTR ilk;

	ilk = insert_status_item(ptrStatus, LINK_LAST);
	set_status_item_name(ilk, _T("navibox"));
	set_status_item_title(ilk, _T("导航栏"));
	set_status_item_width(ilk, DEF_TOUCH_SPAN * 6 + 1);

	statusctrl_attach(pdt->hStatusBar, ptrStatus);

	widget_show(pdt->hStatusBar, WS_SHOW_NORMAL);

	ilk = get_status_item(ptrStatus, _T("navibox"));
	statusctrl_get_item_rect(pdt->hStatusBar, ilk, &xr);
	
	pdt->hNaviBox = navibox_create(pdt->hStatusBar, WD_STYLE_CONTROL, &xr);
	widget_set_owner(pdt->hNaviBox, pdt->hStatusBar);
	widget_show(pdt->hNaviBox, WS_SHOW_NORMAL);
}

widget_t _MainFrame_CreatePanel(widget_t widget, const tchar_t* wclass, const tchar_t* fpath)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_t hPanel = NULL;
	xrect_t xr = { 0 };

	link_t_ptr ptr_title, ilk;

	_MainFrame_CalcPanelBar(widget, &xr);

	tchar_t wname[RES_LEN + 1] = { 0 };

	split_path(fpath, NULL, wname, NULL);

	if (compare_text(wclass, -1, PANEL_CLASS_FORM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewForm"));

		hPanel = FormPanel_Create(wname, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_FORMPANEL);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_GRID, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewGrid"));

		hPanel = GridPanel_Create(wname, WD_STYLE_CONTROL, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_GRIDPANEL);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_STATIS, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewStatis"));

		hPanel = StatisPanel_Create(wname, WD_STYLE_CONTROL, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_STATISPANEL);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_RICH, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewRich"));

		hPanel = RichPanel_Create(wname, WD_STYLE_CONTROL, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_RICHPANEL);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_SCHEMA, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewSchema"));

		hPanel = SchemaPanel_Create(wname, WD_STYLE_CONTROL, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_SCHEMAPANEL);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_TOPOG, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewTopog"));

		hPanel = TopogPanel_Create(wname, WD_STYLE_CONTROL, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_TOPOGPANEL);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_IMAGE, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewImages"));

		hPanel = ImagePanel_Create(wname, WD_STYLE_CONTROL, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_IMAGESPANEL);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_DIALOG, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewDialog"));

		hPanel = DialogPanel_Create(wname, WD_STYLE_CONTROL, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_DIALOGPANEL);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewPlot"));

		hPanel = PlotPanel_Create(wname, WD_STYLE_CONTROL, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_SQL, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewSQL"));

		hPanel = SQLPanel_Create(wname, WD_STYLE_CONTROL, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_SQLPANEL);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_XML, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewXML"));

		hPanel = XMLPanel_Create(wname, WD_STYLE_CONTROL, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_XMLPANEL);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_JSON, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewJson"));

		hPanel = JsonPanel_Create(wname, WD_STYLE_CONTROL, &xr, fpath);
		if (hPanel)
			widget_set_user_id(hPanel, IDC_MAINFRAME_JSONPANEL);
	}

	if (!hPanel)
		return NULL;

	widget_set_owner(hPanel, widget);

	ptr_title = titlectrl_fetch(pdt->hTitleBar);
	XDK_ASSERT(ptr_title != NULL);

	ilk = insert_title_item(ptr_title, LINK_LAST);

	set_title_item_name(ilk, wclass);
	set_title_item_title(ilk, wname);
	set_title_item_delta(ilk, (vword_t)hPanel);

	titlectrl_redraw(pdt->hTitleBar);
	titlectrl_set_focus_item(pdt->hTitleBar, ilk);

	widget_layout(hPanel);

	return hPanel;
}

bool_t _MainFrame_FindPanel(widget_t widget, const tchar_t* wclass, const tchar_t* fpath)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	tchar_t wname[RES_LEN + 1] = { 0 };

	split_path(fpath, NULL, wname, NULL);

	LINKPTR ptrTitle = titlectrl_fetch(pdt->hTitleBar);

	LINKPTR ilk = get_title_next_item(ptrTitle, LINK_FIRST);
	while (ilk)
	{
		if (compare_text(wclass, -1, get_title_item_name_ptr(ilk),-1,0) == 0 && compare_text(wname, -1, get_title_item_title_ptr(ilk), -1, 1) == 0)
		{
			titlectrl_set_focus_item(pdt->hTitleBar, ilk);
			return 1;
		}

		ilk = get_title_next_item(ptrTitle, ilk);
	}

	return 0;
}

void _MainFrame_RenamePanel(widget_t widget, const tchar_t* wclass, const tchar_t* wname, const tchar_t* nname)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrTitle = titlectrl_fetch(pdt->hTitleBar);

	LINKPTR ilk = get_title_next_item(ptrTitle, LINK_FIRST);
	while (ilk)
	{
		if (compare_text(wclass, -1, get_title_item_name_ptr(ilk), -1, 0) == 0 && compare_text(wname, -1, get_title_item_title_ptr(ilk), -1, 1) == 0)
		{
			set_title_item_title(ilk, nname);
			titlectrl_redraw_item(pdt->hTitleBar, ilk);

			widget_t hPanel = (widget_t)get_title_item_delta(ilk);
			if (widget_is_valid(hPanel))
			{
				widget_send_command(hPanel, COMMAND_RENAME, IDC_PARENT, (vword_t)nname);
			}
			return;
		}

		ilk = get_title_next_item(ptrTitle, ilk);
	}
}

void _MainFrame_DestroyToolBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrTool = toolctrl_detach(pdt->hToolBar);
	if (ptrTool)
		destroy_tool_doc(ptrTool);
	widget_destroy(pdt->hToolBar);
}

void _MainFrame_DestroyTitleBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrTitle = titlectrl_detach(pdt->hTitleBar);
	if (ptrTitle)
		destroy_title_doc(ptrTitle);
	widget_destroy(pdt->hTitleBar);
}

void _MainFrame_DestroyResBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrTree = treectrl_detach(pdt->hResBar);
	if (ptrTree)
		destroy_tree_doc(ptrTree);
	widget_destroy(pdt->hResBar);
}

void _MainFrame_DestroyObjBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrTree = treectrl_detach(pdt->hObjBar);
	if (ptrTree)
		destroy_tree_doc(ptrTree);
	widget_destroy(pdt->hObjBar);
}

void _MainFrame_DestroyCateBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrCate = titlectrl_detach(pdt->hCateBar);
	if (ptrCate)
		destroy_title_doc(ptrCate);
	widget_destroy(pdt->hCateBar);
}

void _MainFrame_DestroyStatusBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrStatus = statusctrl_detach(pdt->hStatusBar);
	if (ptrStatus)
		destroy_status_doc(ptrStatus);
	widget_destroy(pdt->hStatusBar);
}


/**********************************************************************************************/
int MainFrame_OnCreate(widget_t widget, void* data)
{
	MainFrameDelta* pdt;

	widget_hand_create(widget);

	widget_set_accel(widget, MAINFRAME_ACCEL, MAINFRAME_ACCEL_COUNT);

	xsize_t xs;

	xs.fw = 0;
	xs.fh = MAINFRAME_TOOLBAR_HEIGHT;
	widget_size_to_pt(widget, &xs);
	widget_dock(widget, WS_DOCK_TOP, 0, xs.h);

	xs.fw = 0;
	xs.fh = MAINFRAME_STATUSBAR_HEIGHT;
	widget_size_to_pt(widget, &xs);
	widget_dock(widget, WS_DOCK_BOTTOM, 0, xs.h);

	xs.fw = MAINFRAME_TREEBAR_WIDTH;
	xs.fh = 0;
	widget_size_to_pt(widget, &xs);
	widget_dock(widget, WS_DOCK_LEFT | WS_DOCK_DYNA, xs.w, 0);

	pdt = (MainFrameDelta*)xmem_alloc(sizeof(MainFrameDelta));
	SETMAINFRAMEDELTA(widget, (vword_t)pdt);

	_MainFrame_CreateToolBar(widget);

	_MainFrame_CreateTitleBar(widget);

	_MainFrame_CreateStatusBar(widget);

	_MainFrame_CreateResBar(widget);

	_MainFrame_CreateObjBar(widget);

	_MainFrame_CreateCateBar(widget);

	return 0;
}

void MainFrame_OnDestroy(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	_MainFrame_DestroyToolBar(widget);

	_MainFrame_DestroyTitleBar(widget);

	_MainFrame_DestroyResBar(widget);

	_MainFrame_DestroyObjBar(widget);

	_MainFrame_DestroyCateBar(widget);

	_MainFrame_DestroyStatusBar(widget);

	if (widget_is_valid(pdt->hToolTip))
		widget_destroy(pdt->hToolTip);

	if (widget_is_valid(pdt->hKeyBox))
		widget_destroy(pdt->hKeyBox);

	xmem_free(pdt);

	widget_hand_destroy(widget);
}

int MainFrame_OnClose(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrTitle = titlectrl_fetch(pdt->hTitleBar);
	LINKPTR plk;

	while (plk = titlectrl_get_focus_item(pdt->hTitleBar))
	{
		if (!titlectrl_delete_item(pdt->hTitleBar, plk))
			break;
	}

	if (get_title_item_count(ptrTitle))
		return 1;

	MainFrame_Switch(widget);

	if (pdt->bDirty)
		return 1;

	MainFrame_CloseProject(widget);

	return 0;
}

void MainFrame_OnMenuCommand(widget_t widget, int code, int cid, vword_t data)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_t hPanel = MainFrame_GetActivePanel(widget);
	if (hPanel)
	{
		if (widget_send_command(hPanel, code, cid, data))
			return;
	}

	switch (code)
	{
	case IDA_PROJECT_OPEN:
		MainFrame_OpenProject(widget);
		break;
	case IDA_PROJECT_CREATE:
		MainFrame_CreateProject(widget);
		break;
	case IDA_PROJECT_SAVE:
		MainFrame_SaveProject(widget);
		break;
	case IDA_PROJECT_CLOSE:
		MainFrame_CloseProject(widget);
		break;
	case IDA_FILE_APPEND:
		MainFrame_AppendFile(widget);
		break;
	case IDA_FILE_REMOVE:
		MainFrame_RemoveFile(widget);
		break;
	case IDA_FILE_SHOW:
		MainFrame_ShowFile(widget);
		break;
	case IDA_FILE_OPEN:
		MainFrame_OpenFile(widget);
		break;
	case IDA_FILE_CREATE:
		MainFrame_CreateFile(widget);
		break;
	case IDA_FILE_SYNC:
		MainFrame_SyncFile(widget);
		break;
	case IDA_FILE_SORT:
		MainFrame_SortFile(widget);
		break;
	case IDA_OBJECT_FRESH:
		MainFrame_FreshObject(widget);
		break;
	case IDA_OBJECT_CHECK:
		MainFrame_CheckObject(widget);
		break;

	case IDA_CONFIG_RDS:
		MainFrame_SetDataSource(widget);
		break;
	case IDA_CONFIG_DOC:
		MainFrame_SetDocServer(widget);
		break;

	case IDC_MAINFRAME_MENUBOX:
		widget_destroy((widget_t)data);

		if (code)
		{
			widget_post_command(widget, code, 0, NULL);
		}
		break;

	case IDC_MAINFRAME_FACEMENU:
		widget_destroy((widget_t)data);

		if (code)
		{
			MainFrame_ChangeFace(widget, code - 1);
		}
		break;
	}
}

void MainFrame_OnSysColor(widget_t widget, const xpoint_t* ppt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr = { 0 };

	widget_t hMenu = menubox_create(widget, WD_STYLE_POPUP, &xr);
	widget_set_user_id(hMenu, IDC_MAINFRAME_FACEMENU);
	widget_set_owner(hMenu, widget);

	color_mod_t clr;
	widget_get_color_mode(widget, &clr);

	widget_set_color_mode(hMenu, &clr);

	LINKPTR ptrMenu = create_menu_doc();

	for (int i = 0; i < FACE_COUNT; i++)
	{
		LINKPTR mlk = insert_menu_item(ptrMenu, LINK_LAST);
		set_menu_item_iid(mlk, i + 1);
		set_menu_item_title(mlk, g_face[i].title);
		if (i == g_indFace)
			set_menu_item_checked(mlk, 1);
	}

	menubox_set_data(hMenu, ptrMenu);

	xpoint_t xp;
	xp.x = 0;
	xp.y = 0;

	widget_client_to_screen(widget, &xp);

	menubox_layout(hMenu, &xp, WS_LAYOUT_RIGHTBOTTOM);

	widget_do_track(hMenu);

	destroy_menu_doc(ptrMenu);
}

void MainFrame_OnNotice(widget_t widget, LPNOTICE phdr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if (phdr->user == IDC_MAINFRAME_TOOLBAR)
	{
		NOTICE_TOOL* pnt = (NOTICE_TOOL*)phdr;
		switch (pnt->code)
		{
		case NC_TOOLLBCLK:
			MainFrame_ToolBar_OnLBClick(widget, pnt);
			break;
		case NC_TOOLITEMHOVER:
			MainFrame_ToolBar_OnItemHover(widget, pnt);
			break;
		}
	}
	else if (phdr->user == IDC_MAINFRAME_TITLEBAR)
	{
		NOTICE_TITLE* pnt = (NOTICE_TITLE*)phdr;
		switch (pnt->code)
		{
		case NC_TITLEITEMCHANGING:
			MainFrame_TitleBar_OnItemChanging(widget, pnt);
			break;
		case NC_TITLEITEMCHANGED:
			MainFrame_TitleBar_OnItemChanged(widget, pnt);
			break;
		case NC_TITLEITEMINSERT:
			MainFrame_TitleBar_OnItemInsert(widget, pnt);
			break;
		case NC_TITLEITEMDELETE:
			MainFrame_TitleBar_OnItemDelete(widget, pnt);
			break;
		case NC_TITLEITEMHOVER:
			MainFrame_TitleBar_OnItemHover(widget, pnt);
			break;
		}
	}
	else if (phdr->user == IDC_MAINFRAME_RESBAR)
	{
		NOTICE_TREE* pnt = (NOTICE_TREE*)phdr;
		switch (pnt->code)
		{
		case NC_TREELBCLK:
			MainFrame_ResBar_OnLBClick(widget, pnt);
			break;
		case NC_TREEDBCLK:
			MainFrame_ResBar_OnDBClick(widget, pnt);
			break;
		case NC_TREERBCLK:
			MainFrame_ResBar_OnRBClick(widget, pnt);
			break;
		case NC_TREEITEMEDITING:
			if (!get_tree_parent_item(pnt->item))
			{
				pnt->ret = 1;
			}
			else if (is_tree_doc(get_tree_parent_item(pnt->item)))
			{
				pnt->ret = 1;
			}
			break;
		case NC_TREEITEMCOMMIT:
			MainFrame_ResBar_OnCommit(widget, pnt);
			break;
		case NC_TREEITEMUPDATE:
			pdt->bDirty = 1;
			break;
		}
	}
	else if (phdr->user == IDC_MAINFRAME_OBJBAR)
	{
		NOTICE_TREE* pnt = (NOTICE_TREE*)phdr;
		switch (pnt->code)
		{
		case NC_TREELBCLK:
			MainFrame_ObjBar_OnLBClick(widget, pnt);
			break;
		case NC_TREEDBCLK:
			MainFrame_ObjBar_OnDBClick(widget, pnt);
			break;
		case NC_TREERBCLK:
			MainFrame_ObjBar_OnRBClick(widget, pnt);
			break;
		}
	}
	else if (phdr->user == IDC_MAINFRAME_CATEBAR)
	{
		NOTICE_TITLE* pnt = (NOTICE_TITLE*)phdr;
		switch (pnt->code)
		{
		case NC_TITLEITEMCHANGING:
			if (compare_text(get_title_item_name_ptr(pnt->item), -1, MAINFRAME_TREE_RESOURCE, -1, 0) == 0)
			{
				widget_show(pdt->hResBar, WS_SHOW_HIDE);
			}
			else if (compare_text(get_title_item_name_ptr(pnt->item), -1, MAINFRAME_TREE_OBJECT, -1, 0) == 0)
			{
				widget_show(pdt->hObjBar, WS_SHOW_HIDE);
			}
			break;
		case NC_TITLEITEMCHANGED:
			if(compare_text(get_title_item_name_ptr(pnt->item),-1,MAINFRAME_TREE_RESOURCE,-1,0) == 0)
			{
				widget_show(pdt->hResBar, WS_SHOW_NORMAL);
			}
			else if (compare_text(get_title_item_name_ptr(pnt->item), -1, MAINFRAME_TREE_OBJECT, -1, 0) == 0)
			{
				widget_show(pdt->hObjBar, WS_SHOW_NORMAL);
				widget_post_command(widget, IDA_OBJECT_FRESH, 0, NULL);
			}
			break;
		}
	}
	else if (phdr->user == IDC_MAINFRAME_STATUSBAR)
	{
		NOTICE_STATUS* pnt = (NOTICE_STATUS*)phdr;
		switch (pnt->code)
		{
		case NC_STATUSLBCLK:
			break;
		}
	}
}

void MainFrame_OnSize(widget_t widget, int code, const xsize_t* pxs)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr;

	_MainFrame_CalcToolBar(widget, &xr);
	widget_move(pdt->hToolBar, RECTPOINT(&xr));
	widget_size(pdt->hToolBar, RECTSIZE(&xr));

	_MainFrame_CalcStatusBar(widget, &xr);
	widget_move(pdt->hStatusBar, RECTPOINT(&xr));
	widget_size(pdt->hStatusBar, RECTSIZE(&xr));

	_MainFrame_CalcResBar(widget, &xr);
	widget_move(pdt->hResBar, RECTPOINT(&xr));
	widget_size(pdt->hResBar, RECTSIZE(&xr));

	_MainFrame_CalcObjBar(widget, &xr);
	widget_move(pdt->hObjBar, RECTPOINT(&xr));
	widget_size(pdt->hObjBar, RECTSIZE(&xr));

	_MainFrame_CalcCateBar(widget, &xr);
	widget_move(pdt->hCateBar, RECTPOINT(&xr));
	widget_size(pdt->hCateBar, RECTSIZE(&xr));

	_MainFrame_CalcTitleBar(widget, &xr);
	widget_move(pdt->hTitleBar, RECTPOINT(&xr));
	widget_size(pdt->hTitleBar, RECTSIZE(&xr));

	_MainFrame_CalcPanelBar(widget, &xr);

	LINKPTR ptrTitle = titlectrl_fetch(pdt->hTitleBar);
	LINKPTR plk = get_title_next_item(ptrTitle, LINK_FIRST);
	while (plk)
	{
		widget_t hPanel = (widget_t)get_title_item_delta(plk);

		if (widget_is_valid(hPanel))
		{
			widget_move(hPanel, RECTPOINT(&xr));
			widget_size(hPanel, RECTSIZE(&xr));
		}

		plk = get_title_next_item(ptrTitle, plk);
	}

	widget_erase(widget, NULL);
}

void MainFrame_OnMove(widget_t widget, const xpoint_t* ppt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr;

	_MainFrame_CalcToolBar(widget, &xr);
	widget_move(pdt->hToolBar, RECTPOINT(&xr));

	_MainFrame_CalcStatusBar(widget, &xr);
	widget_move(pdt->hStatusBar, RECTPOINT(&xr));

	_MainFrame_CalcResBar(widget, &xr);
	widget_move(pdt->hResBar, RECTPOINT(&xr));

	_MainFrame_CalcObjBar(widget, &xr);
	widget_move(pdt->hObjBar, RECTPOINT(&xr));

	_MainFrame_CalcCateBar(widget, &xr);
	widget_move(pdt->hCateBar, RECTPOINT(&xr));
	
	_MainFrame_CalcTitleBar(widget, &xr);
	widget_move(pdt->hTitleBar, RECTPOINT(&xr));

	_MainFrame_CalcPanelBar(widget, &xr);

	LINKPTR ptrTitle = titlectrl_fetch(pdt->hTitleBar);
	LINKPTR plk = get_title_next_item(ptrTitle, LINK_FIRST);
	while (plk)
	{
		widget_t hPanel = (widget_t)get_title_item_delta(plk);

		if (widget_is_valid(hPanel))
		{
			widget_move(hPanel, RECTPOINT(&xr));
		}

		plk = get_title_next_item(ptrTitle, plk);
	}
}

/***********************************************************************************************/
widget_t MainFrame_Create(const tchar_t* mname)
{
	widget_t widget;
	xrect_t xr = { 0 };

	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(MainFrame_OnCreate)
		EVENT_ON_DESTROY(MainFrame_OnDestroy)
		EVENT_ON_CLOSE(MainFrame_OnClose)

		EVENT_ON_SIZE(MainFrame_OnSize)
		EVENT_ON_MOVE(MainFrame_OnMove)

		EVENT_ON_NOTICE(MainFrame_OnNotice)
		EVENT_ON_SYSCMD_CLICK(MainFrame_OnSysColor)

		EVENT_ON_MENU_COMMAND(MainFrame_OnMenuCommand)

		
		EVENT_ON_DOCKER_IMPLEMENT

	SUBPROC_END_DISPATH

	get_desktop_size(RECTSIZE(&xr));

	widget = widget_create(_T("xDesign"), WD_STYLE_FRAME | WD_STYLE_DOCKER | WD_STYLE_OWNERNC, &xr, NULL, &ev);

	if (!widget)
	{
		return 0;
	}

	color_mod_t clr;
	parse_xcolor(&clr.clr_bkg, g_face[g_indFace].bkg);
	parse_xcolor(&clr.clr_frg, g_face[g_indFace].frg);
	parse_xcolor(&clr.clr_txt, g_face[g_indFace].txt);
	parse_xcolor(&clr.clr_msk, g_face[g_indFace].msk);
	parse_xcolor(&clr.clr_ico, g_face[g_indFace].ico);

	//widget_set_color_mode(widget, &clr);

	widget_show(widget, WS_SHOW_MAXIMIZE);

	return widget;
}

widget_t MainFrame_GetActivePanel(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	XDK_ASSERT(pdt != NULL);

	LINKPTR nlk = titlectrl_get_focus_item(pdt->hTitleBar);
	if (!nlk)
		return NULL;

	return (widget_t)get_title_item_delta(nlk);
}

void MainFrame_UpdatePanel(widget_t widget, widget_t hPanel, const tchar_t* sz_title)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	XDK_ASSERT(pdt != NULL);

	LINKPTR ptrTitle = titlectrl_fetch(pdt->hTitleBar);
	LINKPTR plk = get_title_next_item(ptrTitle, LINK_FIRST);
	while (plk)
	{
		if ((widget_t)get_title_item_delta(plk) == hPanel)
		{
			set_title_title(plk, sz_title);
			titlectrl_redraw_item(pdt->hTitleBar, plk);
			break;
		}

		plk = get_title_next_item(ptrTitle, plk);
	}
}

LINKPTR MainFrame_GetProject(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	return pdt->ptrProject;
}