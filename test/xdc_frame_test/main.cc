#include <xdl.h>
#include <xdc.h>

res_win_t g_main = NULL;

res_win_t MainFrame_Create(const tchar_t* mname);

#ifdef _OS_WINDOWS
int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
#else
int main(int argc, const char * argv[])
#endif
{

	xdk_process_init(XDK_APARTMENT_PROCESS);

	xdc_process_init();

	g_main = MainFrame_Create(_T("Main"));

	msg_t msg;

	do{
		while (message_peek(&msg))
		{
			message_fetch(&msg, NULL);

			if (!message_translate(&msg))
			{
				message_dispatch(&msg);
			}
		}
	} while (widget_is_valid(g_main));

	xdc_process_uninit();

	xdk_process_uninit();

	return 0;
}

#define MAINFRAME_TOOLBAR_HEIGHT	(float)25
#define MAINFRAME_TREEBAR_WIDTH		(float)50
#define MAINFRAME_TITLEBAR_HEIGHT	(float)8
#define MAINFRAME_STATUSBAR_HEIGHT	(float)8

#define IDC_MAINFRAME				2999
#define IDC_MAINFRAME_TOOLBAR		3000
#define IDC_MAINFRAME_TITLEBAR		3001
#define IDC_MAINFRAME_STATUSBAR		3002
#define IDC_MAINFRAME_TREEBAR		3003
#define IDC_MAINFRAME_OWNERPANEL	3004
#define IDC_MAINFRAME_CALENDARPANEL	3005
#define IDC_MAINFRAME_NOTESPANEL	3006
#define IDC_MAINFRAME_PANELPANEL	3007
#define IDC_MAINFRAME_CURVEPANEL	3008
#define IDC_MAINFRAME_MODELPANEL	3009
#define IDC_MAINFRAME_PLOTPANEL		3010

#define IDA_OWNER			2002
#define IDA_CALENDAR		2003
#define IDA_NOTES			2004
#define IDA_PANEL			2005
#define IDA_CURVE			2006
#define IDA_MODEL			2007
#define IDA_PLOT			2008

#define PANEL_CLASS_OWNER		_T("OWNER")
#define PANEL_CLASS_CALENDAR	_T("CALENDAR")
#define PANEL_CLASS_NOTES		_T("NOTES")
#define PANEL_CLASS_PANEL		_T("PANEL")
#define PANEL_CLASS_CURVE		_T("CURVE")
#define PANEL_CLASS_MODEL		_T("MODEL")
#define PANEL_CLASS_PLOT		_T("PLOT")

#define MAINFRAME_ACCEL_COUNT		1

accel_t	MAINFRAME_ACCEL[MAINFRAME_ACCEL_COUNT] = {
	KEY_CONTROL, _T('O'), IDA_OWNER,
};

typedef struct tagMainFrameDelta{
	res_win_t hToolBar;
	res_win_t hTitleBar;
	res_win_t hTreeBar;
	res_win_t hStatusBar;

	res_win_t hToolTip;
	res_win_t hKeyBox;
	res_win_t hNaviBox;

	bool_t bDirty;
	bool_t bMode;
}MainFrameDelta;

#define GETMAINFRAMEDELTA(widget) 			(MainFrameDelta*)widget_get_user_delta(widget)
#define SETMAINFRAMEDELTA(widget,ptd)		widget_set_user_delta(widget,(vword_t)ptd)

void _MainFrame_CalcToolBar(res_win_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_get_dock_rect(widget, WS_DOCK_TOP, pxr);
}

void _MainFrame_CalcStatusBar(res_win_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_get_dock_rect(widget, WS_DOCK_BOTTOM, pxr);
}

void _MainFrame_CalcTreeBar(res_win_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_get_dock_rect(widget, WS_DOCK_LEFT, pxr);
}

void _MainFrame_CalcTitleBar(res_win_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
	xsize_t xs;

	xs.fw = 0;
	xs.fh = MAINFRAME_TITLEBAR_HEIGHT;
	widget_size_to_pt(widget, &xs);

	widget_get_dock_rect(widget, 0, pxr);
	pxr->h = xs.h;
}

void _MainFrame_CalcPanelBar(res_win_t widget, xrect_t* pxr)
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

void _MainFrame_CreateToolBar(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr = { 0 };

	_MainFrame_CalcToolBar(widget, &xr);

	pdt->hToolBar = toolctrl_create(_T("ToolBar"), WD_STYLE_CONTROL | WD_STYLE_HOTOVER, &xr, widget);
	widget_set_user_id(pdt->hToolBar, IDC_MAINFRAME_TOOLBAR);
	widget_set_owner(pdt->hToolBar, widget);

	LINKPTR ptrTool = create_tool_doc();

	LINKPTR glk = insert_tool_group(ptrTool, LINK_LAST);
	set_tool_group_name(glk, _T("TextOnly"));
	set_tool_group_title(glk, _T("1"));
	set_tool_group_show(glk, ATTR_SHOW_TEXTONLY);
	set_tool_group_item_width(glk, 18);
	set_tool_group_item_height(glk, 7);

	tchar_t token[NUM_LEN + 1] = { 0 };

	LINKPTR ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_OWNER);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("2"));

	glk = insert_tool_group(ptrTool, LINK_LAST);
	set_tool_group_name(glk, _T("ImageOnly"));
	set_tool_group_title(glk, _T("3"));
	set_tool_group_show(glk, ATTR_SHOW_IMAGEONLY);
	set_tool_group_item_width(glk, 7);
	set_tool_group_item_height(glk, 7);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_OWNER);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("4"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_USER);

	glk = insert_tool_group(ptrTool, LINK_LAST);
	set_tool_group_name(glk, _T("ImageText"));
	set_tool_group_title(glk, _T("5"));
	set_tool_group_item_width(glk, 18);
	set_tool_group_item_height(glk, 7);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_OWNER);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("6"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_USER);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_CALENDAR);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("7"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_USER);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_NOTES);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("8"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_USER);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PANEL);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("9"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_USER);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_CURVE);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("10"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_USER);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_MODEL);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("hh"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_USER);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("11"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_USER);

	toolctrl_attach(pdt->hToolBar, ptrTool);
	widget_show(pdt->hToolBar, WS_SHOW_NORMAL);
}

void _MainFrame_CreateTitleBar(res_win_t widget)
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

void _MainFrame_CreateTreeBar(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr = { 0 };

	_MainFrame_CalcTreeBar(widget, &xr);

	pdt->hTreeBar = treectrl_create(_T("TreeBar"), WD_STYLE_CONTROL, &xr, widget);
	widget_set_user_id(pdt->hTreeBar, IDC_MAINFRAME_TREEBAR);
	widget_set_owner(pdt->hTreeBar, widget);

	LINKPTR ptrTree = create_tree_doc();

	set_tree_title(ptrTree, _T("tree"));
	set_tree_title_icon(ptrTree, GDI_ATTR_GIZMO_PROPER);
	treectrl_attach(pdt->hTreeBar, ptrTree);
	treectrl_set_lock(pdt->hTreeBar, 0);

	widget_show(pdt->hTreeBar, WS_SHOW_NORMAL);
}

void _MainFrame_CreateStatusBar(res_win_t widget)
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
	set_status_item_title(ilk, _T("navibox"));
	set_status_item_width(ilk, DEF_TOUCH_SPAN * 6 + 1);

	statusctrl_attach(pdt->hStatusBar, ptrStatus);

	widget_show(pdt->hStatusBar, WS_SHOW_NORMAL);

	ilk = get_status_item(ptrStatus, _T("navibox"));
	statusctrl_get_item_rect(pdt->hStatusBar, ilk, &xr);

	pdt->hNaviBox = navibox_create(pdt->hStatusBar, WD_STYLE_CONTROL, &xr);
	widget_set_owner(pdt->hNaviBox, pdt->hStatusBar);
	widget_show(pdt->hNaviBox, WS_SHOW_NORMAL);
}

void _MainFrame_DestroyToolBar(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrTool = toolctrl_detach(pdt->hToolBar);
	if (ptrTool)
		destroy_tool_doc(ptrTool);
	widget_destroy(pdt->hToolBar);
}

void _MainFrame_DestroyTitleBar(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrTitle = titlectrl_detach(pdt->hTitleBar);
	if (ptrTitle)
		destroy_title_doc(ptrTitle);
	widget_destroy(pdt->hTitleBar);
}

void _MainFrame_DestroyTreeBar(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrTree = treectrl_detach(pdt->hTreeBar);
	if (ptrTree)
		destroy_tree_doc(ptrTree);
	widget_destroy(pdt->hTreeBar);
}

void _MainFrame_DestroyStatusBar(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	LINKPTR ptrStatus = statusctrl_detach(pdt->hStatusBar);
	if (ptrStatus)
		destroy_status_doc(ptrStatus);
	widget_destroy(pdt->hStatusBar);
}

res_win_t _MainFrame_CreatePanel(res_win_t widget, const tchar_t* wclass)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	res_win_t hPanel = NULL;
	xrect_t xr = { 0 };

	link_t_ptr ptr_title, ilk;

	_MainFrame_CalcPanelBar(widget, &xr);

	tchar_t wname[RES_LEN + 1] = { 0 };

	if (compare_text(wclass, -1, PANEL_CLASS_OWNER, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewUser"));

		hPanel = ownerctrl_create(_T("OwnerPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_OWNERPANEL);
		widget_set_owner(hPanel, widget);
		ownerctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_CALENDAR, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewCalendar"));

		hPanel = calendarctrl_create(_T("CalendarPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_CALENDARPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_calendar = create_calendar_doc();

		xdate_t dt;
		get_loc_date(&dt);
		tchar_t sz_date[DATE_LEN];
		format_date(&dt, sz_date);
		set_calendar_today(ptr_calendar, sz_date);

		calendarctrl_attach(hPanel, ptr_calendar);
		calendarctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_NOTES, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewCalendar"));

		hPanel = notesctrl_create(_T("NotesPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_NOTESPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_arch = create_arch_doc();

		LINKPTR ptr_notes = create_notes_doc();
		set_notes_time(ptr_notes, _T("2019-11-25 10:00:00"));
		set_notes_text(ptr_notes, _T("day1"), -1);
		insert_arch_document(ptr_arch, LINK_LAST, ptr_notes);

		ptr_notes = create_notes_doc();
		set_notes_time(ptr_notes, _T("2019-11-26 10:00:00"));
		set_notes_text(ptr_notes, _T("day2"), -1);
		insert_arch_document(ptr_arch, LINK_LAST, ptr_notes);

		ptr_notes = create_notes_doc();
		set_notes_time(ptr_notes, _T("2019-11-27 10:00:00"));
		set_notes_text(ptr_notes, _T("day3"), -1);
		insert_arch_document(ptr_arch, LINK_LAST, ptr_notes);

		notesctrl_attach(hPanel, ptr_arch);
		notesctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PANEL, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewPanel"));

		hPanel = panelctrl_create(_T("PanelPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PANELPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_arch = create_arch_doc();

		LINKPTR ptr_notes = create_notes_doc();
		set_notes_time(ptr_notes, _T("2019-11-25 10:00:00"));
		set_notes_text(ptr_notes, _T("panel1"), -1);
		insert_arch_document(ptr_arch, LINK_LAST, ptr_notes);

		ptr_notes = create_notes_doc();
		set_notes_time(ptr_notes, _T("2019-11-26 10:00:00"));
		set_notes_text(ptr_notes, _T("panel2"), -1);
		insert_arch_document(ptr_arch, LINK_LAST, ptr_notes);

		ptr_notes = create_notes_doc();
		set_notes_time(ptr_notes, _T("2019-11-27 10:00:00"));
		set_notes_text(ptr_notes, _T("panel3"), -1);
		insert_arch_document(ptr_arch, LINK_LAST, ptr_notes);

		notesctrl_attach(hPanel, ptr_arch);
		notesctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_CURVE, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewCurve"));

		hPanel = curvectrl_create(_T("CurvePanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_CURVEPANEL);
		widget_set_owner(hPanel, widget);
		curvectrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_MODEL, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewModel"));

		hPanel = modelctrl_create(_T("ModelPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_MODELPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_anno = create_anno_doc();

		modelctrl_attach(hPanel, ptr_anno);
		modelctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("NewPlot"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_CALENDAR, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 50);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_INDICATOR, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 50);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1, 3, 5] [2, 1,3, 4][4, 3, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit,diet,motion,chronic,therapy,sympt"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_y_shapes_token(ptr_plot, _T("rect,rect,round,right-triangle,ellipse,bottom-triangle"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_THERMOMETER, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 50);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:solid;"), -1);
		set_plot_y_bases_token(ptr_plot, _T("10,5,10,0,0,0,0"), -1);
		set_plot_y_steps_token(ptr_plot, _T("-2,-2,-2,4,4,2,8"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3,text4,text5"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1, 3, 5] [2, 1,3, 4][4, 3, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_BARGRAM, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 50);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_bases_token(ptr_plot, _T("0,0,0,0,0,0,0"), -1);
		set_plot_y_steps_token(ptr_plot, _T("10,10,10,10,10"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3,text4,text5"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1, 3, 5] [2, 1,3, 4][4, 3, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_CONTRAGRAM, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 80);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_bases_token(ptr_plot, _T("10,10"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3,text4,text5"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_ruler(ptr_plot, 5);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1] [2, 2] [4, 3] [6, 5] [8, 10]}"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_BALANCEGRAM, -1);
		set_plot_width(ptr_plot, 50);
		set_plot_height(ptr_plot, 80);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_bases_token(ptr_plot, _T("10,5"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3,text4,text5"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_ruler(ptr_plot, 5);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1] [3, 4] [4, 3] [6, 5] [8, 10]}"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_KPIGRAM, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 60);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_grades_token(ptr_plot, _T("3,5,6"), -1);
		set_plot_y_stages_token(ptr_plot, _T("grade1,grade2,grade3"), -1);
		set_plot_y_bases_token(ptr_plot, _T("2,2,2"), -1);
		set_plot_y_steps_token(ptr_plot, _T("4,2,8"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit,diet,motion,chronic,therapy,sympt"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_y_shapes_token(ptr_plot, _T("top-triangle,rect,left-triangle,round,right-triangle,ellipse,bottom-triangle"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_ruler(ptr_plot, 5);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2,4,5,7,10]}"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_TASKGRAM, -1);
		set_plot_width(ptr_plot, 50);
		set_plot_height(ptr_plot, 20);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit,diet,motion,chronic,therapy,sympt"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_y_shapes_token(ptr_plot, _T("top-triangle,rect,left-triangle,round,right-triangle,ellipse,bottom-triangle"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3,text4,text5"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_ruler(ptr_plot, 5);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1, 3, 5] [2, 0,3, 4][0, 0, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_SCATTERGRAM, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 80);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_bases_token(ptr_plot, _T("10,5,10,0,0,0,0"), -1);
		set_plot_y_steps_token(ptr_plot, _T("-2,-2,-2,4,4,2,8"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit,diet,motion,chronic,therapy,sympt"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3,text4,text5"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1, 3, 5] [2, 1,3, 4][4, 3, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_MEDIANGRAM, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 50);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_grades_token(ptr_plot, _T("3,5,6"), -1);
		set_plot_y_stages_token(ptr_plot, _T("grade1,grade2,grade3"), -1);
		set_plot_y_bases_token(ptr_plot, _T("0,0,0,0,0,0,0"), -1);
		set_plot_y_steps_token(ptr_plot, _T("2,2,2,4,4,2,8"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit,diet,motion,chronic,therapy,sympt"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_y_shapes_token(ptr_plot, _T("top-triangle,rect,left-triangle,round,right-triangle,ellipse,bottom-triangle"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_ruler(ptr_plot, 5);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 4);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1, 3, 5] [2, 1,3, 4][4, 3, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		*/

		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_HISTOGRAM, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 50);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_grades_token(ptr_plot, _T("3,5,6"), -1);
		set_plot_y_stages_token(ptr_plot, _T("grade1,grade2,grade3"), -1);
		set_plot_y_bases_token(ptr_plot, _T("10,5,10,0,0,0,0"), -1);
		set_plot_y_steps_token(ptr_plot, _T("-2,-2,-2,4,4,2,8"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit,diet,motion,chronic,therapy,sympt"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_y_shapes_token(ptr_plot, _T("top-triangle,rect,left-triangle,round,right-triangle,ellipse,bottom-triangle"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3,text4,text5"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1, 3, 5] [2, 1,3, 4][4, 3, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_TRENDGRAM, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 50);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_grades_token(ptr_plot, _T("3,5,6"), -1);
		set_plot_y_stages_token(ptr_plot, _T("grade1,grade2,grade3"), -1);
		set_plot_y_bases_token(ptr_plot, _T("10,5,10,0,0,0,0"), -1);
		set_plot_y_steps_token(ptr_plot, _T("-2,-2,-2,4,4,2,8"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit,diet,motion,chronic,therapy,sympt"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_y_shapes_token(ptr_plot, _T("top-triangle,rect,left-triangle,round,right-triangle,ellipse,bottom-triangle"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T("{[2, 1, 3, 5] [2, 1,3, 4] [4, 3, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_PANTOGRAM, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 50);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_grades_token(ptr_plot, _T("3,5,6"), -1);
		set_plot_y_stages_token(ptr_plot, _T("grade1,grade2,grade3"), -1);
		set_plot_y_bases_token(ptr_plot, _T("10,5,10,0,0,0,0"), -1);
		set_plot_y_steps_token(ptr_plot, _T("-2,-2,-2,4,4,2,8"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit,diet,motion,chronic,therapy,sympt"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_y_shapes_token(ptr_plot, _T("top-triangle,rect,left-triangle,round,right-triangle,ellipse,bottom-triangle"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_ruler(ptr_plot, 5);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1, 3, 5] [2, 1,3, 4] [4, 3, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		*/
		/*set_plot_type(ptr_plot, ATTR_PLOT_TYPE_RADARGRAM, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 100);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_grades_token(ptr_plot, _T("3,5,6"), -1);
		set_plot_y_stages_token(ptr_plot, _T("grade1,grade2,grade3"), -1);
		set_plot_y_bases_token(ptr_plot, _T("10,5,10,0,0,0,0"), -1);
		set_plot_y_steps_token(ptr_plot, _T("-2,-2,-2,4,4,2,8"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit,diet,motion,chronic,therapy,sympt"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_y_shapes_token(ptr_plot, _T("top-triangle,rect,left-triangle,round,right-triangle,ellipse,bottom-triangle"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_ruler(ptr_plot, 5);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 4);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1, 3, 5] [2, 1,3, 4][4, 3, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		*/
		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_FUELGRAM, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 50);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
		set_plot_y_grades_token(ptr_plot, _T("3,5,6"), -1);
		set_plot_y_stages_token(ptr_plot, _T("grade1,grade2,grade3"), -1);
		set_plot_y_bases_token(ptr_plot, _T("10,5,10,0,0,0,0"), -1);
		set_plot_y_steps_token(ptr_plot, _T("-2,-2,-2,4,4,2,8"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit,diet,motion,chronic,therapy,sympt"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_y_shapes_token(ptr_plot, _T("top-triangle,rect,left-triangle,round,right-triangle,ellipse,bottom-triangle"), -1);
		set_plot_x_labels_token(ptr_plot, _T("text1,text2,text3"), -1);
		set_plot_x_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_ruler(ptr_plot, 5);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1, 3, 5] [2, 1,3, 4][4, 3, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}

	if (!hPanel)
		return NULL;

	ptr_title = titlectrl_fetch(pdt->hTitleBar);

	ilk = insert_title_item(ptr_title, LINK_LAST);

	set_title_item_name(ilk, wclass);
	set_title_item_title(ilk, wname);
	set_title_item_delta(ilk, (vword_t)hPanel);

	titlectrl_redraw(pdt->hTitleBar);
	titlectrl_set_focus_item(pdt->hTitleBar, ilk);

	return hPanel;
}

res_win_t _MainFrame_GetActivePanel(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	XDK_ASSERT(pdt != NULL);

	LINKPTR nlk = titlectrl_get_focus_item(pdt->hTitleBar);
	if (!nlk)
		return NULL;

	return (res_win_t)get_title_item_delta(nlk);
}

/*******************************************************************************************************/
void MainFrame_ToolBar_OnLBClick(res_win_t widget, NOTICE_TOOL* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
	xrect_t xr = { 0 };
	xpoint_t pt = { 0 };

	if (!pnt->item)
		return;

	long nID = xstol(get_tool_item_id_ptr(pnt->item));

	toolctrl_get_item_rect(pdt->hToolBar, pnt->item, &xr);
	pt.x = xr.x;
	pt.y = xr.y + xr.h;
	widget_client_to_screen(pdt->hToolBar, &pt);

	widget_send_command(widget, 0, nID, (vword_t)&pt);
}

void MainFrame_ToolBar_OnItemHover(res_win_t widget, NOTICE_TOOL* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xpoint_t xp, *ppt;
	ppt = (xpoint_t*)pnt->data;

	xp.x = ppt->x + 10;
	xp.y = ppt->y + 10;

	widget_client_to_screen(pnt->widget, &xp);

	if (widget_is_valid(pdt->hToolTip))
		reset_toolbox(pdt->hToolTip, &xp, get_tool_item_title_ptr(pnt->item));
	else
		pdt->hToolTip = show_toolbox(&xp, get_tool_item_title_ptr(pnt->item));
}

void MainFrame_TitleBar_OnItemInsert(res_win_t widget, NOTICE_TITLE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);
}

void MainFrame_TitleBar_OnItemDelete(res_win_t widget, NOTICE_TITLE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	res_win_t hPanel = (res_win_t)get_title_item_delta(pnt->item);

	if (!widget_is_valid(hPanel))
		return;

	const tchar_t* wclass = get_title_item_name_ptr(pnt->item);
	LINKPTR ptrDoc = NULL;

	if (compare_text(wclass, -1, PANEL_CLASS_CALENDAR, -1, 0) == 0)
	{
		ptrDoc = calendarctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_NOTES, -1, 0) == 0)
	{
		ptrDoc = notesctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PANEL, -1, 0) == 0)
	{
		ptrDoc = panelctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_MODEL, -1, 0) == 0)
	{
		ptrDoc = modelctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}

	widget_close(hPanel, 0);

	if (widget_is_valid(hPanel))
	{
		pnt->ret = 1;
		return;
	}

	if (compare_text(wclass, -1, PANEL_CLASS_CALENDAR, -1, 0) == 0)
	{
		destroy_calendar_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_NOTES, -1, 0) == 0)
	{
		destroy_arch_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PANEL, -1, 0) == 0)
	{
		destroy_arch_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_MODEL, -1, 0) == 0)
	{
		destroy_anno_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
}

void MainFrame_TitleBar_OnItemChanging(res_win_t widget, NOTICE_TITLE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	res_win_t hPanel = (res_win_t)get_title_item_delta(pnt->item);

	if (widget_is_valid(hPanel))
	{
		widget_show(hPanel, WS_SHOW_HIDE);
	}
}

void MainFrame_TitleBar_OnItemChanged(res_win_t widget, NOTICE_TITLE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	res_win_t hPanel = (res_win_t)get_title_item_delta(pnt->item);

	if (widget_is_valid(hPanel))
	{
		clr_mod_t clr;
		widget_get_color_mode(widget, &clr);

		widget_set_color_mode(hPanel, &clr);

		widget_show(hPanel, WS_SHOW_NORMAL);
	}
}

void MainFrame_TitleBar_OnItemHover(res_win_t widget, NOTICE_TITLE* pnt)
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

/*void MainFrame_UserPanel_OnCalc(res_win_t win, PAGE_CALC* ppc)
{
	ppc->total_height = 8096;
	ppc->total_width = 4096;
	ppc->line_height = 10;
	ppc->line_width = 10;
}*/

void MainFrame_UserPanel_OnDraw(res_win_t win, visual_t rdc)
{
	canvbox_t cb;
	xcolor_t xc;

	xpen_t xp;
	widget_get_xpen(win, &xp);
	xbrush_t xb;
	widget_get_xbrush(win, &xb);
	lighten_xbrush(&xb, DEF_HARD_DARKEN);

	canvas_t canv;
	drawing_interface ifc = { 0 };
	
	canv = widget_get_canvas(win);

	get_canvas_interface(canv, &ifc);

	widget_get_canv_rect(win, &cb);
	
	parse_xcolor(&xc, GDI_ATTR_RGB_LIGHTRED);

	//test_gizmo(&ifc, &xc, (xrect_t*)&cb);

	//test_color(&ifc, (xrect_t*)&cb);

	/*xscpy(xp.size, _T("2"));

	xpoint_t pt1, pt2;

	pt1.fx = 10.0f;
	pt1.fy = 10.0f;
	pt2.fx = 20.0f;
	pt2.fy = 25.0f;

	(*ifc.pf_draw_line)(ifc.ctx, &xp, &pt1, &pt2);

	draw_linecap(&ifc, &xp, &pt1, &pt2, XPI / 4, GDI_ATTR_STROKE_LINECAP_SQUARE);

	draw_linecap(&ifc, &xp, &pt2, &pt1, XPI / 4, GDI_ATTR_STROKE_LINECAP_ARROW);

	pt1.fx = 35.0f;
	pt1.fy = 25.0f;
	pt2.fx = 45.0f;
	pt2.fy = 10.0f;

	(*ifc.pf_draw_line)(ifc.ctx, &xp, &pt1, &pt2);

	draw_linecap(&ifc, &xp, &pt1, &pt2, XPI / 4, GDI_ATTR_STROKE_LINECAP_ARROW);

	draw_linecap(&ifc, &xp, &pt2, &pt1, XPI / 4, GDI_ATTR_STROKE_LINECAP_SQUARE);

	pt1.fx = 50.0f;
	pt1.fy = 20.0f;
	pt2.fx = 60.0f;
	pt2.fy = 20.0f;

	(*ifc.pf_draw_line)(ifc.ctx, &xp, &pt1, &pt2);

	draw_linecap(&ifc, &xp, &pt1, &pt2, XPI / 4, GDI_ATTR_STROKE_LINECAP_ROUND);

	draw_linecap(&ifc, &xp, &pt2, &pt1, XPI / 4, GDI_ATTR_STROKE_LINECAP_ARROW);

	pt1.fx = 70.0f;
	pt1.fy = 10.0f;
	pt2.fx = 70.0f;
	pt2.fy = 20.0f;

	(*ifc.pf_draw_line)(ifc.ctx, &xp, &pt1, &pt2);

	draw_linecap(&ifc, &xp, &pt1, &pt2, XPI / 4, GDI_ATTR_STROKE_LINECAP_ARROW);

	draw_linecap(&ifc, &xp, &pt2, &pt1, XPI / 4, GDI_ATTR_STROKE_LINECAP_ROUND);*/

	/*drawing_interface ifv = { 0 };

	get_visual_interface(rdc, &ifv);

	tchar_t aa[10] = { 0 };
	xpoint_t pa[20] = { 0 };

	int i = 0;
	int n = 0;
	int feed = 10;


	xrect_t xr;
	widget_get_client_rect(win, &xr);

	xr.w -= 10;
	xr.h = 50;

	aa[i] = _T('M');
	pa[n].x = xr.x;
	pa[n].y = xr.y + feed;
	i++;
	n++;

	aa[i] = _T('A');
	pa[n].x = 1;
	pa[n].y = 0;
	pa[n+1].x = feed;
	pa[n+1].y = feed;
	pa[n+2].x = xr.x + feed;
	pa[n+2].y = xr.y;
	i++;
	n+=3;

	aa[i] = _T('L');
	pa[n].x = xr.x + xr.w - feed;
	pa[n].y = xr.y;
	i++;
	n++;

	aa[i] = _T('A');
	pa[n].x = 1;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x + xr.w;
	pa[n + 2].y = xr.y + feed;
	i++;
	n += 3;

	aa[i] = _T('L');
	pa[n].x = xr.x + xr.w;
	pa[n].y = xr.y + xr.h - feed;
	i++;
	n++;

	aa[i] = _T('A');
	pa[n].x = 1;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x + xr.w - feed;
	pa[n + 2].y = xr.y + xr.h;
	i++;
	n += 3;

	aa[i] = _T('C');
	pa[n].x = xr.x + xr.w / 8 * 7;
	pa[n].y = xr.y + xr.h - 10;
	pa[n + 1].x = xr.x + xr.w / 4 * 3;
	pa[n + 1].y = xr.y + xr.h - 10;
	pa[n + 2].x = xr.x + xr.w / 2;
	pa[n + 2].y = xr.y + xr.h;
	i++;
	n += 3;

	aa[i] = _T('S');
	pa[n].x = xr.x + xr.w / 4;
	pa[n].y = xr.y + xr.h;
	pa[n + 1].x = xr.x + feed;
	pa[n + 1].y = xr.y + xr.h;
	i++;
	n += 2;
	
	aa[i] = _T('A');
	pa[n].x = 1;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x;
	pa[n + 2].y = xr.y + xr.h - feed;
	i++;
	n += 3;

	aa[i] = _T('Z');
	i++;

	xp.adorn.feed = 0;
	xp.adorn.size = 0;
	xb.shadow.offx = 10;
	xb.shadow.offy = 10;

	(*ifv.pf_draw_path)(ifv.ctx, &xp, &xb, aa, pa, n);

	xr.y = 60;
	xr.x = 10;
	xr.w = 50;
	xr.h = 50;

	xp.adorn.feed = 0;
	xp.adorn.size = 0;
	xb.shadow.offx = 5;
	xb.shadow.offy = 5;
	(*ifv.pf_draw_rect)(ifv.ctx, &xp, &xb, &xr);

	xr.y = 60;
	xr.x = 80;
	xr.w = 50;
	xr.h = 50;

	xp.adorn.feed = 0;
	xp.adorn.size = 0;
	xb.shadow.offx = 5;
	xb.shadow.offy = 5;
	(*ifv.pf_draw_round)(ifv.ctx, &xp, &xb, &xr, NULL);

	xr.y = 60;
	xr.x = 150;
	xr.w = 50;
	xr.h = 50;

	xp.adorn.feed = 0;
	xp.adorn.size = 0;
	xb.shadow.offx = 5;
	xb.shadow.offy = 5;
	(*ifv.pf_draw_ellipse)(ifv.ctx, &xp, &xb, &xr);

	xr.y = 60;
	xr.x = 220;
	xr.w = 50;
	xr.h = 50;

	xpoint_t pt;

	xsize_t xs;

	xp.adorn.feed = 0;
	xp.adorn.size = 0;
	xb.shadow.offx = 5;
	xb.shadow.offy = 5;
	(*ifv.pf_draw_pie)(ifv.ctx, &xp, &xb, &xr, 0, XPI / 2);

	(*ifv.pf_draw_pie)(ifv.ctx, &xp, &xb, &xr, XPI, XPI * 3 / 2);

	xr.y = 60;
	xr.x = 280;
	xr.w = 50;
	xr.h = 50;

	xpoint_t pk;

	pt.x = xr.x;
	pt.y = xr.y + xr.h / 2;
	pk.x = xr.x + xr.w;
	pk.y = xr.y + xr.h / 2;

	xs.w = xr.w / 2;
	xs.h = xr.h / 2;

	xp.adorn.feed = 1;
	xp.adorn.size = 1;
	xb.shadow.offx = 0;
	xb.shadow.offy = 0;
	(*ifv.pf_draw_arc)(ifv.ctx, &xp, &pt, &pk, &xs, 0, 0);

	xr.y += 50;
	pt.x = xr.x;
	pt.y = xr.y + xr.h / 2;
	pk.x = xr.x + xr.w;
	pk.y = xr.y + xr.h / 2;
	xs.w = xr.w / 2;
	xs.h = xr.h / 2;

	xp.adorn.feed = 1;
	xp.adorn.size = 1;
	xb.shadow.offx = 0;
	xb.shadow.offy = 0;
	(*ifv.pf_draw_arc)(ifv.ctx, &xp, &pt, &pk, &xs, 1, 1);

	xr.x += 50;
	pt.x = xr.x;
	pt.y = xr.y;
	pk.x = xr.x;
	pk.y = xr.y + xr.h;

	xs.w = xr.w / 2;
	xs.h = xr.h / 2;

	xp.adorn.feed = 1;
	xp.adorn.size = 1;
	xb.shadow.offx = 0;
	xb.shadow.offy = 0;
	(*ifv.pf_draw_arc)(ifv.ctx, &xp, &pt, &pk, &xs, 1, 0);

	xr.x += 50;
	pt.x = xr.x;
	pt.y = xr.y;
	pk.x = xr.x;
	pk.y = xr.y + xr.h;

	xs.w = xr.w / 2;
	xs.h = xr.h / 2;

	xp.adorn.feed = 1;
	xp.adorn.size = 1;
	xb.shadow.offx = 0;
	xb.shadow.offy = 0;
	(*ifv.pf_draw_arc)(ifv.ctx, &xp, &pt, &pk, &xs, 0, 0);

	xr.y += 20;
	pt.x = xr.x;
	pt.y = xr.y + xr.h / 2;
	pk.x = xr.x + xr.w / 2;
	pk.y = xr.y + xr.h;
	xs.w = xr.w / 2;
	xs.h = xr.h / 2;

	xp.adorn.feed = 1;
	xp.adorn.size = 1;
	xb.shadow.offx = 0;
	xb.shadow.offy = 0;
	(*ifv.pf_draw_arc)(ifv.ctx, &xp, &pt, &pk, &xs, 1, 0);

	xp.adorn.feed = 1;
	xp.adorn.size = 1;
	xb.shadow.offx = 0;
	xb.shadow.offy = 0;
	(*ifv.pf_draw_arc)(ifv.ctx, &xp, &pt, &pk, &xs, 1, 1);

	xr.x += 100;
	pt.x = xr.x;
	pt.y = xr.y + xr.h / 2;
	pk.x = xr.x + xr.w / 2;
	pk.y = xr.y + xr.h;
	xs.w = xr.w / 2;
	xs.h = xr.h / 2;
	(*ifv.pf_draw_rect)(ifv.ctx, &xp, NULL, &xr);

	xp.adorn.feed = 1;
	xp.adorn.size = 1;
	xb.shadow.offx = 0;
	xb.shadow.offy = 0;
	(*ifv.pf_draw_arc)(ifv.ctx, &xp, &pt, &pk, &xs, 0, 0);

	xp.adorn.feed = 1;
	xp.adorn.size = 1;
	xb.shadow.offx = 0;
	xb.shadow.offy = 0;
	(*ifv.pf_draw_arc)(ifv.ctx, &xp, &pt, &pk, &xs, 0, 1);

	xr.y = 60;
	xr.x = 340;
	xr.w = 50;
	xr.h = 50;

	xspan_t xn;
	xn.s = 20;

	xr.y = 100;
	xr.x = 450;
	xr.w = 50;
	xr.h = 50;
	xn.s = 20;
	(*ifv.pf_draw_equilagon)(ifv.ctx, &xp, &xb, RECTPOINT(&xr), &xn, 6);

	widget_get_client_rect(win, &xr);

	xr.y += 200;
	xr.w -= 10;
	xr.h = 50;

	i = 0;
	n = 0;

	aa[i] = _T('M');
	pa[n].x = xr.x + xr.w - feed;
	pa[n].y = xr.y + xr.h;
	i++;
	n++;

	aa[i] = _T('A');
	pa[n].x = 0;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x + xr.w;
	pa[n + 2].y = xr.y + xr.h - feed;
	i++;
	n += 3;

	aa[i] = _T('L');
	pa[n].x = xr.x + xr.w;
	pa[n].y = xr.y + feed;
	i++;
	n++;

	aa[i] = _T('A');
	pa[n].x = 0;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x + xr.w - feed;
	pa[n + 2].y = xr.y;
	i++;
	n += 3;

	aa[i] = _T('L');
	pa[n].x = xr.x + feed;
	pa[n].y = xr.y;
	i++;
	n++;

	aa[i] = _T('A');
	pa[n].x = 0;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x;
	pa[n + 2].y = xr.y + feed;
	i++;
	n += 3;

	aa[i] = _T('L');
	pa[n].x = xr.x;
	pa[n].y = xr.y + xr.h - feed;
	i++;
	n++;

	aa[i] = _T('A');
	pa[n].x = 0;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x + feed;
	pa[n + 2].y = xr.y + xr.h;
	i++;
	n += 3;

	aa[i] = _T('Z');
	i++;

	xp.adorn.feed = 0;
	xp.adorn.size = 0;
	xb.shadow.offx = 10;
	xb.shadow.offy = 10;

	(*ifv.pf_draw_path)(ifv.ctx, &xp, &xb, aa, pa, n);

	xr.x = 100;
	xr.y += 100;
	xr.w = 50;
	xr.h = 50;
	feed = xr.w / 2;

	i = 0;
	n = 0;

	aa[i] = _T('M');
	pa[n].x = xr.x;
	pa[n].y = xr.y;
	i++;
	n++;

	aa[i] = _T('A');
	pa[n].x = 1;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x + xr.w;
	pa[n + 2].y = xr.y;
	i++;
	n += 3;

	aa[i] = _T('A');
	pa[n].x = 1;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x + xr.w;
	pa[n + 2].y = xr.y + xr.h;
	i++;
	n += 3;

	aa[i] = _T('A');
	pa[n].x = 1;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x;
	pa[n + 2].y = xr.y + xr.h;
	i++;
	n += 3;

	aa[i] = _T('A');
	pa[n].x = 1;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x;
	pa[n + 2].y = xr.y;
	i++;
	n += 3;

	aa[i] = _T('Z');
	i++;

	xp.adorn.feed = 0;
	xp.adorn.size = 0;
	xb.shadow.offx = 10;
	xb.shadow.offy = 10;

	(*ifv.pf_draw_path)(ifv.ctx, &xp, &xb, aa, pa, n);
	*/
	
}

/******************************************************************************************************/

int MainFrame_OnCreate(res_win_t widget, void* data)
{
	MainFrameDelta* pdt;

	widget_hand_create(widget);

	res_acl_t hac = create_accel_table(MAINFRAME_ACCEL, MAINFRAME_ACCEL_COUNT);

	widget_attach_accel(widget, hac);

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
	SETMAINFRAMEDELTA(widget, pdt);

	_MainFrame_CreateToolBar(widget);

	_MainFrame_CreateTitleBar(widget);

	_MainFrame_CreateStatusBar(widget);

	_MainFrame_CreateTreeBar(widget);

	return 0;
}

void MainFrame_OnDestroy(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	res_acl_t hac = widget_get_accel(widget);
	if (hac)
		destroy_accel_table(hac);

	_MainFrame_DestroyToolBar(widget);

	_MainFrame_DestroyTitleBar(widget);

	_MainFrame_DestroyTreeBar(widget);

	_MainFrame_DestroyStatusBar(widget);

	if (widget_is_valid(pdt->hToolTip))
		widget_destroy(pdt->hToolTip);

	if (widget_is_valid(pdt->hKeyBox))
		widget_destroy(pdt->hKeyBox);

	xmem_free(pdt);

	widget_hand_destroy(widget);
}

int MainFrame_OnClose(res_win_t widget)
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


	widget_destroy(widget);

	send_quit_message(0);

	return 0;
}

void MainFrame_OnSize(res_win_t widget, int code, const xsize_t* pxs)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr;

	_MainFrame_CalcToolBar(widget, &xr);
	if(widget_is_valid(pdt->hToolBar))
	{
		widget_move(pdt->hToolBar, RECTPOINT(&xr));
		widget_size(pdt->hToolBar, RECTSIZE(&xr));
		widget_update(pdt->hToolBar);
	}

	_MainFrame_CalcStatusBar(widget, &xr);
	if(widget_is_valid(pdt->hStatusBar))
	{
		widget_move(pdt->hStatusBar, RECTPOINT(&xr));
		widget_size(pdt->hStatusBar, RECTSIZE(&xr));
		widget_update(pdt->hStatusBar);
	}

	_MainFrame_CalcTreeBar(widget, &xr);
	if(widget_is_valid(pdt->hTreeBar))
	{
		widget_move(pdt->hTreeBar, RECTPOINT(&xr));
		widget_size(pdt->hTreeBar, RECTSIZE(&xr));
		widget_update(pdt->hTreeBar);
	}

	_MainFrame_CalcTitleBar(widget, &xr);
	if(widget_is_valid(pdt->hTitleBar))
	{
		widget_move(pdt->hTitleBar, RECTPOINT(&xr));
		widget_size(pdt->hTitleBar, RECTSIZE(&xr));
		widget_update(pdt->hTitleBar);
	}

	_MainFrame_CalcPanelBar(widget, &xr);

	if(widget_is_valid(pdt->hTitleBar))
	{
		LINKPTR ptrTitle = titlectrl_fetch(pdt->hTitleBar);
		LINKPTR plk = get_title_next_item(ptrTitle, LINK_FIRST);
		while (plk)
		{
			res_win_t hPanel = (res_win_t)get_title_item_delta(plk);

			if (widget_is_valid(hPanel))
			{
				widget_move(hPanel, RECTPOINT(&xr));
				widget_size(hPanel, RECTSIZE(&xr));
				widget_update(hPanel);
			}

			plk = get_title_next_item(ptrTitle, plk);
		}
	}

	widget_erase(widget, NULL);
}

void MainFrame_OnScroll(res_win_t widget, bool_t bHorz, int nLine)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_hand_scroll(widget, bHorz, nLine);
}

void MainFrame_OnMenuCommand(res_win_t widget, int code, int cid, vword_t data)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	res_win_t hPanel = _MainFrame_GetActivePanel(widget);
	if (hPanel && !code)
	{
		if (widget_send_command(hPanel, code, cid, data))
			return;
	}

	switch (cid)
	{
	case IDA_OWNER:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_OWNER);
		break;
	case IDA_CALENDAR:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_CALENDAR);
		break;
	case IDA_NOTES:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_NOTES);
		break;
	case IDA_PANEL:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PANEL);
		break;
	case IDA_CURVE:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_CURVE);
		break;
	case IDA_PLOT:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT);
		break;
	}
}

void MainFrame_OnNotice(res_win_t widget, LPNOTICE phdr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if (phdr->id == IDC_MAINFRAME_TOOLBAR)
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
	else if (phdr->id == IDC_MAINFRAME_TITLEBAR)
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
	else if (phdr->id == IDC_MAINFRAME_TREEBAR)
	{
		NOTICE_TREE* pnt = (NOTICE_TREE*)phdr;
		switch (pnt->code)
		{
		case NC_TREELBCLK:
			break;
		case NC_TREEDBCLK:
			break;
		case NC_TREERBCLK:
			break;
		case NC_TREEITEMEDITING:
			break;
		case NC_TREEITEMCOMMIT:
			break;
		case NC_TREEITEMUPDATE:
			break;
		}
	}
	else if (phdr->id == IDC_MAINFRAME_STATUSBAR)
	{
		NOTICE_STATUS* pnt = (NOTICE_STATUS*)phdr;
		switch (pnt->code)
		{
		case NC_STATUSLBCLK:
			break;
		}
	}
	else if (phdr->id == IDC_MAINFRAME_OWNERPANEL)
	{
		NOTICE_OWNER* pnu = (NOTICE_OWNER*)phdr;
		switch (pnu->code)
		{
		case NC_OWNERCALC:
			//MainFrame_UserPanel_OnCalc(pnu->widget, (PAGE_CALC*)pnu->data);
			break;
		case NC_OWNERDRAW:
			MainFrame_UserPanel_OnDraw(pnu->widget, (visual_t)pnu->data);
			break;
		}
	}
}

res_win_t MainFrame_Create(const tchar_t* mname)
{
	res_win_t widget;
	xrect_t xr = { 0 };

	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(MainFrame_OnCreate)
		EVENT_ON_DESTROY(MainFrame_OnDestroy)
		EVENT_ON_CLOSE(MainFrame_OnClose)

		EVENT_ON_SIZE(MainFrame_OnSize)
		EVENT_ON_SCROLL(MainFrame_OnScroll)

		EVENT_ON_NOTICE(MainFrame_OnNotice)
		EVENT_ON_MENU_COMMAND(MainFrame_OnMenuCommand)

		EVENT_ON_NC_IMPLEMENT
		EVENT_ON_DOCKER_IMPLEMENT

	SUBPROC_END_DISPATH

	//get_desktop_size(RECTSIZE(&xr));

	xr.x = 0;
	xr.y = 0;
	xr.w = 800;
	xr.h = 600;

	widget = widget_create(_T("TEST"), WD_STYLE_FRAME | WD_STYLE_DOCKER | WD_STYLE_MENUBAR | WD_STYLE_OWNERNC, &xr, NULL, &ev);

	if (!widget)
	{
		return 0;
	}
	
	widget_show(widget, WS_SHOW_NORMAL);
	widget_update(widget);

	return widget;
}


