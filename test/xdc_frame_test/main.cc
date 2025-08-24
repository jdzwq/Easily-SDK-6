#include <xdl.h>
#include <xdg.h>
#include <xdu.h>
#include <xdc.h>

widget_t g_main = NULL;

widget_t MainFrame_Create(const tchar_t* mname);

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

	xdu_process_init();

	g_main = MainFrame_Create(_T("Main"));

	widget_do_main(g_main);

	xdu_process_uninit();

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
#define IDC_MAINFRAME_GIZMOPANEL	3010
#define IDC_MAINFRAME_COLORPANEL	3011
#define IDC_MAINFRAME_CALENDARPANEL	3005
#define IDC_MAINFRAME_NOTESPANEL	3006
#define IDC_MAINFRAME_PANELPANEL	3007
#define IDC_MAINFRAME_CURVEPANEL	3008
#define IDC_MAINFRAME_MODELPANEL	3009
#define IDC_MAINFRAME_PLOTPANEL		3010

#define IDA_OWNER_GIZMO			2001
#define IDA_OWNER_COLOR			2002
#define IDA_CALENDAR			2010
#define IDA_NOTES			2004
#define IDA_PANEL			2005
#define IDA_CURVE			2006
#define IDA_MODEL			2007
#define IDA_PLOT_CALENDAR			2020
#define IDA_PLOT_INDICATOR			2021
#define IDA_PLOT_THERMOMETER		2022
#define IDA_PLOT_BALANCEGRAM		2024
#define IDA_PLOT_CONTRAGRAM			2025
#define IDA_PLOT_TASKGRAM			2026
#define IDA_PLOT_FUELGRAM			2027
#define IDA_PLOT_RADARGRAM			2028
#define IDA_PLOT_KPIGRAM			2029
#define IDA_PLOT_BARGRAM			2030
#define IDA_PLOT_MEDIANGRAM			2031
#define IDA_PLOT_HISTOGRAM			2032
#define IDA_PLOT_PANTOGRAM			2033
#define IDA_PLOT_SCATTERGRAM		2034
#define IDA_PLOT_TRENDGRAM			2035
#define IDA_PLOT_CONTOURGRAM		2036
#define IDA_PLOT_TOPOGGGRAM			2037

#define ATTR_PLOT_TYPE_	_T("topoggram") //地形图
#define ATTR_PLOT_TYPE_	_T("contourgram") //等高线
#define ATTR_PLOT_TYPE_	_T("trendgram") //趋势图
#define ATTR_PLOT_TYPE_	_T("scattergram") //密度图
#define ATTR_PLOT_TYPE_	_T("pantogram") //比例图
#define ATTR_PLOT_TYPE_	_T("histogram") //直方图
#define ATTR_PLOT_TYPE_	_T("mediangram") //中位图
#define ATTR_PLOT_TYPE_		_T("bargram") //条形图
#define ATTR_PLOT_TYPE_		_T("kpigram") //达标图
#define ATTR_PLOT_TYPE_	_T("radargram") //雷达图
#define ATTR_PLOT_TYPE_	_T("fuelgram") //油量表
#define ATTR_PLOT_TYPE_		_T("taskgram") //任务表
#define ATTR_PLOT_TYPE_	_T("contragram") //对比图
#define ATTR_PLOT_TYPE_	_T("balancegram") //平衡图
#define ATTR_PLOT_TYPE_	_T("indicator") //指示器
#define ATTR_PLOT_TYPE_	_T("thermometer") //温度计
#define ATTR_PLOT_TYPE_		_T("calendar") //日历

#define PANEL_CLASS_OWNER_GIZMO		_T("OWNER_GIZMO")
#define PANEL_CLASS_OWNER_COLOR		_T("OWNER_COLOR")
#define PANEL_CLASS_CALENDAR	_T("CALENDAR")
#define PANEL_CLASS_NOTES		_T("NOTES")
#define PANEL_CLASS_PANEL		_T("PANEL")
#define PANEL_CLASS_CURVE		_T("CURVE")
#define PANEL_CLASS_MODEL		_T("MODEL")
#define PANEL_CLASS_PLOT_CALENDAR		_T("PLOT_CALENDAR")
#define PANEL_CLASS_PLOT_INDICATOR		_T("PLOT_INDICATOR")
#define PANEL_CLASS_PLOT_THERMOMETER	_T("PLOT_THERMOMETER")
#define PANEL_CLASS_PLOT_BALANCEGRAM	_T("PLOT_BALANCEGRAM")
#define PANEL_CLASS_PLOT_CONTRAGRAM		_T("PLOT_CONTRAGRAM")
#define PANEL_CLASS_PLOT_TASKGRAM		_T("PLOT_TASKGRAM")
#define PANEL_CLASS_PLOT_FUELGRAM		_T("PLOT_FUELGRAM")
#define PANEL_CLASS_PLOT_RADARGRAM		_T("PLOT_RADARGRAM")
#define PANEL_CLASS_PLOT_KPIGRAM		_T("PLOT_KPIGRAM")
#define PANEL_CLASS_PLOT_BARGRAM		_T("PLOT_BARGRAM")
#define PANEL_CLASS_PLOT_MEDIANGRAM		_T("PLOT_MEDIANGRAM")
#define PANEL_CLASS_PLOT_HISTOGRAM		_T("PLOT_HISTOGRAM")
#define PANEL_CLASS_PLOT_PANTOGRAM		_T("PLOT_PANTOGRAM")
#define PANEL_CLASS_PLOT_SCATTERGRAM	_T("PLOT_SCATTERGRAM")
#define PANEL_CLASS_PLOT_TRENDGRAM		_T("PLOT_TRENDGRAM")
#define PANEL_CLASS_PLOT_CONTOURGRAM	_T("PLOT_CONTOURGRAM")
#define PANEL_CLASS_PLOT_TOPOGGGRAM		_T("PLOT_TOPOGGGRAM")

#define MAINFRAME_ACCEL_COUNT		1

accel_table_t	MAINFRAME_ACCEL[MAINFRAME_ACCEL_COUNT] = {
	KEY_CONTROL, _T('O'), IDA_OWNER_GIZMO,
};

typedef struct tagMainFrameDelta{
	widget_t hToolBar;
	widget_t hTitleBar;
	widget_t hTreeBar;
	widget_t hStatusBar;

	widget_t hToolTip;
	widget_t hKeyBox;
	widget_t hNaviBox;

	bool_t bDirty;
	bool_t bMode;
}MainFrameDelta;

#define GETMAINFRAMEDELTA(widget) 			(MainFrameDelta*)widget_get_user_delta(widget)
#define SETMAINFRAMEDELTA(widget,ptd)		widget_set_user_delta(widget,(vword_t)ptd)

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

void _MainFrame_CalcTreeBar(widget_t widget, xrect_t* pxr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_get_dock_rect(widget, WS_DOCK_LEFT, pxr);
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
	set_tool_group_name(glk, _T("TextOnly"));
	set_tool_group_title(glk, _T("User"));
	set_tool_group_show(glk, ATTR_SHOW_TEXTONLY);
	set_tool_group_item_width(glk, 18);
	set_tool_group_item_height(glk, 7);

	tchar_t token[NUM_LEN + 1] = { 0 };

	LINKPTR ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_OWNER_GIZMO);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("Gizmo"));

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_OWNER_COLOR);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("Color"));

	glk = insert_tool_group(ptrTool, LINK_LAST);
	set_tool_group_name(glk, _T("ImageText"));
	set_tool_group_title(glk, _T("Widget"));
	set_tool_group_item_width(glk, 18);
	set_tool_group_item_height(glk, 7);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_CALENDAR);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("Calendar"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_NOTES);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("Note"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_NOTE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PANEL);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("Panel"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_BOOK);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_CURVE);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("Curve"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_SCATTER);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_MODEL);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, _T("Model"));
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_MEMO);

	glk = insert_tool_group(ptrTool, LINK_LAST);
	set_tool_group_show(glk, ATTR_SHOW_IMAGEONLY);
	set_tool_group_name(glk, _T("ImageOnly"));
	set_tool_group_title(glk, _T("Plot"));
	set_tool_group_item_width(glk, 18);
	set_tool_group_item_height(glk, 7);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_CALENDAR);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_CALENDAR);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_INDICATOR);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_INDICATOR);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_THERMOMETER);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_THERMOMETER);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_BALANCEGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_BALANCEGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_CONTRAGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_CONTRAGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_TASKGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_TASKGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_FUELGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_FUELGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_RADARGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_RADARGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_KPIGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_KPIGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_BARGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_BARGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_MEDIANGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_MEDIANGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);
	
	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_HISTOGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_HISTOGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_PANTOGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_PANTOGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_SCATTERGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_SCATTERGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_TRENDGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_TRENDGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_CONTOURGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_CONTOURGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

	ilk = insert_tool_group_item(glk, LINK_LAST);
	xsprintf(token, _T("%d"), IDA_PLOT_TOPOGGGRAM);
	set_tool_item_id(ilk, token);
	set_tool_item_title(ilk, ATTR_PLOT_TYPE_TOPOGGGRAM);
	set_tool_item_icon(ilk, GDI_ATTR_GIZMO_DATE);

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

void _MainFrame_CreateTreeBar(widget_t widget)
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
	set_status_item_title(ilk, _T("navibox"));
	set_status_item_width(ilk, DEF_TOUCH_SPAN * 6 + 1);

	statusctrl_attach(pdt->hStatusBar, ptrStatus);

	widget_show(pdt->hStatusBar, WS_SHOW_NORMAL);

	ilk = get_status_item(ptrStatus, _T("navibox"));
	statusctrl_get_item_rect(pdt->hStatusBar, ilk, &xr);

	//pdt->hNaviBox = navibox_create(pdt->hStatusBar, WD_STYLE_CONTROL, &xr);
	//widget_set_owner(pdt->hNaviBox, pdt->hStatusBar);
	//widget_show(pdt->hNaviBox, WS_SHOW_NORMAL);
}

void _MainFrame_DestroyToolBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if(!widget_is_valid(pdt->hToolBar)) return;

	LINKPTR ptrTool = toolctrl_detach(pdt->hToolBar);
	if (ptrTool) destroy_tool_doc(ptrTool);

	widget_destroy(pdt->hToolBar);
}

void _MainFrame_DestroyTitleBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if(!widget_is_valid(pdt->hTitleBar)) return;

	LINKPTR ptrTitle = titlectrl_detach(pdt->hTitleBar);
	if (ptrTitle) destroy_title_doc(ptrTitle);

	widget_destroy(pdt->hTitleBar);
}

void _MainFrame_DestroyTreeBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if(!widget_is_valid(pdt->hTreeBar)) return;

	LINKPTR ptrTree = treectrl_detach(pdt->hTreeBar);
	if (ptrTree) destroy_tree_doc(ptrTree);

	widget_destroy(pdt->hTreeBar);
}

void _MainFrame_DestroyStatusBar(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if(!widget_is_valid(pdt->hStatusBar)) return;

	LINKPTR ptrStatus = statusctrl_detach(pdt->hStatusBar);
	if (ptrStatus) destroy_status_doc(ptrStatus);

	widget_destroy(pdt->hStatusBar);
}

widget_t _MainFrame_CreatePanel(widget_t widget, const tchar_t* wclass)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_t hPanel = NULL;
	xrect_t xr = { 0 };

	link_t_ptr ptr_title, ilk;

	_MainFrame_CalcPanelBar(widget, &xr);

	tchar_t wname[RES_LEN + 1] = { 0 };

	if (compare_text(wclass, -1, PANEL_CLASS_OWNER_GIZMO, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("Gizmo"));

		hPanel = ownerctrl_create(_T("OwnerPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_GIZMOPANEL);
		widget_set_owner(hPanel, widget);
		ownerctrl_redraw(hPanel);
	}else if (compare_text(wclass, -1, PANEL_CLASS_OWNER_COLOR, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("Color"));

		hPanel = ownerctrl_create(_T("ColorPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_COLORPANEL);
		widget_set_owner(hPanel, widget);
		ownerctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_CALENDAR, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("Calendar"));

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
			xscpy(wname, _T("Note"));

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
			xscpy(wname, _T("Panel"));

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
			xscpy(wname, _T("Curve"));

		hPanel = curvectrl_create(_T("CurvePanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_CURVEPANEL);
		widget_set_owner(hPanel, widget);
		curvectrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_MODEL, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("Model"));

		hPanel = modelctrl_create(_T("ModelPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_MODELPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_anno = create_anno_doc();

		modelctrl_attach(hPanel, ptr_anno);
		modelctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_CALENDAR, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("calendar"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_CALENDAR, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 50);
		set_plot_style(ptr_plot, _T("font-size:10;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:radial;"), -1);
	
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_INDICATOR, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("indicator"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_INDICATOR, -1);
		set_plot_width(ptr_plot, 100);
		set_plot_height(ptr_plot, 50);
		set_plot_style(ptr_plot, _T("font-size:10;text-color:Orange;stroke-width:1;fill-color:Gray;stroke-color:LightSlateGray;fill-style:gradient;gradient:horz;"), -1);
		set_plot_matrix_rows(ptr_plot, 5);
		set_plot_matrix_cols(ptr_plot, 3);
		set_plot_matrix_data(ptr_plot, _T(" {[2, 1, 3, 5] [2, 1,3, 4][4, 3, 5, 7] [6, 5, 7, 8] [8, 5, 8, 10]}"), -1);
		set_plot_y_labels_token(ptr_plot, _T("physi,habit,diet,motion,chronic,therapy,sympt"), -1);
		set_plot_y_colors_token(ptr_plot, _T("LightSlateGray,CornflowerBlue,DarkSalmon,ForestGreen,Indigo,LightSteelBlue,Orange,PapayaWhip"), -1);
		set_plot_y_shapes_token(ptr_plot, _T("rect,rect,round,right-triangle,ellipse,bottom-triangle"), -1);
	
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_THERMOMETER, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("thermometer"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_THERMOMETER, -1);
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
	
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_BARGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("bargram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_BARGRAM, -1);
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
	
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_CONTRAGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("contragram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_CONTRAGRAM, -1);
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
	
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_BALANCEGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("balancegram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_BALANCEGRAM, -1);
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
	
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_KPIGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("kpigram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_KPIGRAM, -1);
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
		
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_TASKGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("taskgram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_TASKGRAM, -1);
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
		
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_SCATTERGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("scattergram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_SCATTERGRAM, -1);
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
		
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_MEDIANGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("mediangram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_MEDIANGRAM, -1);
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
	
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_HISTOGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("histogram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_HISTOGRAM, -1);
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
		
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_TRENDGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("trendgram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_TRENDGRAM, -1);
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
		
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_PANTOGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("pantogram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_PANTOGRAM, -1);
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
		
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_RADARGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("radargram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

		set_plot_type(ptr_plot, ATTR_PLOT_TYPE_RADARGRAM, -1);
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
		
		plotctrl_attach(hPanel, ptr_plot);
		plotctrl_redraw(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_FUELGRAM, -1, 0) == 0)
	{
		if (is_null(wname))
			xscpy(wname, _T("fuelgram"));

		hPanel = plotctrl_create(_T("PlotPanel"), WD_STYLE_CONTROL, &xr, widget);
		widget_set_user_id(hPanel, IDC_MAINFRAME_PLOTPANEL);
		widget_set_owner(hPanel, widget);

		LINKPTR ptr_plot = create_plot_doc();

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

widget_t _MainFrame_GetActivePanel(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	XDK_ASSERT(pdt != NULL);

	LINKPTR nlk = titlectrl_get_focus_item(pdt->hTitleBar);
	if (!nlk) return NULL;

	return (widget_t)get_title_item_delta(nlk);
}

/*******************************************************************************************************/
void MainFrame_ToolBar_OnLBClick(widget_t widget, NOTICE_TOOL* pnt)
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

void MainFrame_ToolBar_OnItemHover(widget_t widget, NOTICE_TOOL* pnt)
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
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_CALENDAR, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_INDICATOR, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_THERMOMETER, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_BALANCEGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_CONTRAGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_TASKGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_FUELGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_RADARGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_KPIGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_BARGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_MEDIANGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_HISTOGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_PANTOGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_SCATTERGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_TRENDGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_CONTOURGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_TOPOGGGRAM, -1, 0) == 0)
	{
		ptrDoc = plotctrl_fetch(hPanel);
	}

	widget_destroy(hPanel);

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
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_CALENDAR, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_INDICATOR, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_THERMOMETER, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_BALANCEGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_CONTRAGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_TASKGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_FUELGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_RADARGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_KPIGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_BARGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_MEDIANGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_HISTOGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_PANTOGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_SCATTERGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_TRENDGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_CONTOURGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
	else if (compare_text(wclass, -1, PANEL_CLASS_PLOT_TOPOGGGRAM, -1, 0) == 0)
	{
		destroy_plot_doc(ptrDoc);
	}
}

void MainFrame_TitleBar_OnItemChanging(widget_t widget, NOTICE_TITLE* pnt)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_t hPanel = (widget_t)get_title_item_delta(pnt->item);

	if (widget_is_valid(hPanel))
	{
		widget_show(hPanel, WS_SHOW_HIDE);
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

/*void MainFrame_UserPanel_OnCalc(widget_t win, PAGE_CALC* ppc)
{
	ppc->total_height = 8096;
	ppc->total_width = 4096;
	ppc->line_height = 10;
	ppc->line_width = 10;
}*/

void MainFrame_GizmoPanel_OnDraw(widget_t win, visual_t rdc)
{
	canvbox_t cb;
	xcolor_t xc;

	xpen_t xp;
	default_xpen(&xp);
	xbrush_t xb;
	default_xbrush(&xb);
	lighten_xbrush(&xb, DEF_HARD_DARKEN);

	canvas_t canv;
	drawing_interface ifc = { 0 };
	
	canv = widget_get_canvas(win);

	get_canvas_interface(canv, &ifc);

	widget_get_canv_rect(win, &cb);
	
	parse_xcolor(&xc, GDI_ATTR_RGB_LIGHTRED);

	test_gizmo(&ifc, &xc, (xrect_t*)&cb);
	
}

void MainFrame_ColorPanel_OnDraw(widget_t win, visual_t rdc)
{
	canvbox_t cb;
	xcolor_t xc;

	xpen_t xp;
	default_xpen(&xp);
	xbrush_t xb;
	default_xbrush(&xb);
	lighten_xbrush(&xb, DEF_HARD_DARKEN);

	canvas_t canv;
	drawing_interface ifc = { 0 };
	
	canv = widget_get_canvas(win);

	get_canvas_interface(canv, &ifc);

	widget_get_canv_rect(win, &cb);
	
	parse_xcolor(&xc, GDI_ATTR_RGB_LIGHTRED);

	test_color(&ifc, (xrect_t*)&cb);
	
}
/******************************************************************************************************/

int MainFrame_OnCreate(widget_t widget, void* data)
{
	MainFrameDelta* pdt;

	widget_hand_create(widget);

	widget_set_accel(widget, MAINFRAME_ACCEL, MAINFRAME_ACCEL_COUNT);

	pdt = (MainFrameDelta*)xmem_alloc(sizeof(MainFrameDelta));
	SETMAINFRAMEDELTA(widget, pdt);

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

	_MainFrame_CreateToolBar(widget);

	_MainFrame_CreateTitleBar(widget);

	_MainFrame_CreateStatusBar(widget);

	_MainFrame_CreateTreeBar(widget);

	return 0;
}

void MainFrame_OnDestroy(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

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

int MainFrame_OnClose(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if(widget_is_valid(pdt->hTitleBar))
	{
		LINKPTR ptrTitle = titlectrl_fetch(pdt->hTitleBar);
		LINKPTR plk;

		while (plk = titlectrl_get_focus_item(pdt->hTitleBar))
		{
			if (!titlectrl_delete_item(pdt->hTitleBar, plk))
				break;
		}

		if (get_title_item_count(ptrTitle))
			return 1;
	}

	return 0;
}

void MainFrame_OnSize(widget_t widget, int code, const xsize_t* pxs)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr;

	_MainFrame_CalcToolBar(widget, &xr);
	if(widget_is_valid(pdt->hToolBar))
	{
		widget_move(pdt->hToolBar, RECTPOINT(&xr));
		widget_size(pdt->hToolBar, RECTSIZE(&xr));
	}

	_MainFrame_CalcStatusBar(widget, &xr);
	if(widget_is_valid(pdt->hStatusBar))
	{
		widget_move(pdt->hStatusBar, RECTPOINT(&xr));
		widget_size(pdt->hStatusBar, RECTSIZE(&xr));
	}

	_MainFrame_CalcTreeBar(widget, &xr);
	if(widget_is_valid(pdt->hTreeBar))
	{
		widget_move(pdt->hTreeBar, RECTPOINT(&xr));
		widget_size(pdt->hTreeBar, RECTSIZE(&xr));
	}

	_MainFrame_CalcTitleBar(widget, &xr);
	if(widget_is_valid(pdt->hTitleBar))
	{
		widget_move(pdt->hTitleBar, RECTPOINT(&xr));
		widget_size(pdt->hTitleBar, RECTSIZE(&xr));
	}

	_MainFrame_CalcPanelBar(widget, &xr);

	if(widget_is_valid(pdt->hTitleBar))
	{
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
	}

	widget_erase(widget, NULL);
}

void MainFrame_OnScroll(widget_t widget, bool_t bHorz, int nLine)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_hand_scroll(widget, bHorz, nLine);
}

void MainFrame_OnMenuCommand(widget_t widget, int code, int cid, vword_t data)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_t hPanel = _MainFrame_GetActivePanel(widget);
	if (hPanel && !code)
	{
		if (widget_send_command(hPanel, code, cid, data))
			return;
	}

	switch (cid)
	{
	case IDA_OWNER_GIZMO:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_OWNER_GIZMO);
		break;
	case IDA_OWNER_COLOR:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_OWNER_COLOR);
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
	case IDA_PLOT_CALENDAR:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_CALENDAR);
		break;
	case IDA_PLOT_INDICATOR:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_INDICATOR);
		break;
	case IDA_PLOT_THERMOMETER:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_THERMOMETER);
		break;
	case IDA_PLOT_BALANCEGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_BALANCEGRAM);
		break;
	case IDA_PLOT_CONTRAGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_CONTRAGRAM);
		break;
	case IDA_PLOT_TASKGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_TASKGRAM);
		break;
	case IDA_PLOT_FUELGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_FUELGRAM);
		break;
	case IDA_PLOT_RADARGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_RADARGRAM);
		break;
	case IDA_PLOT_KPIGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_KPIGRAM);
		break;
	case IDA_PLOT_BARGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_BARGRAM);
		break;
	case IDA_PLOT_MEDIANGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_MEDIANGRAM);
		break;
	case IDA_PLOT_HISTOGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_HISTOGRAM);
		break;
	case IDA_PLOT_PANTOGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_PANTOGRAM);
		break;
	case IDA_PLOT_SCATTERGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_SCATTERGRAM);
		break;
	case IDA_PLOT_TRENDGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_TRENDGRAM);
		break;
	case IDA_PLOT_CONTOURGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_CONTOURGRAM);
		break;
	case IDA_PLOT_TOPOGGGRAM:
		_MainFrame_CreatePanel(widget, PANEL_CLASS_PLOT_TOPOGGGRAM);
		break;
	}
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
	else if (phdr->user == IDC_MAINFRAME_TREEBAR)
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
	else if (phdr->user == IDC_MAINFRAME_STATUSBAR)
	{
		NOTICE_STATUS* pnt = (NOTICE_STATUS*)phdr;
		switch (pnt->code)
		{
		case NC_STATUSLBCLK:
			break;
		}
	}
	else if (phdr->user == IDC_MAINFRAME_GIZMOPANEL)
	{
		NOTICE_OWNER* pnu = (NOTICE_OWNER*)phdr;
		switch (pnu->code)
		{
		case NC_OWNERCALC:
			//MainFrame_UserPanel_OnCalc(pnu->widget, (PAGE_CALC*)pnu->data);
			break;
		case NC_OWNERDRAW:
			MainFrame_GizmoPanel_OnDraw(pnu->widget, (visual_t)pnu->data);
			break;
		}
	}
	else if (phdr->user == IDC_MAINFRAME_COLORPANEL)
	{
		NOTICE_OWNER* pnu = (NOTICE_OWNER*)phdr;
		switch (pnu->code)
		{
		case NC_OWNERCALC:
			//MainFrame_UserPanel_OnCalc(pnu->widget, (PAGE_CALC*)pnu->data);
			break;
		case NC_OWNERDRAW:
			MainFrame_ColorPanel_OnDraw(pnu->widget, (visual_t)pnu->data);
			break;
		}
	}
}

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
		EVENT_ON_SCROLL(MainFrame_OnScroll)

		EVENT_ON_NOTICE(MainFrame_OnNotice)
		EVENT_ON_MENU_COMMAND(MainFrame_OnMenuCommand)

		
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

	color_mod_t clrs = {0};
    parse_xcolor(&clrs.clr_bkg, GDI_ATTR_RGB_WHITE);
    parse_xcolor(&clrs.clr_frg, GDI_ATTR_RGB_SLATE);
    parse_xcolor(&clrs.clr_txt, GDI_ATTR_RGB_DARKBLACK);
    parse_xcolor(&clrs.clr_msk, GDI_ATTR_RGB_BLACK);
    parse_xcolor(&clrs.clr_ico, GDI_ATTR_RGB_GRAY);
	
	widget_set_color_mode(widget, &clrs);

	widget_show(widget, WS_SHOW_NORMAL);

	widget_get_window_rect(widget, &xr);

	return widget;
}


