#include <xdl.h>
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

#define IDC_MAINFRAME				2999
#define IDC_MAINFRAME_EDITOR		3000

#define IDA_OPEN					10
#define IDA_SAVE					11

#define MAINFRAME_ACCEL_COUNT		2

accel_table_t	MAINFRAME_ACCEL[MAINFRAME_ACCEL_COUNT] = {
	KS_WITH_CONTROL, _T('O'), IDA_OPEN,
	KS_WITH_CONTROL, _T('s'), IDA_SAVE,
};

typedef struct tagMainFrameDelta{
	widget_t hEditor;

	bool_t bDirty;
	bool_t bMode;
}MainFrameDelta;

#define GETMAINFRAMEDELTA(widget) 			(MainFrameDelta*)widget_get_user_delta(widget)
#define SETMAINFRAMEDELTA(widget,ptd)		widget_set_user_delta(widget,(vword_t)ptd)

/*******************************************************************************************************/
void _MainFrame_CreateEditor(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	color_mod_t clrs = {0};
    parse_xcolor(&clrs.clr_bkg, GDI_ATTR_RGB_SNOWWHITE);
    parse_xcolor(&clrs.clr_frg, GDI_ATTR_RGB_SOFTBLACK);
    parse_xcolor(&clrs.clr_txt, GDI_ATTR_RGB_HARDBLACK);
    parse_xcolor(&clrs.clr_msk, GDI_ATTR_RGB_BLACK);
    parse_xcolor(&clrs.clr_ico, GDI_ATTR_RGB_SLATE);

	xrect_t xr = { 0 };

	widget_get_client_rect(widget, &xr);

	pdt->hEditor = editbox_create(widget, WD_STYLE_CONTROL | WD_STYLE_EDITOR, &xr);

	widget_set_user_id(pdt->hEditor, IDC_EDITBOX);
	widget_set_owner(pdt->hEditor, widget);

	widget_set_color_mode(pdt->hEditor, &clrs);

	widget_show(pdt->hEditor, WS_SHOW_NORMAL);

	editbox_set_text(pdt->hEditor, _T("Hello World!"));
}

void _MainFrame_DestroyEditor(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if(widget_is_valid(pdt->hEditor))
		widget_destroy(pdt->hEditor);
}

int MainFrame_OnCreate(widget_t widget, void* data)
{
	MainFrameDelta* pdt;

	widget_hand_create(widget);

	widget_set_accel(widget, MAINFRAME_ACCEL, 2);

	pdt = (MainFrameDelta*)xmem_alloc(sizeof(MainFrameDelta));
	SETMAINFRAMEDELTA(widget, pdt);

	_MainFrame_CreateEditor(widget);

	return 0;
}

void MainFrame_OnDestroy(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	_MainFrame_DestroyEditor(widget);

	xmem_free(pdt);

	widget_hand_destroy(widget);
}

int MainFrame_OnClose(widget_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_destroy(widget);

	message_quit(0);

	return 0;
}

void MainFrame_OnSize(widget_t widget, int code, const xsize_t* pxs)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr;

	if(widget_is_valid(pdt->hEditor))
	{
		widget_get_client_rect(widget, &xr);

		widget_move(pdt->hEditor, RECTPOINT(&xr));
		widget_size(pdt->hEditor, RECTSIZE(&xr));
		widget_paint(pdt->hEditor);
	}
}

void MainFrame_OnScroll(widget_t widget, bool_t bHorz, int nLine)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_hand_scroll(widget, bHorz, nLine);
}

void MainFrame_OnMenuCommand(widget_t widget, int code, int cid, vword_t data)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

}

void MainFrame_OnNotice(widget_t widget, LPNOTICE phdr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

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

		EVENT_ON_NC_IMPLEMENT
		EVENT_ON_DOCKER_IMPLEMENT

	SUBPROC_END_DISPATH

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
	widget_paint(widget);

	return widget;
}


