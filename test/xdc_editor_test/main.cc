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

	widget_do_main(g_main);

	xdc_process_uninit();

	xdk_process_uninit();

	return 0;
}

#define IDC_MAINFRAME				2999
#define IDC_MAINFRAME_EDITOR		3000

#define IDA_OPEN					10
#define IDA_SAVE					11

#define MAINFRAME_ACCEL_COUNT		2

accel_t	MAINFRAME_ACCEL[MAINFRAME_ACCEL_COUNT] = {
	KS_WITH_CONTROL, _T('O'), IDA_OPEN,
	KS_WITH_CONTROL, _T('s'), IDA_SAVE,
};

typedef struct tagMainFrameDelta{
	res_win_t hEditor;

	bool_t bDirty;
	bool_t bMode;
}MainFrameDelta;

#define GETMAINFRAMEDELTA(widget) 			(MainFrameDelta*)widget_get_user_delta(widget)
#define SETMAINFRAMEDELTA(widget,ptd)		widget_set_user_delta(widget,(vword_t)ptd)

/*******************************************************************************************************/
void _MainFrame_CreateEditor(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	xrect_t xr = { 0 };

	widget_get_client_rect(widget, &xr);

	pdt->hEditor = editbox_create(widget, WD_STYLE_CONTROL | WD_STYLE_EDITOR, &xr);

	widget_set_user_id(pdt->hEditor, IDC_EDITBOX);
	widget_set_owner(pdt->hEditor, widget);

	widget_show(pdt->hEditor, WS_SHOW_NORMAL);
}

void _MainFrame_DestroyEditor(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	if(widget_is_valid(pdt->hEditor))
		widget_destroy(pdt->hEditor);
}

int MainFrame_OnCreate(res_win_t widget, void* data)
{
	MainFrameDelta* pdt;

	widget_hand_create(widget);

	res_acl_t hac = create_accel_table(MAINFRAME_ACCEL, MAINFRAME_ACCEL_COUNT);

	widget_attach_accel(widget, hac);

	pdt = (MainFrameDelta*)xmem_alloc(sizeof(MainFrameDelta));
	SETMAINFRAMEDELTA(widget, pdt);

	_MainFrame_CreateEditor(widget);

	return 0;
}

void MainFrame_OnDestroy(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	res_acl_t hac = widget_get_accel(widget);
	if (hac)
		destroy_accel_table(hac);

	_MainFrame_DestroyEditor(widget);

	xmem_free(pdt);

	widget_hand_destroy(widget);
}

int MainFrame_OnClose(res_win_t widget)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_destroy(widget);

	//send_quit_message(0);

	return 0;
}

void MainFrame_OnSize(res_win_t widget, int code, const xsize_t* pxs)
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

void MainFrame_OnScroll(res_win_t widget, bool_t bHorz, int nLine)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

	widget_hand_scroll(widget, bHorz, nLine);
}

void MainFrame_OnMenuCommand(res_win_t widget, int code, int cid, vword_t data)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

}

void MainFrame_OnNotice(res_win_t widget, LPNOTICE phdr)
{
	MainFrameDelta* pdt = GETMAINFRAMEDELTA(widget);

}

res_win_t MainFrame_Create(const tchar_t* mname)
{
	res_win_t widget;
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


