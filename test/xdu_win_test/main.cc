#include <xdk.h>
#include <xdg.h>
#include <xdu.h>

if_context_t if_context = {0};
if_widget_t if_widget = {0};
widget_t g_main = 0;
vword_t g_timer = 0;


int pop_on_create(widget_t wt, void* param)
{
    printf("pop on_create\n");

    (*if_widget.pf_widget_post_command)(wt, 4, IDC_SELF, 100);
    
    return 0;
}

void pop_on_destroy(widget_t wt)
{
    printf("pop on_destroy\n");
}

void pop_on_lbutton_down(widget_t wt, const xpoint_t* ppt)
{
    printf("pop on_lbutton_down x:%d y:%d\n", ppt->x, ppt->y);

    widget_t par =  (*if_widget.pf_widget_get_owner)(wt);

    (*if_widget.pf_widget_send_command)(par, 1, 1000, 100);
}

void pop_on_lbutton_up(widget_t wt, const xpoint_t* ppt)
{
    printf("pop on_lbutton_up x:%d y:%d\n", ppt->x, ppt->y);

    widget_t par =  (*if_widget.pf_widget_get_parent)(wt);

   // (*if_widget.pf_widget_post_command)(par, 2, IDC_CHILD, 100);

    (*if_widget.pf_widget_close)(wt, 0);
}

void pop_on_self_command(widget_t wt, int code, vword_t data)
{
    printf("pop on_self_command code: %d \n", code);
}

void pop_on_paint(widget_t wt, visual_t rdc, const xrect_t* prt)
{
    printf("pop on_paint the rect is x:%d y:%d w:%d h:%d \n", prt->x, prt->y, prt->w, prt->h);

    xrect_t rt;
    (*if_widget.pf_widget_get_client_rect)(wt, &rt);
    visual_t ctx = (*if_context.pf_create_compatible_context)(rdc, rt.w, rt.h);

	xpen_t xp = { 0 };
	default_xpen(&xp);
	xscpy(xp.color, GDI_ATTR_RGB_DARKBLACK);

	xbrush_t xb = { 0 };
	default_xbrush(&xb);
	xscpy(xb.color, GDI_ATTR_RGB_SLATE);

    (*if_context.pf_gdi_draw_rect)(ctx, &xp, &xb, &rt);

    (*if_context.pf_render_context)(ctx, 0,0, rdc, 0, 0, rt.w, rt.h);

    (*if_context.pf_destroy_context)(ctx);
}
/****************************************************************************/
int sub_on_create(widget_t wt, void* param)
{
    xrect_t xr;
    (*if_widget.pf_widget_get_window_rect)(wt, &xr);

    printf("sub on_create at x:%d y:%d w:%d h:%d \n", xr.x, xr.y, xr.w, xr.h);

    (*if_widget.pf_widget_post_command)(wt, 4, IDC_SELF, 100);
    
    return 0;
}

void sub_on_destroy(widget_t wt)
{
    printf("sub on_destroy\n");
}

void sub_on_paint(widget_t wt, visual_t rdc, const xrect_t* prt)
{
    printf("sub on_paint the rect is x:%d y:%d w:%d h:%d \n", prt->x, prt->y, prt->w, prt->h);

    xrect_t rt;
    (*if_widget.pf_widget_get_client_rect)(wt, &rt);
    visual_t ctx = (*if_context.pf_create_compatible_context)(rdc, rt.w, rt.h);

	xpen_t xp = { 0 };
	default_xpen(&xp);
	xscpy(xp.color, GDI_ATTR_RGB_DARKBLACK);

	xbrush_t xb = { 0 };
	default_xbrush(&xb);
	xscpy(xb.color, GDI_ATTR_RGB_GREEN);

    (*if_context.pf_gdi_draw_rect)(ctx, &xp, &xb, &rt);

    (*if_context.pf_render_context)(ctx, 0,0, rdc, 0, 0, rt.w, rt.h);

    (*if_context.pf_destroy_context)(ctx);
}

void sub_on_mouse_move(widget_t wt, dword_t ms, const xpoint_t* ppt)
{
    if(ms & MS_WITH_LBUTTON)
        printf("sub on_mouse_move x:%d y:%d with lbutton\n", ppt->x, ppt->y);
    else if(ms & MS_WITH_RBUTTON)
        printf("sub on_mouse_move x:%d y:%d with rbutton\n", ppt->x, ppt->y);
    else
        printf("sub on_mouse_move x:%d y:%d\n", ppt->x, ppt->y);
}
/****************************************************************************/

int child_on_create(widget_t wt, void* param)
{
    xrect_t xr;
    (*if_widget.pf_widget_get_window_rect)(wt, &xr);

    printf("child on_create at x:%d y:%d w:%d h:%d \n", xr.x, xr.y, xr.w, xr.h);
    
    if_dispatch_t ev = {0};

    ev.pf_on_create = sub_on_create;
	ev.pf_on_destroy = sub_on_destroy;
    ev.pf_on_paint = sub_on_paint;
    ev.pf_on_mouse_move = sub_on_mouse_move;

    xr.x = 50;
    xr.y = 50;
    xr.w = 100;
    xr.h = 100;

    widget_t sub = (*if_widget.pf_widget_create)(_T("sub"),WD_STYLE_CONTROL,&xr,wt,&ev);
    (*if_widget.pf_widget_set_owner)(sub, wt);
    (*if_widget.pf_widget_set_user_id)(sub, 2000);
    (*if_widget.pf_widget_show)(sub, 0);

    return 0;
}

void child_on_destroy(widget_t wt)
{
    printf("child on_destroy\n");

    widget_t sub = (*if_widget.pf_widget_get_child)(wt, 2000);
    if(sub) (*if_widget.pf_widget_destroy)(sub);
}

void child_on_mouse_move(widget_t wt, dword_t ms, const xpoint_t* ppt)
{
    if(ms & MS_WITH_LBUTTON)
        printf("child on_mouse_move x:%d y:%d with lbutton\n", ppt->x, ppt->y);
    else if(ms & MS_WITH_RBUTTON)
        printf("child on_mouse_move x:%d y:%d with rbutton\n", ppt->x, ppt->y);
    else
        printf("child on_mouse_move x:%d y:%d\n", ppt->x, ppt->y);
}

void child_on_mouse_hover(widget_t wt, dword_t ms, const xpoint_t* ppt)
{
    if(ms & MS_WITH_LBUTTON)
        printf("child on_mouse_hover x:%d y:%d with lbutton\n", ppt->x, ppt->y);
    else if(ms & MS_WITH_RBUTTON)
        printf("child on_mouse_hover x:%d y:%d with rbutton\n", ppt->x, ppt->y);
    else
        printf("child on_mouse_hover x:%d y:%d\n", ppt->x, ppt->y);
}

void child_on_mouse_enter(widget_t wt, dword_t ms, const xpoint_t* ppt)
{
    if(ms & MS_WITH_LBUTTON)
        printf("child on_mouse_enter x:%d y:%d with lbutton\n", ppt->x, ppt->y);
    else if(ms & MS_WITH_RBUTTON)
        printf("child on_mouse_enter x:%d y:%d with rbutton\n", ppt->x, ppt->y);
    else
        printf("child on_mouse_enter x:%d y:%d\n", ppt->x, ppt->y);
}

void child_on_mouse_leave(widget_t wt, dword_t ms, const xpoint_t* ppt)
{
    if(ms & MS_WITH_LBUTTON)
        printf("child on_mouse_leave x:%d y:%d with lbutton\n", ppt->x, ppt->y);
    else if(ms & MS_WITH_RBUTTON)
        printf("child on_mouse_leave x:%d y:%d with rbutton\n", ppt->x, ppt->y);
    else
        printf("child on_mouse_leave x:%d y:%d\n", ppt->x, ppt->y);
}

static NOTICE nt2 = {0};

void child_on_lbutton_down(widget_t wt, const xpoint_t* ppt)
{
    printf("child on_lbutton_down x:%d y:%d\n", ppt->x, ppt->y);

    (*if_widget.pf_widget_set_focus)(wt);

    widget_t par =  (*if_widget.pf_widget_get_parent)(wt);

    nt2.user = 1001;
    nt2.code = 6;
    nt2.widget = wt;

    (*if_widget.pf_widget_post_notice)(par, &nt2);
    printf("child post notice\n");    

    NOTICE nt = {0};
    nt.user = 1000;
    nt.code = 5;
    nt.widget = wt;

   int n = (*if_widget.pf_widget_send_notice)(par, &nt);
    printf("child send notice return %d \n", n);

   (*if_widget.pf_widget_set_capture)(wt, 1);

   (*if_widget.pf_widget_set_cursor)(wt, CURSOR_HAND);

   (*if_widget.pf_widget_show_caret)(wt, ppt->x, ppt->y);
}

void child_on_lbutton_up(widget_t wt, const xpoint_t* ppt)
{
    printf("child on_lbutton_up x:%d y:%d\n", ppt->x, ppt->y);

    (*if_widget.pf_widget_set_cursor)(wt, 0);

    (*if_widget.pf_widget_set_capture)(wt, 0);

    (*if_widget.pf_widget_erase)(wt, NULL);
}

void child_on_lbutton_dbclick(widget_t wt, const xpoint_t* ppt)
{
    printf("child on_lbutton_dbclick x:%d y:%d\n", ppt->x, ppt->y);

    nt2.user = 1003;
    nt2.code = 7;
    nt2.widget = wt;

    (*if_widget.pf_widget_post_notice)(wt, &nt2);
    
    printf("child post notice\n");    
}

void child_on_rbutton_down(widget_t wt, const xpoint_t* ppt)
{
    printf("child on_rbutton_down x:%d y:%d\n", ppt->x, ppt->y);
}

void child_on_rbutton_up(widget_t wt, const xpoint_t* ppt)
{
    printf("child on_rbutton_up x:%d y:%d\n", ppt->x, ppt->y);

    if_dispatch_t ev = {0};

    ev.pf_on_create = pop_on_create;
	ev.pf_on_destroy = pop_on_destroy;
    ev.pf_on_lbutton_down = pop_on_lbutton_down;
    ev.pf_on_lbutton_up = pop_on_lbutton_up;
    ev.pf_on_self_command = pop_on_self_command;
    ev.pf_on_paint = pop_on_paint;

    xrect_t xr;
    xr.x = ppt->x;
    xr.y = ppt->y;
    xr.w = 100;
    xr.h = 200;

    (*if_widget.pf_widget_client_to_screen)(wt, RECTPOINT(&xr));

    widget_t pop = (*if_widget.pf_widget_create)(_T("popup"),WD_STYLE_MENU,&xr,g_main,&ev);

    (*if_widget.pf_widget_set_owner)(pop, wt);

    (*if_widget.pf_widget_show)(pop, 0);

    (*if_widget.pf_widget_do_track)(pop);
}

void child_on_keydown(widget_t wt, dword_t ks, int key)
{
    if(ks & KS_WITH_CONTROL)
        printf("child on_key_down keycode:%02x with control\n", key);
    else if(ks & KS_WITH_SHIFT)
        printf("child on_key_down keycode:%02x with shift\n", key);
    else
        printf("child on_key_down keycode:%02x\n", key);

    switch(key)
    {
    case KEY_BACK:
        printf("child on_key_back\n");
        break;
    case KEY_TAB:
        printf("child on_key_tab\n");
        break;
    case KEY_ENTER:
        printf("child on_key_enter\n");
        break;
    case KEY_ESC:
        printf("child on_key_escape\n");
        break;
    case KEY_PAGEUP:
        printf("child on_key_pageup\n");
        break;
    case KEY_PAGEDOWN:
        printf("child on_key_pagedown\n");
        break;
    case KEY_HOME:
        printf("child on_key_home\n");
        break;
    case KEY_END:
        printf("child on_key_end\n");
        break;
    case KEY_LEFT:
        printf("child on_key_left\n");
        break;
    case KEY_RIGHT:
        printf("child on_key_right\n");
        break;
    case KEY_UP:
        printf("child on_key_up\n");
        break;
    case KEY_DOWN:
        printf("child on_key_down\n");
        break;
    }
}

void child_on_wchar(widget_t wt, wchar_t wch)
{
    schar_t str[10] = { 0 };
    ucs_byte_to_mbs(wch, str);

    printf("child on_char:%s\n", str);
}

void child_on_set_focus(widget_t wt, widget_t from)
{
    printf("child on_set_focus \n");

    (*if_widget.pf_widget_create_caret)(wt, 2, 20);

    (*if_widget.pf_widget_show_caret)(wt, 10, 10);
}

void child_on_kill_focus(widget_t wt, widget_t to)
{
    printf("child on_kill_focus \n");

    (*if_widget.pf_widget_destroy_caret)(wt);
}

void child_on_menu_command(widget_t wt, int code, int cid, vword_t data)
{
    printf("child on_menu_command code: %d cid: %d \n", code, cid);
}

void child_on_parent_command(widget_t, int code, vword_t data)
{
    printf("child on_parent_command code: %d \n", code);
}

void child_on_paint(widget_t wt, visual_t rdc, const xrect_t* prt)
{
    printf("child on_paint the rect is x:%d y:%d w:%d h:%d \n", prt->x, prt->y, prt->w, prt->h);

    xrect_t rt;
    (*if_widget.pf_widget_get_client_rect)(wt, &rt);
    visual_t ctx = (*if_context.pf_create_compatible_context)(rdc, rt.w, rt.h);

	xpen_t xp = { 0 };
	default_xpen(&xp);
	xscpy(xp.color, GDI_ATTR_RGB_DARKBLACK);

	xbrush_t xb = { 0 };
	default_xbrush(&xb);
	xscpy(xb.color, GDI_ATTR_RGB_HARDBLACK);

    (*if_context.pf_gdi_draw_rect)(ctx, &xp, &xb, &rt);

	xrect_t xr;
	xr.x = 10;
	xr.y = 10;
	xr.w = rt.w / 2;
	xr.h = rt.h / 2;

    xscpy(xp.color, GDI_ATTR_RGB_SOFTWHITE);
    xscpy(xb.color, GDI_ATTR_RGB_SOFTBLACK);
    //(*if_context.pf_gdi_draw_rect)(ctx, &xp, &xb, &xr);

    xpoint_t xp1,xp2,xp3,xp4;
    xp1.x = 10;
    xp1.y = 10;
    xp2.x = 100;
	xp2.y = 20;
    xp3.x = 30;
    xp3.y = 60;
    xscpy(xp.color, GDI_ATTR_RGB_SLATE);
   //(*if_context.pf_gdi_draw_line)(ctx, &xp, &xp1, &xp2);
   //(*if_context.pf_gdi_draw_line)(ctx, &xp, &xp2, &xp3);
   //(*if_context.pf_gdi_draw_line)(ctx, &xp, &xp3, &xp1);

   xpoint_t pt[5];
   pt[0].x = 40;
   pt[0].y = 40;
   pt[1].x = 100;
   pt[1].y = 60;
   pt[2].x = 80;
   pt[2].y = 80;
   pt[3].x = 20;
   pt[3].y = 60;
   pt[4].x = 40;
   pt[4].y = 40;
   xscpy(xp.color, GDI_ATTR_RGB_SLATE);
   //(*if_context.pf_gdi_draw_polyline)(ctx, &xp, pt, 4);

   xscpy(xb.color, GDI_ATTR_RGB_YELLOW);
   //(*if_context.pf_gdi_draw_polygon)(ctx, &xp, &xb, pt, 4);

   xr.x = 50;
   xr.y = 50;
   xr.w = 90;
   xr.h = 90;
   xsize_t xs1;
   xs1.w = 10;
   xs1.h = 10;
   xscpy(xb.color, GDI_ATTR_RGB_SOFTRED);
   //(*if_context.pf_gdi_draw_round)(ctx, &xp, &xb, &xr, &xs1);

   xr.x = 50;
   xr.y = 50;
   xr.w = 80;
   xr.h = 100;
   xscpy(xb.color, GDI_ATTR_RGB_SOFTRED);
   //(*if_context.pf_gdi_draw_ellipse)(ctx, &xp, &xb, &xr);

    xp1.x = 100;
    xp1.y = 100;
    xp2.x = 50;
    xp2.y = 150;

    xs1.w = 50;
    xs1.h = 50;
    xscpy(xp.size,_T("1"));
    xscpy(xp.color, GDI_ATTR_RGB_YELLOW);
   //(*if_context.pf_gdi_draw_arc)(ctx, &xp, &xp1, &xp2, &xs1, 1, 0);
   //(*if_context.pf_gdi_draw_line)(ctx, &xp, &xp1, &xp2);

   xr.x = 100;
   xr.y = 50;
   xr.w = 100;
   xr.h = 120;
   xscpy(xp.color, GDI_ATTR_RGB_GREEN);
   xscpy(xb.color, GDI_ATTR_RGB_BLUE);
   //(*if_context.pf_gdi_draw_pie)(ctx, &xp, &xb, &xr, XPI, XPI * 7 / 4);

    pt[0].x = 20;
    pt[0].y = 100;
    pt[1].x = 60;
    pt[1].y = 40;
    pt[2].x = 100;
    pt[2].y = 80;
	xscpy(xp.color, GDI_ATTR_RGB_SLATE);
	//(*if_context.pf_gdi_draw_polyline)(ctx, &xp, pt, 3);
    //(*if_context.pf_gdi_draw_curve)(ctx, &xp, pt, 3);

    pt[0].x = 20;
    pt[0].y = 100;
    pt[1].x = 60;
    pt[1].y = 40;
    pt[2].x = 100;
    pt[2].y = 50;
    pt[3].x = 120;
    pt[3].y = 90;
	xscpy(xp.color, GDI_ATTR_RGB_SLATE);
	//(*if_context.pf_gdi_draw_polyline)(ctx, &xp, pt, 4);
	//(*if_context.pf_gdi_draw_bezier)(ctx, &xp, &pt[0], &pt[1], &pt[2], &pt[3]);

	tchar_t aa[20] = { 0 };
	xpoint_t pa[50] = { 0 };

	int i = 0;
	int n = 0;
	int feed = 12;

	xr.x = 10;
	xr.y = 10;
	xr.w = 96;
	xr.h = 30;

	aa[i] = _T('M');
	pa[n].x = xr.x;
	pa[n].y = xr.y + feed;
	i++;
	n++;

	aa[i] = _T('A');
	pa[n].x = 1;
	pa[n].y = 0;
	pa[n + 1].x = feed;
	pa[n + 1].y = feed;
	pa[n + 2].x = xr.x + feed;
	pa[n + 2].y = xr.y;
	i++;
	n += 3;

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

    aa[i] = _T('L');
	pa[n].x = xr.x;
	pa[n].y = xr.y + feed;
	i++;
	n++;

	aa[i] = _T('Z');
	i++;

	xscpy(xp.color, GDI_ATTR_RGB_SLATE);
	//(*if_context.pf_gdi_draw_path)(ctx, &xp, NULL, aa, pa, n);

	xcolor_t brim_color, core_color;
	parse_xcolor(&brim_color, GDI_ATTR_RGB_GRAY);
	parse_xcolor(&core_color, GDI_ATTR_RGB_BLACK);
	lighten_xcolor(&core_color, -5);

	xr.x = 2;
	xr.y = 2;
	xr.w = 96;
	xr.h = 96;
	//(*if_context.pf_gdi_gradient_rect)(ctx, &brim_color, &core_color, GDI_ATTR_GRADIENT_HORZ, &xr);

    xr.x = 10;
	xr.y = 10;
	xr.w = 50;
	xr.h = 50;
    //(*if_context.pf_gdi_exclude_rect)(ctx, &xr);
    xr.x -= 1;
    xr.y -= 1;
    xr.w += 2;
    xr.h += 2;
    xscpy(xp.color, GDI_ATTR_RGB_SOFTWHITE);
    //(*if_context.pf_gdi_draw_rect)(ctx, &xp, NULL, &xr);
    xr.x = 30;
	xr.y = 30;
	xr.w = 50;
	xr.h = 50;
    xscpy(xb.color, GDI_ATTR_RGB_SOFTBLACK);
    //(*if_context.pf_gdi_draw_rect)(ctx, &xp, &xb, &xr);

    xr.x = 40;
	xr.y = 40;
	xr.w = 50;
	xr.h = 50;
    //(*if_context.pf_gdi_inclip_rect)(ctx, &xr);
    xr.x += 1;
    xr.y += 1;
    xr.w -= 2;
    xr.h -= 2;
    xscpy(xp.color, GDI_ATTR_RGB_SOFTWHITE);
    xscpy(xb.color, GDI_ATTR_RGB_SOFTBLACK);
    //(*if_context.pf_gdi_draw_rect)(ctx, &xp, NULL, &xr);
    xr.x = 30;
	xr.y = 30;
	xr.w = 50;
	xr.h = 50;
    //(*if_context.pf_gdi_draw_rect)(ctx, &xp, &xb, &xr);

    xr.x = 10;
	xr.y = 10;
	xr.w = 90;
	xr.h = 90;
    //(*if_context.pf_gdi_invert_rect)(ctx, &xr);

    xr.x = 20;
	xr.y = 20;
    xr.w = 120;
	xr.h = 120;
	xcolor_t xc = { 0 };
	parse_xcolor(&xc, GDI_ATTR_RGB_RED);
	//(*if_context.pf_gdi_alphablend_rect)(ctx, &xc, &xr, 128);

    xfont_t xf = {0};
    default_textor_xfont(&xf);
    xscpy(xf.size, _T("13"));

    xface_t xa = {0};
    default_xface(&xa);
    xscpy(xa.text_color, GDI_ATTR_RGB_LIGHTCYAN);

    const tchar_t* token = _T("您好，世界！");
    
    xsize_t xs = {0};
    (*if_context.pf_gdi_font_size)(ctx, &xs);
	(*if_context.pf_gdi_text_size)(ctx, token, -1, &xs);
	xp1.x = 10;
	xp1.y = 10;
	xp2.x = xp1.x + xs.w;
	xp2.y = 10;

	(*if_context.pf_gdi_draw_line)(ctx, &xp, &xp1, &xp2);
	(*if_context.pf_gdi_text_out)(ctx, &xa, &xp1, token, -1);

    xr.x = 10;
    xr.y = 20;
    //(*if_context.pf_gdi_text_size)(ctx, &xf, _T("Hello World!"), -1, RECTSIZE(&xr));
    //(*if_context.pf_gdi_draw_rect)(ctx, &xp, &xb, &xr);
    //(*if_context.pf_gdi_draw_text)(ctx, &xf, &xa, &xr, _T("Hello World!"), -1);

    xr.x = 10;
    xr.y = 10;
    xr.w = 150;
    xr.h = 100;
    //(*if_context.pf_gdi_draw_rect)(ctx, &xp, &xb, &xr);
    xscpy(xa.text_align, GDI_ATTR_TEXT_ALIGN_CENTER);
    xscpy(xa.line_align, GDI_ATTR_TEXT_ALIGN_CENTER);
    //(*if_context.pf_gdi_draw_text)(ctx, &xf, &xa, &xr, _T("Hello World!"), -1);

    parse_xcolor(&xc, GDI_ATTR_RGB_RED);
	xcolor_t xc_back;
	parse_xcolor(&xc_back, GDI_ATTR_RGB_YELLOW);
    bitmap_t bmp = NULL;
	bmp = (*if_context.pf_create_color_bitmap)(ctx, &xc, 32, 32);
	//bmp = (*if_context.pf_create_pattern_bitmap)(ctx, &xc, &xc_back, 5, 5);
	//bmp = (*if_context.pf_create_gradient_bitmap)(ctx, &xc, &xc_back, 50, 50, GDI_ATTR_GRADIENT_VERT);

	byte_t code[10] = { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' };
	byte_t bar[1000] = { 0 };
	dword_t bar_len = code128_encode(code, 10, bar, 1000);
	//bmp = (*if_context.pf_create_code128_bitmap)(ctx, &xc, &xc_back, bar, bar_len);
	int bar_rows, bar_cols;
	//bar_len = pdf417_encode(code, 10, bar, 1000, &bar_rows, &bar_cols);
	//bmp = (*if_context.pf_create_pdf417_bitmap)(ctx, &xc, &xc_back, bar, bar_rows, bar_cols);
	//bar_len = qr_encode(code, 10, bar, 1000, &bar_rows, &bar_cols);
	//bmp = (*if_context.pf_create_qrcode_bitmap)(ctx, &xc, &xc_back, bar, bar_rows, bar_cols);
    if(bmp)
    {
		int w, h;
		(*if_context.pf_get_bitmap_size)(bmp, &w, &h);
        xr.x = 10;
        xr.y = 50;
        xr.w = w;
        xr.h = h;

       (*if_context.pf_gdi_draw_rect)(ctx, &xp, NULL, &xr);

       (*if_context.pf_gdi_draw_bitmap)(ctx, bmp, RECTPOINT(&xr));
    
        (*if_context.pf_destroy_bitmap)(bmp);
        bmp = NULL;
    }

    //bmp = (*if_context.pf_create_storage_bitmap)(ctx, _T("./title.jpg"));
	//bmp = (*if_context.pf_create_storage_bitmap)(ctx, _T("./draw.bmp"));
    if(bmp)
    {
        xr.x = 10;
        xr.y = 10;
        xr.w = 200;
        xr.h = 200;

       //(*if_context.pf_gdi_draw_bitmap)(ctx, bmp, RECTPOINT(&xr));

       parse_xcolor(&xc, GDI_ATTR_RGB_BLACK);
       (*if_context.pf_gdi_draw_image)(ctx, bmp, &xc, &xr);

        (*if_context.pf_destroy_bitmap)(bmp);
        bmp = NULL;
    }

    (*if_context.pf_render_context)(ctx, 0,0, rdc, 0, 0, rt.w, rt.h);

    (*if_context.pf_destroy_context)(ctx);
}
/**********************************************************************************/

int dlg_on_create(widget_t wt, void* param)
{
    printf("dlg on_create\n");

    return 0;
}

void dlg_on_destroy(widget_t wt)
{
    printf("dlg on_destroy\n");
}

int dlg_on_close(widget_t wt)
{
    printf("dlg on_closein\n");

    return 0;
}

void dlg_on_lbutton_dbclick(widget_t wt, const xpoint_t* ppt)
{
    printf("dlg on_lbutton_dbclick x:%d y:%d\n", ppt->x, ppt->y);

    (*if_widget.pf_widget_close)(wt, 0);   
}
/**********************************************************************************/

int main_on_create(widget_t wt, void* param)
{
    xrect_t xr;
    (*if_widget.pf_widget_get_window_rect)(wt, &xr);

    printf("main on_create at x:%d y:%d w:%d h:%d \n", xr.x, xr.y, xr.w, xr.h);

    color_mod_t clrs = {0};
    parse_xcolor(&clrs.clr_bkg, GDI_ATTR_RGB_HARDBLACK);
    parse_xcolor(&clrs.clr_frg, GDI_ATTR_RGB_SNOWWHITE);
    parse_xcolor(&clrs.clr_txt, GDI_ATTR_RGB_LIGHTWHITE);
    parse_xcolor(&clrs.clr_msk, GDI_ATTR_RGB_BLACK);
    parse_xcolor(&clrs.clr_ico, GDI_ATTR_RGB_SNOWWHITE);

    if_dispatch_t ev = {0};

    ev.pf_on_create = child_on_create;
	ev.pf_on_destroy = child_on_destroy;
    ev.pf_on_mouse_move = child_on_mouse_move;
	ev.pf_on_mouse_hover = child_on_mouse_hover;
    ev.pf_on_mouse_enter = child_on_mouse_enter;
	ev.pf_on_mouse_leave = child_on_mouse_leave;
    ev.pf_on_lbutton_down = child_on_lbutton_down;
    ev.pf_on_lbutton_up = child_on_lbutton_up;
	ev.pf_on_lbutton_dbclick = child_on_lbutton_dbclick;
    ev.pf_on_rbutton_down = child_on_rbutton_down;
	ev.pf_on_rbutton_up = child_on_rbutton_up;
	ev.pf_on_keydown = child_on_keydown;
    ev.pf_on_wchar = child_on_wchar;
	ev.pf_on_set_focus = child_on_set_focus;
	ev.pf_on_kill_focus = child_on_kill_focus;
	ev.pf_on_paint = child_on_paint;
	ev.pf_on_menu_command = child_on_menu_command;
	ev.pf_on_parent_command = child_on_parent_command;

    xr.x = 50;
	xr.y = 50;
	xr.w = 300;
	xr.h = 200;

    widget_t child = (*if_widget.pf_widget_create)(_T("child"),WD_STYLE_CHILD,&xr,wt,&ev);

    (*if_widget.pf_widget_set_user_id)(child, 1000);

    (*if_widget.pf_widget_set_color_mode)(child, &clrs);

    (*if_widget.pf_widget_show)(child, WS_SHOW_NORMAL);

   //(*if_widget.pf_widget_enable)(child, 0);

   (*if_widget.pf_widget_get_window_rect)(child, &xr);
    printf("child screen position at: x:%d y:%d w:%d h:%d\n", xr.x, xr.y, xr.w, xr.h);

    (*if_widget.pf_widget_screen_to_client)(child, RECTPOINT(&xr));
    printf("child client position at: x:%d y:%d w:%d h:%d\n", xr.x, xr.y, xr.w, xr.h);

    //g_timer = (*if_widget.pf_widget_set_timer)(wt, 3000);

    return 0;
}

int main_on_close(widget_t wt)
{
    printf("main on_closein\n");

    return 0;
}

void main_on_destroy(widget_t wt)
{
    printf("main on_destroy\n");

    if(g_timer)
    {
        (*if_widget.pf_widget_kill_timer)(wt, g_timer);
    }

    widget_t child = (*if_widget.pf_widget_get_child)(wt, 1000);
    if(child) (*if_widget.pf_widget_destroy)(child);
}

void main_on_lbutton_down(widget_t wt, const xpoint_t* ppt)
{
    printf("main on_lbutton_down x:%d y:%d\n", ppt->x, ppt->y);
}

void main_on_lbutton_up(widget_t wt, const xpoint_t* ppt)
{
    printf("main on_lbutton_up x:%d y:%d\n", ppt->x, ppt->y);

    /*widget_t cld = (*if_widget.pf_widget_get_child)(wt, 1000);
    if(cld)
    {
        (*if_widget.pf_widget_post_command)(cld, 3, IDC_PARENT, 100);
    }*/
}

void main_on_lbutton_dbclick(widget_t wt, const xpoint_t* ppt)
{
    printf("main on_lbutton_dbclick x:%d y:%d\n", ppt->x, ppt->y);

   //(*if_widget.pf_widget_post_key)(wt, KEY_ENTER);
}

void main_on_rbutton_down(widget_t wt, const xpoint_t* ppt)
{
    printf("main on_rbutton_down x:%d y:%d\n", ppt->x, ppt->y);
    //(*if_widget.pf_widget_post_wchar)(wt, L'��');
}

void main_on_rbutton_up(widget_t wt, const xpoint_t* ppt)
{
    printf("main on_rbutton_up x:%d y:%d\n", ppt->x, ppt->y);

    if_dispatch_t ev = {0};

    ev.pf_on_create = dlg_on_create;
	ev.pf_on_destroy = dlg_on_destroy;
    ev.pf_on_close = dlg_on_close;
    ev.pf_on_lbutton_dbclick = dlg_on_lbutton_dbclick;

    xrect_t xr;
    xr.x = ppt->x;
    xr.y = ppt->y;
    xr.w = 200;
    xr.h = 100;

    (*if_widget.pf_widget_client_to_screen)(wt, RECTPOINT(&xr));

    widget_t dlg = (*if_widget.pf_widget_create)(_T("dialog"),(WD_STYLE_DIALOG & (~WD_STYLE_OWNERNC)),&xr,g_main,&ev);

    (*if_widget.pf_widget_show)(dlg, 0);

    (*if_widget.pf_widget_set_owner)(dlg, wt);

    (*if_widget.pf_widget_do_modal)(dlg);
}

void main_on_mouse_move(widget_t wt, dword_t ms, const xpoint_t* ppt)
{
    if(ms & MS_WITH_LBUTTON)
        printf("main on_mouse_move x:%d y:%d with lbutton\n", ppt->x, ppt->y);
    else if(ms & MS_WITH_RBUTTON)
        printf("main on_mouse_move x:%d y:%d with rbutton\n", ppt->x, ppt->y);
    else
        printf("main on_mouse_move x:%d y:%d\n", ppt->x, ppt->y);
}

void main_on_mouse_enter(widget_t wt, dword_t ms, const xpoint_t* ppt)
{
    if(ms & MS_WITH_LBUTTON)
        printf("main on_mouse_enter x:%d y:%d with lbutton\n", ppt->x, ppt->y);
    else if(ms & MS_WITH_RBUTTON)
        printf("main on_mouse_enter x:%d y:%d with rbutton\n", ppt->x, ppt->y);
    else
        printf("main on_mouse_enter x:%d y:%d\n", ppt->x, ppt->y);
}

void main_on_mouse_leave(widget_t wt, dword_t ms, const xpoint_t* ppt)
{
    if(ms & MS_WITH_LBUTTON)
        printf("main on_mouse_leave x:%d y:%d with lbutton\n", ppt->x, ppt->y);
    else if(ms & MS_WITH_RBUTTON)
        printf("main on_mouse_leave x:%d y:%d with rbutton\n", ppt->x, ppt->y);
    else
        printf("main on_mouse_leave x:%d y:%d\n", ppt->x, ppt->y);
}

void main_on_mouse_hover(widget_t wt, dword_t ms, const xpoint_t* ppt)
{
    if(ms & MS_WITH_LBUTTON)
        printf("main on_mouse_hover x:%d y:%d with lbutton\n", ppt->x, ppt->y);
    else if(ms & MS_WITH_RBUTTON)
        printf("main on_mouse_hover x:%d y:%d with rbutton\n", ppt->x, ppt->y);
    else
        printf("main on_mouse_hover x:%d y:%d\n", ppt->x, ppt->y);
}

void main_on_whell(widget_t wt, bool_t horz, int delta)
{
    if(horz)
        printf("main on_whell_horz delta:%d\n", delta);
    else
       printf("main on_whell_vert delta:%d\n", delta);

    (*if_widget.pf_widget_scroll)(g_main, horz, (delta < 0)? -10 : 10);
}

void main_on_scroll(widget_t wt, bool_t horz, int pos)
{
    if(horz)
        printf("main on_scroll_horz position:%d\n", pos);
    else
       printf("main on_scroll_vert position:%d\n", pos);

    xrect_t xr;
	widget_t child = (*if_widget.pf_widget_get_child)(wt, 1000);
	if (child)
	{
		(*if_widget.pf_widget_get_window_rect)(child, &xr);
		(*if_widget.pf_widget_screen_to_client)(child, RECTPOINT(&xr));

        printf("child org position: x:%d y:%d w:%d h:%d\n", xr.x, xr.y, xr.w, xr.h);
	}

    scroll_t sc;
    (*if_widget.pf_widget_get_scroll_info)(wt, horz, &sc);
    if(sc.pos + pos >= sc.min && sc.pos + pos <= sc.max)
    {
        sc.pos += pos;
        (*if_widget.pf_widget_set_scroll_info)(wt, horz, &sc);
    }

    if (child)
	{
        (*if_widget.pf_widget_get_window_rect)(child, &xr);
        (*if_widget.pf_widget_screen_to_client)(child, RECTPOINT(&xr));

        printf("child new position: x:%d y:%d w:%d h:%d\n", xr.x, xr.y, xr.w, xr.h);
	}

    if(horz)
        printf("main horz scroll: min:%d pos:%d max:%d\n", sc.min, sc.pos, sc.max);
    else
        printf("main vert scroll: min:%d pos:%d max:%d\n", sc.min, sc.pos, sc.max);
}

void main_on_keydown(widget_t wt, dword_t ks, int key)
{
    if(ks & KS_WITH_CONTROL)
        printf("main on_key_down keycode:%02x with control\n", key);
    else if(ks & KS_WITH_SHIFT)
        printf("main on_key_down keycode:%02x with shift\n", key);
    else
        printf("main on_key_down keycode:%02x\n", key);
}

void main_on_keyup(widget_t wt, dword_t ks, int key)
{
    if(ks & KS_WITH_CONTROL)
        printf("main on_key_up keycode:%02x with control\n", key);
    else if(ks & KS_WITH_SHIFT)
        printf("main on_key_up keycode:%02x with shift\n", key);
    else
        printf("main on_key_up keycode:%02x\n", key);
}

void main_on_wchar(widget_t wt, wchar_t wch)
{
    schar_t str[10] = { 0 };
    ucs_byte_to_mbs(wch, str);

    printf("main on_char character:%s\n", str);
}

void main_on_size(widget_t wt, int type, const xsize_t* pst)
{
    if(type == WS_SIZE_MAXIMIZED)
        printf("main on_size maximized width:%d height:%d\n", pst->w, pst->h);
    else if(type == WS_SIZE_MINIMIZED)
        printf("main on_size minimized width:%d height:%d\n", pst->w, pst->h);
    else if(type == WS_SIZE_FULLSCREEN)
        printf("main on_size fullscreen width:%d height:%d\n", pst->w, pst->h);
    else if(type == WS_SIZE_LAYOUT)
        printf("main on_size layout width:%d height:%d\n", pst->w, pst->h);
    else
        printf("main on_size restore width:%d height:%d\n", pst->w, pst->h);
}

void main_on_move(widget_t wt, const xpoint_t* ppt)
{
    printf("main on_move position x:%d y:%d\n", ppt->x, ppt->y);
    xrect_t xr;

    (*if_widget.pf_widget_get_window_rect)(wt, &xr);
    printf("main window at: x:%d y:%d w:%d h:%d\n", xr.x, xr.y, xr.w, xr.h);
}

void main_on_show(widget_t wt, bool_t show)
{
    if(show)
        printf("main on_show \n");
    else
        printf("main on_hide \n");
}

void main_on_activate(widget_t wt, int ma)
{
    if(ma == WS_ACTIVE_CLICK)
        printf("main on_activate by mouse click \n");
    else
        printf("main on_activate by application \n");
}

void main_on_paint(widget_t wt, visual_t rdc, const xrect_t* prt)
{
    printf("main main on_paint the rect is x:%d y:%d w:%d h:%d \n", prt->x, prt->y, prt->w, prt->h);

	xrect_t rt;
	(*if_widget.pf_widget_get_client_rect)(wt, &rt);
	visual_t ctx = (*if_context.pf_create_compatible_context)(rdc, rt.w, rt.h);

	xpen_t xp = { 0 };
	default_xpen(&xp);
	xscpy(xp.color, GDI_ATTR_RGB_RED);

	xbrush_t xb = { 0 };
	default_xbrush(&xb);

	xrect_t xr;
	xr.x = 0;
	xr.y = 0;
	xr.w = rt.w;
	xr.h = rt.h;

	xscpy(xb.color, GDI_ATTR_RGB_SOFTAZURE);
	(*if_context.pf_gdi_draw_rect)(ctx, &xp, &xb, &xr);

	(*if_context.pf_render_context)(ctx, 0, 0, rdc, 0, 0, rt.w, rt.h);

	(*if_context.pf_destroy_context)(ctx);
}

void main_on_set_focus(widget_t wt, widget_t from)
{
    printf("main on_set_focus \n");
}

void main_on_kill_focus(widget_t wt, widget_t to)
{
    printf("main on_kill_focus \n");
}

void main_on_notice(widget_t, NOTICE* pnt)
{
    printf("main on_notice child id: %d code: %d \n", pnt->user, pnt->code);
}

void main_on_menu_command(widget_t wt, int code, int cid, vword_t data)
{
    printf("main on_menu_command child id: %d code: %d \n", cid, code);
}

void main_on_parent_command(widget_t, int code, vword_t data)
{
    printf("main on_parent_command code: %d \n", code);
}

void main_on_child_command(widget_t wt, int code, vword_t data)
{
    printf("main on_child_command code: %d \n", code);
}

void main_on_self_command(widget_t wt, int code, vword_t data)
{
    printf("main on_self_command code: %d \n", code);
}

void main_on_command_find(widget_t wt, str_find_t* psf)
{
}

void main_on_comamnd_replace(widget_t wt, str_replace_t* psr)
{
}

void main_on_syscmd_click(widget_t wt, const xpoint_t* ppt)
{
}

void main_on_timer(widget_t wt, vword_t tid)
{
    printf("main on_timer tid: %lld \n", (unsigned long long)tid);
}

void main_on_idle(widget_t wt)
{
    printf("main on_idle:\n");
}

/********************************************************************************/

void init_instance()
{
    xdu_impl_context(&if_context);

    xdu_impl_context_graphic(&if_context);

    xdu_impl_context_bitmap(&if_context);

    (*if_context.pf_context_startup)();

    xdu_impl_widget(&if_widget);

    (*if_widget.pf_widget_startup)(0);

    accel_table_t acs[3] = {
        {KS_WITH_CONTROL, 'a', 10},
        {KS_WITH_ALT, 's', 20},
        {KS_WITH_SHIFT, '\t', 30}
    };

    color_mod_t clrs = {0};
    parse_xcolor(&clrs.clr_bkg, GDI_ATTR_RGB_DARKBLACK);
    parse_xcolor(&clrs.clr_frg, GDI_ATTR_RGB_SNOWWHITE);
    parse_xcolor(&clrs.clr_txt, GDI_ATTR_RGB_LIGHTWHITE);
    parse_xcolor(&clrs.clr_msk, GDI_ATTR_RGB_BLACK);
    parse_xcolor(&clrs.clr_ico, GDI_ATTR_RGB_SNOWWHITE);

    if_dispatch_t ev = {0};
    ev.pf_on_create = main_on_create;
	ev.pf_on_close = main_on_close;
	ev.pf_on_destroy = main_on_destroy;
	ev.pf_on_lbutton_down = main_on_lbutton_down;
	ev.pf_on_lbutton_up = main_on_lbutton_up;
	ev.pf_on_lbutton_dbclick = main_on_lbutton_dbclick;
	ev.pf_on_rbutton_down = main_on_rbutton_down;
	ev.pf_on_rbutton_up = main_on_rbutton_up;
	ev.pf_on_mouse_move = main_on_mouse_move;
	ev.pf_on_mouse_enter = main_on_mouse_enter;
	ev.pf_on_mouse_leave = main_on_mouse_leave;
    ev.pf_on_mouse_hover = main_on_mouse_hover;
	ev.pf_on_wheel = main_on_whell;
	ev.pf_on_scroll = main_on_scroll;
	ev.pf_on_keydown = main_on_keydown;
	ev.pf_on_keyup = main_on_keyup;
	ev.pf_on_wchar = main_on_wchar;
	ev.pf_on_size = main_on_size;
	ev.pf_on_move = main_on_move;
	ev.pf_on_show = main_on_show;
	ev.pf_on_activate = main_on_activate;
	ev.pf_on_set_focus = main_on_set_focus;
	ev.pf_on_kill_focus = main_on_kill_focus;
	ev.pf_on_paint = main_on_paint;
	ev.pf_on_notice = main_on_notice;
	ev.pf_on_menu_command = main_on_menu_command;
	ev.pf_on_parent_command = main_on_parent_command;
	ev.pf_on_child_command = main_on_child_command;
	ev.pf_on_self_command = main_on_self_command;
    ev.pf_on_scroll = main_on_scroll;
    ev.pf_on_timer = main_on_timer;
    ev.pf_on_idle = main_on_idle;

    xrect_t xr = {0};
    xr.x = 100;
	xr.y = 582;
	xr.w = 600;
	xr.h = 400;

	g_main = (*if_widget.pf_widget_create)(_T("frame1"), (WD_STYLE_FRAME /*& (~WD_STYLE_OWNERNC)*/), &xr, NULL, &ev);
	(*if_widget.pf_widget_set_accel)(g_main, acs, sizeof(acs) / sizeof(accel_table_t));

    (*if_widget.pf_widget_set_color_mode)(g_main, &clrs);
    (*if_widget.pf_widget_show)(g_main, WS_SHOW_NORMAL);

    scroll_t scr = {0};
    scr.max = 600;
    scr.min = 0;

    (*if_widget.pf_widget_set_scroll_info)(g_main, 0, &scr);

    (*if_widget.pf_widget_active)(g_main);

    (*if_widget.pf_widget_get_window_rect)(g_main, &xr);
    printf("main window at: x:%d y:%d w:%d h:%d\n", xr.x, xr.y, xr.w, xr.h);
}

void uninit_instance()
{
    (*if_widget.pf_widget_cleanup)();

    (*if_context.pf_context_cleanup)();
}

void test_win()
{
	init_instance();

	(*if_widget.pf_widget_do_main)(g_main);

	uninit_instance();
}

#ifdef _OS_WINDOWS
#pragma comment( linker, "/subsystem:windows /entry:mainCRTStartup" )
#endif

int main(int argc, const char * argv[]) {

    xdk_process_init(XDK_APARTMENT_PROCESS);

	test_win();

    xdk_process_uninit();

    return 0;
}
