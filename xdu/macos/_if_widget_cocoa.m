/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc widget document

	@module	if_widget_cocoa.m | macos implement file

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

#import <QuartzCore/CAMetalLayer.h>
#import <AppKit/AppKit.h>

#include <Carbon/Carbon.h>
#include <IOKit/hid/IOHIDLib.h>

#include "../xduloc.h"
#include "../xduutil.h"

#include <float.h>
#include <string.h>
#include <assert.h>

#ifdef XDU_SUPPORT_WIDGET

static const NSRange NullRange = { NSNotFound, 0 };

typedef struct _cocoa_widget_t{
	res_win_t parent;
	res_win_t owner;
	res_win_t oneself;

	uid_t uid;
	dword_t style;
	bool_t disable;
	bool_t idling;

	res_acl_t acl;
	res_cur_t cur;

	int state;
	int result;
    dword_t keymsk;

	border_t bd;
	xpoint_t pt;
	xsize_t st;

	scroll_t hs;
	scroll_t vs;

	clr_mod_t clrs;
}cocoa_widget_t;

#ifndef NSEscapeCharacter
#define NSEscapeCharacter 0x001B
#endif

#ifndef NSSpaceCharacter
#define NSSpaceCharacter 0x0020
#endif

static int unichar_to_keycode(unichar uch)
{
    switch (uch)
    {
        case NSBackspaceCharacter: return KEY_BACK; 
        case NSTabCharacter: return KEY_TAB; 
        case NSCarriageReturnCharacter: return KEY_ENTER;
        case NSEscapeCharacter: return KEY_ESC;
        case NSSpaceCharacter: return KEY_SPACE;
        case NSPageUpFunctionKey: return KEY_PAGEUP; 
        case NSPageDownFunctionKey: return KEY_PAGEDOWN;
        case NSEndFunctionKey: return KEY_END;
        case NSHomeFunctionKey: return KEY_HOME;
        case NSLeftArrowFunctionKey: return KEY_LEFT; 
        case NSUpArrowFunctionKey: return KEY_UP; 
        case NSRightArrowFunctionKey: return KEY_RIGHT; 
        case NSDownArrowFunctionKey: return KEY_DOWN;
        case NSInsertFunctionKey: return KEY_INSERT; 
        case NSDeleteFunctionKey: return KEY_DELETE;
        case NSF1FunctionKey: return KEY_F1;
        case NSF2FunctionKey: return KEY_F2;
        case NSF3FunctionKey: return KEY_F3;
        case NSF4FunctionKey: return KEY_F4;
        case NSF5FunctionKey: return KEY_F5;
        case NSF6FunctionKey: return KEY_F6;
        case NSF7FunctionKey: return KEY_F7;
        case NSF8FunctionKey: return KEY_F8;
        case NSF9FunctionKey: return KEY_F9;
        case NSF10FunctionKey: return KEY_F10;
        case NSF11FunctionKey: return KEY_F11;
        case NSF12FunctionKey: return KEY_F12;
        default: return (int)0; 
    }
}

static unichar keycode_to_unichar(int key)
{
    switch (key)
    {
        case KEY_BACK: return NSBackspaceCharacter; 
        case KEY_TAB: return NSTabCharacter; 
        case KEY_ENTER: return NSCarriageReturnCharacter;
        case KEY_ESC: return NSEscapeCharacter;
        case KEY_SPACE: return NSSpaceCharacter;
        case KEY_PAGEUP: return NSPageUpFunctionKey; 
        case KEY_PAGEDOWN: return NSPageDownFunctionKey;
        case KEY_END: return NSEndFunctionKey;
        case KEY_HOME: return NSHomeFunctionKey;
        case KEY_LEFT: return NSLeftArrowFunctionKey; 
        case KEY_UP: return NSUpArrowFunctionKey; 
        case KEY_RIGHT: return NSRightArrowFunctionKey; 
        case KEY_DOWN: return NSDownArrowFunctionKey;
        case KEY_INSERT: return NSInsertFunctionKey; 
        case KEY_DELETE: return NSDeleteFunctionKey;
        case KEY_F1: return NSF1FunctionKey;
        case KEY_F2: return NSF2FunctionKey;
        case KEY_F3: return NSF3FunctionKey;
        case KEY_F4: return NSF4FunctionKey;
        case KEY_F5: return NSF5FunctionKey;
        case KEY_F6: return NSF6FunctionKey;
        case KEY_F7: return NSF7FunctionKey;
        case KEY_F8: return NSF8FunctionKey;
        case KEY_F9: return NSF9FunctionKey;
        case KEY_F10: return NSF10FunctionKey;
        case KEY_F11: return NSF11FunctionKey;
        case KEY_F12: return NSF12FunctionKey;
        default: return (unichar)0; 
    }
}

static dword_t _keynsState(NSUInteger nsFlags)
{
    dword_t mask = 0;

    if (nsFlags & NSEventModifierFlagShift)
        mask |= KS_WITH_SHIFT;
    if (nsFlags & NSEventModifierFlagControl)
        mask |= KS_WITH_CONTROL;
    if (nsFlags & NSEventModifierFlagOption)
        mask |= KS_WITH_ALT;
    if (nsFlags & NSEventModifierFlagCapsLock)
        mask |= KS_WITH_CAPS;

    return mask;
}

static dword_t _mousensState(NSUInteger nsState)
{
    dword_t mask = 0;

    if (nsState & 1)
        mask |= MS_WITH_LBUTTON;
    if (nsState & 2)
        mask |= MS_WITH_RBUTTON;
    
    return mask;
}

static void _cocoa_to_view(NSView* view, NSPoint* point)
{
    NSRect frame = [view frame];
    point->y = frame.size.height - point->y;
}

static void _view_to_cocoa(NSView* view, NSPoint* point)
{
    NSRect frame = [view frame];
    point->y = frame.size.height - point->y;
}

static void _cocoa_to_window(NSWindow* window, NSPoint* point)
{
    NSRect frame = [window frame];
    point->y = frame.size.height - point->y;
}

static void _window_to_cocoa(NSWindow* window, NSPoint* point)
{
    NSRect frame = [window frame];
    point->y = frame.size.height - point->y;
}

static void _cocoa_to_screen(NSScreen* screen, NSPoint* point)
{
    NSRect frame = [screen frame];
    point->y = frame.size.height - point->y;
}

static void _screen_to_cocoa(NSScreen* screen, NSPoint* point)
{
    NSRect frame = [screen frame];
    point->y = frame.size.height - point->y;
}

static void _child_to_parent(NSView* child, NSPoint* point)
{
    NSView* parent = [child superview];

    if (child == parent) return;

    NSPoint localPoint = [child convertPoint:*point toView:parent];
    *point = localPoint;
}

static void _parent_to_child(NSView* child, NSPoint* point)
{
    NSView* parent = [child superview];

    if (child == parent) return;

    NSPoint localPoint = [child convertPoint:*point fromView:parent];
    *point = localPoint;
}

/**************************************************************************************/

@interface _CocoaApplicationDelegate : NSObject{}

- (instancetype)init;
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender;

@end

@interface _CocoaWindowDelegate : NSObject{}

- (instancetype)initWithCocoaWindow:(id)initWindow;

@end

@interface _CocoaViewDelegate : NSObject{}

- (instancetype)initWithCocoaView:(id)initView;

@end

@interface _CocoaView : NSView <NSTextInputClient>
{
    NSTrackingArea* tracking;
}
    @property (assign, nonatomic) id delegate;
    @property (assign, nonatomic) id widget;
    @property (assign, nonatomic) id dispatch;
    @property (assign, nonatomic) id subproc;
    @property (assign, nonatomic) id coredelta;
    @property (assign, nonatomic) id userdelta;

    @property (assign) NSRect caret_rect;
    @property (assign) BOOL caret_visible;
    @property (strong) NSTimer* caret_timer;

    @property (strong) NSMutableDictionary* properties;

- (instancetype)initWithFrame:(NSRect)frameRect;
- (void)drawCaret;
- (void)toggleCaret;

@end

typedef enum{
    _CocoaWindowRunInvalid = -1,
    _CocoaWindowRunNormal = 0,
    _CocoaWindowRunMain = 1,
    _CocoaWindowRunModal = 2
}_CocoaWindowRunType;

@interface _CocoaWindow : NSWindow {}
    @property (assign) _CocoaWindowRunType running;
    @property (strong) NSTimer* schedule;
@end

/**************************************************************************************/
@implementation _CocoaApplicationDelegate

- (instancetype)init
{
    self = [super init];

    if (self != nil)
    {
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(applicationWillTerminate:)
                                                     name:NSApplicationWillTerminateNotification
                                                   object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(applicationDidFinishLaunching:)
                                                     name:NSApplicationDidFinishLaunchingNotification
                                                   object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(applicationDidBecomeActive:)
                                                     name:NSApplicationDidBecomeActiveNotification
                                                   object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(applicationDidResignActive:)
                                                     name:NSApplicationDidResignActiveNotification
                                                   object:nil];
    }

    return self;
}

- (void)applicationWillTerminate:(NSNotification *)notification 
{ 
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification 
{
   NOP;
}

- (void)applicationDidBecomeActive:(NSNotification *)notification 
{
    NOP;
}

- (void)applicationDidResignActive:(NSNotification *)notification 
{
   NOP;
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender
{
    return YES;
}

@end

NSString *const NoticeMessage = @"NoticeMessage";
NSString *const CommandMessage = @"CommandMessage";

@implementation _CocoaViewDelegate

- (instancetype)initWithCocoaView:(id)initView
{
    self = [super init];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                            selector:@selector(handleViewNotice:)
                                            name:NoticeMessage
                                            object:initView];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                            selector:@selector(handleViewCommand:)
                                            name:CommandMessage
                                            object:initView];
    return self;
}

- (void)handleViewNotice:(NSNotification *)notification 
{@autoreleasepool {
    _CocoaView* ref_view = notification.object;

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSDictionary *userInfo = notification.userInfo;
    NOTICE* pnt = (NOTICE*)[userInfo[@"delta"] unsignedLongValue];

    int result = 0;
    if (pdisp && pdisp->pf_on_notice)
    {
        (*pdisp->pf_on_notice)((res_win_t)ref_view, pnt);
        result = 1;
    }

    pwidg->result = result;
}}

- (void)handleViewCommand:(NSNotification *)notification 
{@autoreleasepool {
    _CocoaView* ref_view = notification.object;

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSDictionary *userInfo = notification.userInfo;
    int code = (int)[userInfo[@"code"] intValue];
    dword_t cid = (dword_t)[userInfo[@"user"] unsignedIntValue];
    vword_t data = (vword_t)[userInfo[@"data"] unsignedLongValue];

    int result = 0;
    switch(cid)
    {
    case IDC_PARENT:
        if (pdisp && pdisp->pf_on_parent_command)
        {
            (*pdisp->pf_on_parent_command)((res_win_t)ref_view, code, data);
            result = 1;
        }
    break;
    case IDC_CHILD:
        if (pdisp && pdisp->pf_on_child_command)
        {
            (*pdisp->pf_on_child_command)((res_win_t)ref_view, code, data);
            result = 1;
        }
    break;
    case IDC_SELF:
        if (pdisp && pdisp->pf_on_self_command)
        {
            (*pdisp->pf_on_self_command)((res_win_t)ref_view, code, data);
            result = 1;
        }
    break;
    default:
        if (pdisp && pdisp->pf_on_menu_command)
        {
            (*pdisp->pf_on_menu_command)((res_win_t)ref_view, code, cid, data);
            result = 1;
        }
    break;
    }

    pwidg->result = result;
}}

@end

/**************************************************************************************/

@implementation _CocoaWindowDelegate

- (instancetype)initWithCocoaWindow:(id)initWindow
{
    self = [super init];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                            selector:@selector(handleWindowNotice:)
                                                name:NoticeMessage
                                            object:initWindow];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                            selector:@selector(handleWindowCommand:)
                                                name:CommandMessage
                                            object:initWindow];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                         selector:@selector(windowWillClose:)
                                             name:NSWindowWillCloseNotification
                                           object:initWindow];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                         selector:@selector(windowDidResize:)
                                             name:NSWindowDidResizeNotification
                                           object:initWindow];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                         selector:@selector(windowDidMove:)
                                             name:NSWindowDidMoveNotification
                                           object:initWindow];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                         selector:@selector(windowDidEnterFullScreen:)
                                             name:NSWindowDidEnterFullScreenNotification
                                           object:initWindow];                             
    [[NSNotificationCenter defaultCenter] addObserver:self
                                         selector:@selector(windowDidExitFullScreen:)
                                             name:NSWindowDidExitFullScreenNotification
                                           object:initWindow]; 
    return self;
}

- (void)handleWindowNotice:(NSNotification *)notification 
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSMutableDictionary *userInfo = notification.userInfo;
    NOTICE* pnt = (NOTICE*)[userInfo[@"delta"] unsignedLongValue];

    int result = 0;
    if (pdisp && pdisp->pf_on_notice)
    {
        (*pdisp->pf_on_notice)((res_win_t)ref_view, pnt);
        result = 1;
    }

   pwidg->result = result;
}}

- (void)handleWindowCommand:(NSNotification *)notification 
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;
    
    NSDictionary *userInfo = notification.userInfo;
    int code = (int)[userInfo[@"code"] intValue];
    dword_t cid = (dword_t)[userInfo[@"user"] unsignedIntValue];
    vword_t data = (vword_t)[userInfo[@"data"] unsignedLongValue];

    int result = 0;

    switch(cid)
    {
    case IDC_PARENT:
        if (pdisp && pdisp->pf_on_parent_command)
        {
            (*pdisp->pf_on_parent_command)((res_win_t)ref_view, code, data);
            result = 1;
        }
    break;
    case IDC_CHILD:
        if (pdisp && pdisp->pf_on_child_command)
        {
            (*pdisp->pf_on_child_command)((res_win_t)ref_view, code, data);
            result = 1;
        }
    break;
    case IDC_SELF:
        if (pdisp && pdisp->pf_on_self_command)
        {
            (*pdisp->pf_on_self_command)((res_win_t)ref_view, code, data);
            result = 1;
        }
    break;
    default:
        if (pdisp && pdisp->pf_on_menu_command)
        {
            (*pdisp->pf_on_menu_command)((res_win_t)ref_view, code, cid, data);
            result = 1;
        }
    break;
    }

    pwidg->result = result;
}}

- (BOOL)windowShouldClose:(NSWindow *)sender
{@autoreleasepool {
    _CocoaWindow* ref_window = sender;
    _CocoaView* ref_view = [ref_window contentView];

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    if (pdisp && pdisp->pf_on_close)
     {
        if((*pdisp->pf_on_close)((res_win_t)ref_view))
            return NO;
    }

    return YES;
}}

- (void)windowWillClose:(NSNotification *)notification 
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    _CocoaWindowRunType run_type = [ref_window running];
    ref_window.running = _CocoaWindowRunInvalid;
    
    switch(run_type)
    {
    case _CocoaWindowRunMain:
        //[NSApp stop:nil];
        break;
    case _CocoaWindowRunModal:
        [NSApp stopModal];
        break;
    }

    if(run_type != _CocoaWindowRunInvalid)
    {
        _widget_destroy((res_win_t)ref_view);
    }
}}

- (void)windowDidResize:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSScreen *nsScreen = [ref_window screen] ?: [NSScreen mainScreen];

    NSRect newFrame = [ref_window frame];
    NSRect scrFrame = [nsScreen visibleFrame];

    xsize_t xs;
    xs.w = (int)newFrame.size.width;
    xs.h = (int)newFrame.size.height;

    if(pdisp && pdisp->pf_on_size)
    {
         if (NSEqualRects(newFrame, scrFrame))
            (*pdisp->pf_on_size)((res_win_t)ref_view, WS_SIZE_MAXIMIZED, &xs);
        else if(pwidg->st.w == xs.w && pwidg->st.h == xs.h)
            (*pdisp->pf_on_size)((res_win_t)ref_view, WS_SIZE_LAYOUT, &xs);
        else
            (*pdisp->pf_on_size)((res_win_t)ref_view, WS_SIZE_RESTORE, &xs);

        pwidg->st.w = xs.w;
        pwidg->st.h = xs.h;
    }
}}

- (void)windowDidEnterFullScreen:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if(pwidg->state == WS_SHOW_FULLSCREEN)
        return;

    NSRect newFrame = [ref_window frame];

    xsize_t xs;
    xs.w = (int)newFrame.size.width;
    xs.h = (int)newFrame.size.height;

    if(pdisp && pdisp->pf_on_size)
    {
        (*pdisp->pf_on_size)((res_win_t)ref_view, WS_SIZE_FULLSCREEN, &xs);
    }

    pwidg->state = WS_SHOW_FULLSCREEN;
}}

- (void)windowDidExitFullScreen:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if(pwidg->state != WS_SHOW_FULLSCREEN)
        return;

    NSRect newFrame = [ref_window frame];

    xsize_t xs;
    xs.w = (int)newFrame.size.width;
    xs.h = (int)newFrame.size.height;

    if(pdisp && pdisp->pf_on_size)
    {
        (*pdisp->pf_on_size)((res_win_t)ref_view, WS_SIZE_RESTORE, &xs);
    }

    pwidg->state = WS_SHOW_NORMAL;
}}

- (void)windowDidMove:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSScreen* nsScreen = [ref_window screen] ?: [NSScreen mainScreen];
    NSRect scrFrame = [nsScreen frame];
    NSRect newFrame = [ref_window frame];
    NSPoint newOrigin = newFrame.origin;
    newOrigin.y += newFrame.size.height;

    _cocoa_to_screen(nsScreen, &newOrigin);

    xpoint_t pt;
    pt.x = (int)newOrigin.x;
    pt.y = (int)newOrigin.y;

    if(pwidg->pt.x == pt.x && pwidg->pt.y == pt.y)
        return;

    if(pdisp && pdisp->pf_on_move)
    {
        (*pdisp->pf_on_move)((res_win_t)ref_view, &pt);

        pwidg->pt.x = pt.x;
        pwidg->pt.y = pt.y;
    }
}}

- (void)windowDidMiniaturize:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if(pwidg->state == WS_SHOW_MINIMIZE)
        return;
    
    if(pdisp && pdisp->pf_on_size)
    {
        xsize_t xs;
        xs.w = 0;
        xs.h = 0;
        (*pdisp->pf_on_size)((res_win_t)ref_view, WS_SIZE_MINIMIZED, &xs);

        pwidg->st.w = xs.w;
        pwidg->st.h = xs.h;
    }

    pwidg->state = WS_SHOW_MINIMIZE;
}}

- (void)windowDidDeminiaturize:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSRect newFrame = [ref_window frame];
 
    xsize_t xs;
    xs.w = (int)newFrame.size.width;
    xs.h = (int)newFrame.size.height;

    if(pwidg->state != WS_SHOW_MINIMIZE)
        return;

    if(pdisp && pdisp->pf_on_size)
    {
        (*pdisp->pf_on_size)((res_win_t)ref_view, WS_SIZE_RESTORE, &xs);

        pwidg->st.w = xs.w;
        pwidg->st.h = xs.h;
    }

    pwidg->state = WS_SHOW_NORMAL;
}}

- (void)windowDidBecomeMain:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    if(pdisp && pdisp->pf_on_activate)
    {
        (*pdisp->pf_on_activate)((res_win_t)ref_view, 1);
    }
}}

- (void)windowDidBecomeKey:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    [ref_window makeFirstResponder:[ref_window contentView]];
}}

- (void)windowDidResignKey:(NSNotification *)notification
{@autoreleasepool {
    //_CocoaWindow* ref_window = notification.object;
    //_CocoaView* ref_view = [ref_window contentView];
}}

- (void)windowDidChangeOcclusionState:(NSNotification* )notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    bool_t visible = (ref_window.occlusionState & NSWindowOcclusionStateVisible)? 1 : 0;

    if(pdisp && pdisp->pf_on_show)
    {
        (*pdisp->pf_on_show)((res_win_t)ref_view, visible);
    }
}}

@end

/**************************************************************************************/

@implementation _CocoaWindow

- (BOOL)canBecomeKeyWindow
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaWindow class]] == NO)
        return [super canBecomeKeyWindow];
    
    _CocoaWindow* ref_window = self;
    _CocoaView* ref_view = [ref_window contentView];
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    return (pwidg->style & WD_STYLE_NOACTIVE)? NO : YES;
}}

- (BOOL)canBecomeMainWindow
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaWindow class]] == NO)
        return [super canBecomeMainWindow];

    _CocoaWindow* ref_window = self;
    _CocoaView* ref_view = [ref_window contentView];
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

   return (pwidg->style & WD_STYLE_TITLE)? YES : NO;
}}

- (void)scheduleTimer
{@autoreleasepool {
   if([self isKindOfClass:[_CocoaWindow class]] == NO)
        return;
    
    _CocoaView* ref_view = [self contentView];
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    if (pdisp && pdisp->pf_on_timer)
    {
        (*pdisp->pf_on_timer)((res_win_t)ref_view, 0);
    }
}}

- (void)sendEvent:(NSEvent *)nsEvent 
{@autoreleasepool {
   if([self isKindOfClass:[_CocoaWindow class]] == NO)
        return;

    _CocoaWindow* ref_window = self;
    if([ref_window running] == _CocoaWindowRunInvalid)
        return;

    [super sendEvent:nsEvent];
    //NSLog(@"Custom nsEvent handling: %@", nsEvent);
}}

@end
/**************************************************************************************/

@implementation _CocoaView

- (instancetype)initWithFrame:(NSRect)frameRect
{@autoreleasepool {
    self = [super initWithFrame:frameRect];

    if (self != nil)
    {
        tracking = nil;

        [self updateTrackingAreas];
        [self registerForDraggedTypes:@[NSPasteboardTypeURL]];
    }

    return self;
}}

- (void)dealloc
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO)
        return [super dealloc];

    if(tracking != nil) [tracking release];

    [super dealloc];
}}

- (BOOL)isOpaque
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO)
        return [super isOpaque];
    
    return YES;
}}

- (BOOL)canBecomeKeyView
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO)
        return [super canBecomeKeyView];

    return YES;
}}

- (BOOL)acceptsFirstResponder
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO)
        return [super acceptsFirstResponder];

    return YES;
}}

- (BOOL)becomeFirstResponder
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO)
        return [super becomeFirstResponder];

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    if (pdisp && pdisp->pf_on_set_focus)
    {
        (*pdisp->pf_on_set_focus)((res_win_t)ref_view, ref_view);
    }

    return YES;
}}

- (BOOL)resignFirstResponder
{
    if([self isKindOfClass:[_CocoaView class]] == NO)
        return [super resignFirstResponder];

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    if (pdisp && pdisp->pf_on_kill_focus)
    {
        (*pdisp->pf_on_kill_focus)((res_win_t)ref_view, 0);
    }

    return YES;
}

- (NSView *)hitTest:(NSPoint)aPoint
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO)
        return [super hitTest:aPoint];

    _CocoaView* coc_view = self;

	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    return (pwidg->disable)? nil : [super hitTest:aPoint];
}}

- (BOOL)acceptsFirstMouse:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO)
        return [super acceptsFirstMouse:nsEvent];

    return YES;
}}

- (void)mouseDown:(NSEvent *)nsEvent
{@autoreleasepool {
    [super mouseDown:nsEvent];
    if([self isKindOfClass:[_CocoaView class]] == NO) return;
    
    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    NSPoint cliPoint = [ref_view convertPoint:[nsEvent locationInWindow] fromView:nil];
    _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

   if ([nsEvent clickCount] == 1)
    {
        if(pdisp && pdisp->pf_on_lbutton_down)
        {
            (*pdisp->pf_on_lbutton_down)((res_win_t)ref_view, &pt);
        }
    }
}}

- (void)mouseUp:(NSEvent *)nsEvent
{@autoreleasepool {
    [super mouseUp:nsEvent];
    if([self isKindOfClass:[_CocoaView class]] == NO) return;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    NSPoint cliPoint = [ref_view convertPoint:[nsEvent locationInWindow] fromView:nil];

     _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    if ([nsEvent clickCount] == 1)
    {
        if(pdisp && pdisp->pf_on_lbutton_up)
        {
            (*pdisp->pf_on_lbutton_up)((res_win_t)ref_view, &pt);
        }
    }else
    {
        if(pdisp && pdisp->pf_on_lbutton_dbclick)
        {
            (*pdisp->pf_on_lbutton_dbclick)((res_win_t)ref_view, &pt);
        } 
    }
}}

- (void)mouseMoved:(NSEvent *)nsEvent
{@autoreleasepool {
    [super mouseMoved:nsEvent];
    if([self isKindOfClass:[_CocoaView class]] == NO) return;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    NSPoint cliPoint = [ref_view convertPoint:[nsEvent locationInWindow] fromView:nil];

     _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    NSUInteger nsFlags = [nsEvent modifierFlags];
    dword_t mask = _keynsState(nsFlags);

    NSUInteger nsState = [NSEvent pressedMouseButtons];
    mask |= _mousensState(nsState);

    if(pdisp && pdisp->pf_on_mouse_move)
    {
        (*pdisp->pf_on_mouse_move)((res_win_t)ref_view, mask, &pt);
    }
}}

- (void)rightMouseDown:(NSEvent *)nsEvent
{@autoreleasepool {
    [super rightMouseDown:nsEvent];
    if([self isKindOfClass:[_CocoaView class]] == NO) return;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    NSPoint cliPoint = [ref_view convertPoint:[nsEvent locationInWindow] fromView:nil];

     _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    if(pdisp && pdisp->pf_on_rbutton_down)
    {
        (*pdisp->pf_on_rbutton_down)((res_win_t)ref_view, &pt);
    }
}}

- (void)rightMouseUp:(NSEvent *)nsEvent
{@autoreleasepool {
    [super rightMouseUp:nsEvent];
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    NSPoint cliPoint = [ref_view convertPoint:[nsEvent locationInWindow] fromView:nil];

     _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    if(pdisp && pdisp->pf_on_rbutton_up)
    {
        (*pdisp->pf_on_rbutton_up)((res_win_t)ref_view, &pt);
    }
}}

- (void)mouseEntered:(NSEvent *)nsEvent
{@autoreleasepool {
    [super mouseEntered:nsEvent];
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    NSPoint cliPoint = [ref_view convertPoint:[nsEvent locationInWindow] fromView:nil];

     _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    NSUInteger nsFlags = [nsEvent modifierFlags];
    dword_t mask = _keynsState(nsFlags);

    NSUInteger nsState = [NSEvent pressedMouseButtons];
    mask |= _mousensState(nsState);

    if(pdisp && pdisp->pf_on_mouse_hover)
    {
        (*pdisp->pf_on_mouse_hover)((res_win_t)ref_view, mask, &pt);
    }
}}

- (void)mouseExited:(NSEvent *)nsEvent
{@autoreleasepool {
    [super mouseExited:nsEvent];
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    NSPoint cliPoint = [ref_view convertPoint:[nsEvent locationInWindow] fromView:nil];

     _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    NSUInteger nsFlags = [nsEvent modifierFlags];
    dword_t mask = _keynsState(nsFlags);

    NSUInteger nsState = [NSEvent pressedMouseButtons];
    mask |= _mousensState(nsState);

    if(pdisp && pdisp->pf_on_mouse_leave)
    {
        (*pdisp->pf_on_mouse_leave)((res_win_t)ref_view, mask, &pt);
    }
}}

- (void)drawRect:(NSRect)rect
{@autoreleasepool {
    [super drawRect:rect];
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;
    
    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    visual_t rdc = _create_display_context((res_win_t)ref_view);
    if(!rdc) return;

    NSPoint nsOrigin = NSMakePoint(rect.origin.x, rect.origin.y);
    _cocoa_to_view(ref_view, &nsOrigin);

	xrect_t xr = {0};
	xr.x = nsOrigin.x;
	xr.y = nsOrigin.y;
	xr.w = rect.size.width;
	xr.h = rect.size.height;

    if(pdisp && pdisp->pf_on_paint)
    {
        (*pdisp->pf_on_paint)((res_win_t)ref_view, rdc, &xr);
    }

    _destroy_context(rdc);

    [self drawCaret];
}}

- (void)drawCaret
{@autoreleasepool {
    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if(!ref_view.caret_visible) return;

    NSColor *nsColor = [NSColor colorWithCalibratedRed:(float)(pwidg->clrs.clr_frg.r) / 255.0f
                                    green:(float)(pwidg->clrs.clr_frg.g) / 255.0f
                                    blue:(float)(pwidg->clrs.clr_frg.b) / 255.0f
                                    alpha:1.0f];
    [nsColor set];
    NSRectFill(ref_view.caret_rect);
}}

- (void)toggleCaret
{@autoreleasepool {
    _CocoaView* ref_view = self;
    
    ref_view.caret_visible = !ref_view.caret_visible;

    [ref_view setNeedsDisplayInRect:ref_view.caret_rect];
}}

- (void)updateTrackingAreas
{@autoreleasepool {
    [super updateTrackingAreas];
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    if (tracking != nil)
    {
        [self removeTrackingArea:tracking];
        [tracking release];
    }

    const NSTrackingAreaOptions options = NSTrackingMouseEnteredAndExited |
                                          NSTrackingActiveInKeyWindow |
                                          NSTrackingEnabledDuringMouseDrag |
                                          NSTrackingCursorUpdate |
                                          NSTrackingInVisibleRect |
                                          NSTrackingAssumeInside;

    tracking = [[NSTrackingArea alloc] initWithRect:[self bounds]
                                                options:options
                                                  owner:self
                                               userInfo:nil];

    [self addTrackingArea:tracking];
}}

- (void)keyDown:(NSEvent *)nsEvent
{@autoreleasepool {
    [super keyDown:nsEvent];
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    unsigned short key = [nsEvent keyCode];
    NSUInteger nsFlags = [nsEvent modifierFlags];
    dword_t mask = _keynsState(nsFlags);

    if(pdisp && pdisp->pf_on_keydown)
    {
        (*pdisp->pf_on_keydown)((res_win_t)ref_view, mask, (int)key);
    }
}}

- (void)flagsChanged:(NSEvent *)nsEvent
{@autoreleasepool {
    [super flagsChanged:nsEvent];
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
	cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    const unsigned int modifierFlags = [nsEvent modifierFlags] & NSEventModifierFlagDeviceIndependentFlagsMask;

    pwidg->keymsk = _keynsState(modifierFlags);
}}

- (void)keyUp:(NSEvent *)nsEvent
{@autoreleasepool {
    [super keyUp:nsEvent];
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    unsigned short key = [nsEvent keyCode];
    NSUInteger nsFlags = [nsEvent modifierFlags];
    dword_t mask = _keynsState(nsFlags);

    if(pdisp && pdisp->pf_on_keyup)
    {
        (*pdisp->pf_on_keyup)((res_win_t)ref_view, mask, key);
    }
}}

- (void)scrollWheel:(NSEvent *)nsEvent
{@autoreleasepool {
    [super scrollWheel:nsEvent];
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    double deltaX = [nsEvent scrollingDeltaX];
    double deltaY = [nsEvent scrollingDeltaY];

    int sx, sy;

    if ([nsEvent hasPreciseScrollingDeltas])
    {
        sx = -(int)deltaX;
        sy = -(int)deltaY;
    }else
    {
        sx = -(int)(deltaX * 0.1);
        sy = -(int)(deltaY * 0.1);
    }

    if(pdisp && pdisp->pf_on_scroll)
    {
        if(sx)
            (*pdisp->pf_on_scroll)((res_win_t)ref_view, 1, sx);
        
        if(sy)
            (*pdisp->pf_on_scroll)((res_win_t)ref_view, 0, sy);
    }
}}

- (void)insertText:(id)string replacementRange:(NSRange)replacementRange
{@autoreleasepool {
    [super insertText:string replacementRange:replacementRange];
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    NSString* token;
    NSEvent* nsEvent = [NSApp currentEvent];

    if ([string isKindOfClass:[NSAttributedString class]])
        token = [string string];
    else
        token = (NSString*) string;

    NSRange range = NSMakeRange(0, [token length]);
    while (range.length)
    {
        uint32_t widechar = 0;

        if ([token getBytes:&widechar
                       maxLength:sizeof(widechar)
                      usedLength:NULL
                        encoding:NSUTF32StringEncoding
                         options:0
                           range:range
                  remainingRange:&range])
        {
            if (widechar >= 0xf700 && widechar <= 0xf7ff)
                continue;

            if(pdisp && pdisp->pf_on_wchar)
            {
                (*pdisp->pf_on_wchar)((res_win_t)ref_view, (wchar_t)widechar);
            }
        }
    }
}}

- (void)doCommandBySelector:(SEL)selector
{@autoreleasepool {
    [super doCommandBySelector:selector];
    if([self isKindOfClass:[_CocoaView class]] == NO) return;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    if (selector == @selector(insertNewline:)) {
       NOP;
    } else if (selector == @selector(deleteBackward:)) {
         NOP;
    }
}}

@end

/*****************************************************************************************/

void _widget_startup(int ver)
{
    NOP;
}

void _widget_cleanup()
{
    NOP;
}

res_win_t _widget_create(const tchar_t* wname, dword_t wstyle, const xrect_t* wrect, res_win_t wparent, const if_dispatch_t* wnsEvent)
{@autoreleasepool {
    _CocoaView* new_view = nil;

    NSUInteger nsStyle = 0;
    NSRect nsRect;
    NSPoint nsPoint;
    NSColor* nsColor;

    NSScreen* nsScreen = [NSScreen mainScreen];
    NSWindow* nsWindow = (wparent)? [(NSView*)wparent window] : nil;
    NSView* nsView = (nsWindow)? [nsWindow contentView] : nil;

    cocoa_widget_t* pwidg = (cocoa_widget_t*)calloc(1, sizeof(cocoa_widget_t));
	if_dispatch_t* pdisp = (if_dispatch_t*)calloc(1, sizeof(if_dispatch_t));
    if(wnsEvent)
	{
		memcpy((void*)(pdisp), (void*)wnsEvent, sizeof(if_dispatch_t));
	}

    pwidg->parent = wparent;
	pwidg->style = wstyle;
	pwidg->state = WS_SHOW_HIDE;

	if(wstyle & WD_STYLE_CHILD)
	{
		nsStyle = NSBorderlessWindowMask;

        nsPoint.x = wrect->x;
        nsPoint.y = wrect->y + wrect->h;
        _view_to_cocoa(nsView, &nsPoint);
        nsRect = NSMakeRect(nsPoint.x, nsPoint.y, wrect->w, wrect->h);

        new_view = [[_CocoaView alloc] initWithFrame:nsRect];

        if(new_view == nil) {free(pwidg); free(pdisp); return (res_win_t)nil;}

        new_view.properties = [[NSMutableDictionary alloc] init];
        new_view.widget = pwidg;
        new_view.dispatch = pdisp;

        if(nsView)
        {
            [nsView addSubview:new_view];
        }

        _CocoaViewDelegate* view_delegate = [[_CocoaViewDelegate alloc] initWithCocoaView:new_view];
        
        if(view_delegate == nil) {free(pwidg); free(pdisp); return (res_win_t)nil;}

        new_view.delegate = view_delegate;
    }else
    {
        nsPoint.x = wrect->x;
        nsPoint.y = wrect->y + wrect->h;
        _screen_to_cocoa(nsScreen, &nsPoint);
        nsRect = NSMakeRect(nsPoint.x, nsPoint.y, wrect->w, wrect->h);

        if(wstyle & WD_STYLE_TITLE)
        {
            nsStyle = NSWindowStyleMaskTitled;
            if(wstyle & WD_STYLE_CLOSEBOX) nsStyle |= NSWindowStyleMaskClosable;
            if(wstyle & WD_STYLE_SIZEBOX) nsStyle |= (NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable);

        }
	    else
		{
		    nsStyle = NSWindowStyleMaskBorderless;
		}
	
    	_CocoaWindow* coc_window = [[_CocoaWindow alloc] initWithContentRect:nsRect
                                    styleMask:nsStyle
                                    backing:NSBackingStoreBuffered
                                    defer:NO];

	    if(coc_window == nil) {free(pwidg); free(pdisp); return (res_win_t)nil;}
        
        if(!(wstyle & WD_STYLE_TITLE))
        {
            [coc_window setLevel:NSFloatingWindowLevel];
        }
        [coc_window setReleasedWhenClosed:YES];

        new_view = [[_CocoaView alloc] initWithFrame:[[coc_window contentView] bounds]];

        if(new_view == nil) {free(pwidg); free(pdisp); return (res_win_t)nil;}

        new_view.properties = [[NSMutableDictionary alloc] init];
        new_view.widget = pwidg;
        new_view.dispatch = pdisp;
        [new_view setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
        
        [coc_window setContentView:new_view];
        [coc_window setTitle:[NSString stringWithUTF8String:wname]];
        
        if(nsWindow)
        {
            [coc_window setParentWindow:nsWindow];
            [nsWindow addChildWindow:coc_window ordered:NSWindowAbove];
        }

        _CocoaWindowDelegate* win_delegate = [[_CocoaWindowDelegate alloc] initWithCocoaWindow:coc_window];
        
        if(win_delegate == nil) {free(pwidg); free(pdisp); return (res_win_t)nil;}

        [coc_window setDelegate:win_delegate];
        coc_window.running = _CocoaWindowRunNormal;
    }

    if (pdisp && pdisp->pf_on_create)
    {
        (*pdisp->pf_on_create)((res_win_t)new_view, pdisp->param);
    }

    return (res_win_t)new_view;
}}

void _widget_destroy(res_win_t wt)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return [(NSView*)wt release];

    _CocoaView* coc_view = wt;

	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;
	if_dispatch_t* pdisp = (if_dispatch_t*)coc_view.dispatch;

    BOOL b_windowless = (pwidg->style & WD_STYLE_CHILD) ? YES : NO;

	if(pdisp && pdisp->pf_on_destroy)
	{
		(*pdisp->pf_on_destroy)(wt);
	}

    if(pwidg) free(pwidg);
    if(pdisp) free(pdisp);

    if(coc_view.caret_timer)
    {
        [coc_view.caret_timer invalidate];
        coc_view.caret_timer = nil;
    }
    if(coc_view.properties)
    {
        [coc_view.properties removeAllObjects];
        [coc_view.properties release];
        coc_view.properties = nil;
    }

    /*if(b_windowless)
    {
        _CocoaViewDelegate* view_delegate = coc_view.delegate;

        coc_view.delegate = nil;
        //[coc_view removeFromSuperview];

        [coc_view release];
        [view_delegate release];
    }else
    {
        _CocoaWindow* coc_window = [coc_view window];

        [coc_window orderOut:nil];

        if(coc_window.schedule)
        {
            [coc_window.schedule invalidate];
            coc_window.schedule = nil;
        }

        _CocoaWindowDelegate* win_delegate = [coc_window delegate];

        [coc_window setDelegate:nil];
        //[coc_window setContentView:nil];

        [coc_view release];
        [coc_window release];
        [win_delegate release];
    }*/
}}

void _widget_close(res_win_t wt, int ret)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return;
    
    _CocoaView* coc_view = wt;
	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD) return;

	if_dispatch_t* pdisp = (if_dispatch_t*)coc_view.dispatch;

	pwidg->result = ret;
	
	if(pdisp && pdisp->pf_on_close)
	{
		if((*pdisp->pf_on_close)(wt))
			return;
	}

	dispatch_async(dispatch_get_main_queue(), ^{
    [[NSNotificationCenter defaultCenter] postNotificationName:NSWindowWillCloseNotification
                                                        object:[coc_view window]];
    });
}}

const if_dispatch_t* _widget_get_dispatch(res_win_t wt)
{@autoreleasepool {
     if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return NULL;

    _CocoaView* coc_view = wt;

	if_dispatch_t* pdisp = (if_dispatch_t*)coc_view.dispatch;

	return (pdisp);
}}

if_subproc_t* _widget_get_subproc(res_win_t wt, uid_t sid)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return NULL;

    _CocoaView* coc_view = wt;

    if_subproc_t* psub = (if_subproc_t*)coc_view.subproc;

	return (psub);
}}

bool_t _widget_set_subproc(res_win_t wt, uid_t sid, if_subproc_t* sub)
{@autoreleasepool {
     if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return 0;

    _CocoaView* coc_view = wt;

	coc_view.subproc = (id)sub;

	return 1;
}}

void _widget_del_subproc(res_win_t wt, uid_t sid)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return;

   _CocoaView* coc_view = wt;

	coc_view.subproc = 0;

}}

bool_t _widget_set_subproc_delta(res_win_t wt, uid_t sid, vword_t delta)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return 0;

    _CocoaView* coc_view = wt;

	if_subproc_t* psub = (if_subproc_t*)coc_view.subproc;

    if(psub == NULL) return 0;

	psub->delta = delta;

	return 1;
}}

vword_t _widget_get_subproc_delta(res_win_t wt, uid_t sid)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return (vword_t)0;

    _CocoaView* coc_view = wt;

	if_subproc_t* psub = (if_subproc_t*)coc_view.subproc;

    if(psub == NULL) return (vword_t)0;

	return psub->delta;
}}

bool_t _widget_has_subproc(res_win_t wt)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return 0;

    _CocoaView* coc_view = wt;

    if_subproc_t* psub = (if_subproc_t*)coc_view.subproc;

	return (psub == NULL) ? 0 : 1;
}}

void _widget_set_core_delta(res_win_t wt, vword_t pd)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return ;

    _CocoaView* coc_view = wt;

    coc_view.coredelta = (id)pd;
}}

vword_t _widget_get_core_delta(res_win_t wt)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return (vword_t)0;

    _CocoaView* coc_view = wt;

	return (vword_t)coc_view.coredelta;
}}

void _widget_set_user_delta(res_win_t wt, vword_t pd)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return;

    _CocoaView* coc_view = wt;

	coc_view.userdelta = (id)pd;
}}

vword_t _widget_get_user_delta(res_win_t wt)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return (vword_t)0;

     _CocoaView* coc_view = wt;

	return (vword_t)coc_view.userdelta;
}}

void _widget_set_style(res_win_t wt, dword_t ws)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return;

    _CocoaView* coc_view = wt;

	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	if(pwidg) pwidg->style = ws;
}}

dword_t _widget_get_style(res_win_t wt)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return (dword_t)0;

     _CocoaView* coc_view = wt;

	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	return (pwidg)? pwidg->style : 0;
}}

void _widget_set_accel(res_win_t wt, res_acl_t acl)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return;

     _CocoaView* coc_view = wt;

	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	if(pwidg) pwidg->acl = acl;
}}

res_acl_t _widget_get_accel(res_win_t wt)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return (res_acl_t)0;

    _CocoaView* coc_view = wt;

	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	return (pwidg)? pwidg->acl : (res_acl_t)0;
}}

void _widget_set_owner(res_win_t wt, res_win_t owner)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return;

     _CocoaView* coc_view = wt;
	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	if(pwidg) pwidg->owner = owner;
}}

res_win_t _widget_get_owner(res_win_t wt)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return (res_win_t)0;

     _CocoaView* coc_view = wt;

	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	return (pwidg)? pwidg->owner : (res_win_t)nil;
}}

void _widget_set_user_id(res_win_t wt, uid_t uid)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return;

    _CocoaView* coc_view = wt;

    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	if(pwidg) pwidg->uid = uid;
}}

uid_t _widget_get_user_id(res_win_t wt)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return (uid_t)0;

    _CocoaView* coc_view = wt;

	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    return (pwidg)? pwidg->uid : 0;
}}

void _widget_set_user_result(res_win_t wt, int rt)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return;

     _CocoaView* coc_view = wt;

	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	if(pwidg) pwidg->result = rt;
}}

int _widget_get_user_result(res_win_t wt)
{@autoreleasepool {
    if([(NSView*)wt isKindOfClass:[_CocoaView class]] == NO)
        return 0;

    _CocoaView* coc_view = wt;

	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    return (pwidg)? pwidg->result : 0;
}}

bool_t _widget_enum_child(res_win_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

    _CocoaView* coc_view = wt;

    NSArray *subviews = [coc_view subviews];
    
    for (NSView *nsChild in subviews) 
    {
        if([nsChild isKindOfClass:[_CocoaView class]])
        {
            (*pf)((res_win_t)nsChild, pv);
        }
    }

    return 1;
}}

res_win_t _widget_get_child(res_win_t wt, uid_t uid)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return (res_win_t)nil;

    _CocoaView* coc_view = wt;

    NSArray *subviews = [coc_view subviews];
    
    for (NSView *nsChild in subviews) 
    {
        if([nsChild isKindOfClass:[_CocoaView class]])
        {
            _CocoaView* cocChild = (_CocoaView*)nsChild;
            cocoa_widget_t* pwidg = (cocoa_widget_t*)cocChild.widget;

            if(pwidg->uid == uid) return (res_win_t)nsChild;
        }
    }

    return (res_win_t)nil;
}}

res_win_t _widget_get_parent(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return (res_win_t)nil;

     _CocoaView* coc_view = wt;
     cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    return (res_win_t)pwidg->parent;
}}

void _widget_set_user_prop(res_win_t wt, const tchar_t* pname,vword_t val)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

     _CocoaView* coc_view = wt;
     NSString* nsKey = [NSString stringWithUTF8String:pname];

    [[coc_view properties] setObject:@(val) forKey:nsKey];
}}

vword_t _widget_get_user_prop(res_win_t wt, const tchar_t* pname)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return (vword_t)0;
    
    _CocoaView* coc_view = wt;
    NSString* nsKey = [NSString stringWithUTF8String:pname];
    return [coc_view.properties[nsKey] unsignedLongLongValue];
}}

vword_t _widget_del_user_prop(res_win_t wt, const tchar_t* pname)
{@autoreleasepool {
   if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return (vword_t)0;
    
    _CocoaView* coc_view = wt;
    NSString* nsKey = [NSString stringWithUTF8String:pname];

    vword_t val = [coc_view.properties[nsKey] unsignedLongLongValue];
    [[coc_view properties] removeObjectForKey:nsKey];

   return val;
}}

void _widget_get_menu_rect(res_win_t wt, xrect_t* pxr)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;

	pxr->x = 0;
    pxr->y = 0;
    pxr->w = 0;
    pxr->h = 0;
}}

void _widget_get_border(res_win_t wt, border_t* pbd)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	memcpy((void*)pbd, (void*)(&pwidg->bd), sizeof(border_t));
}}

void _widget_adjust_size(dword_t wstyle, xsize_t* pxs)
{@autoreleasepool {

    if(!(wstyle & WD_STYLE_TITLE)) return;

    NSApplication *nsApp = [NSApplication sharedApplication];
    NSWindow* nsWindow = [nsApp mainWindow];

    NSRect frameRect = [nsWindow frame];
    NSRect contentRect = [nsWindow contentRectForFrameRect:frameRect];
    CGFloat titleBarHeight = NSMaxY(frameRect) - NSMaxY(contentRect);
    CGFloat borderLeft = contentRect.origin.x - frameRect.origin.x;
    CGFloat borderRight = NSMaxX(frameRect) - NSMaxX(contentRect);
    CGFloat borderBottom = contentRect.origin.y - frameRect.origin.y;

    pxs->w += (int)(borderLeft + borderRight);
    pxs->h += (int)(titleBarHeight + borderBottom);
}}

bool_t _widget_is_maximized(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

    _CocoaView* coc_view = wt;
	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	return (pwidg->state == WS_SHOW_MAXIMIZE)? 1 : 0;
}}

bool_t _widget_is_minimized(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

    _CocoaView* coc_view = wt;
	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	return (pwidg->state == WS_SHOW_MINIMIZE)? 1 : 0;
}}

visual_t _widget_client_ctx(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return NULL;

	NSGraphicsContext *nsContext = [NSGraphicsContext currentContext];

	cocoa_context_t* ctx = (cocoa_context_t*)calloc(1, sizeof(cocoa_context_t));
	ctx->head.tag = _VISUAL_DISPLAY;
    ctx->context = [nsContext CGContext];
	ctx->type = CONTEXT_SCREEN;
	
	return (visual_t)&(ctx->head);
}}

visual_t _widget_window_ctx(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return NULL;

    _CocoaView* coc_view = wt;
    NSWindow* nsWindow = [coc_view window];

	NSGraphicsContext *nsContext = [nsWindow graphicsContext];

    cocoa_context_t* ctx = (cocoa_context_t*)calloc(1, sizeof(cocoa_context_t));
	ctx->head.tag = _VISUAL_DISPLAY;
    ctx->context = [nsContext CGContext];
	ctx->type = CONTEXT_SCREEN;

	return (visual_t)&(ctx->head);
}}

void _widget_release_ctx(res_win_t wt, visual_t dc)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    cocoa_context_t* ctx = (cocoa_context_t*)dc;
	
    free(ctx);
}}

void _widget_get_client_rect(res_win_t wt, xrect_t* prt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
	NSRect nsRect = [coc_view frame];

	prt->x = 0;
    prt->y = 0;
	prt->w = nsRect.size.width;
	prt->h = nsRect.size.height;
}}

void _widget_get_window_rect(res_win_t wt, xrect_t* prt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSRect nsRect = [coc_view frame];
        prt->x = 0;
        prt->y = 0;
        prt->w = nsRect.size.width;
        prt->h = nsRect.size.height;
    }else
    {
        NSWindow* window = [coc_view window];
        NSRect nsRect = [window frame];

        NSPoint nsOrigin = NSMakePoint(nsRect.origin.x, nsRect.origin.y);
        NSScreen* nsScreen = [window screen] ?: [NSScreen mainScreen];
        _cocoa_to_screen(nsScreen, &nsOrigin);

	    prt->x = nsOrigin.x;
        prt->y = nsOrigin.y - nsRect.size.height;
	    prt->w = nsRect.size.width;
	    prt->h = nsRect.size.height;
    }
}}

void _widget_client_to_window(res_win_t wt, xpoint_t* ppt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD)
        return;

    NSPoint cliPoint = NSMakePoint(ppt->x, ppt->y);
    _view_to_cocoa(coc_view, &cliPoint);

    NSPoint winPoint = [coc_view convertPoint:cliPoint toView:nil];
    NSWindow* nsWindow = [coc_view window];
    _cocoa_to_window(nsWindow, &winPoint);

	ppt->x = winPoint.x;
    ppt->y = winPoint.y;
}}

void _widget_window_to_client(res_win_t wt, xpoint_t* ppt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD) return;

    NSPoint winPoint = NSMakePoint(ppt->x, ppt->y);
    NSWindow* nsWindow = [coc_view window];
    _window_to_cocoa(nsWindow, &winPoint);

    NSPoint cliPoint = [coc_view convertPoint:winPoint fromView:nil];
    _cocoa_to_view(coc_view, &cliPoint);

	ppt->x = cliPoint.x;
    ppt->y = cliPoint.y;
}}

void _widget_client_to_screen(res_win_t wt, xpoint_t* ppt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;
    NSWindow* nsWindow;

    NSPoint cliPoint = NSMakePoint(ppt->x, ppt->y);
    _view_to_cocoa(coc_view, &cliPoint);

    NSPoint winPoint = [coc_view convertPoint:cliPoint toView:nil];

    if(pwidg->style & WD_STYLE_CHILD)
    {
        nsWindow = [(NSView*)pwidg->parent window];
    }
    else
    {
        nsWindow = [coc_view window];
    }

    NSScreen* nsScreen = [nsWindow screen] ?: [NSScreen mainScreen];
    NSPoint scrPoint = [nsWindow convertPointToScreen:winPoint];
    _cocoa_to_screen(nsScreen, &scrPoint);

	ppt->x = scrPoint.x;
    ppt->y = scrPoint.y;
}}

void _widget_screen_to_client(res_win_t wt, xpoint_t* ppt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    NSWindow* nsWindow = [coc_view window];
    NSScreen* screen = [nsWindow screen] ?: [NSScreen mainScreen];

    NSPoint scrPoint = NSMakePoint(ppt->x, ppt->y);
    _screen_to_cocoa(screen, &scrPoint);

    NSPoint winPoint = [nsWindow convertPointFromScreen:scrPoint];
    NSPoint cliPoint = [coc_view convertPoint:winPoint fromView:nil];

    _cocoa_to_view(coc_view, &cliPoint);

	ppt->x = cliPoint.x;
    ppt->y = cliPoint.y;
}}

void _widget_center_window(res_win_t wt, res_win_t owner)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    NSWindow* src_window = [(NSView*)wt window];
    NSWindow* dst_window = (owner)? [(NSView*)owner window] : nil ;

    if(src_window == nil) return;

    NSRect winFrame = [src_window frame];
    NSRect scrFrame = (dst_window)? [dst_window frame] : [[NSScreen mainScreen] visibleFrame];

    CGFloat newX = NSMidX(scrFrame) - (NSWidth(winFrame) / 2);
    CGFloat newY = NSMidY(scrFrame) - (NSHeight(winFrame) / 2);
    
    //[src_window setFrameOrigin:NSMakePoint(newX, newY)];
}}

void _widget_set_cursor(res_win_t wt, int ci)
{@autoreleasepool {
	switch (ci)
	{
	case CURSOR_SIZENS:
		[[NSCursor resizeUpDownCursor] set];
		break;
	case CURSOR_SIZEWE:
		[[NSCursor resizeLeftRightCursor] set];
		break;
	case CURSOR_SIZEALL:
		[[NSCursor crosshairCursor] set];
		break;
	case CURSOR_HAND:
		[[NSCursor closedHandCursor] set];
		break;
	case CURSOR_HELP:
		[[NSCursor pointingHandCursor] set];
		break;
	case CURSOR_DRAG:
		[[NSCursor closedHandCursor] set];
		break;
	case CURSOR_ARROW:
		[[NSCursor arrowCursor] set];
		break;
	case CURSOR_IBEAM:
		[[NSCursor IBeamCursor] set];
		break;
	default:
        [[NSCursor arrowCursor] set];
		break;
	}
}}

void _widget_set_capture(res_win_t wt, bool_t b)
{@autoreleasepool {
	NOP;
}}

vword_t _widget_set_timer(res_win_t wt, int ms)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD) return 0;

    _CocoaWindow* coc_window = [coc_view window];
	coc_window.schedule = [NSTimer scheduledTimerWithTimeInterval:(ms / 1000.0)
                                                    target:coc_window
                                                    selector:@selector(scheduleTimer)
                                                    userInfo:nil
                                                    repeats:YES];
}}

void _widget_kill_timer(res_win_t wt, vword_t tid)
{@autoreleasepool {
	if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD) return;

    _CocoaWindow* coc_window = [coc_view window];
    if(coc_window.schedule)
    {
        [coc_window.schedule invalidate];
        coc_window.schedule = nil;
    }
}}

void _widget_create_caret(res_win_t wt, int w, int h)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;

    coc_view.caret_visible = YES;
    coc_view.caret_timer = [NSTimer scheduledTimerWithTimeInterval:0.5
                                                    target:coc_view
                                                    selector:@selector(toggleCaret)
                                                    userInfo:nil
                                                    repeats:YES];
    coc_view.caret_rect = NSMakeRect(0, 0, w, h);                                              
    [coc_view setNeedsDisplayInRect:[coc_view caret_rect]];
}}

void _widget_destroy_caret(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

	 _CocoaView* coc_view = wt;

     coc_view.caret_visible = NO;

     if(coc_view.caret_timer)
     {
         [coc_view.caret_timer invalidate];
         coc_view.caret_timer = nil;
     }

     [coc_view setNeedsDisplayInRect:[coc_view caret_rect]];
}}

void _widget_show_caret(res_win_t wt, int x, int y, bool_t b)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

	_CocoaView* coc_view = wt;

    coc_view.caret_visible = b;
    if(b)
    {
        NSPoint nsPoint = NSMakePoint(x, y);
        _view_to_cocoa(coc_view, &nsPoint);
        coc_view.caret_rect = NSMakeRect(nsPoint.x, nsPoint.y, coc_view.caret_rect.size.width, coc_view.caret_rect.size.height);
    }
    [coc_view setNeedsDisplayInRect:coc_view.caret_rect];
}}

void _widget_set_focus(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

	 NSWindow* nsWindow = [(NSView*)wt window];
    if(nsWindow)
    {
        [nsWindow makeFirstResponder:(NSView*)wt];
        return;
    }

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;
    nsWindow = (pwidg->parent)? [(NSView*)pwidg->parent window] : nil;
    if(nsWindow == nil) return;

	[nsWindow makeFirstResponder:(NSView*)wt];
}}

bool_t _widget_key_state(res_win_t wt, int ks)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    return (ks & pwidg->keymsk)? 1 : 0;
}}

bool_t _widget_is_valid(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	return (pwidg == NULL)? 0 : 1;
}}

bool_t _widget_is_focus(res_win_t wt)
{@autoreleasepool {
	NSWindow* window = [(NSView*)wt window];

    if(window == nil) return 0;

    return ([window firstResponder] == wt)? 1 : 0;
}}

bool_t _widget_is_child(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	return (pwidg->style & WD_STYLE_CHILD)? 1 : 0;
}}

bool_t _widget_is_ownc(res_win_t wt)
{@autoreleasepool {
	if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	return (pwidg->style & WD_STYLE_OWNERNC)? 1 : 0;
}}

void _widget_move(res_win_t wt, const xpoint_t* ppt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

	_CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    NSPoint newPosition = NSMakePoint(ppt->x, ppt->y);

    if(pwidg->style & WD_STYLE_CHILD)
    {
        _view_to_cocoa(coc_view, &newPosition);
        [coc_view setFrameOrigin:newPosition];
    }
    else
    {
        NSWindow* nsWindow = [(NSView*)wt window];
        NSScreen* nsScreen = [nsWindow screen] ?: [NSScreen mainScreen];

        _screen_to_cocoa(nsScreen, &newPosition);
        [nsWindow setFrameOrigin:newPosition];
    }
}}

void _widget_size(res_win_t wt, const xsize_t* pxs)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSRect frmRect = [coc_view frame];
        frmRect.size = NSMakeSize(pxs->w, pxs->h);
        [coc_view setFrame:frmRect display:YES];
    }
    else
    {
        NSWindow* nsWindow = [coc_view window];
        NSRect frmRect = [nsWindow frame];
        frmRect.size = NSMakeSize(pxs->w, pxs->h);
        [nsWindow setFrame:frmRect display:YES];
    }
}}

void _widget_take(res_win_t wt, int zor)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD) return;

    NSWindow* coc_window = [(NSView*)coc_view window];

    if(coc_window == nil) return;

	switch(zor)
	{
	case WS_TAKE_TOP:
		[coc_window orderFront:nil];
		break;
	case WS_TAKE_BOTTOM:
		[coc_window orderBack:nil];
		break;
	case WS_TAKE_TOPMOST:
		[coc_window setLevel:NSFloatingWindowLevel];
		break;
	case WS_TAKE_NOTOPMOST:
		[coc_window setLevel:NSNormalWindowLevel];
		break;
	}
}}

void _widget_show(res_win_t wt, dword_t sw)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    NSWindow* coc_window = (pwidg->style & WD_STYLE_CHILD)? nil : [(NSView*)coc_view window];

	switch(sw)
	{
	case WS_SHOW_MINIMIZE:
        if(coc_window == nil) break;

		[coc_window miniaturize:nil];
		pwidg->state = WS_SHOW_MINIMIZE;
		break;
	case WS_SHOW_MAXIMIZE:
        if(coc_window == nil) break;

        NSRect nsFrame = [[coc_window screen] visibleFrame];
        [coc_window setFrame:nsFrame display:YES animate:NO];
        pwidg->state = WS_SHOW_MAXIMIZE;
        break;
    case WS_SHOW_FULLSCREEN:
        if(coc_window == nil) break;

		[coc_window toggleFullScreen:nil];
		pwidg->state = WS_SHOW_FULLSCREEN;
		break;
	case WS_SHOW_HIDE:
        if(coc_window == nil)
        {
            [coc_view setHidden:YES];
        }else
        {
		    [coc_window orderOut:nil];
        }
        pwidg->state = WS_SHOW_HIDE;
		break;
	default:
        if(coc_window == nil)
        {
            [coc_view setHidden:NO];
        }else
        {
		    [coc_window makeKeyAndOrderFront:nil];
        }
		pwidg->state = WS_SHOW_NORMAL;
		break;
	}
}}

void _widget_paint(res_win_t wt)
{@autoreleasepool {
    [(NSView*)wt setNeedsDisplay:YES];
}}

void _widget_layout(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD) return;

    NSWindow* coc_window = [(NSView*)coc_view window];

    [[NSNotificationCenter defaultCenter] postNotificationName:NSWindowDidResizeNotification
                        object:coc_window];
}}

void _widget_erase(res_win_t wt, const xrect_t* prt)
{@autoreleasepool {  
    if(prt)
    {
        NSPoint nsPoint = NSMakePoint(prt->x, prt->y);
         _view_to_cocoa((NSView*)wt, &nsPoint);
    
        NSRect nsRect = NSMakeRect(nsPoint.x, nsPoint.y, prt->w, prt->h);
        [(NSView*)wt setNeedsDisplayInRect:nsRect];
    }
    else
    {
        [(NSView*)wt setNeedsDisplay:YES];
    }
}}

void _widget_enable(res_win_t wt, bool_t b)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

	_CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    pwidg->disable = b;
}}

void _widget_post_notice(res_win_t wt, NOTICE* pnt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

	_CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;
    vword_t delta = (vword_t)pnt;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSMutableDictionary *userInfo = @{
            @"delta" : @(delta)
        };
        dispatch_async(dispatch_get_main_queue(),^{
            [[NSNotificationCenter defaultCenter] postNotificationName:NoticeMessage
                                          object:coc_view
                                          userInfo:userInfo];});
    }
    else
    {
        NSWindow* nsWindow = [(NSView*)coc_view window];
        NSMutableDictionary *userInfo = @{
            @"delta" : @(delta)
        };
        dispatch_async(dispatch_get_main_queue(),^{
            [[NSNotificationCenter defaultCenter] postNotificationName:NoticeMessage
                                          object:nsWindow
                                          userInfo:userInfo];});
    }
}}

int _widget_send_notice(res_win_t wt, NOTICE* pnt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

	_CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;
    vword_t delta = (vword_t)pnt;
    int result = 0;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSMutableDictionary *userInfo = @{
            @"delta" : @(delta)
        };
        [[NSNotificationCenter defaultCenter] postNotificationName:NoticeMessage
                                          object:coc_view
                                          userInfo:userInfo];
    }
    else
    {
        NSWindow* nsWindow = [(NSView*)coc_view window];
        NSMutableDictionary *userInfo = @{
            @"delta" : @(delta)
        };
        [[NSNotificationCenter defaultCenter] postNotificationName:NoticeMessage
                                          object:nsWindow
                                          userInfo:userInfo];
    }

    return pwidg->result;
}}

void _widget_post_command(res_win_t wt, int code, uid_t cid, vword_t data)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

	_CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSDictionary *userInfo = @{
            @"code": @(code),
            @"user": @(cid),
            @"data": @(data)
        };
        dispatch_async(dispatch_get_main_queue(),^{
        [[NSNotificationCenter defaultCenter] postNotificationName:CommandMessage
                                              object:coc_view
                                              userInfo:userInfo];});
    }
    else
    {
        NSWindow* nsWindow = [(NSView*)coc_view window];
        NSWindow* window = [coc_view window];
        NSDictionary *userInfo = @{
            @"code": @(code),
            @"user": @(cid),
            @"data": @(data)
        };

        dispatch_async(dispatch_get_main_queue(),^{
        [[NSNotificationCenter defaultCenter] postNotificationName:CommandMessage
                                          object:nsWindow
                                          userInfo:userInfo];});
    }
}}

int _widget_send_command(res_win_t wt, int code, uid_t cid, vword_t data)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

	_CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSDictionary *userInfo = @{
            @"code": @(code),
            @"user": @(cid),
            @"data": @(data)
        };
        [[NSNotificationCenter defaultCenter] postNotificationName:CommandMessage
                                              object:coc_view
                                              userInfo:userInfo];
    }
    else
    {
        NSWindow* nsWindow = [coc_view window];
        NSDictionary *userInfo = @{
            @"code": @(code),
            @"user": @(cid),
            @"data": @(data)
        };
        [[NSNotificationCenter defaultCenter] postNotificationName:CommandMessage
                                          object:nsWindow
                                          userInfo:userInfo];
    }

    return pwidg->result;
}}

void _widget_post_wchar(res_win_t wt, wchar_t ch)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;
    NSWindow* nsWindow = [(NSView*)coc_view window];

    NSString* nsString = [NSString stringWithCharacters:&ch length:1];

    NSEvent *nsKeydown = [NSEvent keyEventWithType:NSEventTypeKeyDown
                                  location:NSMakePoint(0,0)
                             modifierFlags:0
                                 timestamp:0
                              windowNumber:[nsWindow windowNumber]
                                   context:nil
                                characters:nsString
               charactersIgnoringModifiers:nsString
                                 isARepeat:NO
                                   keyCode:0];
    //[coc_view interpretKeyEvents:@[nsKeydown]];
    [NSApp postEvent:nsKeydown atStart:NO];

    NSEvent *nsKeyup = [NSEvent keyEventWithType:NSEventTypeKeyUp
                                  location:NSMakePoint(0,0)
                             modifierFlags:0
                                 timestamp:0
                              windowNumber:[nsWindow windowNumber]
                                   context:nil
                                characters:nsString
               charactersIgnoringModifiers:nsString
                                 isARepeat:NO
                                   keyCode:0];
    //[coc_view interpretKeyEvents:@[nsKeyup]];
    [NSApp postEvent:nsKeyup atStart:NO];
}}

void _widget_post_key(res_win_t wt, int key)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    NSWindow* nsWindow = [(NSView*)coc_view window];
    NSString *nsString = [NSString stringWithFormat:@"%c", key];

    NSEvent *nsKeydown = [NSEvent keyEventWithType:NSEventTypeKeyDown
                                         location:NSMakePoint(0, 0)
                                    modifierFlags:0
                                        timestamp:0
                                     windowNumber:[nsWindow windowNumber]
                                          context:nil
                                       characters:nsString
                      charactersIgnoringModifiers:nsString
                                        isARepeat:NO
                                          keyCode:key];

    //[window sendEvent:nsKeydown];
    [NSApp postEvent:nsKeydown atStart:NO];

    NSEvent *nsKeyup = [NSEvent keyEventWithType:NSEventTypeKeyUp
                                         location:NSMakePoint(0, 0)
                                    modifierFlags:0
                                        timestamp:0
                                     windowNumber:[nsWindow windowNumber]
                                          context:nil
                                       characters:nsString
                      charactersIgnoringModifiers:nsString
                                        isARepeat:NO
                                          keyCode:key];

   // [window sendEvent:nsKeyup];
   [NSApp postEvent:nsKeyup atStart:NO];
}}

void _widget_set_title(res_win_t wt, const tchar_t* token)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(!(pwidg->style & WD_STYLE_TITLE)) return;

    NSWindow* coc_window = [(NSView*)coc_view window];
    NSString *title = [NSString stringWithUTF8String:token];

    [coc_window setTitle:title];
}}

int _widget_get_title(res_win_t wt, tchar_t* buf, int max)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

	_CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(!(pwidg->style & WD_STYLE_TITLE)) return 0;

    NSWindow* coc_window = [(NSView*)coc_view window];
    NSString *title = [coc_window title];
    const char *token = [title UTF8String];
    int len = (int)strlen(token);
    len = (len < max) ? len : max;
    if(buf)
    {
        xsncpy(buf, token, len);
    }
    return len;
}}

void _widget_active(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD) return;

    NSWindow* coc_window = [(NSView*)coc_view window];

    //[coc_window makeMainWindow];
    [coc_window makeKeyAndOrderFront:nil];
}}

void _widget_scroll(res_win_t wt, bool_t horz, int line)
{@autoreleasepool {
    if (![(NSView*)wt isKindOfClass:[NSScrollView class]]) 
        return; 
    
    NSScrollView *scrollView = (NSScrollView *)wt;
    NSPoint newOrigin = [[scrollView contentView] bounds].origin;

    if (horz) {
        newOrigin.x += line; 
    } else {
        newOrigin.y += line; 
    }

    [[scrollView contentView] scrollToPoint:newOrigin];
    [scrollView reflectScrolledClipView:[scrollView contentView]];
}}

void _widget_get_scroll_info(res_win_t wt, bool_t horz, scroll_t* psl)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	if(horz)
		memcpy((void*)psl, (void*)&(pwidg->hs), sizeof(scroll_t));
	else
		memcpy((void*)psl, (void*)&(pwidg->vs), sizeof(scroll_t));
}}

static int CALLBACK _update_horz_position(res_win_t child, vword_t b)
{@autoreleasepool {
    _CocoaView* coc_view = child;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSPoint orgPosition = [coc_view frame].origin;
        NSPoint newPosition = NSMakePoint(orgPosition.x + *(int*)b, orgPosition.y);
        [coc_view setFrameOrigin:newPosition];
    }
    else
    {
        NSWindow* nsWindow = [(NSView*)child window];

        NSPoint orgPosition = [nsWindow frame].origin;
        NSPoint newPosition = NSMakePoint(orgPosition.x + *(int*)b, orgPosition.y);
        [nsWindow setFrameOrigin:newPosition];
    }

	return (0);
}}

static int CALLBACK _update_vert_position(res_win_t child, vword_t b)
{@autoreleasepool {
    _CocoaView* coc_view = child;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSPoint orgPosition = [coc_view frame].origin;
        NSPoint newPosition = NSMakePoint(orgPosition.x, orgPosition.y - *(int*)b);
        [coc_view setFrameOrigin:newPosition];
    }
    else
    {
        NSWindow* nsWindow = [(NSView*)child window];

        NSPoint orgPosition = [nsWindow frame].origin;
        NSPoint newPosition = NSMakePoint(orgPosition.x, orgPosition.y - *(int*)b);
        [nsWindow setFrameOrigin:newPosition];
    }

	return (0);
}}

void _widget_set_scroll_info(res_win_t wt, bool_t horz, const scroll_t* psl)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;
	int b;

	if(horz)
	{
		b = (psl->pos - pwidg->hs.pos);
		memcpy((void*)&(pwidg->hs), (void*)psl, sizeof(scroll_t));

		if(!b) return;

		_widget_enum_child(wt, (PF_ENUM_WINDOW_PROC)_update_horz_position, (vword_t)&b);
	}
	else
	{
		b = (psl->pos - pwidg->vs.pos);
		memcpy((void*)&(pwidg->vs), (void*)psl, sizeof(scroll_t));

		if(!b) return;

		_widget_enum_child(wt, (PF_ENUM_WINDOW_PROC)_update_vert_position, (vword_t)&b);
	}
}}

bool_t _widget_has_struct(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return 0;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    return (pwidg)? 1 : 0;
}}

void _widget_set_point(res_win_t wt, const xpoint_t* ppt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	memcpy((void*)&pwidg->pt, (void*)ppt, sizeof(xpoint_t));
}}

void _widget_get_point(res_win_t wt, xpoint_t* ppt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	memcpy((void*)ppt, (void*)&pwidg->pt, sizeof(xpoint_t));
}}

void _widget_set_size(res_win_t wt, const xsize_t* pst)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	memcpy((void*)&pwidg->st, (void*)pst, sizeof(xsize_t));
}}

void _widget_get_size(res_win_t wt, xsize_t* pst)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	memcpy((void*)pst, (void*)&pwidg->st, sizeof(xsize_t));
}}

static int CALLBACK _widget_set_child_color_mode(res_win_t wt, vword_t pv)
{@autoreleasepool {
	if (_widget_has_struct(wt))
	{
		dword_t dw = _widget_get_style(wt);
		if (dw & WD_STYLE_NOCHANGE)
			return 1;

		_widget_set_color_mode(wt, (const clr_mod_t*)pv);
	}

	return 1;
}}

void _widget_set_color_mode(res_win_t wt, const clr_mod_t* pclr)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

	dword_t dw = pwidg->style;

    memcpy((void*)&pwidg->clrs, (void*)pclr, sizeof(clr_mod_t));

	NSColor *nsColor = [NSColor colorWithCalibratedRed:(float)(pwidg->clrs.clr_bkg.r) / 255.0f
                                    green:(float)(pwidg->clrs.clr_bkg.g) / 255.0f
                                    blue:(float)(pwidg->clrs.clr_bkg.b) / 255.0f
                                    alpha:1.0f];

    [coc_view setWantsLayer:YES];
    coc_view.layer.backgroundColor = [nsColor CGColor];

	_widget_send_command(wt, COMMAND_COLOR, IDC_SELF, (vword_t)pclr);

	if (dw & WD_STYLE_NOCHANGE) return;

	_widget_enum_child(wt, _widget_set_child_color_mode, (vword_t)pclr);
}}

void _widget_get_color_mode(res_win_t wt, clr_mod_t* pclr)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    memcpy((void*)pclr, (void*)&pwidg->clrs, sizeof(clr_mod_t));
}}

void _widget_noti_xfont(res_win_t wt, const xfont_t* pxf)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    if_dispatch_t* pdisp = (if_dispatch_t*)coc_view.dispatch;

	if(pdisp && pdisp->pf_on_xfont)
	{
		(*pdisp->pf_on_xfont)(wt, pxf);
	}
}}

void _widget_noti_xface(res_win_t wt, const xface_t* pxa)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    if_dispatch_t* pdisp = (if_dispatch_t*)coc_view.dispatch;

	if(pdisp && pdisp->pf_on_xface)
	{
		(*pdisp->pf_on_xface)(wt, pxa);
	}
}}

void _widget_noti_xbrush(res_win_t wt, const xbrush_t* pxb)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    if_dispatch_t* pdisp = (if_dispatch_t*)coc_view.dispatch;

	if(pdisp && pdisp->pf_on_xbrush)
	{
		(*pdisp->pf_on_xbrush)(wt, pxb);
	}
}}

void _widget_noti_xpen(res_win_t wt, const xpen_t* pxp)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]])
        return;

    _CocoaView* coc_view = wt;
    if_dispatch_t* pdisp = (if_dispatch_t*)coc_view.dispatch;

	if(pdisp && pdisp->pf_on_xpen)
	{
		(*pdisp->pf_on_xpen)(wt, pxp);
	}
}}

int	_widget_do_main(res_win_t wt)
{@autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]]) return 0;

    _CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD) return 0;

    _CocoaWindow* coc_window = [coc_view window];
    coc_window.running = _CocoaWindowRunMain;

    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    _CocoaApplicationDelegate *app_delegate = [[_CocoaApplicationDelegate alloc] init];
    [NSApp setDelegate:app_delegate];
    [NSApp run];
    }

	return 0;
}

int	_widget_do_modal(res_win_t wt)
{
    int ret = 0;
    @autoreleasepool {
    if(![(NSView*)wt isKindOfClass:[_CocoaView class]]) return 0;

	_CocoaView* coc_view = wt;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;

    if(pwidg->style & WD_STYLE_CHILD) return 0;

    _CocoaWindow* coc_window = [coc_view window];
    coc_window.running = _CocoaWindowRunModal;

    [coc_window setLevel:NSFloatingWindowLevel];
    [coc_window makeKeyAndOrderFront:nil];

    [NSApp runModalForWindow:coc_window];

    ret = pwidg->result;
    }

    return ret;
}

void _widget_do_track(res_win_t wt)
{@autoreleasepool {
	if(![(NSView*)wt isKindOfClass:[_CocoaView class]]) return;
}}

/*---------------------------------------------------------------*/

void _get_screen_size(xsize_t* pxs)
{
    NSScreen *mainScreen = [NSScreen mainScreen];
    NSRect screenFrame = [mainScreen frame];

    pxs->w = (int)screenFrame.size.width;
    pxs->h = (int)screenFrame.size.height;
}

void _get_desktop_size(xsize_t* pxs)
{
    NSScreen *mainScreen = [NSScreen mainScreen];
    NSRect visibleFrame = [mainScreen visibleFrame];

    pxs->w = (int)visibleFrame.size.width;
    pxs->h = (int)visibleFrame.size.height;
}

void _screen_size_to_tm(xsize_t* pxs)
{
	pxs->fw = (float)((double)pxs->w * MMPERPT);
	pxs->fh = (float)((double)pxs->h * MMPERPT);
}

void _screen_size_to_pt(xsize_t* pxs)
{
	pxs->w = (int)((double)pxs->fw * PTPERMM);
	pxs->h = (int)((double)pxs->fh * PTPERMM);
}

res_acl_t _create_accel_table(const accel_t* pac, int n)
{
	accel_t* pnew;

	pnew = (accel_t*)calloc(n + 1, sizeof(accel_t));
	memcpy((void*)pnew, (void*)pac, n * sizeof(accel_t));

	pnew[n].vir = 0;
	pnew[n].key = 0;

	pnew[n].cmd = 0;

	return (res_acl_t)pnew;
}

void _destroy_accel_table(res_acl_t hac)
{
	accel_t* pac = (accel_t*)hac;

	free(pac);
}

void _widget_track_mouse(res_win_t wt, dword_t mask)
{

}

void _widget_set_alpha(res_win_t wt, unsigned char b)
{

}

unsigned char _widget_get_alpha(res_win_t wt)
{
	return (unsigned char)0;
}

#endif //XDU_SUPPORT_WIDGET