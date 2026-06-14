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

#include "_if_cocoa.h"

#import <QuartzCore/CAMetalLayer.h>
#import <AppKit/AppKit.h>

#include <Carbon/Carbon.h>
#include <IOKit/hid/IOHIDLib.h>


#include <float.h>
#include <string.h>
#include <assert.h>


static const NSRange NullRange = { NSNotFound, 0 };

#ifndef NSEscapeCharacter
#define NSEscapeCharacter 0x001B
#endif

#ifndef NSSpaceCharacter
#define NSSpaceCharacter 0x0020
#endif

static int _cocoa_to_keycode(unichar uch)
{
    switch (uch)
    {
        case NSDeleteCharacter: return KEY_BACK;
        //case NSBackspaceCharacter: return KEY_BACK; 
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

static unichar _keycode_to_cocoa(int key)
{
    switch (key)
    {
        case KEY_BACK: return NSDeleteCharacter; 
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

static dword_t _key_state(NSUInteger nsFlags)
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
    if (nsFlags & NSEventModifierFlagCommand)
        mask |= KS_WITH_CMD;

    return mask;
}

static dword_t _mouse_state(NSUInteger nsState)
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

static void _nscolor_to_xcolor(NSColor* nsclr, xcolor_t* xclr)
{
    CGFloat r = 0, g = 0, b = 0, a = 1;

    NSColor *srgb = [nsclr colorUsingColorSpace:[NSColorSpace sRGBColorSpace]];
    [srgb getRed:&r green:&g blue:&b alpha:&a];
    
    xclr->r = (uint8_t)lrintf(fminf(fmaxf(r, 0.f), 1.f) * 255.f);
    xclr->g = (uint8_t)lrintf(fminf(fmaxf(g, 0.f), 1.f) * 255.f);
    xclr->b = (uint8_t)lrintf(fminf(fmaxf(b, 0.f), 1.f) * 255.f);
    xclr->a = (uint8_t)lrintf(fminf(fmaxf(a, 0.f), 1.f) * 255.f);
}

static NSColor* _xcolor_to_nscolor(xcolor_t* xclr)
{
    return [NSColor colorWithColorSpace:[NSColorSpace sRGBColorSpace]
                             components:(CGFloat[]){ xclr->r/255.0, xclr->g/255.0, xclr->b/255.0, 1.0f }
                                  count:4];
}
/**************************************************************************************/

@interface _CocoaApplicationDelegate : NSObject{}
    @property (assign, nonatomic) id trackview;
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
    NSMutableAttributedString* texting;
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
- (void)setFrameSize:(NSSize)newSize;

@end

@interface _CocoaWindow : NSWindow {}
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
NSString *const HideNotification = @"HideNotification";
NSString *const UnHideNotification = @"UnHideNotification";

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
    [[NSNotificationCenter defaultCenter] addObserver:self
                                            selector:@selector(handleViewFrameChanged:)
                                            name:NSViewFrameDidChangeNotification
                                            object:initView];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                            selector:@selector(handleViewVisibilityChanged:)
                                            name:HideNotification
                                            object:initView];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                            selector:@selector(handleViewVisibilityChanged:)
                                            name:UnHideNotification
                                            object:initView];
    return self;
}

- (void)handleViewNotice:(NSNotification *)notification 
{@autoreleasepool {
    _CocoaView* ref_view = notification.object;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSDictionary *userInfo = notification.userInfo;
    NOTICE* pnt = (NOTICE*)[userInfo[@"delta"] unsignedLongValue];

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_notice)
    {
        pwidg->result = (*psubp->sub_on_notice)((widget_t)&(pwidg->head), pnt, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if (pdisp && pdisp->pf_on_notice)
    {
        (*pdisp->pf_on_notice)((widget_t)&(pwidg->head), pnt);
        pwidg->result = 1;
    }
}}

- (void)handleViewCommand:(NSNotification *)notification 
{@autoreleasepool {
    _CocoaView* ref_view = notification.object;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSDictionary *userInfo = notification.userInfo;
    int code = (int)[userInfo[@"code"] intValue];
    dword_t cid = (dword_t)[userInfo[@"user"] unsignedIntValue];
    vword_t data = (vword_t)[userInfo[@"data"] unsignedLongValue];

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    switch(cid)
    {
    case IDC_PARENT:
        if (psubp && psubp->sub_on_parent_command)
        {
            pwidg->result = (*psubp->sub_on_parent_command)((widget_t)&(pwidg->head), code, data, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }
    break;
    case IDC_CHILD:
        if (psubp && psubp->sub_on_child_command)
        {
            pwidg->result = (*psubp->sub_on_child_command)((widget_t)&(pwidg->head), code, data, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }
    break;
    case IDC_SELF:
        if (psubp && psubp->sub_on_self_command)
        {
            pwidg->result = (*psubp->sub_on_self_command)((widget_t)&(pwidg->head), code, data, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }
    break;
    default:
        if (psubp && psubp->sub_on_menu_command)
        {
            pwidg->result = (*psubp->sub_on_menu_command)((widget_t)&(pwidg->head), code, cid, data, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }
    break;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    switch(cid)
    {
    case IDC_PARENT:
        if (pdisp && pdisp->pf_on_parent_command)
        {
            (*pdisp->pf_on_parent_command)((widget_t)&(pwidg->head), code, data);
            pwidg->result = 1;
        }
    break;
    case IDC_CHILD:
        if (pdisp && pdisp->pf_on_child_command)
        {
            (*pdisp->pf_on_child_command)((widget_t)&(pwidg->head), code, data);
            pwidg->result = 1;
        }
    break;
    case IDC_SELF:
        if (pdisp && pdisp->pf_on_self_command)
        {
            (*pdisp->pf_on_self_command)((widget_t)&(pwidg->head), code, data);
            pwidg->result = 1;
        }
    break;
    default:
        if (pdisp && pdisp->pf_on_menu_command)
        {
            (*pdisp->pf_on_menu_command)((widget_t)&(pwidg->head), code, cid, data);
            pwidg->result = 1;
        }
    break;
    }
}}

- (void)handleViewFrameChanged:(NSNotification*)notification
{@autoreleasepool {
    _CocoaView* ref_view = notification.object;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if(!(pwidg->style & WD_STYLE_CHILD)) return;

    NSRect nsFrame = [ref_view frame];
    xsize_t xs;
    xs.w = (int)nsFrame.size.width;
    xs.h = (int)nsFrame.size.height;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_size)
    {
        pwidg->result = (*psubp->sub_on_size)((widget_t)&(pwidg->head), WS_SIZE_RESTORE, &xs, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_size)
    {
        (*pdisp->pf_on_size)((widget_t)&(pwidg->head), WS_SIZE_RESTORE, &xs);
    }
}}

- (void)handleViewVisibilityChanged:(NSNotification*)notification
{@autoreleasepool {
    _CocoaView* ref_view = notification.object;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    bool_t visible = ([notification.name isEqualToString:HideNotification]) ? 0 : 1;
    
    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_show)
    {
        pwidg->result = (*psubp->sub_on_show)((widget_t)&(pwidg->head), visible, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_show)
    {
        (*pdisp->pf_on_show)((widget_t)&(pwidg->head), visible);
    }
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
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSMutableDictionary *userInfo = notification.userInfo;
    NOTICE* pnt = (NOTICE*)[userInfo[@"delta"] unsignedLongValue];

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_notice)
    {
        pwidg->result = (*psubp->sub_on_notice)((widget_t)&(pwidg->head), pnt, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if (pdisp && pdisp->pf_on_notice)
    {
        (*pdisp->pf_on_notice)((widget_t)&(pwidg->head), pnt);
        pwidg->result = 1;
    }
}}

- (void)handleWindowCommand:(NSNotification *)notification 
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;
    
    NSDictionary *userInfo = notification.userInfo;
    int code = (int)[userInfo[@"code"] intValue];
    dword_t cid = (dword_t)[userInfo[@"user"] unsignedIntValue];
    vword_t data = (vword_t)[userInfo[@"data"] unsignedLongValue];

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    switch(cid)
    {
    case IDC_PARENT:
        if (psubp && psubp->sub_on_parent_command)
        {
            pwidg->result = (*psubp->sub_on_parent_command)((widget_t)&(pwidg->head), code, data, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }
    break;
    case IDC_CHILD:
        if (psubp && psubp->sub_on_child_command)
        {
            pwidg->result = (*psubp->sub_on_child_command)((widget_t)&(pwidg->head), code, data, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }
    break;
    case IDC_SELF:
        if (psubp && psubp->sub_on_self_command)
        {
            pwidg->result = (*psubp->sub_on_self_command)((widget_t)&(pwidg->head), code, data, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }
    break;
    default:
        if (psubp && psubp->sub_on_menu_command)
        {
            pwidg->result = (*psubp->sub_on_menu_command)((widget_t)&(pwidg->head), code, cid, data, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }
    break;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    switch(cid)
    {
    case IDC_PARENT:
        if (pdisp && pdisp->pf_on_parent_command)
        {
            (*pdisp->pf_on_parent_command)((widget_t)&(pwidg->head), code, data);
            pwidg->result = 1;
        }
    break;
    case IDC_CHILD:
        if (pdisp && pdisp->pf_on_child_command)
        {
            (*pdisp->pf_on_child_command)((widget_t)&(pwidg->head), code, data);
            pwidg->result = 1;
        }
    break;
    case IDC_SELF:
        if (pdisp && pdisp->pf_on_self_command)
        {
            (*pdisp->pf_on_self_command)((widget_t)&(pwidg->head), code, data);
            pwidg->result = 1;
        }
    break;
    default:
        if (pdisp && pdisp->pf_on_menu_command)
        {
            (*pdisp->pf_on_menu_command)((widget_t)&(pwidg->head), code, cid, data);
            pwidg->result = 1;
        }
    break;
    }
}}

- (BOOL)windowShouldClose:(NSWindow *)sender
{@autoreleasepool {
    _CocoaWindow* ref_window = sender;
    _CocoaView* ref_view = [ref_window contentView];
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_close)
    {
        pwidg->result = (*psubp->sub_on_close)((widget_t)&(pwidg->head), psubp->sid, psubp->delta);
        if(pwidg->result) return NO;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if (pdisp && pdisp->pf_on_close)
     {
        if((*pdisp->pf_on_close)((widget_t)&(pwidg->head)))
            return NO;
    }

    return YES;
}}

- (void)windowWillClose:(NSNotification *)notification 
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    int mode = pwidg->mode;
    pwidg->mode = WS_MODE_INVALID;

    switch(mode)
    {
    case WS_MODE_MAIN:
        [NSApp stop:nil];
        break;
    case WS_MODE_MODAL:
        [NSApp stopModal];
        break;
    case WS_MODE_TRACK:
        _CocoaApplicationDelegate* appDelegate = [NSApp delegate];
        appDelegate.trackview = nil;
        [NSApp stopModal];
        break;
    }
}}

- (void)windowDidResize:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSScreen *nsScreen = [ref_window screen] ?: [NSScreen mainScreen];

    NSRect newFrame = [ref_window frame];
    NSRect scrFrame = [nsScreen visibleFrame];

    xsize_t xs;
    xs.w = (int)newFrame.size.width;
    xs.h = (int)newFrame.size.height;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_size)
    {
        if (NSEqualRects(newFrame, scrFrame))
            pwidg->result = (*psubp->sub_on_size)((widget_t)&(pwidg->head), WS_SIZE_MAXIMIZED, &xs, psubp->sid, psubp->delta);
        else
            pwidg->result = (*psubp->sub_on_size)((widget_t)&(pwidg->head), WS_SIZE_RESTORE, &xs, psubp->sid, psubp->delta);
        
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_size)
    {
        if (NSEqualRects(newFrame, scrFrame))
            (*pdisp->pf_on_size)((widget_t)&(pwidg->head), WS_SIZE_MAXIMIZED, &xs);
        else
            (*pdisp->pf_on_size)((widget_t)&(pwidg->head), WS_SIZE_RESTORE, &xs);
    }
}}

- (void)windowDidEnterFullScreen:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if(pwidg->state == WS_SHOW_FULLSCREEN)
        return;

    NSRect newFrame = [ref_window frame];

    xsize_t xs;
    xs.w = (int)newFrame.size.width;
    xs.h = (int)newFrame.size.height;

    pwidg->state = WS_SHOW_FULLSCREEN;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_size)
    {
        pwidg->result = (*psubp->sub_on_size)((widget_t)&(pwidg->head), WS_SIZE_FULLSCREEN, &xs, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_size)
    {
        (*pdisp->pf_on_size)((widget_t)&(pwidg->head), WS_SIZE_FULLSCREEN, &xs);
    }
}}

- (void)windowDidExitFullScreen:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if(pwidg->state != WS_SHOW_FULLSCREEN)
        return;

    NSRect newFrame = [ref_window frame];

    xsize_t xs;
    xs.w = (int)newFrame.size.width;
    xs.h = (int)newFrame.size.height;

    pwidg->state = WS_SHOW_NORMAL;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_size)
    {
        pwidg->result = (*psubp->sub_on_size)((widget_t)&(pwidg->head), WS_SIZE_RESTORE, &xs, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_size)
    {
        (*pdisp->pf_on_size)((widget_t)&(pwidg->head), WS_SIZE_RESTORE, &xs);
    }
}}

- (void)windowDidMove:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];
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

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_move)
    {
        pwidg->result = (*psubp->sub_on_move)((widget_t)&(pwidg->head), &pt, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_move)
    {
        (*pdisp->pf_on_move)((widget_t)&(pwidg->head), &pt);
    }
}}

- (void)windowDidMiniaturize:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if(pwidg->state == WS_SHOW_MINIMIZE)
        return;
    
    pwidg->state = WS_SHOW_MINIMIZE;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_size)
    {
        xsize_t xs;
        xs.w = 0;
        xs.h = 0;
        pwidg->result = (*psubp->sub_on_size)((widget_t)&(pwidg->head), WS_SIZE_MINIMIZED, &xs, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_size)
    {
        xsize_t xs;
        xs.w = 0;
        xs.h = 0;
        (*pdisp->pf_on_size)((widget_t)&(pwidg->head), WS_SIZE_MINIMIZED, &xs);
    }
}}

- (void)windowDidDeminiaturize:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSRect newFrame = [ref_window frame];
 
    xsize_t xs;
    xs.w = (int)newFrame.size.width;
    xs.h = (int)newFrame.size.height;

    if(pwidg->state != WS_SHOW_MINIMIZE)
        return;

    pwidg->state = WS_SHOW_NORMAL;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_size)
    {
        pwidg->result = (*psubp->sub_on_size)((widget_t)&(pwidg->head), WS_SIZE_RESTORE, &xs, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_size)
    {
        (*pdisp->pf_on_size)((widget_t)&(pwidg->head), WS_SIZE_RESTORE, &xs);
    }
}}

- (void)windowDidBecomeMain:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_activate)
    {
        pwidg->result = (*psubp->sub_on_activate)((widget_t)&(pwidg->head), 1, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_activate)
    {
        (*pdisp->pf_on_activate)((widget_t)&(pwidg->head), 1);
    }
}}

- (void)windowDidBecomeKey:(NSNotification *)notification
{@autoreleasepool {
    _CocoaWindow* ref_window = notification.object;
    _CocoaView* ref_view = [ref_window contentView];

    [ref_window makeFirstResponder:ref_view];
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
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    bool_t visible = (ref_window.occlusionState & NSWindowOcclusionStateVisible)? 1 : 0;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_show)
    {
        pwidg->result = (*psubp->sub_on_show)((widget_t)&(pwidg->head), visible, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_show)
    {
        (*pdisp->pf_on_show)((widget_t)&(pwidg->head), visible);
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
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;

    if (pdisp && pdisp->pf_on_timer)
    {
        (*pdisp->pf_on_timer)((widget_t)&(pwidg->head), 0);
    }
}}

- (void)sendEvent:(NSEvent *)nsEvent 
{@autoreleasepool {
   if([self isKindOfClass:[_CocoaWindow class]] == NO)
        return;

    _CocoaWindow* ref_window = self;
    _CocoaView* ref_view = [ref_window contentView];
    if(!ref_view) return;

    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;
    if(pwidg->mode == WS_MODE_INVALID) return;

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
        texting = [[NSMutableAttributedString alloc] init];

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
    if(texting != nil) [texting release];

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
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_set_focus)
    {
        pwidg->result = (*psubp->sub_on_set_focus)((widget_t)&(pwidg->head), NULL, psubp->sid, psubp->delta);
        if(pwidg->result) return YES;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if (pdisp && pdisp->pf_on_set_focus)
    {
        (*pdisp->pf_on_set_focus)((widget_t)&(pwidg->head), NULL);
    }

    return YES;
}}

- (BOOL)resignFirstResponder
{
    if([self isKindOfClass:[_CocoaView class]] == NO)
        return [super resignFirstResponder];

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_kill_focus)
    {
        pwidg->result = (*psubp->sub_on_kill_focus)((widget_t)&(pwidg->head), NULL, psubp->sid, psubp->delta);
        if(pwidg->result) return YES;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if (pdisp && pdisp->pf_on_kill_focus)
    {
        (*pdisp->pf_on_kill_focus)((widget_t)&(pwidg->head), NULL);
    }

    return YES;
}

- (void)setFrameSize:(NSSize)newSize
{
    NSSize oldSize = [self frame].size;

    [super setFrameSize:newSize];

    if(!NSEqualSizes(oldSize, newSize))
    {
        [[NSNotificationCenter defaultCenter] postNotificationName:NSViewFrameDidChangeNotification object:self];
    }
}

- (void)setHidden:(BOOL)hidden
{
    [super setHidden:hidden];

    [[NSNotificationCenter defaultCenter] postNotificationName:(hidden ? HideNotification : UnHideNotification)
                                                        object:self];
}

- (NSView *)hitTest:(NSPoint)aPoint
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO)
        return [super hitTest:aPoint];

    NSView* cur_view = [super hitTest:aPoint];

    _CocoaApplicationDelegate* appDelegate = [NSApp delegate];
    if(appDelegate.trackview && (NSView*)appDelegate.trackview != cur_view)
    {
        NSEvent *event = [NSApp currentEvent];
        NSEventType type = event.type;
        if(NSEventTypeLeftMouseDown == type || NSEventTypeRightMouseDown == type)
        {
            _CocoaView* track_view = appDelegate.trackview;
            cocoa_widget_t* pw = (cocoa_widget_t*)track_view.widget;
            if(pw) coWidgetPostKey(&(pw->head), KEY_ESC);
        }
        return nil;//(NSView*)appDelegate.trackview;
    }

    _CocoaView* coc_view = self;
	cocoa_widget_t* pwidg = (cocoa_widget_t*)coc_view.widget;
    if(pwidg && pwidg->disable) return nil;

    return cur_view;
}}

- (BOOL)acceptsFirstMouse:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO)
        return [super acceptsFirstMouse:nsEvent];

    return YES;
}}

- (void)mouseDown:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO) return;
    
    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSPoint winPoint = [nsEvent locationInWindow];
    NSPoint cliPoint = [ref_view convertPoint:winPoint fromView:nil];
    _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

   if ([nsEvent clickCount] == 1)
    {
        if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
        if(psubp && psubp->sub_on_lbutton_down)
        {
            pwidg->result = (*psubp->sub_on_lbutton_down)((widget_t)&(pwidg->head), &pt, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }

        if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
        if(pdisp && pdisp->pf_on_lbutton_down)
        {
            (*pdisp->pf_on_lbutton_down)((widget_t)&(pwidg->head), &pt);
        }
    }
}}

- (void)mouseUp:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO) return;

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSPoint winPoint = [nsEvent locationInWindow];
    NSPoint cliPoint = [ref_view convertPoint:winPoint fromView:nil];
    _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if ([nsEvent clickCount] == 2)
    {
        if(psubp && psubp->sub_on_lbutton_dbclick)
        {
            pwidg->result = (*psubp->sub_on_lbutton_dbclick)((widget_t)&(pwidg->head), &pt, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }
    }else
    {
        if(psubp && psubp->sub_on_lbutton_up)
        {
            pwidg->result = (*psubp->sub_on_lbutton_up)((widget_t)&(pwidg->head), &pt, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if ([nsEvent clickCount] == 2)
    {
        if(pdisp && pdisp->pf_on_lbutton_dbclick)
        {
            (*pdisp->pf_on_lbutton_dbclick)((widget_t)&(pwidg->head), &pt);
        }
    }else
    {
       if(pdisp && pdisp->pf_on_lbutton_up)
        {
            (*pdisp->pf_on_lbutton_up)((widget_t)&(pwidg->head), &pt);
        }
    }
}}

- (void)mouseMoved:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO) return;

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSPoint winPoint = [nsEvent locationInWindow];
    NSPoint cliPoint = [ref_view convertPoint:winPoint fromView:nil];
     _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    NSUInteger nsFlags = [nsEvent modifierFlags];
    dword_t mask = _key_state(nsFlags);

    NSUInteger nsState = [NSEvent pressedMouseButtons];
    mask |= _mouse_state(nsState);

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_mouse_move)
    {
        pwidg->result = (*psubp->sub_on_mouse_move)((widget_t)&(pwidg->head), mask, &pt, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_mouse_move)
    {
        (*pdisp->pf_on_mouse_move)((widget_t)&(pwidg->head), mask, &pt);
    }
}}

- (void)mouseDragged:(NSEvent *)nsEvent
{
    if([self isKindOfClass:[_CocoaView class]] == NO) return;

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSPoint winPoint = [nsEvent locationInWindow];
    NSPoint cliPoint = [ref_view convertPoint:winPoint fromView:nil];
     _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    NSUInteger nsFlags = [nsEvent modifierFlags];
    dword_t mask = _key_state(nsFlags);
    mask |= MS_WITH_LBUTTON;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_mouse_move)
    {
        pwidg->result = (*psubp->sub_on_mouse_move)((widget_t)&(pwidg->head), mask, &pt, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_mouse_move)
    {
        (*pdisp->pf_on_mouse_move)((widget_t)&(pwidg->head), mask, &pt);
    }
}

- (void)rightMouseDown:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO) return;

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSPoint winPoint = [nsEvent locationInWindow];
    NSPoint cliPoint = [ref_view convertPoint:winPoint fromView:nil];
     _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_rbutton_down)
    {
        pwidg->result = (*psubp->sub_on_rbutton_down)((widget_t)&(pwidg->head), &pt, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_rbutton_down)
    {
        (*pdisp->pf_on_rbutton_down)((widget_t)&(pwidg->head), &pt);
    }
}}

- (void)rightMouseUp:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSPoint winPoint = [nsEvent locationInWindow];
    NSPoint cliPoint = [ref_view convertPoint:winPoint fromView:nil];
    _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_rbutton_up)
    {
        pwidg->result = (*psubp->sub_on_rbutton_up)((widget_t)&(pwidg->head), &pt, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_rbutton_up)
    {
        (*pdisp->pf_on_rbutton_up)((widget_t)&(pwidg->head), &pt);
    }
}}

- (void)mouseEntered:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSPoint winPoint = [nsEvent locationInWindow];
    NSPoint cliPoint = [ref_view convertPoint:winPoint fromView:nil];
     _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    NSUInteger nsFlags = [nsEvent modifierFlags];
    dword_t mask = _key_state(nsFlags);

    NSUInteger nsState = [NSEvent pressedMouseButtons];
    mask |= _mouse_state(nsState);

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_mouse_enter)
    {
        pwidg->result = (*psubp->sub_on_mouse_enter)((widget_t)&(pwidg->head), mask, &pt, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_mouse_enter)
    {
        (*pdisp->pf_on_mouse_enter)((widget_t)&(pwidg->head), mask, &pt);
    }
}}

- (void)mouseExited:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    NSPoint winPoint = [nsEvent locationInWindow];
    NSPoint cliPoint = [ref_view convertPoint:winPoint fromView:nil];
     _cocoa_to_view(ref_view, &cliPoint);

    xpoint_t pt;
    pt.x = (int)cliPoint.x, pt.y = (int)cliPoint.y;

    NSUInteger nsFlags = [nsEvent modifierFlags];
    dword_t mask = _key_state(nsFlags);

    NSUInteger nsState = [NSEvent pressedMouseButtons];
    mask |= _mouse_state(nsState);

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_mouse_leave)
    {
        pwidg->result = (*psubp->sub_on_mouse_leave)((widget_t)&(pwidg->head), mask, &pt, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_mouse_leave)
    {
        (*pdisp->pf_on_mouse_leave)((widget_t)&(pwidg->head), mask, &pt);
    }
}}

- (void)scrollWheel:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

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

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_scroll)
    {
        if(sx)
            pwidg->result = (*psubp->sub_on_scroll)((widget_t)&(pwidg->head), 1, sx, psubp->sid, psubp->delta);
        else
            pwidg->result = 0;

        if(sy)
            pwidg->result = (*psubp->sub_on_scroll)((widget_t)&(pwidg->head), 0, sy, psubp->sid, psubp->delta);
        else
            pwidg->result = 0;

        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_scroll)
    {
        if(sx)
            (*pdisp->pf_on_scroll)((widget_t)&(pwidg->head), 1, sx);
        
        if(sy)
            (*pdisp->pf_on_scroll)((widget_t)&(pwidg->head), 0, sy);
    }
}}

- (void)drawRect:(NSRect)dirtyRect
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;
    
    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    visual_t rdc = coCreateDisplayContext((widget_t)&(pwidg->head));
    if(!rdc) return;

    NSRect nsRect = [ref_view frame];
	xrect_t xr = {0};
	xr.x = 0;
	xr.y = 0;
	xr.w = nsRect.size.width;
	xr.h = nsRect.size.height;

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_paint)
    {
        pwidg->result = (*psubp->sub_on_paint)((widget_t)&(pwidg->head), rdc, &xr, psubp->sid, psubp->delta);
    }else{
        pwidg->result = 0;
    }

    if(!pwidg->result)
    {
        if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
        if(pdisp && pdisp->pf_on_paint)
        {
            (*pdisp->pf_on_paint)((widget_t)&(pwidg->head), rdc, &xr);
        }
    }

    coDestroyContext(rdc);

    [self drawCaret];
}}

- (void)drawCaret
{@autoreleasepool {
    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if(!ref_view.caret_visible) return;

    NSColor *nsColor = _xcolor_to_nscolor(&(pwidg->clrs.clr_frg));

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
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    if (tracking != nil)
    {
        [self removeTrackingArea:tracking];
        [tracking release];
        tracking = nil;
    }

    const NSTrackingAreaOptions options = NSTrackingMouseEnteredAndExited |
                                          NSTrackingMouseMoved |
                                          NSTrackingActiveInKeyWindow |
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
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    unichar nsKey = [[nsEvent charactersIgnoringModifiers] characterAtIndex:0];
    unsigned short key = _cocoa_to_keycode(nsKey);
    if(!key) key = nsKey;
    NSUInteger nsFlags = [nsEvent modifierFlags];
    dword_t mask = _key_state(nsFlags);

    if((mask & KS_WITH_CONTROL) || (mask & KS_WITH_CMD))
    {
        switch(nsKey)
        {
        case L'c':
        case L'C':
            key = KEY_COPY;
            break;
        case L'v':
        case L'V':
            key = KEY_PASTE;
            break;
        case L'x':
        case L'X':
            key = KEY_CUT;
            break;
        case L'z':
        case L'Z':
            key = KEY_UNDO;
            break;
        }
    } 

    accel_table_t* pac = (accel_table_t*)pwidg->accel;
    if(pac)
    {
        for (int i = 0; pac[i].vir != 0; ++i) 
        {
            if (pac[i].key == key && (mask & pac[i].vir)) 
            {
                coWidgetPostCommand((widget_t)&(pwidg->head), pac[i].cmd, pwidg->uid, 0);
                return;
            }
        }
    }

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_keydown)
    {
        pwidg->result = (*psubp->sub_on_keydown)((widget_t)&(pwidg->head), mask, (int)key, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_keydown)
    {
        (*pdisp->pf_on_keydown)((widget_t)&(pwidg->head), mask, (int)key);
    }

    if(key == KEY_ENTER || key == KEY_TAB)
    {
        if(psubp && psubp->sub_on_wchar)
        {
            pwidg->result = (*psubp->sub_on_wchar)((widget_t)&(pwidg->head), (wchar_t)key, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }

        if(pdisp && pdisp->pf_on_wchar)
        {
            (*pdisp->pf_on_wchar)((widget_t)&(pwidg->head), (wchar_t)key);
        }

        return;
    }

    [self interpretKeyEvents:@[nsEvent]];
}}

- (void)flagsChanged:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
	cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    const unsigned int modifierFlags = [nsEvent modifierFlags] & NSEventModifierFlagDeviceIndependentFlagsMask;

    pwidg->mask = _key_state(modifierFlags);
}}

- (void)keyUp:(NSEvent *)nsEvent
{@autoreleasepool {
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

    unichar nsKey = [[nsEvent charactersIgnoringModifiers] characterAtIndex:0];
    unsigned short key = _cocoa_to_keycode(nsKey);
    if(!key) key = nsKey;
    NSUInteger nsFlags = [nsEvent modifierFlags];
    dword_t mask = _key_state(nsFlags);

     if((mask & KS_WITH_CONTROL) || (mask & KS_WITH_CMD))
    {
        switch(nsKey)
        {
        case L'c':
        case L'C':
            key = KEY_COPY;
            break;
        case L'v':
        case L'V':
            key = KEY_PASTE;
            break;
        case L'x':
        case L'X':
            key = KEY_CUT;
            break;
        case L'z':
        case L'Z':
            key = KEY_UNDO;
            break;
        }
    } 

    if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
    if(psubp && psubp->sub_on_keyup)
    {
        pwidg->result = (*psubp->sub_on_keyup)((widget_t)&(pwidg->head), mask, (int)key, psubp->sid, psubp->delta);
        if(pwidg->result) return;
    }

    if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
    if(pdisp && pdisp->pf_on_keyup)
    {
        (*pdisp->pf_on_keyup)((widget_t)&(pwidg->head), mask, (int)key);
    }
}}

- (void)insertText:(id)string replacementRange:(NSRange)replacementRange
{@autoreleasepool {
    //[super insertText:string replacementRange:replacementRange];
    if([self isKindOfClass:[_CocoaView class]] == NO) return ;

    _CocoaView* ref_view = self;
    cocoa_widget_t* pwidg = (cocoa_widget_t*)ref_view.widget;

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

            if_subproc_t* psubp = (if_subproc_t*)ref_view.subproc;
            if(psubp && psubp->sub_on_wchar)
            {
                pwidg->result = (*psubp->sub_on_wchar)((widget_t)&(pwidg->head), (wchar_t)widechar, psubp->sid, psubp->delta);
                if(pwidg->result) continue;
            }

            if_dispatch_t* pdisp = (if_dispatch_t*)ref_view.dispatch;
            if(pdisp && pdisp->pf_on_wchar)
            {
                (*pdisp->pf_on_wchar)((widget_t)&(pwidg->head), (wchar_t)widechar);
            }
        }
    }
}}

- (BOOL)hasMarkedText
{
    return [texting length] > 0;
}

static const NSRange emptyRange = { NSNotFound, 0 };

- (NSRange)markedRange
{
    if ([texting length] > 0)
        return NSMakeRange(0, [texting length] - 1);
    else
        return emptyRange;
}

- (NSRange)selectedRange
{
    return emptyRange;
}

- (void)setMarkedText:(id)string
        selectedRange:(NSRange)selectedRange
     replacementRange:(NSRange)replacementRange
{
    [texting release];

    if ([string isKindOfClass:[NSAttributedString class]])
        texting = [[NSMutableAttributedString alloc] initWithAttributedString:string];
    else
        texting = [[NSMutableAttributedString alloc] initWithString:string];
}

- (void)unmarkText
{
    [[texting mutableString] setString:@""];
}

- (NSArray*)validAttributesForMarkedText
{
    return @[NSUnderlineStyleAttributeName, NSForegroundColorAttributeName];
}

- (NSAttributedString*)attributedSubstringForProposedRange:(NSRange)range
                                               actualRange:(NSRangePointer)actualRange
{
    return nil;
}

- (NSUInteger)characterIndexForPoint:(NSPoint)point
{
    return NSNotFound;
}

- (NSRect)firstRectForCharacterRange:(NSRange)range
                         actualRange:(NSRangePointer)actualRange
{
    const NSRect frame = [self frame];
    return NSMakeRect(frame.origin.x, frame.origin.y, 0.0, 0.0);
}

- (void)doCommandBySelector:(SEL)selector
{@autoreleasepool {
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

void coWidgetStartup(int ver)
{
    NOP;
}

void coWidgetCleanup()
{
    NOP;
}

widget_t coWidgetCreate(const tchar_t* wname, dword_t wstyle, const xrect_t* wrect, widget_t wparent, const if_dispatch_t* wnsEvent)
{@autoreleasepool {
    cocoa_widget_t* pwidg_parent = (wparent)? TypePtrFromHead(cocoa_widget_t, wparent) : NULL;
    dword_t pstyle = (wparent)? pwidg_parent->style : 0;
    NSView* parView = (wparent)? (NSView*)(pwidg_parent->self) : nil;

    NSUInteger nsStyle = 0;
    NSScreen* nsScreen = [NSScreen mainScreen];
    NSWindow* nsWindow = (pwidg_parent)? [(NSView*)(pwidg_parent->self) window] : nil;
    NSView* nsView = (nsWindow)? [nsWindow contentView] : nil;

    cocoa_widget_t* pwidg = (cocoa_widget_t*)xmem_alloc_handle(sizeof(cocoa_widget_t));

	if_dispatch_t* pdisp = (if_dispatch_t*)xmem_alloc(sizeof(if_dispatch_t));
    if(wnsEvent)
	{
		xmem_copy((void*)(pdisp), (void*)wnsEvent, sizeof(if_dispatch_t));
	}

    pwidg->head.tag = _HANDLE_WIDGET;
    pwidg->parent = (pwidg_parent)? pwidg_parent->self : nil;
	pwidg->style = wstyle;
	pwidg->state = WS_SHOW_HIDE;
    pwidg->accel = NULL;

    _CocoaView* new_view = nil;

	if(wstyle & WD_STYLE_CHILD)
	{
        NSPoint nsPoint = NSMakePoint(wrect->x, wrect->y + wrect->h);
        if(pstyle & WD_STYLE_CHILD)
            _view_to_cocoa(parView, &nsPoint);
        else
            _view_to_cocoa(nsView, &nsPoint);
        NSRect nsRect = NSMakeRect(nsPoint.x, nsPoint.y, wrect->w, wrect->h);

        new_view = [[_CocoaView alloc] initWithFrame:nsRect];
        if(new_view == nil) goto clean;

        new_view.properties = [[NSMutableDictionary alloc] init];
        new_view.widget = pwidg;
        new_view.dispatch = pdisp;
        //[new_view setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
        [new_view setWantsLayer:NO];
        [new_view setAutoresizingMask:0];

        if(pstyle & WD_STYLE_CHILD)
            [parView addSubview:new_view];
        else
            [nsView addSubview:new_view];

        _CocoaViewDelegate* view_delegate = [[_CocoaViewDelegate alloc] initWithCocoaView:new_view];
        
        if(view_delegate == nil) goto clean;

        new_view.delegate = view_delegate;
    }else
    {
        NSPoint nsPoint = NSMakePoint(wrect->x, wrect->y + wrect->h);
        _screen_to_cocoa(nsScreen, &nsPoint);
        NSRect nsRect = NSMakeRect(nsPoint.x, nsPoint.y, wrect->w, wrect->h);

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

	    if(coc_window == nil) goto clean;
        
        [coc_window setReleasedWhenClosed:YES];

        nsRect = [coc_window frame];
        NSRect content = [NSWindow contentRectForFrameRect:nsRect styleMask:nsStyle];

        nsRect = [[coc_window contentView] bounds];
        new_view = [[_CocoaView alloc] initWithFrame:nsRect];

        if(new_view == nil) goto clean;

        new_view.properties = [[NSMutableDictionary alloc] init];
        new_view.widget = pwidg;
        new_view.dispatch = pdisp;
        //[new_view setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
        [new_view setWantsLayer:NO];
        [new_view setAutoresizingMask:0];
        
        [coc_window setContentView:new_view];
        if(!is_null(wname))
        {
            [coc_window setTitle:[NSString stringWithUTF8String:wname]];
        }
        
        if(nsWindow)
        {
            [coc_window setParentWindow:nsWindow];
            [nsWindow addChildWindow:coc_window ordered:NSWindowAbove];
        }

        _CocoaWindowDelegate* win_delegate = [[_CocoaWindowDelegate alloc] initWithCocoaWindow:coc_window];
        
        if(win_delegate == nil) goto clean;

        [coc_window setDelegate:win_delegate];
    }

    //NSAppearance *ape = new_view.effectiveAppearance;

    NSColor *bkgColor = [NSColor windowBackgroundColor];
    //if(ape) [bkgColor resolvedColorWithAppearance:ape];
    _nscolor_to_xcolor(bkgColor, &(pwidg->clrs.clr_bkg));
    _nscolor_to_xcolor(bkgColor, &(pwidg->clrs.clr_msk));

    NSColor *frgColor = [NSColor labelColor];
    //if(ape) [frgColor resolvedColorWithAppearance:ape];
    _nscolor_to_xcolor(frgColor, &(pwidg->clrs.clr_frg));

    NSColor *txtColor = [NSColor textColor];
    //if(ape) [txtColor resolvedColorWithAppearance:ape];
    _nscolor_to_xcolor(txtColor, &(pwidg->clrs.clr_txt));
    _nscolor_to_xcolor(txtColor, &(pwidg->clrs.clr_ico));

    pwidg->self = new_view;

    if (pdisp && pdisp->pf_on_create)
    {
        (*pdisp->pf_on_create)((widget_t)&(pwidg->head), pdisp->param);
    }

    return (widget_t)&(pwidg->head);

clean:
    xmem_free_handle(pwidg); 
    xmem_free(pdisp); 
    return (widget_t)nil;
}}

void coWidgetDestroy(widget_t wt)
{@autoreleasepool {
	cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    _CocoaApplicationDelegate* appDelegate = [NSApp delegate];
    if(appDelegate.trackview == coc_view)
    {
        appDelegate.trackview = nil;
    }

    BOOL b_windowless = (pwidg->style & WD_STYLE_CHILD) ? YES : NO;

    if_subproc_t* psubp = (if_subproc_t*)coc_view.subproc;
    if(psubp && psubp->sub_on_unsubbed)
    {
        (*psubp->sub_on_unsubbed)((widget_t)&(pwidg->head), psubp->sid, psubp->delta);
    }

	if_dispatch_t* pdisp = (if_dispatch_t*)coc_view.dispatch;
	if(pdisp && pdisp->pf_on_destroy)
	{
		(*pdisp->pf_on_destroy)(wt);
	}

    if(pwidg && pwidg->accel) xmem_free(pwidg->accel);

    if(pwidg) xmem_free_handle(pwidg);

    pdisp = (if_dispatch_t*)coc_view.dispatch;
    if(pdisp) xmem_free(pdisp);

    psubp = (if_subproc_t*)coc_view.subproc;
    if(psubp) xmem_free(psubp);

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

    if(b_windowless)
    {
        _CocoaViewDelegate* view_delegate = coc_view.delegate;

        coc_view.delegate = nil;
        [coc_view removeFromSuperview];

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
        [coc_window setContentView:nil];

        [coc_view release];
        [win_delegate release];

        //DONT call, NsApp maybe crashed
        //[coc_window release];
    }
}}

void coWidgetClose(widget_t wt, int ret)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	if_dispatch_t* pdisp = (if_dispatch_t*)coc_view.dispatch;
	pwidg->retcode = ret;

	if(pdisp && pdisp->pf_on_close)
	{
		if((*pdisp->pf_on_close)(wt))
			return;
	}

    if(pdisp && pdisp->pf_on_show)
	{
		(*pdisp->pf_on_show)(wt, bool_false);
	}

    if(pwidg->style & WD_STYLE_CHILD)
    {
        coWidgetDestroy(wt);
    }else
    {
        int mode = pwidg->mode;
        _CocoaWindow* coc_window = [coc_view window];
        [coc_window close];

        if(mode == WS_MODE_TRACK)
        {
            coWidgetDestroy(wt);
        }
    }
}}

const if_dispatch_t* coWidgetGetDispatch(widget_t wt)
{@autoreleasepool {
     cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	if_dispatch_t* pdisp = (if_dispatch_t*)coc_view.dispatch;

	return (pdisp);
}}

const if_subproc_t* coWidgetGetSubproc(widget_t wt, uid_t sid)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if_subproc_t* psub = (if_subproc_t*)coc_view.subproc;

	return (psub);
}}

bool_t coWidgetSetSubproc(widget_t wt, uid_t sid, if_subproc_t* sub)
{@autoreleasepool {
     cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(coc_view.subproc)
    {
        xmem_free((if_subproc_t*)coc_view.subproc);
        coc_view.subproc = 0;
    }

    if_subproc_t* new_sub = (if_subproc_t*)xmem_alloc(sizeof(if_subproc_t));
    if(sub)
    {
        xmem_copy((void*)new_sub, (void*)sub, sizeof(if_subproc_t));
        new_sub->sid = sid;
    }
	coc_view.subproc = (id)new_sub;

    if_subproc_t* psubp = (if_subproc_t*)coc_view.subproc;
    if(psubp && psubp->sub_on_subbing)
    {
        (*psubp->sub_on_subbing)((widget_t)&(pwidg->head), psubp->sid, psubp->delta);
    }

	return 1;
}}

void coWidgetDelSubproc(widget_t wt, uid_t sid)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if_subproc_t* psubp = (if_subproc_t*)coc_view.subproc;
    if(psubp && psubp->sub_on_unsubbed)
    {
        (*psubp->sub_on_unsubbed)((widget_t)&(pwidg->head), psubp->sid, psubp->delta);

        xmem_free((if_subproc_t*)coc_view.subproc);
        coc_view.subproc = 0;
    }
}}

bool_t coWidgetSetSubprocDelta(widget_t wt, uid_t sid, vword_t delta)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	if_subproc_t* psub = (if_subproc_t*)coc_view.subproc;

    if(psub == NULL) return 0;

	psub->delta = delta;

	return 1;
}}

vword_t coWidgetGetSubprocDelta(widget_t wt, uid_t sid)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	if_subproc_t* psub = (if_subproc_t*)coc_view.subproc;

    if(psub == NULL) return (vword_t)0;

	return psub->delta;
}}

bool_t coWidgetHasSubproc(widget_t wt, uid_t sid)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if_subproc_t* psub = (if_subproc_t*)coc_view.subproc;

	return (psub == NULL) ? 0 : 1;
}}

void coWidgetSetCoreDelta(widget_t wt, vword_t pd)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    coc_view.coredelta = (id)pd;
}}

vword_t coWidgetGetCoreDelta(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	return (vword_t)coc_view.coredelta;
}}

void coWidgetSetUserDelta(widget_t wt, vword_t pd)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	coc_view.userdelta = (id)pd;
}}

vword_t coWidgetGetUserDelta(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	return (vword_t)coc_view.userdelta;
}}

void coWidgetSetStyle(widget_t wt, dword_t ws)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	pwidg->style = ws;
}}

dword_t coWidgetGetStyle(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	return pwidg->style;
}}

void coWidgetSetAccel(widget_t wt, const accel_table_t* pacl, int n)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->accel) xmem_free(pwidg->accel);
    pwidg->accel = NULL;

    if(pacl && n)
    {
	    accel_table_t* pa = (accel_table_t*)xmem_alloc((n + 1) * sizeof(accel_table_t));
	    xmem_copy((void*)pa, (void*)pacl, n * sizeof(accel_table_t));

	    pa[n].vir = 0, pa[n].key = 0, pa[n].cmd = 0;
	    pwidg->accel = pa;
    }
}}

void coWidgetSetOwner(widget_t wt, widget_t owner)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    cocoa_widget_t* pwidg_owner = (owner)? TypePtrFromHead(cocoa_widget_t, owner) : NULL;

	pwidg->owner = (pwidg_owner)? pwidg_owner->self : nil;
}}

widget_t coWidgetGetOwner(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    _CocoaView* coc_owner = pwidg->owner;
	cocoa_widget_t* pwidg_owner = (coc_owner)? (cocoa_widget_t*)coc_owner.widget : NULL;

	return (pwidg_owner)? &(pwidg_owner->head) : NULL;
}}

void coWidgetSetUserId(widget_t wt, uid_t uid)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	pwidg->uid = uid;
}}

uid_t coWidgetGetUserId(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    return pwidg->uid;
}}

void coWidgetSetUserResult(widget_t wt, int rt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	pwidg->result = rt;
}}

int coWidgetGetUserResult(widget_t wt)
{@autoreleasepool {
cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    return pwidg->result;
}}

bool_t coWidgetEnumChild(widget_t wt, PF_ENUM_WINDOW_PROC pf, vword_t pv)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    NSArray *subviews = [coc_view subviews];
    
    for (NSView *nsChild in subviews) 
    {
        if([nsChild isKindOfClass:[_CocoaView class]])
        {
             _CocoaView* cocChild = (_CocoaView*)nsChild;
            pwidg = (cocoa_widget_t*)cocChild.widget;

            (*pf)((widget_t)&(pwidg->head), pv);
        }
    }

    return 1;
}}

widget_t coWidgetGetChild(widget_t wt, uid_t uid)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    NSArray *subviews = [coc_view subviews];
    
    for (NSView *nsChild in subviews) 
    {
        if([nsChild isKindOfClass:[_CocoaView class]])
        {
            _CocoaView* cocChild = (_CocoaView*)nsChild;
            pwidg = (cocoa_widget_t*)cocChild.widget;

            if(pwidg->uid == uid) return (widget_t)&(pwidg->head);
        }
    }

    return (widget_t)nil;
}}

widget_t coWidgetGetParent(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);

    _CocoaView* coc_view = pwidg->parent;
    pwidg = (coc_view)? (cocoa_widget_t*)coc_view.widget : NULL;

    return (pwidg)? (widget_t)&(pwidg->head) : NULL;
}}

void coWidgetSetUserProp(widget_t wt, const tchar_t* pname,vword_t val)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

     NSString* nsKey = [NSString stringWithUTF8String:pname];

    [[coc_view properties] setObject:@(val) forKey:nsKey];
}}

vword_t coWidgetGetUserProp(widget_t wt, const tchar_t* pname)
{@autoreleasepool {
   cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    NSString* nsKey = [NSString stringWithUTF8String:pname];
    return [coc_view.properties[nsKey] unsignedLongLongValue];
}}

vword_t coWidgetDelUserProp(widget_t wt, const tchar_t* pname)
{@autoreleasepool {
   cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    NSString* nsKey = [NSString stringWithUTF8String:pname];

    vword_t val = [coc_view.properties[nsKey] unsignedLongLongValue];
    [[coc_view properties] removeObjectForKey:nsKey];

   return val;
}}

bool_t coWidgetIsMaximized(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	return (pwidg->state == WS_SHOW_MAXIMIZE)? 1 : 0;
}}

bool_t coWidgetIsMinimized(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	return (pwidg->state == WS_SHOW_MINIMIZE)? 1 : 0;
}}

visual_t coWidgetClientContext(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	NSGraphicsContext *nsContext = [NSGraphicsContext currentContext];

	cocoa_context_t* ctx = (cocoa_context_t*)xmem_alloc_handle(sizeof(cocoa_context_t));
	ctx->head.tag = _VISUAL_DISPLAY;
    ctx->context = [nsContext CGContext];
	ctx->type = CONTEXT_SCREEN;
    ctx->fontset = g_fontset;
	
	return (visual_t)&(ctx->head);
}}

visual_t coWidgetWindowContext(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    NSWindow* nsWindow = [coc_view window];

    NSGraphicsContext *nsContext = [nsWindow graphicContext];
    //NSGraphicsContext *nsContext = [NSGraphicsContext currentContext];

    cocoa_context_t* ctx = (cocoa_context_t*)xmem_alloc_handle(sizeof(cocoa_context_t));
	ctx->head.tag = _VISUAL_DISPLAY;
    ctx->context = [nsContext CGContext];
	ctx->type = CONTEXT_SCREEN;
    ctx->fontset = g_fontset;

	return (visual_t)&(ctx->head);
}}

void coWidgetReleaseContext(widget_t wt, visual_t dc)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, dc);

    xmem_free_handle((xhand_t)ctx);
}}

void coWidgetGetClientRect(widget_t wt, xrect_t* prt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	NSRect nsRect = [coc_view frame];

	prt->x = 0;
    prt->y = 0;
	prt->w = nsRect.size.width;
	prt->h = nsRect.size.height;
}}

void coWidgetGetWindowRect(widget_t wt, xrect_t* prt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    NSPoint nsPoint;
    NSRect nsRect;
    NSWindow* nsWindow = [coc_view window];
    NSScreen* nsScreen = [NSScreen mainScreen];

    if(pwidg->style & WD_STYLE_CHILD)
    {
        nsRect = [coc_view frame];
        nsPoint = [coc_view convertPoint:NSMakePoint(0,0) toView:nil];
        nsPoint = [nsWindow convertPointToScreen:nsPoint];
    }else
    {
        nsRect = [nsWindow frame];
        nsPoint = nsRect.origin;
    }
    _cocoa_to_screen(nsScreen, &nsPoint);

	prt->x = nsPoint.x;
    prt->y = nsPoint.y - nsRect.size.height;
	prt->w = nsRect.size.width;
	prt->h = nsRect.size.height;
}}

void coWidgetClientToWindow(widget_t wt, xpoint_t* ppt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD) return;

    NSPoint cliPoint = NSMakePoint(ppt->x, ppt->y);
    _view_to_cocoa(coc_view, &cliPoint);

    NSPoint winPoint = [coc_view convertPoint:cliPoint toView:nil];
    NSWindow* nsWindow = [coc_view window];
    _cocoa_to_window(nsWindow, &winPoint);

	ppt->x = winPoint.x;
    ppt->y = winPoint.y;
}}

void coWidgetWindowToClient(widget_t wt, xpoint_t* ppt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD) return;

    NSPoint winPoint = NSMakePoint(ppt->x, ppt->y);
    NSWindow* nsWindow = [coc_view window];
    _window_to_cocoa(nsWindow, &winPoint);

    NSPoint cliPoint = [coc_view convertPoint:winPoint fromView:nil];
    _cocoa_to_view(coc_view, &cliPoint);

	ppt->x = cliPoint.x;
    ppt->y = cliPoint.y;
}}

void coWidgetClientToScreen(widget_t wt, xpoint_t* ppt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

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

void coWidgetScreenToClient(widget_t wt, xpoint_t* ppt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

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

void coWidgetCenterWindow(widget_t wt, widget_t owner)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    cocoa_widget_t* powner = (owner)? TypePtrFromHead(cocoa_widget_t, owner) : NULL;
    _CocoaView* coc_owner = (powner)? powner->self : nil;

    NSWindow* src_window = [coc_view window];
    NSWindow* dst_window = (coc_owner)? [coc_owner window] : nil ;

    if(src_window == nil) return;

    NSRect winFrame = [src_window frame];
    NSRect scrFrame = (dst_window)? [dst_window frame] : [[NSScreen mainScreen] visibleFrame];

    CGFloat newX = NSMidX(scrFrame) - (NSWidth(winFrame) / 2);
    CGFloat newY = NSMidY(scrFrame) - (NSHeight(winFrame) / 2);
    
    winFrame.origin = NSMakePoint(newX, newY);
    [src_window setFrame:winFrame display:YES];
}}

void coWidgetSetCursor(widget_t wt, int ci)
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

void coWidgetSetCapture(widget_t wt, bool_t b)
{@autoreleasepool {
	NOP;
}}

vword_t coWidgetSetTimer(widget_t wt, int ms)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD) return 0;

    _CocoaWindow* coc_window = [coc_view window];
	coc_window.schedule = [NSTimer scheduledTimerWithTimeInterval:(ms / 1000.0)
                                                    target:coc_window
                                                    selector:@selector(scheduleTimer)
                                                    userInfo:nil
                                                    repeats:YES];
}}

void coWidgetKillTimer(widget_t wt, vword_t tid)
{@autoreleasepool {
	cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD) return;

    _CocoaWindow* coc_window = [coc_view window];
    if(coc_window.schedule)
    {
        [coc_window.schedule invalidate];
        coc_window.schedule = nil;
    }
}}

void coWidgetCreateCaret(widget_t wt, int w, int h)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    coc_view.caret_visible = NO;
    coc_view.caret_timer = [NSTimer scheduledTimerWithTimeInterval:0.5
                                                    target:coc_view
                                                    selector:@selector(toggleCaret)
                                                    userInfo:nil
                                                    repeats:YES];
    coc_view.caret_rect = NSMakeRect(0, h, w, h);                                              
    [coc_view setNeedsDisplayInRect:[coc_view caret_rect]];
}}
 
void coWidgetDestroyCaret(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

     coc_view.caret_visible = NO;

     if(coc_view.caret_timer)
     {
         [coc_view.caret_timer invalidate];
         coc_view.caret_timer = nil;
     }

     [coc_view setNeedsDisplayInRect:[coc_view caret_rect]];
}}

void coWidgetShowCaret(widget_t wt, int x, int y)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(coc_view.caret_visible)
    {
        [coc_view setNeedsDisplayInRect:coc_view.caret_rect];
    }

    coc_view.caret_visible = 1;
    NSPoint nsPoint = NSMakePoint(x, y + coc_view.caret_rect.size.height);
    _view_to_cocoa(coc_view, &nsPoint);
    coc_view.caret_rect = NSMakeRect(nsPoint.x, nsPoint.y, coc_view.caret_rect.size.width, coc_view.caret_rect.size.height);
    
    [coc_view setNeedsDisplayInRect:coc_view.caret_rect];
}}

void coWidgetSetFocus(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	 NSWindow* nsWindow = [coc_view window];
    if(nsWindow)
    {
        [nsWindow makeFirstResponder:coc_view];
        return;
    }

    nsWindow = (pwidg->parent)? [(NSView*)pwidg->parent window] : nil;
    if(nsWindow == nil) return;

	[nsWindow makeFirstResponder:coc_view];
}}

bool_t coWidgetKeyState(widget_t wt, int ks)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    return (ks & pwidg->mask)? 1 : 0;
}}

bool_t coWidgetIsValid(widget_t wt)
{@autoreleasepool {
    if(!wt) return 0;
    if(wt->tag != _HANDLE_WIDGET) return 0;

    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	return (coc_view == nil)? 0 : 1;
}}

bool_t coWidgetIsFocus(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	NSWindow* window = [coc_view window];

    if(window == nil) return 0;

    return ([window firstResponder] == coc_view)? 1 : 0;
}}

bool_t coWidgetIsChild(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	return (pwidg->style & WD_STYLE_CHILD)? 1 : 0;
}}

bool_t coWidgetIsOwnerNc(widget_t wt)
{@autoreleasepool {
	cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	return (pwidg->style & WD_STYLE_OWNERNC)? 1 : 0;
}}

void coWidgetMove(widget_t wt, const xpoint_t* ppt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        _CocoaView* parView = (_CocoaView*)(pwidg->parent);
        cocoa_widget_t* par_pwidg = (cocoa_widget_t*)parView.widget;
        dword_t pstyle = (par_pwidg)? par_pwidg->style : 0;

        NSWindow* nsWindow = [coc_view window];
        NSView* nsView = [nsWindow contentView];
        int h = [coc_view frame].size.height;
        NSPoint newPosition = NSMakePoint(ppt->x, ppt->y + h);
        if(pstyle & WD_STYLE_CHILD)
             _view_to_cocoa(parView, &newPosition);
        else
            _view_to_cocoa(nsView, &newPosition);
        //[coc_view setTranslatesAutoresizingMaskIntoConstraints:YES];
        [coc_view setFrameOrigin:newPosition];
    }
    else
    {
        NSWindow* nsWindow = [coc_view window];
        NSScreen* nsScreen = [nsWindow screen] ?: [NSScreen mainScreen];

        NSRect nsRect = [nsWindow frame];
        NSPoint newPosition = NSMakePoint(ppt->x, ppt->y + nsRect.size.height);
        _screen_to_cocoa(nsScreen, &newPosition);
        
        nsRect.origin = newPosition;
        [nsWindow setFrame:nsRect display:YES];
    }
}}

void coWidgetSize(widget_t wt, const xsize_t* pxs)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSRect frmRect = [coc_view frame];
        if((int)frmRect.size.width == pxs->w && (int)frmRect.size.height == pxs->h)
            return;

        NSRect nsRect = NSMakeRect(frmRect.origin.x, frmRect.origin.y,pxs->w,pxs->h);
        [coc_view setFrame:nsRect]; 
        //NSSize newSize = NSMakeSize(pxs->w, pxs->h);
        //[coc_view setTranslatesAutoresizingMaskIntoConstraints:YES];
        //[coc_view setFrameSize:newSize];
    }
    else
    {
        NSWindow* nsWindow = [coc_view window];
        NSRect frmRect = [nsWindow frame];
        if((int)frmRect.size.width == pxs->w && (int)frmRect.size.height == pxs->h)
            return;

        NSRect nsRect = NSMakeRect(frmRect.origin.x, frmRect.origin.y - (pxs->h - frmRect.size.height),pxs->w,pxs->h);
        [nsWindow setFrame:nsRect display:YES];
        //NSSize newSize = NSMakeSize(pxs->w, pxs->h);
        //[nsWindow setContentSize:newSize];
    }
}}

void coWidgetTake(widget_t wt, int zor)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

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

void coWidgetShow(widget_t wt, dword_t sw)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    NSWindow* coc_window = (pwidg->style & WD_STYLE_CHILD)? nil : [coc_view window];

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
        [coc_window setFrame:nsFrame display:YES];
        [coc_window makeKeyAndOrderFront:nil];
        pwidg->state = WS_SHOW_MAXIMIZE;
        break;
    case WS_SHOW_FULLSCREEN:
        if(coc_window == nil) break;

		[coc_window toggleFullScreen:nil];
        [coc_window makeKeyAndOrderFront:nil];
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

void coWidgetLayout(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSRect nsFrame = [coc_view frame];
        xsize_t xs;
        xs.w = (int)nsFrame.size.width;
        xs.h = (int)nsFrame.size.height;

        if_subproc_t* psubp = (if_subproc_t*)coc_view.subproc;
        if(psubp && psubp->sub_on_size)
        {
            pwidg->result = (*psubp->sub_on_size)((widget_t)&(pwidg->head), WS_SIZE_LAYOUT, &xs, psubp->sid, psubp->delta);
            if(pwidg->result) return;
        }

        if_dispatch_t* pdisp = (if_dispatch_t*)coc_view.dispatch;
        if(pdisp && pdisp->pf_on_size)
        {
            (*pdisp->pf_on_size)((widget_t)&(pwidg->head), WS_SIZE_LAYOUT, &xs);
        }
    }
    else
    {
        NSWindow* coc_window = [coc_view window];
        [[NSNotificationCenter defaultCenter] postNotificationName:NSWindowDidResizeNotification
                        object:coc_window];
    }
}}

void coWidgetErase(widget_t wt, const xrect_t* prt)
{@autoreleasepool {  
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(prt)
    {
        NSPoint nsPoint = NSMakePoint(prt->x, prt->y + prt->h);
        _view_to_cocoa(coc_view, &nsPoint);
    
        NSRect nsRect = NSMakeRect(nsPoint.x, nsPoint.y, prt->w, prt->h);
        [coc_view setNeedsDisplayInRect:nsRect];
    }
    else
    {
        [coc_view setNeedsDisplay:YES];
    }
}}

void coWidgetEnable(widget_t wt, bool_t b)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    pwidg->disable = b;
}}

void coWidgetEnableHover(widget_t wt, bool_t b)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

}}

void coWidgetPostNotice(widget_t wt, NOTICE* pnt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = (wt)? TypePtrFromHead(cocoa_widget_t, wt) : nil;
    _CocoaView* coc_view = (wt)? pwidg->self : nil;

    if(!coc_view)
    {
        NSWindow *win = [NSApp keyWindow];
        if (!win) win = [NSApp mainWindow];
        if(win)
        {
            coc_view = [win firstResponder];
        }
        if(!coc_view) return;

        pwidg = coc_view.widget;
    }

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

int coWidgetSendNotice(widget_t wt, NOTICE* pnt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

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

void coWidgetPostCommand(widget_t wt, int code, uid_t cid, vword_t data)
{@autoreleasepool {
    cocoa_widget_t* pwidg = (wt)? TypePtrFromHead(cocoa_widget_t, wt) : nil;
    _CocoaView* coc_view = (wt)? pwidg->self : nil;

    if(!coc_view)
    {
        NSWindow *win = [NSApp keyWindow];
        if (!win) win = [NSApp mainWindow];
        if(win)
        {
            coc_view = [win firstResponder];
        }
        if(!coc_view) return;
    }

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

int coWidgetSendCommand(widget_t wt, int code, uid_t cid, vword_t data)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

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

void coWidgetPostWChar(widget_t wt, wchar_t ch)
{@autoreleasepool {
    cocoa_widget_t* pwidg = (wt)? TypePtrFromHead(cocoa_widget_t, wt) : nil;
    _CocoaView* coc_view = (wt)? pwidg->self : nil;

    if(!coc_view)
    {
        NSWindow *win = [NSApp keyWindow];
        if (!win) win = [NSApp mainWindow];
        if(win)
        {
            coc_view = [win firstResponder];
        }
    }
    if(!coc_view) return;

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

void coWidgetPostKey(widget_t wt, int key)
{@autoreleasepool {
    cocoa_widget_t* pwidg = (wt)? TypePtrFromHead(cocoa_widget_t, wt) : nil;
    _CocoaView* coc_view = (wt)? pwidg->self : nil;

    if(!coc_view)
    {
        NSWindow *win = [NSApp keyWindow];
        if (!win) win = [NSApp mainWindow];
        if(win)
        {
            coc_view = [win firstResponder];
        }
    }
    if(!coc_view) return;

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

void coWidgetSetTitle(widget_t wt, const tchar_t* token)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(!(pwidg->style & WD_STYLE_TITLE)) return;

    NSWindow* coc_window = [(NSView*)coc_view window];
    NSString *title = [NSString stringWithUTF8String:token];

    [coc_window setTitle:title];
}}

int coWidgetGetTitle(widget_t wt, tchar_t* buf, int max)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

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

void coWidgetActive(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD) return;

    NSWindow* coc_window = [(NSView*)coc_view window];

    //[coc_window makeMainWindow];
    [coc_window makeKeyAndOrderFront:nil];
}}

void coWidgetScroll(widget_t wt, bool_t horz, int line)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;
    
    NSScrollView *scrollView = (NSScrollView *)coc_view;
    NSPoint newOrigin = [[scrollView contentView] bounds].origin;

    if (horz) {
        newOrigin.x += line; 
    } else {
        newOrigin.y += line; 
    }

    [[scrollView contentView] scrollToPoint:newOrigin];
    [scrollView reflectScrolledClipView:[scrollView contentView]];
}}

void coWidgetGetScrollInfo(widget_t wt, bool_t horz, scroll_t* psl)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	if(horz)
		xmem_copy((void*)psl, (void*)&(pwidg->hs), sizeof(scroll_t));
	else
		xmem_copy((void*)psl, (void*)&(pwidg->vs), sizeof(scroll_t));
}}

static int CALLBACK _update_horz_position(widget_t child, vword_t b)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, child);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSPoint orgPosition = [coc_view frame].origin;
        NSPoint newPosition = NSMakePoint(orgPosition.x + *(int*)b, orgPosition.y);
        [coc_view setFrameOrigin:newPosition];
    }
    else
    {
        NSWindow* nsWindow = [(NSView*)child window];

        NSRect nsRect = [nsWindow frame];
        nsRect.origin = NSMakePoint(nsRect.origin.x + *(int*)b, nsRect.origin.y);
        [nsWindow setFrame:nsRect display:YES];
    }

	return (0);
}}

static int CALLBACK _update_vert_position(widget_t child, vword_t b)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, child);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD)
    {
        NSPoint orgPosition = [coc_view frame].origin;
        NSPoint newPosition = NSMakePoint(orgPosition.x, orgPosition.y - *(int*)b);
        [coc_view setFrameOrigin:newPosition];
    }
    else
    {
        NSWindow* nsWindow = [(NSView*)child window];

        NSRect nsRect = [nsWindow frame];
        NSPoint newPosition = NSMakePoint(nsRect.origin.x, nsRect.origin.y - *(int*)b);
        [nsWindow setFrame:nsRect display:YES];
    }

	return (0);
}}

void coWidgetSetScrollInfo(widget_t wt, bool_t horz, const scroll_t* psl)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	int b;

	if(horz)
	{
		b = (psl->pos - pwidg->hs.pos);
		xmem_copy((void*)&(pwidg->hs), (void*)psl, sizeof(scroll_t));

		if(!b) return;

		coWidgetEnumChild(wt, (PF_ENUM_WINDOW_PROC)_update_horz_position, (vword_t)&b);
	}
	else
	{
		b = (psl->pos - pwidg->vs.pos);
		xmem_copy((void*)&(pwidg->vs), (void*)psl, sizeof(scroll_t));

		if(!b) return;

		coWidgetEnumChild(wt, (PF_ENUM_WINDOW_PROC)_update_vert_position, (vword_t)&b);
	}
}}

static int CALLBACK _widget_set_child_color_mode(widget_t wt, vword_t pv)
{
	dword_t dw = coWidgetGetStyle(wt);
	if (dw & WD_STYLE_NOCHANGE)
		return 1;

	coWidgetSetColorMode(wt, (const color_mod_t*)pv);

	return 1;
}

void coWidgetSetColorMode(widget_t wt, const color_mod_t* pclr)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	dword_t dw = pwidg->style;

    xmem_copy((void*)&(pwidg->clrs), (void*)pclr, sizeof(color_mod_t));

	NSColor *nsColor = [NSColor colorWithCalibratedRed:(float)(pwidg->clrs.clr_bkg.r) / 255.0f
                                    green:(float)(pwidg->clrs.clr_bkg.g) / 255.0f
                                    blue:(float)(pwidg->clrs.clr_bkg.b) / 255.0f
                                    alpha:1.0f];

    [coc_view setWantsLayer:YES];
    coc_view.layer.backgroundColor = [nsColor CGColor];

	coWidgetSendCommand(wt, COMMAND_COLOR, IDC_SELF, (vword_t)pclr);

	if (dw & WD_STYLE_NOCHANGE) return;

	coWidgetEnumChild(wt, _widget_set_child_color_mode, (vword_t)pclr);
}}

const color_mod_t* coWidgetGetColorModePtr(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    return &(pwidg->clrs);
}}

void coWidgetGetColorMode(widget_t wt, color_mod_t* pclr)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    xmem_copy((void*)pclr, (void*)&(pwidg->clrs), sizeof(color_mod_t));
}}

void coWidgetSetDiaph(widget_t wt, float b)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    pwidg->diaph = b;
    [coc_view setWantsLayer:YES];
    coc_view.layer.opacity = (1.0 - b); 
}}

float coWidgetGetDiaph(widget_t wt)
{@autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

	return pwidg->diaph;
}}

int	coWidgetDoMain(widget_t wt)
{   int ret;
    @autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD) return 0;

    pwidg->mode = WS_MODE_MAIN;

    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    _CocoaApplicationDelegate *app_delegate = [[_CocoaApplicationDelegate alloc] init];
    [NSApp setDelegate:app_delegate];
    [NSApp run];

    ret = pwidg->retcode;
    coWidgetDestroy(wt);
    }

	return ret;
}

int	coWidgetDoModal(widget_t wt)
{
    int ret = 0;
    @autoreleasepool {
    cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD) return 0;

    pwidg->mode = WS_MODE_MODAL;

    _CocoaWindow* coc_window = [coc_view window];
    [coc_window setLevel:NSFloatingWindowLevel];
    [coc_window makeKeyAndOrderFront:nil];

    [NSApp runModalForWindow:coc_window];

    ret = pwidg->retcode;
    coWidgetDestroy(wt);
    }

    return ret;
}

void coWidgetDoTrack(widget_t wt)
{@autoreleasepool {
    _CocoaApplicationDelegate *app_delegate = [NSApp delegate];

	cocoa_widget_t* pwidg = TypePtrFromHead(cocoa_widget_t, wt);
    _CocoaView* coc_view = pwidg->self;

    if(pwidg->style & WD_STYLE_CHILD) return;

    pwidg->mode = WS_MODE_TRACK;

    _CocoaWindow* coc_window = [coc_view window];
    [coc_window setLevel:NSFloatingWindowLevel];
    [coc_window makeKeyAndOrderFront:nil];

    app_delegate.trackview = coc_view;

    [NSApp runModalForWindow:coc_window];
}}

void coMessageQuit(int code)
{
    [NSApp stop:nil];
}

void coMessagePosition(xpoint_t* pxp)
{@autoreleasepool {
    NSPoint nsPos = [NSEvent mouseLocation];
    NSScreen* nsScreen = [NSScreen mainScreen];
    _cocoa_to_screen(nsScreen, &nsPos);

    pxp->x = nsPos.x;
    pxp->y = nsPos.y;
}}

/*---------------------------------------------------------------*/
void coCalcWidgetBorder(dword_t ws, border_t* pbd)
{@autoreleasepool {
    pbd->edge = pbd->title = pbd->scrh = pbd->scrw = 0;

	if (ws & WD_STYLE_TITLE)
	{
		pbd->title = FRAME_TITLE_DOTS;
	}

	if (ws & WD_STYLE_BORDER)
	{
		if (ws & WD_STYLE_CHILD)
			pbd->edge = CHILD_EDGE_DOTS;
		else
			pbd->edge = FRAME_EDGE_DOTS;
	}

	if (ws & WD_STYLE_HSCROLL)
	{
		pbd->scrh = FRAME_SCROLL_DOTS;
	}

	if (ws & WD_STYLE_VSCROLL)
	{
		pbd->scrw = FRAME_SCROLL_DOTS;
	}
}}

void coAdjustWidgetSize(dword_t wstyle, xsize_t* pxs)
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

void coGetScreenSize(xsize_t* pxs)
{@autoreleasepool {
    NSScreen *mainScreen = [NSScreen mainScreen];
    NSRect screenFrame = [mainScreen frame];

    pxs->w = (int)screenFrame.size.width;
    pxs->h = (int)screenFrame.size.height;
}}

void coGetDesktopSize(xsize_t* pxs)
{@autoreleasepool {
    NSScreen *mainScreen = [NSScreen mainScreen];
    NSRect visibleFrame = [mainScreen visibleFrame];

    pxs->w = (int)visibleFrame.size.width;
    pxs->h = (int)visibleFrame.size.height;
}}

void coScreenSizeToMm(xsize_t* pxs)
{
	pxs->fw = (float)((double)pxs->w * MMPERPT);
	pxs->fh = (float)((double)pxs->h * MMPERPT);
}

void coScreenSizeToPt(xsize_t* pxs)
{
	pxs->w = (int)((double)pxs->fw * PTPERMM);
	pxs->h = (int)((double)pxs->fh * PTPERMM);
}
