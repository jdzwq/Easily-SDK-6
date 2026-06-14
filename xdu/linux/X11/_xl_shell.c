/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc shell document

	@module	xl_shell.c | X11/GTK implement file

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

#include "_if_X11.h"


bool_t xlShellGetFileName(widget_t owner, const tchar_t* defpath, const tchar_t* filter, const tchar_t* defext, bool_t saveit, tchar_t* pathbuf, int pathlen, tchar_t* filebuf, int filelen)
{
    GtkWidget *dialog;
    char *fname = NULL;
    bool_t b = 0;

    dialog = gtk_file_chooser_dialog_new(saveit ? "Save File" : "Open File",
                                         NULL,
                                         saveit ? GTK_FILE_CHOOSER_ACTION_SAVE : GTK_FILE_CHOOSER_ACTION_OPEN,
                                         "_Cancel", GTK_RESPONSE_CANCEL,
                                         saveit ? "_Save" : "_Open", GTK_RESPONSE_ACCEPT,
                                         NULL);

    if (defpath && defpath[0]) 
    {
        gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(dialog), defpath);
    }

    if (saveit) 
    {
        gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
        if (defext && defext[0]) 
        {
            if (!defpath || !defpath[0]) 
            {
                gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), defext);
            }
        }
    }

    if (filter && filter[0]) 
    {
        GtkFileFilter *ff = gtk_file_filter_new();
        gtk_file_filter_add_pattern(ff, filter); 
        gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), ff);
    }

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) 
    {
        fname = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        if (fname) {
            split_path(fname, pathbuf, filebuf, NULL);
            g_free(fname);
            b = bool_true;
        }
    }

    gtk_widget_destroy(dialog);

    while (gtk_events_pending()) 
    {
        gtk_main_iteration(); 
    }

    return b;
}

bool_t xlShellGetPathName(widget_t owner, const tchar_t* defpath, bool_t createit, tchar_t* pathbuf, int pathlen)
{
    GtkWidget *dialog;
    char *sel = NULL;
    bool_t b = 0;

    dialog = gtk_file_chooser_dialog_new("Select Folder",
                                         NULL,
                                         GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
                                         "_Cancel", GTK_RESPONSE_CANCEL,
                                         "_Select", GTK_RESPONSE_ACCEPT,
                                         NULL);

    if (defpath && defpath[0]) 
    {
        gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), defpath);
    }

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) 
    {
        sel = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        if (sel) 
        {
            strncpy(pathbuf, sel, pathlen - 1);
            pathbuf[pathlen - 1] = 0;
            g_free(sel);
            b = 1;
        }
    }

    gtk_widget_destroy(dialog);

    while (gtk_events_pending())
    {
        gtk_main_iteration(); 
    }

    return b;
}

bool_t xlShellGetCurPath(tchar_t* pathbuf, int pathlen)
{
	if (getcwd(pathbuf, pathlen)) {
        return 1;
    }
    pathbuf[0] = 0;
    return 0;
}

bool_t xlShellGetRunPath(tchar_t* pathbuf, int pathlen)
{
	char exe_path[PATH_MAX];
    char* last_slash;

    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) {
        pathbuf[0] = 0;
        return 0;
    }
    exe_path[len] = 0;
    last_slash = strrchr(exe_path, '/');
    if (last_slash) {
        *last_slash = 0;
        strncpy(pathbuf, exe_path, pathlen - 1);
        pathbuf[pathlen - 1] = 0;
        return 1;
    }
    pathbuf[0] = 0;
    return 0;
}

bool_t xlShellGetAppPath(tchar_t* pathbuf, int pathlen)
{
	char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    
    if (len <= 0) {
        pathbuf[0] = 0;
        return 0;
    }
    exe_path[len] = 0;
    strncpy(pathbuf, exe_path, pathlen - 1);
    pathbuf[pathlen - 1] = 0;
    return 1;
}

bool_t xlShellGetDocPath(tchar_t* pathbuf, int pathlen)
{
	const char* home = getenv("HOME");
    if (!home) {
        pathbuf[0] = 0;
        return 0;
    }
    snprintf(pathbuf, pathlen, "%s/Documents", home);
    pathbuf[pathlen - 1] = 0;
    return 1;
}

bool_t xlShellGetTmpPath(tchar_t* pathbuf, int pathlen)
{
	const char* tmp = getenv("TMPDIR");
    if (!tmp || !tmp[0]) {
        tmp = "/tmp";
    }
    strncpy(pathbuf, tmp, pathlen - 1);
    pathbuf[pathlen - 1] = 0;
    return 1;
}
