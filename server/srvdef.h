/***********************************************************************
	Easily Port Service

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, China ZheJiang HangZhou JianDe, Mail: powersuite@hotmaol.com

	@doc service defination document

	@module	srvdef.h | service definition interface file

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


#ifndef _SRVDEF_H
#define _SRVDEF_H

#include <xdk.h>
#include <xdn.h>
#include <xdg.h>
#include <xdl.h>

#define XSERVICE_ROOT			_T("XSERVICE_ROOT")
#define XSERVICE_DATA			_T("XSERVICE_DATA")

#define XPORTM_WAIT_TIMO         (1000)
#define XPORTM_PIPE_NAME		_T("xportm")

#define XPORTD_PORT				_T("port")
#define XPORTD_PORT_ATTR_BIND			_T("bind")
#define XPORTD_PORT_ATTR_TYPE			_T("type")
#define XPORTD_PORT_ATTR_TYPE_HTTP		_T("http")
#define XPORTD_PORT_ATTR_TYPE_TCP		_T("tcp")
#define XPORTD_PORT_ATTR_TYPE_UDP		_T("udp")
#define XPORTD_PORT_ATTR_TYPE_UCP		_T("ucp")
#define XPORTD_MODE				_T("mode")
#define XPORTD_MODE_THREAD		_T("thread")
#define XPORTD_MODE_PROCESS		_T("process")
#define XPORTD_MODULE			_T("module")
#define XPORTD_PARAM			_T("param")
#define XPORTD_PARAM_SITE		_T("site")
#define XPORTD_PARAM_AUTHORIZATION	_T("authorization")
#define XPORTD_PARAM_SECURITY	_T("security")
#define XPORTD_PARAM_SECURITY_SSL	_T("ssl")
#define XPORTD_PARAM_SECURITY_SSH	_T("ssh")
#define XPORTD_PARAM_SECURITY_DTLS	_T("dtls")
#define XPORTD_PARAM_SECURITY_VERIFY	_T("security-verify")
#define XPORTD_PARAM_SECURITY_VERIFY_OPTIONAL	_T("optional")
#define XPORTD_PARAM_SECURITY_VERIFY_REQUEST	_T("request")
#define XPORTD_PARAM_CA_NAME		_T("ca-name")
#define XPORTD_PARAM_CRT_NAME		_T("crt-name")
#define XPORTD_PARAM_KEY_NAME		_T("key-name")
#define XPORTD_PARAM_KEY_PASSWORD	_T("key-password")
#define XPORTD_PARAM_TIMEOUT		_T("timeout")

#define IS_THREAD_MODE(mode)		(compare_text(mode,-1,_T("thread"),-1,1) == 0)

#define XPORTD_CONFIG_PROC		_T("proc")
#define XPORTD_CONFIG_PATH		_T("path")
#define XPORTD_CONFIG_TRACK		_T("track")
#define XPORTD_CONFIG_TRACE		_T("trace")

#define XTIMERD_WAIT_TIMO         (500)
#define XTIMERD_MUTEX_NAME		_T("xtimerd")

#define XTIMERD_STATE_STOPPED	0
#define XTIMERD_STATE_RUNNING	1
#define XTIMERD_STATE_PAUSED	2

#define XTIMERD_ATTR_SCHEDULE	_T("schedule")
#define XTIMERD_ATTR_MODE		_T("mode")
#define XTIMERD_ATTR_MODULE		_T("module")
#define XTIMERD_ATTR_TASK		_T("task")
#define XTIMERD_ATTR_HINT		_T("hint")
#define XTIMERD_ATTR_FIRSTTIME	_T("first-time")
#define XTIMERD_ATTR_LASTTIME	_T("last-time")
#define XTIMERD_ATTR_MONTH		_T("month")
#define XTIMERD_ATTR_WEEK		_T("week")
#define XTIMERD_ATTR_DAY		_T("day")
#define XTIMERD_ATTR_HOUR		_T("hour")
#define XTIMERD_ATTR_MINUTE		_T("minute")
#define XTIMERD_ATTR_SECOND		_T("second")

#define XTIMERD_CONFIG_NAME		_T("name")
#define XTIMERD_CONFIG_PROC		_T("proc")
#define XTIMERD_CONFIG_PATH		_T("path")
#define XTIMERD_CONFIG_TRACK	_T("track")
#define XTIMERD_CONFIG_TRACE	_T("trace")

typedef struct _timer_hint{
	xdate_t fdate;
	xdate_t ldate;

	int n_mon;
	int* p_mon;
	int n_week;
	int* p_week;
	int n_day;
	int* p_day;
	int n_hour;
	int* p_hour;
	int n_min;
	int* p_min;
	int n_sec;
	int* p_sec;
}timer_hint;

#endif //_SRVDEF_H