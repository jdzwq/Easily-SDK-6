﻿/**
* \file timing.h
*
* \brief Portable interface to timeouts and to the CPU cycle counter
*/
/*
*  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
*  SPDX-License-Identifier: Apache-2.0
*
*  Licensed under the Apache License, Version 2.0 (the "License"); you may
*  not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
*  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
*  This file is part of mbed TLS (https://tls.mbed.org)
*/
#ifndef TIMING_H
#define TIMING_H

#include "../xdkdef.h"

/**
* \brief          timer structure
*/
struct timing_hr_time
{
	byte_t opaque[32];
};

/**
* \brief          Context for timing_set/get_delay()
*/
typedef struct timing_delay_context
{
	struct timing_hr_time   timer;
	dword_t                        int_ms;
	dword_t                        fin_ms;
} timing_delay_context;

#ifdef __cplusplus
extern "C" {
#endif

extern volatile int timing_alarmed;

/**
 * \brief          Return the CPU cycle counter value
 *
 * \warning        This is only a best effort! Do not rely on this!
 *                 In particular, it is known to be unreliable on virtual
 *                 machines.
 *
 * \note           This value starts at an unspecified origin and
 *                 may wrap around.
 */
unsigned long timing_hardclock( void );

/**
 * \brief          Return the elapsed time in milliseconds
 *
 * \param val      points to a timer structure
 * \param reset    If 0, query the elapsed time. Otherwise (re)start the timer.
 *
 * \return         Elapsed time since the previous reset in ms. When
 *                 restarting, this is always 0.
 *
 * \note           To initialize a timer, call this function with reset=1.
 *
 *                 Determining the elapsed time and resetting the timer is not
 *                 atomic on all platforms, so after the sequence
 *                 `{ get_timer(1); ...; time1 = get_timer(1); ...; time2 =
 *                 get_timer(0) }` the value time1+time2 is only approximately
 *                 the delay since the first reset.
 */
unsigned long timing_get_timer( struct timing_hr_time *val, int reset );

/**
 * \brief          Setup an alarm clock
 *
 * \param seconds  delay before the "timing_alarmed" flag is set
 *                 (must be >=0)
 *
 * \warning        Only one alarm at a time  is supported. In a threaded
 *                 context, this means one for the whole process, not one per
 *                 thread.
 */
void set_alarm( int seconds );

/**
 * \brief          Set a pair of delays to watch
 *                 (See \c timing_get_delay().)
 *
 * \param data     Pointer to timing data.
 *                 Must point to a valid \c timing_delay_context struct.
 * \param int_ms   First (intermediate) delay in milliseconds.
 *                 The effect if int_ms > fin_ms is unspecified.
 * \param fin_ms   Second (final) delay in milliseconds.
 *                 Pass 0 to cancel the current delay.
 *
 * \note           To set a single delay, either use \c timing_set_timer
 *                 directly or use this function with int_ms == fin_ms.
 */
void timing_set_delay( void *data, dword_t int_ms, dword_t fin_ms );

/**
 * \brief          Get the status of delays
 *                 (Memory helper: number of delays passed.)
 *
 * \param data     Pointer to timing data
 *                 Must point to a valid \c timing_delay_context struct.
 *
 * \return         -1 if cancelled (fin_ms = 0),
 *                  0 if none of the delays are passed,
 *                  1 if only the intermediate delay is passed,
 *                  2 if the final delay is passed.
 */
int timing_get_delay( void *data );

#if defined(XDK_SUPPORT_TEST)
/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if a test failed
 */
EXP_API int timing_self_test( int verbose );
#endif

#ifdef __cplusplus
}
#endif


#endif /* timing.h */