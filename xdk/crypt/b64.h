﻿/**
* \file base64.h
*
* \brief RFC 1521 base64 encoding/decoding
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
#ifndef OEMB64_H
#define OEMB64_H


#include "../xdkdef.h"


#ifdef __cplusplus
extern "C" {
#endif

	/**
 * \brief          Encode a buffer into base64 format
 *
 * \param dst      destination buffer
 * \param dlen     size of the destination buffer
 * \param olen     number of bytes written
 * \param src      source buffer
 * \param slen     amount of data to be encoded
 *
 * \return         0 if successful, or ERR_BASE64_BUFFER_TOO_SMALL.
 *                 *olen is always updated to reflect the amount
 *                 of data that has (or would have) been written.
 *                 If that length cannot be represented, then no data is
 *                 written to the buffer and *olen is set to the maximum
 *                 length representable as a dword_t.
 *
 * \note           Call this function with dlen = 0 to obtain the
 *                 required buffer size in *olen
 */
EXP_API int base64_encode(byte_t *dst, dword_t dlen, dword_t *olen,
                   const byte_t *src, dword_t slen );

/**
 * \brief          Decode a base64-formatted buffer
 *
 * \param dst      destination buffer (can be NULL for checking size)
 * \param dlen     size of the destination buffer
 * \param olen     number of bytes written
 * \param src      source buffer
 * \param slen     amount of data to be decoded
 *
 * \return         0 if successful, ERR_BASE64_BUFFER_TOO_SMALL, or
 *                 ERR_BASE64_INVALID_CHARACTER if the input data is
 *                 not correct. *olen is always updated to reflect the amount
 *                 of data that has (or would have) been written.
 *
 * \note           Call this function with *dst = NULL or dlen = 0 to obtain
 *                 the required buffer size in *olen
 */
EXP_API int base64_decode(byte_t *dst, dword_t dlen, dword_t *olen,
                   const byte_t *src, dword_t slen );

#if defined(XDK_SUPPORT_TEST)
/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
EXP_API int base64_self_test( int verbose );

#endif /* SELF_TEST */


#ifdef __cplusplus
}
#endif

#endif /* base64.h */

