﻿/**
* \file hmac_drbg.h
*
* \brief The HMAC_DRBG pseudorandom generator.
*
* This module implements the HMAC_DRBG pseudorandom generator described
* in <em>NIST SP 800-90A: Recommendation for Random Number Generation Using
* Deterministic Random Bit Generators</em>.
*/
/*
*  Copyright (C) 2006-2019, ARM Limited, All Rights Reserved
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
#ifndef HMAC_DBRG_H
#define HMAC_DBRG_H

#include "../xdkdef.h"
#include "mdwrap.h"

/**
* \name SECTION: Module settings
*
* The configuration options you can set for this module are in this section.
* Either change them in config.h or define them on the compiler command line.
* \{
*/

#if !defined(HMAC_DRBG_RESEED_INTERVAL)
#define HMAC_DRBG_RESEED_INTERVAL   10000   /**< Interval before reseed is performed by default */
#endif

#if !defined(HMAC_DRBG_MAX_INPUT)
#define HMAC_DRBG_MAX_INPUT         256     /**< Maximum number of additional input bytes */
#endif

#if !defined(HMAC_DRBG_MAX_REQUEST)
#define HMAC_DRBG_MAX_REQUEST       1024    /**< Maximum number of requested bytes per call */
#endif

#if !defined(HMAC_DRBG_MAX_SEED_INPUT)
#define HMAC_DRBG_MAX_SEED_INPUT    384     /**< Maximum size of (re)seed buffer */
#endif

/* \} name SECTION: Module settings */

#define HMAC_DRBG_PR_OFF   0   /**< No prediction resistance       */
#define HMAC_DRBG_PR_ON    1   /**< Prediction resistance enabled  */


/**
* HMAC_DRBG context.
*/
typedef struct hmac_drbg_context
{
	/* Working state: the key K is not stored explicitly,
	* but is implied by the HMAC context */
	md_type_t md_type;                    /*!< HMAC context (inc. K)  */
	void* md_ctx;

	byte_t V[MD_MAX_SIZE];  /*!< V in the spec          */
	int reseed_counter;                     /*!< reseed counter         */

	/* Administrative state */
	dword_t entropy_len;         /*!< entropy bytes grabbed on each (re)seed */
	int prediction_resistance;  /*!< enable prediction resistance (Automatic
								reseed before every random generation) */
	int reseed_interval;        /*!< reseed interval   */

	/* Callbacks */
	int(*f_entropy)(void *, byte_t *, dword_t); /*!< entropy function */
	void *p_entropy;            /*!< context for the entropy function        */

} hmac_drbg_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief               HMAC_DRBG context initialization.
 *
 * This function makes the context ready for hmac_drbg_seed(),
 * hmac_drbg_seed_buf() or hmac_drbg_free().
 *
 * \param ctx           HMAC_DRBG context to be initialized.
 */
EXP_API void hmac_drbg_init(hmac_drbg_context *ctx);

/**
 * \brief               HMAC_DRBG initial seeding.
 *
 * Set the initial seed and set up the entropy source for future reseeds.
 *
 * A typical choice for the \p f_entropy and \p p_entropy parameters is
 * to use the entropy module:
 * - \p f_entropy is entropy_func();
 * - \p p_entropy is an instance of ::entropy_context initialized
 *   with entropy_init() (which registers the platform's default
 *   entropy sources).
 *
 * You can provide a personalization string in addition to the
 * entropy source, to make this instantiation as unique as possible.
 *
 * \note                By default, the security strength as defined by NIST is:
 *                      - 128 bits if \p md_info is SHA-1;
 *                      - 192 bits if \p md_info is SHA-224;
 *                      - 256 bits if \p md_info is SHA-256, SHA-384 or SHA-512.
 *                      Note that SHA-256 is just as efficient as SHA-224.
 *                      The security strength can be reduced if a smaller
 *                      entropy length is set with
 *                      hmac_drbg_set_entropy_len().
 *
 * \note                The default entropy length is the security strength
 *                      (converted from bits to bytes). You can override
 *                      it by calling hmac_drbg_set_entropy_len().
 *
 * \note                During the initial seeding, this function calls
 *                      the entropy source to obtain a nonce
 *                      whose length is half the entropy length.
 *
 * \param ctx           HMAC_DRBG context to be seeded.
 * \param md_info       MD algorithm to use for HMAC_DRBG.
 * \param f_entropy     The entropy callback, taking as arguments the
 *                      \p p_entropy context, the buffer to fill, and the
 *                      length of the buffer.
 *                      \p f_entropy is always called with a length that is
 *                      less than or equal to the entropy length.
 * \param p_entropy     The entropy context to pass to \p f_entropy.
 * \param custom        The personalization string.
 *                      This can be \c NULL, in which case the personalization
 *                      string is empty regardless of the value of \p len.
 * \param len           The length of the personalization string.
 *                      This must be at most #HMAC_DRBG_MAX_INPUT
 *                      and also at most
 *                      #HMAC_DRBG_MAX_SEED_INPUT - \p entropy_len * 3 / 2
 *                      where \p entropy_len is the entropy length
 *                      described above.
 *
 * \return              \c 0 if successful.
 * \return              #ERR_MD_BAD_INPUT_DATA if \p md_info is
 *                      invalid.
 * \return              #ERR_MD_ALLOC_FAILED if there was not enough
 *                      memory to allocate context data.
 * \return              #ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED
 *                      if the call to \p f_entropy failed.
 */
EXP_API int hmac_drbg_seed(hmac_drbg_context *ctx,
                    md_type_t md_type,
                    int (*f_entropy)(void *, byte_t *, dword_t),
                    void *p_entropy,
                    const byte_t *custom,
                    dword_t len );

/**
 * \brief               Initilisation of simpified HMAC_DRBG (never reseeds).
 *
 * This function is meant for use in algorithms that need a pseudorandom
 * input such as deterministic ECDSA.
 *
 * \param ctx           HMAC_DRBG context to be initialised.
 * \param md_info       MD algorithm to use for HMAC_DRBG.
 * \param data          Concatenation of the initial entropy string and
 *                      the additional data.
 * \param data_len      Length of \p data in bytes.
 *
 * \return              \c 0 if successful. or
 * \return              #ERR_MD_BAD_INPUT_DATA if \p md_info is
 *                      invalid.
 * \return              #ERR_MD_ALLOC_FAILED if there was not enough
 *                      memory to allocate context data.
 */
EXP_API int hmac_drbg_seed_buf(hmac_drbg_context *ctx,
                        md_type_t md_type,
                        const byte_t *data, dword_t data_len );

/**
 * \brief               This function turns prediction resistance on or off.
 *                      The default value is off.
 *
 * \note                If enabled, entropy is gathered at the beginning of
 *                      every call to hmac_drbg_random_with_add()
 *                      or hmac_drbg_random().
 *                      Only use this if your entropy source has sufficient
 *                      throughput.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param resistance    #HMAC_DRBG_PR_ON or #HMAC_DRBG_PR_OFF.
 */
EXP_API void hmac_drbg_set_prediction_resistance(hmac_drbg_context *ctx,
                                          int resistance );

/**
 * \brief               This function sets the amount of entropy grabbed on each
 *                      seed or reseed.
 *
 * See the documentation of hmac_drbg_seed() for the default value.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param len           The amount of entropy to grab, in bytes.
 */
EXP_API void hmac_drbg_set_entropy_len(hmac_drbg_context *ctx,
                                dword_t len );

/**
 * \brief               Set the reseed interval.
 *
 * The reseed interval is the number of calls to hmac_drbg_random()
 * or hmac_drbg_random_with_add() after which the entropy function
 * is called again.
 *
 * The default value is #HMAC_DRBG_RESEED_INTERVAL.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param interval      The reseed interval.
 */
EXP_API void hmac_drbg_set_reseed_interval(hmac_drbg_context *ctx,
                                    int interval );

/**
 * \brief               This function updates the state of the HMAC_DRBG context.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param additional    The data to update the state with.
 *                      If this is \c NULL, there is no additional data.
 * \param add_len       Length of \p additional in bytes.
 *                      Unused if \p additional is \c NULL.
 *
 * \return              \c 0 on success, or an error from the underlying
 *                      hash calculation.
 */
EXP_API int hmac_drbg_update(hmac_drbg_context *ctx,
                       const byte_t *additional, dword_t add_len );

/**
 * \brief               This function reseeds the HMAC_DRBG context, that is
 *                      extracts data from the entropy source.
 *
 * \param ctx           The HMAC_DRBG context.
 * \param additional    Additional data to add to the state.
 *                      If this is \c NULL, there is no additional data
 *                      and \p len should be \c 0.
 * \param len           The length of the additional data.
 *                      This must be at most #HMAC_DRBG_MAX_INPUT
 *                      and also at most
 *                      #HMAC_DRBG_MAX_SEED_INPUT - \p entropy_len
 *                      where \p entropy_len is the entropy length
 *                      (see hmac_drbg_set_entropy_len()).
 *
 * \return              \c 0 if successful.
 * \return              #ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED
 *                      if a call to the entropy function failed.
 */
EXP_API int hmac_drbg_reseed(hmac_drbg_context *ctx,
                      const byte_t *additional, dword_t len );

/**
 * \brief   This function updates an HMAC_DRBG instance with additional
 *          data and uses it to generate random data.
 *
 * This function automatically reseeds if the reseed counter is exceeded
 * or prediction resistance is enabled.
 *
 * \param p_rng         The HMAC_DRBG context. This must be a pointer to a
 *                      #hmac_drbg_context structure.
 * \param output        The buffer to fill.
 * \param output_len    The length of the buffer in bytes.
 *                      This must be at most #HMAC_DRBG_MAX_REQUEST.
 * \param additional    Additional data to update with.
 *                      If this is \c NULL, there is no additional data
 *                      and \p add_len should be \c 0.
 * \param add_len       The length of the additional data.
 *                      This must be at most #HMAC_DRBG_MAX_INPUT.
 *
 * \return              \c 0 if successful.
 * \return              #ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED
 *                      if a call to the entropy source failed.
 * \return              #ERR_HMAC_DRBG_REQUEST_TOO_BIG if
 *                      \p output_len > #HMAC_DRBG_MAX_REQUEST.
 * \return              #ERR_HMAC_DRBG_INPUT_TOO_BIG if
 *                      \p add_len > #HMAC_DRBG_MAX_INPUT.
 */
EXP_API int hmac_drbg_random_with_add(void *p_rng,
                               byte_t *output, dword_t output_len,
                               const byte_t *additional,
                               dword_t add_len );

/**
 * \brief   This function uses HMAC_DRBG to generate random data.
 *
 * This function automatically reseeds if the reseed counter is exceeded
 * or prediction resistance is enabled.
 *
 * \param p_rng         The HMAC_DRBG context. This must be a pointer to a
 *                      #hmac_drbg_context structure.
 * \param output        The buffer to fill.
 * \param out_len       The length of the buffer in bytes.
 *                      This must be at most #HMAC_DRBG_MAX_REQUEST.
 *
 * \return              \c 0 if successful.
 * \return              #ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED
 *                      if a call to the entropy source failed.
 * \return              #ERR_HMAC_DRBG_REQUEST_TOO_BIG if
 *                      \p out_len > #HMAC_DRBG_MAX_REQUEST.
 */
EXP_API int hmac_drbg_random(void *p_rng, byte_t *output, dword_t out_len);

/**
 * \brief               Free an HMAC_DRBG context
 *
 * \param ctx           The HMAC_DRBG context to free.
 */
EXP_API void hmac_drbg_free(hmac_drbg_context *ctx);



#if defined(XDK_SUPPORT_TEST)
/**
 * \brief               The HMAC_DRBG Checkup routine.
 *
 * \return              \c 0 if successful.
 * \return              \c 1 if the test failed.
 */
EXP_API int hmac_drbg_self_test( int verbose );

#endif


#ifdef __cplusplus
}
#endif


#endif /* havege.h */


