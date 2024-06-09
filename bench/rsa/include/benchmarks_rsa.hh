/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once

#include "alcp/alcp.h"
#include "gbench_base.hh"
#include "rng_base.hh"
#include "rsa/alc_rsa.hh"
#include "rsa/rsa.hh"
#include <benchmark/benchmark.h>
#include <iostream>
#include <string>

#ifdef USE_IPP
#include "rsa/ipp_rsa.hh"
#endif

#ifdef USE_OSSL
#include "rsa/openssl_rsa.hh"
#endif

using namespace alcp::testing;

typedef enum
{
    RSA_BENCH_ENC_PUB_KEY = 0,
    RSA_BENCH_DEC_PVT_KEY = 1
} rsa_bench_opt;

std::vector<Int64> rsa_key_sizes = { 1024, 2048 };

/* bench function */
inline int
Rsa_Bench(benchmark::State&       state,
          rsa_bench_opt           opt,
          int                     padding_mode,
          int                     KeySize,
          const alc_digest_info_t dinfo,
          const alc_digest_info_t mgfinfo)
{
    int InputSize;
    /* Keysize is in bits */
    KeySize = KeySize / 8;
    alcp_rsa_data_t data;

    AlcpRsaBase arb;
    std::string LibStr = "ALCP";
    RsaBase*    rb;
    RngBase     rngb;

    rb = &arb;

#ifdef USE_OSSL
    OpenSSLRsaBase orb;
    if (useossl == true) {
        rb     = &orb;
        LibStr = "OpenSSL";
    }
#endif

#ifdef USE_IPP
    IPPRsaBase irb;
    if (useipp == true) {
        rb     = &irb;
        LibStr = "IPP";
    }
#endif

    if (padding_mode == 1) {
        rb->m_padding_mode = ALCP_TEST_RSA_PADDING;
        /* input size should be 0 to m_key_size - 2 * m_hash_len - 2*/
        if (KeySize == 128) {
            InputSize = 62;
        } else
            InputSize = 47;
    } else {
        rb->m_padding_mode = ALCP_TEST_RSA_NO_PADDING;
        InputSize          = KeySize;
    }
    /*FIXME: keeping input const for now, a valid data for now */
    std::vector<Uint8> input_data(InputSize, 30);
    std::vector<Uint8> encrypted_data(KeySize);
    std::vector<Uint8> decrypted_data(KeySize);
    std::vector<Uint8> PubKeyKeyMod(KeySize);

    data.m_msg            = &(input_data[0]);
    data.m_pub_key_mod    = &(PubKeyKeyMod[0]);
    data.m_encrypted_data = &(encrypted_data[0]);
    data.m_decrypted_data = &(decrypted_data[0]);
    data.m_msg_len        = input_data.size();
    data.m_key_len        = KeySize;

    rb->m_key_len     = KeySize;
    rb->m_digest_info = dinfo;
    rb->m_mgf_info    = mgfinfo;
    rb->m_hash_len    = dinfo.dt_len / 8;

    /* seed and label for padding mode */
    std::vector<Uint8> seed(rb->m_hash_len);
    data.m_pseed = &(seed[0]);
    std::vector<Uint8> label(5);
    data.m_label      = &(label[0]);
    data.m_label_size = label.size();

    if (!rb->init()) {
        state.SkipWithError("Error in RSA init");
    }
    if (!rb->SetPublicKey(data)) {
        state.SkipWithError("Error in RSA SetPublicKey");
    }
    if (!rb->SetPrivateKey(data)) {
        state.SkipWithError("Error in RSA SetPrivateKey");
    }

    if (opt == RSA_BENCH_ENC_PUB_KEY) {
        for (auto _ : state) {
            if (0 != rb->EncryptPubKey(data)) {
                state.SkipWithError("Error in RSA EncryptPubKey");
            }
        }
    } else if (opt == RSA_BENCH_DEC_PVT_KEY) {
        /* encrypt, then benchmark only dec pvt key */
        if (0 != rb->EncryptPubKey(data)) {
            state.SkipWithError("Error in RSA EncryptPubKey");
        }
        /* benchmark only this */
        for (auto _ : state) {
            if (0 != rb->DecryptPvtKey(data)) {
                state.SkipWithError("Error in RSA DecryptPvtKey");
            }
        }
    }

    std::string sResultUnit = (opt == RSA_BENCH_ENC_PUB_KEY) ? "Encryptions/Sec"
                              : (opt == RSA_BENCH_DEC_PVT_KEY)
                                  ? "Decryptions/Sec"
                                  : "";
    state.counters[sResultUnit] =
        benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
    return 0;
}

static void
BENCH_RSA_DecryptPvtKey_Padding(benchmark::State& state)
{
    alc_digest_info_t dinfo, mgfinfo;
    dinfo.dt_mode.dm_sha2 = ALC_SHA2_256;
    dinfo.dt_len          = ALC_DIGEST_LEN_256;
    dinfo.dt_type         = ALC_DIGEST_TYPE_SHA2;
    mgfinfo               = dinfo;
    benchmark::DoNotOptimize(Rsa_Bench(state,
                                       RSA_BENCH_DEC_PVT_KEY,
                                       ALCP_TEST_RSA_PADDING,
                                       state.range(0),
                                       dinfo,
                                       mgfinfo));
}

static void
BENCH_RSA_DecryptPvtKey_NoPadding(benchmark::State& state)
{
    alc_digest_info_t dinfo, mgfinfo;
    dinfo.dt_mode.dm_sha2 = ALC_SHA2_256;
    dinfo.dt_len          = ALC_DIGEST_LEN_256;
    dinfo.dt_type         = ALC_DIGEST_TYPE_SHA2;
    mgfinfo               = dinfo;
    benchmark::DoNotOptimize(Rsa_Bench(state,
                                       RSA_BENCH_DEC_PVT_KEY,
                                       ALCP_TEST_RSA_NO_PADDING,
                                       state.range(0),
                                       dinfo,
                                       mgfinfo));
}

static void
BENCH_RSA_EncryptPubKey_Padding(benchmark::State& state)
{
    alc_digest_info_t dinfo, mgfinfo;
    dinfo.dt_mode.dm_sha2 = ALC_SHA2_256;
    dinfo.dt_len          = ALC_DIGEST_LEN_256;
    dinfo.dt_type         = ALC_DIGEST_TYPE_SHA2;
    mgfinfo               = dinfo;
    benchmark::DoNotOptimize(Rsa_Bench(state,
                                       RSA_BENCH_ENC_PUB_KEY,
                                       ALCP_TEST_RSA_PADDING,
                                       state.range(0),
                                       dinfo,
                                       mgfinfo));
}

static void
BENCH_RSA_EncryptPubKey_NoPadding(benchmark::State& state)
{
    alc_digest_info_t dinfo, mgfinfo;
    dinfo.dt_mode.dm_sha2 = ALC_SHA2_256;
    dinfo.dt_len          = ALC_DIGEST_LEN_256;
    dinfo.dt_type         = ALC_DIGEST_TYPE_SHA2;
    mgfinfo               = dinfo;
    benchmark::DoNotOptimize(Rsa_Bench(state,
                                       RSA_BENCH_ENC_PUB_KEY,
                                       ALCP_TEST_RSA_NO_PADDING,
                                       state.range(0),
                                       dinfo,
                                       mgfinfo));
}

/* add new benchmarks here */
int
AddBenchmarks_rsa()
{
    BENCHMARK(BENCH_RSA_EncryptPubKey_NoPadding)
        ->ArgsProduct({ rsa_key_sizes });
    BENCHMARK(BENCH_RSA_DecryptPvtKey_NoPadding)
        ->ArgsProduct({ rsa_key_sizes });
    BENCHMARK(BENCH_RSA_EncryptPubKey_Padding)->ArgsProduct({ rsa_key_sizes });
    BENCHMARK(BENCH_RSA_DecryptPvtKey_Padding)->ArgsProduct({ rsa_key_sizes });

    return 0;
}