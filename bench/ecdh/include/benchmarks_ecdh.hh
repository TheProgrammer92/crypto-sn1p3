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
#include "alcp/utils/cpuid.hh"
#include "ecdh/alc_ecdh.hh"
#include "ecdh/ecdh.hh"
#include "gbench_base.hh"
#include "rng_base.hh"
#include <benchmark/benchmark.h>
#include <iostream>
#include <string>

#ifdef USE_IPP
#include "ecdh/ipp_ecdh.hh"
#endif

#ifdef USE_OSSL
#include "ecdh/openssl_ecdh.hh"
#endif

using namespace alcp::testing;
using alcp::utils::CpuId;

typedef enum
{
    ECDH_BENCH_GEN_PUB_KEY    = 0,
    ECDH_BENCH_GEN_SECRET_KEY = 1
} ecdh_bench_opt;

inline int
ecdh_Bench(benchmark::State& state, alc_ec_info_t info, ecdh_bench_opt opt)
{
    std::string LibStr = "";

    /*TODO, Keysize in bytes. might change for other curves */
    int                KeySize = ECDH_KEYSIZE;
    std::vector<Uint8> Peer1PubKey(KeySize), Peer2PubKey(KeySize),
        Peer1SharedSecretKey(KeySize), Peer2SharedSecretKey(KeySize);

    alcp_ecdh_data_t data_peer1, data_peer2;

    AlcpEcdhBase aeb_peer1(info);
    AlcpEcdhBase aeb_peer2(info);

    EcdhBase *Eb_peer1, *Eb_peer2;
    RngBase   rb;
    Eb_peer1 = &aeb_peer1;
    Eb_peer2 = &aeb_peer2;

    LibStr = "ALCP";

#ifdef USE_OSSL
    OpenSSLEcdhBase oeb_peer1(info);
    OpenSSLEcdhBase oeb_peer2(info);
    /* Select by default openssl for cross testing if nothing provided*/
    if (useossl == true) {
        Eb_peer1 = &oeb_peer1;
        Eb_peer2 = &oeb_peer2;
        LibStr   = "OpenSSL";
    }
#endif
#ifdef USE_IPP
    IPPEcdhBase ieb_peer1(info);
    IPPEcdhBase ieb_peer2(info);
    if (useipp == true) {
        // FIXME : skip bench if not running on avx512 architecture
        if (!CpuId::cpuHasAvx512(alcp::utils::AVX512_F)) {
            state.SkipWithError(
                "IPP Ecdh multi-buffer implementations arent supported "
                "on non-avx512 supported arch,"
                "skipping benchmarks!");
            return 0;
        }
        Eb_peer1 = &ieb_peer1;
        Eb_peer2 = &ieb_peer2;
        LibStr   = "IPP";
    }
#endif

    std::vector<Uint8> Peer1PvtKey = rb.genRandomBytes(KeySize);
    std::vector<Uint8> Peer2PvtKey = rb.genRandomBytes(KeySize);

    /* now load this pvtkey pair into both alc, ext data */
    data_peer1.m_Peer_PvtKey    = &(Peer1PvtKey[0]);
    data_peer2.m_Peer_PvtKey    = &(Peer2PvtKey[0]);
    data_peer1.m_Peer_PvtKeyLen = KeySize;
    data_peer2.m_Peer_PvtKeyLen = KeySize;
    data_peer1.m_Peer_PubKey    = &(Peer1PubKey[0]);
    data_peer2.m_Peer_PubKey    = &(Peer2PubKey[0]);
    data_peer1.m_Peer_PubKeyLen = KeySize;
    data_peer2.m_Peer_PubKeyLen = KeySize;
    data_peer1.m_Peer_SecretKey = &(Peer1SharedSecretKey[0]);
    data_peer2.m_Peer_SecretKey = &(Peer2SharedSecretKey[0]);

    /* init wont be benchmarked */
    if (!Eb_peer1->init(info)) {
        state.SkipWithError("Error in ECDH init");
    }
    if (!Eb_peer2->init(info)) {
        state.SkipWithError("Error in ECDH init");
    }

    /* Just benchmark Gen public key */
    if (opt == ECDH_BENCH_GEN_PUB_KEY) {
        for (auto _ : state) {
            if (!Eb_peer1->GeneratePublicKey(data_peer1)) {
                state.SkipWithError("Error in ECDH GeneratePublicKey");
            }
        }
    } else if (opt == ECDH_BENCH_GEN_SECRET_KEY) {
        /* this step is needed for computing secret key */
        if (!Eb_peer1->GeneratePublicKey(data_peer1)) {
            state.SkipWithError("Error in ECDH GeneratePublicKey");
        }
        if (!Eb_peer2->GeneratePublicKey(data_peer2)) {
            state.SkipWithError("Error in ECDH GeneratePublicKey");
        }
        /* to benchmark only Computing secret key */
        for (auto _ : state) {
            if (!Eb_peer1->ComputeSecretKey(data_peer1, data_peer2)) {
                state.SkipWithError("Error in ECDH ComputeSecretKey");
            }
        }
    }
    state.counters["KeysGen/Sec"] =
        benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
    return 0;
}

static void
BENCH_ECDH_x25519_GenPubKey(benchmark::State& state)
{
    alc_ec_info_t info;
    info.ecCurveId     = ALCP_EC_CURVE25519;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    benchmark::DoNotOptimize(ecdh_Bench(state, info, ECDH_BENCH_GEN_PUB_KEY));
}
static void
BENCH_ECDH_x25519_GenSecretKey(benchmark::State& state)
{
    alc_ec_info_t info;
    info.ecCurveId     = ALCP_EC_CURVE25519;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    benchmark::DoNotOptimize(
        ecdh_Bench(state, info, ECDH_BENCH_GEN_SECRET_KEY));
}

/* add new benchmarks here */
int
AddBenchmarks_Ecdh()
{
    BENCHMARK(BENCH_ECDH_x25519_GenPubKey);
    BENCHMARK(BENCH_ECDH_x25519_GenSecretKey);
    return 0;
}