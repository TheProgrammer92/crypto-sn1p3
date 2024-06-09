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
#include "hmac/alc_hmac.hh"
#include "hmac/hmac.hh"

#ifdef USE_IPP
#include "hmac/ipp_hmac.hh"
#endif

#ifdef USE_OSSL
#include "hmac/openssl_hmac.hh"
#endif

#include "gbench_base.hh"
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include <string.h>

using namespace alcp::testing;

/* Valid block sizes for performance comparison */
std::vector<Int64> hmac_block_sizes = { 16, 64, 256, 1024, 8192, 16384, 32768 };

void inline Hmac_Bench(benchmark::State& state,
                       alc_mac_info_t    info,
                       Uint64            block_size,
                       int               HmacSize)
{
    // In ALCP code, any key size greater than the internal block length of the
    // SHA used is the hottest path for alcp request. So Using KeySize above
    // 1024.
    const int          KeySize = 1048;
    std::vector<Uint8> Hmac(HmacSize / 8, 0);
    std::vector<Uint8> message(block_size, 0);
    std::vector<Uint8> Key(KeySize, 0);

    /* Initialize info params based on hmac type */
    info.mi_type = ALC_MAC_HMAC;
    info.mi_algoinfo.hmac.hmac_digest.dt_len =
        static_cast<enum _alc_digest_len>(HmacSize);

    AlcpHmacBase     ahb(info);
    HmacBase*        hb = &ahb;
    alcp_hmac_data_t data;
#ifdef USE_IPP
    IPPHmacBase ihb(info);
    if (useipp) {
        hb = &ihb;
    }
#endif

#ifdef USE_OSSL
    OpenSSLHmacBase ohb(info);
    if (useossl) {
        hb = &ohb;
    }
#endif

    data.in.m_msg       = &(message[0]);
    data.in.m_msg_len   = message.size();
    data.out.m_hmac     = &(Hmac[0]);
    data.out.m_hmac_len = Hmac.size();
    data.in.m_key       = &(Key[0]);
    data.in.m_key_len   = Key.size();

    if (!hb->init(info, Key)) {
        state.SkipWithError("Error in hmac init function");
    }
    for (auto _ : state) {
        if (!hb->Hmac_function(data)) {
            state.SkipWithError("Error in hmac benchmark function");
        }
        if (!hb->reset()) {
            std::cout << "Error in hmac Reset function" << std::endl;
            return;
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

/* add all your new benchmarks here */
/* SHA2 benchmarks */
static void
BENCH_HMAC_SHA2_224(benchmark::State& state)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha2 = ALC_SHA2_224;
    Hmac_Bench(state, info, state.range(0), 224);
}
static void
BENCH_HMAC_SHA2_256(benchmark::State& state)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha2 = ALC_SHA2_256;
    Hmac_Bench(state, info, state.range(0), 256);
}
static void
BENCH_HMAC_SHA2_384(benchmark::State& state)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha2 = ALC_SHA2_384;
    Hmac_Bench(state, info, state.range(0), 384);
}
static void
BENCH_HMAC_SHA2_512(benchmark::State& state)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha2 = ALC_SHA2_512;
    Hmac_Bench(state, info, state.range(0), 512);
}

/* SHA3 benchmarks */
static void
BENCH_HMAC_SHA3_224(benchmark::State& state)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 = ALC_SHA3_224;
    Hmac_Bench(state, info, state.range(0), 224);
}
static void
BENCH_HMAC_SHA3_256(benchmark::State& state)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 = ALC_SHA3_256;
    Hmac_Bench(state, info, state.range(0), 256);
}
static void
BENCH_HMAC_SHA3_384(benchmark::State& state)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 = ALC_SHA3_384;
    Hmac_Bench(state, info, state.range(0), 384);
}
static void
BENCH_HMAC_SHA3_512(benchmark::State& state)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 = ALC_SHA3_512;
    Hmac_Bench(state, info, state.range(0), 512);
}

/* add benchmarks */
int
AddBenchmarks()
{
    BENCHMARK(BENCH_HMAC_SHA2_224)->ArgsProduct({ hmac_block_sizes });
    BENCHMARK(BENCH_HMAC_SHA2_256)->ArgsProduct({ hmac_block_sizes });
    BENCHMARK(BENCH_HMAC_SHA2_384)->ArgsProduct({ hmac_block_sizes });
    BENCHMARK(BENCH_HMAC_SHA2_512)->ArgsProduct({ hmac_block_sizes });

    /* IPPCP Doesnt support HMAC SHA3 */
    if (!useipp) {
        BENCHMARK(BENCH_HMAC_SHA3_224)->ArgsProduct({ hmac_block_sizes });
        BENCHMARK(BENCH_HMAC_SHA3_256)->ArgsProduct({ hmac_block_sizes });
        BENCHMARK(BENCH_HMAC_SHA3_384)->ArgsProduct({ hmac_block_sizes });
        BENCHMARK(BENCH_HMAC_SHA3_512)->ArgsProduct({ hmac_block_sizes });
    }
    return 0;
}