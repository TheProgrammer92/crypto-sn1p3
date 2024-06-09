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
#include "digest/alc_digest.hh"
#include "digest/digest.hh"
#include "rng_base.hh"

#ifdef USE_IPP
#include "digest/ipp_digest.hh"
#endif

#ifdef USE_OSSL
#include "digest/openssl_digest.hh"
#endif

#include "gbench_base.hh"
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include <string.h>

using namespace alcp::testing;

std::vector<Int64> digest_block_sizes = {
    16, 64, 256, 1024, 8192, 16384, 32768
};

void inline Digest_Bench(benchmark::State& state,
                         alc_digest_info_t info,
                         Uint64            block_size)
{
    RngBase            rb;
    std::vector<Uint8> msg(block_size);
    AlcpDigestBase     adb(info);
    DigestBase*        db = &adb;
    alcp_digest_data_t data;
#ifdef USE_IPP
    IPPDigestBase idb(info);
    if (useipp) {
        db = &idb;
    }
#endif

#ifdef USE_OSSL
    OpenSSLDigestBase odb(info);
    if (useossl) {
        db = &odb;
    }
#endif

    if (info.dt_mode.dm_sha3 == ALC_SHAKE_128
        || info.dt_mode.dm_sha3 == ALC_SHAKE_256) {

        if (!db->init(info, info.dt_custom_len)) {
            state.SkipWithError("Error: Digest base init failed");
        }
        /* override digest len for shake cases */
        data.m_digest_len = info.dt_custom_len;
    } else {
        data.m_digest_len = info.dt_len / 8;
    }

    Uint8 digest[data.m_digest_len];
    memset(digest, 0, data.m_digest_len * sizeof(Uint8));
    /* generate random bytes */
    msg = rb.genRandomBytes(block_size);

    data.m_msg     = &(msg[0]);
    data.m_digest  = digest;
    data.m_msg_len = block_size;

    for (auto _ : state) {
        if (!db->digest_function(data)) {
            state.SkipWithError("Error in running digest benchmark:");
        }
        db->reset();
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

/* add all your new benchmarks here */
/* SHA2 benchmarks */
static void
BENCH_SHA2_224(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_224;
    info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.dt_len          = ALC_DIGEST_LEN_224;
    Digest_Bench(state, info, state.range(0));
}
static void
BENCH_SHA2_256(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_256;
    info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.dt_len          = ALC_DIGEST_LEN_256;
    Digest_Bench(state, info, state.range(0));
}
static void
BENCH_SHA2_384(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_384;
    info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.dt_len          = ALC_DIGEST_LEN_384;
    Digest_Bench(state, info, state.range(0));
}
static void
BENCH_SHA2_512(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_512;
    info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.dt_len          = ALC_DIGEST_LEN_512;
    Digest_Bench(state, info, state.range(0));
}
/* SHA 512 224 and 256 len*/
static void
BENCH_SHA2_512_224(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_512;
    info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.dt_len          = ALC_DIGEST_LEN_224;
    Digest_Bench(state, info, state.range(0));
}
static void
BENCH_SHA2_512_256(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_512;
    info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.dt_len          = ALC_DIGEST_LEN_256;
    Digest_Bench(state, info, state.range(0));
}

/* SHA3 benchmarks */
static void
BENCH_SHA3_224(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha3 = ALC_SHA3_224;
    info.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.dt_len          = ALC_DIGEST_LEN_224;
    Digest_Bench(state, info, state.range(0));
}
static void
BENCH_SHA3_256(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha3 = ALC_SHA3_256;
    info.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.dt_len          = ALC_DIGEST_LEN_256;
    Digest_Bench(state, info, state.range(0));
}
static void
BENCH_SHA3_384(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha3 = ALC_SHA3_384;
    info.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.dt_len          = ALC_DIGEST_LEN_384;
    Digest_Bench(state, info, state.range(0));
}
static void
BENCH_SHA3_512(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha3 = ALC_SHA3_512;
    info.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.dt_len          = ALC_DIGEST_LEN_512;
    Digest_Bench(state, info, state.range(0));
}

/* SHAKE */
static void
BENCH_SHAKE_128(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha3 = ALC_SHAKE_128;
    info.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.dt_len          = ALC_DIGEST_LEN_CUSTOM;
    info.dt_custom_len   = 256;
    Digest_Bench(state, info, state.range(0));
}
static void
BENCH_SHAKE_256(benchmark::State& state)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha3 = ALC_SHAKE_256;
    info.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.dt_len          = ALC_DIGEST_LEN_CUSTOM;
    info.dt_custom_len   = 256;
    Digest_Bench(state, info, state.range(0));
}

/* add benchmarks */
int
AddBenchmarks()
{
    BENCHMARK(BENCH_SHA2_224)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_256)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_384)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_512)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_512_224)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_512_256)->ArgsProduct({ digest_block_sizes });

    /* SHA3 is not supported for IPP */
    if (!useipp) {
        BENCHMARK(BENCH_SHA3_224)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHA3_256)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHA3_384)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHA3_512)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHAKE_128)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHAKE_256)->ArgsProduct({ digest_block_sizes });
    }
    return 0;
}