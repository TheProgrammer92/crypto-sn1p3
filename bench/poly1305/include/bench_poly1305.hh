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
#include "poly1305/alc_poly1305.hh"
#include "poly1305/poly1305.hh"

#ifdef USE_IPP
#include "poly1305/ipp_poly1305.hh"
#endif

#ifdef USE_OSSL
#include "poly1305/openssl_poly1305.hh"
#endif

#include "gbench_base.hh"
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include <string.h>

using namespace alcp::testing;

/* Valid block sizes for performance comparison */
std::vector<Int64> poly1305_blocksizes = {
    16, 64, 256, 1024, 8192, 16384, 32768
};

void inline Poly1305_Bench(benchmark::State& state,
                           alc_mac_info_t    info,
                           Uint64            block_size,
                           Uint64            KeySize)
{

    /* MAX len of poly1305 would be 128 bits */
    const int          macSize = 16;
    std::vector<Uint8> poly1305_mac(macSize, 0);
    std::vector<Uint8> msg(block_size);
    std::vector<Uint8> Key(KeySize);

    /* Initialize info params based on poly1305 type */
    info.mi_type = ALC_MAC_POLY1305;

    AlcpPoly1305Base     apb(info);
    Poly1305Base*        pb = &apb;
    alcp_poly1305_data_t data{};

#ifdef USE_OSSL
    OpenSSLPoly1305Base opb(info);
    if (useossl) {
        pb = &opb;
    }
#endif

    data.m_msg     = &(msg[0]);
    data.m_msg_len = msg.size();
    data.m_mac     = &(poly1305_mac[0]);
    data.m_mac_len = poly1305_mac.size();
    data.m_key     = &(Key[0]);
    data.m_key_len = Key.size();

    if (!pb->init(info, Key)) {
        state.SkipWithError("Error in poly1305 init function");
    }
    for (auto _ : state) {
        if (!pb->mac(data)) {
            state.SkipWithError("Error in poly1305 bench function");
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

/* add all your new benchmarks here */
/* POLY1305 benchmarks */
static void
BENCH_POLY1305(benchmark::State& state)
{
    alc_mac_info_t info;
    Poly1305_Bench(state, info, state.range(0), 32);
}

/* add benchmarks */
int
AddBenchmarks_Poly1305()
{
    /* ippcp doesnt have poly1305 mac implementations yet */
    if (!useipp)
        BENCHMARK(BENCH_POLY1305)->ArgsProduct({ poly1305_blocksizes });
    return 0;
}