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

#include <benchmark/benchmark.h>
#include <memory>

#include "cipher_experimental/alc_cipher_gcm.hh"
#include "cipher_experimental/alc_cipher_xts.hh"
#include "cipher_experimental/factory.hh"
#include "common/experimental/gtest_essentials.hh"
#include "utils.hh"

namespace alcp::benchmarking::cipher {

using namespace alcp::testing::cipher;
using alcp::testing::cipher::ITestCipher;

std::vector<Int64> blocksizes = { 16, 64, 256, 1024, 8192, 16384, 32768 };

template<bool encryptor>
int
BenchCipherExperimental(benchmark::State&            state,
                        const Uint64                 cBlockSize,
                        std::unique_ptr<ITestCipher> iTestCipher,
                        Uint32                       keylen,
                        alc_test_init_data_t&        dataInit,
                        alc_test_update_data_t&      dataUpdate,
                        alc_test_finalize_data_t&    dataFinalize)
{
    if (iTestCipher == nullptr) {
        state.SkipWithError(
            "MicroBench: Library is unavailable at compile time");
        return -1;
    }

    // Real benchmark begins here
    bool no_err = true;
    no_err &= iTestCipher->init(&dataInit);
    if (no_err == false) {
        state.SkipWithError("MicroBench: Initialization failed!");
    }

    // Benchmark hot path
    for (auto _ : state) {
        no_err &= iTestCipher->update(&dataUpdate);
        if (no_err == false) {
            state.SkipWithError("MicroBench: Update failed!");
        }
    }

    // Cleanup
    no_err &= iTestCipher->finalize(&dataFinalize);
    if (no_err == false) {
        state.SkipWithError("MicroBench: Finalize failed!");
    }

    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * cBlockSize, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = cBlockSize;
    return 0;
}

using namespace alcp::testing::cipher::gcm;

template<bool encryptor>
int
BenchGcmCipherExperimental(benchmark::State&            state,
                           const Uint64                 cBlockSize,
                           std::unique_ptr<ITestCipher> iTestCipher,
                           Uint32                       keylen)
{
    alignas(64) Uint8 input_text[cBlockSize];
    alignas(64) Uint8 output_text[cBlockSize];
    alignas(32) Uint8 key[keylen / 8];
    alignas(16) Uint8 iv[16];
    alignas(16) Uint8 ad[16];
    alignas(16) Uint8 tag[16];
    // FIXME: Tkey might be needed for XTS

    alc_test_gcm_init_data_t dataInit;
    dataInit.m_iv      = iv;
    dataInit.m_iv_len  = 12;
    dataInit.m_aad     = ad;
    dataInit.m_aad_len = 16;
    dataInit.m_key     = key;
    dataInit.m_key_len = keylen / 8;

    alc_test_gcm_update_data_t dataUpdate;
    dataUpdate.m_iv         = iv;
    dataUpdate.m_iv_len     = 12;
    dataUpdate.m_output     = output_text;
    dataUpdate.m_output_len = cBlockSize;
    dataUpdate.m_input      = input_text;
    dataUpdate.m_input_len  = cBlockSize;

    alc_test_gcm_finalize_data_t dataFinalize;
    dataFinalize.m_tag_expected = tag;
    dataFinalize.m_tag_len      = 16;
    dataFinalize.m_tag          = tag;
    dataFinalize.verified       = false;

    if constexpr (encryptor == false) { // Decrypt
        // Create a vaid data for decryption (mainly tag and ct)
        std::unique_ptr<ITestCipher> iTestCipher =
            std::make_unique<AlcpGcmCipher<true>>();
        bool no_err = true;
        no_err &= iTestCipher->init(&dataInit);
        if (no_err == false) {
            state.SkipWithError("MicroBench: Initialization failed for decrypt "
                                "ct,tag generation using encrypt");
            return -1;
        }
        no_err &= iTestCipher->update(&dataUpdate);
        if (no_err == false) {
            state.SkipWithError("MicroBench: Update failed for decrypt "
                                "ct,tag generation using encrypt");
            return -1;
        }
        // After encrypting, to decrypt output becomes input
        dataUpdate.m_input  = output_text;
        dataUpdate.m_output = input_text;
        no_err &= iTestCipher->finalize(&dataFinalize);
        if (no_err == false) {
            state.SkipWithError("MicroBench: Finalize failed for decrypt "
                                "ct,tag generation using encrypt");
            return -1;
        }
    }

    return BenchCipherExperimental<encryptor>(state,
                                              cBlockSize,
                                              std::move(iTestCipher),
                                              keylen,
                                              dataInit,
                                              dataUpdate,
                                              dataFinalize);
}

using namespace alcp::testing::cipher::xts;

template<bool encryptor>
int
BenchXtsCipherExperimental(benchmark::State&            state,
                           const Uint64                 cBlockSize,
                           std::unique_ptr<ITestCipher> iTestCipher,
                           Uint32                       keylen)
{
    alignas(64) Uint8 input_text[cBlockSize];
    alignas(64) Uint8 output_text[cBlockSize];
    alignas(32) Uint8 key[keylen / 8 * 2];
    alignas(16) Uint8 iv[16];
    alignas(16) Uint8 ad[16];
    alignas(16) Uint8 tag[16];
    int               blocks = cBlockSize / 16;

    for (int i = 0; i < keylen / 8 * 2; i++) {
        key[i] = i;
    }

    // FIXME: Tkey might be needed for XTS

    alc_test_xts_init_data_t dataInit;
    dataInit.m_iv      = iv;
    dataInit.m_iv_len  = 12;
    dataInit.m_key     = key;
    dataInit.m_key_len = keylen / 8;

    alc_test_xts_update_data_t dataUpdate;
    dataUpdate.m_iv              = iv;
    dataUpdate.m_iv_len          = 12;
    dataUpdate.m_output          = output_text;
    dataUpdate.m_output_len      = cBlockSize;
    dataUpdate.m_input           = input_text;
    dataUpdate.m_total_input_len = 100000000;
    dataUpdate.m_input_len       = cBlockSize;
    dataUpdate.m_aes_block_id    = 0;

    alc_test_xts_finalize_data_t dataFinalize;
    dataFinalize.m_out    = dataUpdate.m_output;
    dataFinalize.m_pt_len = dataUpdate.m_input_len;

    if (iTestCipher == nullptr) {
        state.SkipWithError(
            "MicroBench: Library is unavailable at compile time");
        return -1;
    }

    // Real benchmark begins here
    bool no_err = true;
    no_err &= iTestCipher->init(&dataInit);
    if (no_err == false) {
        state.SkipWithError("MicroBench: Initialization failed!");
    }

    // Benchmark hot path
    for (auto _ : state) {
        no_err &= iTestCipher->update(&dataUpdate);
        if (no_err == false) {
            state.SkipWithError("MicroBench: Update failed!");
        }
        dataUpdate.m_aes_block_id += blocks;
    }

    // Cleanup
    no_err &= iTestCipher->finalize(&dataFinalize);
    if (no_err == false) {
        state.SkipWithError("MicroBench: Finalize failed!");
    }

    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * cBlockSize, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = cBlockSize;
    return 0;
}

} // namespace alcp::benchmarking::cipher

using alcp::testing::cipher::LibrarySelect;

using alcp::benchmarking::cipher::BenchGcmCipherExperimental;
using alcp::testing::cipher::gcm::GcmCipherFactory;

static void
BENCH_AES_ENCRYPT_GCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchGcmCipherExperimental<true>(
        state,
        state.range(0),
        std::move(
            GcmCipherFactory<true>(static_cast<LibrarySelect>(state.range(1)))),
        128));
}

static void
BENCH_AES_ENCRYPT_GCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchGcmCipherExperimental<true>(
        state,
        state.range(0),
        std::move(
            GcmCipherFactory<true>(static_cast<LibrarySelect>(state.range(1)))),
        192));
}

static void
BENCH_AES_ENCRYPT_GCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchGcmCipherExperimental<true>(
        state,
        state.range(0),
        std::move(
            GcmCipherFactory<true>(static_cast<LibrarySelect>(state.range(1)))),
        256));
}

static void
BENCH_AES_DECRYPT_GCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchGcmCipherExperimental<false>(
        state,
        state.range(0),
        std::move(
            GcmCipherFactory<true>(static_cast<LibrarySelect>(state.range(1)))),
        128));
}

static void
BENCH_AES_DECRYPT_GCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchGcmCipherExperimental<false>(
        state,
        state.range(0),
        std::move(
            GcmCipherFactory<true>(static_cast<LibrarySelect>(state.range(1)))),
        192));
}

static void
BENCH_AES_DECRYPT_GCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchGcmCipherExperimental<false>(
        state,
        state.range(0),
        std::move(
            GcmCipherFactory<true>(static_cast<LibrarySelect>(state.range(1)))),
        256));
}

using alcp::benchmarking::cipher::BenchXtsCipherExperimental;
using alcp::testing::cipher::xts::XtsCipherFactory;

static void
BENCH_AES_ENCRYPT_XTS_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchXtsCipherExperimental<true>(
        state,
        state.range(0),
        std::move(
            XtsCipherFactory<true>(static_cast<LibrarySelect>(state.range(1)))),
        128));
}

static void
BENCH_AES_ENCRYPT_XTS_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchXtsCipherExperimental<true>(
        state,
        state.range(0),
        std::move(
            XtsCipherFactory<true>(static_cast<LibrarySelect>(state.range(1)))),
        256));
}

static void
BENCH_AES_DECRYPT_XTS_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchXtsCipherExperimental<false>(
        state,
        state.range(0),
        std::move(XtsCipherFactory<false>(
            static_cast<LibrarySelect>(state.range(1)))),
        128));
}

static void
BENCH_AES_DECRYPT_XTS_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchXtsCipherExperimental<false>(
        state,
        state.range(0),
        std::move(XtsCipherFactory<false>(
            static_cast<LibrarySelect>(state.range(1)))),
        256));
}

using alcp::testing::cipher::CipherFactory;
using alcp::testing::cipher::LibrarySelect;
using alcp::testing::utils::ArgsMap;
using alcp::testing::utils::ParamType;
using alcp::testing::utils::parseArgs;
using alcp::testing::utils::printErrors;
int
main(int argc, char** argv)
{
    std::vector<Int64> testlibs = {};

    ::benchmark::Initialize(&argc, argv);

    ArgsMap argsMap = parseArgs(argc, argv);

    assert(argsMap["USE_OSSL"].paramType == ParamType::TYPE_BOOL);
    assert(argsMap["USE_IPP"].paramType == ParamType::TYPE_BOOL);
    assert(argsMap["USE_ALCP"].paramType == ParamType::TYPE_BOOL);

    if (std::get<bool>(argsMap["USE_OSSL"].value) == false
        && std::get<bool>(argsMap["USE_IPP"].value) == false
        && std::get<bool>(argsMap["USE_ALCP"].value) == false) {
#ifdef USE_IPP
        testlibs.insert(testlibs.begin(),
                        static_cast<Int64>(LibrarySelect::IPP));
#endif
#ifdef USE_OSSL
        testlibs.insert(testlibs.begin(),
                        static_cast<Int64>(LibrarySelect::OPENSSL));
#endif
        testlibs.insert(testlibs.begin(),
                        static_cast<Int64>(LibrarySelect::ALCP));
    } else {
        if (std::get<bool>(argsMap["USE_ALCP"].value) == true) {
            testlibs.insert(testlibs.begin(),
                            static_cast<Int64>(LibrarySelect::ALCP));
        }
        if (std::get<bool>(argsMap["USE_OSSL"].value) == true) {
#ifdef USE_OSSL
            testlibs.insert(testlibs.begin(),
                            static_cast<Int64>(LibrarySelect::OPENSSL));
#else
            printErrors("OpenSSL unavailable at compile time!");
            return -1;
#endif
        }
        if (std::get<bool>(argsMap["USE_IPP"].value) == true) {
#ifdef USE_IPP
            testlibs.insert(testlibs.begin(),
                            static_cast<Int64>(LibrarySelect::IPP));
#else
            printErrors("IPP unavailable at compile time!");
            return -1;
#endif
        }
    }

    // GCM
    BENCHMARK(BENCH_AES_ENCRYPT_GCM_128)
        ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes, testlibs });

    BENCHMARK(BENCH_AES_ENCRYPT_GCM_192)
        ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes, testlibs });

    BENCHMARK(BENCH_AES_ENCRYPT_GCM_256)
        ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes, testlibs });

    BENCHMARK(BENCH_AES_DECRYPT_GCM_128)
        ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes, testlibs });

    BENCHMARK(BENCH_AES_DECRYPT_GCM_192)
        ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes, testlibs });

    BENCHMARK(BENCH_AES_DECRYPT_GCM_256)
        ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes, testlibs });

    // XTS
    BENCHMARK(BENCH_AES_ENCRYPT_XTS_128)
        ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes, testlibs });

    BENCHMARK(BENCH_AES_ENCRYPT_XTS_256)
        ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes, testlibs });

    BENCHMARK(BENCH_AES_DECRYPT_XTS_128)
        ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes, testlibs });

    BENCHMARK(BENCH_AES_DECRYPT_XTS_256)
        ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes, testlibs });

    // if (::benchmark::ReportUnrecognizedArguments(argc, argv))
    //     return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}