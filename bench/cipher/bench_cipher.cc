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

#include "benchmarks_cipher.hh"
#include "cipher/cipher.hh"
#include "gbench_base.hh"
#include <memory>

#define MAX_BLOCK_SIZE 32768
#define MAX_KEY_SIZE   256

// Test blocksizes, append more if needed, size is in bytes
std::vector<Int64> blocksizes = { 16, 64, 256, 1024, 8192, 16384, 32768 };

int
Chacha20Cipher(benchmark::State& state,
               Uint64            blockSize,
               encrypt_t         enc,
               _alc_cipher_type  cipher_type,
               alc_cipher_mode_t alcpMode,
               size_t            keylen)
{
    // Dynamic allocation better for larger sizes
    std::vector<Uint8>         vec_in(blockSize, 0x01);
    std::vector<Uint8>         vec_out(blockSize, 0x21);
    Uint8                      key[keylen / 8];
    Uint8                      iv[16];
    alcp::testing::CipherBase* cb;

    alcp::testing::AlcpCipherBase acb = alcp::testing::AlcpCipherBase(
        cipher_type, alcpMode, iv, 12, key, keylen, nullptr, blockSize);

    cb = &acb;
#ifdef USE_IPP
    alcp::testing::IPPCipherBase icb = alcp::testing::IPPCipherBase(
        cipher_type, alcpMode, iv, 12, key, keylen, nullptr, blockSize);
    if (useipp) {
        cb = &icb;
    }
#endif
#ifdef USE_OSSL
    alcp::testing::OpenSSLCipherBase ocb = alcp::testing::OpenSSLCipherBase(
        cipher_type, alcpMode, iv, 12, key, keylen, nullptr, blockSize);
    if (useossl) {
        cb = &ocb;
    }
#endif
    alcp::testing::alcp_dc_ex_t data;
    data.m_in   = &(vec_in[0]);
    data.m_inl  = blockSize;
    data.m_out  = &(vec_out[0]);
    data.m_outl = blockSize;
    data.m_iv   = iv;
    data.m_ivl  = 16;
    for (auto _ : state) {
        if (enc) {
            if (!cb->encrypt(data)) {
                state.SkipWithError("BENCH_ENC_FAILURE");
            }

        } else {
            if (!cb->decrypt(data)) {
                state.SkipWithError("BENCH_DEC_FAILURE");
            }
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * blockSize, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = blockSize;

    return 0;
}

int
AesAeadCipher(benchmark::State& state,
              const Uint64      blockSize,
              encrypt_t         enc,
              _alc_cipher_type  cipher_type,
              alc_cipher_mode_t alcpMode,
              size_t            keylen)
{
    // Allocate with 512 bit alignment
    alignas(64) Uint8              vec_in_arr[MAX_BLOCK_SIZE]  = {};
    alignas(64) Uint8              vec_out_arr[MAX_BLOCK_SIZE] = {};
    alignas(16) Uint8              tagBuffer[16]               = {};
    alignas(16) Uint8              key[MAX_KEY_SIZE / 8]       = {};
    alignas(16) Uint8              iv[16]                      = {};
    alignas(16) Uint8              ad[16]                      = {};
    alignas(16) Uint8              tag[16]                     = {};
    alignas(16) Uint8              tkey[MAX_KEY_SIZE / 8]      = {};
    alcp::testing::CipherAeadBase* cb                          = nullptr;

    alcp::testing::AlcpCipherAeadBase acb = alcp::testing::AlcpCipherAeadBase(
        cipher_type, alcpMode, iv, 12, key, keylen, tkey, blockSize);

    cb = &acb;
#ifdef USE_IPP
    std::unique_ptr<alcp::testing::IPPCipherAeadBase> icb;
    if (useipp) {
        icb = std::make_unique<alcp::testing::IPPCipherAeadBase>(
            cipher_type,
            alcpMode,
            iv,
            12,
            reinterpret_cast<Uint8*>(key),
            keylen,
            reinterpret_cast<Uint8*>(tkey),
            blockSize);
        cb = icb.get();
    }
#endif
#ifdef USE_OSSL
    std::unique_ptr<alcp::testing::OpenSSLCipherAeadBase> ocb;
    if (useossl) {
        ocb = std::make_unique<alcp::testing::OpenSSLCipherAeadBase>(
            cipher_type,
            alcpMode,
            iv,
            12,
            reinterpret_cast<Uint8*>(key),
            keylen,
            reinterpret_cast<Uint8*>(tkey),
            blockSize);
        cb = ocb.get();
    }
#endif
    alcp::testing::alcp_dca_ex_t data;
    data.m_in      = vec_in_arr;
    data.m_inl     = blockSize;
    data.m_out     = vec_out_arr;
    data.m_outl    = blockSize;
    data.m_iv      = iv;
    data.m_ivl     = 12;
    data.m_ad      = ad;
    data.m_adl     = 16;
    data.m_tag     = tag;
    data.m_tagl    = 16;
    data.m_tagBuff = tagBuffer;
    data.m_tkey    = tkey;
    data.m_tkeyl   = 16;

    if (!enc
        && (alcpMode == ALC_AES_MODE_GCM || alcpMode == ALC_AES_MODE_CCM
            || alcpMode == ALC_AES_MODE_SIV)) {
        if (!cb->encrypt(data)) {
            state.SkipWithError("GCM / CCM : BENCH_ENC_FAILURE");
        }
        data.m_in  = vec_out_arr;
        data.m_out = vec_in_arr;
        // TAG is the IV
        // cb->init(key, keylen);
        if (alcpMode == ALC_AES_MODE_SIV)
            memcpy(iv, data.m_tag, 16);
    }

    for (auto _ : state) {
        // For OpenSSL GCM and SIV, Reset needs to be called again since tag
        // needs to be generated each time
        if ((useossl
             && (alcpMode == ALC_AES_MODE_GCM
                 || alcpMode == ALC_AES_MODE_SIV))) {
            if (!cb->init(key, keylen)) {
                state.SkipWithError("GCM: BENCH_RESET_FAILURE");
            }
        }
        if (enc) {
            if (!cb->encrypt(data)) {
                state.SkipWithError("BENCH_ENC_FAILURE");
            }
        } else {
            if (!cb->decrypt(data)) {
                state.SkipWithError("BENCH_DEC_FAILURE");
            }
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * blockSize, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = blockSize;

    return 0;
}

int
AesCipher(benchmark::State& state,
          Uint64            blockSize,
          encrypt_t         enc,
          _alc_cipher_type  cipher_type,
          alc_cipher_mode_t alcpMode,
          size_t            keylen)
{
    // Dynamic allocation better for larger sizes
    std::vector<Uint8>         vec_in(blockSize, 0x01);
    std::vector<Uint8>         vec_out(blockSize, 0x21);
    std::unique_ptr<Uint8[]>   tagBuffer = std::make_unique<Uint8[]>(16);
    Uint8                      key[keylen / 8];
    Uint8                      iv[16];
    Uint8                      ad[16] = {};
    Uint8                      tag[16];
    Uint8                      tkey[keylen / 8];
    alcp::testing::CipherBase* cb;

    alcp::testing::AlcpCipherBase acb = alcp::testing::AlcpCipherBase(
        cipher_type, alcpMode, iv, 12, key, keylen, tkey, blockSize);

    cb = &acb;
#ifdef USE_IPP
    alcp::testing::IPPCipherBase icb = alcp::testing::IPPCipherBase(
        cipher_type, alcpMode, iv, 12, key, keylen, tkey, blockSize);
    if (useipp) {
        cb = &icb;
    }
#endif
#ifdef USE_OSSL
    alcp::testing::OpenSSLCipherBase ocb = alcp::testing::OpenSSLCipherBase(
        cipher_type, alcpMode, iv, 12, key, keylen, tkey, blockSize);
    if (useossl) {
        cb = &ocb;
    }
#endif
    alcp::testing::alcp_dc_ex_t data;
    data.m_in    = &(vec_in[0]);
    data.m_inl   = blockSize;
    data.m_out   = &(vec_out[0]);
    data.m_outl  = blockSize;
    data.m_iv    = iv;
    data.m_ivl   = 16;
    data.m_tkey  = tkey;
    data.m_tkeyl = 16;
    for (auto _ : state) {
        if (enc) {
            if (!cb->encrypt(data)) {
                state.SkipWithError("BENCH_ENC_FAILURE");
            }
        } else {
            if (!cb->decrypt(data)) {
                state.SkipWithError("BENCH_DEC_FAILURE");
            }
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * blockSize, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = blockSize;

    return 0;
}

// 128 bit key size

/**
 * @brief Encrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_ENCRYPT_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CBC,
                                       128));
}

static void
BENCH_AES_ENCRYPT_CTR_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CTR,
                                       128));
}

static void
BENCH_AES_ENCRYPT_OFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_OFB,
                                       128));
}

static void
BENCH_AES_ENCRYPT_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CFB,
                                       128));
}

static void
BENCH_AES_ENCRYPT_GCM_MULTI_INIT_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           ENCRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_GCM,
                                           128));
}

static void
BENCH_AES_ENCRYPT_CCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           ENCRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_CCM,
                                           128));
}

static void
BENCH_AES_ENCRYPT_XTS_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_XTS,
                                       128));
}

static void
BENCH_AES_ENCRYPT_SIV_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           ENCRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_SIV,
                                           128));
}

/**
 * @brief Decrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_DECRYPT_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CBC,
                                       128));
}

static void
BENCH_AES_DECRYPT_CTR_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CTR,
                                       128));
}

static void
BENCH_AES_DECRYPT_OFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_OFB,
                                       128));
}

static void
BENCH_AES_DECRYPT_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CFB,
                                       128));
}

static void
BENCH_AES_DECRYPT_GCM_MULTI_INIT_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           DECRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_GCM,
                                           128));
}

static void
BENCH_AES_DECRYPT_XTS_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_XTS,
                                       128));
}

static void
BENCH_AES_DECRYPT_CCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           DECRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_CCM,
                                           128));
}

static void
BENCH_AES_DECRYPT_SIV_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           DECRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_SIV,
                                           128));
}
// END 128 bit key size

// 192 bit key size

/**
 * @brief Encrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_ENCRYPT_CBC_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CBC,
                                       192));
}

static void
BENCH_AES_ENCRYPT_CTR_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CTR,
                                       192));
}

static void
BENCH_AES_ENCRYPT_OFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_OFB,
                                       192));
}

static void
BENCH_AES_ENCRYPT_CFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CFB,
                                       192));
}

static void
BENCH_AES_ENCRYPT_GCM_MULTI_INIT_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           ENCRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_GCM,
                                           192));
}

static void
BENCH_AES_ENCRYPT_CCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           ENCRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_CCM,
                                           192));
}

static void
BENCH_AES_ENCRYPT_SIV_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           ENCRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_SIV,
                                           192));
}

/**
 * @brief Decrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_DECRYPT_CBC_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CBC,
                                       192));
}

static void
BENCH_AES_DECRYPT_CTR_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CTR,
                                       192));
}

static void
BENCH_AES_DECRYPT_OFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_OFB,
                                       192));
}

static void
BENCH_AES_DECRYPT_CFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CFB,
                                       192));
}

static void
BENCH_AES_DECRYPT_GCM_MULTI_INIT_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           DECRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_GCM,
                                           192));
}

static void
BENCH_AES_DECRYPT_CCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           DECRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_CCM,
                                           192));
}

static void
BENCH_AES_DECRYPT_SIV_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           DECRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_SIV,
                                           192));
}

// END 192 bit keysize

// 256 bit key size

/**
 * @brief Encrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_ENCRYPT_CBC_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CBC,
                                       256));
}

static void
BENCH_AES_ENCRYPT_CTR_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CTR,
                                       256));
}

static void
BENCH_AES_ENCRYPT_OFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_OFB,
                                       256));
}

static void
BENCH_AES_ENCRYPT_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CFB,
                                       256));
}

static void
BENCH_AES_ENCRYPT_GCM_MULTI_INIT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           ENCRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_GCM,
                                           256));
}

static void
BENCH_AES_ENCRYPT_CCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           ENCRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_CCM,
                                           256));
}

static void
BENCH_AES_ENCRYPT_XTS_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       ENCRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_XTS,
                                       256));
}

static void
BENCH_AES_ENCRYPT_SIV_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           ENCRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_SIV,
                                           256));
}

/**
 * @brief Decrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_DECRYPT_CBC_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CBC,
                                       256));
}

static void
BENCH_AES_DECRYPT_CTR_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CTR,
                                       256));
}

static void
BENCH_AES_DECRYPT_OFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_OFB,
                                       256));
}

static void
BENCH_AES_DECRYPT_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_CFB,
                                       256));
}

static void
BENCH_AES_DECRYPT_GCM_MULTI_INIT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           DECRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_GCM,
                                           256));
}

static void
BENCH_AES_DECRYPT_XTS_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesCipher(state,
                                       state.range(0),
                                       DECRYPT,
                                       ALC_CIPHER_TYPE_AES,
                                       ALC_AES_MODE_XTS,
                                       256));
}

static void
BENCH_AES_DECRYPT_CCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           DECRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_CCM,
                                           256));
}

static void
BENCH_AES_DECRYPT_SIV_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(AesAeadCipher(state,
                                           state.range(0),
                                           ENCRYPT,
                                           ALC_CIPHER_TYPE_AES,
                                           ALC_AES_MODE_SIV,
                                           256));
}
// END 256 bit keysize

/* non AES ciphers */
static void
BENCH_CHACHA20_ENCRYPT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(Chacha20Cipher(state,
                                            state.range(0),
                                            ENCRYPT,
                                            ALC_CIPHER_TYPE_CHACHA20,
                                            ALC_AES_MODE_NONE,
                                            256));
}
static void
BENCH_CHACHA20_DECRYPT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(Chacha20Cipher(state,
                                            state.range(0),
                                            DECRYPT,
                                            ALC_CIPHER_TYPE_CHACHA20,
                                            ALC_AES_MODE_NONE,
                                            256));
}

int
AddBenchmarks()
{
    /* IPPCP doesnt have Chacha20 stream cipher variant yet */
    if (!useipp) {
        BENCHMARK(BENCH_CHACHA20_ENCRYPT_256)->ArgsProduct({ blocksizes });
        BENCHMARK(BENCH_CHACHA20_DECRYPT_256)->ArgsProduct({ blocksizes });
    }
    BENCHMARK(BENCH_AES_ENCRYPT_CBC_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CTR_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_OFB_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CFB_128)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_DECRYPT_CBC_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CTR_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_OFB_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CFB_128)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_ENCRYPT_CBC_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CTR_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_OFB_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CFB_192)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_DECRYPT_CBC_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CTR_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_OFB_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CFB_192)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_ENCRYPT_CBC_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CTR_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_OFB_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CFB_256)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_DECRYPT_CBC_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CTR_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_OFB_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CFB_256)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_ENCRYPT_XTS_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_XTS_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_XTS_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_XTS_256)->ArgsProduct({ blocksizes });

    /* Benchmark of AEAD Ciphers */
    // GCM Benchmarks
    BENCHMARK(BENCH_AES_ENCRYPT_GCM_MULTI_INIT_128)
        ->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_GCM_MULTI_INIT_128)
        ->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_GCM_MULTI_INIT_192)
        ->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_GCM_MULTI_INIT_192)
        ->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_GCM_MULTI_INIT_256)
        ->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_GCM_MULTI_INIT_256)
        ->ArgsProduct({ blocksizes });
    // SIV Benchmarks
    BENCHMARK(BENCH_AES_ENCRYPT_SIV_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_SIV_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_SIV_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_SIV_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_SIV_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_SIV_256)->ArgsProduct({ blocksizes });
    // CCM Benchmarks
    BENCHMARK(BENCH_AES_ENCRYPT_CCM_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CCM_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CCM_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CCM_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CCM_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CCM_192)->ArgsProduct({ blocksizes });
    return 0;
}

int
main(int argc, char** argv)
{
    parseArgs(&argc, argv);
#ifndef USE_IPP
    if (useipp) {
        alcp::testing::utils::printErrors(
            "Error IPP not found defaulting to ALCP");
    }
#endif
#ifndef USE_OSSL
    if (useossl) {
        alcp::testing::utils::printErrors(
            "Error OpenSSL not found defaulting to ALCP");
    }
#endif
    AddBenchmarks();
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}