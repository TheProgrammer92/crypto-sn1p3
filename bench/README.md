# ALCP Micro Benchmarks 

### Building ALCP with Testing framework

1. `git clone [alcp-crypto git url here]`
2. `cd alcp-crypto`
3. `cmake -B build -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_BENCH=ON  -DCMAKE_BUILD_TYPE=Release`
4. `cmake --build build`

> <span style="color:red">__Note:__</span> To include IPP, please define `-DENABLE_TESTS_IPP_API=ON -DIPP_INSTALL_DIR=/path/to/ipp_prefix` in step 3. <br>
> <span style="color:red"> __Note:__</span> To include OpenSSL, please define `-DENABLE_TESTS_OPENSSL_API=ON -DOPENSSL_INSTALL_DIR=/path/to/openssl_prefix` in step 3.


<a name = "Executing_Benches"></a>

### Executing Benches

After building ALCP, there should be binary files of each cryptographic algorithm with respective name in base_path = ./bench/{Respective cryptographic algorithm}

To run tests with verbose mode (prints also success)

1. `$cd aocl-crypto/build`
2. `$./bench/cipher/bench_cipher`
3. `$./bench/digest/bench_digest`

#### Selecting benchmarks

Example for selecting only "CBC" benchmarks

​	`$./bench/cipher/bench_cipher --benchmark_filter="CBC"`

Example for selecting only "SHA256" benchmarks

​	`$./bench/digest/bench_digest --benchmark_filter="SHA2_256"`

Always you can use `--help` to know all the command line arguments which can be given to the executable.

#### Supported Benchmarks

##### Cipher

1. AES_CBC             (128,192,256)
2. AES_CTR             (128,192,256)
3. AES_CFB             (128,192,256)
4. AES_OFB             (128,192,256)
5. AES_GCM_MULTI_INIT  (128,192,256)
6. AES_XTS_MULTI_INIT  (128,256)
7. AES_CCM             (128,192,256)
8. AES_SIV             (128,192,256)
9. CHACHA20            (256)

##### Cipher_experimental

1. AES_GCM (128,192,256)
2. AES_XTS (128,256)

##### Digest

1.  SHA2_224
2.  SHA2_256
3.  SHA2_384
4.  SHA2_512
5.  SHA2_512_224
6.  SHA2_512_256
7.  SHA3_224
8.  SHA3_256
9.  SHA3_384
10. SHA3_512
11. SHAKE_128
12. SHAKE_256

##### MAC

1.  CMAC_AES_128
2.  CMAC_AES_192
3.  CMAC_AES_256
4.  HMAC_SHA2_224
5.  HMAC_SHA2_256
6.  HMAC_SHA2_384
7.  HMAC_SHA2_512
8.  HMAC_SHA3_224
9.  HMAC_SHA3_256
10. HMAC_SHA3_384
11. HMAC_SHA3_512
12. POLY1305

##### EC

1. ECDH_x25519_GenPubKey
2. ECDH_x25519_GenSecretKey

##### RSA

1. RSA_EncryptPubKey
2. RSA_DecryptPvtKey

#### Using IPP

For using IPP just specify `-i` command line argument.

#### Using OpenSSL

For using OpenSSL just specify `-o` command line argument.

