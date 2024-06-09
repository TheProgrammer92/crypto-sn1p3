 # Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 # 2. Redistributions in binary form must reproduce the above copyright notice,
 #    this list of conditions and the following disclaimer in the documentation
 #    and/or other materials provided with the distribution.
 # 3. Neither the name of the copyright holder nor the names of its contributors
 #    may be used to endorse or promote products derived from this software
 # without specific prior written permission.
 #
 # THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 # AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 # IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 # ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 # LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 # CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 
 INCLUDE(FetchContent)
 FetchContent_Declare(gtest
     GIT_REPOSITORY https://github.com/google/googletest.git
     GIT_TAG release-1.12.1)
 FetchContent_MakeAvailable(gtest)
 FetchContent_Declare(benchmark
     GIT_REPOSITORY https://github.com/google/benchmark.git
     GIT_TAG v1.6.1)
 FetchContent_MakeAvailable(benchmark)


FILE(GLOB COMMON_SRCS ${CMAKE_SOURCE_DIR}/tests/common/base/*.cc)
FILE(GLOB ALC_CIPHER_FWK_SRCS ${CMAKE_SOURCE_DIR}/tests/cipher_experimental/framework/alc_*.cc)
SET(LIBS ${LIBS} benchmark alcp)

SET(EXTRA_SOURCES "")
SET(EXTRA_INCLUDES "")

IF(ENABLE_TESTS_OPENSSL_API)
    FILE(GLOB OPENSSL_CIPHER_FWK_SRCS ${CMAKE_SOURCE_DIR}/tests/cipher_experimental/framework/openssl_*.cc)
    ADD_COMPILE_OPTIONS("-DUSE_OSSL")
    IF(OPENSSL_INSTALL_DIR)
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR set, overriding fetch path")
    ELSE(OPENSSL_INSTALL_DIR)
        SET(OPENSSL_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR not set, defaulting to external")
    ENDIF(OPENSSL_INSTALL_DIR)
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} 
                      ${OPENSSL_CIPHER_FWK_SRCS})
	IF(UNIX)
		IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
			SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
		ELSEIF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
			SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
		ELSE()
			SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
		ENDIF()
	ENDIF(UNIX)
	IF(WIN32)
		IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
			INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/include)
			INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/bin)
			SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
		ENDIF()
	ENDIF(WIN32)
    SET(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${OPENSSL_INSTALL_DIR}/include)
ENDIF(ENABLE_TESTS_OPENSSL_API)

IF(ENABLE_TESTS_IPP_API)
    FILE(GLOB IPP_CIPHER_FWK_SRCS ${CMAKE_SOURCE_DIR}/tests/cipher_experimental/framework/ipp_*.cc)
    ADD_COMPILE_OPTIONS("-DUSE_IPP")
    IF(IPP_INSTALL_DIR)
        MESSAGE(STATUS "IPP_INSTALL_DIR set, overriding fetch path")
    ELSE(IPP_INSTALL_DIR)
        SET(IPP_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "IPP_INSTALL_DIR not set, defaulting to external")
    ENDIF(IPP_INSTALL_DIR)
    # If there is IPP, add IPP source and add IPP liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} 
                      ${IPP_CIPHER_FWK_SRCS})
	IF(UNIX)
        IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
        ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
        ENDIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
	ENDIF(UNIX)
	IF(WIN32)
        IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
        ELSEIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
        ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/ippcp.lib)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/ippcp.lib)
        ENDIF()
	ENDIF(WIN32)
    SET(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${IPP_INSTALL_DIR}/include)
ENDIF(ENABLE_TESTS_IPP_API)

# FIXME: Move into a function
ADD_EXECUTABLE(bench_cipher_experimental bench_cipher_experimental.cc ${COMMON_SRCS} ${ALC_CIPHER_FWK_SRCS} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(bench_cipher_experimental PRIVATE
"${CMAKE_SOURCE_DIR}/include"
"${CMAKE_SOURCE_DIR}/lib/include"
"${CMAKE_SOURCE_DIR}/tests/include"
"${CMAKE_SOURCE_DIR}/tests/common/include"
${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(bench_cipher_experimental PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(bench_cipher_experimental ${LIBS})