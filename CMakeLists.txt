cmake_minimum_required(VERSION 3.20)
project(GxCrypt CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(GXCRYPT_SOURCES
    "src/excrypt_aes.c"
    "src/excrypt_bn_key.cpp"
    "src/excrypt_bn_mod.cpp"
    "src/excrypt_bn_pkcs1.cpp"
    "src/excrypt_bn_rsa.cpp"
    "src/excrypt_bn_sig.c"
    "src/excrypt_bn.c"
    "src/excrypt_des.c"
    "src/excrypt_ecc.c"
    "src/excrypt_md5.c"
    "src/excrypt_mem.cpp"
    "src/excrypt_parve.c"
    "src/excrypt_rc4.c"
    "src/excrypt_rotsum.c"
    "src/excrypt_sha.c"
    "src/excrypt_sha2.c"
    "src/exkeys.cpp"
    "src/rijndael.c"
)

set(GXCRYPT_HEADERS
    "include/excrypt_aes.h"
    "include/excrypt_bn.h"
    "include/excrypt_des_data.h"
    "include/excrypt_des.h"
    "include/excrypt_ecc.h"
    "include/excrypt_md5.h"
    "include/excrypt_mem.h"
    "include/excrypt_parve.h"
    "include/excrypt_rc4.h"
    "include/excrypt_rotsum.h"
    "include/excrypt_sha.h"
    "include/excrypt_sha2.h"
    "include/excrypt.h"
    "include/exkeys.h"
    "include/fp61.hpp"
    "include/rijndael.h"
)

add_library(GxCrypt STATIC
    ${GXCRYPT_SOURCES}
    ${GXCRYPT_HEADERS}
)

target_include_directories(GxCrypt
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(WIN32)
    target_link_libraries(GxCrypt PRIVATE bcrypt)
else()
    target_compile_options(GxCrypt PRIVATE -maes -msse4.1)
endif()