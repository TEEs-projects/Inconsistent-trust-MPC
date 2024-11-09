cmake_minimum_required(VERSION 3.11)

if (NDEBUG)
    add_compile_definitions(NDEBUG)
endif()

if (PROT_MPC_TEST AND SECAGG_TEST)
    message(FATAL_ERROR "Confilct test options")
endif()

if (PROT_MPC_TEST)
    add_compile_definitions(PROT_MPC_TEST)
endif()

if (SECAGG_TEST)
    add_compile_definitions(SECAGG_TEST)
endif()

set(CMAKE_C_COMPILER clang-11)
set(CMAKE_CXX_COMPILER clang++-11)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CONFIGURATION_TYPES Release)

project("Remote Host-side Enclave Verification Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)
find_package(MbedTLS REQUIRED)
find_package(OpenSSL REQUIRED)

add_subdirectory(amd_server)
add_subdirectory(common)
add_subdirectory(prot_mpc_client)
add_subdirectory(sgx_server)
