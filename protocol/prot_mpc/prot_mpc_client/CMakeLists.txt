cmake_minimum_required(VERSION 3.11)

set(CMAKE_CXX_COMPILER /usr/bin/clang++-11)

set(CMAKE_CXX_STANDARD 20)

project("Protocol inconsistent trust MPC")

include_directories(
    ${CMAKE_SOURCE_DIR}/common/
    ${CMAKE_SOURCE_DIR}/common/evidence/
    ${CMAKE_SOURCE_DIR}/common/secagg/
    ${CMAKE_SOURCE_DIR}/asio-1.30.2/include/
    ${CMAKE_SOURCE_DIR}/json/include/
)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(MbedTLS)

add_executable(prot_mpc_client 
    prot_mpc_client.cpp)
target_link_libraries(prot_mpc_client PRIVATE
    Threads::Threads MbedTLS::mbedtls MbedTLS::mbedcrypto evidence_verifier_lib_host)

# add_dependencies(prot_mpc_client pubkey)
