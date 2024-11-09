cmake_minimum_required(VERSION 3.11)

set(CMAKE_CXX_STANDARD 20)

add_executable(server server.cpp)

target_include_directories(
    server
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
            ${CMAKE_SOURCE_DIR}/common/
            ${CMAKE_SOURCE_DIR}/common/secagg/
            ${CMAKE_SOURCE_DIR}/asio-1.30.2/include/
            ${CMAKE_SOURCE_DIR}/json/include)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

target_link_libraries(server
    PRIVATE Threads::Threads MbedTLS::mbedcrypto evidence_verifier_lib_host)
