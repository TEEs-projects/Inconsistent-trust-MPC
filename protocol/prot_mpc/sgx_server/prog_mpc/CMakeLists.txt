# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT prog_mpc_t.h prog_mpc_t.c prog_mpc_args.h
  DEPENDS ${SGX_SERVER_SOURCE_DIR}/prog_mpc.edl
  COMMAND
    openenclave::oeedger8r --trusted ${SGX_SERVER_SOURCE_DIR}/prog_mpc.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

set(CRYPTO_SRC ${OE_CRYPTO_LIB}_src)
if (OE_CRYPTO_LIB STREQUAL "openssl_3")
  set(CRYPTO_SRC openssl_src)
endif ()

add_executable(
  prog_mpc ecalls.cpp prog_mpc.cpp ${CMAKE_CURRENT_BINARY_DIR}/prog_mpc_t.c)
if (WIN32)
  maybe_build_using_clangw(prog_mpc)
endif ()

target_compile_definitions(prog_mpc PUBLIC OE_API_VERSION=2)

target_include_directories(
    prog_mpc
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
          ${CMAKE_SOURCE_DIR}/common/
          ${CMAKE_SOURCE_DIR}/common/secagg/
          ${CMAKE_SOURCE_DIR}/common/evidence/)

target_link_libraries(
  prog_mpc evidence_generator_lib evidence_verifier_lib_enclave openenclave::oeenclave openenclave::oecryptombedtls
  openenclave::oelibcxx)

# add_dependencies(prog_mpc pubkey)
