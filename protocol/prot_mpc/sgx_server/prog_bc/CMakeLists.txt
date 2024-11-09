# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT prog_bc_t.h prog_bc_t.c prog_bc_args.h
  DEPENDS ${SGX_SERVER_SOURCE_DIR}/prog_bc.edl
  COMMAND
    openenclave::oeedger8r --trusted ${SGX_SERVER_SOURCE_DIR}/prog_bc.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(
  prog_bc ecalls.cpp prog_bc.cpp ${CMAKE_CURRENT_BINARY_DIR}/prog_bc_t.c)
if (WIN32)
  maybe_build_using_clangw(enclave)
endif ()

target_compile_definitions(prog_bc PUBLIC OE_API_VERSION=2)

target_include_directories(
    prog_bc
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
          ${CMAKE_SOURCE_DIR}/common/
          ${CMAKE_SOURCE_DIR}/common/secagg/
          ${CMAKE_SOURCE_DIR}/common/evidence/)

target_link_libraries(
    prog_bc evidence_generator_lib evidence_verifier_lib_enclave openenclave::oeenclave openenclave::oecryptombedtls
  openenclave::oelibcxx)

# add_dependencies(prog_bc pubkey)
