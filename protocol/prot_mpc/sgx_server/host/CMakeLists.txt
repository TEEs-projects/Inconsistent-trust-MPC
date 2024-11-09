# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

find_package(OpenEnclave CONFIG REQUIRED)

add_custom_command(
    OUTPUT prog_mpc_u.h prog_mpc_u.c prog_mpc_args.h
    DEPENDS ${SGX_SERVER_SOURCE_DIR}/prog_mpc.edl
    COMMAND
        openenclave::oeedger8r --untrusted ${SGX_SERVER_SOURCE_DIR}/prog_mpc.edl
        --search-path ${OE_INCLUDEDIR} --search-path
        ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_custom_command(
  OUTPUT prog_bc_u.h prog_bc_u.c prog_bc_args.h
  DEPENDS ${SGX_SERVER_SOURCE_DIR}/prog_bc.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${SGX_SERVER_SOURCE_DIR}/prog_bc.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(host host.cpp ${CMAKE_CURRENT_BINARY_DIR}/prog_mpc_u.c ${CMAKE_CURRENT_BINARY_DIR}/prog_bc_u.c)

if (WIN32)
  copy_oedebugrt_target(file-encryptor_host_oedebugrt)
  add_dependencies(file-encryptor_host file-encryptor_host_oedebugrt)
endif ()

target_include_directories(
  host
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
          ${CMAKE_SOURCE_DIR}/common/
          ${CMAKE_SOURCE_DIR}/asio-1.30.2/include/
          ${CMAKE_SOURCE_DIR}/common/secagg/
          ${CMAKE_SOURCE_DIR}/json/include/)

target_link_libraries(host evidence_verifier_lib_host openenclave::oehost)

# add_dependencies(host pubkey)
