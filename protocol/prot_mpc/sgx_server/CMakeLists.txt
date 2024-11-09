# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(SGX_SERVER_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(prog_bc)
add_subdirectory(prog_mpc)
add_subdirectory(host)

# Sign enclave
add_custom_command(
  OUTPUT prog_bc/prog_bc.signed
  DEPENDS prog_bc ${SGX_SERVER_SOURCE_DIR}/prog_bc/prog_bc.conf ${SGX_SERVER_SOURCE_DIR}/private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:prog_bc> -c
          ${SGX_SERVER_SOURCE_DIR}/prog_bc/prog_bc.conf -k ${SGX_SERVER_SOURCE_DIR}/private.pem)

add_custom_command(
OUTPUT prog_mpc/prog_mpc.signed
DEPENDS prog_mpc ${SGX_SERVER_SOURCE_DIR}/prog_mpc/prog_mpc.conf ${SGX_SERVER_SOURCE_DIR}/private.pem
COMMAND openenclave::oesign sign -e $<TARGET_FILE:prog_mpc> -c
        ${SGX_SERVER_SOURCE_DIR}/prog_mpc/prog_mpc.conf -k ${SGX_SERVER_SOURCE_DIR}/private.pem)

add_custom_target(sign ALL DEPENDS prog_bc/prog_bc.signed prog_mpc/prog_mpc.signed)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS host sign testfile
    COMMAND host ${CMAKE_CURRENT_SOURCE_DIR}/testfile
            ${CMAKE_BINARY_DIR}/prog_bc/prog_bc.signed)
endif ()

add_custom_target(
  simulate
  DEPENDS host sign testfile
  COMMAND host ${CMAKE_CURRENT_SOURCE_DIR}/testfile
          ${CMAKE_BINARY_DIR}/prog_bc/prog_bc.signed --simulate)
