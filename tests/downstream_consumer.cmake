# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# Installs the runtime into a private prefix, configures the downstream consumer
# against that prefix only, builds it, and runs it. A failure at any step fails
# the test.

if(NOT DEFINED NDO_BINARY_DIR)
  message(FATAL_ERROR "NDO_BINARY_DIR must name the build tree to install")
endif()

set(NDO_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/ndo_downstream_prefix")
set(NDO_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/ndo_downstream_build")

file(REMOVE_RECURSE "${NDO_INSTALL_DIR}" "${NDO_BUILD_DIR}")

execute_process(
  COMMAND ${CMAKE_COMMAND} --install "${NDO_BINARY_DIR}" --config ${NDO_CTEST_CONFIG}
          --prefix "${NDO_INSTALL_DIR}"
  RESULT_VARIABLE install_result
  OUTPUT_VARIABLE install_output
  ERROR_VARIABLE install_error)
if(NOT install_result EQUAL 0)
  message(FATAL_ERROR "install failed: ${install_output} ${install_error}")
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -S "${NDO_CONSUMER_DIR}" -B "${NDO_BUILD_DIR}"
          -DCMAKE_PREFIX_PATH=${NDO_INSTALL_DIR}
          -DCMAKE_BUILD_TYPE=${NDO_CTEST_CONFIG}
  RESULT_VARIABLE configure_result
  OUTPUT_VARIABLE configure_output
  ERROR_VARIABLE configure_error)
if(NOT configure_result EQUAL 0)
  message(FATAL_ERROR "downstream configure failed: ${configure_output} ${configure_error}")
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} --build "${NDO_BUILD_DIR}" --config ${NDO_CTEST_CONFIG}
  RESULT_VARIABLE build_result
  OUTPUT_VARIABLE build_output
  ERROR_VARIABLE build_error)
if(NOT build_result EQUAL 0)
  message(FATAL_ERROR "downstream build failed: ${build_output} ${build_error}")
endif()

find_program(NDO_CONSUMER_EXE
  NAMES ndo_downstream_consumer
  PATHS "${NDO_BUILD_DIR}/${NDO_CTEST_CONFIG}" "${NDO_BUILD_DIR}"
  NO_DEFAULT_PATH)
if(NOT NDO_CONSUMER_EXE)
  message(FATAL_ERROR "the downstream consumer executable was not produced")
endif()

execute_process(
  COMMAND "${NDO_CONSUMER_EXE}"
  RESULT_VARIABLE run_result
  OUTPUT_VARIABLE run_output
  ERROR_VARIABLE run_error)
if(NOT run_result EQUAL 0)
  message(FATAL_ERROR "downstream consumer failed: ${run_output} ${run_error}")
endif()
message(STATUS "downstream consumer ran: ${run_output}")
