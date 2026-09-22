# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

set(NDO_TEST_SUITES
  test_core
  test_value_json
  test_intent_policy
  test_freshness
  test_comparison
  test_ledger
  test_property
  test_adversarial
  test_concurrency
  test_persistence
  test_scale
  test_transport
  test_e2e
  test_multiprocess)

foreach(suite IN LISTS NDO_TEST_SUITES)
  add_executable(${suite} ${suite}.cpp test_main.cpp)
  target_link_libraries(${suite} PRIVATE network_drift_observatory)
  target_include_directories(${suite} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME ${suite} COMMAND ${suite})
endforeach()

if(NDO_BUILD_TOOLS)
  # The process suites launch the real command line tools as independent
  # operating-system processes; the directory is resolved per configuration.
  # The tool directory is passed as a CMake path (forward slashes) plus the
  # configuration name, so the value survives a C++ string literal: a Windows
  # backslash would be read as an escape sequence by the compiler.
  file(TO_CMAKE_PATH "${CMAKE_BINARY_DIR}/tools" NDO_TOOL_ROOT)
  target_compile_definitions(test_multiprocess PRIVATE
    NDO_TOOL_ROOT="${NDO_TOOL_ROOT}" NDO_TOOL_CONFIG="$<CONFIG>")
  target_compile_definitions(test_e2e PRIVATE
    NDO_TOOL_ROOT="${NDO_TOOL_ROOT}" NDO_TOOL_CONFIG="$<CONFIG>")
  add_dependencies(test_multiprocess ndo_collector)
  add_dependencies(test_e2e ndo_cli)
endif()

# Downstream find_package consumer: proves the installed package from outside
# the build tree.
add_test(NAME test_downstream_package
  COMMAND ${CMAKE_COMMAND}
    -DNDO_SOURCE_DIR=${CMAKE_SOURCE_DIR}
    -DNDO_BINARY_DIR=${CMAKE_BINARY_DIR}
    -DNDO_CONSUMER_DIR=${CMAKE_CURRENT_SOURCE_DIR}/consumer
    -DNDO_CTEST_CONFIG=$<CONFIG>
    -P ${CMAKE_CURRENT_SOURCE_DIR}/downstream_consumer.cmake)
