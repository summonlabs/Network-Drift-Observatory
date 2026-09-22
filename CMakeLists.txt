# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# Network Drift Observatory -- build, test and install.
#
# The runtime is portable C++20 with no third-party dependency. It uses the
# standard library and, on Windows, the platform sockets library that ships with
# the operating system.

cmake_minimum_required(VERSION 3.20)

project(NetworkDriftObservatory
  VERSION 1.0.0
  DESCRIPTION "Observational detection and explanation of drift between intended and observed network state"
  HOMEPAGE_URL "https://github.com/summonlabs/Network-Drift-Observatory"
  LANGUAGES CXX)

set(NDO_VERSION "${PROJECT_VERSION}")

option(NDO_BUILD_TOOLS "Build the command line tools" ON)
option(NDO_BUILD_TESTS "Build the test suites" ON)
option(NDO_BUILD_EXAMPLES "Build the examples" ON)
option(NDO_BUILD_BENCH "Build the measurement benchmark" ON)
option(NDO_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(NDO_ENABLE_SANITIZERS "Build with AddressSanitizer and UBSan where supported" OFF)
option(NDO_BUILD_SHARED "Build the runtime as a shared library" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NDO_BUILD_SHARED)
  set(NDO_LIBRARY_TYPE SHARED)
else()
  set(NDO_LIBRARY_TYPE STATIC)
endif()

add_library(network_drift_observatory ${NDO_LIBRARY_TYPE}
  src/client.cpp
  src/comparison.cpp
  src/drift.cpp
  src/engine.cpp
  src/finding.cpp
  src/freshness.cpp
  src/hash.cpp
  src/identity.cpp
  src/intent.cpp
  src/interchange.cpp
  src/json.cpp
  src/ledger.cpp
  src/limits.cpp
  src/net.cpp
  src/observation.cpp
  src/persistence.cpp
  src/policy.cpp
  src/query.cpp
  src/report.cpp
  src/server.cpp
  src/status.cpp
  src/time.cpp
  src/value.cpp
  src/wire.cpp)

add_library(SummonLabs::NetworkDriftObservatory::network_drift_observatory ALIAS network_drift_observatory)

target_include_directories(network_drift_observatory
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_features(network_drift_observatory PUBLIC cxx_std_20)

if(NDO_BUILD_SHARED)
  target_compile_definitions(network_drift_observatory
    PUBLIC NDO_SHARED
    PRIVATE NDO_BUILDING_LIBRARY)
endif()

find_package(Threads REQUIRED)
target_link_libraries(network_drift_observatory PRIVATE Threads::Threads)

if(WIN32)
  target_link_libraries(network_drift_observatory PRIVATE ws2_32)
endif()

# ---- warnings ----
if(MSVC)
  set(NDO_WARNINGS
    /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /Zc:preprocessor
    /w14242 /w14254 /w14263 /w14265 /w14287 /w14296 /w14311 /w14545 /w14546 /w14547
    /w14549 /w14555 /w14619 /w14640 /w14826 /w14905 /w14906 /w14928)
  if(NDO_WARNINGS_AS_ERRORS)
    list(APPEND NDO_WARNINGS /WX)
  endif()
  add_compile_options(${NDO_WARNINGS})
else()
  set(NDO_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
  if(NDO_WARNINGS_AS_ERRORS)
    list(APPEND NDO_WARNINGS -Werror)
  endif()
  add_compile_options(${NDO_WARNINGS})
endif()

if(NDO_ENABLE_SANITIZERS)
  if(MSVC)
    target_compile_options(network_drift_observatory PUBLIC /fsanitize=address)
  else()
    target_compile_options(network_drift_observatory PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(network_drift_observatory PUBLIC -fsanitize=address,undefined)
  endif()
endif()

# ---- tools, examples, benchmarks, tests ----
if(NDO_BUILD_TOOLS)
  add_subdirectory(tools)
endif()

if(NDO_BUILD_BENCH)
  add_subdirectory(bench)
endif()

if(NDO_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(NDO_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---- installation ----
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS network_drift_observatory
  EXPORT NetworkDriftObservatoryTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT NetworkDriftObservatoryTargets
  FILE NetworkDriftObservatoryTargets.cmake
  NAMESPACE SummonLabs::NetworkDriftObservatory::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetworkDriftObservatory)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/NetworkDriftObservatoryConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/NetworkDriftObservatoryConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetworkDriftObservatory)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/NetworkDriftObservatoryConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
  ARCH_INDEPENDENT)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/NetworkDriftObservatoryConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/NetworkDriftObservatoryConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetworkDriftObservatory)

install(FILES README.md LICENSE
  DESTINATION ${CMAKE_INSTALL_DATADIR}/NetworkDriftObservatory)
