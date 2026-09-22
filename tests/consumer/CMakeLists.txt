# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# Downstream consumer: this project is built outside the observatory build tree
# and only ever sees the installed package.

cmake_minimum_required(VERSION 3.20)
project(NdoDownstreamConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(NetworkDriftObservatory 1.0 REQUIRED)

add_executable(ndo_downstream_consumer consumer.cpp)
target_link_libraries(ndo_downstream_consumer
  PRIVATE SummonLabs::NetworkDriftObservatory::network_drift_observatory)
