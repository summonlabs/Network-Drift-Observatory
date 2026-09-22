# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

add_executable(ndo_example_basic basic_observatory.cpp)
target_link_libraries(ndo_example_basic PRIVATE network_drift_observatory)

add_executable(ndo_example_restart restart_recovery.cpp)
target_link_libraries(ndo_example_restart PRIVATE network_drift_observatory)

add_executable(ndo_example_sources multiple_sources.cpp)
target_link_libraries(ndo_example_sources PRIVATE network_drift_observatory)
