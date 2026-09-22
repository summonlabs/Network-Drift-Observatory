# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

add_executable(ndo_bench ndo_bench.cpp)
target_link_libraries(ndo_bench PRIVATE network_drift_observatory)
