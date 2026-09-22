# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

add_executable(ndo_cli ndo_cli.cpp)
target_link_libraries(ndo_cli PRIVATE network_drift_observatory)
set_target_properties(ndo_cli PROPERTIES OUTPUT_NAME ndo_cli)

add_executable(ndo_collector ndo_collector.cpp)
target_link_libraries(ndo_collector PRIVATE network_drift_observatory)
set_target_properties(ndo_collector PROPERTIES OUTPUT_NAME ndo_collector)
