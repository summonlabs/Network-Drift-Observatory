// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Platform surface.
//
// The runtime is portable C++20 with no third-party dependency. This header is
// the only place that knows about the compiler and the dynamic-linking model.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_PLATFORM_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_PLATFORM_HPP

#if defined(_WIN32)
#if defined(NDO_SHARED)
#if defined(NDO_BUILDING_LIBRARY)
#define NDO_API __declspec(dllexport)
#else
#define NDO_API __declspec(dllimport)
#endif
#else
#define NDO_API
#endif
#else
#if defined(NDO_SHARED)
#define NDO_API __attribute__((visibility("default")))
#else
#define NDO_API
#endif
#endif

#define NDO_NODISCARD [[nodiscard]]

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_PLATFORM_HPP
