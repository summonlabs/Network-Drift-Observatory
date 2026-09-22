// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Product identity for the Network Drift Observatory runtime.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_VERSION_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_VERSION_HPP

#include <cstdint>

namespace summon {
namespace network_drift_observatory {

inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 0;

/// Semantic version of the Network Drift Observatory runtime.
inline constexpr const char* kVersionString = "1.0.0";
inline constexpr const char* kProductName = "Network Drift Observatory";
inline constexpr const char* kProductVendor = "Summon Software Labs";

/// Durable and wire format versions.
///
/// Every persisted artifact and every frame declares one of these, and every
/// reader refuses a version it does not understand instead of guessing.
inline constexpr std::uint16_t kLedgerFormatVersion = 1;
inline constexpr std::uint16_t kIntentDocumentFormatVersion = 1;
inline constexpr std::uint16_t kObservationDocumentFormatVersion = 1;
inline constexpr std::uint16_t kReportFormatVersion = 1;
inline constexpr std::uint16_t kWireProtocolVersion = 1;
inline constexpr std::uint16_t kPolicyFormatVersion = 1;

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_VERSION_HPP
