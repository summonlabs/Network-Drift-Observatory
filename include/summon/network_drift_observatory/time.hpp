// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Observation time.
//
// Time is a strongly typed quantity measured in nanoseconds since the Unix
// epoch. The observatory never reads a wall clock implicitly: receive time is
// stamped by the observatory through an injected clock, and every evaluation
// receives its "now" explicitly so that a decision is reproducible.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_TIME_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_TIME_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "summon/network_drift_observatory/platform.hpp"

namespace summon {
namespace network_drift_observatory {

/// Nanoseconds since 1970-01-01T00:00:00Z. Zero means "unset".
struct NDO_API NdoTime {
  std::int64_t unix_nanos{0};

  constexpr NdoTime() noexcept = default;
  constexpr explicit NdoTime(std::int64_t value) noexcept : unix_nanos(value) {}

  NDO_NODISCARD static constexpr NdoTime FromNanos(std::int64_t value) noexcept {
    return NdoTime(value);
  }
  NDO_NODISCARD static constexpr NdoTime FromMillis(std::int64_t value) noexcept {
    return NdoTime(value * 1000000);
  }
  NDO_NODISCARD static constexpr NdoTime FromSeconds(std::int64_t value) noexcept {
    return NdoTime(value * 1000000000);
  }

  NDO_NODISCARD constexpr bool is_set() const noexcept { return unix_nanos != 0; }

  friend constexpr bool operator==(const NdoTime&, const NdoTime&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const NdoTime& lhs,
                                                    const NdoTime& rhs) noexcept {
    return lhs.unix_nanos <=> rhs.unix_nanos;
  }
};

/// Signed duration in nanoseconds. May be negative for clock-skew arithmetic.
struct NdoDuration {
  std::int64_t nanos{0};
  NDO_NODISCARD constexpr bool is_set() const noexcept { return nanos != 0; }
  friend constexpr bool operator==(const NdoDuration&, const NdoDuration&) noexcept = default;
};

/// Reads the system clock. Used for receive-time stamping and for CLI defaults;
/// never used to decide freshness inside a deterministic evaluation, which
/// always receives its own "now".
NDO_NODISCARD NDO_API NdoTime SystemNow() noexcept;

/// Formats a time as RFC 3339 UTC with nanosecond precision.
NDO_NODISCARD NDO_API std::string FormatTime(NdoTime time);
/// Parses RFC 3339 UTC. Returns false for anything malformed.
NDO_NODISCARD NDO_API bool TryParseTime(std::string_view text, NdoTime& out) noexcept;

/// Defensive subtraction: a clock that moved backwards never produces a huge
/// positive age. Returns the signed difference with overflow detected.
NDO_NODISCARD NDO_API bool TryDifference(NdoTime later, NdoTime earlier,
                                         std::int64_t& out_nanos) noexcept;

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_TIME_HPP
