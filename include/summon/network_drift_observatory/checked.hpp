// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Checked arithmetic.
//
// Every size, count, offset or capacity derived from external input (wire
// frames, persisted records, observation documents, CLI arguments) passes
// through these helpers before it is used to allocate, index or accumulate.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_CHECKED_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_CHECKED_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

#include "summon/network_drift_observatory/platform.hpp"

namespace summon {
namespace network_drift_observatory {

template <typename T>
NDO_NODISCARD constexpr std::optional<T> CheckedAdd(T a, T b) noexcept {
  static_assert(std::is_unsigned_v<T>, "CheckedAdd requires an unsigned type");
  if (a > std::numeric_limits<T>::max() - b) {
    return std::nullopt;
  }
  return static_cast<T>(a + b);
}

template <typename T>
NDO_NODISCARD constexpr std::optional<T> CheckedSub(T a, T b) noexcept {
  static_assert(std::is_unsigned_v<T>, "CheckedSub requires an unsigned type");
  if (b > a) {
    return std::nullopt;
  }
  return static_cast<T>(a - b);
}

template <typename T>
NDO_NODISCARD constexpr std::optional<T> CheckedMul(T a, T b) noexcept {
  static_assert(std::is_unsigned_v<T>, "CheckedMul requires an unsigned type");
  if (a != 0 && b > std::numeric_limits<T>::max() / a) {
    return std::nullopt;
  }
  return static_cast<T>(a * b);
}

/// Narrowing conversion that fails instead of truncating.
template <typename To, typename From>
NDO_NODISCARD constexpr std::optional<To> CheckedCast(From value) noexcept {
  static_assert(std::is_integral_v<To> && std::is_integral_v<From>,
                "CheckedCast requires integral types");
  if constexpr (std::is_signed_v<From> == std::is_signed_v<To>) {
    if (value < static_cast<From>(std::numeric_limits<To>::min()) ||
        value > static_cast<From>(std::numeric_limits<To>::max())) {
      return std::nullopt;
    }
  } else if constexpr (std::is_signed_v<From>) {
    if (value < 0) {
      return std::nullopt;
    }
    using UnsignedFrom = std::make_unsigned_t<From>;
    if (static_cast<UnsignedFrom>(value) > std::numeric_limits<To>::max()) {
      return std::nullopt;
    }
  } else {
    if (value > static_cast<From>(std::numeric_limits<To>::max())) {
      return std::nullopt;
    }
  }
  return static_cast<To>(value);
}

/// Signed addition with overflow detection, used for time arithmetic.
NDO_NODISCARD constexpr std::optional<std::int64_t> CheckedAddSigned(std::int64_t a,
                                                                    std::int64_t b) noexcept {
  if (b > 0 && a > std::numeric_limits<std::int64_t>::max() - b) {
    return std::nullopt;
  }
  if (b < 0 && a < std::numeric_limits<std::int64_t>::min() - b) {
    return std::nullopt;
  }
  return static_cast<std::int64_t>(a + b);
}

NDO_NODISCARD constexpr std::optional<std::int64_t> CheckedSubSigned(std::int64_t a,
                                                                    std::int64_t b) noexcept {
  if (b == std::numeric_limits<std::int64_t>::min()) {
    return std::nullopt;
  }
  return CheckedAddSigned(a, -b);
}

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_CHECKED_HPP
