// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Canonical observed/intended values.
//
// A value is a bounded tree of scalars, sequences and members. Its canonical
// text form, its ordering and its digest are pure functions of the tree, so two
// runs that observe the same state produce byte-identical encodings and
// therefore identical finding identities.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_VALUE_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_VALUE_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "summon/network_drift_observatory/hash.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"

namespace summon {
namespace network_drift_observatory {

enum class ValueKind : std::uint8_t {
  Null = 0,
  Bool = 1,
  Int = 2,
  Uint = 3,
  Double = 4,
  String = 5,
  Bytes = 6,
  List = 7,
  Map = 8,
};

NDO_API const char* ToText(ValueKind value) noexcept;

/// How two scalar values of different numeric kinds are compared.
enum class NumericEquivalence : std::uint8_t {
  /// Kinds must match exactly. Int 80 and Uint 80 differ.
  Exact = 0,
  /// Integral kinds compare by mathematical value; a double equals an integral
  /// value only when it is finite, integral and exactly representable.
  Numeric = 1,
};

/// Outcome of comparing two values.
enum class ValueRelation : std::uint8_t {
  /// Canonically identical under the requested numeric equivalence.
  Equal = 0,
  /// Both sides are present and comparable, and they differ.
  Different = 1,
  /// The two values are not in the same comparison class (for example a member
  /// versus a sequence). The runtime reports this instead of guessing.
  Incomparable = 2,
};

class NDO_API Value {
 public:
  using List = std::vector<Value>;
  using Map = std::map<std::string, Value, std::less<>>;

  Value() = default;

  NDO_NODISCARD static Value MakeNull() { return Value(); }
  NDO_NODISCARD static Value MakeBool(bool v);
  NDO_NODISCARD static Value MakeInt(std::int64_t v);
  /// An unsigned value that fits the signed range is stored as a signed value:
  /// there is exactly one canonical kind for each numeric value, so a document
  /// written by this runtime always parses back to the value it came from and
  /// an unsigned literal never looks like drift against a signed one.
  NDO_NODISCARD static Value MakeUint(std::uint64_t v);
  /// Fails for NaN and infinity: the runtime never invents a JSON number for a
  /// value it cannot encode canonically.
  NDO_NODISCARD static std::optional<Value> TryMakeDouble(double v);
  NDO_NODISCARD static Value MakeString(std::string v);
  NDO_NODISCARD static Value MakeBytes(std::vector<std::uint8_t> v);
  NDO_NODISCARD static Value MakeList(List v);
  NDO_NODISCARD static Value MakeMap(Map v);

  NDO_NODISCARD ValueKind kind() const noexcept;
  NDO_NODISCARD bool is_null() const noexcept;
  NDO_NODISCARD bool is_scalar() const noexcept;
  NDO_NODISCARD bool is_container() const noexcept;

  NDO_NODISCARD const bool* as_bool() const noexcept;
  NDO_NODISCARD const std::int64_t* as_int() const noexcept;
  NDO_NODISCARD const std::uint64_t* as_uint() const noexcept;
  NDO_NODISCARD const double* as_double() const noexcept;
  NDO_NODISCARD const std::string* as_string() const noexcept;
  NDO_NODISCARD const std::vector<std::uint8_t>* as_bytes() const noexcept;
  NDO_NODISCARD const List* as_list() const noexcept;
  NDO_NODISCARD const Map* as_map() const noexcept;

  /// Canonical text. Deterministic, unambiguous, safe to hash and to compare.
  NDO_NODISCARD std::string ToCanonicalText() const;
  /// Human-facing rendering used in explanations. Never hashed.
  NDO_NODISCARD std::string ToDisplayText(std::size_t max_bytes) const;

  void HashInto(Sha256& hasher) const;
  NDO_NODISCARD Digest DigestOf() const;

  /// Structural equality: exact kind match, no numeric coercion.
  friend bool operator==(const Value& lhs, const Value& rhs);
  friend bool operator!=(const Value& lhs, const Value& rhs) { return !(lhs == rhs); }

  /// Canonical total order over heterogeneous values.
  friend std::strong_ordering operator<=>(const Value& lhs, const Value& rhs);

  NDO_NODISCARD std::size_t NodeCount() const;
  NDO_NODISCARD std::size_t MaxDepth() const;
  /// Sum of leaf payload bytes plus per-node overhead. Used for bounds checks.
  NDO_NODISCARD std::size_t ApproximateBytes() const;

  /// Checks the value against the configured envelope. Returns Ok or a
  /// Rejected status carrying the precise bound that was exceeded.
  NDO_NODISCARD Status Validate(const RuntimeLimits& limits) const;

 private:
  struct NullTag {
    friend constexpr bool operator==(NullTag, NullTag) noexcept { return true; }
  };
  using Storage = std::variant<NullTag, bool, std::int64_t, std::uint64_t, double, std::string,
                              std::vector<std::uint8_t>, List, Map>;

  Storage storage_{NullTag{}};
};

/// Compares two values under an explicit numeric equivalence. Both values must
/// exist; absence is modelled by the caller, never by a sentinel value.
NDO_NODISCARD NDO_API ValueRelation RelateValues(const Value& lhs, const Value& rhs,
                                                 NumericEquivalence equivalence) noexcept;

/// Validates that a byte range is well-formed UTF-8 (no overlong forms, no
/// lone surrogates, no truncated sequences).
NDO_NODISCARD NDO_API bool IsValidUtf8(std::string_view text) noexcept;

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_VALUE_HPP
