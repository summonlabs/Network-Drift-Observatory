// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Internal helpers shared by every document codec.
//
// These helpers make the strictness uniform: a member that is not declared by
// the format is a refusal, a member of the wrong kind is a refusal, and a
// missing required member is a refusal. None of them substitutes a default.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_SRC_JSON_HELP_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_SRC_JSON_HELP_HPP

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/value.hpp"

namespace summon {
namespace network_drift_observatory {
namespace detail {

inline Status MemberError(const char* what, std::string_view member, const char* detail) {
  std::string text(what);
  text.append(": ");
  text.append(member);
  text.append(": ");
  text.append(detail);
  return Status::Rejected(ReasonCode::EncodingMalformed, std::move(text));
}

/// Refuses any member that the format does not declare.
inline Status CheckMembers(const Value::Map& map, std::initializer_list<std::string_view> allowed,
                           const char* what) {
  for (const auto& entry : map) {
    bool known = false;
    for (std::string_view name : allowed) {
      if (entry.first == name) {
        known = true;
        break;
      }
    }
    if (!known) {
      return MemberError(what, entry.first, "unknown member");
    }
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

inline const Value* FindMember(const Value::Map& map, std::string_view name) {
  const auto found = map.find(name);
  if (found == map.end()) {
    return nullptr;
  }
  return &found->second;
}

inline Status RequireString(const Value::Map& map, std::string_view name, const char* what,
                            std::string& out) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return MemberError(what, name, "missing required member");
  }
  const std::string* text = member->as_string();
  if (text == nullptr) {
    return MemberError(what, name, "must be a string");
  }
  out = *text;
  return Status(StatusCode::Ok, ReasonCode::None);
}

inline std::optional<std::string> OptionalString(const Value::Map& map, std::string_view name) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return std::nullopt;
  }
  const std::string* text = member->as_string();
  if (text == nullptr) {
    return std::nullopt;
  }
  return *text;
}

inline Status RequireBool(const Value::Map& map, std::string_view name, const char* what, bool& out) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return MemberError(what, name, "missing required member");
  }
  const bool* value = member->as_bool();
  if (value == nullptr) {
    return MemberError(what, name, "must be a boolean");
  }
  out = *value;
  return Status(StatusCode::Ok, ReasonCode::None);
}

inline std::optional<bool> OptionalBool(const Value::Map& map, std::string_view name) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return std::nullopt;
  }
  const bool* value = member->as_bool();
  if (value == nullptr) {
    return std::nullopt;
  }
  return *value;
}

inline Status RequireUint(const Value::Map& map, std::string_view name, const char* what,
                          std::uint64_t& out) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return MemberError(what, name, "missing required member");
  }
  if (const std::uint64_t* value = member->as_uint(); value != nullptr) {
    out = *value;
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  if (const std::int64_t* value = member->as_int(); value != nullptr && *value >= 0) {
    out = static_cast<std::uint64_t>(*value);
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  return MemberError(what, name, "must be a non-negative integer");
}

inline std::optional<std::uint64_t> OptionalUint(const Value::Map& map, std::string_view name) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return std::nullopt;
  }
  if (const std::uint64_t* value = member->as_uint(); value != nullptr) {
    return *value;
  }
  if (const std::int64_t* value = member->as_int(); value != nullptr && *value >= 0) {
    return static_cast<std::uint64_t>(*value);
  }
  return std::nullopt;
}

inline std::optional<std::int64_t> OptionalInt(const Value::Map& map, std::string_view name) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return std::nullopt;
  }
  if (const std::int64_t* value = member->as_int(); value != nullptr) {
    return *value;
  }
  if (const std::uint64_t* value = member->as_uint();
      value != nullptr && *value <= 9223372036854775807ULL) {
    return static_cast<std::int64_t>(*value);
  }
  return std::nullopt;
}

/// The kind a declared member must have when it is present.
enum class MemberKind : std::uint8_t {
  Any = 0,
  /// A signed or unsigned integral value. A fractional number is refused.
  Integer = 1,
  /// Any numeric value.
  Number = 2,
  Boolean = 3,
  Text = 4,
  Sequence = 5,
  Object = 6,
};

inline bool MemberHasKind(const Value& value, MemberKind kind) {
  switch (kind) {
    case MemberKind::Any:
      return true;
    case MemberKind::Integer:
      return value.as_int() != nullptr || value.as_uint() != nullptr;
    case MemberKind::Number:
      return value.as_int() != nullptr || value.as_uint() != nullptr ||
             value.as_double() != nullptr;
    case MemberKind::Boolean:
      return value.as_bool() != nullptr;
    case MemberKind::Text:
      return value.as_string() != nullptr;
    case MemberKind::Sequence:
      return value.as_list() != nullptr;
    case MemberKind::Object:
      return value.as_map() != nullptr;
  }
  return false;
}

/// Refuses a declared member that is present with the wrong kind. This runs
/// before extraction so that no decoder can silently substitute a default for
/// a member the author wrote incorrectly.
inline Status CheckMemberKinds(
    const Value::Map& map,
    std::initializer_list<std::pair<std::string_view, MemberKind>> expectations, const char* what) {
  for (const auto& expectation : expectations) {
    const Value* member = FindMember(map, expectation.first);
    if (member == nullptr) {
      continue;
    }
    if (!MemberHasKind(*member, expectation.second)) {
      return MemberError(what, expectation.first, "has the wrong kind");
    }
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

/// An optional member that must have the declared kind when it is present.
/// A member of the wrong kind is a refusal, never a silent default: a caller
/// that quietly substituted "1" for "two" would be inventing intent.
inline Status ReadOptionalUint(const Value::Map& map, std::string_view name, const char* what,
                               std::optional<std::uint64_t>& out) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  if (const std::uint64_t* value = member->as_uint(); value != nullptr) {
    out = *value;
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  if (const std::int64_t* value = member->as_int(); value != nullptr && *value >= 0) {
    out = static_cast<std::uint64_t>(*value);
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  return MemberError(what, name, "must be a non-negative integer");
}

inline Status ReadOptionalInt(const Value::Map& map, std::string_view name, const char* what,
                              std::optional<std::int64_t>& out) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  if (const std::int64_t* value = member->as_int(); value != nullptr) {
    out = *value;
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  if (const std::uint64_t* value = member->as_uint();
      value != nullptr && *value <= 9223372036854775807ULL) {
    out = static_cast<std::int64_t>(*value);
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  return MemberError(what, name, "must be an integer");
}

inline Status ReadOptionalBool(const Value::Map& map, std::string_view name, const char* what,
                               std::optional<bool>& out) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  const bool* value = member->as_bool();
  if (value == nullptr) {
    return MemberError(what, name, "must be a boolean");
  }
  out = *value;
  return Status(StatusCode::Ok, ReasonCode::None);
}

inline Status ReadOptionalString(const Value::Map& map, std::string_view name, const char* what,
                                 std::optional<std::string>& out) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  const std::string* value = member->as_string();
  if (value == nullptr) {
    return MemberError(what, name, "must be a string");
  }
  out = *value;
  return Status(StatusCode::Ok, ReasonCode::None);
}

inline Status RequireList(const Value::Map& map, std::string_view name, const char* what,
                          const Value::List*& out) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return MemberError(what, name, "missing required member");
  }
  const Value::List* list = member->as_list();
  if (list == nullptr) {
    return MemberError(what, name, "must be a sequence");
  }
  out = list;
  return Status(StatusCode::Ok, ReasonCode::None);
}

inline Status RequireMap(const Value::Map& map, std::string_view name, const char* what,
                         const Value::Map*& out) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    return MemberError(what, name, "missing required member");
  }
  const Value::Map* inner = member->as_map();
  if (inner == nullptr) {
    return MemberError(what, name, "must be an object");
  }
  out = inner;
  return Status(StatusCode::Ok, ReasonCode::None);
}

inline Status RequireObject(const Value& value, const char* what, const Value::Map*& out) {
  const Value::Map* map = value.as_map();
  if (map == nullptr) {
    std::string text(what);
    text.append(": top-level value must be an object");
    return Status::Rejected(ReasonCode::EncodingMalformed, std::move(text));
  }
  out = map;
  return Status(StatusCode::Ok, ReasonCode::None);
}

/// A deterministic, monotonically increasing version tag in every hash input.
inline constexpr const char* kFindingIdentityTag = "ndo/finding-identity/v1";
inline constexpr const char* kSnapshotIdentityTag = "ndo/observation-snapshot/v1";
inline constexpr const char* kIntentContentTag = "ndo/intent-generation/v1";
inline constexpr const char* kPolicyTag = "ndo/policy/v1";
inline constexpr const char* kGroupIdentityTag = "ndo/root-cause-group/v1";
inline constexpr const char* kEvaluationTag = "ndo/evaluation-outcome/v1";

}  // namespace detail
}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_SRC_JSON_HELP_HPP
