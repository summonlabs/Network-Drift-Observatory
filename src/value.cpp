// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/value.hpp"

#include <algorithm>
#include <bit>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace summon {
namespace network_drift_observatory {
namespace {

/// Hard recursion guard. Values built through the codec are already bounded by
/// the configured envelope; this protects the runtime from a value assembled
/// programmatically into a pathological tree.
constexpr std::size_t kHardRecursionLimit = 64;

constexpr std::size_t kNodeOverheadBytes = 32;
constexpr std::size_t kContainerOverheadBytes = 48;

/// Shortest round-trippable decimal form. Deterministic across platforms.
std::string FormatDouble(double value) {
  char buffer[64];
  const std::to_chars_result result =
      std::to_chars(buffer, buffer + sizeof(buffer), value, std::chars_format::general);
  if (result.ec != std::errc{}) {
    return "0";
  }
  std::string text(buffer, result.ptr);
  if (text.find('.') == std::string::npos && text.find('e') == std::string::npos &&
      text.find('E') == std::string::npos) {
    text += ".0";
  }
  return text;
}

}  // namespace

const char* ToText(ValueKind value) noexcept {
  switch (value) {
    case ValueKind::Null:
      return "null";
    case ValueKind::Bool:
      return "bool";
    case ValueKind::Int:
      return "int";
    case ValueKind::Uint:
      return "uint";
    case ValueKind::Double:
      return "double";
    case ValueKind::String:
      return "string";
    case ValueKind::Bytes:
      return "bytes";
    case ValueKind::List:
      return "list";
    case ValueKind::Map:
      return "map";
  }
  return "invalid";
}

Value Value::MakeBool(bool v) {
  Value value;
  value.storage_ = v;
  return value;
}

Value Value::MakeInt(std::int64_t v) {
  Value value;
  value.storage_ = v;
  return value;
}

Value Value::MakeUint(std::uint64_t v) {
  if (v <= 9223372036854775807ULL) {
    // The canonical kind for a value that fits the signed range is signed.
    Value value;
    value.storage_ = static_cast<std::int64_t>(v);
    return value;
  }
  Value value;
  value.storage_ = v;
  return value;
}

std::optional<Value> Value::TryMakeDouble(double v) {
  if (!std::isfinite(v)) {
    return std::nullopt;
  }
  Value value;
  value.storage_ = v;
  return value;
}

Value Value::MakeString(std::string v) {
  Value value;
  value.storage_ = std::move(v);
  return value;
}

Value Value::MakeBytes(std::vector<std::uint8_t> v) {
  Value value;
  value.storage_ = std::move(v);
  return value;
}

Value Value::MakeList(List v) {
  Value value;
  value.storage_ = std::move(v);
  return value;
}

Value Value::MakeMap(Map v) {
  Value value;
  value.storage_ = std::move(v);
  return value;
}

ValueKind Value::kind() const noexcept {
  return static_cast<ValueKind>(storage_.index());
}

bool Value::is_null() const noexcept {
  return std::holds_alternative<NullTag>(storage_);
}

bool Value::is_scalar() const noexcept {
  return !is_container();
}

bool Value::is_container() const noexcept {
  return std::holds_alternative<List>(storage_) || std::holds_alternative<Map>(storage_);
}

const bool* Value::as_bool() const noexcept {
  return std::get_if<bool>(&storage_);
}

const std::int64_t* Value::as_int() const noexcept {
  return std::get_if<std::int64_t>(&storage_);
}

const std::uint64_t* Value::as_uint() const noexcept {
  return std::get_if<std::uint64_t>(&storage_);
}

const double* Value::as_double() const noexcept {
  return std::get_if<double>(&storage_);
}

const std::string* Value::as_string() const noexcept {
  return std::get_if<std::string>(&storage_);
}

const std::vector<std::uint8_t>* Value::as_bytes() const noexcept {
  return std::get_if<std::vector<std::uint8_t>>(&storage_);
}

const Value::List* Value::as_list() const noexcept {
  return std::get_if<List>(&storage_);
}

const Value::Map* Value::as_map() const noexcept {
  return std::get_if<Map>(&storage_);
}

namespace {

void AppendCanonical(std::string& out, const Value& value, std::size_t depth);

void AppendCanonicalMap(std::string& out, const Value::Map& map, std::size_t depth) {
  out.push_back('{');
  bool first = true;
  for (const auto& entry : map) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    out += std::to_string(entry.first.size());
    out.push_back(':');
    out.append(entry.first);
    out.push_back('=');
    AppendCanonical(out, entry.second, depth + 1);
  }
  out.push_back('}');
}

void AppendCanonical(std::string& out, const Value& value, std::size_t depth) {
  if (depth > kHardRecursionLimit) {
    out.append("!depth");
    return;
  }
  switch (value.kind()) {
    case ValueKind::Null:
      out.append("n");
      return;
    case ValueKind::Bool:
      out.append(*value.as_bool() ? "t" : "f");
      return;
    case ValueKind::Int:
      out.push_back('i');
      out += std::to_string(*value.as_int());
      return;
    case ValueKind::Uint:
      out.push_back('u');
      out += std::to_string(*value.as_uint());
      return;
    case ValueKind::Double:
      out.push_back('d');
      out += FormatDouble(*value.as_double());
      return;
    case ValueKind::String: {
      const std::string& text = *value.as_string();
      out.push_back('s');
      out += std::to_string(text.size());
      out.push_back(':');
      out.append(text);
      return;
    }
    case ValueKind::Bytes: {
      const std::vector<std::uint8_t>& bytes = *value.as_bytes();
      out.push_back('b');
      out += std::to_string(bytes.size());
      out.push_back(':');
      out += ToHex(bytes.data(), bytes.size());
      return;
    }
    case ValueKind::List: {
      const Value::List& list = *value.as_list();
      out.push_back('l');
      out += std::to_string(list.size());
      out.push_back('[');
      for (const Value& element : list) {
        AppendCanonical(out, element, depth + 1);
        out.push_back(';');
      }
      out.push_back(']');
      return;
    }
    case ValueKind::Map:
      out.push_back('m');
      out += std::to_string(value.as_map()->size());
      AppendCanonicalMap(out, *value.as_map(), depth);
      return;
  }
}

void HashValue(Sha256& hasher, const Value& value, std::size_t depth) {
  if (depth > kHardRecursionLimit) {
    hasher.UpdateTag("!depth");
    return;
  }
  const std::uint8_t tag = static_cast<std::uint8_t>(value.kind());
  hasher.UpdateByte(tag);
  switch (value.kind()) {
    case ValueKind::Null:
      return;
    case ValueKind::Bool:
      hasher.UpdateByte(*value.as_bool() ? 1u : 0u);
      return;
    case ValueKind::Int:
      hasher.UpdateU64(static_cast<std::uint64_t>(*value.as_int()));
      return;
    case ValueKind::Uint:
      hasher.UpdateU64(*value.as_uint());
      return;
    case ValueKind::Double: {
      static_assert(sizeof(std::uint64_t) == sizeof(double), "double must be 64-bit");
      hasher.UpdateU64(std::bit_cast<std::uint64_t>(*value.as_double()));
      return;
    }
    case ValueKind::String:
      hasher.UpdateLengthPrefixed(*value.as_string());
      return;
    case ValueKind::Bytes: {
      const std::vector<std::uint8_t>& bytes = *value.as_bytes();
      hasher.UpdateU64(bytes.size());
      hasher.Update(bytes.data(), bytes.size());
      return;
    }
    case ValueKind::List: {
      const Value::List& list = *value.as_list();
      hasher.UpdateU64(list.size());
      for (const Value& element : list) {
        HashValue(hasher, element, depth + 1);
      }
      return;
    }
    case ValueKind::Map: {
      const Value::Map& map = *value.as_map();
      hasher.UpdateU64(map.size());
      for (const auto& entry : map) {
        hasher.UpdateLengthPrefixed(entry.first);
        HashValue(hasher, entry.second, depth + 1);
      }
      return;
    }
  }
}

std::size_t CountNodes(const Value& value, std::size_t depth);
std::size_t CountDepth(const Value& value, std::size_t depth);
std::size_t CountBytes(const Value& value, std::size_t depth);

std::size_t CountNodes(const Value& value, std::size_t depth) {
  if (depth > kHardRecursionLimit) {
    return 1;
  }
  switch (value.kind()) {
    case ValueKind::List: {
      std::size_t total = 1;
      for (const Value& element : *value.as_list()) {
        total += CountNodes(element, depth + 1);
      }
      return total;
    }
    case ValueKind::Map: {
      std::size_t total = 1;
      for (const auto& entry : *value.as_map()) {
        total += CountNodes(entry.second, depth + 1);
      }
      return total;
    }
    default:
      return 1;
  }
}

std::size_t CountDepth(const Value& value, std::size_t depth) {
  if (depth > kHardRecursionLimit) {
    return depth;
  }
  switch (value.kind()) {
    case ValueKind::List: {
      std::size_t deepest = depth;
      for (const Value& element : *value.as_list()) {
        deepest = std::max(deepest, CountDepth(element, depth + 1));
      }
      return deepest;
    }
    case ValueKind::Map: {
      std::size_t deepest = depth;
      for (const auto& entry : *value.as_map()) {
        deepest = std::max(deepest, CountDepth(entry.second, depth + 1));
      }
      return deepest;
    }
    default:
      return depth;
  }
}

void MeasureBytes(const Value& value, std::size_t depth, std::size_t& total) {
  if (depth > kHardRecursionLimit) {
    return;
  }
  total += kNodeOverheadBytes;
  switch (value.kind()) {
    case ValueKind::String:
      total += value.as_string()->size();
      return;
    case ValueKind::Bytes:
      total += value.as_bytes()->size();
      return;
    case ValueKind::List:
      total += kContainerOverheadBytes;
      for (const Value& element : *value.as_list()) {
        MeasureBytes(element, depth + 1, total);
      }
      return;
    case ValueKind::Map:
      total += kContainerOverheadBytes;
      for (const auto& entry : *value.as_map()) {
        total += entry.first.size() + kNodeOverheadBytes;
        MeasureBytes(entry.second, depth + 1, total);
      }
      return;
    default:
      return;
  }
}

Status ValidateValue(const Value& value, const RuntimeLimits& limits, std::size_t depth) {
  if (depth > limits.max_value_depth || depth > kHardRecursionLimit) {
    return Status::Limit(ReasonCode::LimitDepthExceeded, "value nesting exceeds the envelope");
  }
  switch (value.kind()) {
    case ValueKind::String: {
      const std::string& text = *value.as_string();
      if (text.size() > limits.max_leaf_bytes) {
        return Status::Limit(ReasonCode::LimitBytesExceeded, "string leaf exceeds the envelope");
      }
      if (!IsValidUtf8(text)) {
        return Status::Rejected(ReasonCode::EncodingInvalidUtf8, "string leaf is not UTF-8");
      }
      return Status::Ok();
    }
    case ValueKind::Bytes: {
      if (value.as_bytes()->size() > limits.max_leaf_bytes) {
        return Status::Limit(ReasonCode::LimitBytesExceeded, "byte leaf exceeds the envelope");
      }
      return Status::Ok();
    }
    case ValueKind::List: {
      const Value::List& list = *value.as_list();
      if (list.size() > limits.max_value_nodes) {
        return Status::Limit(ReasonCode::LimitObjectsExceeded, "sequence exceeds the envelope");
      }
      for (const Value& element : list) {
        Status status = ValidateValue(element, limits, depth + 1);
        if (!status.ok()) {
          return status;
        }
      }
      return Status::Ok();
    }
    case ValueKind::Map: {
      const Value::Map& map = *value.as_map();
      if (map.size() > limits.max_value_nodes) {
        return Status::Limit(ReasonCode::LimitFieldsExceeded, "member set exceeds the envelope");
      }
      for (const auto& entry : map) {
        if (entry.first.size() > limits.max_leaf_bytes) {
          return Status::Limit(ReasonCode::LimitBytesExceeded, "member name exceeds the envelope");
        }
        if (!IsValidUtf8(entry.first)) {
          return Status::Rejected(ReasonCode::EncodingInvalidUtf8, "member name is not UTF-8");
        }
        Status status = ValidateValue(entry.second, limits, depth + 1);
        if (!status.ok()) {
          return status;
        }
      }
      return Status::Ok();
    }
    default:
      return Status::Ok();
  }
}

}  // namespace

std::string Value::ToCanonicalText() const {
  std::string out;
  out.reserve(64);
  AppendCanonical(out, *this, 0);
  return out;
}

std::string Value::ToDisplayText(std::size_t max_bytes) const {
  std::string text = ToCanonicalText();
  if (text.size() <= max_bytes) {
    return text;
  }
  text.resize(max_bytes);
  text.append("...");
  return text;
}

void Value::HashInto(Sha256& hasher) const {
  HashValue(hasher, *this, 0);
}

Digest Value::DigestOf() const {
  Sha256 hasher;
  HashInto(hasher);
  return hasher.Final();
}

bool operator==(const Value& lhs, const Value& rhs) {
  return lhs.storage_ == rhs.storage_;
}

std::strong_ordering operator<=>(const Value& lhs, const Value& rhs) {
  if (lhs.kind() != rhs.kind()) {
    return lhs.kind() <=> rhs.kind();
  }
  switch (lhs.kind()) {
    case ValueKind::Null:
      return std::strong_ordering::equal;
    case ValueKind::Bool:
      return *lhs.as_bool() <=> *rhs.as_bool();
    case ValueKind::Int:
      return *lhs.as_int() <=> *rhs.as_int();
    case ValueKind::Uint:
      return *lhs.as_uint() <=> *rhs.as_uint();
    case ValueKind::Double: {
      // Doubles are always finite here, so a total order exists; the standard
      // three-way comparison would yield a partial order instead.
      const double left = *lhs.as_double();
      const double right = *rhs.as_double();
      if (left < right) {
        return std::strong_ordering::less;
      }
      if (left > right) {
        return std::strong_ordering::greater;
      }
      return std::strong_ordering::equal;
    }
    case ValueKind::String:
      return *lhs.as_string() <=> *rhs.as_string();
    case ValueKind::Bytes:
      return *lhs.as_bytes() <=> *rhs.as_bytes();
    case ValueKind::List:
      return *lhs.as_list() <=> *rhs.as_list();
    case ValueKind::Map:
      return *lhs.as_map() <=> *rhs.as_map();
  }
  return std::strong_ordering::equal;
}

std::size_t Value::NodeCount() const {
  return CountNodes(*this, 0);
}

std::size_t Value::MaxDepth() const {
  return CountDepth(*this, 0);
}

std::size_t Value::ApproximateBytes() const {
  std::size_t total = 0;
  MeasureBytes(*this, 0, total);
  return total;
}

Status Value::Validate(const RuntimeLimits& limits) const {
  if (NodeCount() > limits.max_value_nodes) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded, "value node count exceeds the envelope");
  }
  return ValidateValue(*this, limits, 0);
}

namespace {

ValueRelation RelateValuesAt(const Value& lhs, const Value& rhs, NumericEquivalence equivalence,
                             std::size_t depth);

bool RelateNumerics(const Value& lhs, const Value& rhs, bool& equal) {
  const std::int64_t* lhs_int = lhs.as_int();
  const std::uint64_t* lhs_uint = lhs.as_uint();
  const double* lhs_double = lhs.as_double();
  const std::int64_t* rhs_int = rhs.as_int();
  const std::uint64_t* rhs_uint = rhs.as_uint();
  const double* rhs_double = rhs.as_double();
  if (lhs_int != nullptr && rhs_int != nullptr) {
    equal = *lhs_int == *rhs_int;
    return true;
  }
  if (lhs_uint != nullptr && rhs_uint != nullptr) {
    equal = *lhs_uint == *rhs_uint;
    return true;
  }
  if (lhs_int != nullptr && rhs_uint != nullptr) {
    equal = *lhs_int >= 0 && static_cast<std::uint64_t>(*lhs_int) == *rhs_uint;
    return true;
  }
  if (lhs_uint != nullptr && rhs_int != nullptr) {
    equal = *rhs_int >= 0 && static_cast<std::uint64_t>(*rhs_int) == *lhs_uint;
    return true;
  }
  if (lhs_double != nullptr && rhs_double != nullptr) {
    equal = *lhs_double == *rhs_double;
    return true;
  }
  if (lhs_int != nullptr && rhs_double != nullptr) {
    const double other = *rhs_double;
    equal = std::isfinite(other) && std::floor(other) == other &&
            other >= -9223372036854775808.0 && other < 9223372036854775808.0 &&
            static_cast<std::int64_t>(other) == *lhs_int;
    return true;
  }
  if (lhs_double != nullptr && rhs_int != nullptr) {
    const double other = *lhs_double;
    equal = std::isfinite(other) && std::floor(other) == other &&
            other >= -9223372036854775808.0 && other < 9223372036854775808.0 &&
            static_cast<std::int64_t>(other) == *rhs_int;
    return true;
  }
  if (lhs_uint != nullptr && rhs_double != nullptr) {
    const double other = *rhs_double;
    equal = std::isfinite(other) && std::floor(other) == other && other >= 0.0 &&
            other < 18446744073709551616.0 && static_cast<std::uint64_t>(other) == *lhs_uint;
    return true;
  }
  if (lhs_double != nullptr && rhs_uint != nullptr) {
    const double other = *lhs_double;
    equal = std::isfinite(other) && std::floor(other) == other && other >= 0.0 &&
            other < 18446744073709551616.0 && static_cast<std::uint64_t>(other) == *rhs_uint;
    return true;
  }
  return false;
}

ValueRelation RelateValuesAt(const Value& lhs, const Value& rhs, NumericEquivalence equivalence,
                             std::size_t depth) {
  if (depth > kHardRecursionLimit) {
    return ValueRelation::Incomparable;
  }
  const bool lhs_numeric = lhs.kind() == ValueKind::Int || lhs.kind() == ValueKind::Uint ||
                           lhs.kind() == ValueKind::Double;
  const bool rhs_numeric = rhs.kind() == ValueKind::Int || rhs.kind() == ValueKind::Uint ||
                           rhs.kind() == ValueKind::Double;
  if (lhs_numeric && rhs_numeric) {
    if (equivalence == NumericEquivalence::Exact && lhs.kind() != rhs.kind()) {
      return ValueRelation::Different;
    }
    bool equal = false;
    if (RelateNumerics(lhs, rhs, equal)) {
      return equal ? ValueRelation::Equal : ValueRelation::Different;
    }
  }
  if (lhs.kind() != rhs.kind()) {
    if (lhs.is_null() || rhs.is_null()) {
      return ValueRelation::Incomparable;
    }
    if (lhs.is_container() != rhs.is_container()) {
      return ValueRelation::Incomparable;
    }
    return ValueRelation::Incomparable;
  }
  switch (lhs.kind()) {
    case ValueKind::Null:
      return ValueRelation::Equal;
    case ValueKind::Bool:
      return *lhs.as_bool() == *rhs.as_bool() ? ValueRelation::Equal : ValueRelation::Different;
    case ValueKind::String:
      return *lhs.as_string() == *rhs.as_string() ? ValueRelation::Equal : ValueRelation::Different;
    case ValueKind::Bytes:
      return *lhs.as_bytes() == *rhs.as_bytes() ? ValueRelation::Equal : ValueRelation::Different;
    case ValueKind::List: {
      const Value::List& left = *lhs.as_list();
      const Value::List& right = *rhs.as_list();
      if (left.size() != right.size()) {
        return ValueRelation::Different;
      }
      bool incomparable = false;
      for (std::size_t index = 0; index < left.size(); ++index) {
        const ValueRelation relation = RelateValuesAt(left[index], right[index], equivalence,
                                                      depth + 1);
        if (relation == ValueRelation::Different) {
          return ValueRelation::Different;
        }
        incomparable = incomparable || relation == ValueRelation::Incomparable;
      }
      return incomparable ? ValueRelation::Incomparable : ValueRelation::Equal;
    }
    case ValueKind::Map: {
      const Value::Map& left = *lhs.as_map();
      const Value::Map& right = *rhs.as_map();
      if (left.size() != right.size()) {
        return ValueRelation::Different;
      }
      auto left_it = left.begin();
      auto right_it = right.begin();
      bool incomparable = false;
      while (left_it != left.end() && right_it != right.end()) {
        if (left_it->first != right_it->first) {
          return ValueRelation::Different;
        }
        const ValueRelation relation =
            RelateValuesAt(left_it->second, right_it->second, equivalence, depth + 1);
        if (relation == ValueRelation::Different) {
          return ValueRelation::Different;
        }
        incomparable = incomparable || relation == ValueRelation::Incomparable;
        ++left_it;
        ++right_it;
      }
      return incomparable ? ValueRelation::Incomparable : ValueRelation::Equal;
    }
    default:
      return ValueRelation::Equal;
  }
}

}  // namespace

ValueRelation RelateValues(const Value& lhs, const Value& rhs,
                           NumericEquivalence equivalence) noexcept {
  return RelateValuesAt(lhs, rhs, equivalence, 0);
}

bool IsValidUtf8(std::string_view text) noexcept {
  std::size_t index = 0;
  while (index < text.size()) {
    const unsigned char lead = static_cast<unsigned char>(text[index]);
    std::size_t extra = 0;
    std::uint32_t codepoint = 0;
    if (lead < 0x80) {
      ++index;
      continue;
    }
    if ((lead & 0xE0) == 0xC0) {
      extra = 1;
      codepoint = lead & 0x1Fu;
      if (codepoint == 0) {
        return false;  // overlong
      }
    } else if ((lead & 0xF0) == 0xE0) {
      extra = 2;
      codepoint = lead & 0x0Fu;
    } else if ((lead & 0xF8) == 0xF0) {
      extra = 3;
      codepoint = lead & 0x07u;
    } else {
      return false;
    }
    if (index + extra >= text.size()) {
      return false;
    }
    for (std::size_t offset = 1; offset <= extra; ++offset) {
      const unsigned char continuation = static_cast<unsigned char>(text[index + offset]);
      if ((continuation & 0xC0) != 0x80) {
        return false;
      }
      codepoint = (codepoint << 6) | (continuation & 0x3Fu);
    }
    if (extra == 1 && codepoint < 0x80) {
      return false;
    }
    if (extra == 2 && codepoint < 0x800) {
      return false;
    }
    if (extra == 3 && codepoint < 0x10000) {
      return false;
    }
    if (codepoint > 0x10FFFF) {
      return false;
    }
    if (codepoint >= 0xD800 && codepoint <= 0xDFFF) {
      return false;
    }
    index += extra + 1;
  }
  return true;
}

}  // namespace network_drift_observatory
}  // namespace summon
