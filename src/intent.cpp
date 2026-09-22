// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/intent.hpp"

#include <cstdint>
#include <string>
#include <string_view>

#include "json_help.hpp"

namespace summon {
namespace network_drift_observatory {
namespace {

struct NamePair {
  std::uint8_t value;
  const char* name;
};

constexpr NamePair kAuthorityNames[] = {
    {0, "unknown"},      {1, "intent-fabric"}, {2, "configuration-fabric"},
    {3, "local-policy"}, {4, "imported-document"},
};

constexpr NamePair kComparabilityNames[] = {
    {0, "managed"}, {1, "observe-only"}, {2, "unmanaged"}, {3, "unobservable"}, {4, "unsupported"},
};

constexpr NamePair kExistenceNames[] = {
    {0, "required"},
    {1, "forbidden"},
};

constexpr const char* Lookup(const NamePair* table, std::size_t count, std::uint8_t value) noexcept {
  for (std::size_t index = 0; index < count; ++index) {
    if (table[index].value == value) {
      return table[index].name;
    }
  }
  return "invalid";
}

bool ParseName(const NamePair* table, std::size_t count, const char* text,
               std::uint8_t& out) noexcept {
  if (text == nullptr) {
    return false;
  }
  const std::string_view wanted(text);
  for (std::size_t index = 0; index < count; ++index) {
    if (wanted == table[index].name) {
      out = table[index].value;
      return true;
    }
  }
  return false;
}

}  // namespace

const char* ToText(IntentAuthority value) noexcept {
  return Lookup(kAuthorityNames, sizeof(kAuthorityNames) / sizeof(kAuthorityNames[0]),
                static_cast<std::uint8_t>(value));
}

bool TryParseIntentAuthority(const char* text, IntentAuthority& out) noexcept {
  std::uint8_t raw = 0;
  if (!ParseName(kAuthorityNames, sizeof(kAuthorityNames) / sizeof(kAuthorityNames[0]), text, raw)) {
    return false;
  }
  out = static_cast<IntentAuthority>(raw);
  return true;
}

const char* ToText(FieldComparability value) noexcept {
  return Lookup(kComparabilityNames, sizeof(kComparabilityNames) / sizeof(kComparabilityNames[0]),
                static_cast<std::uint8_t>(value));
}

bool TryParseFieldComparability(const char* text, FieldComparability& out) noexcept {
  std::uint8_t raw = 0;
  if (!ParseName(kComparabilityNames, sizeof(kComparabilityNames) / sizeof(kComparabilityNames[0]),
                 text, raw)) {
    return false;
  }
  out = static_cast<FieldComparability>(raw);
  return true;
}

const char* ToText(ObjectExistence value) noexcept {
  return Lookup(kExistenceNames, sizeof(kExistenceNames) / sizeof(kExistenceNames[0]),
                static_cast<std::uint8_t>(value));
}

Digest IntentGenerationDocument::ComputeContentDigest() const {
  Sha256 hasher;
  hasher.UpdateTag(detail::kIntentContentTag);
  hasher.UpdateLengthPrefixed(target.str());
  hasher.UpdateU64(generation.value());
  hasher.UpdateU64(epoch.value());
  hasher.UpdateLengthPrefixed(ToText(authority));
  hasher.UpdateLengthPrefixed(policy.str());
  hasher.UpdateU64(static_cast<std::uint64_t>(authored_at.unix_nanos));
  hasher.UpdateByte(static_cast<std::uint8_t>(evidence));
  hasher.UpdateU64(objects.size());
  for (const auto& entry : objects) {
    hasher.UpdateLengthPrefixed(entry.first.str());
    hasher.UpdateByte(static_cast<std::uint8_t>(entry.second.existence));
    hasher.UpdateU64(entry.second.fields.size());
    for (const auto& field : entry.second.fields) {
      hasher.UpdateLengthPrefixed(field.first.ToText());
      hasher.UpdateByte(static_cast<std::uint8_t>(field.second.comparability));
      field.second.intended.HashInto(hasher);
    }
  }
  return hasher.Final();
}

std::size_t IntentGenerationDocument::FieldCount() const noexcept {
  std::size_t total = 0;
  for (const auto& entry : objects) {
    total += entry.second.fields.size();
  }
  return total;
}

Status IntentGenerationDocument::Validate(const RuntimeLimits& limits) const {
  if (!IsValidIdentityText(target.str())) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "target identity is invalid");
  }
  if (!generation.is_set()) {
    return Status::Rejected(ReasonCode::IntentTargetUndeclared,
                            "intent generation must be a positive generation");
  }
  if (!epoch.is_set()) {
    return Status::Rejected(ReasonCode::FencedStaleEpoch,
                            "intent generation must declare the epoch it was authored under");
  }
  if (policy.empty() || !IsValidIdentityText(policy.str())) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "intent policy identity is invalid");
  }
  if (authority == IntentAuthority::Unknown) {
    return Status::Rejected(ReasonCode::AuthorityMismatch,
                            "intent generation must declare the authority that produced it");
  }
  if (objects.size() > limits.max_objects_per_target) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded, "intent object count exceeds the envelope");
  }
  for (const auto& entry : objects) {
    if (!IsValidIdentityText(entry.first.str())) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "intent object identity is invalid");
    }
    const IntentObject& object = entry.second;
    if (object.fields.size() > limits.max_fields_per_object) {
      return Status::Limit(ReasonCode::LimitFieldsExceeded, "intent field count exceeds the envelope");
    }
    for (const auto& field : object.fields) {
      if (field.first.size() > limits.max_path_segments) {
        return Status::Limit(ReasonCode::LimitDepthExceeded, "intent field path is too deep");
      }
      for (const PathSegment& segment : field.first.segments()) {
        if (segment.kind == PathSegment::Kind::Key && segment.key.size() > limits.max_path_key_bytes) {
          return Status::Limit(ReasonCode::LimitBytesExceeded, "intent field key is too long");
        }
      }
      Status status = field.second.intended.Validate(limits);
      if (!status.ok()) {
        return status;
      }
    }
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

const IntentObject* IntentBaseline::FindObject(const ObjectId& id) const noexcept {
  const auto found = objects.find(id);
  if (found == objects.end()) {
    return nullptr;
  }
  return &found->second;
}

}  // namespace network_drift_observatory
}  // namespace summon
