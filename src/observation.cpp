// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/observation.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "json_help.hpp"

namespace summon {
namespace network_drift_observatory {
namespace {

struct NamePair {
  std::uint8_t value;
  const char* name;
};

constexpr NamePair kPresenceNames[] = {
    {0, "absent"},
    {1, "present"},
    {2, "unknown"},
};

constexpr NamePair kCoverageNames[] = {
    {0, "unknown"},
    {1, "partial"},
    {2, "complete"},
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

const char* ToText(ObjectPresence value) noexcept {
  return Lookup(kPresenceNames, sizeof(kPresenceNames) / sizeof(kPresenceNames[0]),
                static_cast<std::uint8_t>(value));
}

bool TryParseObjectPresence(const char* text, ObjectPresence& out) noexcept {
  std::uint8_t raw = 0;
  if (!ParseName(kPresenceNames, sizeof(kPresenceNames) / sizeof(kPresenceNames[0]), text, raw)) {
    return false;
  }
  out = static_cast<ObjectPresence>(raw);
  return true;
}

const char* ToText(ObservationCoverage value) noexcept {
  return Lookup(kCoverageNames, sizeof(kCoverageNames) / sizeof(kCoverageNames[0]),
                static_cast<std::uint8_t>(value));
}

bool TryParseObservationCoverage(const char* text, ObservationCoverage& out) noexcept {
  std::uint8_t raw = 0;
  if (!ParseName(kCoverageNames, sizeof(kCoverageNames) / sizeof(kCoverageNames[0]), text, raw)) {
    return false;
  }
  out = static_cast<ObservationCoverage>(raw);
  return true;
}

Digest ObservationSnapshot::ComputeContentDigest() const {
  Sha256 hasher;
  hasher.UpdateTag(detail::kSnapshotIdentityTag);
  hasher.UpdateLengthPrefixed(source.str());
  hasher.UpdateU64(epoch.value());
  hasher.UpdateU64(incarnation.value());
  hasher.UpdateU64(sequence.value());
  hasher.UpdateLengthPrefixed(target.str());
  hasher.UpdateU64(static_cast<std::uint64_t>(collected_at.unix_nanos));
  hasher.UpdateU64(static_cast<std::uint64_t>(ttl_nanos));
  hasher.UpdateByte(static_cast<std::uint8_t>(coverage));
  hasher.UpdateByte(static_cast<std::uint8_t>(evidence));
  hasher.UpdateByte(capabilities.asserts_absence ? 1u : 0u);
  hasher.UpdateByte(capabilities.complete_coverage ? 1u : 0u);
  hasher.UpdateByte(capabilities.reports_nested_paths ? 1u : 0u);
  hasher.UpdateByte(static_cast<std::uint8_t>(capabilities.evidence));
  // The set of unobserved objects is a set: order must not change identity.
  std::vector<std::string_view> unobserved_view;
  unobserved_view.reserve(this->unobserved.size());
  for (const ObjectId& id : this->unobserved) {
    unobserved_view.push_back(id.str());
  }
  std::sort(unobserved_view.begin(), unobserved_view.end());
  unobserved_view.erase(std::unique(unobserved_view.begin(), unobserved_view.end()),
                        unobserved_view.end());
  hasher.UpdateU64(unobserved_view.size());
  for (std::string_view id : unobserved_view) {
    hasher.UpdateLengthPrefixed(id);
  }
  hasher.UpdateU64(objects.size());
  for (const auto& entry : objects) {
    hasher.UpdateLengthPrefixed(entry.first.str());
    hasher.UpdateByte(static_cast<std::uint8_t>(entry.second.presence));
    hasher.UpdateU64(entry.second.fields.size());
    for (const auto& field : entry.second.fields) {
      hasher.UpdateLengthPrefixed(field.first.ToText());
      field.second.HashInto(hasher);
    }
  }
  return hasher.Final();
}

SnapshotId ObservationSnapshot::ComputeSnapshotId() const {
  return SnapshotId::Trusted(ComputeContentDigest().ToHex());
}

bool ObservationSnapshot::declares_complete_coverage() const noexcept {
  return coverage == ObservationCoverage::Complete && capabilities.complete_coverage;
}

bool ObservationSnapshot::may_assert_absence() const noexcept {
  return capabilities.asserts_absence;
}

const ObservedObject* ObservationSnapshot::FindObject(const ObjectId& id) const noexcept {
  const auto found = objects.find(id);
  if (found == objects.end()) {
    return nullptr;
  }
  return &found->second;
}

bool ObservationSnapshot::declares_unobserved(const ObjectId& id) const noexcept {
  for (const ObjectId& candidate : unobserved) {
    if (candidate == id) {
      return true;
    }
  }
  return false;
}

Status ObservationSnapshot::Validate(const RuntimeLimits& limits) const {
  if (!IsValidIdentityText(source.str())) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "observation source identity is invalid");
  }
  if (!IsValidIdentityText(target.str())) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "observation target identity is invalid");
  }
  if (!epoch.is_set()) {
    return Status::Rejected(ReasonCode::FencedStaleEpoch,
                            "observation must declare the epoch it was collected under");
  }
  if (!incarnation.is_set()) {
    return Status::Rejected(ReasonCode::FencedStaleIncarnation,
                            "observation must declare the source incarnation that produced it");
  }
  if (!sequence.is_set()) {
    return Status::Rejected(ReasonCode::ObservationSequenceRegressed,
                            "observation sequence must be positive");
  }
  if (!collected_at.is_set()) {
    return Status::Rejected(ReasonCode::ObservationClockRegression,
                            "observation must declare its collection time");
  }
  if (ttl_nanos < 0) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "observation ttl must not be negative");
  }
  if (unobserved.size() > limits.max_objects_per_target) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded,
                         "unobserved declaration exceeds the envelope");
  }
  for (const ObjectId& id : unobserved) {
    if (!IsValidIdentityText(id.str())) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "unobserved identity is invalid");
    }
  }
  if (objects.size() > limits.max_objects_per_target) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded,
                         "observation object count exceeds the envelope");
  }
  for (const auto& entry : objects) {
    if (!IsValidIdentityText(entry.first.str())) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "observed object identity is invalid");
    }
    const ObservedObject& object = entry.second;
    if (object.presence == ObjectPresence::Absent && !capabilities.asserts_absence) {
      // A source that cannot assert absence must not report one. Accepting it
      // would let an unqualified source declare a target non-compliant.
      return Status::Rejected(ReasonCode::ObservationSourceCannotAssertAbsence,
                              "source reports absence without the capability to assert it");
    }
    if (object.fields.size() > limits.max_fields_per_object) {
      return Status::Limit(ReasonCode::LimitFieldsExceeded,
                           "observed field count exceeds the envelope");
    }
    if (object.presence == ObjectPresence::Absent && !object.fields.empty()) {
      return Status::Rejected(ReasonCode::EncodingMalformed,
                              "an absent object cannot carry observed fields");
    }
    for (const auto& field : object.fields) {
      if (field.first.size() > limits.max_path_segments) {
        return Status::Limit(ReasonCode::LimitDepthExceeded, "observed field path is too deep");
      }
      for (const PathSegment& segment : field.first.segments()) {
        if (segment.kind == PathSegment::Kind::Key &&
            segment.key.size() > limits.max_path_key_bytes) {
          return Status::Limit(ReasonCode::LimitBytesExceeded, "observed field key is too long");
        }
      }
      Status status = field.second.Validate(limits);
      if (!status.ok()) {
        return status;
      }
    }
  }
  const Digest computed = ComputeContentDigest();
  if (snapshot_id.empty()) {
    return Status::Rejected(ReasonCode::LedgerIntegrityDigestMismatch,
                            "observation snapshot identity is missing");
  }
  if (snapshot_id.str() != computed.ToHex()) {
    return Status::Rejected(ReasonCode::LedgerIntegrityDigestMismatch,
                            "declared snapshot identity does not match snapshot content");
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

}  // namespace network_drift_observatory
}  // namespace summon
