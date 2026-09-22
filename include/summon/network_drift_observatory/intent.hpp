// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Typed intent generations.
//
// Intent is the authoritative statement of what a target must look like. It
// arrives as a generated document, and the observatory compares observations
// against exactly one committed generation per target. A generation regression,
// an epoch regression or a duplicate generation with different content is
// refused, never merged.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_INTENT_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_INTENT_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "summon/network_drift_observatory/hash.hpp"
#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/time.hpp"
#include "summon/network_drift_observatory/value.hpp"

namespace summon {
namespace network_drift_observatory {

/// Which authority produced an intent generation.
///
/// The observatory never rewrites intent. It records the authority it compared
/// against so that a finding can always name the baseline it used.
enum class IntentAuthority : std::uint8_t {
  Unknown = 0,
  /// Intent Fabric produced the generation.
  IntentFabric = 1,
  /// Configuration Fabric produced the generation.
  ConfigurationFabric = 2,
  /// A local observatory policy file produced the generation.
  LocalPolicy = 3,
  /// A document imported from an unspecified authority.
  ImportedDocument = 4,
};

NDO_API const char* ToText(IntentAuthority value) noexcept;
NDO_NODISCARD NDO_API bool TryParseIntentAuthority(const char* text, IntentAuthority& out) noexcept;

/// How a field participates in comparison.
enum class FieldComparability : std::uint8_t {
  /// Must match; a difference is drift.
  Managed = 0,
  /// Reported for context, never a drift source on its own.
  ObserveOnly = 1,
  /// Explicitly excluded from comparison by the intent author.
  Unmanaged = 2,
  /// The intent author states that no source can observe it. Comparisons
  /// against it are reported as Unknown, never as compliance.
  Unobservable = 3,
  /// The intent author states the runtime does not support this field's class.
  Unsupported = 4,
};

NDO_API const char* ToText(FieldComparability value) noexcept;
NDO_NODISCARD NDO_API bool TryParseFieldComparability(const char* text,
                                                      FieldComparability& out) noexcept;

/// One intended field inside an intent object.
struct NDO_API IntentField {
  FieldPath path;
  Value intended;
  FieldComparability comparability{FieldComparability::Managed};

  friend bool operator==(const IntentField&, const IntentField&) = default;
};

/// Whether the intent requires the object to exist.
enum class ObjectExistence : std::uint8_t {
  /// The object must exist at the target.
  Required = 0,
  /// The object must not exist at the target.
  Forbidden = 1,
};

NDO_API const char* ToText(ObjectExistence value) noexcept;

/// One intent object inside a target.
struct NDO_API IntentObject {
  ObjectId id;
  ObjectExistence existence{ObjectExistence::Required};
  std::map<FieldPath, IntentField> fields;

  friend bool operator==(const IntentObject&, const IntentObject&) = default;
};

/// A complete, self-describing intent generation for one target.
struct NDO_API IntentGenerationDocument {
  TargetId target;
  IntentGeneration generation;
  FabricEpoch epoch;
  IntentAuthority authority{IntentAuthority::Unknown};
  PolicyId policy;
  NdoTime authored_at;
  std::map<ObjectId, IntentObject> objects;
  EvidenceClass evidence{EvidenceClass::Unknown};

  /// Digest over the canonical content of this document, excluding the digest
  /// itself. Used to detect divergent re-publication of one generation.
  NDO_NODISCARD Digest ComputeContentDigest() const;
  /// Checks structure, bounds and identity validity.
  NDO_NODISCARD Status Validate(const RuntimeLimits& limits) const;
  NDO_NODISCARD std::size_t ObjectCount() const noexcept { return objects.size(); }
  NDO_NODISCARD std::size_t FieldCount() const noexcept;
};

/// The committed baseline for one target: exactly one generation.
struct NDO_API IntentBaseline {
  TargetId target;
  IntentGeneration generation;
  FabricEpoch epoch;
  IntentAuthority authority{IntentAuthority::Unknown};
  PolicyId policy;
  NdoTime committed_at;
  Digest content_digest;
  EvidenceClass evidence{EvidenceClass::Unknown};
  std::map<ObjectId, IntentObject> objects;

  NDO_NODISCARD bool is_set() const noexcept { return generation.is_set(); }
  NDO_NODISCARD const IntentObject* FindObject(const ObjectId& id) const noexcept;
};

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_INTENT_HPP
