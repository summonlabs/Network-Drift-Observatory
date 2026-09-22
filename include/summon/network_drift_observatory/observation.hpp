// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Observation snapshots and their provenance.
//
// A snapshot is what one source claims to have seen at one target at one time.
// It carries its provenance (source, epoch, incarnation, sequence), its
// collection time, its requested time-to-live, its coverage declaration and a
// content digest. Nothing in a snapshot is trusted: the digest is recomputed on
// ingest and the observation is refused if it does not match.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_OBSERVATION_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_OBSERVATION_HPP

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

/// What a source says about the existence of one object.
enum class ObjectPresence : std::uint8_t {
  /// The source asserts the object does not exist.
  Absent = 0,
  /// The source observed the object.
  Present = 1,
  /// The source cannot tell, or cannot assert absence. Never read as Absent.
  Unknown = 2,
};

NDO_API const char* ToText(ObjectPresence value) noexcept;
NDO_NODISCARD NDO_API bool TryParseObjectPresence(const char* text, ObjectPresence& out) noexcept;

/// How much of the target a source claims to have seen.
enum class ObservationCoverage : std::uint8_t {
  /// The source makes no claim about coverage.
  Unknown = 0,
  /// The source saw part of the target and lists what it did not see.
  Partial = 1,
  /// The source saw the whole target.
  Complete = 2,
};

NDO_API const char* ToText(ObservationCoverage value) noexcept;
NDO_NODISCARD NDO_API bool TryParseObservationCoverage(const char* text,
                                                       ObservationCoverage& out) noexcept;

/// What a source is able to assert at all. A capability is not a claim about
/// one snapshot; it is the contract of the source.
struct NDO_API SourceCapabilities {
  /// The source can assert that an object does not exist.
  bool asserts_absence{false};
  /// The source can report complete coverage of a target when it says so.
  bool complete_coverage{false};
  /// The source reports nested paths rather than flat top-level fields.
  bool reports_nested_paths{false};
  EvidenceClass evidence{EvidenceClass::Unknown};

  friend bool operator==(const SourceCapabilities&, const SourceCapabilities&) = default;
};

/// One observed object inside a snapshot.
struct NDO_API ObservedObject {
  ObjectId id;
  ObjectPresence presence{ObjectPresence::Unknown};
  std::map<FieldPath, Value> fields;

  friend bool operator==(const ObservedObject&, const ObservedObject&) = default;
};

/// One immutable observation of one target by one source.
struct NDO_API ObservationSnapshot {
  /// Content-addressed identity. Recomputed and compared on ingest.
  SnapshotId snapshot_id;
  SourceId source;
  FabricEpoch epoch;
  Incarnation incarnation;
  SourceSequence sequence;
  TargetId target;
  /// When the source says it collected the state.
  NdoTime collected_at;
  /// When the observatory received the snapshot. Stamped locally.
  NdoTime received_at;
  /// Time to live requested by the source. Zero means "use the policy value".
  /// The effective TTL is never larger than the policy value.
  std::int64_t ttl_nanos{0};
  ObservationCoverage coverage{ObservationCoverage::Unknown};
  /// Objects the source deliberately did not observe when coverage is Partial.
  std::vector<ObjectId> unobserved;
  std::map<ObjectId, ObservedObject> objects;
  SourceCapabilities capabilities;
  EvidenceClass evidence{EvidenceClass::Unknown};

  /// Digest over the canonical content of this snapshot, excluding snapshot_id
  /// and received_at (which is stamped locally and therefore not part of what
  /// the source asserted).
  NDO_NODISCARD Digest ComputeContentDigest() const;
  /// The identity implied by the content digest.
  NDO_NODISCARD SnapshotId ComputeSnapshotId() const;
  /// Checks structure, bounds, identity validity and digest agreement.
  NDO_NODISCARD Status Validate(const RuntimeLimits& limits) const;
  /// True when the snapshot declares that it saw the whole target.
  NDO_NODISCARD bool declares_complete_coverage() const noexcept;
  /// True when the snapshot may assert the absence of an object.
  NDO_NODISCARD bool may_assert_absence() const noexcept;
  NDO_NODISCARD const ObservedObject* FindObject(const ObjectId& id) const noexcept;
  /// True when the source explicitly declared it did not observe an object.
  NDO_NODISCARD bool declares_unobserved(const ObjectId& id) const noexcept;
};

/// Immutable description of one observation source.
struct NDO_API SourceDescriptor {
  SourceId id;
  SourceCapabilities capabilities;
  NdoTime registered_at;
  FabricEpoch epoch;
  Incarnation incarnation;
  std::string provenance;
  EvidenceClass evidence{EvidenceClass::Unknown};
};

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_OBSERVATION_HPP
