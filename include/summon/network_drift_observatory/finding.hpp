// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Drift findings and their deterministic identity.
//
// A finding is identified by the location it concerns, the class of divergence
// and the intent generation it was compared against -- never by the values that
// happen to differ today. Persistent drift therefore updates one finding
// instead of creating a new one on every evaluation.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_FINDING_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_FINDING_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "summon/network_drift_observatory/comparison.hpp"
#include "summon/network_drift_observatory/drift.hpp"
#include "summon/network_drift_observatory/freshness.hpp"
#include "summon/network_drift_observatory/hash.hpp"
#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/intent.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/time.hpp"
#include "summon/network_drift_observatory/value.hpp"

namespace summon {
namespace network_drift_observatory {

/// Lifecycle state of one finding.
enum class FindingState : std::uint8_t {
  /// Divergence is present under the current baseline and is not suppressed.
  Open = 0,
  /// An operator has seen it. Acknowledgement never changes compliance truth
  /// and never removes the finding from the compliance computation.
  Acknowledged = 1,
  /// A suppression currently applies. The finding, its evidence and its
  /// compliance truth are unchanged; only reporting and export are affected.
  Suppressed = 2,
  /// Fresh, sufficiently covering evidence agreed with intent, for the
  /// configured number of confirmations.
  Resolved = 3,
  /// The finding was replaced by a differently classified finding at the same
  /// location. It did not disappear; it was re-explained.
  Superseded = 4,
  /// The observable was genuinely withdrawn from the baseline (the intent no
  /// longer manages this location). Historical evidence is retained.
  Retired = 5,
};

NDO_API const char* ToText(FindingState value) noexcept;
NDO_NODISCARD NDO_API bool TryParseFindingState(const char* text, FindingState& out) noexcept;
/// True when the state participates in the current compliance computation.
NDO_NODISCARD NDO_API bool IsLiveState(FindingState value) noexcept;

/// Where a suppression came from. A policy suppression ends when the policy no
/// longer matches; an operator suppression ends only when it is cleared or
/// expires. Neither ever erases the underlying evidence.
enum class SuppressionOrigin : std::uint8_t {
  None = 0,
  Policy = 1,
  Operator = 2,
};

NDO_API const char* ToText(SuppressionOrigin value) noexcept;
NDO_NODISCARD NDO_API bool TryParseSuppressionOrigin(const char* text,
                                                     SuppressionOrigin& out) noexcept;

/// One entry in a finding's timeline.
enum class TimelineEventKind : std::uint8_t {
  Created = 0,
  Updated = 1,
  Reopened = 2,
  Resolved = 3,
  Suppressed = 4,
  SuppressionExpired = 5,
  SuppressionCleared = 6,
  Acknowledged = 7,
  AcknowledgementCleared = 8,
  Reclassified = 9,
  Rebased = 10,
  EvidenceRecovered = 11,
  Grouped = 12,
  Retired = 13,
};

inline constexpr std::size_t kTimelineEventKindCount = 14;

NDO_API const char* ToText(TimelineEventKind value) noexcept;
NDO_NODISCARD NDO_API bool TryParseTimelineEventKind(const char* text,
                                                     TimelineEventKind& out) noexcept;

struct NDO_API TimelineEntry {
  TimelineEventKind kind{TimelineEventKind::Created};
  /// The location the transition concerns. A target-level transition (an intent
  /// generation commit, for example) leaves `finding` unset and records the
  /// reserved scope object instead.
  TargetId target;
  ObjectId object;
  FindingId finding;
  /// Global monotonic sequence assigned by the ledger. Orders entries even when
  /// two events share a timestamp.
  std::uint64_t sequence{0};
  NdoTime at;
  FindingState state_after{FindingState::Open};
  DriftClass klass{DriftClass::None};
  Severity severity{Severity::Medium};
  ReasonCode reason{ReasonCode::None};
  IntentGeneration baseline_generation;
  FabricEpoch baseline_epoch;
  Digest evidence_digest;
  ActorId actor;
  std::string detail;

  friend bool operator==(const TimelineEntry&, const TimelineEntry&) = default;
};

/// Why several leaf findings were attributed to one divergence.
enum class RootCauseKind : std::uint8_t {
  None = 0,
  /// One field differs. Not a group; recorded for symmetry only.
  SingleField = 1,
  /// The target has not applied the intended generation at all.
  GenerationNotApplied = 2,
  /// The target applied the intended generation to some objects only.
  PartialApplication = 3,
  /// Two live sources disagree about the same location.
  SourceConflict = 4,
  /// The only evidence available is not fresh.
  StaleEvidence = 5,
  /// Coverage is insufficient to decide.
  InsufficientCoverage = 6,
  /// A target policy requires intent and none is committed.
  MissingIntent = 7,
  /// A field lies outside the supported comparison class.
  UnsupportedField = 8,
};

inline constexpr std::size_t kRootCauseKindCount = 9;

NDO_API const char* ToText(RootCauseKind value) noexcept;

/// A root-cause group: one generation or application divergence that explains
/// several leaf findings. The raw findings are always preserved; a group never
/// replaces or hides them.
struct NDO_API RootCauseGroup {
  GroupId id;
  TargetId target;
  IntentGeneration baseline_generation;
  FabricEpoch baseline_epoch;
  RootCauseKind cause{RootCauseKind::None};
  Digest discriminator;
  std::vector<FindingId> members;
  std::vector<ObjectId> objects;
  std::string summary;
  std::uint64_t observation_count{0};
  NdoTime first_seen;
  NdoTime last_seen;

  NDO_NODISCARD std::size_t size() const noexcept { return members.size(); }
};

/// The deterministic identity inputs of a finding.
struct NDO_API FindingIdentity {
  TargetId target;
  ObjectId object;
  FieldPath path;
  DriftClass klass{DriftClass::None};
  IntentGeneration baseline_generation;
  Digest qualifier;

  /// The stable identity digest. Ordering of the members is fixed.
  NDO_NODISCARD FindingId ComputeId() const;
  friend bool operator==(const FindingIdentity&, const FindingIdentity&) = default;
};

/// One drift finding: the durable record of a divergence.
struct NDO_API Finding {
  FindingId id;
  FindingIdentity identity;
  DriftClass klass{DriftClass::None};
  DriftClass raw_class{DriftClass::None};
  Severity severity{Severity::Medium};
  FindingState state{FindingState::Open};
  ReasonCode reason{ReasonCode::None};

  IntentGeneration baseline_generation;
  FabricEpoch baseline_epoch;
  IntentAuthority baseline_authority{IntentAuthority::Unknown};
  PolicyId policy;
  Digest policy_digest;

  bool has_intended{false};
  Value intended;
  bool has_observed{false};
  Value observed;

  std::vector<EvidenceRef> evidence;
  FreshnessState evidence_freshness{FreshnessState::Unknown};

  GroupId group;
  RootCauseKind group_cause{RootCauseKind::None};

  /// Number of evaluation passes that observed this divergence. Monotonic.
  std::uint64_t observation_count{0};
  std::uint64_t reopen_count{0};
  /// Consecutive fresh agreements observed while the finding was live.
  std::uint32_t resolution_confirmations{0};

  NdoTime first_seen;
  NdoTime last_seen;
  NdoTime last_evaluated;
  NdoTime resolved_at;

  /// Suppression state. A suppression never erases the finding or its history.
  std::optional<SuppressionId> suppression;
  SuppressionOrigin suppression_origin{SuppressionOrigin::None};
  ActorId suppressed_by;
  std::string suppression_reason;
  std::optional<NdoTime> suppression_expires_at;

  ActorId acknowledged_by;
  NdoTime acknowledged_at;
  std::string acknowledgement_reason;

  /// Deterministic explanation of the current state.
  std::string summary;
  /// True when this finding can make a target non-compliant. Suppressed and
  /// acknowledged findings keep the same value they had before.
  bool compliance_relevant{true};

  std::vector<TimelineEntry> timeline;

  NDO_NODISCARD bool is_live() const noexcept { return IsLiveState(state); }
  NDO_NODISCARD bool is_suppressed() const noexcept {
    return state == FindingState::Suppressed;
  }
  /// Age in nanoseconds relative to the supplied clock reading.
  NDO_NODISCARD std::int64_t AgeNanos(NdoTime now) const noexcept;
};

/// Deterministic one-line explanation of a finding.
NDO_NODISCARD NDO_API std::string ExplainFinding(const Finding& finding);

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_FINDING_HPP
