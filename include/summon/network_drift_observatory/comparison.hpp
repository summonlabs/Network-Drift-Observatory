// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Canonical comparison of intent against observed state.
//
// The comparator is a pure function of (committed intent baseline, live
// snapshots, their freshness verdicts, policy, "now" and the live epoch). It
// has no other inputs: results never depend on container order, arrival order,
// hash seeds or which thread performed the comparison. Identical inputs
// therefore yield identical findings.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_COMPARISON_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_COMPARISON_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "summon/network_drift_observatory/drift.hpp"
#include "summon/network_drift_observatory/freshness.hpp"
#include "summon/network_drift_observatory/hash.hpp"
#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/intent.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/observation.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/policy.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/time.hpp"
#include "summon/network_drift_observatory/value.hpp"

namespace summon {
namespace network_drift_observatory {

/// Reserved object identity used by target-scope findings and timeline
/// entries that do not concern one object.
inline constexpr const char* kTargetScopeObjectId = "@target";

/// Field path prefix that a source uses to report the intent generation it has
/// actually applied at the target. Reserved: never compared as a managed field,
/// but used to separate "the change was never applied" from "the change was
/// applied partially" and from "the value is simply wrong".
inline constexpr const char* kAppliedGenerationPath = "@applied-generation";
/// Field path prefix for source-reported free-form metadata. Ignored in
/// comparison but preserved in evidence.
inline constexpr const char* kMetadataPathPrefix = "@";

/// One reference to the evidence a finding was derived from.
struct NDO_API EvidenceRef {
  SourceId source;
  SnapshotId snapshot;
  FabricEpoch epoch;
  Incarnation incarnation;
  SourceSequence sequence;
  NdoTime collected_at;
  NdoTime received_at;
  FreshnessState freshness{FreshnessState::Unknown};
  Digest content_digest;
  ObservationCoverage coverage{ObservationCoverage::Unknown};
  EvidenceClass evidence{EvidenceClass::Unknown};

  friend bool operator==(const EvidenceRef&, const EvidenceRef&) = default;
};

/// A single leaf divergence discovered by the comparator, before the ledger
/// assigns identity, lifecycle or grouping.
struct NDO_API FindingDraft {
  TargetId target;
  ObjectId object;
  FieldPath path;
  DriftClass klass{DriftClass::None};
  /// The leaf class before any generation-level regrouping. Preserved so a
  /// reader can always see the raw difference even when the finding is
  /// reported as a partial application or a generation mismatch.
  DriftClass raw_class{DriftClass::None};
  Severity severity{Severity::Medium};
  ReasonCode reason{ReasonCode::None};
  IntentGeneration baseline_generation;
  FabricEpoch baseline_epoch;
  IntentAuthority baseline_authority{IntentAuthority::Unknown};
  bool has_intended{false};
  Value intended;
  bool has_observed{false};
  Value observed;
  std::vector<EvidenceRef> evidence;
  /// Distinguishes findings that share a location and class but arise from
  /// different divergences (a different applied generation, a different
  /// conflicting source pair). Empty for ordinary findings.
  Digest qualifier;
  /// True when this draft can contribute to a compliance conclusion.
  bool compliance_relevant{true};
  /// Ordered decision trace: why this draft exists, deterministic and bounded.
  std::vector<std::string> rationale;
};

/// Per-target comparison result.
struct NDO_API TargetEvaluation {
  TargetId target;
  bool has_baseline{false};
  IntentGeneration baseline_generation;
  FabricEpoch baseline_epoch;
  IntentAuthority baseline_authority{IntentAuthority::Unknown};
  /// Freshness of the best available evidence, whether or not it is fresh.
  FreshnessState best_freshness{FreshnessState::Unknown};
  std::size_t sources_considered{0};
  std::size_t fresh_sources{0};
  /// True only when fresh evidence with sufficient coverage covers the target.
  /// The absence of fresh evidence never yields true.
  bool compliance_decidable{false};
  /// Meaningful only when compliance_decidable is true.
  bool compliant{false};
  ReasonCode decision_reason{ReasonCode::NoFreshEvidence};
  std::vector<FindingDraft> drafts;
  /// Deterministic trace of the decision for this target.
  std::vector<std::string> trace;
};

/// The complete result of one evaluation pass. Evaluating the same ledger
/// contents with the same clock reading yields a byte-identical outcome.
struct NDO_API EvaluationOutcome {
  NdoTime now;
  FabricEpoch epoch;
  Incarnation incarnation;
  PolicyId policy;
  Digest policy_digest;
  /// Resolution confirmations in force when this outcome was computed. Carried
  /// with the outcome so applying it never depends on a mutable policy.
  std::uint32_t resolution_confirmations{1};
  std::uint64_t sequence{0};
  std::vector<TargetEvaluation> targets;

  NDO_NODISCARD std::size_t DraftCount() const noexcept;
  NDO_NODISCARD Digest ComputeDigest() const;
};

/// Input for one target: the committed baseline (if any) and the candidate
/// snapshots with their freshness verdicts, already filtered for epoch and
/// integrity by the caller.
struct NDO_API TargetComparisonInput {
  TargetId target;
  std::optional<IntentBaseline> baseline;
  /// Candidate snapshots. Order is irrelevant; the comparator sorts them.
  std::vector<const ObservationSnapshot*> snapshots;
  /// Freshness verdict per candidate, index-aligned with snapshots.
  std::vector<FreshnessVerdict> freshness;
};

/// Compares one target. Pure and deterministic; safe to call concurrently.
NDO_NODISCARD NDO_API TargetEvaluation CompareTarget(const TargetComparisonInput& input,
                                                     const ObservatoryPolicy& policy,
                                                     const RuntimeLimits& limits);

/// Deterministic human-readable explanation of one draft. The text depends
/// only on the draft and the policy.
NDO_NODISCARD NDO_API std::string ExplainDraft(const FindingDraft& draft,
                                               const ObservatoryPolicy& policy);

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_COMPARISON_HPP
