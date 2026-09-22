// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The finding ledger.
//
// The ledger owns committed intent baselines, the live evidence window, the
// findings derived from them, their timelines, their root-cause groups and the
// suppression and acknowledgement records. It is the only authority for what
// the observatory believes, and every mutation is refused when it would violate
// a generation, epoch or integrity rule.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_LEDGER_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_LEDGER_HPP

#include <compare>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "summon/network_drift_observatory/comparison.hpp"
#include "summon/network_drift_observatory/drift.hpp"
#include "summon/network_drift_observatory/finding.hpp"
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

namespace summon {
namespace network_drift_observatory {

/// Outcome of committing one intent generation.
struct NDO_API IntentCommitReport {
  TargetId target;
  IntentGeneration previous_generation;
  IntentGeneration committed_generation;
  FabricEpoch epoch;
  /// Number of findings that were rebased or retired because the baseline
  /// changed under them.
  std::size_t findings_rebased{0};
  std::size_t findings_retired{0};
  bool duplicate_identical{false};
};

/// Outcome of admitting one observation snapshot.
struct NDO_API ObservationAdmission {
  SnapshotId snapshot;
  SourceId source;
  TargetId target;
  SourceSequence sequence;
  FreshnessState freshness{FreshnessState::Unknown};
  /// True when the snapshot was an exact duplicate of the retained one and was
  /// therefore not stored again.
  bool duplicate_identical{false};
  /// True when an older snapshot for this source was superseded.
  bool superseded_older{false};

  friend bool operator==(const ObservationAdmission&, const ObservationAdmission&) = default;
};

/// Outcome of applying one evaluation pass to the ledger.
struct NDO_API LedgerApplyReport {
  std::size_t created{0};
  std::size_t updated{0};
  std::size_t reopened{0};
  std::size_t resolved{0};
  std::size_t suppressed{0};
  std::size_t superseded{0};
  std::size_t retired{0};
  std::size_t unchanged{0};
  /// Targets whose drafts were refused because the committed baseline moved
  /// while the evaluation was running.
  std::size_t fenced_targets{0};
  std::size_t groups_touched{0};
  std::vector<FindingId> created_ids;
  std::vector<FindingId> resolved_ids;
};

/// One retained observation snapshot plus its verdict.
struct NDO_API RetainedObservation {
  ObservationSnapshot snapshot;
  FreshnessVerdict freshness;
  /// True when the snapshot came from durable state and has not been replaced
  /// by a live observation in this incarnation. Such evidence is never fresh.
  bool recovered{false};
};

/// Why a suppression ended.
enum class SuppressionEndReason : std::uint8_t {
  Cleared = 0,
  Expired = 1,
  FindingResolved = 2,
  FindingSuperseded = 3,
};

NDO_API const char* ToText(SuppressionEndReason value) noexcept;

/// Counters describing ledger content. Used by inspection tooling.
struct NDO_API LedgerStats {
  std::size_t targets{0};
  std::size_t baselines{0};
  std::size_t observations{0};
  std::size_t sources{0};
  std::size_t findings{0};
  std::size_t live_findings{0};
  std::size_t resolved_findings{0};
  std::size_t superseded_findings{0};
  std::size_t suppressed_findings{0};
  std::size_t acknowledged_findings{0};
  std::size_t groups{0};
  std::size_t timeline_entries{0};
  std::size_t suppressions_active{0};
  std::size_t suppressions_expired{0};
};

/// Bounded, deterministic, integrity-conscious store of observatory state.
///
/// Every public mutator is serialized by the observatory; the ledger itself
/// publishes no callbacks and acquires no locks, so it can never deadlock or
/// re-enter its owner.
class NDO_API FindingLedger {
 public:
  explicit FindingLedger(RuntimeLimits limits = RuntimeLimits{});
  FindingLedger(const FindingLedger&) = delete;
  FindingLedger& operator=(const FindingLedger&) = delete;
  FindingLedger(FindingLedger&&) = default;
  FindingLedger& operator=(FindingLedger&&) = default;

  NDO_NODISCARD const RuntimeLimits& limits() const noexcept { return limits_; }
  void SetLimits(const RuntimeLimits& limits) noexcept { limits_ = limits; }

  // ---- intent ----
  /// Commits one intent generation. Refuses a regression, a foreign epoch, a
  /// divergent re-publication of the current generation and any bound breach.
  Status CommitIntent(const IntentGenerationDocument& document, NdoTime now,
                      IntentCommitReport& report);
  NDO_NODISCARD const IntentBaseline* FindBaseline(const TargetId& target) const noexcept;
  NDO_NODISCARD std::vector<TargetId> Targets() const;

  // ---- observations ----
  /// Admits one snapshot. Refuses stale sequence numbers, foreign epochs,
  /// foreign incarnations, foreign targets and bound breaches. An exact
  /// duplicate is accepted but not stored twice.
  Status RecordObservation(const ObservationSnapshot& snapshot, const FreshnessVerdict& verdict,
                           bool recovered, ObservationAdmission& report);
  NDO_NODISCARD std::vector<RetainedObservation> ObservationsFor(const TargetId& target) const;
  /// Marks every retained observation as no longer fresh. Called once at
  /// recovery: evidence that survived a restart is never treated as current.
  std::size_t InvalidateRetainedEvidence(ReasonCode reason, NdoTime now);

  // ---- evaluation ----
  Status ApplyEvaluation(const EvaluationOutcome& outcome, const ObservatoryPolicy& policy,
                         NdoTime now, LedgerApplyReport& report);

  // ---- operator actions ----
  Status Suppress(FindingId finding, ActorId actor, std::string reason,
                  std::optional<NdoTime> expires_at, NdoTime now);
  Status ClearSuppression(FindingId finding, ActorId actor, NdoTime now);
  Status Acknowledge(FindingId finding, ActorId actor, std::string reason, NdoTime now);
  Status ClearAcknowledgement(FindingId finding, ActorId actor, NdoTime now);
  /// Re-evaluates time-based suppression expiry against the supplied clock.
  std::size_t ExpireSuppressions(NdoTime now);

  // ---- inspection ----
  NDO_NODISCARD const Finding* FindFinding(FindingId id) const noexcept;
  NDO_NODISCARD std::vector<const Finding*> Findings() const;
  NDO_NODISCARD std::vector<const RootCauseGroup*> Groups() const;
  NDO_NODISCARD std::vector<const TimelineEntry*> GlobalTimeline() const;
  NDO_NODISCARD LedgerStats Stats() const;
  NDO_NODISCARD LedgerRevision revision() const noexcept { return revision_; }
  /// Digest over the canonical durable content. Used by persistence.
  NDO_NODISCARD Digest ContentDigest() const;

  // ---- recovery-only mutation ----
  //
  // These methods exist for the trusted decode path. They do not re-run
  // admission checks, because the decoder has already validated structure and
  // integrity; they do enforce bounds and they always mark evidence as
  // recovered rather than fresh.
  Status RestoreBaseline(IntentBaseline baseline);
  Status RestoreObservation(RetainedObservation observation);
  Status RestoreFinding(Finding finding);
  Status RestoreGroup(RootCauseGroup group);
  Status RestoreTimeline(TimelineEntry entry);
  Status RestoreRevision(LedgerRevision revision);
  Status RestoreSuppressionSequence(std::uint64_t sequence);

  /// Records a target- or policy-scope event on the global timeline. Used for
  /// transitions that belong to no single finding.
  void RecordEvent(TimelineEntry entry);

  /// Assigns the next global timeline sequence. Deterministic per ledger.
  NDO_NODISCARD std::uint64_t NextTimelineSequence() noexcept { return ++timeline_sequence_; }
  NDO_NODISCARD std::uint64_t timeline_sequence() const noexcept { return timeline_sequence_; }

 private:
  struct SourceWindowKey {
    TargetId target;
    SourceId source;
    friend bool operator==(const SourceWindowKey&, const SourceWindowKey&) = default;
    friend std::strong_ordering operator<=>(const SourceWindowKey& lhs,
                                            const SourceWindowKey& rhs) {
      if (auto cmp = lhs.target <=> rhs.target; cmp != 0) {
        return cmp;
      }
      return lhs.source <=> rhs.source;
    }
  };

  void AppendTimeline(TimelineEntry entry);
  void TrimTimelineIfNeeded();
  Status RefreshGroups(const TargetId& target, NdoTime now, LedgerApplyReport& report);
  Status RebaseFindingsForTarget(const TargetId& target, IntentGeneration generation,
                                 NdoTime now, IntentCommitReport& report);
  void RecomputeSummary(Finding& finding) const;

  RuntimeLimits limits_;
  LedgerRevision revision_;
  std::uint64_t timeline_sequence_{0};
  std::map<TargetId, IntentBaseline> baselines_;
  std::map<SourceWindowKey, std::vector<RetainedObservation>> windows_;
  std::map<FindingId, Finding> findings_;
  std::map<GroupId, RootCauseGroup> groups_;
  std::vector<TimelineEntry> global_timeline_;
  /// Consecutive fresh agreements per finding, used for resolution.
  std::map<FindingId, std::uint32_t> resolution_streak_;
  std::size_t suppressions_active_{0};
  std::size_t suppressions_expired_{0};
};

/// Recovery report produced by the durable-state decoder.
struct NDO_API LedgerRecoveryReport {
  LedgerRevision revision;
  std::size_t findings_restored{0};
  std::size_t groups_restored{0};
  std::size_t baselines_restored{0};
  std::size_t observations_restored{0};
  bool conservative{true};
  ReasonCode reason{ReasonCode::LedgerRecoveredConservatively};
};

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_LEDGER_HPP
