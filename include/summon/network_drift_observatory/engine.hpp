// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The observatory runtime.
//
// The engine owns the ledger, the live epoch and incarnation, the source
// registry, the policy and the evaluation path. It detects and explains
// divergence between intended and observed state. It never mutates a device,
// never rolls out a fix and never silently reconciles drift: everything it
// produces is a typed finding or a typed request for another runtime.
//
// Concurrency contract
// --------------------
// One mutex guards all ledger state. No callback is invoked and no event is
// emitted while that mutex is held, and no method acquires a second lock.
// Evaluation copies its inputs under the mutex, releases it, compares without
// holding it, then re-acquires it to apply results. Results computed against a
// baseline that moved in the meantime are fenced, not applied.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_ENGINE_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_ENGINE_HPP

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "summon/network_drift_observatory/comparison.hpp"
#include "summon/network_drift_observatory/drift.hpp"
#include "summon/network_drift_observatory/finding.hpp"
#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/intent.hpp"
#include "summon/network_drift_observatory/ledger.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/observation.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/policy.hpp"
#include "summon/network_drift_observatory/query.hpp"
#include "summon/network_drift_observatory/report.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/time.hpp"
#include "summon/network_drift_observatory/value.hpp"

namespace summon {
namespace network_drift_observatory {

/// Injectable clock. The observatory reads it only to stamp receive times and
/// to default "now"; no freshness decision depends on an implicit clock.
using ClockFn = std::function<NdoTime()>;

struct NDO_API ObservatoryConfig {
  ObservatoryPolicy policy{ObservatoryPolicy::Default()};
  RuntimeLimits limits;
  FabricEpoch epoch;
  Incarnation incarnation;
  /// Bounded evaluation parallelism across targets. One means strictly
  /// sequential. The result is identical for every value.
  std::size_t evaluation_workers{1};
  /// When true, ingestion is refused until Start() has been called.
  bool require_started{true};
  /// When true, observations from an unregistered source are refused.
  bool require_registered_sources{false};
};

/// Monotonic counters describing what the runtime has done.
struct NDO_API ObservatoryCounters {
  std::uint64_t intents_accepted{0};
  std::uint64_t intents_rejected{0};
  std::uint64_t intents_duplicate_identical{0};
  std::uint64_t observations_accepted{0};
  std::uint64_t observations_rejected{0};
  std::uint64_t observations_duplicate_identical{0};
  std::uint64_t observations_superseded{0};
  std::uint64_t evaluations{0};
  std::uint64_t evaluations_cancelled{0};
  std::uint64_t evaluations_fenced{0};
  std::uint64_t findings_created{0};
  std::uint64_t findings_resolved{0};
  std::uint64_t findings_reopened{0};
  std::uint64_t findings_suppressed{0};
  std::uint64_t acknowledgements{0};
  std::uint64_t recoveries{0};
  std::uint64_t persistence_writes{0};
  std::uint64_t policy_changes{0};
};

/// A consistent, immutable copy of ledger content for report building and for
/// inspection tooling. Nothing in it aliases live state.
struct NDO_API ReportInputs {
  NdoTime generated_at;
  PolicyId policy;
  Digest policy_digest;
  FabricEpoch epoch;
  Incarnation incarnation;
  LedgerRevision revision;
  LedgerStats stats;
  ObservatoryCounters counters;
  std::vector<Finding> findings;
  std::vector<RootCauseGroup> groups;
  std::vector<TimelineEntry> timeline;
  std::size_t matching_findings{0};
  /// Number of timeline entries retained for this report. Entries may be
  /// trimmed by the global timeline bound.
  std::size_t timeline_entries{0};
  bool truncated{false};
  bool started{false};
  Digest state_digest;
};

class NDO_API Observatory {
 public:
  explicit Observatory(ObservatoryConfig config, ClockFn clock = {});
  ~Observatory();
  Observatory(const Observatory&) = delete;
  Observatory& operator=(const Observatory&) = delete;

  // ---- lifecycle ----
  /// Validates configuration and admits work. Refuses an unset epoch or
  /// incarnation: the observatory never runs without an explicit authority.
  Status Start();
  /// Stops admission, waits for in-flight evaluation, and retires nothing:
  /// findings survive a stop so a restart can recover them. Idempotent.
  Status Stop();
  NDO_NODISCARD bool started() const;
  /// Moves the runtime to a new incarnation and epoch, exactly as a restart
  /// would: retained evidence becomes non-fresh and every open finding keeps
  /// its history but loses any claim to be current.
  Status RotateIncarnation(Incarnation next_incarnation, FabricEpoch next_epoch, NdoTime now);
  /// Requests cancellation of in-flight evaluations. A cancelled evaluation
  /// never applies its outcome and never reports success.
  Status RequestCancellation() noexcept;
  void ClearCancellation() noexcept;
  NDO_NODISCARD bool cancellation_requested() const noexcept;

  // ---- sources ----
  Status RegisterSource(const SourceDescriptor& descriptor);
  NDO_NODISCARD const SourceDescriptor* FindSource(const SourceId& id) const noexcept;
  NDO_NODISCARD std::size_t SourceCount() const;

  // ---- ingestion ----
  /// Commits one intent generation. Validate, then commit under the lock.
  Status PublishIntent(const IntentGenerationDocument& document, IntentCommitReport& report);
  /// Admits one observation. The receive time is stamped locally; a caller
  /// supplied receive time is overwritten. Returns the admission decision.
  Status IngestObservation(ObservationSnapshot snapshot, ObservationAdmission& report);
  /// Parses, validates and admits an observation document.
  Status IngestObservationJson(std::string_view json, ObservationAdmission& report);

  // ---- evaluation ----
  /// Evaluates every target and applies the outcome to the ledger.
  Result<EvaluationOutcome> Evaluate();
  /// Evaluates at an explicit clock reading. Deterministic: the same ledger
  /// contents and the same "now" always produce the same outcome.
  Result<EvaluationOutcome> EvaluateAt(NdoTime now, bool apply = true);

  // ---- operator actions ----
  Status SuppressFinding(FindingId finding, ActorId actor, std::string reason,
                         std::optional<NdoTime> expires_at, NdoTime now);
  Status ClearSuppression(FindingId finding, ActorId actor, NdoTime now);
  Status AcknowledgeFinding(FindingId finding, ActorId actor, std::string reason, NdoTime now);
  Status ClearAcknowledgement(FindingId finding, ActorId actor, NdoTime now);
  /// Installs a new policy. Findings keep their history; the next evaluation
  /// uses the new policy and records its digest.
  Status SetPolicy(ObservatoryPolicy policy, NdoTime now);
  std::size_t ExpireSuppressions(NdoTime now);

  // ---- inspection ----
  Result<QueryResult> Query(const QuerySpec& spec) const;
  Result<TimelinePage> QueryTimeline(const TimelineSpec& spec) const;
  NDO_NODISCARD Result<ReportInputs> CollectReportInputs(const ReportSpec& spec) const;
  NDO_NODISCARD LedgerStats Stats() const;
  NDO_NODISCARD ObservatoryCounters Counters() const;
  NDO_NODISCARD ObservatoryPolicy policy() const;
  NDO_NODISCARD RuntimeLimits limits() const noexcept { return config_.limits; }
  NDO_NODISCARD FabricEpoch epoch() const;
  NDO_NODISCARD Incarnation incarnation() const;
  NDO_NODISCARD Digest policy_digest() const;
  NDO_NODISCARD NdoTime now() const;

  // ---- persistence ----
  Status Save(const std::string& path);
  Status Load(const std::string& path, LedgerRecoveryReport& report);
  NDO_NODISCARD Result<std::vector<std::uint8_t>> EncodeState() const;
  Status DecodeState(const std::uint8_t* bytes, std::size_t size, LedgerRecoveryReport& report);

 private:
  struct EvaluationInput {
    NdoTime now;
    FabricEpoch epoch;
    Incarnation incarnation;
    PolicyId policy;
    Digest policy_digest;
    std::uint32_t resolution_confirmations{1};
    std::uint64_t sequence{0};
    std::vector<TargetComparisonInput> targets;
    /// Owned snapshot storage backing the pointers inside targets.
    std::vector<ObservationSnapshot> snapshot_storage;
    std::vector<FreshnessVerdict> verdict_storage;
  };

  Status BuildEvaluationInput(NdoTime now, EvaluationInput& input) const;
  Result<EvaluationOutcome> EvaluateInternal(const EvaluationInput& input, bool apply);
  void EvaluateTargetRange(const EvaluationInput& input, ObservatoryPolicy policy,
                           std::size_t begin, std::size_t end,
                           std::vector<TargetEvaluation>& out) const;
  std::vector<Finding> SnapshotFindingsForQuery() const;

  ObservatoryConfig config_;
  ClockFn clock_;
  mutable std::mutex mutex_;
  std::condition_variable idle_cv_;
  FindingLedger ledger_;
  std::map<SourceId, SourceDescriptor> sources_;
  std::atomic<std::uint64_t> timeline_sequence_{0};
  std::uint64_t evaluation_sequence_{0};
  bool started_{false};
  std::atomic<bool> cancelled_{false};
  std::atomic<bool> stopping_{false};
  std::atomic<std::uint64_t> active_evaluations_{0};
  ObservatoryCounters counters_;
  std::string save_path_;
};

/// Convenience: the evaluator used by tests and tooling to run one deterministic
/// pass without persistence or transport.
NDO_NODISCARD NDO_API Result<EvaluationOutcome> EvaluateLedgerOnce(
    const FindingLedger& ledger, const ObservatoryPolicy& policy, const RuntimeLimits& limits,
    FabricEpoch epoch, Incarnation incarnation, NdoTime now);

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_ENGINE_HPP
