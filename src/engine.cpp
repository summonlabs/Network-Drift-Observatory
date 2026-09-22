// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/engine.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "summon/network_drift_observatory/interchange.hpp"
#include "summon/network_drift_observatory/persistence.hpp"
#include "summon/network_drift_observatory/version.hpp"

namespace summon {
namespace network_drift_observatory {
Observatory::Observatory(ObservatoryConfig config, ClockFn clock)
    : config_(std::move(config)),
      clock_(clock ? std::move(clock) : ClockFn([]() { return SystemNow(); })),
      ledger_(config_.limits) {
  if (config_.evaluation_workers == 0) {
    config_.evaluation_workers = 1;
  }
  if (config_.evaluation_workers > config_.limits.max_evaluation_workers) {
    config_.evaluation_workers = config_.limits.max_evaluation_workers;
  }
}

Observatory::~Observatory() {
  try {
    Stop();
  } catch (...) {
    // A destructor must not propagate. Stop() itself does not throw.
  }
}

Status Observatory::Start() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (started_) {
    return Status::Precondition(ReasonCode::None, "the observatory is already started");
  }
  if (!config_.epoch.is_set() || !config_.incarnation.is_set()) {
    return Status::Rejected(ReasonCode::FencedStaleEpoch,
                            "the observatory requires an explicit epoch and incarnation");
  }
  Status status = config_.policy.Validate(config_.limits);
  if (!status.ok()) {
    return status;
  }
  if (config_.policy.evidence == EvidenceClass::Unknown) {
    return Status::Rejected(ReasonCode::EncodingMalformed,
                            "policy must declare its evidence class");
  }
  ledger_.SetLimits(config_.limits);
  started_ = true;
  stopping_ = false;
  cancelled_.store(false);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status Observatory::Stop() {
  std::unique_lock<std::mutex> lock(mutex_);
  stopping_ = true;
  started_ = false;
  idle_cv_.wait(lock, [this]() { return active_evaluations_.load() == 0; });
  return Status(StatusCode::Ok, ReasonCode::None);
}

bool Observatory::started() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return started_;
}

Status Observatory::RotateIncarnation(Incarnation next_incarnation, FabricEpoch next_epoch,
                                      NdoTime now) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!next_incarnation.is_set()) {
    return Status::Rejected(ReasonCode::FencedStaleIncarnation,
                            "the new incarnation must be positive");
  }
  if (next_incarnation <= config_.incarnation) {
    return Status::Rejected(ReasonCode::FencedStaleIncarnation,
                            "the new incarnation must be strictly greater than the current one");
  }
  if (next_epoch < config_.epoch) {
    return Status::Rejected(ReasonCode::FencedStaleEpoch,
                            "the new epoch must not be older than the current one");
  }
  config_.incarnation = next_incarnation;
  config_.epoch = next_epoch;
  const std::size_t invalidated =
      ledger_.InvalidateRetainedEvidence(ReasonCode::EvidenceRecoveredNotFresh, now);
  ++counters_.recoveries;
  static_cast<void>(invalidated);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status Observatory::RequestCancellation() noexcept {
  cancelled_.store(true);
  return Status(StatusCode::Ok, ReasonCode::None);
}

void Observatory::ClearCancellation() noexcept {
  cancelled_.store(false);
}

bool Observatory::cancellation_requested() const noexcept {
  return cancelled_.load();
}

Status Observatory::RegisterSource(const SourceDescriptor& descriptor) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (descriptor.id.empty() || !IsValidIdentityText(descriptor.id.str())) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "source identity is invalid");
  }
  if (!descriptor.incarnation.is_set() || !descriptor.epoch.is_set()) {
    return Status::Rejected(ReasonCode::FencedStaleIncarnation,
                            "source must declare its epoch and incarnation");
  }
  const auto existing = sources_.find(descriptor.id);
  if (existing != sources_.end()) {
    if (descriptor.incarnation < existing->second.incarnation) {
      return Status::Stale(ReasonCode::FencedStaleIncarnation,
                           "source incarnation regressed; the registration is refused");
    }
  } else if (sources_.size() >= config_.limits.max_sources) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded, "source count exceeds the envelope");
  }
  sources_[descriptor.id] = descriptor;
  return Status(StatusCode::Ok, ReasonCode::None);
}

const SourceDescriptor* Observatory::FindSource(const SourceId& id) const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto found = sources_.find(id);
  if (found == sources_.end()) {
    return nullptr;
  }
  return &found->second;
}

std::size_t Observatory::SourceCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return sources_.size();
}

Status Observatory::PublishIntent(const IntentGenerationDocument& document,
                                  IntentCommitReport& report) {
  // The injected clock is consulted before the lock is taken: no caller-supplied
  // callback ever runs beneath the engine mutex, so it cannot re-enter.
  const NdoTime stamp = clock_();
  std::lock_guard<std::mutex> lock(mutex_);
  if (config_.require_started && !started_) {
    return Status::Precondition(ReasonCode::None, "the observatory is not started");
  }
  if (document.epoch != config_.epoch) {
    return Status::Stale(ReasonCode::FencedStaleEpoch,
                         "intent was authored under a different epoch");
  }
  report = IntentCommitReport{};
  const Status status = ledger_.CommitIntent(document, stamp, report);
  if (!status.ok()) {
    ++counters_.intents_rejected;
    return status;
  }
  if (report.duplicate_identical) {
    ++counters_.intents_duplicate_identical;
  } else {
    ++counters_.intents_accepted;
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status Observatory::IngestObservation(ObservationSnapshot snapshot, ObservationAdmission& report) {
  const NdoTime receive_time = clock_();
  std::lock_guard<std::mutex> lock(mutex_);
  if (config_.require_started && !started_) {
    return Status::Precondition(ReasonCode::None, "the observatory is not started");
  }
  // The observatory stamps the receive time itself. A caller-supplied value is
  // never trusted, because receive time is used to bound how long evidence may
  // be held.
  snapshot.received_at = receive_time;
  report = ObservationAdmission{};

  if (config_.require_registered_sources && sources_.find(snapshot.source) == sources_.end()) {
    ++counters_.observations_rejected;
    return Status::NotFound(ReasonCode::AuthorityMismatch, "the observation source is not registered");
  }

  FreshnessPolicy freshness = config_.policy.freshness;
  const auto scope_object =
      ObjectId::TryParse(kTargetScopeObjectId).value_or(ObjectId::Trusted("@target"));
  freshness.ttl_nanos = config_.policy.TtlFor(snapshot.target, scope_object, FieldPath{});
  const FreshnessVerdict verdict =
      EvaluateFreshness(snapshot, freshness, receive_time, config_.epoch, false);

  const Status status = ledger_.RecordObservation(snapshot, verdict, false, report);
  if (!status.ok()) {
    ++counters_.observations_rejected;
    return status;
  }
  if (report.duplicate_identical) {
    ++counters_.observations_duplicate_identical;
  } else {
    ++counters_.observations_accepted;
    if (report.superseded_older) {
      ++counters_.observations_superseded;
    }
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status Observatory::IngestObservationJson(std::string_view json, ObservationAdmission& report) {
  ObservationSnapshot snapshot;
  Status status = ParseObservationJson(json, config_.limits, snapshot);
  if (!status.ok()) {
    ++counters_.observations_rejected;
    return status;
  }
  return IngestObservation(std::move(snapshot), report);
}

Status Observatory::BuildEvaluationInput(NdoTime now, EvaluationInput& input) const {
  input.now = now;
  input.epoch = config_.epoch;
  input.incarnation = config_.incarnation;
  input.policy = config_.policy.id;
  input.policy_digest = config_.policy.ComputeDigest();
  input.sequence = evaluation_sequence_ + 1;

  // The evaluation set is the union of everything the ledger knows about and
  // every target policy requires. A required target that has never been
  // observed must still be evaluated, or its absence of intent would be
  // invisible.
  std::vector<TargetId> targets = ledger_.Targets();
  targets.insert(targets.end(), config_.policy.required_targets.begin(),
                 config_.policy.required_targets.end());
  std::sort(targets.begin(), targets.end());
  targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
  std::vector<std::vector<RetainedObservation>> per_target;
  per_target.reserve(targets.size());
  std::size_t total_observations = 0;
  for (const TargetId& target : targets) {
    per_target.push_back(ledger_.ObservationsFor(target));
    total_observations += per_target.back().size();
  }
  input.snapshot_storage.reserve(total_observations);
  input.verdict_storage.reserve(total_observations);
  input.targets.reserve(targets.size());

  const auto scope_object =
      ObjectId::TryParse(kTargetScopeObjectId).value_or(ObjectId::Trusted("@target"));
  for (std::size_t target_index = 0; target_index < targets.size(); ++target_index) {
    const TargetId& target = targets[target_index];
    TargetComparisonInput comparison;
    comparison.target = target;
    if (const IntentBaseline* baseline = ledger_.FindBaseline(target); baseline != nullptr) {
      comparison.baseline = *baseline;
    }
    FreshnessPolicy freshness = config_.policy.freshness;
    freshness.ttl_nanos = config_.policy.TtlFor(target, scope_object, FieldPath{});
    for (const RetainedObservation& observation : per_target[target_index]) {
      input.snapshot_storage.push_back(observation.snapshot);
      FreshnessVerdict verdict;
      if (observation.recovered) {
        // Evidence that survived a restart stays non-fresh even inside one
        // incarnation, until a live observation replaces it.
        verdict.state = FreshnessState::RecoveredNotFresh;
        verdict.reason = ReasonCode::EvidenceRecoveredNotFresh;
        verdict.may_support_compliance = false;
        verdict.may_assert_absence = false;
        std::int64_t age = 0;
        if (TryDifference(now, observation.snapshot.collected_at, age)) {
          verdict.age_nanos = age;
        }
      } else {
        verdict = EvaluateFreshness(observation.snapshot, freshness, now, config_.epoch, false);
      }
      input.verdict_storage.push_back(verdict);
    }
    input.targets.push_back(std::move(comparison));
  }

  // Second pass: attach pointers now that snapshot_storage will not grow again.
  std::size_t cursor = 0;
  for (std::size_t target_index = 0; target_index < input.targets.size(); ++target_index) {
    TargetComparisonInput& comparison = input.targets[target_index];
    const std::size_t count = per_target[target_index].size();
    comparison.snapshots.clear();
    comparison.freshness.clear();
    for (std::size_t index = 0; index < count; ++index) {
      comparison.snapshots.push_back(&input.snapshot_storage[cursor + index]);
      comparison.freshness.push_back(input.verdict_storage[cursor + index]);
    }
    cursor += count;
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

void Observatory::EvaluateTargetRange(const EvaluationInput& input, ObservatoryPolicy policy,
                                      std::size_t begin, std::size_t end,
                                      std::vector<TargetEvaluation>& out) const {
  for (std::size_t index = begin; index < end; ++index) {
    if (cancelled_.load() || stopping_.load()) {
      return;
    }
    out[index] = CompareTarget(input.targets[index], policy, config_.limits);
  }
}

Result<EvaluationOutcome> Observatory::EvaluateInternal(const EvaluationInput& input, bool apply) {
  EvaluationOutcome outcome;
  outcome.now = input.now;
  outcome.epoch = input.epoch;
  outcome.incarnation = input.incarnation;
  outcome.policy = input.policy;
  outcome.policy_digest = input.policy_digest;
  outcome.resolution_confirmations = input.resolution_confirmations;
  outcome.sequence = input.sequence;
  outcome.targets.resize(input.targets.size());

  ObservatoryPolicy policy;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    policy = config_.policy;
  }

  const std::size_t workers = std::min<std::size_t>(
      config_.evaluation_workers == 0 ? 1 : config_.evaluation_workers,
      input.targets.empty() ? 1 : input.targets.size());
  if (workers <= 1) {
    EvaluateTargetRange(input, policy, 0, input.targets.size(), outcome.targets);
  } else {
    std::vector<std::thread> threads;
    threads.reserve(workers);
    const std::size_t per_worker = (input.targets.size() + workers - 1) / workers;
    for (std::size_t worker = 0; worker < workers; ++worker) {
      const std::size_t begin = worker * per_worker;
      const std::size_t end = std::min(begin + per_worker, input.targets.size());
      if (begin >= end) {
        continue;
      }
      threads.emplace_back([this, &input, policy, begin, end, &outcome]() {
        EvaluateTargetRange(input, policy, begin, end, outcome.targets);
      });
    }
    for (std::thread& thread : threads) {
      thread.join();
    }
  }

  std::lock_guard<std::mutex> lock(mutex_);
  --active_evaluations_;
  idle_cv_.notify_all();

  if (cancelled_.load()) {
    ++counters_.evaluations_cancelled;
    return Status::Cancelled(ReasonCode::None,
                             "the evaluation was cancelled; no outcome was published");
  }
  if (stopping_.load() || (config_.require_started && !started_)) {
    ++counters_.evaluations_cancelled;
    return Status::Cancelled(ReasonCode::None,
                             "the observatory stopped before the outcome was published");
  }
  if (input.epoch != config_.epoch || input.incarnation != config_.incarnation) {
    ++counters_.evaluations_fenced;
    return Status::Stale(ReasonCode::FencedStaleEpoch,
                         "the epoch or incarnation changed while the evaluation was running");
  }

  if (apply) {
    LedgerApplyReport report;
    const Status status = ledger_.ApplyEvaluation(outcome, policy, input.now, report);
    if (!status.ok()) {
      return status;
    }
    counters_.findings_created += report.created;
    counters_.findings_resolved += report.resolved;
    counters_.findings_reopened += report.reopened;
    counters_.findings_suppressed += report.suppressed;
  }
  ++counters_.evaluations;
  return outcome;
}

Result<EvaluationOutcome> Observatory::Evaluate() {
  return EvaluateAt(clock_(), true);
}

Result<EvaluationOutcome> Observatory::EvaluateAt(NdoTime now, bool apply) {
  EvaluationInput input;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (config_.require_started && !started_) {
      return Status::Precondition(ReasonCode::None, "the observatory is not started");
    }
    if (cancelled_.load()) {
      // A refused evaluation is accounted for: the caller can tell how often
      // cancellation actually prevented work.
      ++counters_.evaluations_cancelled;
      return Status::Cancelled(ReasonCode::None, "cancellation is requested");
    }
    Status status = BuildEvaluationInput(now, input);
    if (!status.ok()) {
      return status;
    }
    input.resolution_confirmations = config_.policy.resolution_confirmations;
    ++active_evaluations_;
  }
  return EvaluateInternal(input, apply);
}

Status Observatory::SuppressFinding(FindingId finding, ActorId actor, std::string reason,
                                    std::optional<NdoTime> expires_at, NdoTime now) {
  std::lock_guard<std::mutex> lock(mutex_);
  const Status status = ledger_.Suppress(finding, std::move(actor), std::move(reason), expires_at, now);
  if (status.ok()) {
    ++counters_.findings_suppressed;
  }
  return status;
}

Status Observatory::ClearSuppression(FindingId finding, ActorId actor, NdoTime now) {
  std::lock_guard<std::mutex> lock(mutex_);
  return ledger_.ClearSuppression(finding, std::move(actor), now);
}

Status Observatory::AcknowledgeFinding(FindingId finding, ActorId actor, std::string reason,
                                       NdoTime now) {
  std::lock_guard<std::mutex> lock(mutex_);
  const Status status = ledger_.Acknowledge(finding, std::move(actor), std::move(reason), now);
  if (status.ok()) {
    ++counters_.acknowledgements;
  }
  return status;
}

Status Observatory::ClearAcknowledgement(FindingId finding, ActorId actor, NdoTime now) {
  std::lock_guard<std::mutex> lock(mutex_);
  return ledger_.ClearAcknowledgement(finding, std::move(actor), now);
}

Status Observatory::SetPolicy(ObservatoryPolicy policy, NdoTime now) {
  Status status = policy.Validate(config_.limits);
  if (!status.ok()) {
    return status;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  const Digest previous = config_.policy.ComputeDigest();
  config_.policy = std::move(policy);
  ++counters_.policy_changes;
  TimelineEntry entry;
  entry.kind = TimelineEventKind::Updated;
  entry.target = TargetId::Trusted("policy");
  entry.object = ObjectId::Trusted("policy");
  entry.at = now;
  entry.klass = DriftClass::None;
  entry.severity = Severity::Info;
  entry.reason = ReasonCode::None;
  entry.detail = std::string("policy ") + config_.policy.id.str() + " installed; previous digest " +
                 previous.ToShortHex();
  ledger_.RecordEvent(std::move(entry));
  return Status(StatusCode::Ok, ReasonCode::None);
}

std::size_t Observatory::ExpireSuppressions(NdoTime now) {
  std::lock_guard<std::mutex> lock(mutex_);
  return ledger_.ExpireSuppressions(now);
}

Result<QueryResult> Observatory::Query(const QuerySpec& spec) const {
  const NdoTime now = clock_();
  std::vector<Finding> findings;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    findings = SnapshotFindingsForQuery();
  }
  return ExecuteQuery(findings, spec, now);
}

Result<TimelinePage> Observatory::QueryTimeline(const TimelineSpec& spec) const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<TimelineEntry> entries;
  for (const TimelineEntry* entry : ledger_.GlobalTimeline()) {
    entries.push_back(*entry);
  }
  return ExecuteTimelineQuery(entries, spec);
}

Result<ReportInputs> Observatory::CollectReportInputs(const ReportSpec& spec) const {
  const NdoTime stamp = clock_();
  std::lock_guard<std::mutex> lock(mutex_);
  ReportInputs inputs;
  inputs.generated_at = stamp;
  inputs.policy = config_.policy.id;
  inputs.policy_digest = config_.policy.ComputeDigest();
  inputs.epoch = config_.epoch;
  inputs.incarnation = config_.incarnation;
  inputs.revision = ledger_.revision();
  inputs.stats = ledger_.Stats();
  inputs.counters = counters_;
  inputs.started = started_;
  inputs.state_digest = ledger_.ContentDigest();
  // The runtime envelope caps how many findings one report may serialize, even
  // when the caller asks for more.
  const std::size_t report_budget =
      std::min(spec.max_findings, config_.limits.max_report_findings);
  for (const Finding* finding : ledger_.Findings()) {
    if (spec.target.has_value() && !(finding->identity.target == *spec.target)) {
      continue;
    }
    if (!spec.include_resolved && finding->state == FindingState::Resolved) {
      continue;
    }
    if (!spec.include_superseded && finding->state == FindingState::Superseded) {
      continue;
    }
    if (!spec.include_suppressed && finding->state == FindingState::Suppressed) {
      continue;
    }
    if (inputs.findings.size() >= report_budget) {
      inputs.truncated = true;
      break;
    }
    inputs.findings.push_back(*finding);
    ++inputs.matching_findings;
  }
  if (spec.include_groups) {
    for (const RootCauseGroup* group : ledger_.Groups()) {
      if (spec.target.has_value() && !(group->target == *spec.target)) {
        continue;
      }
      inputs.groups.push_back(*group);
    }
  }
  if (spec.include_timeline) {
    for (const TimelineEntry* entry : ledger_.GlobalTimeline()) {
      if (spec.target.has_value() && !entry->target.empty() && !(entry->target == *spec.target)) {
        continue;
      }
      inputs.timeline.push_back(*entry);
    }
    inputs.timeline_entries = inputs.timeline.size();
  }
  return inputs;
}

std::vector<Finding> Observatory::SnapshotFindingsForQuery() const {
  std::vector<Finding> findings;
  findings.reserve(ledger_.Stats().findings);
  for (const Finding* finding : ledger_.Findings()) {
    findings.push_back(*finding);
  }
  return findings;
}

LedgerStats Observatory::Stats() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return ledger_.Stats();
}

ObservatoryCounters Observatory::Counters() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return counters_;
}

ObservatoryPolicy Observatory::policy() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return config_.policy;
}

FabricEpoch Observatory::epoch() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return config_.epoch;
}

Incarnation Observatory::incarnation() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return config_.incarnation;
}

Digest Observatory::policy_digest() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return config_.policy.ComputeDigest();
}

NdoTime Observatory::now() const {
  return clock_();
}

Status Observatory::Save(const std::string& path) {
  std::lock_guard<std::mutex> lock(mutex_);
  const Status status = SaveLedgerFile(ledger_, path, config_.epoch, config_.incarnation,
                                       config_.limits.max_ledger_bytes);
  if (status.ok()) {
    ++counters_.persistence_writes;
  }
  return status;
}

Status Observatory::Load(const std::string& path, LedgerRecoveryReport& report) {
  FindingLedger decoded(config_.limits);
  Status status = LoadLedgerFile(path, config_.limits, config_.epoch, decoded, report);
  if (!status.ok()) {
    return status;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  ledger_ = std::move(decoded);
  ++counters_.recoveries;
  return Status(StatusCode::Ok, ReasonCode::None);
}

Result<std::vector<std::uint8_t>> Observatory::EncodeState() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::uint8_t> bytes;
  const Status status = EncodeLedger(ledger_, config_.epoch, config_.incarnation, bytes);
  if (!status.ok()) {
    return status;
  }
  return bytes;
}

Status Observatory::DecodeState(const std::uint8_t* bytes, std::size_t size,
                                LedgerRecoveryReport& report) {
  FindingLedger decoded(config_.limits);
  Status status = DecodeLedger(bytes, size, config_.limits, config_.epoch, decoded, report);
  if (!status.ok()) {
    return status;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  ledger_ = std::move(decoded);
  ++counters_.recoveries;
  return Status(StatusCode::Ok, ReasonCode::None);
}

Result<EvaluationOutcome> EvaluateLedgerOnce(const FindingLedger& ledger,
                                             const ObservatoryPolicy& policy,
                                             const RuntimeLimits& limits, FabricEpoch epoch,
                                             Incarnation incarnation, NdoTime now) {
  Status status = policy.Validate(limits);
  if (!status.ok()) {
    return status;
  }
  std::vector<TargetId> targets = ledger.Targets();
  targets.insert(targets.end(), policy.required_targets.begin(), policy.required_targets.end());
  std::sort(targets.begin(), targets.end());
  targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
  std::vector<ObservationSnapshot> storage;
  std::vector<FreshnessVerdict> verdicts;
  std::vector<TargetComparisonInput> inputs;
  std::size_t total = 0;
  for (const TargetId& target : targets) {
    total += ledger.ObservationsFor(target).size();
  }
  storage.reserve(total);
  verdicts.reserve(total);
  inputs.reserve(targets.size());
  const auto scope_object =
      ObjectId::TryParse(kTargetScopeObjectId).value_or(ObjectId::Trusted("@target"));
  for (const TargetId& target : targets) {
    TargetComparisonInput comparison;
    comparison.target = target;
    if (const IntentBaseline* baseline = ledger.FindBaseline(target); baseline != nullptr) {
      comparison.baseline = *baseline;
    }
    FreshnessPolicy freshness = policy.freshness;
    freshness.ttl_nanos = policy.TtlFor(target, scope_object, FieldPath{});
    for (const RetainedObservation& observation : ledger.ObservationsFor(target)) {
      storage.push_back(observation.snapshot);
      if (observation.recovered) {
        FreshnessVerdict verdict;
        verdict.state = FreshnessState::RecoveredNotFresh;
        verdict.reason = ReasonCode::EvidenceRecoveredNotFresh;
        verdicts.push_back(verdict);
      } else {
        verdicts.push_back(EvaluateFreshness(observation.snapshot, freshness, now, epoch, false));
      }
    }
    inputs.push_back(std::move(comparison));
  }
  std::size_t cursor = 0;
  for (TargetComparisonInput& comparison : inputs) {
    const std::size_t count = ledger.ObservationsFor(comparison.target).size();
    for (std::size_t index = 0; index < count; ++index) {
      comparison.snapshots.push_back(&storage[cursor + index]);
      comparison.freshness.push_back(verdicts[cursor + index]);
    }
    cursor += count;
  }

  EvaluationOutcome outcome;
  outcome.now = now;
  outcome.epoch = epoch;
  outcome.incarnation = incarnation;
  outcome.policy = policy.id;
  outcome.policy_digest = policy.ComputeDigest();
  outcome.resolution_confirmations = policy.resolution_confirmations;
  outcome.targets.reserve(inputs.size());
  for (const TargetComparisonInput& input : inputs) {
    outcome.targets.push_back(CompareTarget(input, policy, limits));
  }
  return outcome;
}

}  // namespace network_drift_observatory
}  // namespace summon
