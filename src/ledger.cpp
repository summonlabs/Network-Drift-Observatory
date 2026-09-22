// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/ledger.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace summon {
namespace network_drift_observatory {
namespace {

constexpr const char* kGroupTag = "ndo/root-cause-group/v1";
constexpr const char* kContentTag = "ndo/ledger-content/v1";

std::string BoundedDetail(std::string text, std::size_t limit = 240) {
  if (text.size() <= limit) {
    return text;
  }
  text.resize(limit);
  text.append("...");
  return text;
}

RootCauseKind CauseFor(DriftClass klass) noexcept {
  switch (klass) {
    case DriftClass::GenerationMismatch:
      return RootCauseKind::GenerationNotApplied;
    case DriftClass::PartialApplication:
      return RootCauseKind::PartialApplication;
    case DriftClass::SourceConflict:
      return RootCauseKind::SourceConflict;
    case DriftClass::StaleObservation:
      return RootCauseKind::StaleEvidence;
    case DriftClass::Unknown:
      return RootCauseKind::InsufficientCoverage;
    case DriftClass::Unsupported:
      return RootCauseKind::UnsupportedField;
    case DriftClass::IntentMissing:
      return RootCauseKind::MissingIntent;
    default:
      return RootCauseKind::SingleField;
  }
}

bool CauseFormsGroup(RootCauseKind cause, std::size_t members) noexcept {
  if (members >= 2) {
    return cause != RootCauseKind::None;
  }
  return cause == RootCauseKind::GenerationNotApplied || cause == RootCauseKind::PartialApplication;
}

Digest GroupDiscriminator(const std::vector<const Finding*>& members) {
  std::vector<std::string> qualifiers;
  qualifiers.reserve(members.size());
  for (const Finding* finding : members) {
    qualifiers.push_back(finding->identity.qualifier.is_set() ? finding->identity.qualifier.ToHex()
                                                              : finding->id.ToHex());
  }
  std::sort(qualifiers.begin(), qualifiers.end());
  qualifiers.erase(std::unique(qualifiers.begin(), qualifiers.end()), qualifiers.end());
  Sha256 hasher;
  hasher.UpdateTag("ndo/group-discriminator/v1");
  hasher.UpdateU64(qualifiers.size());
  for (const std::string& qualifier : qualifiers) {
    hasher.UpdateLengthPrefixed(qualifier);
  }
  return hasher.Final();
}

GroupId GroupIdentity(const TargetId& target, IntentGeneration generation, RootCauseKind cause,
                      const Digest& discriminator) {
  Sha256 hasher;
  hasher.UpdateTag(kGroupTag);
  hasher.UpdateLengthPrefixed(target.str());
  hasher.UpdateU64(generation.value());
  hasher.UpdateLengthPrefixed(ToText(cause));
  hasher.Update(discriminator.bytes.data(), discriminator.bytes.size());
  return GroupId::FromDigest(hasher.Final());
}

}  // namespace

const char* ToText(SuppressionEndReason value) noexcept {
  switch (value) {
    case SuppressionEndReason::Cleared:
      return "cleared";
    case SuppressionEndReason::Expired:
      return "expired";
    case SuppressionEndReason::FindingResolved:
      return "finding-resolved";
    case SuppressionEndReason::FindingSuperseded:
      return "finding-superseded";
  }
  return "unknown";
}

FindingLedger::FindingLedger(RuntimeLimits limits) : limits_(limits) {}

// ---------------------------------------------------------------------------
// intent
// ---------------------------------------------------------------------------

Status FindingLedger::CommitIntent(const IntentGenerationDocument& document, NdoTime now,
                                   IntentCommitReport& report) {
  Status status = document.Validate(limits_);
  if (!status.ok()) {
    return status;
  }
  report = IntentCommitReport{};
  report.target = document.target;
  report.epoch = document.epoch;
  const Digest digest = document.ComputeContentDigest();

  const auto found = baselines_.find(document.target);
  if (found == baselines_.end()) {
    if (baselines_.size() >= limits_.max_targets) {
      return Status::Limit(ReasonCode::LimitObjectsExceeded,
                           "committed intent target count exceeds the envelope");
    }
    IntentBaseline baseline;
    baseline.target = document.target;
    baseline.generation = document.generation;
    baseline.epoch = document.epoch;
    baseline.authority = document.authority;
    baseline.policy = document.policy;
    baseline.committed_at = now;
    baseline.content_digest = digest;
    baseline.evidence = document.evidence;
    baseline.objects = document.objects;
    baselines_.emplace(document.target, std::move(baseline));
    report.committed_generation = document.generation;

    TimelineEntry entry;
    entry.kind = TimelineEventKind::Created;
    entry.target = document.target;
    entry.object = ObjectId::TryParse(kTargetScopeObjectId).value_or(ObjectId::Trusted("@target"));
    entry.at = now;
    entry.state_after = FindingState::Open;
    entry.klass = DriftClass::None;
    entry.severity = Severity::Info;
    entry.reason = ReasonCode::None;
    entry.baseline_generation = document.generation;
    entry.baseline_epoch = document.epoch;
    entry.detail = BoundedDetail("intent generation " + std::to_string(document.generation.value()) +
                                 " committed from " + std::string(ToText(document.authority)));
    AppendTimeline(std::move(entry));
    revision_ = LedgerRevision::FromValue(revision_.value() + 1);
    return Status(StatusCode::Ok, ReasonCode::None);
  }

  IntentBaseline& existing = found->second;
  if (document.epoch < existing.epoch) {
    return Status::Stale(ReasonCode::FencedStaleEpoch,
                         "intent epoch is older than the committed baseline epoch");
  }
  if (document.generation < existing.generation) {
    return Status::Conflict(ReasonCode::IntentGenerationRegressed,
                            "intent generation is older than the committed baseline");
  }
  if (document.generation == existing.generation) {
    if (digest == existing.content_digest) {
      report.duplicate_identical = true;
      report.committed_generation = existing.generation;
      return Status(StatusCode::Ok, ReasonCode::None);
    }
    return Status::Conflict(ReasonCode::IntentGenerationConflicting,
                            "divergent re-publication of the committed intent generation");
  }

  report.previous_generation = existing.generation;
  existing.generation = document.generation;
  existing.epoch = document.epoch;
  existing.authority = document.authority;
  existing.policy = document.policy;
  existing.committed_at = now;
  existing.content_digest = digest;
  existing.evidence = document.evidence;
  existing.objects = document.objects;
  report.committed_generation = document.generation;

  status = RebaseFindingsForTarget(document.target, document.generation, now, report);
  if (!status.ok()) {
    return status;
  }

  TimelineEntry entry;
  entry.kind = TimelineEventKind::Rebased;
  entry.target = document.target;
  entry.object = ObjectId::TryParse(kTargetScopeObjectId).value_or(ObjectId::Trusted("@target"));
  entry.at = now;
  entry.state_after = FindingState::Open;
  entry.klass = DriftClass::None;
  entry.severity = Severity::Info;
  entry.reason = ReasonCode::FindingRebasedToNewGeneration;
  entry.baseline_generation = document.generation;
  entry.baseline_epoch = document.epoch;
  entry.detail = BoundedDetail("intent generation advanced to " +
                               std::to_string(document.generation.value()) + " from " +
                               std::string(ToText(document.authority)));
  AppendTimeline(std::move(entry));
  revision_ = LedgerRevision::FromValue(revision_.value() + 1);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status FindingLedger::RebaseFindingsForTarget(const TargetId& target, IntentGeneration generation,
                                              NdoTime now, IntentCommitReport& report) {
  std::set<GroupId> groups_to_drop;
  const IntentBaseline* baseline = FindBaseline(target);
  for (auto& entry : findings_) {
    Finding& finding = entry.second;
    if (!(finding.identity.target == target)) {
      continue;
    }
    if (!IsLiveState(finding.state)) {
      continue;
    }
    if (finding.baseline_generation == generation) {
      continue;
    }
    // A finding whose location the new generation still manages is superseded
    // and will be re-derived against the new baseline. A finding whose location
    // the new generation no longer declares is retired: the observable was
    // withdrawn, so it is not drift any more and its history is retained.
    bool still_managed = baseline != nullptr;
    if (baseline != nullptr) {
      const std::string& scope = finding.identity.object.str();
      if (scope == kTargetScopeObjectId) {
        still_managed = true;
      } else {
        const IntentObject* object = baseline->FindObject(finding.identity.object);
        if (object == nullptr) {
          still_managed = false;
        } else if (!finding.identity.path.empty()) {
          still_managed = object->fields.find(finding.identity.path) != object->fields.end();
        }
      }
    }
    if (still_managed) {
      finding.state = FindingState::Superseded;
      finding.reason = ReasonCode::FindingRebasedToNewGeneration;
      ++report.findings_rebased;
    } else {
      finding.state = FindingState::Retired;
      finding.reason = ReasonCode::FindingRetired;
      ++report.findings_retired;
    }
    finding.last_evaluated = now;
    if (finding.group.is_set()) {
      groups_to_drop.insert(finding.group);
      finding.group = GroupId{};
      finding.group_cause = RootCauseKind::None;
    }
    TimelineEntry event;
    event.kind = still_managed ? TimelineEventKind::Rebased : TimelineEventKind::Retired;
    event.target = finding.identity.target;
    event.object = finding.identity.object;
    event.finding = finding.id;
    event.at = now;
    event.state_after = finding.state;
    event.klass = finding.klass;
    event.severity = finding.severity;
    event.reason = finding.reason;
    event.baseline_generation = generation;
    event.baseline_epoch = finding.baseline_epoch;
    event.evidence_digest = finding.policy_digest;
    event.detail = BoundedDetail(
        still_managed ? "baseline advanced to generation " + std::to_string(generation.value()) +
                            "; finding is superseded until the next evaluation"
                      : "the new baseline no longer manages this location; the finding is retired");
    finding.timeline.push_back(event);
    AppendTimeline(std::move(event));
    RecomputeSummary(finding);
  }
  for (const GroupId& id : groups_to_drop) {
    groups_.erase(id);
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

const IntentBaseline* FindingLedger::FindBaseline(const TargetId& target) const noexcept {
  const auto found = baselines_.find(target);
  if (found == baselines_.end()) {
    return nullptr;
  }
  return &found->second;
}

std::vector<TargetId> FindingLedger::Targets() const {
  std::vector<TargetId> targets;
  targets.reserve(baselines_.size() + windows_.size());
  for (const auto& entry : baselines_) {
    targets.push_back(entry.first);
  }
  for (const auto& entry : windows_) {
    if (baselines_.find(entry.first.target) == baselines_.end()) {
      targets.push_back(entry.first.target);
    }
  }
  std::sort(targets.begin(), targets.end());
  targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
  return targets;
}

// ---------------------------------------------------------------------------
// observations
// ---------------------------------------------------------------------------

Status FindingLedger::RecordObservation(const ObservationSnapshot& snapshot,
                                        const FreshnessVerdict& verdict, bool recovered,
                                        ObservationAdmission& report) {
  Status status = snapshot.Validate(limits_);
  if (!status.ok()) {
    return status;
  }
  report = ObservationAdmission{};
  report.snapshot = snapshot.snapshot_id;
  report.source = snapshot.source;
  report.target = snapshot.target;
  report.sequence = snapshot.sequence;
  report.freshness = verdict.state;

  const Digest digest = snapshot.ComputeContentDigest();
  const SourceWindowKey key{snapshot.target, snapshot.source};
  auto& window = windows_[key];

  if (!window.empty()) {
    const RetainedObservation& newest = window.back();
    if (snapshot.incarnation < newest.snapshot.incarnation) {
      return Status::Stale(ReasonCode::FencedStaleIncarnation,
                           "observation incarnation predates the newest retained observation");
    }
    if (snapshot.epoch < newest.snapshot.epoch) {
      return Status::Stale(ReasonCode::FencedStaleEpoch,
                           "observation epoch predates the newest retained observation");
    }
    if (snapshot.incarnation == newest.snapshot.incarnation &&
        snapshot.sequence == newest.snapshot.sequence) {
      if (digest == newest.snapshot.ComputeContentDigest()) {
        report.duplicate_identical = true;
        return Status(StatusCode::Ok, ReasonCode::None);
      }
      return Status::Conflict(ReasonCode::ObservationDuplicateConflicting,
                              "two observations claim the same source sequence with different content");
    }
    if (snapshot.sequence < newest.snapshot.sequence) {
      // Out-of-order arrival is preserved as evidence but never supersedes the
      // newest observation for its source.
      report.superseded_older = true;
    }
  }

  const auto order = [](const RetainedObservation& lhs, const RetainedObservation& rhs) {
    if (lhs.snapshot.epoch != rhs.snapshot.epoch) {
      return lhs.snapshot.epoch < rhs.snapshot.epoch;
    }
    if (lhs.snapshot.incarnation != rhs.snapshot.incarnation) {
      return lhs.snapshot.incarnation < rhs.snapshot.incarnation;
    }
    return lhs.snapshot.sequence < rhs.snapshot.sequence;
  };

  RetainedObservation record;
  record.snapshot = snapshot;
  record.freshness = verdict;
  record.recovered = recovered;
  const auto position = std::lower_bound(window.begin(), window.end(), record, order);
  window.insert(position, std::move(record));

  if (window.size() > limits_.max_retained_snapshots_per_source) {
    // Evict the oldest retained record, preferring records that survived a
    // restart. The window is ordered by (epoch, incarnation, sequence), so
    // dropping the front keeps a contiguous window of the most recent
    // observations and never evicts the newest one.
    std::size_t victim = 0;
    for (std::size_t index = 0; index + 1 < window.size(); ++index) {
      if (window[index].recovered) {
        victim = index;
        break;
      }
    }
    window.erase(window.begin() + static_cast<std::ptrdiff_t>(victim));
  }

  revision_ = LedgerRevision::FromValue(revision_.value() + 1);
  return Status(StatusCode::Ok, ReasonCode::None);
}

std::vector<RetainedObservation> FindingLedger::ObservationsFor(const TargetId& target) const {
  std::vector<RetainedObservation> observations;
  for (const auto& entry : windows_) {
    if (!(entry.first.target == target)) {
      continue;
    }
    observations.insert(observations.end(), entry.second.begin(), entry.second.end());
  }
  return observations;
}

std::size_t FindingLedger::InvalidateRetainedEvidence(ReasonCode reason, NdoTime now) {
  std::size_t invalidated = 0;
  for (auto& entry : windows_) {
    for (RetainedObservation& observation : entry.second) {
      observation.recovered = true;
      observation.freshness = FreshnessVerdict{};
      observation.freshness.state = FreshnessState::RecoveredNotFresh;
      observation.freshness.reason = reason;
      observation.freshness.effective_ttl_nanos = 0;
      observation.freshness.may_support_compliance = false;
      observation.freshness.may_assert_absence = false;
      std::int64_t age = 0;
      if (TryDifference(now, observation.snapshot.collected_at, age)) {
        observation.freshness.age_nanos = age;
      }
      ++invalidated;
    }
  }
  if (invalidated > 0) {
    revision_ = LedgerRevision::FromValue(revision_.value() + 1);
  }
  return invalidated;
}

// ---------------------------------------------------------------------------
// evaluation
// ---------------------------------------------------------------------------

Status FindingLedger::ApplyEvaluation(const EvaluationOutcome& outcome,
                                      const ObservatoryPolicy& policy, NdoTime now,
                                      LedgerApplyReport& report) {
  report = LedgerApplyReport{};

  // Phase one: fence every target and bound the number of new findings before a
  // single mutation is performed, so a refusal leaves the ledger untouched.
  std::size_t new_findings = 0;
  std::vector<bool> accepted(outcome.targets.size(), false);
  for (std::size_t index = 0; index < outcome.targets.size(); ++index) {
    const TargetEvaluation& evaluation = outcome.targets[index];
    const IntentBaseline* current = FindBaseline(evaluation.target);
    if (evaluation.has_baseline) {
      if (current == nullptr || current->generation != evaluation.baseline_generation) {
        ++report.fenced_targets;
        continue;
      }
    } else if (current != nullptr) {
      ++report.fenced_targets;
      continue;
    }
    accepted[index] = true;
    for (const FindingDraft& draft : evaluation.drafts) {
      FindingIdentity identity;
      identity.target = draft.target;
      identity.object = draft.object;
      identity.path = draft.path;
      identity.klass = draft.klass;
      identity.baseline_generation = draft.baseline_generation;
      identity.qualifier = draft.qualifier;
      if (findings_.find(identity.ComputeId()) == findings_.end()) {
        ++new_findings;
      }
    }
  }
  if (findings_.size() + new_findings > limits_.max_findings) {
    return Status::Limit(ReasonCode::LimitFindingsExceeded,
                         "applying this evaluation would exceed the finding envelope");
  }

  // Phase two: apply.
  for (std::size_t index = 0; index < outcome.targets.size(); ++index) {
    if (!accepted[index]) {
      continue;
    }
    const TargetEvaluation& evaluation = outcome.targets[index];
    std::map<FindingId, const FindingDraft*> drafts;
    for (const FindingDraft& draft : evaluation.drafts) {
      FindingIdentity identity;
      identity.target = draft.target;
      identity.object = draft.object;
      identity.path = draft.path;
      identity.klass = draft.klass;
      identity.baseline_generation = draft.baseline_generation;
      identity.qualifier = draft.qualifier;
      const FindingId id = identity.ComputeId();
      drafts.emplace(id, &draft);
    }

    std::set<GroupId> groups_to_drop;
    for (const auto& entry : drafts) {
      const FindingId id = entry.first;
      const FindingDraft& draft = *entry.second;
      const auto existing = findings_.find(id);
      if (existing == findings_.end()) {
        Finding finding;
        finding.id = id;
        finding.identity.target = draft.target;
        finding.identity.object = draft.object;
        finding.identity.path = draft.path;
        finding.identity.klass = draft.klass;
        finding.identity.baseline_generation = draft.baseline_generation;
        finding.identity.qualifier = draft.qualifier;
        finding.klass = draft.klass;
        finding.raw_class = draft.raw_class;
        finding.severity = draft.severity;
        finding.state = FindingState::Open;
        finding.reason = draft.reason;
        finding.baseline_generation = draft.baseline_generation;
        finding.baseline_epoch = draft.baseline_epoch;
        finding.baseline_authority = draft.baseline_authority;
        finding.policy = outcome.policy;
        finding.policy_digest = outcome.policy_digest;
        finding.has_intended = draft.has_intended;
        finding.intended = draft.intended;
        finding.has_observed = draft.has_observed;
        finding.observed = draft.observed;
        finding.evidence = draft.evidence;
        finding.evidence_freshness = evaluation.best_freshness;
        finding.observation_count = 1;
        finding.first_seen = now;
        finding.last_seen = now;
        finding.last_evaluated = now;
        finding.compliance_relevant = draft.compliance_relevant;
        const SuppressionRule* suppression =
            policy.FindSuppression(draft.target, draft.object, draft.path, draft.klass,
                                   draft.severity, now);
        TimelineEntry event;
        event.target = finding.identity.target;
        event.object = finding.identity.object;
        event.finding = finding.id;
        event.at = now;
        event.klass = finding.klass;
        event.severity = finding.severity;
        event.baseline_generation = finding.baseline_generation;
        event.baseline_epoch = finding.baseline_epoch;
        if (!finding.evidence.empty()) {
          event.evidence_digest = finding.evidence.front().content_digest;
        }
        if (suppression != nullptr) {
          finding.state = FindingState::Suppressed;
          finding.suppression_origin = SuppressionOrigin::Policy;
          finding.suppression = suppression->id;
          finding.suppressed_by = suppression->author;
          finding.suppression_reason = suppression->reason;
          finding.suppression_expires_at = suppression->expires_at;
          event.kind = TimelineEventKind::Suppressed;
          event.state_after = FindingState::Suppressed;
          event.reason = ReasonCode::SuppressedByPolicy;
          event.detail = BoundedDetail("suppressed by policy rule " + suppression->id.str() +
                                       ": " + suppression->reason);
          ++report.suppressed;
        } else {
          event.kind = TimelineEventKind::Created;
          event.state_after = FindingState::Open;
          event.reason = ReasonCode::FindingCreated;
          event.detail = BoundedDetail(std::string("finding created: ") + ToText(draft.reason));
        }
        finding.timeline.push_back(event);
        AppendTimeline(event);
        RecomputeSummary(finding);
        findings_.emplace(id, std::move(finding));
        ++report.created;
        report.created_ids.push_back(id);
        continue;
      }

      Finding& finding = existing->second;
      const bool was_resolved = finding.state == FindingState::Resolved;
      const bool was_superseded = finding.state == FindingState::Superseded;
      const bool was_retired = finding.state == FindingState::Retired;
      const Value previous_observed = finding.observed;
      const bool had_observed = finding.has_observed;
      const Severity previous_severity = finding.severity;
      const FreshnessState previous_freshness = finding.evidence_freshness;

      finding.klass = draft.klass;
      finding.raw_class = draft.raw_class;
      finding.severity = draft.severity;
      finding.reason = draft.reason;
      finding.baseline_generation = draft.baseline_generation;
      finding.baseline_epoch = draft.baseline_epoch;
      finding.baseline_authority = draft.baseline_authority;
      finding.policy = outcome.policy;
      finding.policy_digest = outcome.policy_digest;
      finding.has_intended = draft.has_intended;
      finding.intended = draft.intended;
      finding.has_observed = draft.has_observed;
      finding.observed = draft.observed;
      finding.evidence = draft.evidence;
      finding.evidence_freshness = evaluation.best_freshness;
      finding.compliance_relevant = draft.compliance_relevant;
      finding.last_seen = now;
      finding.last_evaluated = now;
      ++finding.observation_count;

      const bool material_change = was_resolved || was_superseded || was_retired ||
                                   finding.severity != previous_severity ||
                                   finding.evidence_freshness != previous_freshness ||
                                   finding.has_observed != had_observed ||
                                   !(finding.observed == previous_observed);

      if (was_resolved || was_superseded || was_retired) {
        finding.state = FindingState::Open;
        finding.resolved_at = NdoTime{};
        finding.resolution_confirmations = 0;
        ++finding.reopen_count;
        ++report.reopened;
        TimelineEntry event;
        event.kind = TimelineEventKind::Reopened;
        event.target = finding.identity.target;
        event.object = finding.identity.object;
        event.finding = finding.id;
        event.at = now;
        event.state_after = FindingState::Open;
        event.klass = finding.klass;
        event.severity = finding.severity;
        event.reason = ReasonCode::FindingReopened;
        event.baseline_generation = finding.baseline_generation;
        event.baseline_epoch = finding.baseline_epoch;
        if (!finding.evidence.empty()) {
          event.evidence_digest = finding.evidence.front().content_digest;
        }
        event.detail = BoundedDetail("drift is present again under the current baseline");
        finding.timeline.push_back(event);
        AppendTimeline(event);
      } else if (material_change) {
        TimelineEntry event;
        event.kind = TimelineEventKind::Updated;
        event.target = finding.identity.target;
        event.object = finding.identity.object;
        event.finding = finding.id;
        event.at = now;
        event.state_after = finding.state;
        event.klass = finding.klass;
        event.severity = finding.severity;
        event.reason = ReasonCode::FindingUpdated;
        event.baseline_generation = finding.baseline_generation;
        event.baseline_epoch = finding.baseline_epoch;
        if (!finding.evidence.empty()) {
          event.evidence_digest = finding.evidence.front().content_digest;
        }
        event.detail = BoundedDetail("evidence changed: " + std::string(ToText(finding.reason)));
        finding.timeline.push_back(event);
        AppendTimeline(event);
      }
      resolution_streak_[id] = 0;
      if (finding.suppression.has_value() &&
          finding.suppression_origin == SuppressionOrigin::Policy) {
        const bool still_suppressed =
            policy.FindSuppression(finding.identity.target, finding.identity.object,
                                   finding.identity.path, finding.klass, finding.severity,
                                   now) != nullptr;
        if (!still_suppressed) {
          finding.suppression.reset();
          finding.suppression_origin = SuppressionOrigin::None;
          finding.suppressed_by = ActorId{};
          finding.suppression_reason.clear();
          finding.suppression_expires_at.reset();
          if (finding.state == FindingState::Suppressed) {
            finding.state = finding.acknowledged_by.empty() ? FindingState::Open
                                                            : FindingState::Acknowledged;
          }
          TimelineEntry event;
          event.kind = TimelineEventKind::SuppressionExpired;
          event.target = finding.identity.target;
          event.object = finding.identity.object;
          event.finding = finding.id;
          event.at = now;
          event.state_after = finding.state;
          event.klass = finding.klass;
          event.severity = finding.severity;
          event.reason = ReasonCode::SuppressionExpired;
          event.baseline_generation = finding.baseline_generation;
          event.baseline_epoch = finding.baseline_epoch;
          event.detail = "the governing suppression no longer applies";
          finding.timeline.push_back(event);
          AppendTimeline(event);
        }
      }
      RecomputeSummary(finding);
      ++report.updated;
    }

    // Resolution and reclassification for findings that were not drafted.
    std::vector<FindingId> live_ids;
    for (const auto& entry : findings_) {
      if (!(entry.second.identity.target == evaluation.target)) {
        continue;
      }
      if (!IsLiveState(entry.second.state)) {
        continue;
      }
      if (drafts.find(entry.first) != drafts.end()) {
        continue;
      }
      live_ids.push_back(entry.first);
    }
    for (const FindingId& id : live_ids) {
      Finding& finding = findings_[id];
      if (!evaluation.compliance_decidable) {
        // No fresh, sufficiently covering evidence: the finding stays open and
        // is never declared resolved by absence of evidence.
        ++report.unchanged;
        continue;
      }
      bool reclassified = false;
      for (const auto& draft_entry : drafts) {
        const Finding& other = findings_[draft_entry.first];
        if (other.identity.object == finding.identity.object &&
            other.identity.path == finding.identity.path &&
            other.baseline_generation == finding.baseline_generation) {
          reclassified = true;
          break;
        }
      }
      if (reclassified) {
        finding.state = FindingState::Superseded;
        finding.reason = ReasonCode::FindingReclassified;
        finding.last_evaluated = now;
        if (finding.group.is_set()) {
          groups_to_drop.insert(finding.group);
          finding.group = GroupId{};
          finding.group_cause = RootCauseKind::None;
        }
        TimelineEntry event;
        event.kind = TimelineEventKind::Reclassified;
        event.target = finding.identity.target;
        event.object = finding.identity.object;
        event.finding = finding.id;
        event.at = now;
        event.state_after = finding.state;
        event.klass = finding.klass;
        event.severity = finding.severity;
        event.reason = ReasonCode::FindingReclassified;
        event.baseline_generation = finding.baseline_generation;
        event.baseline_epoch = finding.baseline_epoch;
        event.detail = "the same location is now explained by a differently classified finding";
        finding.timeline.push_back(event);
        AppendTimeline(event);
        ++report.superseded;
        continue;
      }
      std::uint32_t& streak = resolution_streak_[id];
      ++streak;
      finding.resolution_confirmations = streak;
      const std::uint32_t required =
          outcome.resolution_confirmations == 0 ? 1 : outcome.resolution_confirmations;
      if (streak >= required) {
        finding.state = FindingState::Resolved;
        finding.reason = ReasonCode::FindingResolved;
        finding.resolved_at = now;
        finding.last_evaluated = now;
        if (finding.group.is_set()) {
          groups_to_drop.insert(finding.group);
          finding.group = GroupId{};
          finding.group_cause = RootCauseKind::None;
        }
        RecomputeSummary(finding);
        TimelineEntry event;
        event.kind = TimelineEventKind::Resolved;
        event.target = finding.identity.target;
        event.object = finding.identity.object;
        event.finding = finding.id;
        event.at = now;
        event.state_after = FindingState::Resolved;
        event.klass = finding.klass;
        event.severity = finding.severity;
        event.reason = ReasonCode::FindingResolved;
        event.baseline_generation = finding.baseline_generation;
        event.baseline_epoch = finding.baseline_epoch;
        event.detail = BoundedDetail("fresh evidence agreed with intent for " +
                                     std::to_string(streak) + " evaluation(s)");
        finding.timeline.push_back(event);
        AppendTimeline(event);
        ++report.resolved;
        report.resolved_ids.push_back(id);
      } else {
        ++report.unchanged;
      }
    }

    Status status = RefreshGroups(evaluation.target, now, report);
    if (!status.ok()) {
      return status;
    }
    for (const GroupId& group : groups_to_drop) {
      groups_.erase(group);
    }
  }

  static_cast<void>(ExpireSuppressions(now));
  revision_ = LedgerRevision::FromValue(revision_.value() + 1);
  TrimTimelineIfNeeded();
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status FindingLedger::RefreshGroups(const TargetId& target, NdoTime now,
                                    LedgerApplyReport& report) {
  std::map<std::pair<std::uint64_t, std::uint8_t>, std::vector<const Finding*>> buckets;
  for (const auto& entry : findings_) {
    const Finding& finding = entry.second;
    if (!(finding.identity.target == target)) {
      continue;
    }
    if (!IsLiveState(finding.state)) {
      continue;
    }
    const RootCauseKind cause = CauseFor(finding.klass);
    buckets[{finding.baseline_generation.value(), static_cast<std::uint8_t>(cause)}].push_back(
        &finding);
  }

  std::set<GroupId> produced;
  std::map<FindingId, GroupId> assignment;
  for (auto& bucket : buckets) {
    const RootCauseKind cause = static_cast<RootCauseKind>(bucket.first.second);
    if (cause == RootCauseKind::None) {
      continue;
    }
    if (!CauseFormsGroup(cause, bucket.second.size())) {
      continue;
    }
    std::sort(bucket.second.begin(), bucket.second.end(),
              [](const Finding* lhs, const Finding* rhs) { return lhs->id < rhs->id; });
    const Digest discriminator = GroupDiscriminator(bucket.second);
    const IntentGeneration generation =
        IntentGeneration::FromValue(bucket.second.front()->baseline_generation.value());
    const GroupId id = GroupIdentity(target, generation, cause, discriminator);
    produced.insert(id);
    auto existing = groups_.find(id);
    if (existing == groups_.end()) {
      if (groups_.size() >= limits_.max_groups) {
        return Status::Limit(ReasonCode::LimitObjectsExceeded,
                             "root-cause group count exceeds the envelope");
      }
      RootCauseGroup group;
      group.id = id;
      group.target = target;
      group.baseline_generation = generation;
      group.baseline_epoch = bucket.second.front()->baseline_epoch;
      group.cause = cause;
      group.discriminator = discriminator;
      group.first_seen = now;
      group.last_seen = now;
      group.observation_count = 1;
      for (const Finding* finding : bucket.second) {
        group.members.push_back(finding->id);
        group.objects.push_back(finding->identity.object);
        assignment[finding->id] = id;
      }
      std::sort(group.objects.begin(), group.objects.end());
      group.objects.erase(std::unique(group.objects.begin(), group.objects.end()),
                          group.objects.end());
      group.summary = BoundedDetail(std::string(ToText(cause)) + " explains " +
                                    std::to_string(group.members.size()) +
                                    " finding(s) on target " + target.str());
      groups_.emplace(id, std::move(group));
      ++report.groups_touched;
    } else {
      RootCauseGroup& group = existing->second;
      group.last_seen = now;
      ++group.observation_count;
      group.members.clear();
      group.objects.clear();
      for (const Finding* finding : bucket.second) {
        group.members.push_back(finding->id);
        group.objects.push_back(finding->identity.object);
        assignment[finding->id] = id;
      }
      std::sort(group.objects.begin(), group.objects.end());
      group.objects.erase(std::unique(group.objects.begin(), group.objects.end()),
                          group.objects.end());
      group.summary = BoundedDetail(std::string(ToText(cause)) + " explains " +
                                    std::to_string(group.members.size()) +
                                    " finding(s) on target " + target.str());
      ++report.groups_touched;
    }
  }

  // Clear group assignment for findings that no longer belong to a group, and
  // drop groups whose target produced nothing this pass.
  for (auto& entry : findings_) {
    Finding& finding = entry.second;
    if (!(finding.identity.target == target)) {
      continue;
    }
    if (!IsLiveState(finding.state)) {
      continue;
    }
    const auto assigned = assignment.find(finding.id);
    if (assigned != assignment.end()) {
      if (!(finding.group == assigned->second)) {
        finding.group = assigned->second;
        finding.group_cause = CauseFor(finding.klass);
        TimelineEntry event;
        event.kind = TimelineEventKind::Grouped;
        event.target = finding.identity.target;
        event.object = finding.identity.object;
        event.finding = finding.id;
        event.at = now;
        event.state_after = finding.state;
        event.klass = finding.klass;
        event.severity = finding.severity;
        event.reason = ReasonCode::None;
        event.baseline_generation = finding.baseline_generation;
        event.baseline_epoch = finding.baseline_epoch;
        event.detail = BoundedDetail("attributed to root-cause group " +
                                     assigned->second.ToShortHex());
        finding.timeline.push_back(event);
        AppendTimeline(event);
      }
      continue;
    }
    // The cause is recorded for every live finding, whether or not it forms a
    // group, so a query can filter by root cause.
    if (finding.group.is_set()) {
      finding.group = GroupId{};
    }
    finding.group_cause = CauseFor(finding.klass);
  }
  for (auto it = groups_.begin(); it != groups_.end();) {
    if ((it->second.target == target) && produced.find(it->first) == produced.end()) {
      it = groups_.erase(it);
      continue;
    }
    ++it;
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

// ---------------------------------------------------------------------------
// operator actions
// ---------------------------------------------------------------------------

Status FindingLedger::Suppress(FindingId finding, ActorId actor, std::string reason,
                               std::optional<NdoTime> expires_at, NdoTime now) {
  const auto found = findings_.find(finding);
  if (found == findings_.end()) {
    return Status::NotFound(ReasonCode::FindingNotFound,
                            "no finding exists with the supplied identity");
  }
  Finding& target = found->second;
  if (actor.empty() || !IsValidIdentityText(actor.str())) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "suppression actor is invalid");
  }
  if (suppressions_active_ >= limits_.max_suppressions && !target.suppression.has_value()) {
    return Status::Limit(ReasonCode::LimitFieldsExceeded, "suppression count exceeds the envelope");
  }
  std::string suppression_text = "suppression/";
  suppression_text.append(target.id.ToHex().substr(0, 24));
  const auto id = SuppressionId::TryParse(suppression_text);
  if (!id.has_value()) {
    return Status::Internal(ReasonCode::EncodingMalformed, "generated suppression identity is invalid");
  }
  if (!target.suppression.has_value()) {
    ++suppressions_active_;
  }
  target.suppression = *id;
  target.suppression_origin = SuppressionOrigin::Operator;
  target.suppressed_by = actor;
  target.suppression_reason = BoundedDetail(std::move(reason));
  target.suppression_expires_at = expires_at;
  if (IsLiveState(target.state)) {
    target.state = FindingState::Suppressed;
  }
  TimelineEntry event;
  event.kind = TimelineEventKind::Suppressed;
  event.target = target.identity.target;
  event.object = target.identity.object;
  event.finding = target.id;
  event.at = now;
  event.state_after = target.state;
  event.klass = target.klass;
  event.severity = target.severity;
  event.reason = ReasonCode::SuppressedByOperator;
  event.baseline_generation = target.baseline_generation;
  event.baseline_epoch = target.baseline_epoch;
  event.actor = actor;
  event.detail = BoundedDetail("suppressed by " + actor.str() + ": " + target.suppression_reason);
  target.timeline.push_back(event);
  AppendTimeline(event);
  RecomputeSummary(target);
  revision_ = LedgerRevision::FromValue(revision_.value() + 1);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status FindingLedger::ClearSuppression(FindingId finding, ActorId actor, NdoTime now) {
  const auto found = findings_.find(finding);
  if (found == findings_.end()) {
    return Status::NotFound(ReasonCode::SuppressionNotFound, "no finding exists with that identity");
  }
  Finding& target = found->second;
  if (!target.suppression.has_value()) {
    return Status::NotFound(ReasonCode::SuppressionNotFound, "the finding is not suppressed");
  }
  target.suppression.reset();
  target.suppression_origin = SuppressionOrigin::None;
  target.suppressed_by = ActorId{};
  target.suppression_reason.clear();
  target.suppression_expires_at.reset();
  if (suppressions_active_ > 0) {
    --suppressions_active_;
  }
  if (target.state == FindingState::Suppressed) {
    target.state = target.acknowledged_by.empty() ? FindingState::Open : FindingState::Acknowledged;
  }
  TimelineEntry event;
  event.kind = TimelineEventKind::SuppressionCleared;
  event.target = target.identity.target;
  event.object = target.identity.object;
  event.finding = target.id;
  event.at = now;
  event.state_after = target.state;
  event.klass = target.klass;
  event.severity = target.severity;
  event.reason = ReasonCode::None;
  event.baseline_generation = target.baseline_generation;
  event.baseline_epoch = target.baseline_epoch;
  event.actor = actor;
  event.detail = "suppression cleared; the underlying evidence is unchanged";
  target.timeline.push_back(event);
  AppendTimeline(event);
  RecomputeSummary(target);
  revision_ = LedgerRevision::FromValue(revision_.value() + 1);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status FindingLedger::Acknowledge(FindingId finding, ActorId actor, std::string reason, NdoTime now) {
  const auto found = findings_.find(finding);
  if (found == findings_.end()) {
    return Status::NotFound(ReasonCode::FindingNotFound, "no finding exists with that identity");
  }
  Finding& target = found->second;
  if (actor.empty() || !IsValidIdentityText(actor.str())) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "acknowledgement actor is invalid");
  }
  target.acknowledged_by = actor;
  target.acknowledged_at = now;
  target.acknowledgement_reason = BoundedDetail(std::move(reason));
  if (target.state == FindingState::Open) {
    target.state = FindingState::Acknowledged;
  }
  TimelineEntry event;
  event.kind = TimelineEventKind::Acknowledged;
  event.target = target.identity.target;
  event.object = target.identity.object;
  event.finding = target.id;
  event.at = now;
  event.state_after = target.state;
  event.klass = target.klass;
  event.severity = target.severity;
  event.reason = ReasonCode::AcknowledgementRecorded;
  event.baseline_generation = target.baseline_generation;
  event.baseline_epoch = target.baseline_epoch;
  event.actor = actor;
  event.detail = BoundedDetail("acknowledged by " + actor.str() + ": " + target.acknowledgement_reason);
  target.timeline.push_back(event);
  AppendTimeline(event);
  RecomputeSummary(target);
  revision_ = LedgerRevision::FromValue(revision_.value() + 1);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status FindingLedger::ClearAcknowledgement(FindingId finding, ActorId actor, NdoTime now) {
  const auto found = findings_.find(finding);
  if (found == findings_.end()) {
    return Status::NotFound(ReasonCode::FindingNotFound, "no finding exists with that identity");
  }
  Finding& target = found->second;
  if (target.acknowledged_by.empty()) {
    return Status::NotFound(ReasonCode::AcknowledgementRecorded, "the finding is not acknowledged");
  }
  target.acknowledged_by = ActorId{};
  target.acknowledged_at = NdoTime{};
  target.acknowledgement_reason.clear();
  if (target.state == FindingState::Acknowledged) {
    target.state = FindingState::Open;
  }
  TimelineEntry event;
  event.kind = TimelineEventKind::AcknowledgementCleared;
  event.target = target.identity.target;
  event.object = target.identity.object;
  event.finding = target.id;
  event.at = now;
  event.state_after = target.state;
  event.klass = target.klass;
  event.severity = target.severity;
  event.reason = ReasonCode::None;
  event.baseline_generation = target.baseline_generation;
  event.baseline_epoch = target.baseline_epoch;
  event.actor = actor;
  event.detail = "acknowledgement cleared";
  target.timeline.push_back(event);
  AppendTimeline(event);
  RecomputeSummary(target);
  revision_ = LedgerRevision::FromValue(revision_.value() + 1);
  return Status(StatusCode::Ok, ReasonCode::None);
}

std::size_t FindingLedger::ExpireSuppressions(NdoTime now) {
  std::size_t expired = 0;
  for (auto& entry : findings_) {
    Finding& finding = entry.second;
    if (!finding.suppression.has_value()) {
      continue;
    }
    if (!finding.suppression_expires_at.has_value() || now < *finding.suppression_expires_at) {
      continue;
    }
    const NdoTime expired_at = *finding.suppression_expires_at;
    finding.suppression.reset();
    finding.suppression_origin = SuppressionOrigin::None;
    finding.suppressed_by = ActorId{};
    finding.suppression_reason.clear();
    finding.suppression_expires_at.reset();
    if (suppressions_active_ > 0) {
      --suppressions_active_;
    }
    ++suppressions_expired_;
    if (finding.state == FindingState::Suppressed) {
      finding.state = finding.acknowledged_by.empty() ? FindingState::Open
                                                      : FindingState::Acknowledged;
    }
    TimelineEntry event;
    event.kind = TimelineEventKind::SuppressionExpired;
    event.target = finding.identity.target;
    event.object = finding.identity.object;
    event.finding = finding.id;
    event.at = now;
    event.state_after = finding.state;
    event.klass = finding.klass;
    event.severity = finding.severity;
    event.reason = ReasonCode::SuppressionExpired;
    event.baseline_generation = finding.baseline_generation;
    event.baseline_epoch = finding.baseline_epoch;
    event.detail = BoundedDetail("suppression expired at " + FormatTime(expired_at));
    finding.timeline.push_back(event);
    AppendTimeline(event);
    RecomputeSummary(finding);
    ++expired;
  }
  if (expired > 0) {
    revision_ = LedgerRevision::FromValue(revision_.value() + 1);
  }
  return expired;
}

// ---------------------------------------------------------------------------
// inspection
// ---------------------------------------------------------------------------

const Finding* FindingLedger::FindFinding(FindingId id) const noexcept {
  const auto found = findings_.find(id);
  if (found == findings_.end()) {
    return nullptr;
  }
  return &found->second;
}

std::vector<const Finding*> FindingLedger::Findings() const {
  std::vector<const Finding*> findings;
  findings.reserve(findings_.size());
  for (const auto& entry : findings_) {
    findings.push_back(&entry.second);
  }
  return findings;
}

std::vector<const RootCauseGroup*> FindingLedger::Groups() const {
  std::vector<const RootCauseGroup*> groups;
  groups.reserve(groups_.size());
  for (const auto& entry : groups_) {
    groups.push_back(&entry.second);
  }
  return groups;
}

std::vector<const TimelineEntry*> FindingLedger::GlobalTimeline() const {
  std::vector<const TimelineEntry*> entries;
  entries.reserve(global_timeline_.size());
  for (const TimelineEntry& entry : global_timeline_) {
    entries.push_back(&entry);
  }
  return entries;
}

LedgerStats FindingLedger::Stats() const {
  LedgerStats stats;
  stats.targets = Targets().size();
  stats.baselines = baselines_.size();
  std::set<SourceId> sources;
  for (const auto& entry : windows_) {
    stats.observations += entry.second.size();
    sources.insert(entry.first.source);
  }
  stats.sources = sources.size();
  stats.findings = findings_.size();
  for (const auto& entry : findings_) {
    const Finding& finding = entry.second;
    if (IsLiveState(finding.state)) {
      ++stats.live_findings;
    }
    if (finding.state == FindingState::Resolved) {
      ++stats.resolved_findings;
    }
    if (finding.state == FindingState::Superseded) {
      ++stats.superseded_findings;
    }
    if (finding.state == FindingState::Suppressed) {
      ++stats.suppressed_findings;
    }
    if (finding.state == FindingState::Acknowledged) {
      ++stats.acknowledged_findings;
    }
  }
  stats.groups = groups_.size();
  stats.timeline_entries = global_timeline_.size();
  stats.suppressions_active = suppressions_active_;
  stats.suppressions_expired = suppressions_expired_;
  return stats;
}

Digest FindingLedger::ContentDigest() const {
  Sha256 hasher;
  hasher.UpdateTag(kContentTag);
  hasher.UpdateU64(revision_.value());
  hasher.UpdateU64(baselines_.size());
  for (const auto& entry : baselines_) {
    hasher.UpdateLengthPrefixed(entry.first.str());
    hasher.UpdateU64(entry.second.generation.value());
    hasher.UpdateU64(entry.second.epoch.value());
    hasher.Update(entry.second.content_digest.bytes.data(), entry.second.content_digest.bytes.size());
    hasher.UpdateU64(entry.second.objects.size());
    for (const auto& object : entry.second.objects) {
      hasher.UpdateLengthPrefixed(object.first.str());
      hasher.UpdateU64(object.second.fields.size());
      for (const auto& field : object.second.fields) {
        hasher.UpdateLengthPrefixed(field.first.ToText());
        field.second.intended.HashInto(hasher);
      }
    }
  }
  hasher.UpdateU64(windows_.size());
  for (const auto& entry : windows_) {
    hasher.UpdateLengthPrefixed(entry.first.target.str());
    hasher.UpdateLengthPrefixed(entry.first.source.str());
    hasher.UpdateU64(entry.second.size());
    for (const RetainedObservation& observation : entry.second) {
      hasher.UpdateLengthPrefixed(observation.snapshot.snapshot_id.str());
      hasher.UpdateByte(observation.recovered ? 1u : 0u);
      hasher.UpdateByte(static_cast<std::uint8_t>(observation.freshness.state));
    }
  }
  hasher.UpdateU64(findings_.size());
  for (const auto& entry : findings_) {
    const Finding& finding = entry.second;
    hasher.Update(entry.first.digest().bytes.data(), entry.first.digest().bytes.size());
    hasher.UpdateByte(static_cast<std::uint8_t>(finding.state));
    hasher.UpdateByte(static_cast<std::uint8_t>(finding.klass));
    hasher.UpdateByte(static_cast<std::uint8_t>(finding.severity));
    hasher.UpdateU64(finding.baseline_generation.value());
    hasher.UpdateU64(finding.observation_count);
    hasher.UpdateU64(finding.reopen_count);
    hasher.UpdateU64(static_cast<std::uint64_t>(finding.first_seen.unix_nanos));
    hasher.UpdateU64(static_cast<std::uint64_t>(finding.last_seen.unix_nanos));
    hasher.UpdateLengthPrefixed(finding.identity.path.ToText());
    if (finding.group.is_set()) {
      hasher.Update(finding.group.digest().bytes.data(), finding.group.digest().bytes.size());
    }
  }
  hasher.UpdateU64(groups_.size());
  for (const auto& entry : groups_) {
    hasher.Update(entry.first.digest().bytes.data(), entry.first.digest().bytes.size());
    hasher.UpdateLengthPrefixed(entry.second.target.str());
    hasher.UpdateU64(entry.second.members.size());
    for (const FindingId& member : entry.second.members) {
      hasher.Update(member.digest().bytes.data(), member.digest().bytes.size());
    }
  }
  hasher.UpdateU64(global_timeline_.size());
  return hasher.Final();
}

// ---------------------------------------------------------------------------
// recovery-only mutation
// ---------------------------------------------------------------------------

Status FindingLedger::RestoreBaseline(IntentBaseline baseline) {
  if (baselines_.size() >= limits_.max_targets &&
      baselines_.find(baseline.target) == baselines_.end()) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded, "restored baseline count exceeds the envelope");
  }
  baselines_[baseline.target] = std::move(baseline);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status FindingLedger::RestoreObservation(RetainedObservation observation) {
  const SourceWindowKey key{observation.snapshot.target, observation.snapshot.source};
  auto& window = windows_[key];
  if (window.size() >= limits_.max_retained_snapshots_per_source) {
    window.erase(window.begin());
  }
  // Recovered evidence is never fresh, whatever the persisted verdict said.
  observation.recovered = true;
  observation.freshness = FreshnessVerdict{};
  observation.freshness.state = FreshnessState::RecoveredNotFresh;
  observation.freshness.reason = ReasonCode::EvidenceRecoveredNotFresh;
  observation.freshness.may_support_compliance = false;
  observation.freshness.may_assert_absence = false;
  window.push_back(std::move(observation));
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status FindingLedger::RestoreFinding(Finding finding) {
  if (findings_.size() >= limits_.max_findings &&
      findings_.find(finding.id) == findings_.end()) {
    return Status::Limit(ReasonCode::LimitFindingsExceeded, "restored finding count exceeds the envelope");
  }
  if (!finding.id.is_set()) {
    return Status::Rejected(ReasonCode::LedgerDecodeFailed, "restored finding has no identity");
  }
  const bool already_recovered =
      finding.evidence_freshness == FreshnessState::RecoveredNotFresh;
  finding.evidence_freshness = FreshnessState::RecoveredNotFresh;
  if (IsLiveState(finding.state) && !already_recovered) {
    // Recovery is a transition worth recording once: the finding survived a
    // restart and its evidence is explicitly no longer current. Decoding an
    // already-recovered ledger must not fabricate the transition again.
    TimelineEntry event;
    event.kind = TimelineEventKind::EvidenceRecovered;
    event.target = finding.identity.target;
    event.object = finding.identity.object;
    event.finding = finding.id;
    event.at = finding.last_evaluated;
    event.state_after = finding.state;
    event.klass = finding.klass;
    event.severity = finding.severity;
    event.reason = ReasonCode::EvidenceRecoveredNotFresh;
    event.baseline_generation = finding.baseline_generation;
    event.baseline_epoch = finding.baseline_epoch;
    event.detail = "evidence recovered from durable state is not current";
    event.sequence = NextTimelineSequence();
    finding.timeline.push_back(event);
  }
  if (finding.timeline.size() > limits_.max_timeline_entries_per_finding) {
    const std::size_t excess = finding.timeline.size() - limits_.max_timeline_entries_per_finding;
    finding.timeline.erase(finding.timeline.begin(),
                           finding.timeline.begin() + static_cast<std::ptrdiff_t>(excess));
  }
  if (finding.suppression.has_value()) {
    ++suppressions_active_;
  }
  findings_[finding.id] = std::move(finding);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status FindingLedger::RestoreGroup(RootCauseGroup group) {
  if (groups_.size() >= limits_.max_groups && groups_.find(group.id) == groups_.end()) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded, "restored group count exceeds the envelope");
  }
  groups_[group.id] = std::move(group);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status FindingLedger::RestoreTimeline(TimelineEntry entry) {
  global_timeline_.push_back(std::move(entry));
  TrimTimelineIfNeeded();
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status FindingLedger::RestoreRevision(LedgerRevision revision) {
  revision_ = revision;
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status FindingLedger::RestoreSuppressionSequence(std::uint64_t sequence) {
  timeline_sequence_ = sequence;
  return Status(StatusCode::Ok, ReasonCode::None);
}

// ---------------------------------------------------------------------------
// private
// ---------------------------------------------------------------------------

void FindingLedger::AppendTimeline(TimelineEntry entry) {
  entry.sequence = NextTimelineSequence();
  global_timeline_.push_back(std::move(entry));
}

void FindingLedger::RecordEvent(TimelineEntry entry) {
  AppendTimeline(std::move(entry));
  TrimTimelineIfNeeded();
  revision_ = LedgerRevision::FromValue(revision_.value() + 1);
}

void FindingLedger::TrimTimelineIfNeeded() {
  if (global_timeline_.size() <= limits_.max_global_timeline_entries) {
    return;
  }
  const std::size_t excess = global_timeline_.size() - limits_.max_global_timeline_entries;
  global_timeline_.erase(global_timeline_.begin(),
                         global_timeline_.begin() + static_cast<std::ptrdiff_t>(excess));
}

void FindingLedger::RecomputeSummary(Finding& finding) const {
  // Per-finding history is bounded here because every path that appends to a
  // finding timeline finishes with this call.
  if (finding.timeline.size() > limits_.max_timeline_entries_per_finding) {
    const std::size_t excess = finding.timeline.size() - limits_.max_timeline_entries_per_finding;
    finding.timeline.erase(finding.timeline.begin(),
                           finding.timeline.begin() + static_cast<std::ptrdiff_t>(excess));
  }
  finding.summary = ExplainFinding(finding);
}

}  // namespace network_drift_observatory
}  // namespace summon
