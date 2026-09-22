// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/comparison.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace summon {
namespace network_drift_observatory {
namespace {

/// Sources considered for cross-source conflict detection. The scan is
/// quadratic in this number, so it is bounded rather than proportional to the
/// number of registered sources.
constexpr std::size_t kMaxConflictSources = 8;

struct EvidenceView {
  const ObservationSnapshot* snapshot{nullptr};
  FreshnessVerdict verdict;
  bool usable{false};
  bool complete{false};
  bool absence_authority{false};
  std::size_t priority{0};
  Digest content_digest;
};

std::size_t PriorityOf(const ObservatoryPolicy& policy, const SourceId& source) {
  for (std::size_t index = 0; index < policy.source_priority.size(); ++index) {
    if (policy.source_priority[index] == source) {
      return index;
    }
  }
  return policy.source_priority.size();
}

bool ViewLess(const EvidenceView& lhs, const EvidenceView& rhs) {
  // Total order: usable evidence first, then declared authority order, then the
  // most complete coverage, then the source identity. The order never depends
  // on arrival time, so the chosen primary source is reproducible.
  if (lhs.usable != rhs.usable) {
    return lhs.usable;
  }
  if (lhs.priority != rhs.priority) {
    return lhs.priority < rhs.priority;
  }
  if (lhs.complete != rhs.complete) {
    return lhs.complete;
  }
  if (lhs.snapshot->epoch != rhs.snapshot->epoch) {
    return rhs.snapshot->epoch < lhs.snapshot->epoch;
  }
  if (lhs.snapshot->incarnation != rhs.snapshot->incarnation) {
    return rhs.snapshot->incarnation < lhs.snapshot->incarnation;
  }
  if (lhs.snapshot->sequence != rhs.snapshot->sequence) {
    return rhs.snapshot->sequence < lhs.snapshot->sequence;
  }
  return lhs.snapshot->source < rhs.snapshot->source;
}

EvidenceRef MakeRef(const EvidenceView& view) {
  EvidenceRef ref;
  ref.source = view.snapshot->source;
  ref.snapshot = view.snapshot->snapshot_id;
  ref.epoch = view.snapshot->epoch;
  ref.incarnation = view.snapshot->incarnation;
  ref.sequence = view.snapshot->sequence;
  ref.collected_at = view.snapshot->collected_at;
  ref.received_at = view.snapshot->received_at;
  ref.freshness = view.verdict.state;
  ref.content_digest = view.content_digest;
  ref.coverage = view.snapshot->coverage;
  ref.evidence = view.snapshot->evidence;
  return ref;
}

Value UintValue(std::uint64_t value) {
  if (value <= 9223372036854775807ULL) {
    return Value::MakeInt(static_cast<std::int64_t>(value));
  }
  return Value::MakeUint(value);
}

/// Reads the reserved applied-generation marker from an observed object.
bool TryReadAppliedGeneration(const ObservedObject& object, IntentGeneration& out) {
  const auto parsed = FieldPath::TryParse(kAppliedGenerationPath, 4, 128);
  if (!parsed.has_value()) {
    return false;
  }
  const auto found = object.fields.find(*parsed);
  if (found == object.fields.end()) {
    return false;
  }
  if (const std::int64_t* value = found->second.as_int(); value != nullptr && *value >= 0) {
    out = IntentGeneration::FromValue(static_cast<std::uint64_t>(*value));
    return true;
  }
  if (const std::uint64_t* value = found->second.as_uint(); value != nullptr) {
    out = IntentGeneration::FromValue(*value);
    return true;
  }
  return false;
}

bool IsReservedObjectId(const ObjectId& id) {
  const std::string& text = id.str();
  return !text.empty() && text.front() == '@';
}

bool IsReservedPath(const FieldPath& path) {
  if (path.empty()) {
    return false;
  }
  const PathSegment& first = path[0];
  if (first.kind != PathSegment::Kind::Key || first.key.empty()) {
    return false;
  }
  return first.key.front() == '@';
}

bool ObjectFullyVisible(const EvidenceView& view, const ObjectId& id) {
  if (view.snapshot->declares_unobserved(id)) {
    return false;
  }
  return view.complete;
}

bool FieldVisible(const EvidenceView& view, const ObjectId& id, const FieldPath& path) {
  if (!ObjectFullyVisible(view, id)) {
    return false;
  }
  if (path.size() > 1 && !view.snapshot->capabilities.reports_nested_paths) {
    // A flat reporter cannot prove the absence of a nested member.
    return false;
  }
  return true;
}

Digest ConflictQualifier(const SourceId& first, const SourceId& second) {
  const SourceId& low = first < second ? first : second;
  const SourceId& high = first < second ? second : first;
  Sha256 hasher;
  hasher.UpdateTag("ndo/source-conflict/v1");
  hasher.UpdateLengthPrefixed(low.str());
  hasher.UpdateLengthPrefixed(high.str());
  return hasher.Final();
}

Digest GenerationQualifier(std::string_view kind, IntentGeneration intended,
                           const std::vector<std::uint64_t>& applied) {
  Sha256 hasher;
  hasher.UpdateTag("ndo/generation-divergence/v1");
  hasher.UpdateLengthPrefixed(kind);
  hasher.UpdateU64(intended.value());
  hasher.UpdateU64(applied.size());
  for (std::uint64_t value : applied) {
    hasher.UpdateU64(value);
  }
  return hasher.Final();
}

void AttachEvidence(FindingDraft& draft, const EvidenceView& view, const RuntimeLimits& limits) {
  if (draft.evidence.size() >= limits.max_evidence_refs_per_finding) {
    return;
  }
  draft.evidence.push_back(MakeRef(view));
}

FindingDraft MakeDraft(const TargetId& target, const ObjectId& object, const FieldPath& path,
                       DriftClass klass, const IntentBaseline& baseline,
                       const ObservatoryPolicy& policy) {
  FindingDraft draft;
  draft.target = target;
  draft.object = object;
  draft.path = path;
  draft.klass = klass;
  draft.raw_class = klass;
  draft.baseline_generation = baseline.generation;
  draft.baseline_epoch = baseline.epoch;
  draft.baseline_authority = baseline.authority;
  draft.severity = policy.SeverityFor(target, object, path, klass);
  draft.reason = ReasonCode::None;
  return draft;
}

struct GenerationScan {
  bool any_applied{false};
  bool any_matches_baseline{false};
  std::vector<std::uint64_t> applied;
};

GenerationScan ScanAppliedGenerations(const EvidenceView& view,
                                      const std::map<ObjectId, IntentObject>& objects,
                                      IntentGeneration baseline) {
  GenerationScan scan;
  for (const auto& entry : objects) {
    const ObservedObject* observed = view.snapshot->FindObject(entry.first);
    if (observed == nullptr || observed->presence != ObjectPresence::Present) {
      continue;
    }
    IntentGeneration applied;
    if (!TryReadAppliedGeneration(*observed, applied)) {
      continue;
    }
    scan.any_applied = true;
    scan.applied.push_back(applied.value());
    if (baseline.is_set() && applied == baseline) {
      scan.any_matches_baseline = true;
    }
  }
  std::sort(scan.applied.begin(), scan.applied.end());
  scan.applied.erase(std::unique(scan.applied.begin(), scan.applied.end()), scan.applied.end());
  return scan;
}

void AppendTrace(TargetEvaluation& evaluation, std::string text) {
  constexpr std::size_t kMaxTraceEntries = 64;
  if (evaluation.trace.size() >= kMaxTraceEntries) {
    return;
  }
  evaluation.trace.push_back(std::move(text));
}

}  // namespace

std::size_t EvaluationOutcome::DraftCount() const noexcept {
  std::size_t total = 0;
  for (const TargetEvaluation& evaluation : targets) {
    total += evaluation.drafts.size();
  }
  return total;
}

Digest EvaluationOutcome::ComputeDigest() const {
  Sha256 hasher;
  hasher.UpdateTag("ndo/evaluation-outcome/v1");
  hasher.UpdateU64(static_cast<std::uint64_t>(now.unix_nanos));
  hasher.UpdateU64(epoch.value());
  hasher.UpdateU64(incarnation.value());
  hasher.UpdateLengthPrefixed(policy.str());
  hasher.Update(policy_digest.bytes.data(), policy_digest.bytes.size());
  hasher.UpdateU64(targets.size());
  for (const TargetEvaluation& evaluation : targets) {
    hasher.UpdateLengthPrefixed(evaluation.target.str());
    hasher.UpdateLengthPrefixed(evaluation.baseline_generation.value() == 0 ? "" : "baseline");
    hasher.UpdateU64(evaluation.baseline_generation.value());
    hasher.UpdateU64(evaluation.baseline_epoch.value());
    hasher.UpdateByte(evaluation.compliance_decidable ? 1u : 0u);
    hasher.UpdateByte(evaluation.compliant ? 1u : 0u);
    hasher.UpdateLengthPrefixed(ToText(evaluation.decision_reason));
    hasher.UpdateU64(evaluation.drafts.size());
    for (const FindingDraft& draft : evaluation.drafts) {
      hasher.UpdateLengthPrefixed(draft.object.str());
      hasher.UpdateLengthPrefixed(draft.path.ToText());
      hasher.UpdateLengthPrefixed(ToText(draft.klass));
      hasher.UpdateLengthPrefixed(ToText(draft.raw_class));
      hasher.UpdateU64(draft.qualifier.is_set() ? 1u : 0u);
      if (draft.qualifier.is_set()) {
        hasher.Update(draft.qualifier.bytes.data(), draft.qualifier.bytes.size());
      }
      hasher.UpdateByte(draft.has_intended ? 1u : 0u);
      if (draft.has_intended) {
        draft.intended.HashInto(hasher);
      }
      hasher.UpdateByte(draft.has_observed ? 1u : 0u);
      if (draft.has_observed) {
        draft.observed.HashInto(hasher);
      }
    }
  }
  return hasher.Final();
}

TargetEvaluation CompareTarget(const TargetComparisonInput& input, const ObservatoryPolicy& policy,
                               const RuntimeLimits& limits) {
  TargetEvaluation evaluation;
  evaluation.target = input.target;

  if (input.baseline.has_value()) {
    evaluation.has_baseline = true;
    evaluation.baseline_generation = input.baseline->generation;
    evaluation.baseline_epoch = input.baseline->epoch;
    evaluation.baseline_authority = input.baseline->authority;
  }

  if (input.snapshots.size() != input.freshness.size()) {
    // Defensive: the caller must supply one verdict per snapshot.
    evaluation.compliance_decidable = false;
    evaluation.compliant = false;
    evaluation.decision_reason = ReasonCode::ComparisonBaselineUnavailable;
    AppendTrace(evaluation, "evidence and verdict counts disagree; no comparison performed");
    return evaluation;
  }

  std::vector<EvidenceView> views;
  views.reserve(input.snapshots.size());
  for (std::size_t index = 0; index < input.snapshots.size(); ++index) {
    if (input.snapshots[index] == nullptr) {
      continue;
    }
    EvidenceView view;
    view.snapshot = input.snapshots[index];
    view.verdict = input.freshness[index];
    view.usable = view.verdict.may_support_compliance;
    view.complete = view.snapshot->declares_complete_coverage();
    view.absence_authority = view.snapshot->capabilities.asserts_absence;
    view.priority = PriorityOf(policy, view.snapshot->source);
    view.content_digest = view.snapshot->ComputeContentDigest();
    views.push_back(std::move(view));
  }
  // A source states one current claim: its newest published observation. Older
  // retained snapshots are history and must never be read as a second,
  // disagreeing source.
  std::sort(views.begin(), views.end(), [](const EvidenceView& lhs, const EvidenceView& rhs) {
    if (!(lhs.snapshot->source == rhs.snapshot->source)) {
      return lhs.snapshot->source < rhs.snapshot->source;
    }
    if (lhs.snapshot->epoch != rhs.snapshot->epoch) {
      return rhs.snapshot->epoch < lhs.snapshot->epoch;
    }
    if (lhs.snapshot->incarnation != rhs.snapshot->incarnation) {
      return rhs.snapshot->incarnation < lhs.snapshot->incarnation;
    }
    return rhs.snapshot->sequence < lhs.snapshot->sequence;
  });
  {
    std::vector<EvidenceView> newest;
    newest.reserve(views.size());
    for (const EvidenceView& view : views) {
      if (!newest.empty() && newest.back().snapshot->source == view.snapshot->source) {
        continue;
      }
      newest.push_back(view);
    }
    if (newest.size() != views.size()) {
      AppendTrace(evaluation, "older snapshots from the same source were superseded by newer ones");
    }
    views = std::move(newest);
  }
  std::sort(views.begin(), views.end(), ViewLess);

  evaluation.sources_considered = views.size();
  for (const EvidenceView& view : views) {
    if (view.usable) {
      ++evaluation.fresh_sources;
    }
  }
  evaluation.best_freshness =
      views.empty() ? FreshnessState::Unknown : views.front().verdict.state;

  // ---- no committed intent ----
  if (!input.baseline.has_value()) {
    const bool required =
        std::find(policy.required_targets.begin(), policy.required_targets.end(), input.target) !=
        policy.required_targets.end();
    if (required) {
      const auto root = FieldPath::TryParse("", limits.max_path_segments, limits.max_path_key_bytes);
      IntentBaseline empty_baseline;
      const ObjectId scope = ObjectId::TryParse(kTargetScopeObjectId).value_or(ObjectId::Trusted("@target"));
      FindingDraft draft = MakeDraft(input.target, scope, root.value_or(FieldPath{}),
                                     DriftClass::IntentMissing, empty_baseline, policy);
      draft.reason = ReasonCode::ClassifiedNoIntent;
      draft.compliance_relevant = true;
      draft.rationale.push_back("policy requires this target to be managed");
      draft.rationale.push_back("no intent generation is committed for this target");
      if (!views.empty()) {
        AttachEvidence(draft, views.front(), limits);
        draft.compliance_relevant = views.front().usable;
      }
      evaluation.drafts.push_back(std::move(draft));
      AppendTrace(evaluation, "target is required by policy and has no committed intent");
    } else {
      AppendTrace(evaluation, "no intent is committed and policy does not require one");
    }
    evaluation.compliance_decidable = false;
    evaluation.compliant = false;
    evaluation.decision_reason = ReasonCode::ClassifiedNoIntent;
    return evaluation;
  }

  const IntentBaseline& baseline = *input.baseline;

  // ---- no usable evidence ----
  bool any_usable = false;
  for (const EvidenceView& view : views) {
    if (view.usable) {
      any_usable = true;
      break;
    }
  }
  if (!any_usable) {
    ReasonCode reason = views.empty() ? ReasonCode::NoFreshEvidence : ReasonCode::ObservationExpired;
    if (!views.empty()) {
      reason = views.front().verdict.reason;
    }
    FindingDraft draft = MakeDraft(input.target,
                                   ObjectId::TryParse(kTargetScopeObjectId).value_or(ObjectId::Trusted("@target")),
                                   FieldPath{}, DriftClass::StaleObservation, baseline, policy);
    draft.reason = reason;
    draft.compliance_relevant = true;
    draft.rationale.push_back("no fresh evidence is available for this target");
    draft.rationale.push_back(std::string("best available evidence state: ") +
                              ToText(evaluation.best_freshness));
    for (const EvidenceView& view : views) {
      AttachEvidence(draft, view, limits);
    }
    evaluation.drafts.push_back(std::move(draft));
    evaluation.compliance_decidable = false;
    evaluation.compliant = false;
    evaluation.decision_reason = reason;
    AppendTrace(evaluation, "freshness policy refused every available observation");
    return evaluation;
  }

  const EvidenceView& primary = views.front();
  AppendTrace(evaluation, std::string("primary source: ") + primary.snapshot->source.str());
  AppendTrace(evaluation, std::string("baseline generation: ") +
                              std::to_string(baseline.generation.value()));

  // ---- cross-source conflicts ----
  std::size_t conflict_sources = 0;
  for (const EvidenceView& view : views) {
    if (!view.usable) {
      continue;
    }
    if (++conflict_sources > kMaxConflictSources) {
      AppendTrace(evaluation, "cross-source scan bounded; further sources not compared");
      break;
    }
  }
  for (std::size_t first = 0; first < views.size() && first < kMaxConflictSources; ++first) {
    if (!views[first].usable) {
      continue;
    }
    for (std::size_t second = first + 1; second < views.size() && second < kMaxConflictSources;
         ++second) {
      if (!views[second].usable) {
        continue;
      }
      const EvidenceView& lhs = views[first];
      const EvidenceView& rhs = views[second];
      const Digest qualifier = ConflictQualifier(lhs.snapshot->source, rhs.snapshot->source);
      for (const auto& object_entry : lhs.snapshot->objects) {
        const ObservedObject* other = rhs.snapshot->FindObject(object_entry.first);
        if (other == nullptr) {
          continue;
        }
        if (object_entry.second.presence != other->presence) {
          if (object_entry.second.presence == ObjectPresence::Unknown ||
              other->presence == ObjectPresence::Unknown) {
            continue;
          }
          FindingDraft draft = MakeDraft(input.target, object_entry.first, FieldPath{},
                                         DriftClass::SourceConflict, baseline, policy);
          draft.reason = ReasonCode::ObservationSourcesDisagree;
          draft.qualifier = qualifier;
          draft.has_observed = true;
          draft.observed = Value::MakeString(ToText(object_entry.second.presence));
          draft.has_intended = true;
          draft.intended = Value::MakeString(ToText(other->presence));
          draft.rationale.push_back(std::string("sources ") + lhs.snapshot->source.str() + " and " +
                                    rhs.snapshot->source.str() + " disagree about object presence");
          AttachEvidence(draft, lhs, limits);
          AttachEvidence(draft, rhs, limits);
          evaluation.drafts.push_back(std::move(draft));
          continue;
        }
        for (const auto& field_entry : object_entry.second.fields) {
          const auto other_field = other->fields.find(field_entry.first);
          if (other_field == other->fields.end()) {
            continue;
          }
          const ValueRelation relation =
              RelateValues(field_entry.second, other_field->second, policy.numeric_equivalence);
          if (relation != ValueRelation::Different) {
            continue;
          }
          FindingDraft draft = MakeDraft(input.target, object_entry.first, field_entry.first,
                                         DriftClass::SourceConflict, baseline, policy);
          draft.reason = ReasonCode::ObservationSourcesDisagree;
          draft.qualifier = qualifier;
          draft.has_observed = true;
          draft.observed = field_entry.second;
          draft.has_intended = true;
          draft.intended = other_field->second;
          draft.rationale.push_back(std::string("sources ") + lhs.snapshot->source.str() + " and " +
                                    rhs.snapshot->source.str() + " disagree about this field");
          AttachEvidence(draft, lhs, limits);
          AttachEvidence(draft, rhs, limits);
          evaluation.drafts.push_back(std::move(draft));
        }
      }
    }
  }

  // ---- object and field comparison against the primary source ----
  for (const auto& object_entry : baseline.objects) {
    const ObjectId& object_id = object_entry.first;
    const IntentObject& intended_object = object_entry.second;
    const ObservedObject* observed = primary.snapshot->FindObject(object_id);

    ObjectPresence presence = ObjectPresence::Unknown;
    if (observed != nullptr) {
      presence = observed->presence;
    } else if (primary.snapshot->declares_unobserved(object_id)) {
      presence = ObjectPresence::Unknown;
    } else if (ObjectFullyVisible(primary, object_id)) {
      presence = ObjectPresence::Absent;
    } else {
      presence = ObjectPresence::Unknown;
    }

    if (intended_object.existence == ObjectExistence::Required) {
      if (presence == ObjectPresence::Absent) {
        if (policy.require_absence_authority && !primary.absence_authority) {
          FindingDraft draft = MakeDraft(input.target, object_id, FieldPath{}, DriftClass::Unknown,
                                         baseline, policy);
          draft.reason = ReasonCode::ObservationSourceCannotAssertAbsence;
          draft.rationale.push_back("the primary source cannot assert absence");
          AttachEvidence(draft, primary, limits);
          evaluation.drafts.push_back(std::move(draft));
          continue;
        }
        FindingDraft draft = MakeDraft(input.target, object_id, FieldPath{}, DriftClass::Missing,
                                       baseline, policy);
        draft.reason = ReasonCode::ClassifiedObjectMissing;
        draft.has_intended = true;
        draft.intended = Value::MakeString("required");
        draft.has_observed = true;
        draft.observed = Value::MakeString("absent");
        draft.rationale.push_back("intent requires this object to exist");
        draft.rationale.push_back("fresh evidence reports it absent");
        AttachEvidence(draft, primary, limits);
        evaluation.drafts.push_back(std::move(draft));
        continue;
      }
      if (presence == ObjectPresence::Unknown) {
        FindingDraft draft = MakeDraft(input.target, object_id, FieldPath{}, DriftClass::Unknown,
                                       baseline, policy);
        draft.reason = primary.snapshot->declares_unobserved(object_id)
                           ? ReasonCode::ObservationCoveragePartial
                           : ReasonCode::ObservationCoverageUnknown;
        draft.rationale.push_back("the primary source did not observe this object and cannot assert its absence");
        AttachEvidence(draft, primary, limits);
        evaluation.drafts.push_back(std::move(draft));
        continue;
      }
    } else if (presence == ObjectPresence::Present) {
      FindingDraft draft = MakeDraft(input.target, object_id, FieldPath{}, DriftClass::Unexpected,
                                     baseline, policy);
      draft.reason = ReasonCode::ClassifiedObjectUnexpected;
      draft.has_intended = true;
      draft.intended = Value::MakeString("forbidden");
      draft.has_observed = true;
      draft.observed = Value::MakeString("present");
      draft.rationale.push_back("intent forbids this object");
      draft.rationale.push_back("fresh evidence reports it present");
      AttachEvidence(draft, primary, limits);
      evaluation.drafts.push_back(std::move(draft));
      continue;
    }

    if (presence != ObjectPresence::Present || observed == nullptr) {
      continue;
    }

    for (const auto& field_entry : intended_object.fields) {
      const FieldPath& path = field_entry.first;
      const IntentField& intended_field = field_entry.second;
      if (IsReservedPath(path)) {
        continue;
      }
      const FieldComparability comparability =
          policy.ClassifyField(input.target, object_id, path, intended_field.comparability);
      if (comparability == FieldComparability::Unmanaged ||
          comparability == FieldComparability::ObserveOnly) {
        continue;
      }
      if (comparability == FieldComparability::Unobservable) {
        FindingDraft draft = MakeDraft(input.target, object_id, path, DriftClass::Unknown, baseline,
                                       policy);
        draft.reason = ReasonCode::ClassifiedNotObservable;
        draft.rationale.push_back("intent declares this field unobservable");
        AttachEvidence(draft, primary, limits);
        evaluation.drafts.push_back(std::move(draft));
        continue;
      }
      if (comparability == FieldComparability::Unsupported) {
        FindingDraft draft = MakeDraft(input.target, object_id, path, DriftClass::Unsupported,
                                       baseline, policy);
        draft.reason = ReasonCode::ClassifiedUnsupportedField;
        draft.rationale.push_back("intent declares this field outside the supported class");
        AttachEvidence(draft, primary, limits);
        evaluation.drafts.push_back(std::move(draft));
        continue;
      }

      const auto observed_field = observed->fields.find(path);
      if (observed_field == observed->fields.end()) {
        if (FieldVisible(primary, object_id, path)) {
          FindingDraft draft = MakeDraft(input.target, object_id, path, DriftClass::FieldMissing,
                                         baseline, policy);
          draft.reason = ReasonCode::ClassifiedFieldMissing;
          draft.has_intended = true;
          draft.intended = intended_field.intended;
          draft.rationale.push_back("a complete fresh observation does not report this managed field");
          AttachEvidence(draft, primary, limits);
          evaluation.drafts.push_back(std::move(draft));
        } else {
          FindingDraft draft = MakeDraft(input.target, object_id, path, DriftClass::Unknown,
                                         baseline, policy);
          draft.reason = ReasonCode::ObservationCoveragePartial;
          draft.rationale.push_back("the primary source cannot prove the absence of this field");
          AttachEvidence(draft, primary, limits);
          evaluation.drafts.push_back(std::move(draft));
        }
        continue;
      }

      const ValueRelation relation = RelateValues(intended_field.intended, observed_field->second,
                                                  policy.numeric_equivalence);
      if (relation == ValueRelation::Equal) {
        continue;
      }
      if (relation == ValueRelation::Incomparable) {
        FindingDraft draft = MakeDraft(input.target, object_id, path, DriftClass::Unsupported,
                                       baseline, policy);
        draft.reason = ReasonCode::ClassifiedFieldNotComparable;
        draft.has_intended = true;
        draft.intended = intended_field.intended;
        draft.has_observed = true;
        draft.observed = observed_field->second;
        draft.rationale.push_back("intended and observed values are not in the same comparison class");
        AttachEvidence(draft, primary, limits);
        evaluation.drafts.push_back(std::move(draft));
        continue;
      }
      FindingDraft draft = MakeDraft(input.target, object_id, path, DriftClass::ValueMismatch,
                                     baseline, policy);
      draft.reason = ReasonCode::ClassifiedValueMismatch;
      draft.has_intended = true;
      draft.intended = intended_field.intended;
      draft.has_observed = true;
      draft.observed = observed_field->second;
      draft.rationale.push_back("intended and observed values differ");
      AttachEvidence(draft, primary, limits);
      evaluation.drafts.push_back(std::move(draft));
    }

    for (const auto& field_entry : observed->fields) {
      if (IsReservedPath(field_entry.first)) {
        continue;
      }
      if (intended_object.fields.find(field_entry.first) != intended_object.fields.end()) {
        continue;
      }
      FindingDraft draft = MakeDraft(input.target, object_id, field_entry.first,
                                     DriftClass::FieldUnexpected, baseline, policy);
      draft.reason = ReasonCode::ClassifiedFieldUnexpected;
      draft.has_observed = true;
      draft.observed = field_entry.second;
      draft.rationale.push_back("the observation reports a field the intent does not declare");
      AttachEvidence(draft, primary, limits);
      evaluation.drafts.push_back(std::move(draft));
    }
  }

  for (const auto& object_entry : primary.snapshot->objects) {
    if (IsReservedObjectId(object_entry.first)) {
      continue;  // reserved scope object reported by a source
    }
    if (baseline.objects.find(object_entry.first) != baseline.objects.end()) {
      continue;
    }
    if (object_entry.second.presence != ObjectPresence::Present) {
      continue;
    }
    FindingDraft draft = MakeDraft(input.target, object_entry.first, FieldPath{},
                                   DriftClass::Unexpected, baseline, policy);
    draft.reason = ReasonCode::ClassifiedObjectUnexpected;
    draft.has_observed = true;
    draft.observed = Value::MakeString("present");
    draft.rationale.push_back("fresh evidence reports an object the committed intent does not declare");
    AttachEvidence(draft, primary, limits);
    evaluation.drafts.push_back(std::move(draft));
  }

  // ---- generation divergence regrouping ----
  const GenerationScan scan = ScanAppliedGenerations(primary, baseline.objects,
                                                     baseline.generation);
  if (scan.any_applied) {
    bool has_deviation = false;
    for (const FindingDraft& draft : evaluation.drafts) {
      if (draft.klass == DriftClass::ValueMismatch || draft.klass == DriftClass::FieldMissing ||
          draft.klass == DriftClass::Missing) {
        has_deviation = true;
        break;
      }
    }
    if (has_deviation) {
      const bool partial = scan.any_matches_baseline;
      const bool regressed = !partial && !scan.applied.empty() &&
                             scan.applied.back() != baseline.generation.value();
      if (partial || regressed) {
        const Digest qualifier =
            GenerationQualifier(partial ? "partial" : "not-applied", baseline.generation,
                                scan.applied);
        for (FindingDraft& draft : evaluation.drafts) {
          if (draft.klass != DriftClass::ValueMismatch && draft.klass != DriftClass::FieldMissing &&
              draft.klass != DriftClass::Missing) {
            continue;
          }
          draft.klass = partial ? DriftClass::PartialApplication : DriftClass::GenerationMismatch;
          draft.reason = partial ? ReasonCode::ClassifiedPartialApplication
                                 : ReasonCode::ClassifiedGenerationMismatch;
          draft.qualifier = qualifier;
          draft.severity = policy.SeverityFor(draft.target, draft.object, draft.path, draft.klass);
          draft.rationale.push_back(
              partial ? "some objects report the intended generation and others do not"
                      : "the target reports a generation older than the committed baseline");
        }
        AppendTrace(evaluation, partial ? "divergence regrouped as a partial application"
                                        : "divergence regrouped as an unapplied generation");
      }
    }
  }

  // ---- compliance decision ----
  bool indeterminate = false;
  bool actionable = false;
  ReasonCode first_actionable = ReasonCode::None;
  for (const FindingDraft& draft : evaluation.drafts) {
    if (IsIndeterminateDrift(draft.klass) || draft.klass == DriftClass::Unsupported) {
      indeterminate = true;
      if (first_actionable == ReasonCode::None) {
        first_actionable = draft.reason;
      }
      continue;
    }
    if (IsActionableDrift(draft.klass) || draft.klass == DriftClass::IntentMissing) {
      actionable = true;
      if (first_actionable == ReasonCode::None) {
        first_actionable = draft.reason;
      }
    }
  }
  const bool coverage_ok = !policy.require_complete_coverage_for_compliance || primary.complete;
  evaluation.compliance_decidable = !indeterminate && coverage_ok;
  evaluation.compliant = evaluation.compliance_decidable && !actionable;
  if (evaluation.compliant) {
    evaluation.decision_reason = ReasonCode::ClassifiedConverged;
  } else if (first_actionable != ReasonCode::None) {
    evaluation.decision_reason = first_actionable;
  } else {
    evaluation.decision_reason = ReasonCode::ObservationCoveragePartial;
  }
  if (!coverage_ok) {
    AppendTrace(evaluation, "evidence does not cover the whole target; compliance is not decidable");
  }
  AppendTrace(evaluation, evaluation.compliant ? "target complies with the committed intent"
                                               : "target does not comply with the committed intent");
  return evaluation;
}

std::string ExplainDraft(const FindingDraft& draft, const ObservatoryPolicy& policy) {
  std::string text;
  text.reserve(256);
  text.append(ToText(draft.klass));
  text.append(" at ");
  text.append(draft.target.str());
  text.append(" ");
  text.append(draft.object.str());
  text.append(" ");
  text.append(draft.path.Describe());
  text.append("; severity ");
  text.append(ToText(draft.severity));
  text.append(" under policy ");
  text.append(policy.id.str());
  text.append("; reason ");
  text.append(ToText(draft.reason));
  if (draft.has_intended) {
    text.append("; intended ");
    text.append(draft.intended.ToDisplayText(64));
  }
  if (draft.has_observed) {
    text.append("; observed ");
    text.append(draft.observed.ToDisplayText(64));
  }
  for (const std::string& step : draft.rationale) {
    text.append("; ");
    text.append(step);
  }
  if (text.size() > 512) {
    text.resize(512);
    text.append("...");
  }
  return text;
}

}  // namespace network_drift_observatory
}  // namespace summon
