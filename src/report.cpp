// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/report.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "ledger_encode.hpp"
#include "summon/network_drift_observatory/engine.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/version.hpp"

namespace summon {
namespace network_drift_observatory {
namespace {

struct NamePair {
  std::uint8_t value;
  const char* name;
};

constexpr NamePair kActionNames[] = {
    {0, "none"},      {1, "apply-intent"},        {2, "remove-unexpected"},
    {3, "collect-observation"}, {4, "resolve-source-conflict"}, {5, "escalate-to-owner"},
};

std::string RequestIdentity(FindingId id, ReconciliationAction action) {
  std::string text = "request/";
  text.append(id.ToShortHex());
  text.push_back('/');
  text.append(ToText(action));
  return text;
}

Value EncodeFindingSummary(const Finding& finding) {
  Value::Map map;
  map.emplace("id", Value::MakeString(finding.id.ToHex()));
  map.emplace("target", Value::MakeString(finding.identity.target.str()));
  map.emplace("object", Value::MakeString(finding.identity.object.str()));
  map.emplace("path", Value::MakeString(finding.identity.path.ToText()));
  map.emplace("drift_class", Value::MakeString(ToText(finding.klass)));
  map.emplace("raw_class", Value::MakeString(ToText(finding.raw_class)));
  map.emplace("severity", Value::MakeString(ToText(finding.severity)));
  map.emplace("state", Value::MakeString(ToText(finding.state)));
  map.emplace("reason", Value::MakeString(ToText(finding.reason)));
  map.emplace("baseline_generation", Value::MakeUint(finding.baseline_generation.value()));
  map.emplace("baseline_epoch", Value::MakeUint(finding.baseline_epoch.value()));
  map.emplace("baseline_authority", Value::MakeString(ToText(finding.baseline_authority)));
  map.emplace("evidence_freshness", Value::MakeString(ToText(finding.evidence_freshness)));
  map.emplace("suppressed", Value::MakeBool(finding.suppression.has_value()));
  map.emplace("compliance_relevant", Value::MakeBool(finding.compliance_relevant));
  map.emplace("observation_count", Value::MakeUint(finding.observation_count));
  map.emplace("reopen_count", Value::MakeUint(finding.reopen_count));
  map.emplace("first_seen", Value::MakeString(FormatTime(finding.first_seen)));
  map.emplace("last_seen", Value::MakeString(FormatTime(finding.last_seen)));
  map.emplace("summary", Value::MakeString(finding.summary));
  return Value::MakeMap(std::move(map));
}

Value EncodeReconciliationRequest(const Finding& finding) {
  const ReconciliationAction action = ActionFor(finding.klass);
  Value::Map map;
  map.emplace("id", Value::MakeString(RequestIdentity(finding.id, action)));
  map.emplace("finding", Value::MakeString(finding.id.ToHex()));
  map.emplace("action", Value::MakeString(ToText(action)));
  map.emplace("target", Value::MakeString(finding.identity.target.str()));
  map.emplace("object", Value::MakeString(finding.identity.object.str()));
  map.emplace("path", Value::MakeString(finding.identity.path.ToText()));
  map.emplace("drift_class", Value::MakeString(ToText(finding.klass)));
  map.emplace("severity", Value::MakeString(ToText(finding.severity)));
  map.emplace("baseline_generation", Value::MakeUint(finding.baseline_generation.value()));
  map.emplace("baseline_epoch", Value::MakeUint(finding.baseline_epoch.value()));
  map.emplace("policy", Value::MakeString(finding.policy.str()));
  map.emplace("policy_digest", Value::MakeString(finding.policy_digest.ToHex()));
  map.emplace("suppressed", Value::MakeBool(finding.suppression.has_value()));
  map.emplace("acknowledged", Value::MakeBool(!finding.acknowledged_by.empty()));
  map.emplace("observed_freshness", Value::MakeString(ToText(finding.evidence_freshness)));
  map.emplace("reason", Value::MakeString(ToText(finding.reason)));
  if (finding.has_intended) {
    map.emplace("intended", finding.intended);
  }
  if (finding.has_observed) {
    map.emplace("observed", finding.observed);
  }
  {
    Value::List evidence;
    for (const EvidenceRef& reference : finding.evidence) {
      evidence.push_back(detail::EncodeEvidenceRef(reference));
    }
    map.emplace("evidence", Value::MakeList(std::move(evidence)));
  }
  return Value::MakeMap(std::move(map));
}

Value::Map CountByDriftClass(const std::vector<Finding>& findings) {
  Value::Map counts;
  for (const Finding& finding : findings) {
    const std::string key = ToText(finding.klass);
    const auto found = counts.find(key);
    if (found == counts.end()) {
      counts.emplace(key, Value::MakeUint(1));
      continue;
    }
    const std::uint64_t* current = found->second.as_uint();
    counts[key] = Value::MakeUint(current == nullptr ? 1 : *current + 1);
  }
  return counts;
}

Value::Map CountBySeverity(const std::vector<Finding>& findings) {
  Value::Map counts;
  for (const Finding& finding : findings) {
    const std::string key = ToText(finding.severity);
    const auto found = counts.find(key);
    if (found == counts.end()) {
      counts.emplace(key, Value::MakeUint(1));
      continue;
    }
    const std::uint64_t* current = found->second.as_uint();
    counts[key] = Value::MakeUint(current == nullptr ? 1 : *current + 1);
  }
  return counts;
}

Value::Map CountByState(const std::vector<Finding>& findings) {
  Value::Map counts;
  for (const Finding& finding : findings) {
    const std::string key = ToText(finding.state);
    const auto found = counts.find(key);
    if (found == counts.end()) {
      counts.emplace(key, Value::MakeUint(1));
      continue;
    }
    const std::uint64_t* current = found->second.as_uint();
    counts[key] = Value::MakeUint(current == nullptr ? 1 : *current + 1);
  }
  return counts;
}

Value EncodeCounters(const ObservatoryCounters& counters) {
  Value::Map map;
  map.emplace("intents_accepted", Value::MakeUint(counters.intents_accepted));
  map.emplace("intents_rejected", Value::MakeUint(counters.intents_rejected));
  map.emplace("intents_duplicate_identical", Value::MakeUint(counters.intents_duplicate_identical));
  map.emplace("observations_accepted", Value::MakeUint(counters.observations_accepted));
  map.emplace("observations_rejected", Value::MakeUint(counters.observations_rejected));
  map.emplace("observations_duplicate_identical",
              Value::MakeUint(counters.observations_duplicate_identical));
  map.emplace("observations_superseded", Value::MakeUint(counters.observations_superseded));
  map.emplace("evaluations", Value::MakeUint(counters.evaluations));
  map.emplace("evaluations_cancelled", Value::MakeUint(counters.evaluations_cancelled));
  map.emplace("evaluations_fenced", Value::MakeUint(counters.evaluations_fenced));
  map.emplace("findings_created", Value::MakeUint(counters.findings_created));
  map.emplace("findings_resolved", Value::MakeUint(counters.findings_resolved));
  map.emplace("findings_reopened", Value::MakeUint(counters.findings_reopened));
  map.emplace("findings_suppressed", Value::MakeUint(counters.findings_suppressed));
  map.emplace("acknowledgements", Value::MakeUint(counters.acknowledgements));
  map.emplace("recoveries", Value::MakeUint(counters.recoveries));
  map.emplace("persistence_writes", Value::MakeUint(counters.persistence_writes));
  map.emplace("policy_changes", Value::MakeUint(counters.policy_changes));
  return Value::MakeMap(std::move(map));
}

}  // namespace

const char* ToText(ReconciliationAction value) noexcept {
  const std::uint8_t raw = static_cast<std::uint8_t>(value);
  for (const NamePair& entry : kActionNames) {
    if (entry.value == raw) {
      return entry.name;
    }
  }
  return "none";
}

bool TryParseReconciliationAction(const char* text, ReconciliationAction& out) noexcept {
  if (text == nullptr) {
    return false;
  }
  const std::string_view wanted(text);
  for (const NamePair& entry : kActionNames) {
    if (wanted == entry.name) {
      out = static_cast<ReconciliationAction>(entry.value);
      return true;
    }
  }
  return false;
}

ReconciliationAction ActionFor(DriftClass klass) noexcept {
  switch (klass) {
    case DriftClass::Missing:
    case DriftClass::ValueMismatch:
    case DriftClass::FieldMissing:
    case DriftClass::GenerationMismatch:
    case DriftClass::PartialApplication:
      return ReconciliationAction::ApplyIntent;
    case DriftClass::Unexpected:
    case DriftClass::FieldUnexpected:
      return ReconciliationAction::RemoveUnexpected;
    case DriftClass::StaleObservation:
    case DriftClass::Unknown:
      return ReconciliationAction::CollectObservation;
    case DriftClass::SourceConflict:
      return ReconciliationAction::ResolveSourceConflict;
    case DriftClass::Unsupported:
    case DriftClass::IntentMissing:
    case DriftClass::EvidenceInvalid:
      return ReconciliationAction::EscalateToOwner;
    default:
      return ReconciliationAction::None;
  }
}

Status BuildReportValue(const Observatory& observatory, const ReportSpec& spec, Value& out) {
  const Result<ReportInputs> collected = observatory.CollectReportInputs(spec);
  if (!collected.ok()) {
    return collected.status();
  }
  const ReportInputs& inputs = collected.value();

  Value::Map root;
  root.emplace("schema", Value::MakeString("ndo/report/1"));
  root.emplace("report_format_version", Value::MakeUint(kReportFormatVersion));
  root.emplace("report_id", Value::MakeString(spec.id.empty() ? std::string("report/unidentified")
                                                              : spec.id.str()));
  root.emplace("generated_at", Value::MakeString(FormatTime(inputs.generated_at)));
  root.emplace("note", Value::MakeString(spec.note));
  {
    Value::Map product;
    product.emplace("name", Value::MakeString(kProductName));
    product.emplace("vendor", Value::MakeString(kProductVendor));
    product.emplace("version", Value::MakeString(kVersionString));
    product.emplace("evidence", Value::MakeString(ToText(observatory.policy().evidence)));
    root.emplace("product", Value::MakeMap(std::move(product)));
  }
  {
    Value::Map state;
    state.emplace("policy", Value::MakeString(inputs.policy.str()));
    state.emplace("policy_digest", Value::MakeString(inputs.policy_digest.ToHex()));
    state.emplace("epoch", Value::MakeUint(inputs.epoch.value()));
    state.emplace("incarnation", Value::MakeUint(inputs.incarnation.value()));
    state.emplace("ledger_revision", Value::MakeUint(inputs.revision.value()));
    state.emplace("state_digest", Value::MakeString(inputs.state_digest.ToHex()));
    state.emplace("started", Value::MakeBool(inputs.started));
    root.emplace("observatory", Value::MakeMap(std::move(state)));
  }
  root.emplace("counters", EncodeCounters(inputs.counters));
  {
    Value::Map stats;
    stats.emplace("targets", Value::MakeUint(inputs.stats.targets));
    stats.emplace("baselines", Value::MakeUint(inputs.stats.baselines));
    stats.emplace("observations", Value::MakeUint(inputs.stats.observations));
    stats.emplace("sources", Value::MakeUint(inputs.stats.sources));
    stats.emplace("findings", Value::MakeUint(inputs.stats.findings));
    stats.emplace("live_findings", Value::MakeUint(inputs.stats.live_findings));
    stats.emplace("resolved_findings", Value::MakeUint(inputs.stats.resolved_findings));
    stats.emplace("superseded_findings", Value::MakeUint(inputs.stats.superseded_findings));
    stats.emplace("suppressed_findings", Value::MakeUint(inputs.stats.suppressed_findings));
    stats.emplace("acknowledged_findings", Value::MakeUint(inputs.stats.acknowledged_findings));
    stats.emplace("groups", Value::MakeUint(inputs.stats.groups));
    stats.emplace("timeline_entries", Value::MakeUint(inputs.stats.timeline_entries));
    stats.emplace("reported_findings", Value::MakeUint(inputs.findings.size()));
    stats.emplace("matching_findings", Value::MakeUint(inputs.matching_findings));
    stats.emplace("truncated", Value::MakeBool(inputs.truncated));
    root.emplace("stats", Value::MakeMap(std::move(stats)));
  }
  root.emplace("findings_by_class", Value::MakeMap(CountByDriftClass(inputs.findings)));
  root.emplace("findings_by_severity", Value::MakeMap(CountBySeverity(inputs.findings)));
  root.emplace("findings_by_state", Value::MakeMap(CountByState(inputs.findings)));

  {
    Value::List findings;
    for (const Finding& finding : inputs.findings) {
      findings.push_back(EncodeFindingSummary(finding));
    }
    root.emplace("findings", Value::MakeList(std::move(findings)));
  }
  if (spec.include_evidence) {
    Value::List details;
    for (const Finding& finding : inputs.findings) {
      details.push_back(detail::EncodeFinding(finding));
    }
    root.emplace("finding_records", Value::MakeList(std::move(details)));
  }
  if (spec.include_groups) {
    Value::List groups;
    for (const RootCauseGroup& group : inputs.groups) {
      groups.push_back(detail::EncodeGroup(group));
    }
    root.emplace("root_cause_groups", Value::MakeList(std::move(groups)));
  }
  if (spec.include_timeline) {
    Value::List timeline;
    for (const TimelineEntry& entry : inputs.timeline) {
      timeline.push_back(detail::EncodeTimelineEntry(entry));
    }
    root.emplace("timeline", Value::MakeList(std::move(timeline)));
  }
  if (spec.include_reconciliation_requests) {
    Value::List requests;
    for (const Finding& finding : inputs.findings) {
      if (!IsLiveState(finding.state)) {
        continue;
      }
      if (ActionFor(finding.klass) == ReconciliationAction::None) {
        continue;
      }
      requests.push_back(EncodeReconciliationRequest(finding));
    }
    root.emplace("reconciliation_requests", Value::MakeList(std::move(requests)));
  }
  {
    // Explicit, machine-readable statement of what this runtime does and does
    // not claim. A consumer must not read a finding as an executed action.
    Value::List boundaries;
    boundaries.push_back(Value::MakeString(
        "observational only: this runtime never mutates a device and never applies a request"));
    boundaries.push_back(Value::MakeString(
        "reconciliation requests are typed suggestions for another runtime"));
    boundaries.push_back(Value::MakeString(
        "evidence class is declared per observation; synthetic fixtures are not hardware"));
    boundaries.push_back(Value::MakeString(
        "a suppressed finding remains true; suppression affects reporting only"));
    boundaries.push_back(Value::MakeString(
        "absence of fresh evidence is reported as unknown, never as compliance"));
    root.emplace("system_boundary", Value::MakeList(std::move(boundaries)));
  }
  out = Value::MakeMap(std::move(root));
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status BuildReportJson(const Observatory& observatory, const ReportSpec& spec, std::string& out) {
  Value value;
  Status status = BuildReportValue(observatory, spec, value);
  if (!status.ok()) {
    return status;
  }
  out = WritePrettyJson(value, 2);
  return Status(StatusCode::Ok, ReasonCode::None);
}

}  // namespace network_drift_observatory
}  // namespace summon
