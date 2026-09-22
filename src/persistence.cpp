// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/persistence.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "json_help.hpp"
#include "summon/network_drift_observatory/checked.hpp"
#include "summon/network_drift_observatory/hash.hpp"
#include "summon/network_drift_observatory/interchange.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/version.hpp"

namespace summon {
namespace network_drift_observatory {
#include "ledger_encode.hpp"

namespace detail {

using ::summon::network_drift_observatory::detail::CheckMembers;

void AppendU16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void AppendU32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  for (int index = 0; index < 4; ++index) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu));
  }
}

void AppendU64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (int index = 0; index < 8; ++index) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu));
  }
}

std::uint16_t ReadU16(const std::uint8_t* data) {
  return static_cast<std::uint16_t>(data[0]) | static_cast<std::uint16_t>(data[1] << 8);
}

std::uint64_t ReadU64(const std::uint8_t* data) {
  std::uint64_t value = 0;
  for (int index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(data[index]) << (8 * index);
  }
  return value;
}

Value EncodeTimelineEntry(const TimelineEntry& entry) {
  Value::Map map;
  map.emplace("kind", Value::MakeString(ToText(entry.kind)));
  map.emplace("sequence", Value::MakeUint(entry.sequence));
  map.emplace("at", Value::MakeString(FormatTime(entry.at)));
  map.emplace("state", Value::MakeString(ToText(entry.state_after)));
  map.emplace("class", Value::MakeString(ToText(entry.klass)));
  map.emplace("severity", Value::MakeString(ToText(entry.severity)));
  map.emplace("reason", Value::MakeString(ToText(entry.reason)));
  map.emplace("baseline_generation", Value::MakeUint(entry.baseline_generation.value()));
  map.emplace("baseline_epoch", Value::MakeUint(entry.baseline_epoch.value()));
  map.emplace("evidence_digest", Value::MakeString(entry.evidence_digest.ToHex()));
  map.emplace("actor", Value::MakeString(entry.actor.str()));
  map.emplace("detail", Value::MakeString(entry.detail));
  map.emplace("target", Value::MakeString(entry.target.str()));
  map.emplace("object", Value::MakeString(entry.object.str()));
  map.emplace("finding", Value::MakeString(entry.finding.is_set() ? entry.finding.ToHex() : ""));
  return Value::MakeMap(std::move(map));
}

Status DecodeTimelineEntry(const Value& value, TimelineEntry& out) {
  const Value::Map* map = value.as_map();
  if (map == nullptr) {
    return Status::Rejected(ReasonCode::LedgerDecodeFailed, "timeline entry must be an object");
  }
  Status status = CheckMembers(*map,
                               {"kind", "sequence", "at", "state", "class", "severity", "reason",
                                "baseline_generation", "baseline_epoch", "evidence_digest", "actor",
                                "detail", "target", "object", "finding"},
                               "timeline entry");
  if (!status.ok()) {
    return status;
  }
  TimelineEntry entry;
  std::string text;
  status = RequireString(*map, "kind", "timeline entry", text);
  if (!status.ok()) {
    return status;
  }
  if (!TryParseTimelineEventKind(text.c_str(), entry.kind)) {
    return MemberError("timeline entry", "kind", "is not recognized");
  }
  std::uint64_t number = 0;
  status = RequireUint(*map, "sequence", "timeline entry", number);
  if (!status.ok()) {
    return status;
  }
  entry.sequence = number;
  status = RequireString(*map, "at", "timeline entry", text);
  if (!status.ok()) {
    return status;
  }
  if (!TryParseTime(text, entry.at)) {
    return MemberError("timeline entry", "at", "is not an RFC 3339 timestamp");
  }
  if (const std::optional<std::string> state = OptionalString(*map, "state"); state.has_value()) {
    if (!TryParseFindingState(state->c_str(), entry.state_after)) {
      return MemberError("timeline entry", "state", "is not recognized");
    }
  }
  if (const std::optional<std::string> klass = OptionalString(*map, "class"); klass.has_value()) {
    if (!TryParseDriftClass(klass->c_str(), entry.klass)) {
      return MemberError("timeline entry", "class", "is not recognized");
    }
  }
  if (const std::optional<std::string> severity = OptionalString(*map, "severity");
      severity.has_value()) {
    if (!TryParseSeverity(severity->c_str(), entry.severity)) {
      return MemberError("timeline entry", "severity", "is not recognized");
    }
  }
  if (const std::optional<std::string> reason = OptionalString(*map, "reason"); reason.has_value()) {
    if (!TryParseReasonCode(reason->c_str(), entry.reason)) {
      return MemberError("timeline entry", "reason", "is not recognized");
    }
  }
  if (const std::optional<std::uint64_t> generation = OptionalUint(*map, "baseline_generation");
      generation.has_value()) {
    entry.baseline_generation = IntentGeneration::FromValue(*generation);
  }
  if (const std::optional<std::uint64_t> epoch = OptionalUint(*map, "baseline_epoch");
      epoch.has_value()) {
    entry.baseline_epoch = FabricEpoch::FromValue(*epoch);
  }
  if (const std::optional<std::string> digest = OptionalString(*map, "evidence_digest");
      digest.has_value() && !digest->empty()) {
    const auto parsed = Digest::TryFromHex(*digest);
    if (!parsed.has_value()) {
      return MemberError("timeline entry", "evidence_digest", "is not a digest");
    }
    entry.evidence_digest = *parsed;
  }
  if (const std::optional<std::string> actor = OptionalString(*map, "actor");
      actor.has_value() && !actor->empty()) {
    const auto parsed = ActorId::TryParse(*actor);
    if (!parsed.has_value()) {
      return MemberError("timeline entry", "actor", "is not a valid identity");
    }
    entry.actor = *parsed;
  }
  if (const std::optional<std::string> detail = OptionalString(*map, "detail"); detail.has_value()) {
    entry.detail = *detail;
  }
  if (const std::optional<std::string> target = OptionalString(*map, "target");
      target.has_value() && !target->empty()) {
    const auto parsed = TargetId::TryParse(*target);
    if (!parsed.has_value()) {
      return MemberError("timeline entry", "target", "is not a valid identity");
    }
    entry.target = *parsed;
  }
  if (const std::optional<std::string> object = OptionalString(*map, "object");
      object.has_value() && !object->empty()) {
    const auto parsed = ObjectId::TryParse(*object);
    if (!parsed.has_value()) {
      return MemberError("timeline entry", "object", "is not a valid identity");
    }
    entry.object = *parsed;
  }
  if (const std::optional<std::string> finding = OptionalString(*map, "finding");
      finding.has_value() && !finding->empty()) {
    const auto parsed = FindingId::TryParse(*finding);
    if (!parsed.has_value()) {
      return MemberError("timeline entry", "finding", "is not a finding identity");
    }
    entry.finding = *parsed;
  }
  out = std::move(entry);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Value EncodeEvidenceRef(const EvidenceRef& reference) {
  Value::Map map;
  map.emplace("source", Value::MakeString(reference.source.str()));
  map.emplace("snapshot", Value::MakeString(reference.snapshot.str()));
  map.emplace("epoch", Value::MakeUint(reference.epoch.value()));
  map.emplace("incarnation", Value::MakeUint(reference.incarnation.value()));
  map.emplace("sequence", Value::MakeUint(reference.sequence.value()));
  map.emplace("collected_at", Value::MakeString(FormatTime(reference.collected_at)));
  map.emplace("received_at", Value::MakeString(FormatTime(reference.received_at)));
  map.emplace("freshness", Value::MakeString(ToText(reference.freshness)));
  map.emplace("coverage", Value::MakeString(ToText(reference.coverage)));
  map.emplace("evidence", Value::MakeString(ToText(reference.evidence)));
  map.emplace("content_digest", Value::MakeString(reference.content_digest.ToHex()));
  return Value::MakeMap(std::move(map));
}

Status DecodeEvidenceRef(const Value& value, EvidenceRef& out) {
  const Value::Map* map = value.as_map();
  if (map == nullptr) {
    return Status::Rejected(ReasonCode::LedgerDecodeFailed, "evidence reference must be an object");
  }
  Status status = CheckMembers(*map,
                               {"source", "snapshot", "epoch", "incarnation", "sequence",
                                "collected_at", "received_at", "freshness", "coverage", "evidence",
                                "content_digest"},
                               "evidence reference");
  if (!status.ok()) {
    return status;
  }
  EvidenceRef reference;
  std::string text;
  status = RequireString(*map, "source", "evidence reference", text);
  if (!status.ok()) {
    return status;
  }
  const auto source = SourceId::TryParse(text);
  if (!source.has_value()) {
    return MemberError("evidence reference", "source", "is not a valid identity");
  }
  reference.source = *source;
  status = RequireString(*map, "snapshot", "evidence reference", text);
  if (!status.ok()) {
    return status;
  }
  const auto snapshot = SnapshotId::TryParse(text);
  if (!snapshot.has_value()) {
    return MemberError("evidence reference", "snapshot", "is not a valid identity");
  }
  reference.snapshot = *snapshot;
  std::uint64_t number = 0;
  status = RequireUint(*map, "epoch", "evidence reference", number);
  if (!status.ok()) {
    return status;
  }
  reference.epoch = FabricEpoch::FromValue(number);
  status = RequireUint(*map, "incarnation", "evidence reference", number);
  if (!status.ok()) {
    return status;
  }
  reference.incarnation = Incarnation::FromValue(number);
  status = RequireUint(*map, "sequence", "evidence reference", number);
  if (!status.ok()) {
    return status;
  }
  reference.sequence = SourceSequence::FromValue(number);
  if (const std::optional<std::string> collected = OptionalString(*map, "collected_at");
      collected.has_value()) {
    if (!TryParseTime(*collected, reference.collected_at)) {
      return MemberError("evidence reference", "collected_at", "is not an RFC 3339 timestamp");
    }
  }
  if (const std::optional<std::string> received = OptionalString(*map, "received_at");
      received.has_value()) {
    if (!TryParseTime(*received, reference.received_at)) {
      return MemberError("evidence reference", "received_at", "is not an RFC 3339 timestamp");
    }
  }
  if (const std::optional<std::string> freshness = OptionalString(*map, "freshness");
      freshness.has_value()) {
    if (!TryParseFreshnessState(freshness->c_str(), reference.freshness)) {
      return MemberError("evidence reference", "freshness", "is not recognized");
    }
  }
  if (const std::optional<std::string> coverage = OptionalString(*map, "coverage");
      coverage.has_value()) {
    if (!TryParseObservationCoverage(coverage->c_str(), reference.coverage)) {
      return MemberError("evidence reference", "coverage", "is not recognized");
    }
  }
  if (const std::optional<std::string> evidence = OptionalString(*map, "evidence");
      evidence.has_value()) {
    if (!TryParseEvidenceClass(evidence->c_str(), reference.evidence)) {
      return MemberError("evidence reference", "evidence", "is not recognized");
    }
  }
  if (const std::optional<std::string> digest = OptionalString(*map, "content_digest");
      digest.has_value()) {
    const auto parsed = Digest::TryFromHex(*digest);
    if (!parsed.has_value()) {
      return MemberError("evidence reference", "content_digest", "is not a digest");
    }
    reference.content_digest = *parsed;
  }
  out = std::move(reference);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Value EncodeFinding(const Finding& finding) {
  Value::Map map;
  map.emplace("id", Value::MakeString(finding.id.ToHex()));
  map.emplace("target", Value::MakeString(finding.identity.target.str()));
  map.emplace("object", Value::MakeString(finding.identity.object.str()));
  map.emplace("path", Value::MakeString(finding.identity.path.ToText()));
  map.emplace("class", Value::MakeString(ToText(finding.klass)));
  map.emplace("raw_class", Value::MakeString(ToText(finding.raw_class)));
  map.emplace("severity", Value::MakeString(ToText(finding.severity)));
  map.emplace("state", Value::MakeString(ToText(finding.state)));
  map.emplace("reason", Value::MakeString(ToText(finding.reason)));
  map.emplace("baseline_generation", Value::MakeUint(finding.baseline_generation.value()));
  map.emplace("baseline_epoch", Value::MakeUint(finding.baseline_epoch.value()));
  map.emplace("baseline_authority", Value::MakeString(ToText(finding.baseline_authority)));
  map.emplace("policy", Value::MakeString(finding.policy.str()));
  map.emplace("policy_digest", Value::MakeString(finding.policy_digest.ToHex()));
  map.emplace("qualifier", Value::MakeString(finding.identity.qualifier.ToHex()));
  map.emplace("has_intended", Value::MakeBool(finding.has_intended));
  map.emplace("intended", finding.intended);
  map.emplace("has_observed", Value::MakeBool(finding.has_observed));
  map.emplace("observed", finding.observed);
  map.emplace("evidence_freshness", Value::MakeString(ToText(finding.evidence_freshness)));
  map.emplace("group", Value::MakeString(finding.group.is_set() ? finding.group.ToHex() : ""));
  map.emplace("group_cause", Value::MakeString(ToText(finding.group_cause)));
  map.emplace("observation_count", Value::MakeUint(finding.observation_count));
  map.emplace("reopen_count", Value::MakeUint(finding.reopen_count));
  map.emplace("resolution_confirmations", Value::MakeUint(finding.resolution_confirmations));
  map.emplace("first_seen", Value::MakeString(FormatTime(finding.first_seen)));
  map.emplace("last_seen", Value::MakeString(FormatTime(finding.last_seen)));
  map.emplace("last_evaluated", Value::MakeString(FormatTime(finding.last_evaluated)));
  map.emplace("resolved_at", Value::MakeString(FormatTime(finding.resolved_at)));
  map.emplace("suppression", Value::MakeString(finding.suppression.has_value()
                                                   ? finding.suppression->str()
                                                   : std::string()));
  map.emplace("suppression_origin", Value::MakeString(ToText(finding.suppression_origin)));
  map.emplace("suppressed_by", Value::MakeString(finding.suppressed_by.str()));
  map.emplace("suppression_reason", Value::MakeString(finding.suppression_reason));
  map.emplace("suppression_expires_at",
              Value::MakeString(finding.suppression_expires_at.has_value()
                                    ? FormatTime(*finding.suppression_expires_at)
                                    : std::string()));
  map.emplace("acknowledged_by", Value::MakeString(finding.acknowledged_by.str()));
  map.emplace("acknowledged_at", Value::MakeString(FormatTime(finding.acknowledged_at)));
  map.emplace("acknowledgement_reason", Value::MakeString(finding.acknowledgement_reason));
  map.emplace("compliance_relevant", Value::MakeBool(finding.compliance_relevant));
  map.emplace("summary", Value::MakeString(finding.summary));
  {
    Value::List evidence;
    for (const EvidenceRef& reference : finding.evidence) {
      evidence.push_back(EncodeEvidenceRef(reference));
    }
    map.emplace("evidence", Value::MakeList(std::move(evidence)));
  }
  {
    Value::List timeline;
    for (const TimelineEntry& entry : finding.timeline) {
      timeline.push_back(EncodeTimelineEntry(entry));
    }
    map.emplace("timeline", Value::MakeList(std::move(timeline)));
  }
  return Value::MakeMap(std::move(map));
}

Status DecodeFinding(const Value& value, const RuntimeLimits& limits, Finding& out) {
  const Value::Map* map = value.as_map();
  if (map == nullptr) {
    return Status::Rejected(ReasonCode::LedgerDecodeFailed, "finding must be an object");
  }
  Status status = CheckMembers(*map,
                               {"id", "target", "object", "path", "class", "raw_class", "severity",
                                "state", "reason", "baseline_generation", "baseline_epoch",
                                "baseline_authority", "policy", "policy_digest", "qualifier",
                                "has_intended", "intended", "has_observed", "observed",
                                "evidence_freshness", "group", "group_cause", "observation_count",
                                "reopen_count", "resolution_confirmations", "first_seen", "last_seen",
                                "last_evaluated", "resolved_at", "suppression", "suppression_origin",
                                "suppressed_by",
                                "suppression_reason", "suppression_expires_at", "acknowledged_by",
                                "acknowledged_at", "acknowledgement_reason", "compliance_relevant",
                                "summary", "evidence", "timeline"},
                               "finding");
  if (!status.ok()) {
    return status;
  }
  Finding finding;
  std::string text;
  status = RequireString(*map, "id", "finding", text);
  if (!status.ok()) {
    return status;
  }
  const auto id = FindingId::TryParse(text);
  if (!id.has_value()) {
    return MemberError("finding", "id", "is not a finding identity");
  }
  finding.id = *id;
  status = RequireString(*map, "target", "finding", text);
  if (!status.ok()) {
    return status;
  }
  const auto target = TargetId::TryParse(text);
  if (!target.has_value()) {
    return MemberError("finding", "target", "is not a valid identity");
  }
  finding.identity.target = *target;
  status = RequireString(*map, "object", "finding", text);
  if (!status.ok()) {
    return status;
  }
  const auto object = ObjectId::TryParse(text);
  if (!object.has_value()) {
    return MemberError("finding", "object", "is not a valid identity");
  }
  finding.identity.object = *object;
  status = RequireString(*map, "path", "finding", text);
  if (!status.ok()) {
    return status;
  }
  const auto path = FieldPath::TryParse(text, limits.max_path_segments, limits.max_path_key_bytes);
  if (!path.has_value()) {
    return MemberError("finding", "path", "is not a valid field path");
  }
  finding.identity.path = *path;
  status = RequireString(*map, "class", "finding", text);
  if (!status.ok()) {
    return status;
  }
  if (!TryParseDriftClass(text.c_str(), finding.klass)) {
    return MemberError("finding", "class", "is not recognized");
  }
  finding.identity.klass = finding.klass;
  finding.raw_class = finding.klass;
  if (const std::optional<std::string> raw = OptionalString(*map, "raw_class"); raw.has_value()) {
    if (!TryParseDriftClass(raw->c_str(), finding.raw_class)) {
      return MemberError("finding", "raw_class", "is not recognized");
    }
  }
  if (const std::optional<std::string> severity = OptionalString(*map, "severity");
      severity.has_value()) {
    if (!TryParseSeverity(severity->c_str(), finding.severity)) {
      return MemberError("finding", "severity", "is not recognized");
    }
  }
  if (const std::optional<std::string> state = OptionalString(*map, "state"); state.has_value()) {
    if (!TryParseFindingState(state->c_str(), finding.state)) {
      return MemberError("finding", "state", "is not recognized");
    }
  }
  if (const std::optional<std::string> reason = OptionalString(*map, "reason"); reason.has_value()) {
    if (!TryParseReasonCode(reason->c_str(), finding.reason)) {
      return MemberError("finding", "reason", "is not recognized");
    }
  }
  std::uint64_t number = 0;
  status = RequireUint(*map, "baseline_generation", "finding", number);
  if (!status.ok()) {
    return status;
  }
  finding.baseline_generation = IntentGeneration::FromValue(number);
  finding.identity.baseline_generation = finding.baseline_generation;
  if (const std::optional<std::uint64_t> epoch = OptionalUint(*map, "baseline_epoch");
      epoch.has_value()) {
    finding.baseline_epoch = FabricEpoch::FromValue(*epoch);
  }
  if (const std::optional<std::string> authority = OptionalString(*map, "baseline_authority");
      authority.has_value()) {
    if (!TryParseIntentAuthority(authority->c_str(), finding.baseline_authority)) {
      return MemberError("finding", "baseline_authority", "is not recognized");
    }
  }
  if (const std::optional<std::string> policy = OptionalString(*map, "policy"); policy.has_value()) {
    const auto parsed = PolicyId::TryParse(*policy);
    if (!parsed.has_value()) {
      return MemberError("finding", "policy", "is not a valid identity");
    }
    finding.policy = *parsed;
  }
  if (const std::optional<std::string> digest = OptionalString(*map, "policy_digest");
      digest.has_value()) {
    const auto parsed = Digest::TryFromHex(*digest);
    if (!parsed.has_value()) {
      return MemberError("finding", "policy_digest", "is not a digest");
    }
    finding.policy_digest = *parsed;
  }
  if (const std::optional<std::string> qualifier = OptionalString(*map, "qualifier");
      qualifier.has_value() && !qualifier->empty()) {
    const auto parsed = Digest::TryFromHex(*qualifier);
    if (!parsed.has_value()) {
      return MemberError("finding", "qualifier", "is not a digest");
    }
    finding.identity.qualifier = *parsed;
  }
  // The identity digest is derived from the identity members: recompute it and
  // refuse a record whose stored identity does not match its content.
  const FindingId recomputed = finding.identity.ComputeId();
  if (!(recomputed == finding.id)) {
    return Status::Rejected(ReasonCode::LedgerIntegrityDigestMismatch,
                            "finding identity does not match its identity members");
  }
  if (const std::optional<bool> flag = OptionalBool(*map, "has_intended"); flag.has_value()) {
    finding.has_intended = *flag;
  }
  if (const Value* intended = FindMember(*map, "intended"); intended != nullptr) {
    finding.intended = *intended;
  }
  if (const std::optional<bool> flag = OptionalBool(*map, "has_observed"); flag.has_value()) {
    finding.has_observed = *flag;
  }
  if (const Value* observed = FindMember(*map, "observed"); observed != nullptr) {
    finding.observed = *observed;
  }
  if (const std::optional<std::string> freshness = OptionalString(*map, "evidence_freshness");
      freshness.has_value()) {
    if (!TryParseFreshnessState(freshness->c_str(), finding.evidence_freshness)) {
      return MemberError("finding", "evidence_freshness", "is not recognized");
    }
  }
  if (const std::optional<std::string> group = OptionalString(*map, "group");
      group.has_value() && !group->empty()) {
    const auto parsed = GroupId::TryParse(*group);
    if (!parsed.has_value()) {
      return MemberError("finding", "group", "is not a group identity");
    }
    finding.group = *parsed;
  }
  if (const std::optional<std::string> cause = OptionalString(*map, "group_cause");
      cause.has_value()) {
    const std::string_view wanted(*cause);
    bool recognized = false;
    for (std::uint8_t raw = 0; raw < kRootCauseKindCount; ++raw) {
      if (wanted == ToText(static_cast<RootCauseKind>(raw))) {
        finding.group_cause = static_cast<RootCauseKind>(raw);
        recognized = true;
        break;
      }
    }
    if (!recognized) {
      return MemberError("finding", "group_cause", "is not recognized");
    }
  }
  if (const std::optional<std::uint64_t> count = OptionalUint(*map, "observation_count");
      count.has_value()) {
    finding.observation_count = *count;
  }
  if (const std::optional<std::uint64_t> count = OptionalUint(*map, "reopen_count");
      count.has_value()) {
    finding.reopen_count = *count;
  }
  if (const std::optional<std::uint64_t> count = OptionalUint(*map, "resolution_confirmations");
      count.has_value()) {
    if (*count > 0xFFFFFFFFULL) {
      return MemberError("finding", "resolution_confirmations", "is out of range");
    }
    finding.resolution_confirmations = static_cast<std::uint32_t>(*count);
  }
  const char* time_members[] = {"first_seen", "last_seen", "last_evaluated", "resolved_at"};
  NdoTime* time_targets[] = {&finding.first_seen, &finding.last_seen, &finding.last_evaluated,
                             &finding.resolved_at};
  for (std::size_t index = 0; index < 4; ++index) {
    const std::optional<std::string> stamp = OptionalString(*map, time_members[index]);
    if (stamp.has_value() && !stamp->empty()) {
      if (!TryParseTime(*stamp, *time_targets[index])) {
        return MemberError("finding", time_members[index], "is not an RFC 3339 timestamp");
      }
    }
  }
  if (const std::optional<std::string> suppression = OptionalString(*map, "suppression");
      suppression.has_value() && !suppression->empty()) {
    const auto parsed = SuppressionId::TryParse(*suppression);
    if (!parsed.has_value()) {
      return MemberError("finding", "suppression", "is not a valid identity");
    }
    finding.suppression = *parsed;
  }
  if (const std::optional<std::string> origin = OptionalString(*map, "suppression_origin");
      origin.has_value()) {
    if (!TryParseSuppressionOrigin(origin->c_str(), finding.suppression_origin)) {
      return MemberError("finding", "suppression_origin", "is not recognized");
    }
  }
  if (const std::optional<std::string> actor = OptionalString(*map, "suppressed_by");
      actor.has_value() && !actor->empty()) {
    const auto parsed = ActorId::TryParse(*actor);
    if (!parsed.has_value()) {
      return MemberError("finding", "suppressed_by", "is not a valid identity");
    }
    finding.suppressed_by = *parsed;
  }
  if (const std::optional<std::string> reason = OptionalString(*map, "suppression_reason");
      reason.has_value()) {
    finding.suppression_reason = *reason;
  }
  if (const std::optional<std::string> expires = OptionalString(*map, "suppression_expires_at");
      expires.has_value() && !expires->empty()) {
    NdoTime parsed;
    if (!TryParseTime(*expires, parsed)) {
      return MemberError("finding", "suppression_expires_at", "is not an RFC 3339 timestamp");
    }
    finding.suppression_expires_at = parsed;
  }
  if (const std::optional<std::string> actor = OptionalString(*map, "acknowledged_by");
      actor.has_value() && !actor->empty()) {
    const auto parsed = ActorId::TryParse(*actor);
    if (!parsed.has_value()) {
      return MemberError("finding", "acknowledged_by", "is not a valid identity");
    }
    finding.acknowledged_by = *parsed;
  }
  if (const std::optional<std::string> stamp = OptionalString(*map, "acknowledged_at");
      stamp.has_value() && !stamp->empty()) {
    if (!TryParseTime(*stamp, finding.acknowledged_at)) {
      return MemberError("finding", "acknowledged_at", "is not an RFC 3339 timestamp");
    }
  }
  if (const std::optional<std::string> reason = OptionalString(*map, "acknowledgement_reason");
      reason.has_value()) {
    finding.acknowledgement_reason = *reason;
  }
  if (const std::optional<bool> flag = OptionalBool(*map, "compliance_relevant");
      flag.has_value()) {
    finding.compliance_relevant = *flag;
  }
  if (const std::optional<std::string> summary = OptionalString(*map, "summary"); summary.has_value()) {
    finding.summary = *summary;
  }
  if (const Value* evidence = FindMember(*map, "evidence"); evidence != nullptr) {
    const Value::List* list = evidence->as_list();
    if (list == nullptr) {
      return MemberError("finding", "evidence", "must be a sequence");
    }
    if (list->size() > limits.max_evidence_refs_per_finding) {
      return Status::Limit(ReasonCode::LimitBytesExceeded, "evidence references exceed the envelope");
    }
    for (const Value& entry : *list) {
      EvidenceRef reference;
      status = DecodeEvidenceRef(entry, reference);
      if (!status.ok()) {
        return status;
      }
      finding.evidence.push_back(std::move(reference));
    }
  }
  if (const Value* timeline = FindMember(*map, "timeline"); timeline != nullptr) {
    const Value::List* list = timeline->as_list();
    if (list == nullptr) {
      return MemberError("finding", "timeline", "must be a sequence");
    }
    if (list->size() > limits.max_timeline_entries_per_finding) {
      return Status::Limit(ReasonCode::LimitTimelineExceeded, "finding timeline exceeds the envelope");
    }
    for (const Value& entry : *list) {
      TimelineEntry decoded;
      status = DecodeTimelineEntry(entry, decoded);
      if (!status.ok()) {
        return status;
      }
      finding.timeline.push_back(std::move(decoded));
    }
  }
  out = std::move(finding);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Value EncodeGroup(const RootCauseGroup& group) {
  Value::Map map;
  map.emplace("id", Value::MakeString(group.id.ToHex()));
  map.emplace("target", Value::MakeString(group.target.str()));
  map.emplace("baseline_generation", Value::MakeUint(group.baseline_generation.value()));
  map.emplace("baseline_epoch", Value::MakeUint(group.baseline_epoch.value()));
  map.emplace("cause", Value::MakeString(ToText(group.cause)));
  map.emplace("discriminator", Value::MakeString(group.discriminator.ToHex()));
  map.emplace("summary", Value::MakeString(group.summary));
  map.emplace("observation_count", Value::MakeUint(group.observation_count));
  map.emplace("first_seen", Value::MakeString(FormatTime(group.first_seen)));
  map.emplace("last_seen", Value::MakeString(FormatTime(group.last_seen)));
  {
    Value::List members;
    for (const FindingId& member : group.members) {
      members.push_back(Value::MakeString(member.ToHex()));
    }
    map.emplace("members", Value::MakeList(std::move(members)));
  }
  {
    Value::List objects;
    for (const ObjectId& object : group.objects) {
      objects.push_back(Value::MakeString(object.str()));
    }
    map.emplace("objects", Value::MakeList(std::move(objects)));
  }
  return Value::MakeMap(std::move(map));
}

Status DecodeGroup(const Value& value, RootCauseGroup& out) {
  const Value::Map* map = value.as_map();
  if (map == nullptr) {
    return Status::Rejected(ReasonCode::LedgerDecodeFailed, "group must be an object");
  }
  Status status = CheckMembers(*map,
                               {"id", "target", "baseline_generation", "baseline_epoch", "cause",
                                "discriminator", "summary", "observation_count", "first_seen",
                                "last_seen", "members", "objects"},
                               "group");
  if (!status.ok()) {
    return status;
  }
  RootCauseGroup group;
  std::string text;
  status = RequireString(*map, "id", "group", text);
  if (!status.ok()) {
    return status;
  }
  const auto id = GroupId::TryParse(text);
  if (!id.has_value()) {
    return MemberError("group", "id", "is not a group identity");
  }
  group.id = *id;
  status = RequireString(*map, "target", "group", text);
  if (!status.ok()) {
    return status;
  }
  const auto target = TargetId::TryParse(text);
  if (!target.has_value()) {
    return MemberError("group", "target", "is not a valid identity");
  }
  group.target = *target;
  std::uint64_t number = 0;
  status = RequireUint(*map, "baseline_generation", "group", number);
  if (!status.ok()) {
    return status;
  }
  group.baseline_generation = IntentGeneration::FromValue(number);
  if (const std::optional<std::uint64_t> epoch = OptionalUint(*map, "baseline_epoch");
      epoch.has_value()) {
    group.baseline_epoch = FabricEpoch::FromValue(*epoch);
  }
  status = RequireString(*map, "cause", "group", text);
  if (!status.ok()) {
    return status;
  }
  bool recognized = false;
  for (std::uint8_t raw = 0; raw < kRootCauseKindCount; ++raw) {
    if (std::string_view(text) == ToText(static_cast<RootCauseKind>(raw))) {
      group.cause = static_cast<RootCauseKind>(raw);
      recognized = true;
      break;
    }
  }
  if (!recognized) {
    return MemberError("group", "cause", "is not recognized");
  }
  if (const std::optional<std::string> digest = OptionalString(*map, "discriminator");
      digest.has_value() && !digest->empty()) {
    const auto parsed = Digest::TryFromHex(*digest);
    if (!parsed.has_value()) {
      return MemberError("group", "discriminator", "is not a digest");
    }
    group.discriminator = *parsed;
  }
  if (const std::optional<std::string> summary = OptionalString(*map, "summary");
      summary.has_value()) {
    group.summary = *summary;
  }
  if (const std::optional<std::uint64_t> count = OptionalUint(*map, "observation_count");
      count.has_value()) {
    group.observation_count = *count;
  }
  const char* time_members[] = {"first_seen", "last_seen"};
  NdoTime* time_targets[] = {&group.first_seen, &group.last_seen};
  for (std::size_t index = 0; index < 2; ++index) {
    const std::optional<std::string> stamp = OptionalString(*map, time_members[index]);
    if (stamp.has_value() && !stamp->empty()) {
      if (!TryParseTime(*stamp, *time_targets[index])) {
        return MemberError("group", time_members[index], "is not an RFC 3339 timestamp");
      }
    }
  }
  if (const Value* members = FindMember(*map, "members"); members != nullptr) {
    const Value::List* list = members->as_list();
    if (list == nullptr) {
      return MemberError("group", "members", "must be a sequence");
    }
    for (const Value& entry : *list) {
      const std::string* member_text = entry.as_string();
      if (member_text == nullptr) {
        return MemberError("group", "members", "entries must be strings");
      }
      const auto member = FindingId::TryParse(*member_text);
      if (!member.has_value()) {
        return MemberError("group", "members", "entry is not a finding identity");
      }
      group.members.push_back(*member);
    }
  }
  if (const Value* objects = FindMember(*map, "objects"); objects != nullptr) {
    const Value::List* list = objects->as_list();
    if (list == nullptr) {
      return MemberError("group", "objects", "must be a sequence");
    }
    for (const Value& entry : *list) {
      const std::string* object_text = entry.as_string();
      if (object_text == nullptr) {
        return MemberError("group", "objects", "entries must be strings");
      }
      const auto object = ObjectId::TryParse(*object_text);
      if (!object.has_value()) {
        return MemberError("group", "objects", "entry is not a valid identity");
      }
      group.objects.push_back(*object);
    }
  }
  out = std::move(group);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Value EncodeBaseline(const IntentBaseline& baseline) {
  Value::Map map;
  map.emplace("target", Value::MakeString(baseline.target.str()));
  map.emplace("generation", Value::MakeUint(baseline.generation.value()));
  map.emplace("epoch", Value::MakeUint(baseline.epoch.value()));
  map.emplace("authority", Value::MakeString(ToText(baseline.authority)));
  map.emplace("policy", Value::MakeString(baseline.policy.str()));
  map.emplace("committed_at", Value::MakeString(FormatTime(baseline.committed_at)));
  map.emplace("content_digest", Value::MakeString(baseline.content_digest.ToHex()));
  map.emplace("evidence", Value::MakeString(ToText(baseline.evidence)));
  {
    Value::List objects;
    for (const auto& entry : baseline.objects) {
      Value::Map object;
      object.emplace("id", Value::MakeString(entry.first.str()));
      object.emplace("existence", Value::MakeString(ToText(entry.second.existence)));
      Value::List fields;
      for (const auto& field : entry.second.fields) {
        Value::Map encoded;
        encoded.emplace("path", Value::MakeString(field.first.ToText()));
        encoded.emplace("value", field.second.intended);
        encoded.emplace("comparability", Value::MakeString(ToText(field.second.comparability)));
        fields.push_back(Value::MakeMap(std::move(encoded)));
      }
      object.emplace("fields", Value::MakeList(std::move(fields)));
      objects.push_back(Value::MakeMap(std::move(object)));
    }
    map.emplace("objects", Value::MakeList(std::move(objects)));
  }
  return Value::MakeMap(std::move(map));
}

Status DecodeBaseline(const Value& value, const RuntimeLimits& limits, IntentBaseline& out) {
  const Value::Map* map = value.as_map();
  if (map == nullptr) {
    return Status::Rejected(ReasonCode::LedgerDecodeFailed, "baseline must be an object");
  }
  Status status = CheckMembers(*map,
                               {"target", "generation", "epoch", "authority", "policy", "committed_at",
                                "content_digest", "evidence", "objects"},
                               "baseline");
  if (!status.ok()) {
    return status;
  }
  IntentBaseline baseline;
  std::string text;
  status = RequireString(*map, "target", "baseline", text);
  if (!status.ok()) {
    return status;
  }
  const auto target = TargetId::TryParse(text);
  if (!target.has_value()) {
    return MemberError("baseline", "target", "is not a valid identity");
  }
  baseline.target = *target;
  std::uint64_t number = 0;
  status = RequireUint(*map, "generation", "baseline", number);
  if (!status.ok()) {
    return status;
  }
  baseline.generation = IntentGeneration::FromValue(number);
  status = RequireUint(*map, "epoch", "baseline", number);
  if (!status.ok()) {
    return status;
  }
  baseline.epoch = FabricEpoch::FromValue(number);
  if (const std::optional<std::string> authority = OptionalString(*map, "authority");
      authority.has_value()) {
    if (!TryParseIntentAuthority(authority->c_str(), baseline.authority)) {
      return MemberError("baseline", "authority", "is not recognized");
    }
  }
  if (const std::optional<std::string> policy = OptionalString(*map, "policy"); policy.has_value()) {
    const auto parsed = PolicyId::TryParse(*policy);
    if (!parsed.has_value()) {
      return MemberError("baseline", "policy", "is not a valid identity");
    }
    baseline.policy = *parsed;
  }
  if (const std::optional<std::string> committed = OptionalString(*map, "committed_at");
      committed.has_value()) {
    if (!TryParseTime(*committed, baseline.committed_at)) {
      return MemberError("baseline", "committed_at", "is not an RFC 3339 timestamp");
    }
  }
  const std::optional<std::string> digest = OptionalString(*map, "content_digest");
  if (digest.has_value()) {
    const auto parsed = Digest::TryFromHex(*digest);
    if (!parsed.has_value()) {
      return MemberError("baseline", "content_digest", "is not a digest");
    }
    baseline.content_digest = *parsed;
  }
  if (const std::optional<std::string> evidence = OptionalString(*map, "evidence");
      evidence.has_value()) {
    if (!TryParseEvidenceClass(evidence->c_str(), baseline.evidence)) {
      return MemberError("baseline", "evidence", "is not recognized");
    }
  }
  const Value* objects = FindMember(*map, "objects");
  if (objects == nullptr) {
    return MemberError("baseline", "objects", "missing required member");
  }
  const Value::List* list = objects->as_list();
  if (list == nullptr) {
    return MemberError("baseline", "objects", "must be a sequence");
  }
  if (list->size() > limits.max_objects_per_target) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded, "baseline object count exceeds the envelope");
  }
  for (const Value& entry : *list) {
    const Value::Map* object_map = entry.as_map();
    if (object_map == nullptr) {
      return Status::Rejected(ReasonCode::LedgerDecodeFailed, "baseline object must be an object");
    }
    status = CheckMembers(*object_map, {"id", "existence", "fields"}, "baseline.object");
    if (!status.ok()) {
      return status;
    }
    IntentObject object;
    status = RequireString(*object_map, "id", "baseline.object", text);
    if (!status.ok()) {
      return status;
    }
    const auto id = ObjectId::TryParse(text);
    if (!id.has_value()) {
      return MemberError("baseline.object", "id", "is not a valid identity");
    }
    object.id = *id;
    if (const std::optional<std::string> existence = OptionalString(*object_map, "existence");
        existence.has_value()) {
      if (*existence == "required") {
        object.existence = ObjectExistence::Required;
      } else if (*existence == "forbidden") {
        object.existence = ObjectExistence::Forbidden;
      } else {
        return MemberError("baseline.object", "existence", "is not recognized");
      }
    }
    const Value* fields = FindMember(*object_map, "fields");
    if (fields == nullptr) {
      return MemberError("baseline.object", "fields", "missing required member");
    }
    const Value::List* field_list = fields->as_list();
    if (field_list == nullptr) {
      return MemberError("baseline.object", "fields", "must be a sequence");
    }
    if (field_list->size() > limits.max_fields_per_object) {
      return Status::Limit(ReasonCode::LimitFieldsExceeded, "baseline field count exceeds the envelope");
    }
    for (const Value& field_value : *field_list) {
      const Value::Map* field_map = field_value.as_map();
      if (field_map == nullptr) {
        return Status::Rejected(ReasonCode::LedgerDecodeFailed, "baseline field must be an object");
      }
      status = CheckMembers(*field_map, {"path", "value", "comparability"}, "baseline.field");
      if (!status.ok()) {
        return status;
      }
      IntentField field;
      status = RequireString(*field_map, "path", "baseline.field", text);
      if (!status.ok()) {
        return status;
      }
      const auto path =
          FieldPath::TryParse(text, limits.max_path_segments, limits.max_path_key_bytes);
      if (!path.has_value()) {
        return MemberError("baseline.field", "path", "is not a valid field path");
      }
      field.path = *path;
      const Value* raw = FindMember(*field_map, "value");
      if (raw == nullptr) {
        return MemberError("baseline.field", "value", "missing required member");
      }
      field.intended = *raw;
      if (const std::optional<std::string> comparability =
              OptionalString(*field_map, "comparability");
          comparability.has_value()) {
        if (!TryParseFieldComparability(comparability->c_str(), field.comparability)) {
          return MemberError("baseline.field", "comparability", "is not recognized");
        }
      }
      object.fields.emplace(field.path, std::move(field));
    }
    baseline.objects.emplace(object.id, std::move(object));
  }
  out = std::move(baseline);
  return Status(StatusCode::Ok, ReasonCode::None);
}

}  // namespace detail

using detail::AppendU16;
using detail::AppendU64;
using detail::CheckMembers;
using detail::DecodeBaseline;
using detail::DecodeFinding;
using detail::DecodeGroup;
using detail::DecodeTimelineEntry;
using detail::EncodeBaseline;
using detail::EncodeFinding;
using detail::EncodeGroup;
using detail::EncodeTimelineEntry;
using detail::FindMember;
using detail::MemberError;
using detail::OptionalUint;
using detail::ReadU16;
using detail::ReadU64;
using detail::RequireUint;

namespace {

/// The envelope used to parse a ledger payload.
///
/// A ledger payload is not an interchange document: it legitimately contains as
/// many tree nodes as the findings, observations and timeline entries it is
/// allowed to hold. The byte bound stays authoritative; the node, member and
/// depth budgets are raised just far enough that the runtime never refuses a
/// ledger it wrote itself. Every step is checked.
RuntimeLimits LedgerPayloadLimits(const RuntimeLimits& limits) {
  RuntimeLimits payload = limits;
  const std::size_t per_record = 128;
  std::size_t budget = 4096;
  const std::size_t counts[] = {limits.max_findings, limits.max_global_timeline_entries,
                                limits.max_targets};
  for (const std::size_t count : counts) {
    const auto added = CheckedMul<std::size_t>(per_record, count);
    if (!added.has_value()) {
      budget = 0;
      break;
    }
    const auto total = CheckedAdd<std::size_t>(budget, *added);
    if (!total.has_value()) {
      budget = 0;
      break;
    }
    budget = *total;
  }
  payload.max_value_nodes = budget == 0 ? 100000000u : budget;
  payload.max_value_depth = limits.max_value_depth + 8;
  payload.max_fields_per_object = limits.max_fields_per_object > 256 ? limits.max_fields_per_object : 256;
  payload.max_document_bytes = limits.max_ledger_bytes;
  payload.max_leaf_bytes = limits.max_leaf_bytes;
  return payload;
}

}  // namespace

Digest LedgerPayloadDigest(const std::uint8_t* payload, std::size_t size) {
  return HashBytes(payload, size);
}

Status EncodeLedger(const FindingLedger& ledger, FabricEpoch write_epoch,
                    Incarnation write_incarnation, std::vector<std::uint8_t>& out) {
  Value::Map root;
  root.emplace("schema", Value::MakeString("ndo/ledger/1"));
  root.emplace("format_version", Value::MakeUint(kLedgerFormatVersion));
  root.emplace("revision", Value::MakeUint(ledger.revision().value()));
  root.emplace("timeline_sequence", Value::MakeUint(ledger.timeline_sequence()));
  {
    Value::List baselines;
    for (const TargetId& target : ledger.Targets()) {
      const IntentBaseline* baseline = ledger.FindBaseline(target);
      if (baseline == nullptr) {
        continue;
      }
      baselines.push_back(EncodeBaseline(*baseline));
    }
    root.emplace("baselines", Value::MakeList(std::move(baselines)));
  }
  {
    Value::List observations;
    for (const TargetId& target : ledger.Targets()) {
      for (const RetainedObservation& observation : ledger.ObservationsFor(target)) {
        Value::Map entry;
        entry.emplace("recovered", Value::MakeBool(true));
        entry.emplace("document", EncodeObservationDocument(observation.snapshot));
        observations.push_back(Value::MakeMap(std::move(entry)));
      }
    }
    root.emplace("observations", Value::MakeList(std::move(observations)));
  }
  {
    Value::List findings;
    for (const Finding* finding : ledger.Findings()) {
      findings.push_back(EncodeFinding(*finding));
    }
    root.emplace("findings", Value::MakeList(std::move(findings)));
  }
  {
    Value::List groups;
    for (const RootCauseGroup* group : ledger.Groups()) {
      groups.push_back(EncodeGroup(*group));
    }
    root.emplace("groups", Value::MakeList(std::move(groups)));
  }
  {
    Value::List timeline;
    for (const TimelineEntry* entry : ledger.GlobalTimeline()) {
      timeline.push_back(EncodeTimelineEntry(*entry));
    }
    root.emplace("timeline", Value::MakeList(std::move(timeline)));
  }
  const std::string payload = WriteCanonicalJson(Value::MakeMap(std::move(root)));
  const auto payload_bytes = static_cast<std::uint64_t>(payload.size());
  out.clear();
  out.reserve(kLedgerHeaderBytes + payload.size());
  out.insert(out.end(), kLedgerMagic, kLedgerMagic + sizeof(kLedgerMagic));
  AppendU16(out, kLedgerFormatVersion);
  AppendU16(out, 0);
  AppendU64(out, payload_bytes);
  const Digest digest = LedgerPayloadDigest(reinterpret_cast<const std::uint8_t*>(payload.data()),
                                            payload.size());
  out.insert(out.end(), digest.bytes.begin(), digest.bytes.end());
  AppendU64(out, write_epoch.value());
  AppendU64(out, write_incarnation.value());
  out.insert(out.end(), payload.begin(), payload.end());
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status DecodeLedger(const std::uint8_t* bytes, std::size_t size, const RuntimeLimits& limits,
                    FabricEpoch live_epoch, FindingLedger& out, LedgerRecoveryReport& report) {
  report = LedgerRecoveryReport{};
  if (bytes == nullptr) {
    return Status::Rejected(ReasonCode::LedgerHeaderInvalid, "no bytes were supplied");
  }
  if (size > limits.max_ledger_bytes) {
    return Status::Limit(ReasonCode::LedgerPayloadTooLarge, "ledger exceeds the envelope");
  }
  if (size < kLedgerHeaderBytes) {
    return Status::Rejected(ReasonCode::LedgerTruncated, "ledger is shorter than its header");
  }
  for (std::size_t index = 0; index < sizeof(kLedgerMagic); ++index) {
    if (bytes[index] != static_cast<std::uint8_t>(kLedgerMagic[index])) {
      return Status::Rejected(ReasonCode::LedgerHeaderInvalid, "ledger magic does not match");
    }
  }
  const std::uint16_t format = ReadU16(bytes + 8);
  if (format != kLedgerFormatVersion) {
    return Status::Rejected(ReasonCode::LedgerSchemaUnsupported,
                            "ledger format version is not supported");
  }
  const std::uint64_t payload_bytes = ReadU64(bytes + 12);
  if (payload_bytes > limits.max_record_payload_bytes) {
    return Status::Limit(ReasonCode::LedgerPayloadTooLarge, "ledger payload exceeds the envelope");
  }
  const auto expected_size = static_cast<std::uint64_t>(kLedgerHeaderBytes) + payload_bytes;
  if (expected_size > static_cast<std::uint64_t>(size)) {
    return Status::Rejected(ReasonCode::LedgerTruncated, "ledger payload is truncated");
  }
  if (expected_size < static_cast<std::uint64_t>(size)) {
    return Status::Rejected(ReasonCode::LedgerTruncated,
                            "ledger carries bytes beyond its declared payload");
  }
  const std::uint8_t* declared_digest = bytes + 20;
  const std::uint64_t write_epoch = ReadU64(bytes + 52);
  const std::uint64_t write_incarnation = ReadU64(bytes + 60);
  static_cast<void>(write_incarnation);
  const std::uint8_t* payload = bytes + kLedgerHeaderBytes;
  const Digest actual = LedgerPayloadDigest(payload, static_cast<std::size_t>(payload_bytes));
  Digest expected;
  for (std::size_t index = 0; index < kDigestBytes; ++index) {
    expected.bytes[index] = declared_digest[index];
  }
  if (!(actual == expected)) {
    return Status::Integrity(ReasonCode::LedgerIntegrityDigestMismatch,
                             "ledger payload digest does not match the header");
  }
  if (live_epoch.is_set() && write_epoch > live_epoch.value()) {
    return Status::Stale(ReasonCode::LedgerVersionRegression,
                         "ledger was written by a newer epoch than the live one");
  }

  Value root;
  const RuntimeLimits payload_limits = LedgerPayloadLimits(limits);
  Status status =
      ParseJson(std::string_view(reinterpret_cast<const char*>(payload),
                                 static_cast<std::size_t>(payload_bytes)),
                payload_limits, root);
  if (!status.ok()) {
    return Status::Integrity(ReasonCode::LedgerDecodeFailed,
                             std::string("ledger payload did not parse: ") + ToText(status.reason));
  }
  const Value::Map* map = root.as_map();
  if (map == nullptr) {
    return Status::Rejected(ReasonCode::LedgerDecodeFailed, "ledger payload must be an object");
  }
  status = CheckMembers(*map,
                        {"schema", "format_version", "revision", "timeline_sequence", "baselines",
                         "observations", "findings", "groups", "timeline"},
                        "ledger");
  if (!status.ok()) {
    return status;
  }
  std::uint64_t format_member = 0;
  status = RequireUint(*map, "format_version", "ledger", format_member);
  if (!status.ok()) {
    return status;
  }
  if (format_member != kLedgerFormatVersion) {
    return Status::Rejected(ReasonCode::LedgerSchemaUnsupported,
                            "ledger payload declares an unsupported format version");
  }

  FindingLedger decoded(limits);
  std::uint64_t revision = 0;
  status = RequireUint(*map, "revision", "ledger", revision);
  if (!status.ok()) {
    return status;
  }
  decoded.RestoreRevision(LedgerRevision::FromValue(revision));
  if (const std::optional<std::uint64_t> sequence = OptionalUint(*map, "timeline_sequence");
      sequence.has_value()) {
    decoded.RestoreSuppressionSequence(*sequence);
  }
  report.revision = LedgerRevision::FromValue(revision);

  if (const Value* baselines = FindMember(*map, "baselines"); baselines != nullptr) {
    const Value::List* list = baselines->as_list();
    if (list == nullptr) {
      return MemberError("ledger", "baselines", "must be a sequence");
    }
    for (const Value& entry : *list) {
      IntentBaseline baseline;
      status = DecodeBaseline(entry, payload_limits, baseline);
      if (!status.ok()) {
        return status;
      }
      status = decoded.RestoreBaseline(std::move(baseline));
      if (!status.ok()) {
        return status;
      }
      ++report.baselines_restored;
    }
  }
  if (const Value* observations = FindMember(*map, "observations"); observations != nullptr) {
    const Value::List* list = observations->as_list();
    if (list == nullptr) {
      return MemberError("ledger", "observations", "must be a sequence");
    }
    for (const Value& entry : *list) {
      const Value::Map* entry_map = entry.as_map();
      if (entry_map == nullptr) {
        return MemberError("ledger", "observations", "entries must be objects");
      }
      status = CheckMembers(*entry_map, {"recovered", "document"}, "ledger.observation");
      if (!status.ok()) {
        return status;
      }
      const Value* document = FindMember(*entry_map, "document");
      if (document == nullptr) {
        return MemberError("ledger.observation", "document", "missing required member");
      }
      ObservationSnapshot snapshot;
      status = DecodeObservationDocument(*document, payload_limits, snapshot);
      if (!status.ok()) {
        return status;
      }
      RetainedObservation restored;
      restored.snapshot = std::move(snapshot);
      restored.recovered = true;
      restored.freshness.state = FreshnessState::RecoveredNotFresh;
      restored.freshness.reason = ReasonCode::EvidenceRecoveredNotFresh;
      restored.freshness.may_support_compliance = false;
      status = decoded.RestoreObservation(std::move(restored));
      if (!status.ok()) {
        return status;
      }
      ++report.observations_restored;
    }
  }
  if (const Value* findings = FindMember(*map, "findings"); findings != nullptr) {
    const Value::List* list = findings->as_list();
    if (list == nullptr) {
      return MemberError("ledger", "findings", "must be a sequence");
    }
    if (list->size() > limits.max_findings) {
      return Status::Limit(ReasonCode::LimitFindingsExceeded, "ledger finding count exceeds the envelope");
    }
    for (const Value& entry : *list) {
      Finding finding;
      status = DecodeFinding(entry, payload_limits, finding);
      if (!status.ok()) {
        return status;
      }
      status = decoded.RestoreFinding(std::move(finding));
      if (!status.ok()) {
        return status;
      }
      ++report.findings_restored;
    }
  }
  if (const Value* groups = FindMember(*map, "groups"); groups != nullptr) {
    const Value::List* list = groups->as_list();
    if (list == nullptr) {
      return MemberError("ledger", "groups", "must be a sequence");
    }
    for (const Value& entry : *list) {
      RootCauseGroup group;
      status = DecodeGroup(entry, group);
      if (!status.ok()) {
        return status;
      }
      status = decoded.RestoreGroup(std::move(group));
      if (!status.ok()) {
        return status;
      }
      ++report.groups_restored;
    }
  }
  if (const Value* timeline = FindMember(*map, "timeline"); timeline != nullptr) {
    const Value::List* list = timeline->as_list();
    if (list == nullptr) {
      return MemberError("ledger", "timeline", "must be a sequence");
    }
    if (list->size() > limits.max_global_timeline_entries) {
      return Status::Limit(ReasonCode::LimitTimelineExceeded, "ledger timeline exceeds the envelope");
    }
    for (const Value& entry : *list) {
      TimelineEntry decoded_entry;
      status = DecodeTimelineEntry(entry, decoded_entry);
      if (!status.ok()) {
        return status;
      }
      status = decoded.RestoreTimeline(std::move(decoded_entry));
      if (!status.ok()) {
        return status;
      }
    }
  }
  report.conservative = true;
  report.reason = ReasonCode::LedgerRecoveredConservatively;
  out = std::move(decoded);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status SaveLedgerFile(const FindingLedger& ledger, const std::string& path, FabricEpoch write_epoch,
                      Incarnation write_incarnation, std::size_t max_bytes) {
  std::vector<std::uint8_t> bytes;
  Status status = EncodeLedger(ledger, write_epoch, write_incarnation, bytes);
  if (!status.ok()) {
    return status;
  }
  if (bytes.size() > max_bytes) {
    return Status::Limit(ReasonCode::LedgerPayloadTooLarge, "encoded ledger exceeds the file envelope");
  }
  const std::filesystem::path target(path);
  const std::filesystem::path temporary = target.string() + ".tmp";
  {
    std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
    if (!stream) {
      return Status::Rejected(ReasonCode::LedgerHeaderInvalid,
                              "the ledger file could not be opened for writing");
    }
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!stream) {
      return Status::Rejected(ReasonCode::LedgerHeaderInvalid, "the ledger file could not be written");
    }
    stream.flush();
    if (!stream) {
      return Status::Rejected(ReasonCode::LedgerHeaderInvalid, "the ledger file could not be flushed");
    }
  }
  std::error_code error;
  std::filesystem::rename(temporary, target, error);
  if (error) {
    std::filesystem::remove(temporary, error);
    return Status::Rejected(ReasonCode::LedgerHeaderInvalid,
                            "the ledger file could not be replaced atomically");
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status LoadLedgerFile(const std::string& path, const RuntimeLimits& limits, FabricEpoch live_epoch,
                      FindingLedger& out, LedgerRecoveryReport& report) {
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  if (error) {
    return Status::NotFound(ReasonCode::LedgerHeaderInvalid, "the ledger file could not be inspected");
  }
  if (size > limits.max_ledger_bytes) {
    return Status::Limit(ReasonCode::LedgerPayloadTooLarge, "ledger file exceeds the envelope");
  }
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
  {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
      return Status::NotFound(ReasonCode::LedgerHeaderInvalid, "the ledger file could not be opened");
    }
    if (!bytes.empty()) {
      stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
      if (stream.gcount() != static_cast<std::streamsize>(bytes.size())) {
        return Status::Rejected(ReasonCode::LedgerTruncated, "the ledger file ended early");
      }
    }
  }
  return DecodeLedger(bytes.data(), bytes.size(), limits, live_epoch, out, report);
}

}  // namespace network_drift_observatory
}  // namespace summon
