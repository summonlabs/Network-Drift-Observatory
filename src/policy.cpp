// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/policy.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "json_help.hpp"
#include "summon/network_drift_observatory/version.hpp"

namespace summon {
namespace network_drift_observatory {
namespace {

constexpr std::size_t kMaxPolicyRules = 4096;
constexpr std::size_t kPolicySchemaTag = 1;

int SelectorSpecificity(const PolicySelector& selector) noexcept {
  int score = 0;
  if (selector.target.has_value()) {
    score += 8;
  }
  if (selector.object.has_value()) {
    score += 4;
  }
  if (selector.path_prefix.has_value()) {
    score += 2;
  }
  return score;
}

constexpr std::uint8_t ComparabilityRank(FieldComparability value) noexcept {
  return static_cast<std::uint8_t>(value);
}

Value::Map EncodeSelector(const PolicySelector& selector) {
  Value::Map map;
  if (selector.target.has_value()) {
    map.emplace("target", Value::MakeString(selector.target->str()));
  }
  if (selector.object.has_value()) {
    map.emplace("object", Value::MakeString(selector.object->str()));
  }
  if (selector.path_prefix.has_value()) {
    map.emplace("path_prefix", Value::MakeString(selector.path_prefix->ToText()));
  }
  return map;
}

Status DecodeSelector(const Value::Map& map, const RuntimeLimits& limits, const char* what,
                      PolicySelector& out) {
  // The caller has already refused unknown members; this helper only extracts.
  Status status = detail::CheckMemberKinds(
      map, {{"target", detail::MemberKind::Text},
            {"object", detail::MemberKind::Text},
            {"path_prefix", detail::MemberKind::Text}},
      what);
  if (!status.ok()) {
    return status;
  }
  if (const std::optional<std::string> target = detail::OptionalString(map, "target");
      target.has_value()) {
    const auto parsed = TargetId::TryParse(*target);
    if (!parsed.has_value()) {
      return detail::MemberError(what, "target", "is not a valid identity");
    }
    out.target = *parsed;
  }
  if (const std::optional<std::string> object = detail::OptionalString(map, "object");
      object.has_value()) {
    const auto parsed = ObjectId::TryParse(*object);
    if (!parsed.has_value()) {
      return detail::MemberError(what, "object", "is not a valid identity");
    }
    out.object = *parsed;
  }
  if (const std::optional<std::string> path = detail::OptionalString(map, "path_prefix");
      path.has_value()) {
    const auto parsed = FieldPath::TryParse(*path, limits.max_path_segments, limits.max_path_key_bytes);
    if (!parsed.has_value()) {
      return detail::MemberError(what, "path_prefix", "is not a valid field path");
    }
    out.path_prefix = *parsed;
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

}  // namespace

bool PolicySelector::Matches(const TargetId& target_id, const ObjectId& object_id,
                             const FieldPath& path) const noexcept {
  if (target.has_value() && !(*target == target_id)) {
    return false;
  }
  if (object.has_value() && !(*object == object_id)) {
    return false;
  }
  if (path_prefix.has_value() && !path_prefix->IsPrefixOf(path)) {
    return false;
  }
  return true;
}

bool PolicySelector::IsSubsetOf(const PolicySelector& other) const noexcept {
  if (other.target.has_value()) {
    if (!target.has_value() || !(*target == *other.target)) {
      return false;
    }
  }
  if (other.object.has_value()) {
    if (!object.has_value() || !(*object == *other.object)) {
      return false;
    }
  }
  if (other.path_prefix.has_value()) {
    if (!path_prefix.has_value() || !other.path_prefix->IsPrefixOf(*path_prefix)) {
      return false;
    }
  }
  return true;
}

bool SuppressionRule::is_expired_at(NdoTime now) const noexcept {
  if (!expires_at.has_value()) {
    return false;
  }
  return now >= *expires_at;
}

Digest ObservatoryPolicy::ComputeDigest() const {
  Sha256 hasher;
  hasher.UpdateTag(detail::kPolicyTag);
  hasher.UpdateU64(kPolicySchemaTag);
  hasher.UpdateLengthPrefixed(id.str());
  hasher.UpdateU64(format_version);
  hasher.UpdateU64(static_cast<std::uint64_t>(freshness.ttl_nanos));
  hasher.UpdateU64(static_cast<std::uint64_t>(freshness.aging_threshold_percent));
  hasher.UpdateU64(static_cast<std::uint64_t>(freshness.max_clock_skew_nanos));
  hasher.UpdateByte(freshness.ttl_applies_to_receive_time ? 1u : 0u);
  hasher.UpdateU64(resolution_confirmations);
  hasher.UpdateByte(require_complete_coverage_for_compliance ? 1u : 0u);
  hasher.UpdateByte(require_absence_authority ? 1u : 0u);
  hasher.UpdateByte(static_cast<std::uint8_t>(numeric_equivalence));
  hasher.UpdateByte(static_cast<std::uint8_t>(default_severity));
  hasher.UpdateByte(static_cast<std::uint8_t>(evidence));
  hasher.UpdateU64(severity_rules.size());
  for (const SeverityRule& rule : severity_rules) {
    hasher.UpdateLengthPrefixed(rule.selector.target.has_value() ? rule.selector.target->str() : "");
    hasher.UpdateLengthPrefixed(rule.selector.object.has_value() ? rule.selector.object->str() : "");
    hasher.UpdateLengthPrefixed(rule.selector.path_prefix.has_value()
                                    ? rule.selector.path_prefix->ToText()
                                    : "");
    hasher.UpdateLengthPrefixed(rule.klass.has_value() ? ToText(*rule.klass) : "");
    hasher.UpdateByte(rule.min_severity.has_value()
                          ? static_cast<std::uint8_t>(*rule.min_severity) + 1u
                          : 0u);
    hasher.UpdateByte(static_cast<std::uint8_t>(rule.severity));
  }
  hasher.UpdateU64(freshness_rules.size());
  for (const FreshnessRule& rule : freshness_rules) {
    hasher.UpdateLengthPrefixed(rule.selector.target.has_value() ? rule.selector.target->str() : "");
    hasher.UpdateLengthPrefixed(rule.selector.object.has_value() ? rule.selector.object->str() : "");
    hasher.UpdateLengthPrefixed(rule.selector.path_prefix.has_value()
                                    ? rule.selector.path_prefix->ToText()
                                    : "");
    hasher.UpdateU64(static_cast<std::uint64_t>(rule.ttl_nanos));
  }
  hasher.UpdateU64(field_class_rules.size());
  for (const FieldClassRule& rule : field_class_rules) {
    hasher.UpdateLengthPrefixed(rule.selector.target.has_value() ? rule.selector.target->str() : "");
    hasher.UpdateLengthPrefixed(rule.selector.object.has_value() ? rule.selector.object->str() : "");
    hasher.UpdateLengthPrefixed(rule.selector.path_prefix.has_value()
                                    ? rule.selector.path_prefix->ToText()
                                    : "");
    hasher.UpdateByte(static_cast<std::uint8_t>(rule.comparability));
  }
  hasher.UpdateU64(suppressions.size());
  for (const SuppressionRule& rule : suppressions) {
    hasher.UpdateLengthPrefixed(rule.id.str());
    hasher.UpdateLengthPrefixed(rule.selector.target.has_value() ? rule.selector.target->str() : "");
    hasher.UpdateLengthPrefixed(rule.selector.object.has_value() ? rule.selector.object->str() : "");
    hasher.UpdateLengthPrefixed(rule.selector.path_prefix.has_value()
                                    ? rule.selector.path_prefix->ToText()
                                    : "");
    hasher.UpdateLengthPrefixed(rule.klass.has_value() ? ToText(*rule.klass) : "");
    hasher.UpdateByte(rule.min_severity.has_value()
                          ? static_cast<std::uint8_t>(*rule.min_severity) + 1u
                          : 0u);
    hasher.UpdateLengthPrefixed(rule.author.str());
    hasher.UpdateLengthPrefixed(rule.reason);
    hasher.UpdateU64(static_cast<std::uint64_t>(rule.created_at.unix_nanos));
    hasher.UpdateU64(static_cast<std::uint64_t>(rule.expires_at.has_value()
                                                    ? rule.expires_at->unix_nanos
                                                    : 0));
  }
  hasher.UpdateU64(source_priority.size());
  for (const SourceId& source : source_priority) {
    hasher.UpdateLengthPrefixed(source.str());
  }
  hasher.UpdateU64(required_targets.size());
  for (const TargetId& target : required_targets) {
    hasher.UpdateLengthPrefixed(target.str());
  }
  return hasher.Final();
}

Status ObservatoryPolicy::Validate(const RuntimeLimits& limits) const {
  if (id.empty() || !IsValidIdentityText(id.str())) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "policy identity is invalid");
  }
  if (format_version != kPolicyFormatVersion) {
    return Status::Rejected(ReasonCode::LedgerSchemaUnsupported,
                            "policy format version is not supported");
  }
  if (freshness.ttl_nanos <= 0) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "freshness ttl must be positive");
  }
  if (freshness.aging_threshold_percent < 0 || freshness.aging_threshold_percent > 100) {
    return Status::Rejected(ReasonCode::EncodingMalformed,
                            "aging threshold percent must be within 0..100");
  }
  if (freshness.max_clock_skew_nanos < 0) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "clock skew tolerance must not be negative");
  }
  if (resolution_confirmations == 0) {
    return Status::Rejected(ReasonCode::EncodingMalformed,
                            "resolution confirmations must be at least one");
  }
  if (severity_rules.size() > kMaxPolicyRules || freshness_rules.size() > kMaxPolicyRules ||
      field_class_rules.size() > kMaxPolicyRules) {
    return Status::Limit(ReasonCode::LimitFieldsExceeded, "policy rule count exceeds the envelope");
  }
  if (suppressions.size() > limits.max_suppressions) {
    return Status::Limit(ReasonCode::LimitFieldsExceeded, "policy suppression count exceeds the envelope");
  }
  if (source_priority.size() > limits.max_sources) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded, "policy source order exceeds the envelope");
  }
  if (required_targets.size() > limits.max_targets) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded, "policy target list exceeds the envelope");
  }
  for (const SeverityRule& rule : severity_rules) {
    if (rule.selector.path_prefix.has_value() &&
        rule.selector.path_prefix->size() > limits.max_path_segments) {
      return Status::Limit(ReasonCode::LimitDepthExceeded, "policy path prefix is too deep");
    }
  }
  for (const FreshnessRule& rule : freshness_rules) {
    if (rule.ttl_nanos <= 0) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "freshness rule ttl must be positive");
    }
  }
  for (const SuppressionRule& rule : suppressions) {
    if (rule.id.empty()) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "suppression identity is invalid");
    }
    if (rule.author.empty()) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "suppression author is invalid");
    }
  }
  for (const SourceId& source : source_priority) {
    if (source.empty() || !IsValidIdentityText(source.str())) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "source priority identity is invalid");
    }
  }
  for (const TargetId& target : required_targets) {
    if (target.empty() || !IsValidIdentityText(target.str())) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "required target identity is invalid");
    }
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

std::int64_t ObservatoryPolicy::TtlFor(const TargetId& target, const ObjectId& object,
                                       const FieldPath& path) const noexcept {
  std::int64_t ttl = freshness.ttl_nanos;
  int best = -1;
  for (const FreshnessRule& rule : freshness_rules) {
    if (!rule.selector.Matches(target, object, path)) {
      continue;
    }
    const int specificity = SelectorSpecificity(rule.selector);
    if (specificity >= best) {
      best = specificity;
      ttl = rule.ttl_nanos;
    }
  }
  return ttl;
}

Severity ObservatoryPolicy::SeverityFor(const TargetId& target, const ObjectId& object,
                                        const FieldPath& path, DriftClass klass) const noexcept {
  Severity severity = default_severity;
  int best = -1;
  for (const SeverityRule& rule : severity_rules) {
    if (!rule.selector.Matches(target, object, path)) {
      continue;
    }
    if (rule.klass.has_value() && !(*rule.klass == klass)) {
      continue;
    }
    if (rule.min_severity.has_value() && SeverityRank(severity) < SeverityRank(*rule.min_severity)) {
      continue;
    }
    int specificity = SelectorSpecificity(rule.selector) * 4;
    if (rule.klass.has_value()) {
      specificity += 1;
    }
    if (rule.min_severity.has_value()) {
      specificity += 1;
    }
    if (specificity >= best) {
      best = specificity;
      severity = rule.severity;
    }
  }
  return severity;
}

FieldComparability ObservatoryPolicy::ClassifyField(const TargetId& target, const ObjectId& object,
                                                    const FieldPath& path,
                                                    FieldComparability intent_view) const noexcept {
  std::uint8_t rank = ComparabilityRank(intent_view);
  for (const FieldClassRule& rule : field_class_rules) {
    if (!rule.selector.Matches(target, object, path)) {
      continue;
    }
    // Policy narrows comparison only: a rule can never turn an unmanaged field
    // back into a managed one.
    rank = std::max(rank, ComparabilityRank(rule.comparability));
  }
  return static_cast<FieldComparability>(rank);
}

const SuppressionRule* ObservatoryPolicy::FindSuppression(const TargetId& target,
                                                          const ObjectId& object,
                                                          const FieldPath& path, DriftClass klass,
                                                          Severity severity,
                                                          NdoTime now) const noexcept {
  for (const SuppressionRule& rule : suppressions) {
    if (rule.is_expired_at(now)) {
      continue;
    }
    if (!rule.selector.Matches(target, object, path)) {
      continue;
    }
    if (rule.klass.has_value() && !(*rule.klass == klass)) {
      continue;
    }
    if (rule.min_severity.has_value() && SeverityRank(severity) < SeverityRank(*rule.min_severity)) {
      continue;
    }
    return &rule;
  }
  return nullptr;
}

ObservatoryPolicy ObservatoryPolicy::Default() {
  ObservatoryPolicy policy;
  policy.id = PolicyId::Trusted("policy/default");
  policy.format_version = kPolicyFormatVersion;
  return policy;
}

Value EncodePolicy(const ObservatoryPolicy& policy) {
  Value::Map root;
  root.emplace("schema", Value::MakeString("ndo/policy/1"));
  root.emplace("id", Value::MakeString(policy.id.str()));
  root.emplace("format_version", Value::MakeUint(policy.format_version));
  {
    Value::Map freshness;
    freshness.emplace("ttl_nanos", Value::MakeInt(policy.freshness.ttl_nanos));
    freshness.emplace("aging_threshold_percent",
                      Value::MakeInt(policy.freshness.aging_threshold_percent));
    freshness.emplace("max_clock_skew_nanos",
                      Value::MakeInt(policy.freshness.max_clock_skew_nanos));
    freshness.emplace("ttl_applies_to_receive_time",
                      Value::MakeBool(policy.freshness.ttl_applies_to_receive_time));
    root.emplace("freshness", Value::MakeMap(std::move(freshness)));
  }
  root.emplace("resolution_confirmations", Value::MakeUint(policy.resolution_confirmations));
  root.emplace("require_complete_coverage_for_compliance",
               Value::MakeBool(policy.require_complete_coverage_for_compliance));
  root.emplace("require_absence_authority", Value::MakeBool(policy.require_absence_authority));
  root.emplace("numeric_equivalence",
               Value::MakeString(policy.numeric_equivalence == NumericEquivalence::Exact ? "exact"
                                                                                        : "numeric"));
  root.emplace("default_severity", Value::MakeString(ToText(policy.default_severity)));
  root.emplace("evidence", Value::MakeString(ToText(policy.evidence)));
  {
    Value::List rules;
    for (const SeverityRule& rule : policy.severity_rules) {
      Value::Map entry = EncodeSelector(rule.selector);
      if (rule.klass.has_value()) {
        entry.emplace("class", Value::MakeString(std::string(ToText(*rule.klass))));
      }
      if (rule.min_severity.has_value()) {
        entry.emplace("min_severity", Value::MakeString(ToText(*rule.min_severity)));
      }
      entry.emplace("severity", Value::MakeString(ToText(rule.severity)));
      rules.push_back(Value::MakeMap(std::move(entry)));
    }
    root.emplace("severity_rules", Value::MakeList(std::move(rules)));
  }
  {
    Value::List rules;
    for (const FreshnessRule& rule : policy.freshness_rules) {
      Value::Map entry = EncodeSelector(rule.selector);
      entry.emplace("ttl_nanos", Value::MakeInt(rule.ttl_nanos));
      rules.push_back(Value::MakeMap(std::move(entry)));
    }
    root.emplace("freshness_rules", Value::MakeList(std::move(rules)));
  }
  {
    Value::List rules;
    for (const FieldClassRule& rule : policy.field_class_rules) {
      Value::Map entry = EncodeSelector(rule.selector);
      entry.emplace("comparability", Value::MakeString(ToText(rule.comparability)));
      rules.push_back(Value::MakeMap(std::move(entry)));
    }
    root.emplace("field_class_rules", Value::MakeList(std::move(rules)));
  }
  {
    Value::List rules;
    for (const SuppressionRule& rule : policy.suppressions) {
      Value::Map entry = EncodeSelector(rule.selector);
      entry.emplace("id", Value::MakeString(rule.id.str()));
      if (rule.klass.has_value()) {
        entry.emplace("class", Value::MakeString(std::string(ToText(*rule.klass))));
      }
      if (rule.min_severity.has_value()) {
        entry.emplace("min_severity", Value::MakeString(ToText(*rule.min_severity)));
      }
      entry.emplace("author", Value::MakeString(rule.author.str()));
      entry.emplace("reason", Value::MakeString(rule.reason));
      entry.emplace("created_at", Value::MakeString(FormatTime(rule.created_at)));
      if (rule.expires_at.has_value()) {
        entry.emplace("expires_at", Value::MakeString(FormatTime(*rule.expires_at)));
      }
      rules.push_back(Value::MakeMap(std::move(entry)));
    }
    root.emplace("suppressions", Value::MakeList(std::move(rules)));
  }
  {
    Value::List sources;
    for (const SourceId& source : policy.source_priority) {
      sources.push_back(Value::MakeString(source.str()));
    }
    root.emplace("source_priority", Value::MakeList(std::move(sources)));
  }
  {
    Value::List targets;
    for (const TargetId& target : policy.required_targets) {
      targets.push_back(Value::MakeString(target.str()));
    }
    root.emplace("required_targets", Value::MakeList(std::move(targets)));
  }
  return Value::MakeMap(std::move(root));
}

Status DecodePolicy(const Value& value, const RuntimeLimits& limits, ObservatoryPolicy& out) {
  const Value::Map* root = nullptr;
  Status status = detail::RequireObject(value, "policy", root);
  if (!status.ok()) {
    return status;
  }
  status = detail::CheckMembers(*root,
                                {"schema", "id", "format_version", "freshness",
                                 "resolution_confirmations", "require_complete_coverage_for_compliance",
                                 "require_absence_authority", "numeric_equivalence", "default_severity",
                                 "evidence", "severity_rules", "freshness_rules", "field_class_rules",
                                 "suppressions", "source_priority", "required_targets"},
                                "policy");
  if (!status.ok()) {
    return status;
  }
  status = detail::CheckMemberKinds(
      *root,
      {{"id", detail::MemberKind::Text},
       {"format_version", detail::MemberKind::Integer},
       {"resolution_confirmations", detail::MemberKind::Integer},
       {"require_complete_coverage_for_compliance", detail::MemberKind::Boolean},
       {"require_absence_authority", detail::MemberKind::Boolean},
       {"numeric_equivalence", detail::MemberKind::Text},
       {"default_severity", detail::MemberKind::Text},
       {"evidence", detail::MemberKind::Text},
       {"severity_rules", detail::MemberKind::Sequence},
       {"freshness_rules", detail::MemberKind::Sequence},
       {"field_class_rules", detail::MemberKind::Sequence},
       {"suppressions", detail::MemberKind::Sequence},
       {"source_priority", detail::MemberKind::Sequence},
       {"required_targets", detail::MemberKind::Sequence}},
      "policy");
  if (!status.ok()) {
    return status;
  }
  ObservatoryPolicy policy;
  std::string text;
  status = detail::RequireString(*root, "id", "policy", text);
  if (!status.ok()) {
    return status;
  }
  const auto id = PolicyId::TryParse(text);
  if (!id.has_value()) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "policy: id is not a valid identity");
  }
  policy.id = *id;
  std::uint64_t version = 0;
  status = detail::RequireUint(*root, "format_version", "policy", version);
  if (!status.ok()) {
    return status;
  }
  if (version > 0xFFFFu) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "policy: format version is out of range");
  }
  policy.format_version = static_cast<std::uint16_t>(version);
  if (policy.format_version != kPolicyFormatVersion) {
    return Status::Rejected(ReasonCode::LedgerSchemaUnsupported,
                            "policy: format version is not supported");
  }
  const Value::Map* freshness = nullptr;
  status = detail::RequireMap(*root, "freshness", "policy", freshness);
  if (!status.ok()) {
    return status;
  }
  status = detail::CheckMembers(*freshness,
                                {"ttl_nanos", "aging_threshold_percent", "max_clock_skew_nanos",
                                 "ttl_applies_to_receive_time"},
                                "policy.freshness");
  if (!status.ok()) {
    return status;
  }
  status = detail::CheckMemberKinds(*freshness,
                                    {{"ttl_nanos", detail::MemberKind::Integer},
                                     {"aging_threshold_percent", detail::MemberKind::Integer},
                                     {"max_clock_skew_nanos", detail::MemberKind::Integer},
                                     {"ttl_applies_to_receive_time", detail::MemberKind::Boolean}},
                                    "policy.freshness");
  if (!status.ok()) {
    return status;
  }
  const std::optional<std::int64_t> ttl = detail::OptionalInt(*freshness, "ttl_nanos");
  if (!ttl.has_value()) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "policy.freshness: ttl_nanos is required");
  }
  policy.freshness.ttl_nanos = *ttl;
  const std::optional<std::int64_t> aging =
      detail::OptionalInt(*freshness, "aging_threshold_percent");
  if (aging.has_value()) {
    if (*aging < 0 || *aging > 100) {
      return Status::Rejected(ReasonCode::EncodingMalformed,
                              "policy.freshness: aging_threshold_percent is out of range");
    }
    policy.freshness.aging_threshold_percent = static_cast<std::int32_t>(*aging);
  }
  const std::optional<std::int64_t> skew = detail::OptionalInt(*freshness, "max_clock_skew_nanos");
  if (skew.has_value()) {
    policy.freshness.max_clock_skew_nanos = *skew;
  }
  const std::optional<bool> receive_ttl =
      detail::OptionalBool(*freshness, "ttl_applies_to_receive_time");
  if (receive_ttl.has_value()) {
    policy.freshness.ttl_applies_to_receive_time = *receive_ttl;
  }
  const std::optional<std::uint64_t> confirmations =
      detail::OptionalUint(*root, "resolution_confirmations");
  if (confirmations.has_value()) {
    if (*confirmations == 0 || *confirmations > 0xFFFFFFFFULL) {
      return Status::Rejected(ReasonCode::EncodingMalformed,
                              "policy: resolution_confirmations is out of range");
    }
    policy.resolution_confirmations = static_cast<std::uint32_t>(*confirmations);
  }
  const std::optional<bool> coverage =
      detail::OptionalBool(*root, "require_complete_coverage_for_compliance");
  if (coverage.has_value()) {
    policy.require_complete_coverage_for_compliance = *coverage;
  }
  const std::optional<bool> absence = detail::OptionalBool(*root, "require_absence_authority");
  if (absence.has_value()) {
    policy.require_absence_authority = *absence;
  }
  const std::optional<std::string> equivalence = detail::OptionalString(*root, "numeric_equivalence");
  if (equivalence.has_value()) {
    if (*equivalence == "exact") {
      policy.numeric_equivalence = NumericEquivalence::Exact;
    } else if (*equivalence == "numeric") {
      policy.numeric_equivalence = NumericEquivalence::Numeric;
    } else {
      return Status::Rejected(ReasonCode::EncodingMalformed,
                              "policy: numeric_equivalence is not recognized");
    }
  }
  const std::optional<std::string> severity_text = detail::OptionalString(*root, "default_severity");
  if (severity_text.has_value()) {
    Severity severity = Severity::Medium;
    if (!TryParseSeverity(severity_text->c_str(), severity)) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "policy: default_severity is not recognized");
    }
    policy.default_severity = severity;
  }
  const std::optional<std::string> evidence_text = detail::OptionalString(*root, "evidence");
  if (evidence_text.has_value()) {
    EvidenceClass evidence = EvidenceClass::Unknown;
    if (!TryParseEvidenceClass(evidence_text->c_str(), evidence)) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "policy: evidence is not recognized");
    }
    policy.evidence = evidence;
  }
  if (const Value* rules = detail::FindMember(*root, "severity_rules"); rules != nullptr) {
    const Value::List* list = rules->as_list();
    if (list == nullptr) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "policy: severity_rules must be a sequence");
    }
    if (list->size() > kMaxPolicyRules) {
      return Status::Limit(ReasonCode::LimitFieldsExceeded, "policy: severity_rules exceeds the envelope");
    }
    for (const Value& entry : *list) {
      const Value::Map* map = entry.as_map();
      if (map == nullptr) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: severity rule must be an object");
      }
      status = detail::CheckMembers(*map,
                                    {"target", "object", "path_prefix", "class", "min_severity",
                                     "severity"},
                                    "policy.severity_rule");
      if (!status.ok()) {
        return status;
      }
      status = detail::CheckMemberKinds(*map,
                                        {{"class", detail::MemberKind::Text},
                                         {"min_severity", detail::MemberKind::Text},
                                         {"severity", detail::MemberKind::Text}},
                                        "policy.severity_rule");
      if (!status.ok()) {
        return status;
      }
      SeverityRule rule;
      status = DecodeSelector(*map, limits, "policy.severity_rule", rule.selector);
      if (!status.ok()) {
        return status;
      }
      if (const std::optional<std::string> klass = detail::OptionalString(*map, "class");
          klass.has_value()) {
        DriftClass parsed = DriftClass::None;
        if (!TryParseDriftClass(klass->c_str(), parsed)) {
          return Status::Rejected(ReasonCode::EncodingMalformed, "policy: severity rule class is unknown");
        }
        rule.klass = parsed;
      }
      if (const std::optional<std::string> minimum = detail::OptionalString(*map, "min_severity");
          minimum.has_value()) {
        Severity parsed = Severity::Medium;
        if (!TryParseSeverity(minimum->c_str(), parsed)) {
          return Status::Rejected(ReasonCode::EncodingMalformed,
                                  "policy: severity rule min_severity is unknown");
        }
        rule.min_severity = parsed;
      }
      if (const std::optional<std::string> severity = detail::OptionalString(*map, "severity");
          severity.has_value()) {
        Severity parsed = Severity::Medium;
        if (!TryParseSeverity(severity->c_str(), parsed)) {
          return Status::Rejected(ReasonCode::EncodingMalformed, "policy: severity is unknown");
        }
        rule.severity = parsed;
      }
      policy.severity_rules.push_back(std::move(rule));
    }
  }
  if (const Value* rules = detail::FindMember(*root, "freshness_rules"); rules != nullptr) {
    const Value::List* list = rules->as_list();
    if (list == nullptr) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "policy: freshness_rules must be a sequence");
    }
    if (list->size() > kMaxPolicyRules) {
      return Status::Limit(ReasonCode::LimitFieldsExceeded, "policy: freshness_rules exceeds the envelope");
    }
    for (const Value& entry : *list) {
      const Value::Map* map = entry.as_map();
      if (map == nullptr) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: freshness rule must be an object");
      }
      status = detail::CheckMembers(*map, {"target", "object", "path_prefix", "ttl_nanos"},
                                    "policy.freshness_rule");
      if (!status.ok()) {
        return status;
      }
      status = detail::CheckMemberKinds(*map, {{"ttl_nanos", detail::MemberKind::Integer}},
                                        "policy.freshness_rule");
      if (!status.ok()) {
        return status;
      }
      FreshnessRule rule;
      status = DecodeSelector(*map, limits, "policy.freshness_rule", rule.selector);
      if (!status.ok()) {
        return status;
      }
      const std::optional<std::int64_t> rule_ttl = detail::OptionalInt(*map, "ttl_nanos");
      if (!rule_ttl.has_value() || *rule_ttl <= 0) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: freshness rule ttl is required");
      }
      rule.ttl_nanos = *rule_ttl;
      policy.freshness_rules.push_back(std::move(rule));
    }
  }
  if (const Value* rules = detail::FindMember(*root, "field_class_rules"); rules != nullptr) {
    const Value::List* list = rules->as_list();
    if (list == nullptr) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "policy: field_class_rules must be a sequence");
    }
    if (list->size() > kMaxPolicyRules) {
      return Status::Limit(ReasonCode::LimitFieldsExceeded, "policy: field_class_rules exceeds the envelope");
    }
    for (const Value& entry : *list) {
      const Value::Map* map = entry.as_map();
      if (map == nullptr) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: field class rule must be an object");
      }
      status = detail::CheckMembers(*map, {"target", "object", "path_prefix", "comparability"},
                                    "policy.field_class_rule");
      if (!status.ok()) {
        return status;
      }
      status = detail::CheckMemberKinds(*map, {{"comparability", detail::MemberKind::Text}},
                                        "policy.field_class_rule");
      if (!status.ok()) {
        return status;
      }
      FieldClassRule rule;
      status = DecodeSelector(*map, limits, "policy.field_class_rule", rule.selector);
      if (!status.ok()) {
        return status;
      }
      const std::optional<std::string> comparability = detail::OptionalString(*map, "comparability");
      if (!comparability.has_value()) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: comparability is required");
      }
      FieldComparability parsed = FieldComparability::Managed;
      if (!TryParseFieldComparability(comparability->c_str(), parsed)) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: comparability is unknown");
      }
      rule.comparability = parsed;
      policy.field_class_rules.push_back(std::move(rule));
    }
  }
  if (const Value* rules = detail::FindMember(*root, "suppressions"); rules != nullptr) {
    const Value::List* list = rules->as_list();
    if (list == nullptr) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "policy: suppressions must be a sequence");
    }
    if (list->size() > limits.max_suppressions) {
      return Status::Limit(ReasonCode::LimitFieldsExceeded, "policy: suppressions exceeds the envelope");
    }
    for (const Value& entry : *list) {
      const Value::Map* map = entry.as_map();
      if (map == nullptr) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: suppression must be an object");
      }
      status = detail::CheckMembers(*map,
                                    {"id", "target", "object", "path_prefix", "class", "min_severity",
                                     "author", "reason", "created_at", "expires_at"},
                                    "policy.suppression");
      if (!status.ok()) {
        return status;
      }
      status = detail::CheckMemberKinds(*map,
                                        {{"id", detail::MemberKind::Text},
                                         {"class", detail::MemberKind::Text},
                                         {"min_severity", detail::MemberKind::Text},
                                         {"author", detail::MemberKind::Text},
                                         {"reason", detail::MemberKind::Text},
                                         {"created_at", detail::MemberKind::Text},
                                         {"expires_at", detail::MemberKind::Text}},
                                        "policy.suppression");
      if (!status.ok()) {
        return status;
      }
      SuppressionRule rule;
      status = DecodeSelector(*map, limits, "policy.suppression", rule.selector);
      if (!status.ok()) {
        return status;
      }
      std::string id_text;
      status = detail::RequireString(*map, "id", "policy.suppression", id_text);
      if (!status.ok()) {
        return status;
      }
      const auto suppression_id = SuppressionId::TryParse(id_text);
      if (!suppression_id.has_value()) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: suppression id is invalid");
      }
      rule.id = *suppression_id;
      std::string author_text;
      status = detail::RequireString(*map, "author", "policy.suppression", author_text);
      if (!status.ok()) {
        return status;
      }
      const auto author = ActorId::TryParse(author_text);
      if (!author.has_value()) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: suppression author is invalid");
      }
      rule.author = *author;
      std::string reason;
      status = detail::RequireString(*map, "reason", "policy.suppression", reason);
      if (!status.ok()) {
        return status;
      }
      rule.reason = std::move(reason);
      std::string created;
      status = detail::RequireString(*map, "created_at", "policy.suppression", created);
      if (!status.ok()) {
        return status;
      }
      if (!TryParseTime(created, rule.created_at)) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: suppression created_at is invalid");
      }
      if (const std::optional<std::string> expires = detail::OptionalString(*map, "expires_at");
          expires.has_value()) {
        NdoTime parsed;
        if (!TryParseTime(*expires, parsed)) {
          return Status::Rejected(ReasonCode::EncodingMalformed, "policy: suppression expires_at is invalid");
        }
        rule.expires_at = parsed;
      }
      if (const std::optional<std::string> klass = detail::OptionalString(*map, "class");
          klass.has_value()) {
        DriftClass parsed = DriftClass::None;
        if (!TryParseDriftClass(klass->c_str(), parsed)) {
          return Status::Rejected(ReasonCode::EncodingMalformed, "policy: suppression class is unknown");
        }
        rule.klass = parsed;
      }
      if (const std::optional<std::string> minimum = detail::OptionalString(*map, "min_severity");
          minimum.has_value()) {
        Severity parsed = Severity::Medium;
        if (!TryParseSeverity(minimum->c_str(), parsed)) {
          return Status::Rejected(ReasonCode::EncodingMalformed, "policy: suppression min_severity is unknown");
        }
        rule.min_severity = parsed;
      }
      policy.suppressions.push_back(std::move(rule));
    }
  }
  if (const Value* sources = detail::FindMember(*root, "source_priority"); sources != nullptr) {
    const Value::List* list = sources->as_list();
    if (list == nullptr) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "policy: source_priority must be a sequence");
    }
    for (const Value& entry : *list) {
      const std::string* text_value = entry.as_string();
      if (text_value == nullptr) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: source identity must be a string");
      }
      const auto source = SourceId::TryParse(*text_value);
      if (!source.has_value()) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: source identity is invalid");
      }
      policy.source_priority.push_back(*source);
    }
  }
  if (const Value* targets = detail::FindMember(*root, "required_targets"); targets != nullptr) {
    const Value::List* list = targets->as_list();
    if (list == nullptr) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "policy: required_targets must be a sequence");
    }
    for (const Value& entry : *list) {
      const std::string* text_value = entry.as_string();
      if (text_value == nullptr) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: target identity must be a string");
      }
      const auto target = TargetId::TryParse(*text_value);
      if (!target.has_value()) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "policy: target identity is invalid");
      }
      policy.required_targets.push_back(*target);
    }
  }
  status = policy.Validate(limits);
  if (!status.ok()) {
    return status;
  }
  out = std::move(policy);
  return Status(StatusCode::Ok, ReasonCode::None);
}

}  // namespace network_drift_observatory
}  // namespace summon
