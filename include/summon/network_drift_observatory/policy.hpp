// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Observatory policy.
//
// Policy is data, not code: freshness lifetimes, severity assignment, field
// classification and suppressions are all declared in one versioned document.
// The policy digest travels with every finding and every report, so a reader
// can always tell which policy produced a decision.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_POLICY_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_POLICY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "summon/network_drift_observatory/drift.hpp"
#include "summon/network_drift_observatory/freshness.hpp"
#include "summon/network_drift_observatory/hash.hpp"
#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/intent.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/time.hpp"
#include "summon/network_drift_observatory/value.hpp"

namespace summon {
namespace network_drift_observatory {

/// A selector for a target, object and/or field path prefix. An unset member
/// matches everything; a set member must match exactly (paths by prefix).
struct NDO_API PolicySelector {
  std::optional<TargetId> target;
  std::optional<ObjectId> object;
  std::optional<FieldPath> path_prefix;

  /// True when this selector matches the described location.
  NDO_NODISCARD bool Matches(const TargetId& target_id, const ObjectId& object_id,
                             const FieldPath& path) const noexcept;
  /// True when this selector is no broader than the other one.
  NDO_NODISCARD bool IsSubsetOf(const PolicySelector& other) const noexcept;
  friend bool operator==(const PolicySelector&, const PolicySelector&) = default;
};

/// Deterministic severity assignment.
struct NDO_API SeverityRule {
  PolicySelector selector;
  /// Restrict the rule to one drift class. Unset applies to every class.
  std::optional<DriftClass> klass;
  /// Restrict the rule to findings at or above this severity. Unset means all.
  std::optional<Severity> min_severity;
  Severity severity{Severity::Medium};
  /// Later rules win; a rule with greater specificity is evaluated after a
  /// broader one regardless of declaration order.
  friend bool operator==(const SeverityRule&, const SeverityRule&) = default;
};

/// A per-target freshness override.
struct NDO_API FreshnessRule {
  PolicySelector selector;
  std::int64_t ttl_nanos{0};
  friend bool operator==(const FreshnessRule&, const FreshnessRule&) = default;
};

/// Policy-driven classification of a field, applied on top of the intent's own
/// comparability. Policy can only narrow comparison, never widen it.
struct NDO_API FieldClassRule {
  PolicySelector selector;
  FieldComparability comparability{FieldComparability::Managed};
  friend bool operator==(const FieldClassRule&, const FieldClassRule&) = default;
};

/// A suppression never erases evidence. It marks a finding as suppressed for
/// reporting and for reconciliation export, while the finding, its history and
/// its compliance truth remain exactly as they were.
struct NDO_API SuppressionRule {
  SuppressionId id;
  PolicySelector selector;
  std::optional<DriftClass> klass;
  std::optional<Severity> min_severity;
  ActorId author;
  std::string reason;
  NdoTime created_at;
  std::optional<NdoTime> expires_at;

  NDO_NODISCARD bool is_expired_at(NdoTime now) const noexcept;
  friend bool operator==(const SuppressionRule&, const SuppressionRule&) = default;
};

/// The complete observatory policy.
struct NDO_API ObservatoryPolicy {
  PolicyId id;
  std::uint16_t format_version{1};
  FreshnessPolicy freshness;
  /// How many consecutive fresh observations must agree before an open finding
  /// is resolved. One is the default: one authoritative fresh observation.
  std::uint32_t resolution_confirmations{1};
  /// When true, a compliance conclusion requires a source that declares
  /// complete coverage of the target.
  bool require_complete_coverage_for_compliance{true};
  /// When true, an "object absent" conclusion requires a source whose
  /// capabilities include asserting absence.
  bool require_absence_authority{true};
  /// How two numeric kinds are compared.
  NumericEquivalence numeric_equivalence{NumericEquivalence::Numeric};
  /// Severity assigned when no rule matches.
  Severity default_severity{Severity::Medium};
  std::vector<SeverityRule> severity_rules;
  std::vector<FreshnessRule> freshness_rules;
  std::vector<FieldClassRule> field_class_rules;
  std::vector<SuppressionRule> suppressions;
  /// Source authority order. A source listed earlier is preferred when several
  /// fresh sources cover the same target. Unlisted sources sort after listed
  /// ones, by identity, so the choice is total and deterministic.
  std::vector<SourceId> source_priority;
  /// Targets that must have intent. A target in this list without a committed
  /// baseline produces an IntentMissing finding instead of silence.
  std::vector<TargetId> required_targets;
  EvidenceClass evidence{EvidenceClass::Unknown};

  /// Digest over the canonical content of the policy. Stable across runs.
  NDO_NODISCARD Digest ComputeDigest() const;
  NDO_NODISCARD Status Validate(const RuntimeLimits& limits) const;

  NDO_NODISCARD std::int64_t TtlFor(const TargetId& target, const ObjectId& object,
                                    const FieldPath& path) const noexcept;
  NDO_NODISCARD Severity SeverityFor(const TargetId& target, const ObjectId& object,
                                     const FieldPath& path, DriftClass klass) const noexcept;
  NDO_NODISCARD FieldComparability ClassifyField(const TargetId& target, const ObjectId& object,
                                                 const FieldPath& path,
                                                 FieldComparability intent_view) const noexcept;
  /// The first suppression that applies, or nullopt. Deterministic: rules are
  /// consulted in declaration order and the first match wins.
  NDO_NODISCARD const SuppressionRule* FindSuppression(const TargetId& target,
                                                       const ObjectId& object,
                                                       const FieldPath& path, DriftClass klass,
                                                       Severity severity,
                                                       NdoTime now) const noexcept;
  /// The default policy: conservative freshness, no suppressions.
  NDO_NODISCARD static ObservatoryPolicy Default();
};

/// Serializes a policy to the canonical JSON interchange form.
NDO_NODISCARD NDO_API Value EncodePolicy(const ObservatoryPolicy& policy);
/// Parses a policy from the canonical JSON interchange form. Any unknown or
/// malformed member is a refusal, never a default.
NDO_NODISCARD NDO_API Status DecodePolicy(const Value& value, const RuntimeLimits& limits,
                                          ObservatoryPolicy& out);

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_POLICY_HPP
