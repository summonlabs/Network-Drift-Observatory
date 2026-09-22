// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Intent generations and observatory policy.

#include <string>

#include "test_framework.hpp"
#include "test_support.hpp"

using namespace ndotest;

NDO_TEST(IntentCommitLifecycle) {
  ndo::FindingLedger ledger;
  ndo::IntentCommitReport report;

  ndo::IntentGenerationDocument first = MakeIntent("switch/1", 1);
  AddIntentObject(first, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  NDO_CHECK_STATUS(ledger.CommitIntent(first, FixedTime(100), report));
  NDO_CHECK_EQ(report.committed_generation.value(), std::uint64_t{1});
  NDO_CHECK(!report.duplicate_identical);
  const ndo::IntentBaseline* baseline = ledger.FindBaseline(Target("switch/1"));
  NDO_CHECK(baseline != nullptr);
  if (baseline != nullptr) {
    NDO_CHECK_EQ(baseline->generation.value(), std::uint64_t{1});
    NDO_CHECK(baseline->FindObject(Object("port/eth0")) != nullptr);
  }

  // Re-publishing the identical generation is accepted and changes nothing.
  NDO_CHECK_STATUS(ledger.CommitIntent(first, FixedTime(110), report));
  NDO_CHECK(report.duplicate_identical);
  NDO_CHECK_EQ(ledger.FindBaseline(Target("switch/1"))->generation.value(), std::uint64_t{1});

  // The same generation with different content is a conflict.
  ndo::IntentGenerationDocument divergent = first;
  AddIntentObject(divergent, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  NDO_CHECK_REFUSED(ledger.CommitIntent(divergent, FixedTime(120), report),
                    ndo::ReasonCode::IntentGenerationConflicting);

  // A regression is refused: the baseline has moved past this generation.
  ndo::IntentGenerationDocument newer = MakeIntent("switch/1", 2);
  NDO_CHECK_STATUS(ledger.CommitIntent(newer, FixedTime(125), report));
  NDO_CHECK_REFUSED(ledger.CommitIntent(first, FixedTime(130), report),
                    ndo::ReasonCode::IntentGenerationRegressed);

  // An older epoch is refused even when the generation is newer.
  ndo::IntentGenerationDocument stale_epoch = MakeIntent("switch/1", 5, 0);
  stale_epoch.epoch = ndo::FabricEpoch{};
  NDO_CHECK(!ledger.CommitIntent(stale_epoch, FixedTime(140), report).ok());

  // A newer generation is committed and the baseline advances.
  ndo::IntentGenerationDocument third = MakeIntent("switch/1", 3);
  AddIntentObject(third, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  NDO_CHECK_STATUS(ledger.CommitIntent(third, FixedTime(150), report));
  NDO_CHECK_EQ(report.previous_generation.value(), std::uint64_t{2});
  NDO_CHECK_EQ(report.committed_generation.value(), std::uint64_t{3});
  NDO_CHECK_EQ(ledger.FindBaseline(Target("switch/1"))->generation.value(), std::uint64_t{3});
}

NDO_TEST(IntentValidationRefusals) {
  ndo::RuntimeLimits limits;
  ndo::IntentGenerationDocument document = MakeIntent("switch/1", 1);
  NDO_CHECK(document.Validate(limits).ok());

  ndo::IntentGenerationDocument no_epoch = document;
  no_epoch.epoch = ndo::FabricEpoch{};
  NDO_CHECK_REFUSED(no_epoch.Validate(limits), ndo::ReasonCode::FencedStaleEpoch);

  ndo::IntentGenerationDocument no_generation = document;
  no_generation.generation = ndo::IntentGeneration{};
  NDO_CHECK_REFUSED(no_generation.Validate(limits), ndo::ReasonCode::IntentTargetUndeclared);

  ndo::IntentGenerationDocument no_authority = document;
  no_authority.authority = ndo::IntentAuthority::Unknown;
  NDO_CHECK_REFUSED(no_authority.Validate(limits), ndo::ReasonCode::AuthorityMismatch);

  ndo::IntentGenerationDocument no_policy = document;
  no_policy.policy = ndo::PolicyId{};
  NDO_CHECK_REFUSED(no_policy.Validate(limits), ndo::ReasonCode::EncodingMalformed);

  ndo::RuntimeLimits tight;
  tight.max_fields_per_object = 1;
  ndo::IntentGenerationDocument wide = MakeIntent("switch/1", 1);
  AddIntentObject(wide, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(wide, "port/eth0", "admin-up", ndo::Value::MakeBool(true));
  NDO_CHECK_REFUSED(wide.Validate(tight), ndo::ReasonCode::LimitFieldsExceeded);

  ndo::RuntimeLimits small;
  small.max_value_depth = 1;
  ndo::IntentGenerationDocument deep = MakeIntent("switch/1", 1);
  AddIntentObject(deep, "port/eth0", "acl",
                  ndo::Value::MakeMap({{"inner", ndo::Value::MakeMap({{"leaf", ndo::Value::MakeInt(1)}})}}));
  NDO_CHECK_REFUSED(deep.Validate(small), ndo::ReasonCode::LimitDepthExceeded);
}

NDO_TEST(IntentDocumentJsonRoundTrip) {
  ndo::IntentGenerationDocument document = MakeIntent("switch/1", 7);
  AddIntentObject(document, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(document, "port/eth0", "acl.rules[0].action", ndo::Value::MakeString("permit"));
  AddIntentObject(document, "port/eth1", "enabled", ndo::Value::MakeBool(false));

  const ndo::Value encoded = ndo::EncodeIntentDocument(document);
  const std::string text = ndo::WriteCanonicalJson(encoded);
  ndo::IntentGenerationDocument decoded;
  NDO_CHECK_STATUS(ndo::ParseIntentJson(text, ndo::RuntimeLimits{}, decoded));
  NDO_CHECK(decoded.target == document.target);
  NDO_CHECK(decoded.generation == document.generation);
  NDO_CHECK(decoded.epoch == document.epoch);
  NDO_CHECK(decoded.authority == document.authority);
  NDO_CHECK_EQ(decoded.objects.size(), document.objects.size());
  NDO_CHECK(decoded.ComputeContentDigest() == document.ComputeContentDigest());

  // An unknown member is refused rather than ignored.
  ndo::Value::Map mutated = *encoded.as_map();
  mutated.emplace("surprise", ndo::Value::MakeInt(1));
  NDO_CHECK(ndo::DecodeIntentDocument(ndo::Value::MakeMap(mutated), ndo::RuntimeLimits{}, decoded)
                .reason == ndo::ReasonCode::EncodingMalformed);

  // A missing required member is refused.
  ndo::Value::Map missing = *encoded.as_map();
  missing.erase("target");
  NDO_CHECK(!ndo::DecodeIntentDocument(ndo::Value::MakeMap(missing), ndo::RuntimeLimits{}, decoded)
                 .ok());
}

NDO_TEST(PolicyRoundTripAndDigest) {
  ndo::ObservatoryPolicy policy = SyntheticPolicy();
  policy.resolution_confirmations = 2;
  policy.source_priority.push_back(Source("collector/a"));
  policy.required_targets.push_back(Target("switch/1"));
  ndo::SeverityRule rule;
  rule.selector.target = Target("switch/1");
  rule.selector.path_prefix = Path("mtu");
  rule.klass = ndo::DriftClass::ValueMismatch;
  rule.severity = ndo::Severity::High;
  policy.severity_rules.push_back(rule);
  ndo::FreshnessRule freshness_rule;
  freshness_rule.selector.target = Target("switch/1");
  freshness_rule.ttl_nanos = 1000000000LL;
  policy.freshness_rules.push_back(freshness_rule);
  ndo::FieldClassRule class_rule;
  class_rule.selector.path_prefix = Path("counter");
  class_rule.comparability = ndo::FieldComparability::ObserveOnly;
  policy.field_class_rules.push_back(class_rule);
  ndo::SuppressionRule suppression;
  suppression.id = ndo::SuppressionId::Trusted("suppression/one");
  suppression.selector.target = Target("switch/1");
  suppression.author = ndo::ActorId::Trusted("operator/alice");
  suppression.reason = "planned maintenance";
  suppression.created_at = FixedTime(500);
  policy.suppressions.push_back(suppression);

  const ndo::Value encoded = ndo::EncodePolicy(policy);
  const ndo::Digest digest = policy.ComputeDigest();
  ndo::ObservatoryPolicy decoded;
  NDO_CHECK_STATUS(ndo::DecodePolicy(encoded, ndo::RuntimeLimits{}, decoded));
  NDO_CHECK(decoded.ComputeDigest() == digest);
  NDO_CHECK_EQ(decoded.resolution_confirmations, std::uint32_t{2});
  NDO_CHECK_EQ(decoded.source_priority.size(), std::size_t{1});
  NDO_CHECK_EQ(decoded.severity_rules.size(), std::size_t{1});
  NDO_CHECK_EQ(decoded.suppressions.size(), std::size_t{1});

  // Any semantic change changes the digest.
  ndo::ObservatoryPolicy changed = policy;
  changed.default_severity = ndo::Severity::Critical;
  NDO_CHECK(!(changed.ComputeDigest() == digest));
}

NDO_TEST(PolicyValidationAndDecodeRefusals) {
  ndo::RuntimeLimits limits;
  ndo::ObservatoryPolicy policy = SyntheticPolicy();
  NDO_CHECK(policy.Validate(limits).ok());

  ndo::ObservatoryPolicy zero_ttl = policy;
  zero_ttl.freshness.ttl_nanos = 0;
  NDO_CHECK_REFUSED(zero_ttl.Validate(limits), ndo::ReasonCode::EncodingMalformed);

  ndo::ObservatoryPolicy bad_aging = policy;
  bad_aging.freshness.aging_threshold_percent = 101;
  NDO_CHECK_REFUSED(bad_aging.Validate(limits), ndo::ReasonCode::EncodingMalformed);

  ndo::ObservatoryPolicy bad_version = policy;
  bad_version.format_version = 99;
  NDO_CHECK_REFUSED(bad_version.Validate(limits), ndo::ReasonCode::LedgerSchemaUnsupported);

  ndo::ObservatoryPolicy zero_confirmations = policy;
  zero_confirmations.resolution_confirmations = 0;
  NDO_CHECK_REFUSED(zero_confirmations.Validate(limits), ndo::ReasonCode::EncodingMalformed);

  const ndo::Value encoded = ndo::EncodePolicy(policy);
  ndo::ObservatoryPolicy decoded;
  ndo::Value::Map mutated = *encoded.as_map();
  mutated.emplace("unknown_member", ndo::Value::MakeBool(true));
  NDO_CHECK_REFUSED(ndo::DecodePolicy(ndo::Value::MakeMap(mutated), limits, decoded),
                    ndo::ReasonCode::EncodingMalformed);

  ndo::Value::Map wrong_kind = *encoded.as_map();
  wrong_kind["resolution_confirmations"] = ndo::Value::MakeString("two");
  NDO_CHECK(!ndo::DecodePolicy(ndo::Value::MakeMap(wrong_kind), limits, decoded).ok());

  ndo::Value::Map bad_class = *encoded.as_map();
  bad_class["default_severity"] = ndo::Value::MakeString("apocalyptic");
  NDO_CHECK(!ndo::DecodePolicy(ndo::Value::MakeMap(bad_class), limits, decoded).ok());

  ndo::Value::Map bad_freshness = *encoded.as_map();
  bad_freshness["freshness"] = ndo::Value::MakeMap({{"ttl_nanos", ndo::Value::MakeInt(-1)}});
  NDO_CHECK(!ndo::DecodePolicy(ndo::Value::MakeMap(bad_freshness), limits, decoded).ok());
}

NDO_TEST(PolicyRulesResolveDeterministically) {
  ndo::ObservatoryPolicy policy = SyntheticPolicy();
  ndo::SeverityRule broad;
  broad.severity = ndo::Severity::Low;
  policy.severity_rules.push_back(broad);
  ndo::SeverityRule specific;
  specific.selector.target = Target("switch/1");
  specific.selector.object = Object("port/eth0");
  specific.severity = ndo::Severity::Critical;
  policy.severity_rules.push_back(specific);
  // Declared before the specific rule but broader: specificity wins regardless
  // of declaration order.
  ndo::SeverityRule class_rule;
  class_rule.klass = ndo::DriftClass::SourceConflict;
  class_rule.severity = ndo::Severity::High;
  policy.severity_rules.insert(policy.severity_rules.begin(), class_rule);

  NDO_CHECK(policy.SeverityFor(Target("switch/1"), Object("port/eth0"), Path("mtu"),
                               ndo::DriftClass::ValueMismatch) == ndo::Severity::Critical);
  NDO_CHECK(policy.SeverityFor(Target("switch/2"), Object("port/eth0"), Path("mtu"),
                               ndo::DriftClass::ValueMismatch) == ndo::Severity::Low);
  // The class rule applies where no more specific rule matches.
  NDO_CHECK(policy.SeverityFor(Target("switch/1"), Object("port/eth1"), Path("mtu"),
                               ndo::DriftClass::SourceConflict) == ndo::Severity::High);

  // Freshness: a target rule overrides the default, and a more specific rule
  // wins over a broader one.
  ndo::FreshnessRule target_rule;
  target_rule.selector.target = Target("switch/1");
  target_rule.ttl_nanos = 7000000000LL;
  policy.freshness_rules.push_back(target_rule);
  ndo::FreshnessRule object_rule;
  object_rule.selector.target = Target("switch/1");
  object_rule.selector.object = Object("port/eth0");
  object_rule.ttl_nanos = 1000000000LL;
  policy.freshness_rules.push_back(object_rule);
  NDO_CHECK_EQ(policy.TtlFor(Target("switch/1"), Object("port/eth0"), Path("mtu")),
               std::int64_t{1000000000LL});
  NDO_CHECK_EQ(policy.TtlFor(Target("switch/1"), Object("port/eth1"), Path("mtu")),
               std::int64_t{7000000000LL});
  NDO_CHECK_EQ(policy.TtlFor(Target("switch/9"), Object("port/eth0"), Path("mtu")),
               policy.freshness.ttl_nanos);

  // Field classification can only narrow comparison, never widen it.
  ndo::FieldClassRule observe_only;
  observe_only.selector.path_prefix = Path("counter");
  observe_only.comparability = ndo::FieldComparability::ObserveOnly;
  policy.field_class_rules.push_back(observe_only);
  NDO_CHECK(policy.ClassifyField(Target("switch/1"), Object("port/eth0"), Path("counter"),
                                 ndo::FieldComparability::Managed) ==
            ndo::FieldComparability::ObserveOnly);
  NDO_CHECK(policy.ClassifyField(Target("switch/1"), Object("port/eth0"), Path("counter"),
                                 ndo::FieldComparability::Unsupported) ==
            ndo::FieldComparability::Unsupported);
  NDO_CHECK(policy.ClassifyField(Target("switch/1"), Object("port/eth0"), Path("mtu"),
                                 ndo::FieldComparability::Managed) ==
            ndo::FieldComparability::Managed);

  // Suppression lookup honours the class filter, the severity floor and expiry.
  ndo::SuppressionRule suppression;
  suppression.id = ndo::SuppressionId::Trusted("suppression/window");
  suppression.selector.target = Target("switch/1");
  suppression.klass = ndo::DriftClass::ValueMismatch;
  suppression.min_severity = ndo::Severity::Medium;
  suppression.author = ndo::ActorId::Trusted("operator/bob");
  suppression.reason = "change window";
  suppression.created_at = FixedTime(1000);
  suppression.expires_at = FixedTime(2000);
  policy.suppressions.push_back(suppression);

  NDO_CHECK(policy.FindSuppression(Target("switch/1"), Object("port/eth0"), Path("mtu"),
                                   ndo::DriftClass::ValueMismatch, ndo::Severity::High,
                                   FixedTime(1500)) != nullptr);
  NDO_CHECK(policy.FindSuppression(Target("switch/1"), Object("port/eth0"), Path("mtu"),
                                   ndo::DriftClass::ValueMismatch, ndo::Severity::Low,
                                   FixedTime(1500)) == nullptr);
  NDO_CHECK(policy.FindSuppression(Target("switch/1"), Object("port/eth0"), Path("mtu"),
                                   ndo::DriftClass::Unexpected, ndo::Severity::High,
                                   FixedTime(1500)) == nullptr);
  NDO_CHECK(policy.FindSuppression(Target("switch/1"), Object("port/eth0"), Path("mtu"),
                                   ndo::DriftClass::ValueMismatch, ndo::Severity::High,
                                   FixedTime(2500)) == nullptr);
  NDO_CHECK(policy.FindSuppression(Target("switch/2"), Object("port/eth0"), Path("mtu"),
                                   ndo::DriftClass::ValueMismatch, ndo::Severity::High,
                                   FixedTime(1500)) == nullptr);
}

NDO_TEST(SourceDescriptorRoundTrip) {
  ndo::SourceDescriptor descriptor;
  descriptor.id = Source("collector/rack-7");
  descriptor.capabilities.asserts_absence = true;
  descriptor.capabilities.complete_coverage = true;
  descriptor.capabilities.reports_nested_paths = true;
  descriptor.capabilities.evidence = ndo::EvidenceClass::Synthetic;
  descriptor.registered_at = FixedTime(42);
  descriptor.epoch = ndo::FabricEpoch::FromValue(1);
  descriptor.incarnation = ndo::Incarnation::FromValue(3);
  descriptor.provenance = "synthetic fixture";

  const ndo::Value encoded = ndo::EncodeSourceDescriptor(descriptor);
  ndo::SourceDescriptor decoded;
  NDO_CHECK_STATUS(ndo::DecodeSourceDescriptor(encoded, ndo::RuntimeLimits{}, decoded));
  NDO_CHECK(decoded.id == descriptor.id);
  NDO_CHECK(decoded.capabilities == descriptor.capabilities);
  NDO_CHECK(decoded.incarnation == descriptor.incarnation);

  // A descriptor without authority is refused.
  ndo::Value::Map mutated = *encoded.as_map();
  mutated["incarnation"] = ndo::Value::MakeUint(0);
  NDO_CHECK_REFUSED(ndo::DecodeSourceDescriptor(ndo::Value::MakeMap(mutated),
                                                ndo::RuntimeLimits{}, decoded),
                    ndo::ReasonCode::FencedStaleIncarnation);
}
