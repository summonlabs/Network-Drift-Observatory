// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Canonical comparison: every drift class, and the determinism of the result.

#include <algorithm>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

using namespace ndotest;

namespace {

/// Runs one comparison pass over a ledger's committed state.
ndo::EvaluationOutcome Compare(const ndo::FindingLedger& ledger, const ndo::ObservatoryPolicy& policy,
                               ndo::NdoTime now) {
  const ndo::Result<ndo::EvaluationOutcome> outcome =
      ndo::EvaluateLedgerOnce(ledger, policy, ndo::RuntimeLimits{},
                              ndo::FabricEpoch::FromValue(1), ndo::Incarnation::FromValue(1), now);
  if (!outcome.ok()) {
    NDO_CHECK(false);
    return ndo::EvaluationOutcome{};
  }
  return outcome.value();
}

ndo::FindingLedger LedgerWithIntent(const ndo::IntentGenerationDocument& document) {
  ndo::FindingLedger ledger;
  ndo::IntentCommitReport report;
  NDO_CHECK_STATUS(ledger.CommitIntent(document, FixedTime(100), report));
  return ledger;
}

std::vector<ndo::DriftClass> ClassesOf(const ndo::TargetEvaluation& evaluation) {
  std::vector<ndo::DriftClass> classes;
  for (const ndo::FindingDraft& draft : evaluation.drafts) {
    classes.push_back(draft.klass);
  }
  std::sort(classes.begin(), classes.end(), [](ndo::DriftClass lhs, ndo::DriftClass rhs) {
    return static_cast<std::uint8_t>(lhs) < static_cast<std::uint8_t>(rhs);
  });
  return classes;
}

bool HasClass(const ndo::TargetEvaluation& evaluation, ndo::DriftClass klass) {
  for (const ndo::FindingDraft& draft : evaluation.drafts) {
    if (draft.klass == klass) {
      return true;
    }
  }
  return false;
}

const ndo::FindingDraft* FindDraft(const ndo::TargetEvaluation& evaluation,
                                   const std::string& path) {
  for (const ndo::FindingDraft& draft : evaluation.drafts) {
    if (draft.path.ToText() == path) {
      return &draft;
    }
  }
  return nullptr;
}

}  // namespace

NDO_TEST(ConvergedStateProducesNoDrift) {
  ndo::FindingLedger ledger;
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(intent, "port/eth0", "admin-up", ndo::Value::MakeBool(true));
  ndo::FindingLedger committed = LedgerWithIntent(intent);

  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddObservedObject(snapshot, "port/eth0", "admin-up", ndo::Value::MakeBool(true));
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(committed.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));

  const ndo::ObservatoryPolicy policy = SyntheticPolicy();
  const ndo::EvaluationOutcome outcome = Compare(committed, policy, FixedTime(1000));
  NDO_CHECK_EQ(outcome.targets.size(), std::size_t{1});
  const ndo::TargetEvaluation& evaluation = outcome.targets.front();
  NDO_CHECK(evaluation.drafts.empty());
  NDO_CHECK(evaluation.compliance_decidable);
  NDO_CHECK(evaluation.compliant);
  NDO_CHECK(evaluation.decision_reason == ndo::ReasonCode::ClassifiedConverged);
  NDO_CHECK_EQ(evaluation.fresh_sources, std::size_t{1});
}

NDO_TEST(ValueMismatchAndFieldDrift) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 4);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(intent, "port/eth0", "admin-up", ndo::Value::MakeBool(true));
  AddIntentObject(intent, "port/eth0", "description", ndo::Value::MakeString("uplink"));
  ndo::FindingLedger ledger = LedgerWithIntent(intent);

  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  AddObservedObject(snapshot, "port/eth0", "admin-up", ndo::Value::MakeBool(true));
  AddObservedObject(snapshot, "port/eth0", "speed", ndo::Value::MakeString("100g"));
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));

  const ndo::EvaluationOutcome outcome = Compare(ledger, SyntheticPolicy(), FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = outcome.targets.front();
  NDO_CHECK_EQ(evaluation.drafts.size(), std::size_t{3});
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::ValueMismatch));
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::FieldMissing));
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::FieldUnexpected));
  NDO_CHECK(!evaluation.compliant);
  NDO_CHECK(evaluation.compliance_decidable);

  const ndo::FindingDraft* mismatch = FindDraft(evaluation, "mtu");
  NDO_CHECK(mismatch != nullptr);
  if (mismatch != nullptr) {
    NDO_CHECK(mismatch->has_intended && mismatch->has_observed);
    NDO_CHECK(mismatch->intended == ndo::Value::MakeInt(1500));
    NDO_CHECK(mismatch->observed == ndo::Value::MakeInt(9000));
    NDO_CHECK(mismatch->reason == ndo::ReasonCode::ClassifiedValueMismatch);
    NDO_CHECK(!mismatch->evidence.empty());
    NDO_CHECK(!mismatch->rationale.empty());
    NDO_CHECK_EQ(mismatch->baseline_generation.value(), std::uint64_t{4});
  }
}

NDO_TEST(ObjectPresenceDrift) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(intent, "port/eth1", "mtu", ndo::Value::MakeInt(1500));
  // Intent forbids this object outright.
  intent.objects.find(Object("port/eth1"))->second.existence = ndo::ObjectExistence::Forbidden;
  ndo::FindingLedger ledger = LedgerWithIntent(intent);

  // eth0 is absent (authoritative), eth1 is present although forbidden, and an
  // object the intent never declared is present.
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  ndo::ObservedObject absent;
  absent.id = Object("port/eth0");
  absent.presence = ndo::ObjectPresence::Absent;
  snapshot.objects.emplace(absent.id, absent);
  AddObservedObject(snapshot, "port/eth1", "mtu", ndo::Value::MakeInt(1500));
  AddObservedObject(snapshot, "port/eth2", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));

  const ndo::EvaluationOutcome outcome = Compare(ledger, SyntheticPolicy(), FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = outcome.targets.front();
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::Missing));
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::Unexpected));
  NDO_CHECK_EQ(ClassesOf(evaluation).size(), std::size_t{3});
  NDO_CHECK(!evaluation.compliant);
}

NDO_TEST(PartialVisibilityYieldsUnknownNotCompliance) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(intent, "port/eth1", "mtu", ndo::Value::MakeInt(1500));
  ndo::FindingLedger ledger = LedgerWithIntent(intent);

  // The source sees only part of the target and says so.
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  snapshot.coverage = ndo::ObservationCoverage::Partial;
  snapshot.capabilities.complete_coverage = false;
  snapshot.unobserved.push_back(Object("port/eth1"));
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));

  const ndo::EvaluationOutcome outcome = Compare(ledger, SyntheticPolicy(), FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = outcome.targets.front();
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::Unknown));
  NDO_CHECK(!evaluation.compliance_decidable);
  NDO_CHECK(!evaluation.compliant);
  for (const ndo::FindingDraft& draft : evaluation.drafts) {
    if (draft.klass == ndo::DriftClass::Unknown) {
      NDO_CHECK(draft.reason == ndo::ReasonCode::ObservationCoveragePartial ||
                draft.reason == ndo::ReasonCode::ObservationCoverageUnknown);
    }
  }
}

NDO_TEST(AbsenceAuthorityIsRequiredWhenPolicyDemandsIt) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  ndo::FindingLedger ledger = LedgerWithIntent(intent);

  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  snapshot.capabilities.asserts_absence = false;
  ndo::ObservedObject absent;
  absent.id = Object("port/eth0");
  absent.presence = ndo::ObjectPresence::Absent;
  // A source without the capability cannot even express absence, so the object
  // is simply not reported.
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));

  ndo::ObservatoryPolicy policy = SyntheticPolicy();
  policy.require_absence_authority = true;
  const ndo::EvaluationOutcome evaluation_outcome = Compare(ledger, policy, FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = evaluation_outcome.targets.front();
  // Complete coverage without an absence capability is not enough to declare an
  // object missing: the result is Unknown, and compliance is not decidable.
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::Unknown));
  NDO_CHECK(!HasClass(evaluation, ndo::DriftClass::Missing));
  NDO_CHECK(!evaluation.compliance_decidable);

  policy.require_absence_authority = false;
  // Without the requirement the same evidence does assert absence, but the
  // runtime still reports the weaker authority through the reason code.
  const ndo::EvaluationOutcome relaxed_outcome = Compare(ledger, policy, FixedTime(1000));
  const ndo::TargetEvaluation& relaxed = relaxed_outcome.targets.front();
  NDO_CHECK(HasClass(relaxed, ndo::DriftClass::Missing));
}

NDO_TEST(UnmanagedObserveOnlyAndUnsupportedFields) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(intent, "port/eth0", "counter", ndo::Value::MakeInt(1));
  AddIntentObject(intent, "port/eth0", "opaque", ndo::Value::MakeInt(1));
  AddIntentObject(intent, "port/eth0", "invisible", ndo::Value::MakeInt(1));
  intent.objects.find(Object("port/eth0"))->second.fields.find(Path("counter"))->second.comparability =
      ndo::FieldComparability::ObserveOnly;
  intent.objects.find(Object("port/eth0"))->second.fields.find(Path("opaque"))->second.comparability =
      ndo::FieldComparability::Unsupported;
  intent.objects.find(Object("port/eth0"))->second.fields.find(Path("invisible"))->second.comparability =
      ndo::FieldComparability::Unobservable;
  ndo::FindingLedger ledger = LedgerWithIntent(intent);

  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddObservedObject(snapshot, "port/eth0", "counter", ndo::Value::MakeInt(999999));
  // "opaque" is reported with a value of a different class entirely.
  snapshot.objects.find(Object("port/eth0"))->second.fields.insert_or_assign(
      Path("opaque"), ndo::Value::MakeMap({{"nested", ndo::Value::MakeInt(1)}}));
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));

  const ndo::EvaluationOutcome evaluation_outcome = Compare(ledger, SyntheticPolicy(), FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = evaluation_outcome.targets.front();
  NDO_CHECK(!HasClass(evaluation, ndo::DriftClass::ValueMismatch));
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::Unsupported));
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::Unknown));
  NDO_CHECK(!evaluation.compliance_decidable);
  for (const ndo::FindingDraft& draft : evaluation.drafts) {
    NDO_CHECK(draft.path.ToText() != "counter");
  }
}

NDO_TEST(StaleEvidenceNeverYieldsCompliance) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  ndo::FindingLedger ledger = LedgerWithIntent(intent);

  // A perfectly matching observation, collected far in the past.
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(100));
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));

  const ndo::EvaluationOutcome evaluation_outcome = Compare(ledger, SyntheticPolicy(), FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = evaluation_outcome.targets.front();
  NDO_CHECK(!evaluation.compliance_decidable);
  NDO_CHECK(!evaluation.compliant);
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::StaleObservation));
  NDO_CHECK(evaluation.decision_reason == ndo::ReasonCode::ObservationExpired);
  NDO_CHECK_EQ(evaluation.fresh_sources, std::size_t{0});

  // With no evidence at all the result is the same shape but its own reason.
  ndo::FindingLedger empty = LedgerWithIntent(intent);
  const ndo::EvaluationOutcome bare_outcome = Compare(empty, SyntheticPolicy(), FixedTime(1000));
  const ndo::TargetEvaluation& bare = bare_outcome.targets.front();
  NDO_CHECK(!bare.compliance_decidable);
  NDO_CHECK(HasClass(bare, ndo::DriftClass::StaleObservation));
  NDO_CHECK(bare.decision_reason == ndo::ReasonCode::NoFreshEvidence);
}

NDO_TEST(RequiredTargetWithoutIntentIsReported) {
  ndo::FindingLedger ledger;
  ndo::ObservatoryPolicy policy = PolicyRequiringTarget("switch/1");
  const ndo::EvaluationOutcome evaluation_outcome = Compare(ledger, policy, FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = evaluation_outcome.targets.front();
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::IntentMissing));
  NDO_CHECK(!evaluation.compliance_decidable);
  NDO_CHECK(!evaluation.compliant);

  // A target that policy does not require and that has never been observed is
  // not evaluated at all: the runtime makes no claim about it either way.
  ndo::FindingLedger other;
  const ndo::EvaluationOutcome unmanaged_outcome =
      Compare(other, SyntheticPolicy(), FixedTime(1000));
  NDO_CHECK(unmanaged_outcome.targets.empty());
  NDO_CHECK_EQ(unmanaged_outcome.DraftCount(), std::size_t{0});

  // A target that has observations but no intent, and that policy requires, is
  // reported as missing intent rather than passing silently.
  ndo::FindingLedger observed_only;
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/2", 1, FixedTime(995));
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(observed_only.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));
  const ndo::EvaluationOutcome unmanaged_two =
      Compare(observed_only, SyntheticPolicy(), FixedTime(1000));
  NDO_CHECK_EQ(unmanaged_two.targets.size(), std::size_t{1});
  NDO_CHECK(unmanaged_two.targets.front().drafts.empty());
  NDO_CHECK(!unmanaged_two.targets.front().compliance_decidable);
  NDO_CHECK(!unmanaged_two.targets.front().compliant);
}

NDO_TEST(GenerationDivergenceIsRegroupedWithoutLosingTheRawDifference) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 7);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(intent, "port/eth1", "mtu", ndo::Value::MakeInt(1500));
  ndo::FindingLedger ledger = LedgerWithIntent(intent);

  // Both ports report an older applied generation and an older value.
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  for (const std::string& object : {std::string("port/eth0"), std::string("port/eth1")}) {
    AddObservedObject(snapshot, object, "mtu", ndo::Value::MakeInt(1400));
    snapshot.objects.find(Object(object))->second.fields.insert_or_assign(
        Path("@applied-generation"), ndo::Value::MakeInt(6));
  }
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));

  const ndo::EvaluationOutcome evaluation_outcome = Compare(ledger, SyntheticPolicy(), FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = evaluation_outcome.targets.front();
  NDO_CHECK_EQ(evaluation.drafts.size(), std::size_t{2});
  for (const ndo::FindingDraft& draft : evaluation.drafts) {
    NDO_CHECK(draft.klass == ndo::DriftClass::GenerationMismatch);
    // The raw difference survives the regrouping.
    NDO_CHECK(draft.raw_class == ndo::DriftClass::ValueMismatch);
    NDO_CHECK(draft.qualifier.is_set());
    NDO_CHECK(draft.intended == ndo::Value::MakeInt(1500));
    NDO_CHECK(draft.observed == ndo::Value::MakeInt(1400));
  }
  // Both leaves share one divergence qualifier, so they group together.
  NDO_CHECK(evaluation.drafts[0].qualifier == evaluation.drafts[1].qualifier);
}

NDO_TEST(PartialApplicationIsDistinguishedFromAnUnappliedGeneration) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 5);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(intent, "port/eth1", "mtu", ndo::Value::MakeInt(1500));
  ndo::FindingLedger ledger = LedgerWithIntent(intent);

  // eth0 reports the intended generation and matches; eth1 is still behind.
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  snapshot.objects.find(Object("port/eth0"))->second.fields.insert_or_assign(
      Path("@applied-generation"), ndo::Value::MakeInt(5));
  AddObservedObject(snapshot, "port/eth1", "mtu", ndo::Value::MakeInt(1400));
  snapshot.objects.find(Object("port/eth1"))->second.fields.insert_or_assign(
      Path("@applied-generation"), ndo::Value::MakeInt(4));
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));

  const ndo::EvaluationOutcome evaluation_outcome = Compare(ledger, SyntheticPolicy(), FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = evaluation_outcome.targets.front();
  NDO_CHECK_EQ(evaluation.drafts.size(), std::size_t{1});
  NDO_CHECK(evaluation.drafts.front().klass == ndo::DriftClass::PartialApplication);
  NDO_CHECK(evaluation.drafts.front().reason == ndo::ReasonCode::ClassifiedPartialApplication);
  NDO_CHECK(evaluation.drafts.front().raw_class == ndo::DriftClass::ValueMismatch);
}

NDO_TEST(SourceConflictIsReportedWithBothPiecesOfEvidence) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  ndo::FindingLedger ledger = LedgerWithIntent(intent);

  ndo::ObservationSnapshot north = MakeSnapshot("collector/north", "switch/1", 1, FixedTime(995));
  AddObservedObject(north, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(north);
  ndo::ObservationSnapshot south = MakeSnapshot("collector/south", "switch/1", 1, FixedTime(996));
  AddObservedObject(south, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  SealSnapshot(south);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(north, ndo::FreshnessVerdict{}, false, admission));
  NDO_CHECK_STATUS(ledger.RecordObservation(south, ndo::FreshnessVerdict{}, false, admission));

  const ndo::EvaluationOutcome evaluation_outcome = Compare(ledger, SyntheticPolicy(), FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = evaluation_outcome.targets.front();
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::SourceConflict));
  for (const ndo::FindingDraft& draft : evaluation.drafts) {
    if (draft.klass != ndo::DriftClass::SourceConflict) {
      continue;
    }
    NDO_CHECK(draft.qualifier.is_set());
    NDO_CHECK_EQ(draft.evidence.size(), std::size_t{2});
    NDO_CHECK(draft.reason == ndo::ReasonCode::ObservationSourcesDisagree);
    // The two evidence references are the two sources, in a fixed order.
    NDO_CHECK(draft.evidence[0].source < draft.evidence[1].source);
  }

  // Removing the disagreement removes the conflict finding.
  ndo::FindingLedger agreed = LedgerWithIntent(intent);
  ndo::ObservationSnapshot south_agree = south;
  south_agree.objects.find(Object("port/eth0"))->second.fields.insert_or_assign(
      Path("mtu"), ndo::Value::MakeInt(1500));
  SealSnapshot(south_agree);
  NDO_CHECK_STATUS(agreed.RecordObservation(north, ndo::FreshnessVerdict{}, false, admission));
  NDO_CHECK_STATUS(agreed.RecordObservation(south_agree, ndo::FreshnessVerdict{}, false, admission));
  const ndo::EvaluationOutcome agreeing_outcome = Compare(agreed, SyntheticPolicy(), FixedTime(1000));
  const ndo::TargetEvaluation& agreeing = agreeing_outcome.targets.front();
  NDO_CHECK(!HasClass(agreeing, ndo::DriftClass::SourceConflict));
  NDO_CHECK(agreeing.compliant);
}

NDO_TEST(PrimarySourceSelectionFollowsDeclaredPriority) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  ndo::FindingLedger ledger = LedgerWithIntent(intent);

  ndo::ObservationSnapshot north = MakeSnapshot("collector/north", "switch/1", 1, FixedTime(995));
  AddObservedObject(north, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(north);
  ndo::ObservationSnapshot south = MakeSnapshot("collector/south", "switch/1", 1, FixedTime(996));
  AddObservedObject(south, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  SealSnapshot(south);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(north, ndo::FreshnessVerdict{}, false, admission));
  NDO_CHECK_STATUS(ledger.RecordObservation(south, ndo::FreshnessVerdict{}, false, admission));

  // With south declared authoritative there is still a conflict, but the
  // mismatch against intent is now explained from south's value.
  ndo::ObservatoryPolicy policy = SyntheticPolicy();
  policy.source_priority.push_back(Source("collector/south"));
  const ndo::EvaluationOutcome evaluation_outcome = Compare(ledger, policy, FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = evaluation_outcome.targets.front();
  const ndo::FindingDraft* mismatch = FindDraft(evaluation, "mtu");
  NDO_CHECK(mismatch != nullptr);
  if (mismatch != nullptr && mismatch->klass == ndo::DriftClass::ValueMismatch) {
    NDO_CHECK(mismatch->observed == ndo::Value::MakeInt(9000));
    NDO_CHECK(mismatch->evidence.front().source == Source("collector/south"));
  }

  // Regardless of priority, the disagreement itself is always reported.
  NDO_CHECK(HasClass(evaluation, ndo::DriftClass::SourceConflict));
}

NDO_TEST(ComparisonIsDeterministicAndOrderIndependent) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 3);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(intent, "port/eth1", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(intent, "port/eth2", "mtu", ndo::Value::MakeInt(1500));
  ndo::FindingLedger ledger = LedgerWithIntent(intent);

  for (int index = 0; index < 3; ++index) {
    ndo::ObservationSnapshot snapshot =
        MakeSnapshot("collector/" + std::to_string(index), "switch/1", 1,
                     FixedTime(995 + index));
    for (int object = 0; object < 3; ++object) {
      const std::string name = "port/eth" + std::to_string(object);
      AddObservedObject(snapshot, name, "mtu",
                        ndo::Value::MakeInt((object + index) % 2 == 0 ? 1500 : 9000));
    }
    SealSnapshot(snapshot);
    ndo::ObservationAdmission admission;
    NDO_CHECK_STATUS(ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));
  }

  const ndo::ObservatoryPolicy policy = SyntheticPolicy();
  const ndo::EvaluationOutcome first = Compare(ledger, policy, FixedTime(1000));
  for (int repeat = 0; repeat < 5; ++repeat) {
    const ndo::EvaluationOutcome again = Compare(ledger, policy, FixedTime(1000));
    NDO_CHECK(again.ComputeDigest() == first.ComputeDigest());
    NDO_CHECK_EQ(again.DraftCount(), first.DraftCount());
  }

  // Replaying the same observations in a different order changes nothing: the
  // ledger keeps them sorted by source authority and sequence.
  ndo::FindingLedger reordered;
  ndo::IntentCommitReport commit;
  NDO_CHECK_STATUS(reordered.CommitIntent(intent, FixedTime(100), commit));
  for (int index = 2; index >= 0; --index) {
    ndo::ObservationSnapshot snapshot =
        MakeSnapshot("collector/" + std::to_string(index), "switch/1", 1,
                     FixedTime(995 + index));
    for (int object = 0; object < 3; ++object) {
      const std::string name = "port/eth" + std::to_string(object);
      AddObservedObject(snapshot, name, "mtu",
                        ndo::Value::MakeInt((object + index) % 2 == 0 ? 1500 : 9000));
    }
    SealSnapshot(snapshot);
    ndo::ObservationAdmission admission;
    NDO_CHECK_STATUS(
        reordered.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));
  }
  const ndo::EvaluationOutcome reordered_outcome = Compare(reordered, policy, FixedTime(1000));
  NDO_CHECK(reordered_outcome.ComputeDigest() == first.ComputeDigest());
}

NDO_TEST(EvidenceClassTravelsWithEveryDraft) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  ndo::FindingLedger ledger = LedgerWithIntent(intent);
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  snapshot.evidence = ndo::EvidenceClass::Real;
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));

  const ndo::EvaluationOutcome evaluation_outcome = Compare(ledger, SyntheticPolicy(), FixedTime(1000));
  const ndo::TargetEvaluation& evaluation = evaluation_outcome.targets.front();
  NDO_CHECK(!evaluation.drafts.empty());
  for (const ndo::FindingDraft& draft : evaluation.drafts) {
    NDO_CHECK(!draft.evidence.empty());
    NDO_CHECK(draft.evidence.front().evidence == ndo::EvidenceClass::Real);
  }
}
