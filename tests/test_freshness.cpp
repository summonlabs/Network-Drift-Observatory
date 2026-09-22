// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Freshness-aware state: the absence of fresh evidence is never compliance.

#include <string>

#include "test_framework.hpp"
#include "test_support.hpp"

using namespace ndotest;

namespace {

constexpr std::int64_t kSecond = 1000000000LL;

ndo::FreshnessPolicy Policy() {
  ndo::FreshnessPolicy policy;
  policy.ttl_nanos = 100 * kSecond;
  policy.aging_threshold_percent = 80;
  policy.max_clock_skew_nanos = 5 * kSecond;
  policy.ttl_applies_to_receive_time = true;
  return policy;
}

}  // namespace

NDO_TEST(FreshnessStatesAreExplicit) {
  const ndo::FreshnessPolicy policy = Policy();
  const ndo::FabricEpoch live_epoch = ndo::FabricEpoch::FromValue(4);
  const ndo::NdoTime now = FixedTime(1000);

  // Fresh: collected a moment ago.
  ndo::ObservationSnapshot fresh = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(990), 4);
  const ndo::FreshnessVerdict fresh_verdict =
      ndo::EvaluateFreshness(fresh, policy, now, live_epoch, false);
  NDO_CHECK(fresh_verdict.state == ndo::FreshnessState::Fresh);
  NDO_CHECK(fresh_verdict.is_fresh());
  NDO_CHECK(fresh_verdict.may_support_compliance);
  NDO_CHECK(fresh_verdict.may_assert_absence);
  NDO_CHECK_EQ(fresh_verdict.age_nanos, std::int64_t{10 * kSecond});
  NDO_CHECK_EQ(fresh_verdict.effective_ttl_nanos, policy.ttl_nanos);

  // Aging: past the aging threshold (80% of the lifetime) but inside it.
  ndo::ObservationSnapshot aging = MakeSnapshot("collector/a", "switch/1", 2, FixedTime(915), 4);
  const ndo::FreshnessVerdict aging_verdict =
      ndo::EvaluateFreshness(aging, policy, now, live_epoch, false);
  NDO_CHECK(aging_verdict.state == ndo::FreshnessState::Aging);
  NDO_CHECK(aging_verdict.may_support_compliance);

  // Stale: past the lifetime. Compliance may not be concluded from it.
  ndo::ObservationSnapshot stale = MakeSnapshot("collector/a", "switch/1", 3, FixedTime(880), 4);
  const ndo::FreshnessVerdict stale_verdict =
      ndo::EvaluateFreshness(stale, policy, now, live_epoch, false);
  NDO_CHECK(stale_verdict.state == ndo::FreshnessState::Stale);
  NDO_CHECK(!stale_verdict.is_fresh());
  NDO_CHECK(stale_verdict.reason == ndo::ReasonCode::ObservationExpired);
  NDO_CHECK(!stale_verdict.may_support_compliance);
  NDO_CHECK(!stale_verdict.may_assert_absence);

  // Foreign epoch: expired whatever its age.
  ndo::ObservationSnapshot foreign = MakeSnapshot("collector/a", "switch/1", 4, FixedTime(999), 3);
  const ndo::FreshnessVerdict foreign_verdict =
      ndo::EvaluateFreshness(foreign, policy, now, live_epoch, false);
  NDO_CHECK(foreign_verdict.state == ndo::FreshnessState::Expired);
  NDO_CHECK(foreign_verdict.reason == ndo::ReasonCode::ObservationForeignEpoch);
  NDO_CHECK(!foreign_verdict.may_support_compliance);

  // Future: beyond the tolerated skew.
  ndo::ObservationSnapshot future = MakeSnapshot("collector/a", "switch/1", 5, FixedTime(1100), 4);
  const ndo::FreshnessVerdict future_verdict =
      ndo::EvaluateFreshness(future, policy, now, live_epoch, false);
  NDO_CHECK(future_verdict.state == ndo::FreshnessState::Future);
  NDO_CHECK(future_verdict.reason == ndo::ReasonCode::ObservationClockRegression);
  NDO_CHECK(!future_verdict.may_support_compliance);

  // Small skew inside the tolerance is still fresh.
  ndo::ObservationSnapshot skewed = MakeSnapshot("collector/a", "switch/1", 6, FixedTime(1003), 4);
  NDO_CHECK(ndo::EvaluateFreshness(skewed, policy, now, live_epoch, false).state ==
            ndo::FreshnessState::Fresh);

  // Recovered evidence is never fresh, whatever its age claims.
  ndo::ObservationSnapshot recovered =
      MakeSnapshot("collector/a", "switch/1", 7, FixedTime(999), 4);
  const ndo::FreshnessVerdict recovered_verdict =
      ndo::EvaluateFreshness(recovered, policy, now, live_epoch, true);
  NDO_CHECK(recovered_verdict.state == ndo::FreshnessState::RecoveredNotFresh);
  NDO_CHECK(recovered_verdict.reason == ndo::ReasonCode::EvidenceRecoveredNotFresh);
  NDO_CHECK(!recovered_verdict.may_support_compliance);
  NDO_CHECK(!recovered_verdict.may_assert_absence);

  // Evidence without a collection time cannot be judged.
  ndo::ObservationSnapshot timeless = MakeSnapshot("collector/a", "switch/1", 8, ndo::NdoTime{}, 4);
  const ndo::FreshnessVerdict timeless_verdict =
      ndo::EvaluateFreshness(timeless, policy, now, live_epoch, false);
  NDO_CHECK(timeless_verdict.state == ndo::FreshnessState::Unknown);
  NDO_CHECK(!timeless_verdict.may_support_compliance);
}

NDO_TEST(FreshnessTtlIsTheStricterOfPolicyAndSource) {
  ndo::FreshnessPolicy policy = Policy();
  const ndo::NdoTime now = FixedTime(1000);
  const ndo::FabricEpoch epoch = ndo::FabricEpoch::FromValue(1);

  // A source may ask for a shorter lifetime.
  ndo::ObservationSnapshot strict = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(950));
  strict.ttl_nanos = 10 * kSecond;
  const ndo::FreshnessVerdict strict_verdict =
      ndo::EvaluateFreshness(strict, policy, now, epoch, false);
  NDO_CHECK(strict_verdict.state == ndo::FreshnessState::Stale);
  NDO_CHECK_EQ(strict_verdict.effective_ttl_nanos, std::int64_t{10 * kSecond});

  // A source cannot ask for a longer lifetime than policy allows.
  ndo::ObservationSnapshot lenient = MakeSnapshot("collector/a", "switch/1", 2, FixedTime(950));
  lenient.ttl_nanos = 100000 * kSecond;
  const ndo::FreshnessVerdict lenient_verdict =
      ndo::EvaluateFreshness(lenient, policy, now, epoch, false);
  NDO_CHECK_EQ(lenient_verdict.effective_ttl_nanos, policy.ttl_nanos);
  NDO_CHECK(lenient_verdict.state == ndo::FreshnessState::Fresh);

  // The receive-time rule bounds how long evidence may be held: an observation
  // collected recently but received long ago is stale.
  ndo::ObservationSnapshot held = MakeSnapshot("collector/a", "switch/1", 3, FixedTime(995));
  held.received_at = FixedTime(800);
  NDO_CHECK(ndo::EvaluateFreshness(held, policy, now, epoch, false).state ==
            ndo::FreshnessState::Stale);
  policy.ttl_applies_to_receive_time = false;
  NDO_CHECK(ndo::EvaluateFreshness(held, policy, now, epoch, false).state ==
            ndo::FreshnessState::Fresh);
}

NDO_TEST(FreshnessIsDeterministic) {
  const ndo::FreshnessPolicy policy = Policy();
  const ndo::ObservationSnapshot snapshot =
      MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995), 2);
  const ndo::FreshnessVerdict first =
      ndo::EvaluateFreshness(snapshot, policy, FixedTime(1000), ndo::FabricEpoch::FromValue(2),
                             false);
  for (int repeat = 0; repeat < 8; ++repeat) {
    const ndo::FreshnessVerdict again =
        ndo::EvaluateFreshness(snapshot, policy, FixedTime(1000), ndo::FabricEpoch::FromValue(2),
                               false);
    NDO_CHECK(again.state == first.state);
    NDO_CHECK(again.reason == first.reason);
    NDO_CHECK_EQ(again.age_nanos, first.age_nanos);
    NDO_CHECK(again.may_support_compliance == first.may_support_compliance);
  }
}

NDO_TEST(SnapshotIdentityIsContentAddressed) {
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 5, FixedTime(900));
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(snapshot);
  NDO_CHECK_STATUS(snapshot.Validate(ndo::RuntimeLimits{}));

  // The same content produces the same identity, whatever the insertion order.
  ndo::ObservationSnapshot other = MakeSnapshot("collector/a", "switch/1", 5, FixedTime(900));
  AddObservedObject(other, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(other);
  NDO_CHECK(other.snapshot_id == snapshot.snapshot_id);

  // A tampered identity is refused, and so is tampered content.
  ndo::ObservationSnapshot tampered_id = snapshot;
  tampered_id.snapshot_id = ndo::SnapshotId::Trusted(std::string(64, 'a'));
  NDO_CHECK_REFUSED(tampered_id.Validate(ndo::RuntimeLimits{}),
                    ndo::ReasonCode::LedgerIntegrityDigestMismatch);

  ndo::ObservationSnapshot tampered_content = snapshot;
  AddObservedObject(tampered_content, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  NDO_CHECK_REFUSED(tampered_content.Validate(ndo::RuntimeLimits{}),
                    ndo::ReasonCode::LedgerIntegrityDigestMismatch);

  // Declared order of the unobserved set does not change identity.
  ndo::ObservationSnapshot first = MakeSnapshot("collector/a", "switch/2", 6, FixedTime(900));
  first.unobserved.push_back(Object("port/eth0"));
  first.unobserved.push_back(Object("port/eth1"));
  SealSnapshot(first);
  ndo::ObservationSnapshot second = MakeSnapshot("collector/a", "switch/2", 6, FixedTime(900));
  second.unobserved.push_back(Object("port/eth1"));
  second.unobserved.push_back(Object("port/eth0"));
  SealSnapshot(second);
  NDO_CHECK(first.snapshot_id == second.snapshot_id);
}

NDO_TEST(SnapshotValidationRefusals) {
  ndo::RuntimeLimits limits;
  ndo::ObservationSnapshot valid = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(100));
  AddObservedObject(valid, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(valid);
  NDO_CHECK(valid.Validate(limits).ok());

  ndo::ObservationSnapshot no_epoch = valid;
  no_epoch.epoch = ndo::FabricEpoch{};
  NDO_CHECK_REFUSED(no_epoch.Validate(limits), ndo::ReasonCode::FencedStaleEpoch);

  ndo::ObservationSnapshot no_incarnation = valid;
  no_incarnation.incarnation = ndo::Incarnation{};
  NDO_CHECK_REFUSED(no_incarnation.Validate(limits), ndo::ReasonCode::FencedStaleIncarnation);

  ndo::ObservationSnapshot no_sequence = valid;
  no_sequence.sequence = ndo::SourceSequence{};
  NDO_CHECK_REFUSED(no_sequence.Validate(limits), ndo::ReasonCode::ObservationSequenceRegressed);

  ndo::ObservationSnapshot no_time = valid;
  no_time.collected_at = ndo::NdoTime{};
  NDO_CHECK_REFUSED(no_time.Validate(limits), ndo::ReasonCode::ObservationClockRegression);

  ndo::ObservationSnapshot negative_ttl = valid;
  negative_ttl.ttl_nanos = -1;
  NDO_CHECK_REFUSED(negative_ttl.Validate(limits), ndo::ReasonCode::EncodingMalformed);

  // A source that cannot assert absence must not report it.
  ndo::ObservationSnapshot absent = MakeSnapshot("collector/a", "switch/1", 2, FixedTime(100));
  absent.capabilities.asserts_absence = false;
  ndo::ObservedObject object;
  object.id = Object("port/eth0");
  object.presence = ndo::ObjectPresence::Absent;
  absent.objects.emplace(object.id, object);
  SealSnapshot(absent);
  NDO_CHECK_REFUSED(absent.Validate(limits), ndo::ReasonCode::ObservationSourceCannotAssertAbsence);

  // An absent object cannot carry observed fields.
  ndo::ObservationSnapshot absent_with_fields =
      MakeSnapshot("collector/a", "switch/1", 3, FixedTime(100));
  absent_with_fields.capabilities.asserts_absence = true;
  ndo::ObservedObject conflicting;
  conflicting.id = Object("port/eth0");
  conflicting.presence = ndo::ObjectPresence::Absent;
  conflicting.fields.emplace(Path("mtu"), ndo::Value::MakeInt(1500));
  absent_with_fields.objects.emplace(conflicting.id, conflicting);
  SealSnapshot(absent_with_fields);
  NDO_CHECK_REFUSED(absent_with_fields.Validate(limits), ndo::ReasonCode::EncodingMalformed);

  // Bounds are enforced before the snapshot is stored.
  ndo::RuntimeLimits tight;
  tight.max_objects_per_target = 1;
  ndo::ObservationSnapshot wide = MakeSnapshot("collector/a", "switch/1", 4, FixedTime(100));
  AddObservedObject(wide, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddObservedObject(wide, "port/eth1", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(wide);
  NDO_CHECK_REFUSED(wide.Validate(tight), ndo::ReasonCode::LimitObjectsExceeded);
}
