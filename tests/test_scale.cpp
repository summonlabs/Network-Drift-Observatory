// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Scale and resource bounds.
//
// The suite drives the runtime far past the size of an ordinary fixture and
// proves three things at that size: the comparison stays exact and
// deterministic, every configured envelope refuses instead of growing, and
// every history surface stays bounded while the observations behind it keep
// accumulating.
//
// Nothing here measures or asserts wall-clock time. There is no watchdog and no
// timeout: a run that never finishes is a defect to explain, not a tolerance to
// widen.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "summon/network_drift_observatory/comparison.hpp"
#include "summon/network_drift_observatory/engine.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/query.hpp"
#include "summon/network_drift_observatory/report.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/value.hpp"

#include "test_framework.hpp"
#include "test_support.hpp"

using namespace ndotest;

namespace {

const char* const kScaleTarget = "fabric/scale";
const char* const kScaleSource = "collector/scale";

/// Deterministic observatory rig: the clock only moves when a test moves it.
class Rig {
 public:
  explicit Rig(ndo::ObservatoryConfig config)
      : observatory_(std::move(config), [this]() { return clock_; }) {}
  ~Rig() { observatory_.Stop(); }
  Rig(const Rig&) = delete;
  Rig& operator=(const Rig&) = delete;

  ndo::Observatory& observatory() { return observatory_; }
  void SetClock(ndo::NdoTime now) { clock_ = now; }

  ndo::Status Commit(const ndo::IntentGenerationDocument& document) {
    ndo::IntentCommitReport report;
    return observatory_.PublishIntent(document, report);
  }

  ndo::Status Observe(ndo::ObservationSnapshot snapshot) {
    ndo::ObservationAdmission admission;
    return observatory_.IngestObservation(std::move(snapshot), admission);
  }

 private:
  ndo::NdoTime clock_{FixedTime(1000)};
  ndo::Observatory observatory_;
};

ndo::ObservatoryConfig SyntheticConfig(const ndo::RuntimeLimits& limits = ndo::RuntimeLimits{}) {
  ndo::ObservatoryConfig config;
  config.policy = SyntheticPolicy();
  config.limits = limits;
  config.epoch = ndo::FabricEpoch::FromValue(1);
  config.incarnation = ndo::Incarnation::FromValue(1);
  return config;
}

/// Fixed-width object identity so that ordering is textual and stable.
std::string ObjectName(std::size_t index) {
  const std::string digits = std::to_string(index);
  std::string padded;
  for (std::size_t pad = digits.size(); pad < 5; ++pad) {
    padded.push_back('0');
  }
  return "port/p" + padded + digits;
}

/// Three managed fields per object: a number, a boolean and a string.
void AddScaleIntentObjects(ndo::IntentGenerationDocument& document, std::size_t objects) {
  for (std::size_t index = 0; index < objects; ++index) {
    const std::string name = ObjectName(index);
    AddIntentObject(document, name, "mtu", ndo::Value::MakeInt(1500));
    AddIntentObject(document, name, "enabled", ndo::Value::MakeBool(true));
    AddIntentObject(document, name, "admin", ndo::Value::MakeString("ops"));
  }
}

/// Observation of every object, where object i reports the drift value for
/// "mtu" exactly when the predicate says so. Everything else agrees with intent.
ndo::ObservationSnapshot ScaleSnapshot(std::uint64_t sequence, ndo::NdoTime collected_at,
                                       std::size_t objects,
                                       const std::function<bool(std::size_t)>& drifts,
                                       std::int64_t drift_value) {
  ndo::ObservationSnapshot snapshot =
      MakeSnapshot(kScaleSource, kScaleTarget, sequence, collected_at);
  for (std::size_t index = 0; index < objects; ++index) {
    const std::string name = ObjectName(index);
    AddObservedObject(snapshot, name, "mtu",
                      ndo::Value::MakeInt(drifts(index) ? drift_value : 1500));
    AddObservedObject(snapshot, name, "enabled", ndo::Value::MakeBool(true));
    AddObservedObject(snapshot, name, "admin", ndo::Value::MakeString("ops"));
  }
  SealSnapshot(snapshot);
  return snapshot;
}

/// Commits a small generation whose objects all drift, applies one evaluation
/// and returns the number of drafts the evaluation produced.
std::size_t SeedUniformDrift(Rig& rig, std::size_t objects) {
  ndo::IntentGenerationDocument intent = MakeIntent(kScaleTarget, 1);
  AddScaleIntentObjects(intent, objects);
  NDO_CHECK_STATUS(rig.Commit(intent));
  ndo::ObservationSnapshot snapshot =
      ScaleSnapshot(1, FixedTime(1000), objects, [](std::size_t) { return true; }, 9000);
  NDO_CHECK_STATUS(rig.Observe(std::move(snapshot)));
  rig.SetClock(FixedTime(1000));
  const ndo::Result<ndo::EvaluationOutcome> outcome =
      rig.observatory().EvaluateAt(FixedTime(1000), true);
  if (!outcome.ok()) {
    NDO_CHECK(false);
    return 0;
  }
  return outcome.value().DraftCount();
}

std::vector<ndo::Finding> AllFindings(ndo::Observatory& observatory) {
  ndo::QuerySpec spec;
  spec.limit = 1000000;
  spec.include_resolved = true;
  spec.include_superseded = true;
  spec.include_retired = true;
  const ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
  if (!page.ok()) {
    NDO_CHECK(false);
    return {};
  }
  return page.value().findings;
}

const ndo::Finding* FindByObject(const std::vector<ndo::Finding>& findings,
                                    const std::string& object) {
  for (const ndo::Finding& finding : findings) {
    if (finding.identity.object.str() == object) {
      return &finding;
    }
  }
  return nullptr;
}

const ndo::Value* Member(const ndo::Value& value, const std::string& key) {
  const ndo::Value::Map* map = value.as_map();
  if (map == nullptr) {
    return nullptr;
  }
  const auto found = map->find(key);
  if (found == map->end()) {
    return nullptr;
  }
  return &found->second;
}

bool JsonFlag(const ndo::Value& root, const std::string& member) {
  const ndo::Value* stats = Member(root, "stats");
  const ndo::Value* flag = stats == nullptr ? nullptr : Member(*stats, member);
  if (flag == nullptr) {
    return false;
  }
  const bool* value = flag->as_bool();
  return value != nullptr && *value;
}

std::size_t JsonCount(const ndo::Value& root, const std::string& member) {
  const ndo::Value* stats = Member(root, "stats");
  const ndo::Value* count = stats == nullptr ? nullptr : Member(*stats, member);
  if (count == nullptr) {
    return 0;
  }
  const std::uint64_t* unsigned_value = count->as_uint();
  if (unsigned_value != nullptr) {
    return static_cast<std::size_t>(*unsigned_value);
  }
  const std::int64_t* signed_value = count->as_int();
  return signed_value == nullptr ? 0 : static_cast<std::size_t>(*signed_value);
}

// ---------------------------------------------------------------------------
// 1. A generation and an observation far larger than any fixture
// ---------------------------------------------------------------------------

constexpr std::size_t kScaleObjects = 20000;
constexpr std::size_t kScaleDriftPeriod = 100;

NDO_TEST(LargeGenerationEvaluatesExactlyAndDeterministically) {
  Rig rig(SyntheticConfig());
  NDO_CHECK_STATUS(rig.observatory().Start());

  ndo::IntentGenerationDocument intent = MakeIntent(kScaleTarget, 7);
  AddScaleIntentObjects(intent, kScaleObjects);
  NDO_CHECK_EQ(intent.ObjectCount(), kScaleObjects);
  NDO_CHECK_EQ(intent.FieldCount(), kScaleObjects * 3);
  NDO_CHECK_STATUS(rig.Commit(intent));

  ndo::ObservationSnapshot snapshot =
      ScaleSnapshot(1, FixedTime(1000), kScaleObjects,
                    [](std::size_t index) { return index % kScaleDriftPeriod == 0; }, 9000);
  NDO_CHECK_STATUS(rig.Observe(std::move(snapshot)));

  std::vector<std::string> expected_objects;
  for (std::size_t index = 0; index < kScaleObjects; ++index) {
    if (index % kScaleDriftPeriod == 0) {
      expected_objects.push_back(ObjectName(index));
    }
  }
  const std::size_t expected_findings = expected_objects.size();
  NDO_CHECK_EQ(expected_findings, std::size_t{200});

  rig.SetClock(FixedTime(1000));

  // Pass one: computed, not applied.
  const ndo::Result<ndo::EvaluationOutcome> first =
      rig.observatory().EvaluateAt(FixedTime(1000), false);
  NDO_CHECK(first.ok());
  if (!first.ok()) {
    return;
  }
  NDO_CHECK_EQ(first.value().targets.size(), std::size_t{1});
  NDO_CHECK_EQ(first.value().DraftCount(), expected_findings);
  if (first.value().targets.size() == 1) {
    const ndo::TargetEvaluation& evaluation = first.value().targets.front();
    NDO_CHECK(evaluation.has_baseline);
    NDO_CHECK_EQ(evaluation.baseline_generation.value(), std::uint64_t{7});
    NDO_CHECK_EQ(evaluation.sources_considered, std::size_t{1});
    NDO_CHECK_EQ(evaluation.fresh_sources, std::size_t{1});
    NDO_CHECK(evaluation.compliance_decidable);
    NDO_CHECK(!evaluation.compliant);
    NDO_CHECK(evaluation.decision_reason == ndo::ReasonCode::ClassifiedValueMismatch);
  }
  const ndo::Digest first_digest = first.value().ComputeDigest();

  // Pass two over untouched inputs: byte-identical outcome. No container order,
  // arrival order, address or counter may leak into the comparison.
  const ndo::Result<ndo::EvaluationOutcome> second =
      rig.observatory().EvaluateAt(FixedTime(1000), false);
  NDO_CHECK(second.ok());
  if (second.ok()) {
    NDO_CHECK(second.value().ComputeDigest() == first_digest);
    NDO_CHECK_EQ(second.value().DraftCount(), expected_findings);
  }

  // Pass three applies the same outcome: applying findings must not change what
  // the comparison itself produces.
  const ndo::Result<ndo::EvaluationOutcome> applied =
      rig.observatory().EvaluateAt(FixedTime(1000), true);
  NDO_CHECK(applied.ok());
  if (applied.ok()) {
    NDO_CHECK(applied.value().ComputeDigest() == first_digest);
    NDO_CHECK_EQ(applied.value().DraftCount(), expected_findings);
  }

  const ndo::LedgerStats stats = rig.observatory().Stats();
  NDO_CHECK_EQ(stats.targets, std::size_t{1});
  NDO_CHECK_EQ(stats.baselines, std::size_t{1});
  NDO_CHECK_EQ(stats.observations, std::size_t{1});
  NDO_CHECK_EQ(stats.findings, expected_findings);
  NDO_CHECK_EQ(stats.live_findings, expected_findings);
  NDO_CHECK(stats.findings <= rig.observatory().limits().max_findings);
  NDO_CHECK(stats.timeline_entries <= rig.observatory().limits().max_global_timeline_entries);
  NDO_CHECK_EQ(rig.observatory().Counters().findings_created,
               static_cast<std::uint64_t>(expected_findings));
  NDO_CHECK_EQ(rig.observatory().Counters().evaluations, std::uint64_t{3});

  // The findings are exactly the drift that was constructed, at exactly the
  // locations that were constructed.
  const std::vector<ndo::Finding> findings = AllFindings(rig.observatory());
  NDO_CHECK_EQ(findings.size(), expected_findings);
  std::vector<std::string> finding_objects;
  std::set<std::string> finding_ids;
  for (const ndo::Finding& finding : findings) {
    NDO_CHECK(finding.klass == ndo::DriftClass::ValueMismatch);
    NDO_CHECK(finding.reason == ndo::ReasonCode::ClassifiedValueMismatch);
    NDO_CHECK(finding.state == ndo::FindingState::Open);
    NDO_CHECK_EQ(finding.identity.path.ToText(), std::string("mtu"));
    NDO_CHECK(finding.has_intended);
    NDO_CHECK(finding.has_observed);
    NDO_CHECK(finding.intended == ndo::Value::MakeInt(1500));
    NDO_CHECK(finding.observed == ndo::Value::MakeInt(9000));
    NDO_CHECK_EQ(finding.observation_count, std::uint64_t{1});
    NDO_CHECK_EQ(finding.evidence.size(), std::size_t{1});
    if (!finding.evidence.empty()) {
      NDO_CHECK(finding.evidence.front().source == Source(kScaleSource));
      NDO_CHECK_EQ(finding.evidence.front().sequence.value(), std::uint64_t{1});
    }
    // Per-finding history is produced and bounded, even for twenty thousand
    // objects; the ledger's own attribution events are part of that history.
    NDO_CHECK(finding.timeline.size() >= std::size_t{1});
    NDO_CHECK(finding.timeline.size() <=
              rig.observatory().limits().max_timeline_entries_per_finding);
    NDO_CHECK(finding.timeline.front().kind == ndo::TimelineEventKind::Created);
    NDO_CHECK(finding.timeline.front().reason == ndo::ReasonCode::FindingCreated);
    NDO_CHECK(finding.group.is_set());
    NDO_CHECK(finding.group_cause == ndo::RootCauseKind::SingleField);
    finding_objects.push_back(finding.identity.object.str());
    finding_ids.insert(finding.id.ToHex());
  }
  std::sort(finding_objects.begin(), finding_objects.end());
  NDO_CHECK(finding_objects == expected_objects);
  NDO_CHECK_EQ(finding_ids.size(), expected_findings);

  // Root-cause grouping covers the whole generation in one bounded group.
  ndo::ReportSpec group_spec;
  group_spec.include_timeline = false;
  const ndo::Result<ndo::ReportInputs> report_inputs =
      rig.observatory().CollectReportInputs(group_spec);
  NDO_CHECK(report_inputs.ok());
  if (report_inputs.ok()) {
    NDO_CHECK_EQ(report_inputs.value().groups.size(), std::size_t{1});
    if (report_inputs.value().groups.size() == 1) {
      const ndo::RootCauseGroup& group = report_inputs.value().groups.front();
      NDO_CHECK(group.cause == ndo::RootCauseKind::SingleField);
      NDO_CHECK_EQ(group.members.size(), expected_findings);
      NDO_CHECK_EQ(group.objects.size(), expected_findings);
    }
  }
}

// ---------------------------------------------------------------------------
// 2. A small envelope refuses, and refusal leaves the ledger exactly as it was
// ---------------------------------------------------------------------------

NDO_TEST(SmallEnvelopeRefusesWithoutTouchingTheLedger) {
  ndo::RuntimeLimits limits;
  limits.max_objects_per_target = 4;
  limits.max_fields_per_object = 2;
  limits.max_value_depth = 3;
  limits.max_leaf_bytes = 16;
  limits.max_path_segments = 3;
  limits.max_document_bytes = 512;

  Rig rig(SyntheticConfig(limits));
  NDO_CHECK_STATUS(rig.observatory().Start());
  NDO_CHECK_EQ(rig.observatory().limits().max_objects_per_target, std::size_t{4});
  NDO_CHECK_EQ(rig.observatory().limits().max_leaf_bytes, std::size_t{16});

  // The content every refusal below must leave untouched.
  ndo::IntentGenerationDocument good = MakeIntent("switch/1", 1);
  AddIntentObject(good, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(good, "port/eth0", "admin", ndo::Value::MakeString("ops"));
  NDO_CHECK_STATUS(rig.Commit(good));

  ndo::ObservationSnapshot good_snapshot =
      MakeSnapshot("collector/a", "switch/1", 1, FixedTime(1000));
  AddObservedObject(good_snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  AddObservedObject(good_snapshot, "port/eth0", "admin", ndo::Value::MakeString("ops"));
  SealSnapshot(good_snapshot);
  NDO_CHECK_STATUS(rig.Observe(good_snapshot));

  ndo::ReportSpec report_spec;
  report_spec.include_timeline = false;
  report_spec.include_groups = false;
  const ndo::Result<ndo::ReportInputs> before = rig.observatory().CollectReportInputs(report_spec);
  NDO_CHECK(before.ok());
  if (!before.ok()) {
    return;
  }
  const ndo::LedgerRevision revision_before = before.value().revision;
  const ndo::Digest content_before = before.value().state_digest;
  const ndo::LedgerStats stats_before = before.value().stats;
  NDO_CHECK_EQ(stats_before.baselines, std::size_t{1});
  NDO_CHECK_EQ(stats_before.observations, std::size_t{1});
  NDO_CHECK_EQ(stats_before.findings, std::size_t{0});

  const auto ledger_unchanged = [&]() {
    const ndo::Result<ndo::ReportInputs> current =
        rig.observatory().CollectReportInputs(report_spec);
    if (!current.ok()) {
      NDO_CHECK(false);
      return;
    }
    NDO_CHECK(current.value().revision.value() == revision_before.value());
    NDO_CHECK(current.value().state_digest == content_before);
    NDO_CHECK_EQ(current.value().stats.targets, stats_before.targets);
    NDO_CHECK_EQ(current.value().stats.baselines, stats_before.baselines);
    NDO_CHECK_EQ(current.value().stats.observations, stats_before.observations);
    NDO_CHECK_EQ(current.value().stats.findings, stats_before.findings);
    NDO_CHECK_EQ(current.value().stats.timeline_entries, stats_before.timeline_entries);
    NDO_CHECK_EQ(current.value().stats.sources, stats_before.sources);
  };

  ndo::IntentCommitReport intent_report;
  ndo::ObservationAdmission admission;

  // --- intent: too many objects for the target ---
  ndo::IntentGenerationDocument too_many_objects = MakeIntent("switch/1", 2);
  for (std::size_t index = 0; index < 5; ++index) {
    AddIntentObject(too_many_objects, ObjectName(index), "mtu", ndo::Value::MakeInt(1500));
  }
  NDO_CHECK_REFUSED(rig.observatory().PublishIntent(too_many_objects, intent_report),
                    ndo::ReasonCode::LimitObjectsExceeded);
  ledger_unchanged();

  // --- intent: too many fields in one object ---
  ndo::IntentGenerationDocument too_many_fields = MakeIntent("switch/1", 2);
  AddIntentObject(too_many_fields, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(too_many_fields, "port/eth0", "admin", ndo::Value::MakeString("ops"));
  AddIntentObject(too_many_fields, "port/eth0", "enabled", ndo::Value::MakeBool(true));
  NDO_CHECK_REFUSED(rig.observatory().PublishIntent(too_many_fields, intent_report),
                    ndo::ReasonCode::LimitFieldsExceeded);
  ledger_unchanged();

  // --- intent: one leaf larger than the envelope ---
  ndo::IntentGenerationDocument too_many_bytes = MakeIntent("switch/1", 2);
  AddIntentObject(too_many_bytes, "port/eth0", "admin",
                  ndo::Value::MakeString(std::string(64, 'x')));
  NDO_CHECK_REFUSED(rig.observatory().PublishIntent(too_many_bytes, intent_report),
                    ndo::ReasonCode::LimitBytesExceeded);
  ledger_unchanged();

  // --- intent: a field path deeper than the envelope ---
  ndo::IntentGenerationDocument too_deep_path = MakeIntent("switch/1", 2);
  AddIntentObject(too_deep_path, "port/eth0", "a.b.c.d", ndo::Value::MakeInt(1));
  NDO_CHECK_REFUSED(rig.observatory().PublishIntent(too_deep_path, intent_report),
                    ndo::ReasonCode::LimitDepthExceeded);
  ledger_unchanged();

  // --- intent: a value tree deeper than the envelope ---
  ndo::IntentGenerationDocument too_deep_value = MakeIntent("switch/1", 2);
  AddIntentObject(too_deep_value, "port/eth0", "tree",
                  ndo::Value::MakeList({ndo::Value::MakeList(
                      {ndo::Value::MakeList({ndo::Value::MakeList({ndo::Value::MakeInt(1)})})})}));
  NDO_CHECK_REFUSED(rig.observatory().PublishIntent(too_deep_value, intent_report),
                    ndo::ReasonCode::LimitDepthExceeded);
  ledger_unchanged();

  // --- observation: too many objects ---
  ndo::ObservationSnapshot observed_too_many =
      MakeSnapshot("collector/a", "switch/1", 2, FixedTime(1001));
  for (std::size_t index = 0; index < 5; ++index) {
    AddObservedObject(observed_too_many, ObjectName(index), "mtu", ndo::Value::MakeInt(1500));
  }
  SealSnapshot(observed_too_many);
  NDO_CHECK_REFUSED(rig.Observe(observed_too_many), ndo::ReasonCode::LimitObjectsExceeded);
  ledger_unchanged();

  // --- observation: too many fields in one object ---
  ndo::ObservationSnapshot observed_too_many_fields =
      MakeSnapshot("collector/a", "switch/1", 2, FixedTime(1001));
  AddObservedObject(observed_too_many_fields, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddObservedObject(observed_too_many_fields, "port/eth0", "admin", ndo::Value::MakeString("ops"));
  AddObservedObject(observed_too_many_fields, "port/eth0", "enabled", ndo::Value::MakeBool(true));
  SealSnapshot(observed_too_many_fields);
  NDO_CHECK_REFUSED(rig.Observe(observed_too_many_fields), ndo::ReasonCode::LimitFieldsExceeded);
  ledger_unchanged();

  // --- observation: one leaf larger than the envelope ---
  ndo::ObservationSnapshot observed_too_many_bytes =
      MakeSnapshot("collector/a", "switch/1", 2, FixedTime(1001));
  AddObservedObject(observed_too_many_bytes, "port/eth0", "admin",
                    ndo::Value::MakeString(std::string(64, 'x')));
  SealSnapshot(observed_too_many_bytes);
  NDO_CHECK_REFUSED(rig.Observe(observed_too_many_bytes), ndo::ReasonCode::LimitBytesExceeded);
  ledger_unchanged();

  // --- observation document: refused before a byte is parsed ---
  NDO_CHECK_REFUSED(rig.observatory().IngestObservationJson(std::string(1024, 'x'), admission),
                    ndo::ReasonCode::LimitBytesExceeded);
  ledger_unchanged();

  const ndo::ObservatoryCounters counters = rig.observatory().Counters();
  NDO_CHECK_EQ(counters.intents_accepted, std::uint64_t{1});
  NDO_CHECK_EQ(counters.intents_rejected, std::uint64_t{5});
  NDO_CHECK_EQ(counters.observations_accepted, std::uint64_t{1});
  NDO_CHECK_EQ(counters.observations_rejected, std::uint64_t{4});
  NDO_CHECK_EQ(counters.evaluations, std::uint64_t{0});
  NDO_CHECK_EQ(counters.findings_created, std::uint64_t{0});
}

// ---------------------------------------------------------------------------
// 3. Ledger growth bounds and their all-or-nothing semantics
// ---------------------------------------------------------------------------

/// Five managed objects; the listed indices report drift for "mtu".
ndo::ObservationSnapshot BudgetSnapshot(std::uint64_t sequence, ndo::NdoTime collected_at,
                                        const std::vector<std::size_t>& drifting) {
  ndo::ObservationSnapshot snapshot =
      MakeSnapshot("collector/a", "switch/1", sequence, collected_at);
  for (std::size_t index = 0; index < 5; ++index) {
    const bool drifts = std::find(drifting.begin(), drifting.end(), index) != drifting.end();
    AddObservedObject(snapshot, ObjectName(index), "mtu",
                      ndo::Value::MakeInt(drifts ? 9000 : 1500));
  }
  SealSnapshot(snapshot);
  return snapshot;
}

NDO_TEST(FindingBudgetRefusalIsAtomic) {
  ndo::RuntimeLimits limits;
  limits.max_findings = 3;
  Rig rig(SyntheticConfig(limits));
  NDO_CHECK_STATUS(rig.observatory().Start());

  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  for (std::size_t index = 0; index < 5; ++index) {
    AddIntentObject(intent, ObjectName(index), "mtu", ndo::Value::MakeInt(1500));
  }
  NDO_CHECK_STATUS(rig.Commit(intent));

  // Two objects drift: two findings, one below the configured budget.
  NDO_CHECK_STATUS(rig.Observe(BudgetSnapshot(1, FixedTime(1000), {0, 1})));
  rig.SetClock(FixedTime(1000));
  const ndo::Result<ndo::EvaluationOutcome> first =
      rig.observatory().EvaluateAt(FixedTime(1000), true);
  NDO_CHECK(first.ok());
  if (!first.ok()) {
    return;
  }
  NDO_CHECK_EQ(first.value().DraftCount(), std::size_t{2});
  NDO_CHECK_EQ(rig.observatory().Stats().findings, std::size_t{2});

  // The next evaluation would create three more findings. It is refused in
  // full: nothing is created and the two existing findings are not touched.
  NDO_CHECK_STATUS(rig.Observe(BudgetSnapshot(2, FixedTime(1001), {0, 1, 2, 3, 4})));
  rig.SetClock(FixedTime(1001));
  const ndo::Result<ndo::EvaluationOutcome> refused =
      rig.observatory().EvaluateAt(FixedTime(1001), true);
  NDO_CHECK(!refused.ok());
  NDO_CHECK_REFUSED(refused.status(), ndo::ReasonCode::LimitFindingsExceeded);
  NDO_CHECK_EQ(rig.observatory().Stats().findings, std::size_t{2});
  NDO_CHECK_EQ(rig.observatory().Counters().findings_created, std::uint64_t{2});
  NDO_CHECK_EQ(rig.observatory().Counters().evaluations, std::uint64_t{1});
  NDO_CHECK_EQ(rig.observatory().Counters().evaluations_fenced, std::uint64_t{0});
  const std::vector<ndo::Finding> after_refusal = AllFindings(rig.observatory());
  NDO_CHECK_EQ(after_refusal.size(), std::size_t{2});
  for (const ndo::Finding& finding : after_refusal) {
    NDO_CHECK_EQ(finding.observation_count, std::uint64_t{1});
  }

  // Exactly at the bound is allowed: two existing plus one new equals three.
  NDO_CHECK_STATUS(rig.Observe(BudgetSnapshot(3, FixedTime(1002), {0, 1, 2})));
  rig.SetClock(FixedTime(1002));
  const ndo::Result<ndo::EvaluationOutcome> at_bound =
      rig.observatory().EvaluateAt(FixedTime(1002), true);
  NDO_CHECK(at_bound.ok());
  if (at_bound.ok()) {
    NDO_CHECK_EQ(at_bound.value().DraftCount(), std::size_t{3});
  }
  NDO_CHECK_EQ(rig.observatory().Stats().findings, std::size_t{3});
  NDO_CHECK_EQ(rig.observatory().Stats().findings, limits.max_findings);
  NDO_CHECK_EQ(rig.observatory().Counters().findings_created, std::uint64_t{3});
  NDO_CHECK_EQ(rig.observatory().Counters().evaluations, std::uint64_t{2});
  const std::vector<ndo::Finding> final_findings = AllFindings(rig.observatory());
  NDO_CHECK_EQ(final_findings.size(), std::size_t{3});
  NDO_CHECK(FindByObject(final_findings, ObjectName(3)) == nullptr);
  NDO_CHECK(FindByObject(final_findings, ObjectName(4)) == nullptr);
  const ndo::Finding* first_object = FindByObject(final_findings, ObjectName(0));
  const ndo::Finding* second_object = FindByObject(final_findings, ObjectName(1));
  const ndo::Finding* third_object = FindByObject(final_findings, ObjectName(2));
  NDO_CHECK(first_object != nullptr);
  NDO_CHECK(second_object != nullptr);
  NDO_CHECK(third_object != nullptr);
  if (first_object != nullptr) {
    NDO_CHECK_EQ(first_object->observation_count, std::uint64_t{2});
  }
  if (second_object != nullptr) {
    NDO_CHECK_EQ(second_object->observation_count, std::uint64_t{2});
  }
  if (third_object != nullptr) {
    NDO_CHECK_EQ(third_object->observation_count, std::uint64_t{1});
  }
}

NDO_TEST(PerFindingTimelineStaysBoundedWhileObservationCountGrows) {
  ndo::RuntimeLimits limits;
  limits.max_timeline_entries_per_finding = 4;
  Rig rig(SyntheticConfig(limits));
  NDO_CHECK_STATUS(rig.observatory().Start());

  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  NDO_CHECK_STATUS(rig.Commit(intent));

  constexpr std::size_t kPasses = 12;
  for (std::size_t pass = 1; pass <= kPasses; ++pass) {
    const std::int64_t value = static_cast<std::int64_t>(9000 + pass);
    const ndo::NdoTime now = FixedTime(1000 + static_cast<std::int64_t>(pass));
    ndo::ObservationSnapshot snapshot =
        MakeSnapshot("collector/a", "switch/1", static_cast<std::uint64_t>(pass), now);
    AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(value));
    SealSnapshot(snapshot);
    NDO_CHECK_STATUS(rig.Observe(std::move(snapshot)));

    rig.SetClock(now);
    const ndo::Result<ndo::EvaluationOutcome> outcome = rig.observatory().EvaluateAt(now, true);
    NDO_CHECK(outcome.ok());
    if (!outcome.ok()) {
      return;
    }

    const std::vector<ndo::Finding> findings = AllFindings(rig.observatory());
    NDO_CHECK_EQ(findings.size(), std::size_t{1});
    if (findings.size() != 1) {
      return;
    }
    const ndo::Finding& finding = findings.front();
    NDO_CHECK_EQ(finding.observation_count, static_cast<std::uint64_t>(pass));
    NDO_CHECK_EQ(finding.identity.path.ToText(), std::string("mtu"));
    NDO_CHECK(finding.observed == ndo::Value::MakeInt(value));
    const std::size_t expected_history = pass < limits.max_timeline_entries_per_finding
                                             ? pass
                                             : limits.max_timeline_entries_per_finding;
    NDO_CHECK_EQ(finding.timeline.size(), expected_history);
    NDO_CHECK(finding.timeline.size() <= limits.max_timeline_entries_per_finding);
    NDO_CHECK(finding.timeline.back().kind ==
              (pass == 1 ? ndo::TimelineEventKind::Created : ndo::TimelineEventKind::Updated));
  }

  const ndo::LedgerStats stats = rig.observatory().Stats();
  NDO_CHECK_EQ(stats.findings, std::size_t{1});
  NDO_CHECK_EQ(rig.observatory().Counters().evaluations, static_cast<std::uint64_t>(kPasses));
  // History keeps being produced; it is the retained window that is bounded.
  NDO_CHECK(stats.timeline_entries >= kPasses);
  NDO_CHECK(stats.timeline_entries <= limits.max_global_timeline_entries);
}

NDO_TEST(RetainedObservationWindowIsBoundedAndKeepsTheNewest) {
  ndo::RuntimeLimits limits;
  limits.max_retained_snapshots_per_source = 3;
  Rig rig(SyntheticConfig(limits));
  NDO_CHECK_STATUS(rig.observatory().Start());

  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  NDO_CHECK_STATUS(rig.Commit(intent));

  constexpr std::size_t kSnapshots = 15;
  for (std::size_t index = 1; index <= kSnapshots; ++index) {
    const std::int64_t value = static_cast<std::int64_t>(1500 + index);
    ndo::ObservationSnapshot snapshot =
        MakeSnapshot("collector/a", "switch/1", static_cast<std::uint64_t>(index),
                     FixedTime(1000 + static_cast<std::int64_t>(index)));
    AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(value));
    SealSnapshot(snapshot);
    NDO_CHECK_STATUS(rig.Observe(std::move(snapshot)));
    NDO_CHECK(rig.observatory().Stats().observations <= limits.max_retained_snapshots_per_source);
  }
  NDO_CHECK_EQ(rig.observatory().Stats().observations, limits.max_retained_snapshots_per_source);
  NDO_CHECK_EQ(rig.observatory().Counters().observations_accepted,
               static_cast<std::uint64_t>(kSnapshots));

  // The newest observation of the source is always the one compared, however
  // many older ones the window had to drop.
  const ndo::NdoTime now = FixedTime(1000 + static_cast<std::int64_t>(kSnapshots));
  rig.SetClock(now);
  const ndo::Result<ndo::EvaluationOutcome> outcome = rig.observatory().EvaluateAt(now, true);
  NDO_CHECK(outcome.ok());
  if (!outcome.ok()) {
    return;
  }
  NDO_CHECK_EQ(outcome.value().DraftCount(), std::size_t{1});
  const std::vector<ndo::Finding> findings = AllFindings(rig.observatory());
  NDO_CHECK_EQ(findings.size(), std::size_t{1});
  if (findings.empty()) {
    return;
  }
  const ndo::Finding& finding = findings.front();
  NDO_CHECK(finding.observed == ndo::Value::MakeInt(static_cast<std::int64_t>(1500 + kSnapshots)));
  NDO_CHECK_EQ(finding.evidence.size(), std::size_t{1});
  if (!finding.evidence.empty()) {
    NDO_CHECK_EQ(finding.evidence.front().sequence.value(),
                 static_cast<std::uint64_t>(kSnapshots));
    NDO_CHECK(finding.evidence.front().source == Source("collector/a"));
  }
}

// ---------------------------------------------------------------------------
// 4. Report bounds
// ---------------------------------------------------------------------------

NDO_TEST(ReportMaxFindingsTruncatesAndFlagsTheReport) {
  Rig rig(SyntheticConfig());
  NDO_CHECK_STATUS(rig.observatory().Start());

  constexpr std::size_t kFindings = 7;
  NDO_CHECK_EQ(SeedUniformDrift(rig, kFindings), kFindings);

  ndo::ReportSpec spec;
  const auto report_id = ndo::ReportId::TryParse("report/scale");
  NDO_CHECK(report_id.has_value());
  if (report_id.has_value()) {
    spec.id = *report_id;
  }
  spec.include_timeline = false;
  spec.max_findings = 3;

  std::string json;
  NDO_CHECK_STATUS(ndo::BuildReportJson(rig.observatory(), spec, json));
  NDO_CHECK(!json.empty());

  ndo::Value root;
  NDO_CHECK_STATUS(ndo::ParseJson(json, ndo::RuntimeLimits{}, root));
  NDO_CHECK(JsonFlag(root, "truncated"));
  NDO_CHECK_EQ(JsonCount(root, "reported_findings"), std::size_t{3});
  // A truncated report still states how much exists behind the truncation.
  NDO_CHECK_EQ(JsonCount(root, "findings"), kFindings);
  const ndo::Value* listed = Member(root, "findings");
  NDO_CHECK(listed != nullptr);
  if (listed != nullptr && listed->as_list() != nullptr) {
    NDO_CHECK_EQ(listed->as_list()->size(), std::size_t{3});
  }

  spec.max_findings = 100;
  std::string full_json;
  NDO_CHECK_STATUS(ndo::BuildReportJson(rig.observatory(), spec, full_json));
  ndo::Value full_root;
  NDO_CHECK_STATUS(ndo::ParseJson(full_json, ndo::RuntimeLimits{}, full_root));
  NDO_CHECK(!JsonFlag(full_root, "truncated"));
  NDO_CHECK_EQ(JsonCount(full_root, "reported_findings"), kFindings);
  NDO_CHECK_EQ(JsonCount(full_root, "findings"), kFindings);
  const ndo::Value* full_listed = Member(full_root, "findings");
  NDO_CHECK(full_listed != nullptr);
  if (full_listed != nullptr && full_listed->as_list() != nullptr) {
    NDO_CHECK_EQ(full_listed->as_list()->size(), kFindings);
  }
}

// ---------------------------------------------------------------------------
// 5. Query bounds
// ---------------------------------------------------------------------------

NDO_TEST(QueryBoundsRefuseZeroLimitAndKeepPagesStable) {
  Rig rig(SyntheticConfig());
  NDO_CHECK_STATUS(rig.observatory().Start());

  constexpr std::size_t kFindings = 7;
  NDO_CHECK_EQ(SeedUniformDrift(rig, kFindings), kFindings);

  // A limit that would hide everything is refused rather than answered.
  ndo::QuerySpec zero;
  zero.limit = 0;
  const ndo::Result<ndo::QueryResult> refused = rig.observatory().Query(zero);
  NDO_CHECK(!refused.ok());
  NDO_CHECK_REFUSED(refused.status(), ndo::ReasonCode::LimitFindingsExceeded);

  ndo::TimelineSpec zero_timeline;
  zero_timeline.limit = 0;
  const ndo::Result<ndo::TimelinePage> refused_timeline =
      rig.observatory().QueryTimeline(zero_timeline);
  NDO_CHECK(!refused_timeline.ok());
  NDO_CHECK_REFUSED(refused_timeline.status(), ndo::ReasonCode::LimitTimelineExceeded);

  ndo::QuerySpec page_spec;
  page_spec.limit = 3;
  page_spec.order = ndo::QueryOrder::IdentityAscending;
  const ndo::Result<ndo::QueryResult> first = rig.observatory().Query(page_spec);
  NDO_CHECK(first.ok());
  if (!first.ok()) {
    return;
  }
  NDO_CHECK_EQ(first.value().total_matched, kFindings);
  NDO_CHECK_EQ(first.value().findings.size(), std::size_t{3});
  NDO_CHECK(first.value().truncated);
  NDO_CHECK_EQ(first.value().spec.limit, std::size_t{3});

  // The same request produces the same page, digest included.
  const ndo::Result<ndo::QueryResult> repeat = rig.observatory().Query(page_spec);
  NDO_CHECK(repeat.ok());
  if (repeat.ok()) {
    NDO_CHECK_EQ(repeat.value().total_matched, kFindings);
    NDO_CHECK_EQ(repeat.value().findings.size(), first.value().findings.size());
    NDO_CHECK(repeat.value().page_digest == first.value().page_digest);
    for (std::size_t index = 0; index < repeat.value().findings.size(); ++index) {
      NDO_CHECK(repeat.value().findings[index].id == first.value().findings[index].id);
    }
  }

  ndo::QuerySpec next_spec = page_spec;
  next_spec.offset = 3;
  const ndo::Result<ndo::QueryResult> next = rig.observatory().Query(next_spec);
  NDO_CHECK(next.ok());
  if (next.ok()) {
    NDO_CHECK_EQ(next.value().total_matched, kFindings);
    NDO_CHECK_EQ(next.value().findings.size(), std::size_t{3});
    NDO_CHECK(next.value().truncated);
    NDO_CHECK(!(next.value().page_digest == first.value().page_digest));
  }

  ndo::QuerySpec whole_spec = page_spec;
  whole_spec.limit = 100;
  const ndo::Result<ndo::QueryResult> whole = rig.observatory().Query(whole_spec);
  NDO_CHECK(whole.ok());
  if (!whole.ok()) {
    return;
  }
  NDO_CHECK_EQ(whole.value().total_matched, kFindings);
  NDO_CHECK_EQ(whole.value().findings.size(), kFindings);
  NDO_CHECK(!whole.value().truncated);
  if (whole.value().findings.size() == kFindings && first.value().findings.size() == 3) {
    for (std::size_t index = 0; index < 3; ++index) {
      NDO_CHECK(whole.value().findings[index].id == first.value().findings[index].id);
    }
  }
}

// ---------------------------------------------------------------------------
// 6. One huge value inside the envelope
// ---------------------------------------------------------------------------

constexpr std::size_t kValueDepth = 12;
constexpr std::size_t kRampAtEachLevel = 100;
constexpr std::size_t kTailLeaves = 64;
constexpr std::size_t kNoFlip = kValueDepth + 1;

/// A large nested value: twelve levels of members, each carrying a hundred-leaf
/// sequence, a fat string and the next level. `flip_level` selects the single
/// level whose first ramp leaf differs, so two trees built with different
/// arguments are identical except for exactly one scalar.
ndo::Value HugeValue(std::size_t flip_level) {
  ndo::Value::List tail;
  for (std::size_t index = 0; index < kTailLeaves; ++index) {
    tail.push_back(ndo::Value::MakeInt(static_cast<std::int64_t>(index)));
  }
  ndo::Value current = ndo::Value::MakeList(std::move(tail));
  for (std::size_t level = 0; level < kValueDepth; ++level) {
    ndo::Value::List ramp;
    for (std::size_t index = 0; index < kRampAtEachLevel; ++index) {
      std::int64_t leaf = static_cast<std::int64_t>(level * kRampAtEachLevel + index);
      if (index == 0 && level == flip_level) {
        leaf = -1;
      }
      ramp.push_back(ndo::Value::MakeInt(leaf));
    }
    ndo::Value::Map members;
    members.emplace("label",
                    ndo::Value::MakeString(std::string(256, static_cast<char>('a' + level % 26))));
    members.emplace("ramp", ndo::Value::MakeList(std::move(ramp)));
    members.emplace("child", std::move(current));
    current = ndo::Value::MakeMap(std::move(members));
  }
  return current;
}

NDO_TEST(DeepValueInsideTheEnvelopeComparesAtTheRightPath) {
  const ndo::RuntimeLimits limits;
  const ndo::Value intended_value = HugeValue(kNoFlip);
  const ndo::Value identical_value = HugeValue(kNoFlip);
  const ndo::Value one_leaf_different = HugeValue(5);

  NDO_CHECK(intended_value == identical_value);
  NDO_CHECK(!(intended_value == one_leaf_different));
  NDO_CHECK_EQ(one_leaf_different.NodeCount(), intended_value.NodeCount());
  NDO_CHECK_STATUS(intended_value.Validate(limits));
  NDO_CHECK(intended_value.NodeCount() <= limits.max_value_nodes);
  NDO_CHECK(intended_value.MaxDepth() <= limits.max_value_depth);
  NDO_CHECK(ndo::RelateValues(intended_value, identical_value, ndo::NumericEquivalence::Exact) ==
            ndo::ValueRelation::Equal);
  NDO_CHECK(ndo::RelateValues(intended_value, one_leaf_different,
                              ndo::NumericEquivalence::Exact) == ndo::ValueRelation::Different);

  Rig rig(SyntheticConfig());
  NDO_CHECK_STATUS(rig.observatory().Start());

  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "svc/alpha", "profile", intended_value);
  AddIntentObject(intent, "svc/beta", "profile", intended_value);
  NDO_CHECK_STATUS(rig.Commit(intent));
  NDO_CHECK_EQ(intent.FieldCount(), std::size_t{2});

  // An identical observation of the huge tree produces no finding at all.
  ndo::ObservationSnapshot matching = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(1000));
  AddObservedObject(matching, "svc/alpha", "profile", identical_value);
  AddObservedObject(matching, "svc/beta", "profile", identical_value);
  SealSnapshot(matching);
  NDO_CHECK_STATUS(rig.Observe(std::move(matching)));
  rig.SetClock(FixedTime(1000));
  const ndo::Result<ndo::EvaluationOutcome> matching_outcome =
      rig.observatory().EvaluateAt(FixedTime(1000), true);
  NDO_CHECK(matching_outcome.ok());
  if (!matching_outcome.ok()) {
    return;
  }
  NDO_CHECK_EQ(matching_outcome.value().DraftCount(), std::size_t{0});
  NDO_CHECK_EQ(rig.observatory().Stats().findings, std::size_t{0});
  if (matching_outcome.value().targets.size() == 1) {
    NDO_CHECK(matching_outcome.value().targets.front().compliance_decidable);
    NDO_CHECK(matching_outcome.value().targets.front().compliant);
  }

  // One leaf difference inside the tree is exactly one finding, at the managed
  // field path that holds the tree.
  ndo::ObservationSnapshot drifting = MakeSnapshot("collector/a", "switch/1", 2, FixedTime(1001));
  AddObservedObject(drifting, "svc/alpha", "profile", identical_value);
  AddObservedObject(drifting, "svc/beta", "profile", one_leaf_different);
  SealSnapshot(drifting);
  NDO_CHECK_STATUS(rig.Observe(std::move(drifting)));
  rig.SetClock(FixedTime(1001));
  const ndo::Result<ndo::EvaluationOutcome> drifting_outcome =
      rig.observatory().EvaluateAt(FixedTime(1001), true);
  NDO_CHECK(drifting_outcome.ok());
  if (!drifting_outcome.ok()) {
    return;
  }
  NDO_CHECK_EQ(drifting_outcome.value().DraftCount(), std::size_t{1});
  if (drifting_outcome.value().targets.size() == 1) {
    const ndo::TargetEvaluation& evaluation = drifting_outcome.value().targets.front();
    NDO_CHECK_EQ(evaluation.drafts.size(), std::size_t{1});
    if (evaluation.drafts.size() == 1) {
      const ndo::FindingDraft& draft = evaluation.drafts.front();
      NDO_CHECK(draft.object == Object("svc/beta"));
      NDO_CHECK_EQ(draft.path.ToText(), std::string("profile"));
      NDO_CHECK(draft.klass == ndo::DriftClass::ValueMismatch);
      NDO_CHECK(draft.reason == ndo::ReasonCode::ClassifiedValueMismatch);
      NDO_CHECK(draft.intended == intended_value);
      NDO_CHECK(draft.observed == one_leaf_different);
    }
  }

  const std::vector<ndo::Finding> findings = AllFindings(rig.observatory());
  NDO_CHECK_EQ(findings.size(), std::size_t{1});
  if (findings.size() != 1) {
    return;
  }
  const ndo::Finding& finding = findings.front();
  NDO_CHECK(finding.identity.object == Object("svc/beta"));
  NDO_CHECK_EQ(finding.identity.path.ToText(), std::string("profile"));
  NDO_CHECK(finding.klass == ndo::DriftClass::ValueMismatch);
  NDO_CHECK(finding.state == ndo::FindingState::Open);
  NDO_CHECK(finding.has_intended);
  NDO_CHECK(finding.has_observed);
  NDO_CHECK(finding.intended == intended_value);
  NDO_CHECK(finding.observed == one_leaf_different);
  NDO_CHECK(!(finding.intended == finding.observed));
  NDO_CHECK_EQ(finding.intended.NodeCount(), finding.observed.NodeCount());
  NDO_CHECK_EQ(rig.observatory().Stats().findings, std::size_t{1});
}

}  // namespace
