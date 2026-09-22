// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Ledger semantics: deduplication, resolution, reopening, suppression,
// acknowledgement, root-cause grouping and rebasing across generations.

#include <algorithm>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

using namespace ndotest;

namespace {

/// A deterministic observatory: the clock only moves when a test moves it.
class Rig {
 public:
  Rig() : observatory_(Config(), [this]() { return clock_; }) {
    NDO_CHECK_STATUS(observatory_.Start());
  }
  ~Rig() { observatory_.Stop(); }
  Rig(const Rig&) = delete;
  Rig& operator=(const Rig&) = delete;

  ndo::Observatory& observatory() { return observatory_; }
  void SetClock(ndo::NdoTime value) { clock_ = value; }

  void Commit(const ndo::IntentGenerationDocument& document) {
    ndo::IntentCommitReport report;
    NDO_CHECK_STATUS(observatory_.PublishIntent(document, report));
  }

  void Observe(ndo::ObservationSnapshot snapshot) {
    ndo::ObservationAdmission admission;
    NDO_CHECK_STATUS(observatory_.IngestObservation(std::move(snapshot), admission));
  }

  ndo::EvaluationOutcome Evaluate(ndo::NdoTime now) {
    const ndo::Result<ndo::EvaluationOutcome> outcome = observatory_.EvaluateAt(now, true);
    if (!outcome.ok()) {
      NDO_CHECK(false);
      return ndo::EvaluationOutcome{};
    }
    return outcome.value();
  }

  std::vector<ndo::Finding> Findings() {
    ndo::QuerySpec spec;
    spec.limit = 1000000;
    spec.include_resolved = true;
    spec.include_superseded = true;
    spec.include_retired = true;
    const ndo::Result<ndo::QueryResult> page = observatory_.Query(spec);
    if (!page.ok()) {
      NDO_CHECK(false);
      return {};
    }
    return page.value().findings;
  }

  std::vector<ndo::Finding> LiveFindings() {
    std::vector<ndo::Finding> live;
    for (const ndo::Finding& finding : Findings()) {
      if (ndo::IsLiveState(finding.state)) {
        live.push_back(finding);
      }
    }
    return live;
  }

  ndo::TimelinePage Timeline() {
    ndo::TimelineSpec spec;
    spec.limit = 1000000;
    const ndo::Result<ndo::TimelinePage> page = observatory_.QueryTimeline(spec);
    if (!page.ok()) {
      NDO_CHECK(false);
      return {};
    }
    return page.value();
  }

 private:
  static ndo::ObservatoryConfig Config() {
    ndo::ObservatoryConfig config;
    config.policy = SyntheticPolicy();
    config.epoch = ndo::FabricEpoch::FromValue(1);
    config.incarnation = ndo::Incarnation::FromValue(1);
    return config;
  }

  ndo::NdoTime clock_{FixedTime(1000)};
  ndo::Observatory observatory_;
};

ndo::IntentGenerationDocument Baseline(std::uint64_t generation) {
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", generation);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(intent, "port/eth1", "mtu", ndo::Value::MakeInt(1500));
  return intent;
}

ndo::ObservationSnapshot DriftingSnapshot(std::uint64_t sequence, ndo::NdoTime collected_at) {
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", sequence, collected_at);
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  AddObservedObject(snapshot, "port/eth1", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(snapshot);
  return snapshot;
}

ndo::ObservationSnapshot MatchingSnapshot(std::uint64_t sequence, ndo::NdoTime collected_at) {
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", sequence, collected_at);
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddObservedObject(snapshot, "port/eth1", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(snapshot);
  return snapshot;
}

const ndo::Finding* FindByPath(const std::vector<ndo::Finding>& findings, const std::string& path) {
  for (const ndo::Finding& finding : findings) {
    if (finding.identity.path.ToText() == path) {
      return &finding;
    }
  }
  return nullptr;
}

bool HasEvent(const ndo::Finding& finding, ndo::TimelineEventKind kind) {
  for (const ndo::TimelineEntry& entry : finding.timeline) {
    if (entry.kind == kind) {
      return true;
    }
  }
  return false;
}

}  // namespace

NDO_TEST(PersistentDriftUpdatesOneFinding) {
  Rig rig;
  rig.Commit(Baseline(1));
  rig.Observe(DriftingSnapshot(1, FixedTime(995)));
  const ndo::EvaluationOutcome first = rig.Evaluate(FixedTime(1000));
  NDO_CHECK_EQ(first.DraftCount(), std::size_t{1});

  std::vector<ndo::Finding> findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{1});
  const ndo::FindingId id = findings.front().id;
  NDO_CHECK_EQ(findings.front().observation_count, std::uint64_t{1});
  NDO_CHECK(findings.front().state == ndo::FindingState::Open);
  NDO_CHECK(findings.front().raw_class == ndo::DriftClass::ValueMismatch);
  NDO_CHECK(HasEvent(findings.front(), ndo::TimelineEventKind::Created));

  // Three further evaluations of the same drift must update, never duplicate.
  for (int index = 0; index < 3; ++index) {
    rig.SetClock(FixedTime(1000 + index + 1));
    const ndo::EvaluationOutcome outcome = rig.Evaluate(FixedTime(1000 + index + 1));
    NDO_CHECK_EQ(outcome.DraftCount(), std::size_t{1});
    findings = rig.Findings();
    NDO_CHECK_EQ(findings.size(), std::size_t{1});
    NDO_CHECK(findings.front().id == id);
  }
  findings = rig.Findings();
  NDO_CHECK_EQ(findings.front().observation_count, std::uint64_t{4});
  NDO_CHECK(findings.front().first_seen < findings.front().last_seen);
  NDO_CHECK_EQ(findings.front().reopen_count, std::uint64_t{0});

  // The finding identity is a pure function of its identity members.
  ndo::FindingIdentity identity;
  identity.target = Target("switch/1");
  identity.object = Object("port/eth0");
  identity.path = Path("mtu");
  identity.klass = ndo::DriftClass::ValueMismatch;
  identity.baseline_generation = ndo::IntentGeneration::FromValue(1);
  NDO_CHECK(identity.ComputeId() == id);
}

NDO_TEST(ResolutionRequiresFreshAgreementAndReopensOnReturn) {
  Rig rig;
  rig.Commit(Baseline(1));
  rig.Observe(DriftingSnapshot(1, FixedTime(995)));
  static_cast<void>(rig.Evaluate(FixedTime(1000)));
  NDO_CHECK_EQ(rig.LiveFindings().size(), std::size_t{1});

  // Fresh evidence that agrees resolves the finding.
  rig.Observe(MatchingSnapshot(2, FixedTime(1005)));
  static_cast<void>(rig.Evaluate(FixedTime(1010)));
  std::vector<ndo::Finding> findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{1});
  NDO_CHECK(findings.front().state == ndo::FindingState::Resolved);
  NDO_CHECK(findings.front().resolved_at.is_set());
  NDO_CHECK(HasEvent(findings.front(), ndo::TimelineEventKind::Resolved));
  NDO_CHECK(rig.LiveFindings().empty());

  // The drift returns: the same identity is reopened, not duplicated.
  rig.Observe(DriftingSnapshot(3, FixedTime(1015)));
  static_cast<void>(rig.Evaluate(FixedTime(1020)));
  findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{1});
  NDO_CHECK(findings.front().state == ndo::FindingState::Open);
  NDO_CHECK_EQ(findings.front().reopen_count, std::uint64_t{1});
  NDO_CHECK(HasEvent(findings.front(), ndo::TimelineEventKind::Reopened));
}

NDO_TEST(StaleEvidenceNeverResolvesAnOpenFinding) {
  Rig rig;
  rig.Commit(Baseline(1));
  // The only evidence is older than the policy lifetime.
  rig.Observe(DriftingSnapshot(1, FixedTime(100)));
  static_cast<void>(rig.Evaluate(FixedTime(1000)));
  std::vector<ndo::Finding> findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{1});
  NDO_CHECK(findings.front().klass == ndo::DriftClass::StaleObservation);
  const ndo::FindingId id = findings.front().id;

  // Time passes and the evidence stays stale: the finding must not be resolved
  // merely because no fresh evidence arrives.
  for (int index = 1; index <= 3; ++index) {
    const ndo::EvaluationOutcome outcome = rig.Evaluate(FixedTime(1000 + index * 10));
    NDO_CHECK_EQ(outcome.targets.front().compliance_decidable, false);
    findings = rig.Findings();
    NDO_CHECK_EQ(findings.size(), std::size_t{1});
    NDO_CHECK(findings.front().state == ndo::FindingState::Open);
    NDO_CHECK(findings.front().id == id);
    NDO_CHECK(!HasEvent(findings.front(), ndo::TimelineEventKind::Resolved));
  }
}

NDO_TEST(SuppressionNeverChangesComplianceTruth) {
  Rig rig;
  rig.Commit(Baseline(1));
  rig.Observe(DriftingSnapshot(1, FixedTime(995)));
  static_cast<void>(rig.Evaluate(FixedTime(1000)));
  const ndo::FindingId id = rig.Findings().front().id;
  const ndo::Value observed_before = rig.Findings().front().observed;

  NDO_CHECK_STATUS(rig.observatory().SuppressFinding(id, ndo::ActorId::TryParse("operator/alice").value(),
                                                    "change window", std::nullopt, FixedTime(1001)));
  std::vector<ndo::Finding> findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{1});
  NDO_CHECK(findings.front().state == ndo::FindingState::Suppressed);
  NDO_CHECK(findings.front().suppression.has_value());
  NDO_CHECK_EQ(findings.front().suppression_reason, std::string("change window"));
  // The evidence and the compliance truth are untouched by the suppression.
  NDO_CHECK(findings.front().has_observed);
  NDO_CHECK(findings.front().observed == observed_before);
  NDO_CHECK(findings.front().compliance_relevant);
  NDO_CHECK(!findings.front().evidence.empty());

  // Evaluation still reports the target as non-compliant while suppressed.
  const ndo::EvaluationOutcome outcome = rig.Evaluate(FixedTime(1002));
  NDO_CHECK(outcome.targets.front().compliance_decidable);
  NDO_CHECK(!outcome.targets.front().compliant);
  findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{1});
  NDO_CHECK(findings.front().state == ndo::FindingState::Suppressed);

  // Queries can hide suppressed findings, which changes reporting only.
  ndo::QuerySpec hidden;
  hidden.include_suppressed = false;
  const ndo::Result<ndo::QueryResult> page = rig.observatory().Query(hidden);
  NDO_CHECK(page.ok());
  NDO_CHECK_EQ(page.value().findings.size(), std::size_t{0});
  NDO_CHECK_EQ(page.value().total_matched, std::size_t{0});

  // Clearing restores the open state with all evidence intact.
  NDO_CHECK_STATUS(rig.observatory().ClearSuppression(
      id, ndo::ActorId::TryParse("operator/alice").value(), FixedTime(1003)));
  findings = rig.Findings();
  NDO_CHECK(findings.front().state == ndo::FindingState::Open);
  NDO_CHECK(!findings.front().suppression.has_value());
  NDO_CHECK(findings.front().observed == observed_before);
  NDO_CHECK(HasEvent(findings.front(), ndo::TimelineEventKind::SuppressionCleared));
}

NDO_TEST(PolicySuppressionAndExpiry) {
  Rig rig;
  ndo::ObservatoryPolicy policy = SyntheticPolicy();
  ndo::SuppressionRule rule;
  rule.id = ndo::SuppressionId::Trusted("suppression/window");
  rule.selector.target = Target("switch/1");
  rule.author = ndo::ActorId::Trusted("operator/bob");
  rule.reason = "planned maintenance";
  rule.created_at = FixedTime(900);
  rule.expires_at = FixedTime(1050);
  policy.suppressions.push_back(rule);
  NDO_CHECK_STATUS(rig.observatory().SetPolicy(policy, FixedTime(950)));

  rig.Commit(Baseline(1));
  rig.Observe(DriftingSnapshot(1, FixedTime(995)));
  static_cast<void>(rig.Evaluate(FixedTime(1000)));
  std::vector<ndo::Finding> findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{1});
  NDO_CHECK(findings.front().state == ndo::FindingState::Suppressed);
  NDO_CHECK(findings.front().suppression.has_value());
  NDO_CHECK(HasEvent(findings.front(), ndo::TimelineEventKind::Suppressed));

  // Past its expiry the suppression no longer applies and the finding is open.
  const std::size_t expired = rig.observatory().ExpireSuppressions(FixedTime(1060));
  NDO_CHECK_EQ(expired, std::size_t{1});
  findings = rig.Findings();
  NDO_CHECK(findings.front().state == ndo::FindingState::Open);
  NDO_CHECK(!findings.front().suppression.has_value());
  NDO_CHECK(HasEvent(findings.front(), ndo::TimelineEventKind::SuppressionExpired));
  NDO_CHECK_EQ(findings.front().suppression_reason, std::string(""));
}

NDO_TEST(AcknowledgementIsRecordedAndReversible) {
  Rig rig;
  rig.Commit(Baseline(1));
  rig.Observe(DriftingSnapshot(1, FixedTime(995)));
  static_cast<void>(rig.Evaluate(FixedTime(1000)));
  const ndo::FindingId id = rig.Findings().front().id;

  NDO_CHECK_STATUS(rig.observatory().AcknowledgeFinding(
      id, ndo::ActorId::TryParse("operator/carol").value(), "seen, ticket raised", FixedTime(1001)));
  std::vector<ndo::Finding> findings = rig.Findings();
  NDO_CHECK(findings.front().state == ndo::FindingState::Acknowledged);
  NDO_CHECK_EQ(findings.front().acknowledged_by.str(), std::string("operator/carol"));
  NDO_CHECK(findings.front().acknowledged_at.is_set());
  NDO_CHECK(ndo::IsLiveState(findings.front().state));
  NDO_CHECK(findings.front().compliance_relevant);
  NDO_CHECK(!rig.Evaluate(FixedTime(1002)).targets.front().compliant);

  NDO_CHECK_STATUS(rig.observatory().ClearAcknowledgement(
      id, ndo::ActorId::TryParse("operator/carol").value(), FixedTime(1003)));
  findings = rig.Findings();
  NDO_CHECK(findings.front().state == ndo::FindingState::Open);
  NDO_CHECK(findings.front().acknowledged_by.empty());

  // Unknown identities are refused, never silently accepted.
  const ndo::FindingId missing = ndo::FindingId::FromDigest(ndo::HashText("absent"));
  NDO_CHECK_REFUSED(rig.observatory().AcknowledgeFinding(
                        missing, ndo::ActorId::TryParse("operator/carol").value(), "x", FixedTime(1004)),
                    ndo::ReasonCode::FindingNotFound);
  NDO_CHECK_REFUSED(rig.observatory().SuppressFinding(missing, ndo::ActorId::TryParse("operator/carol").value(),
                                                      "x", std::nullopt, FixedTime(1004)),
                    ndo::ReasonCode::FindingNotFound);
}

NDO_TEST(RootCauseGroupingPreservesRawFindings) {
  Rig rig;
  rig.Commit(Baseline(1));
  // Both objects deviate because the applied generation is older.
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  for (const std::string& object : {std::string("port/eth0"), std::string("port/eth1")}) {
    AddObservedObject(snapshot, object, "mtu", ndo::Value::MakeInt(1400));
    snapshot.objects.find(Object(object))->second.fields.insert_or_assign(
        Path("@applied-generation"), ndo::Value::MakeInt(0));
  }
  SealSnapshot(snapshot);
  rig.Observe(snapshot);
  static_cast<void>(rig.Evaluate(FixedTime(1000)));

  std::vector<ndo::Finding> findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{2});
  for (const ndo::Finding& finding : findings) {
    NDO_CHECK(finding.klass == ndo::DriftClass::GenerationMismatch);
    NDO_CHECK(finding.group.is_set());
    NDO_CHECK(finding.group_cause == ndo::RootCauseKind::GenerationNotApplied);
  }
  NDO_CHECK(findings[0].group == findings[1].group);

  // The group itself is derived data, and it carries both members. The report
  // is the machine-readable view a downstream runtime would consume.
  ndo::ReportSpec spec;
  spec.id = ndo::ReportId::Trusted("report/group");
  std::string json;
  NDO_CHECK_STATUS(ndo::BuildReportJson(rig.observatory(), spec, json));
  ndo::Value report;
  NDO_CHECK_STATUS(ndo::ParseJson(json, ndo::RuntimeLimits{}, report));
  const ndo::Value::Map* report_root = report.as_map();
  NDO_CHECK(report_root != nullptr);
  if (report_root != nullptr) {
    const auto groups = report_root->find("root_cause_groups");
    NDO_CHECK(groups != report_root->end());
    if (groups != report_root->end()) {
      const ndo::Value::List* list = groups->second.as_list();
      NDO_CHECK(list != nullptr);
      if (list != nullptr) {
        NDO_CHECK_EQ(list->size(), std::size_t{1});
        const ndo::Value::Map* group = list->front().as_map();
        NDO_CHECK(group != nullptr);
        if (group != nullptr) {
          const auto members = group->find("members");
          const auto cause = group->find("cause");
          NDO_CHECK(members != group->end());
          NDO_CHECK(cause != group->end());
          if (members != group->end() && members->second.as_list() != nullptr) {
            NDO_CHECK_EQ(members->second.as_list()->size(), std::size_t{2});
          }
          if (cause != group->end() && cause->second.as_string() != nullptr) {
            NDO_CHECK_EQ(*cause->second.as_string(), std::string("generation-not-applied"));
          }
        }
      }
    }
  }

  // Resolving the drift removes the group; the raw findings keep their history.
  rig.Observe(MatchingSnapshot(2, FixedTime(1005)));
  static_cast<void>(rig.Evaluate(FixedTime(1010)));
  NDO_CHECK(rig.LiveFindings().empty());
  const ndo::LedgerStats stats = rig.observatory().Stats();
  NDO_CHECK_EQ(stats.groups, std::size_t{0});
  NDO_CHECK_EQ(stats.findings, std::size_t{2});
}

NDO_TEST(IntentGenerationChangeRebasesFindings) {
  Rig rig;
  rig.Commit(Baseline(1));
  rig.Observe(DriftingSnapshot(1, FixedTime(995)));
  static_cast<void>(rig.Evaluate(FixedTime(1000)));
  NDO_CHECK_EQ(rig.LiveFindings().size(), std::size_t{1});

  // A new generation arrives. Findings compared against the old baseline are
  // superseded, not silently re-based or left claiming to be current.
  rig.Commit(Baseline(2));
  std::vector<ndo::Finding> findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{1});
  NDO_CHECK(findings.front().state == ndo::FindingState::Superseded);
  NDO_CHECK(findings.front().reason == ndo::ReasonCode::FindingRebasedToNewGeneration);
  NDO_CHECK(HasEvent(findings.front(), ndo::TimelineEventKind::Rebased));
  NDO_CHECK(rig.LiveFindings().empty());

  // Under the new baseline the drift is re-derived as a new finding.
  static_cast<void>(rig.Evaluate(FixedTime(1010)));
  findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{2});
  const ndo::Finding* live = nullptr;
  for (const ndo::Finding& finding : findings) {
    if (ndo::IsLiveState(finding.state)) {
      live = &finding;
    }
  }
  NDO_CHECK(live != nullptr);
  if (live != nullptr) {
    NDO_CHECK_EQ(live->baseline_generation.value(), std::uint64_t{2});
    NDO_CHECK(live->klass == ndo::DriftClass::ValueMismatch);
  }
}

NDO_TEST(IntentGenerationThatWithdrawsAFieldRetiresTheFinding) {
  Rig rig;
  ndo::IntentGenerationDocument first = MakeIntent("switch/1", 1);
  AddIntentObject(first, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  AddIntentObject(first, "port/eth0", "description", ndo::Value::MakeString("uplink"));
  rig.Commit(first);
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  AddObservedObject(snapshot, "port/eth0", "description", ndo::Value::MakeString("wrong"));
  SealSnapshot(snapshot);
  rig.Observe(snapshot);
  static_cast<void>(rig.Evaluate(FixedTime(1000)));
  NDO_CHECK_EQ(rig.LiveFindings().size(), std::size_t{2});

  // The new generation still manages one field and no longer manages the other.
  ndo::IntentGenerationDocument second = MakeIntent("switch/1", 2);
  AddIntentObject(second, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  rig.Commit(second);

  std::vector<ndo::Finding> findings = rig.Findings();
  std::size_t superseded = 0;
  std::size_t retired = 0;
  for (const ndo::Finding& finding : findings) {
    if (finding.state == ndo::FindingState::Superseded) {
      ++superseded;
      NDO_CHECK_EQ(finding.identity.path.ToText(), std::string("mtu"));
    }
    if (finding.state == ndo::FindingState::Retired) {
      ++retired;
      NDO_CHECK_EQ(finding.identity.path.ToText(), std::string("description"));
      NDO_CHECK(finding.reason == ndo::ReasonCode::FindingRetired);
      NDO_CHECK(HasEvent(finding, ndo::TimelineEventKind::Retired));
      // The evidence of a retired finding is kept.
      NDO_CHECK(!finding.evidence.empty());
    }
  }
  NDO_CHECK_EQ(superseded, std::size_t{1});
  NDO_CHECK_EQ(retired, std::size_t{1});
  NDO_CHECK(rig.LiveFindings().empty());
}

NDO_TEST(FindingsRecordTheirRootCauseForFiltering) {
  Rig rig;
  rig.Commit(Baseline(1));
  rig.Observe(DriftingSnapshot(1, FixedTime(995)));
  static_cast<void>(rig.Evaluate(FixedTime(1000)));
  const std::vector<ndo::Finding> findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{1});
  NDO_CHECK(findings.front().group_cause == ndo::RootCauseKind::SingleField);
  NDO_CHECK(!findings.front().group.is_set());

  ndo::QuerySpec by_cause;
  by_cause.root_cause = ndo::RootCauseKind::SingleField;
  const ndo::Result<ndo::QueryResult> page = rig.observatory().Query(by_cause);
  NDO_CHECK(page.ok());
  NDO_CHECK_EQ(page.value().findings.size(), std::size_t{1});

  ndo::QuerySpec other_cause;
  other_cause.root_cause = ndo::RootCauseKind::SourceConflict;
  const ndo::Result<ndo::QueryResult> none = rig.observatory().Query(other_cause);
  NDO_CHECK(none.ok());
  NDO_CHECK_EQ(none.value().findings.size(), std::size_t{0});

  // The age accessor agrees with the recorded clock readings.
  NDO_CHECK(findings.front().AgeNanos(FixedTime(1010)) == 10LL * 1000000000LL);
}

NDO_TEST(ReclassificationSupersedesInsteadOfResolving) {
  Rig rig;
  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  rig.Commit(intent);
  ndo::ObservationSnapshot first = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  AddObservedObject(first, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  SealSnapshot(first);
  rig.Observe(first);
  static_cast<void>(rig.Evaluate(FixedTime(1000)));
  NDO_CHECK_EQ(rig.LiveFindings().size(), std::size_t{1});
  NDO_CHECK(rig.LiveFindings().front().klass == ndo::DriftClass::ValueMismatch);

  // The target now reports an older applied generation for the same field: the
  // same location, a different explanation. The old finding is superseded, not
  // declared resolved, because the drift never went away.
  ndo::ObservationSnapshot second = MakeSnapshot("collector/a", "switch/1", 2, FixedTime(1005));
  AddObservedObject(second, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  second.objects.find(Object("port/eth0"))->second.fields.insert_or_assign(
      Path("@applied-generation"), ndo::Value::MakeInt(0));
  SealSnapshot(second);
  rig.Observe(second);
  static_cast<void>(rig.Evaluate(FixedTime(1010)));

  std::vector<ndo::Finding> findings = rig.Findings();
  NDO_CHECK_EQ(findings.size(), std::size_t{2});
  const ndo::Finding* superseded = nullptr;
  const ndo::Finding* live = nullptr;
  for (const ndo::Finding& finding : findings) {
    if (finding.state == ndo::FindingState::Superseded) {
      superseded = &finding;
    }
    if (ndo::IsLiveState(finding.state)) {
      live = &finding;
    }
  }
  NDO_CHECK(superseded != nullptr);
  NDO_CHECK(live != nullptr);
  if (superseded != nullptr) {
    NDO_CHECK(superseded->reason == ndo::ReasonCode::FindingReclassified);
    NDO_CHECK(HasEvent(*superseded, ndo::TimelineEventKind::Reclassified));
    NDO_CHECK(!HasEvent(*superseded, ndo::TimelineEventKind::Resolved));
  }
  if (live != nullptr) {
    NDO_CHECK(live->klass == ndo::DriftClass::GenerationMismatch);
    NDO_CHECK(live->raw_class == ndo::DriftClass::ValueMismatch);
  }
}

NDO_TEST(FindingEnvelopeIsRefusedAllOrNothing) {
  ndo::ObservatoryConfig config;
  config.policy = SyntheticPolicy();
  config.epoch = ndo::FabricEpoch::FromValue(1);
  config.incarnation = ndo::Incarnation::FromValue(1);
  config.limits.max_findings = 1;
  ndo::Observatory observatory(config, []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());

  ndo::IntentCommitReport commit;
  NDO_CHECK_STATUS(observatory.PublishIntent(Baseline(1), commit));
  ndo::ObservationAdmission admission;
  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995));
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  AddObservedObject(snapshot, "port/eth1", "mtu", ndo::Value::MakeInt(9000));
  SealSnapshot(snapshot);
  NDO_CHECK_STATUS(observatory.IngestObservation(snapshot, admission));

  // Two findings are implied but the envelope allows one: nothing is applied.
  const ndo::Result<ndo::EvaluationOutcome> outcome = observatory.EvaluateAt(FixedTime(1000), true);
  NDO_CHECK_REFUSED(outcome.status(), ndo::ReasonCode::LimitFindingsExceeded);
  NDO_CHECK_EQ(observatory.Stats().findings, std::size_t{0});
  NDO_CHECK_EQ(observatory.Stats().groups, std::size_t{0});
  observatory.Stop();
}

NDO_TEST(GlobalTimelineIsOrderedAndFilterable) {
  Rig rig;
  rig.Commit(Baseline(1));
  rig.Observe(DriftingSnapshot(1, FixedTime(995)));
  static_cast<void>(rig.Evaluate(FixedTime(1000)));
  rig.Observe(MatchingSnapshot(2, FixedTime(1005)));
  static_cast<void>(rig.Evaluate(FixedTime(1010)));

  const ndo::TimelinePage timeline = rig.Timeline();
  // One intent-generation transition, one finding creation, one resolution.
  NDO_CHECK(timeline.entries.size() >= 3);
  NDO_CHECK_EQ(timeline.total_matched, timeline.entries.size());
  for (std::size_t index = 1; index < timeline.entries.size(); ++index) {
    NDO_CHECK(timeline.entries[index - 1].sequence < timeline.entries[index].sequence);
  }

  // Intent commits are timeline events in their own right.
  bool saw_create = false;
  bool saw_rebase = false;
  for (const ndo::TimelineEntry& entry : timeline.entries) {
    if (entry.kind == ndo::TimelineEventKind::Created && entry.target == Target("switch/1")) {
      saw_create = true;
    }
    if (entry.kind == ndo::TimelineEventKind::Rebased) {
      saw_rebase = true;
    }
  }
  NDO_CHECK(saw_create);
  NDO_CHECK(!saw_rebase);

  ndo::TimelineSpec spec;
  spec.kind = ndo::TimelineEventKind::Resolved;
  spec.limit = 10;
  const ndo::Result<ndo::TimelinePage> resolved = rig.observatory().QueryTimeline(spec);
  NDO_CHECK(resolved.ok());
  NDO_CHECK_EQ(resolved.value().total_matched, std::size_t{1});

  ndo::TimelineSpec zero;
  zero.limit = 0;
  NDO_CHECK_REFUSED(rig.observatory().QueryTimeline(zero).status(),
                    ndo::ReasonCode::LimitTimelineExceeded);
}
