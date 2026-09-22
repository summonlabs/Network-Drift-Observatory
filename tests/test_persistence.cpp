// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Versioned, integrity-checked persistence and conservative recovery.

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

using namespace ndotest;

namespace {

struct Seeded {
  ndo::IntentGenerationDocument intent;
  ndo::ObservationSnapshot snapshot;
};

Seeded Seed(ndo::Observatory& observatory, std::uint64_t generation = 1,
            std::int64_t observed_value = 9000, std::uint64_t epoch = 1) {
  Seeded seeded;
  seeded.intent = MakeIntent("switch/1", generation, epoch);
  AddIntentObject(seeded.intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  ndo::IntentCommitReport commit;
  NDO_CHECK_STATUS(observatory.PublishIntent(seeded.intent, commit));

  seeded.snapshot = MakeSnapshot("collector/a", "switch/1", 1, FixedTime(995), epoch);
  AddObservedObject(seeded.snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(observed_value));
  SealSnapshot(seeded.snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(observatory.IngestObservation(seeded.snapshot, admission));
  return seeded;
}

ndo::ObservatoryConfig Config(std::uint64_t incarnation = 1) {
  ndo::ObservatoryConfig config;
  config.policy = SyntheticPolicy();
  config.epoch = ndo::FabricEpoch::FromValue(1);
  config.incarnation = ndo::Incarnation::FromValue(incarnation);
  return config;
}

std::vector<std::uint8_t> ReadFile(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  std::vector<std::uint8_t> bytes;
  char chunk = 0;
  while (stream.get(chunk)) {
    bytes.push_back(static_cast<std::uint8_t>(chunk));
  }
  return bytes;
}

void WriteFile(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  for (std::uint8_t byte : bytes) {
    stream.put(static_cast<char>(byte));
  }
}

}  // namespace

NDO_TEST(LedgerRoundTripPreservesFindingsAndHistory) {
  const TempDir directory("persist_roundtrip");
  const std::string path = directory.File("ledger.ndo");

  {
    ndo::Observatory observatory(Config(), []() { return FixedTime(1000); });
    NDO_CHECK_STATUS(observatory.Start());
    static_cast<void>(Seed(observatory));
    NDO_CHECK(observatory.EvaluateAt(FixedTime(1000), true).ok());
    NDO_CHECK(observatory.EvaluateAt(FixedTime(1010), true).ok());
    NDO_CHECK_EQ(observatory.Stats().findings, std::size_t{1});
    NDO_CHECK_STATUS(observatory.Save(path));
    NDO_CHECK_STATUS(observatory.Stop());
  }

  {
    ndo::Observatory recovered(Config(2), []() { return FixedTime(2000); });
    ndo::LedgerRecoveryReport report;
    NDO_CHECK_STATUS(recovered.Load(path, report));
    NDO_CHECK_EQ(report.findings_restored, std::size_t{1});
    NDO_CHECK_EQ(report.observations_restored, std::size_t{1});
    NDO_CHECK_EQ(report.baselines_restored, std::size_t{1});
    NDO_CHECK(report.conservative);
    NDO_CHECK_STATUS(recovered.Start());

    ndo::QuerySpec spec;
    const ndo::Result<ndo::QueryResult> page = recovered.Query(spec);
    NDO_CHECK(page.ok());
    NDO_CHECK_EQ(page.value().findings.size(), std::size_t{1});
    if (!page.value().findings.empty()) {
      const ndo::Finding& finding = page.value().findings.front();
      NDO_CHECK(finding.klass == ndo::DriftClass::ValueMismatch);
      NDO_CHECK(finding.state == ndo::FindingState::Open);
      NDO_CHECK_EQ(finding.observation_count, std::uint64_t{2});
      NDO_CHECK(finding.has_observed);
      NDO_CHECK(finding.observed == ndo::Value::MakeInt(9000));
      NDO_CHECK(!finding.evidence.empty());
      // The finding survived, but its evidence is explicitly not fresh.
      NDO_CHECK(finding.evidence_freshness == ndo::FreshnessState::RecoveredNotFresh);
      NDO_CHECK(finding.timeline.size() >= 2);
    }

    // Evidence that survived the restart cannot support a compliance claim.
    const ndo::Result<ndo::EvaluationOutcome> outcome = recovered.EvaluateAt(FixedTime(2000), true);
    NDO_CHECK(outcome.ok());
    if (outcome.ok()) {
      NDO_CHECK(!outcome.value().targets.front().compliance_decidable);
      NDO_CHECK(!outcome.value().targets.front().compliant);
    }
    NDO_CHECK_STATUS(recovered.Stop());
  }
}

NDO_TEST(RecoveredEvidenceIsNeverFreshEvenWhenYoung) {
  const TempDir directory("persist_freshness");
  const std::string path = directory.File("ledger.ndo");

  ndo::Observatory first(Config(), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(first.Start());
  static_cast<void>(Seed(first));
  NDO_CHECK_STATUS(first.Save(path));
  NDO_CHECK_STATUS(first.Stop());

  // The restart happens one second later: the observation is still well inside
  // its time to live, but it survived a restart and is therefore not current.
  ndo::Observatory second(Config(2), []() { return FixedTime(1001); });
  ndo::LedgerRecoveryReport report;
  NDO_CHECK_STATUS(second.Load(path, report));
  NDO_CHECK_STATUS(second.Start());
  const ndo::Result<ndo::EvaluationOutcome> outcome = second.EvaluateAt(FixedTime(1001), true);
  NDO_CHECK(outcome.ok());
  if (outcome.ok()) {
    NDO_CHECK(outcome.value().targets.front().best_freshness ==
              ndo::FreshnessState::RecoveredNotFresh);
    NDO_CHECK(!outcome.value().targets.front().compliance_decidable);
  }
  NDO_CHECK_STATUS(second.Stop());
}

NDO_TEST(UnresolvedDriftSurvivesRestartAndReopensAfterResolution) {
  const TempDir directory("persist_reopen");
  const std::string path = directory.File("ledger.ndo");

  ndo::FindingId first_id;
  {
    ndo::Observatory observatory(Config(), []() { return FixedTime(1000); });
    NDO_CHECK_STATUS(observatory.Start());
    static_cast<void>(Seed(observatory));
    NDO_CHECK(observatory.EvaluateAt(FixedTime(1000), true).ok());
    ndo::QuerySpec spec;
    const ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
    NDO_CHECK(page.ok());
    first_id = page.value().findings.front().id;
    NDO_CHECK_STATUS(observatory.Save(path));
    NDO_CHECK_STATUS(observatory.Stop());
  }

  // After the restart the same drift is still open under the same identity.
  ndo::Observatory observatory(Config(2), []() { return FixedTime(2000); });
  ndo::LedgerRecoveryReport report;
  NDO_CHECK_STATUS(observatory.Load(path, report));
  NDO_CHECK_STATUS(observatory.Start());
  NDO_CHECK(observatory.EvaluateAt(FixedTime(2000), true).ok());
  ndo::QuerySpec spec;
  spec.include_resolved = true;
  spec.include_superseded = true;
  const auto find_by_id = [&](const ndo::QueryResult& result) -> const ndo::Finding* {
    for (const ndo::Finding& finding : result.findings) {
      if (finding.id == first_id) {
        return &finding;
      }
    }
    return nullptr;
  };
  ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
  NDO_CHECK(page.ok());
  // The drift survives with its own identity. The recovered evidence cannot
  // support a compliance decision, so an additional stale-evidence finding is
  // reported for the target; the original finding is untouched.
  const ndo::Finding* survivor = find_by_id(page.value());
  NDO_CHECK(survivor != nullptr);
  if (survivor != nullptr) {
    NDO_CHECK(survivor->state == ndo::FindingState::Open);
    NDO_CHECK(survivor->evidence_freshness == ndo::FreshnessState::RecoveredNotFresh);
  }

  // Fresh evidence that agrees resolves it, and the drift returning reopens the
  // same identity with an incremented reopen count.
  ndo::ObservationSnapshot matching =
      MakeSnapshot("collector/a", "switch/1", 2, FixedTime(2005));
  AddObservedObject(matching, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  SealSnapshot(matching);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(observatory.IngestObservation(matching, admission));
  NDO_CHECK(observatory.EvaluateAt(FixedTime(2010), true).ok());
  page = observatory.Query(spec);
  NDO_CHECK(page.ok());
  const ndo::Finding* resolved = find_by_id(page.value());
  NDO_CHECK(resolved != nullptr);
  if (resolved != nullptr) {
    NDO_CHECK(resolved->state == ndo::FindingState::Resolved);
  }

  ndo::ObservationSnapshot drifting =
      MakeSnapshot("collector/a", "switch/1", 3, FixedTime(2015));
  AddObservedObject(drifting, "port/eth0", "mtu", ndo::Value::MakeInt(9000));
  SealSnapshot(drifting);
  NDO_CHECK_STATUS(observatory.IngestObservation(drifting, admission));
  NDO_CHECK(observatory.EvaluateAt(FixedTime(2020), true).ok());
  page = observatory.Query(spec);
  NDO_CHECK(page.ok());
  const ndo::Finding* reopened = find_by_id(page.value());
  NDO_CHECK(reopened != nullptr);
  if (reopened != nullptr) {
    NDO_CHECK(reopened->state == ndo::FindingState::Open);
    NDO_CHECK_EQ(reopened->reopen_count, std::uint64_t{1});
    // The reopened finding is backed by fresh evidence again, not by the
    // recovered record.
    NDO_CHECK(reopened->evidence_freshness == ndo::FreshnessState::Fresh);
  }
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(SuppressionsSurviveRestartWithoutBeingRevoked) {
  const TempDir directory("persist_suppression");
  const std::string path = directory.File("ledger.ndo");
  ndo::FindingId suppressed_id;

  {
    ndo::Observatory observatory(Config(), []() { return FixedTime(1000); });
    NDO_CHECK_STATUS(observatory.Start());
    static_cast<void>(Seed(observatory));
    NDO_CHECK(observatory.EvaluateAt(FixedTime(1000), true).ok());
    ndo::QuerySpec spec;
    const ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
    NDO_CHECK(page.ok());
    suppressed_id = page.value().findings.front().id;
    NDO_CHECK_STATUS(observatory.SuppressFinding(
        suppressed_id, ndo::ActorId::TryParse("operator/dana").value(),
        "approved window", std::nullopt, FixedTime(1001)));
    NDO_CHECK_STATUS(observatory.Save(path));
    NDO_CHECK_STATUS(observatory.Stop());
  }

  ndo::Observatory observatory(Config(2), []() { return FixedTime(2000); });
  ndo::LedgerRecoveryReport report;
  NDO_CHECK_STATUS(observatory.Load(path, report));
  NDO_CHECK_STATUS(observatory.Start());
  const auto find_suppressed = [&](const ndo::QueryResult& result) -> const ndo::Finding* {
    for (const ndo::Finding& finding : result.findings) {
      if (finding.id == suppressed_id) {
        return &finding;
      }
    }
    return nullptr;
  };

  ndo::QuerySpec spec;
  ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
  NDO_CHECK(page.ok());
  const ndo::Finding* recovered_finding = find_suppressed(page.value());
  NDO_CHECK(recovered_finding != nullptr);
  if (recovered_finding != nullptr) {
    NDO_CHECK(recovered_finding->state == ndo::FindingState::Suppressed);
    NDO_CHECK(recovered_finding->suppression.has_value());
    NDO_CHECK_EQ(recovered_finding->suppression_reason, std::string("approved window"));
  }

  // An operator suppression is not revoked by an evaluation that follows the
  // restart, even though that evaluation can only produce stale-evidence
  // findings from the recovered observations.
  NDO_CHECK(observatory.EvaluateAt(FixedTime(2000), true).ok());
  page = observatory.Query(spec);
  NDO_CHECK(page.ok());
  recovered_finding = find_suppressed(page.value());
  NDO_CHECK(recovered_finding != nullptr);
  if (recovered_finding != nullptr) {
    NDO_CHECK(recovered_finding->state == ndo::FindingState::Suppressed);
    NDO_CHECK_EQ(recovered_finding->suppression_reason, std::string("approved window"));
  }
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(CorruptLedgersAreRefusedWithoutPartialRecovery) {
  const TempDir directory("persist_corrupt");
  const std::string good = directory.File("good.ndo");

  {
    ndo::Observatory observatory(Config(), []() { return FixedTime(1000); });
    NDO_CHECK_STATUS(observatory.Start());
    static_cast<void>(Seed(observatory));
    NDO_CHECK(observatory.EvaluateAt(FixedTime(1000), true).ok());
    NDO_CHECK_STATUS(observatory.Save(good));
    NDO_CHECK_STATUS(observatory.Stop());
  }
  const std::vector<std::uint8_t> bytes = ReadFile(good);
  NDO_CHECK(bytes.size() > 100);

  const auto attempt = [&](const std::vector<std::uint8_t>& corrupted,
                           ndo::ReasonCode expected) {
    const std::string path = directory.File("corrupt.ndo");
    WriteFile(path, corrupted);
    ndo::Observatory observatory(Config(2), []() { return FixedTime(2000); });
    // The observatory already holds a finding of its own; a refused load must
    // leave it exactly as it was.
    NDO_CHECK_STATUS(observatory.Start());
    static_cast<void>(Seed(observatory, 1, 1234));
    NDO_CHECK(observatory.EvaluateAt(FixedTime(2000), true).ok());
    const std::size_t findings_before = observatory.Stats().findings;
    const ndo::Result<std::vector<std::uint8_t>> before = observatory.EncodeState();
    NDO_CHECK(before.ok());
    ndo::LedgerRecoveryReport report;
    const ndo::Status status = observatory.Load(path, report);
    NDO_CHECK(!status.ok());
    NDO_CHECK_EQ(std::string(ndo::ToText(status.reason)), std::string(ndo::ToText(expected)));
    NDO_CHECK_EQ(observatory.Stats().findings, findings_before);
    const ndo::Result<std::vector<std::uint8_t>> after = observatory.EncodeState();
    NDO_CHECK(after.ok());
    NDO_CHECK(after.value() == before.value());
    NDO_CHECK_STATUS(observatory.Stop());
  };

  // A flipped byte inside the payload fails the integrity digest.
  std::vector<std::uint8_t> flipped = bytes;
  flipped[flipped.size() / 2] = static_cast<std::uint8_t>(flipped[flipped.size() / 2] ^ 0x40);
  attempt(flipped, ndo::ReasonCode::LedgerIntegrityDigestMismatch);

  // A corrupted magic is refused before anything else is read.
  std::vector<std::uint8_t> magic = bytes;
  magic[1] = static_cast<std::uint8_t>('X');
  attempt(magic, ndo::ReasonCode::LedgerHeaderInvalid);

  // A truncated file is refused.
  std::vector<std::uint8_t> truncated(bytes.begin(), bytes.begin() + bytes.size() / 2);
  attempt(truncated, ndo::ReasonCode::LedgerTruncated);

  // Trailing bytes beyond the declared payload are refused.
  std::vector<std::uint8_t> extended = bytes;
  extended.push_back(0x00);
  attempt(extended, ndo::ReasonCode::LedgerTruncated);

  // A future format version is refused rather than guessed at.
  std::vector<std::uint8_t> version = bytes;
  version[8] = 0x7F;
  attempt(version, ndo::ReasonCode::LedgerSchemaUnsupported);

  // A file that is shorter than a header is refused as truncated.
  std::vector<std::uint8_t> tiny(8, 0x5A);
  attempt(tiny, ndo::ReasonCode::LedgerTruncated);

  // A file that is long enough but is not a ledger at all.
  std::vector<std::uint8_t> noise(256, 0x5A);
  attempt(noise, ndo::ReasonCode::LedgerHeaderInvalid);
}

NDO_TEST(MissingLedgerFileIsReportedAsNotFound) {
  const TempDir directory("persist_missing");
  ndo::Observatory observatory(Config(), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::LedgerRecoveryReport report;
  const ndo::Status status = observatory.Load(directory.File("absent.ndo"), report);
  NDO_CHECK(!status.ok());
  NDO_CHECK(status.code == ndo::StatusCode::NotFound);
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(SavingReplacesThePreviousLedgerAtomically) {
  const TempDir directory("persist_replace");
  const std::string path = directory.File("ledger.ndo");

  ndo::Observatory observatory(Config(), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  static_cast<void>(Seed(observatory));
  NDO_CHECK(observatory.EvaluateAt(FixedTime(1000), true).ok());
  NDO_CHECK_STATUS(observatory.Save(path));
  const std::size_t first_size = ReadFile(path).size();
  NDO_CHECK(first_size > 0);

  // A second save with more content replaces the file and leaves no temporary
  // debris behind.
  ndo::IntentGenerationDocument second = MakeIntent("switch/2", 1);
  AddIntentObject(second, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  ndo::IntentCommitReport commit;
  NDO_CHECK_STATUS(observatory.PublishIntent(second, commit));
  NDO_CHECK_STATUS(observatory.Save(path));
  const std::vector<std::uint8_t> replaced = ReadFile(path);
  NDO_CHECK(replaced.size() > first_size);
  NDO_CHECK(!std::filesystem::exists(path + ".tmp"));

  // The replaced ledger decodes and carries both targets.
  ndo::Observatory recovered(Config(2), []() { return FixedTime(2000); });
  ndo::LedgerRecoveryReport report;
  NDO_CHECK_STATUS(recovered.Load(path, report));
  NDO_CHECK_EQ(report.baselines_restored, std::size_t{2});
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(LedgerWrittenByANewerEpochIsRefused) {
  const TempDir directory("persist_epoch");
  const std::string path = directory.File("ledger.ndo");

  ndo::ObservatoryConfig newer = Config();
  newer.epoch = ndo::FabricEpoch::FromValue(9);
  ndo::Observatory observatory(newer, []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  static_cast<void>(Seed(observatory, 1, 9000, 9));
  NDO_CHECK_STATUS(observatory.Save(path));
  NDO_CHECK_STATUS(observatory.Stop());

  ndo::Observatory older(Config(), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(older.Start());
  ndo::LedgerRecoveryReport report;
  const ndo::Status status = older.Load(path, report);
  NDO_CHECK(!status.ok());
  NDO_CHECK(status.reason == ndo::ReasonCode::LedgerVersionRegression);
  NDO_CHECK_STATUS(older.Stop());
}

NDO_TEST(EncodingIsCanonicalAcrossRounds) {
  ndo::Observatory observatory(Config(), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  static_cast<void>(Seed(observatory));
  NDO_CHECK(observatory.EvaluateAt(FixedTime(1000), true).ok());
  NDO_CHECK(observatory.EvaluateAt(FixedTime(1010), true).ok());

  const ndo::Result<std::vector<std::uint8_t>> first = observatory.EncodeState();
  NDO_CHECK(first.ok());
  ndo::FindingLedger decoded(observatory.limits());
  ndo::LedgerRecoveryReport report;
  NDO_CHECK_STATUS(ndo::DecodeLedger(first.value().data(), first.value().size(),
                                    observatory.limits(), ndo::FabricEpoch::FromValue(1), decoded,
                                    report));
  std::vector<std::uint8_t> reencoded;
  NDO_CHECK_STATUS(ndo::EncodeLedger(decoded, ndo::FabricEpoch::FromValue(1),
                                     ndo::Incarnation::FromValue(1), reencoded));
  // Recovery is deliberately conservative: the first round rewrites evidence
  // freshness and records the recovery, so it is not byte-identical to the
  // source ledger. It is however a fixed point: a second round changes nothing.
  NDO_CHECK(!(reencoded == first.value()));
  ndo::FindingLedger second_round(observatory.limits());
  ndo::LedgerRecoveryReport second_report;
  NDO_CHECK_STATUS(ndo::DecodeLedger(reencoded.data(), reencoded.size(), observatory.limits(),
                                     ndo::FabricEpoch::FromValue(1), second_round,
                                     second_report));
  std::vector<std::uint8_t> reencoded_twice;
  NDO_CHECK_STATUS(ndo::EncodeLedger(second_round, ndo::FabricEpoch::FromValue(1),
                                     ndo::Incarnation::FromValue(1), reencoded_twice));
  NDO_CHECK(reencoded_twice == reencoded);
  NDO_CHECK(second_round.ContentDigest() == decoded.ContentDigest());
  NDO_CHECK(decoded.ContentDigest().is_set());
  NDO_CHECK(decoded.revision().is_set());
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(TimelineGrowthIsBoundedAcrossManyEvaluations) {
  ndo::ObservatoryConfig config = Config();
  config.limits.max_global_timeline_entries = 32;
  config.limits.max_timeline_entries_per_finding = 8;
  ndo::Observatory observatory(config, []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  static_cast<void>(Seed(observatory));

  for (int iteration = 0; iteration < 60; ++iteration) {
    NDO_CHECK(observatory.EvaluateAt(FixedTime(1000 + iteration), true).ok());
  }
  const ndo::LedgerStats stats = observatory.Stats();
  NDO_CHECK(stats.timeline_entries <= config.limits.max_global_timeline_entries);
  ndo::QuerySpec spec;
  const ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
  NDO_CHECK(page.ok());
  NDO_CHECK_EQ(page.value().findings.size(), std::size_t{1});
  if (!page.value().findings.empty()) {
    NDO_CHECK(page.value().findings.front().timeline.size() <=
              config.limits.max_timeline_entries_per_finding);
    // History is trimmed, but the count of observations is not lost.
    NDO_CHECK_EQ(page.value().findings.front().observation_count, std::uint64_t{60});
  }
  NDO_CHECK_STATUS(observatory.Stop());
}
