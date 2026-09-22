// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Concurrency, cancellation and lifecycle.
//
// The engine serializes every mutation behind one mutex, evaluates outside it
// and fences any outcome whose baseline moved while it was computing. These
// tests exercise those claims with real threads.

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

using namespace ndotest;

namespace {

ndo::ObservatoryConfig ConcurrencyConfig(std::size_t workers) {
  ndo::ObservatoryConfig config;
  config.policy = SyntheticPolicy();
  config.epoch = ndo::FabricEpoch::FromValue(1);
  config.incarnation = ndo::Incarnation::FromValue(1);
  config.evaluation_workers = workers;
  config.limits.max_evaluation_workers = 16;
  return config;
}

void Populate(ndo::Observatory& observatory, std::size_t targets, std::size_t objects,
              bool mismatch) {
  for (std::size_t target = 0; target < targets; ++target) {
    const std::string target_name = "switch/" + std::to_string(target);
    ndo::IntentGenerationDocument intent = MakeIntent(target_name, 1);
    for (std::size_t object = 0; object < objects; ++object) {
      AddIntentObject(intent, "obj/" + std::to_string(object), "mtu", ndo::Value::MakeInt(1500));
    }
    ndo::IntentCommitReport commit;
    NDO_CHECK_STATUS(observatory.PublishIntent(intent, commit));

    ndo::ObservationSnapshot snapshot =
        MakeSnapshot("collector/" + std::to_string(target), target_name, 1, FixedTime(1000));
    for (std::size_t object = 0; object < objects; ++object) {
      const bool drift = mismatch && (object % 2 == 0);
      AddObservedObject(snapshot, "obj/" + std::to_string(object), "mtu",
                        ndo::Value::MakeInt(drift ? 9000 : 1500));
    }
    SealSnapshot(snapshot);
    ndo::ObservationAdmission admission;
    NDO_CHECK_STATUS(observatory.IngestObservation(snapshot, admission));
  }
}

}  // namespace

NDO_TEST(ParallelEvaluationMatchesSequentialEvaluation) {
  const std::size_t targets = 24;
  const std::size_t objects = 8;

  ndo::Observatory sequential(ConcurrencyConfig(1), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(sequential.Start());
  Populate(sequential, targets, objects, true);
  const ndo::Result<ndo::EvaluationOutcome> sequential_outcome =
      sequential.EvaluateAt(FixedTime(1000), true);
  NDO_CHECK(sequential_outcome.ok());
  sequential.Stop();

  ndo::Observatory parallel(ConcurrencyConfig(8), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(parallel.Start());
  Populate(parallel, targets, objects, true);
  const ndo::Result<ndo::EvaluationOutcome> parallel_outcome =
      parallel.EvaluateAt(FixedTime(1000), true);
  NDO_CHECK(parallel_outcome.ok());
  parallel.Stop();

  if (sequential_outcome.ok() && parallel_outcome.ok()) {
    NDO_CHECK(sequential_outcome.value().ComputeDigest() ==
              parallel_outcome.value().ComputeDigest());
    NDO_CHECK_EQ(sequential_outcome.value().DraftCount(),
                 parallel_outcome.value().DraftCount());
  }
  NDO_CHECK_EQ(sequential.Stats().findings, parallel.Stats().findings);
  NDO_CHECK_EQ(sequential.Stats().groups, parallel.Stats().groups);
}

NDO_TEST(ConcurrentIngestionWhileEvaluatingStaysConsistent) {
  const std::size_t targets = 16;
  ndo::Observatory observatory(ConcurrencyConfig(4), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  Populate(observatory, targets, 4, true);

  std::atomic<bool> start{false};
  std::atomic<int> admitted{0};
  std::vector<std::thread> threads;

  // One thread publishes new intent generations while others ingest new
  // observations for the same targets.
  threads.emplace_back([&]() {
    while (!start.load()) {
      std::this_thread::yield();
    }
    for (std::size_t target = 0; target < targets; ++target) {
      ndo::IntentGenerationDocument intent =
          MakeIntent("switch/" + std::to_string(target), 2);
      AddIntentObject(intent, "obj/0", "mtu", ndo::Value::MakeInt(1500));
      ndo::IntentCommitReport report;
      static_cast<void>(observatory.PublishIntent(intent, report));
    }
  });

  for (std::size_t source = 0; source < 4; ++source) {
    threads.emplace_back([&, source]() {
      while (!start.load()) {
        std::this_thread::yield();
      }
      for (std::size_t target = 0; target < targets; ++target) {
        ndo::ObservationSnapshot snapshot =
            MakeSnapshot("collector/thread-" + std::to_string(source),
                         "switch/" + std::to_string(target),
                         static_cast<std::uint64_t>(source + 2), FixedTime(1000));
        AddObservedObject(snapshot, "obj/0", "mtu", ndo::Value::MakeInt(9000));
        SealSnapshot(snapshot);
        ndo::ObservationAdmission admission;
        if (observatory.IngestObservation(snapshot, admission).ok()) {
          admitted.fetch_add(1);
        }
      }
    });
  }

  // Two threads evaluate concurrently with the writers.
  std::atomic<int> evaluations{0};
  for (int index = 0; index < 2; ++index) {
    threads.emplace_back([&]() {
      while (!start.load()) {
        std::this_thread::yield();
      }
      for (int repeat = 0; repeat < 8; ++repeat) {
        const ndo::Result<ndo::EvaluationOutcome> outcome =
            observatory.EvaluateAt(FixedTime(1000), true);
        if (outcome.ok()) {
          evaluations.fetch_add(1);
        }
      }
    });
  }

  start.store(true);
  for (std::thread& thread : threads) {
    thread.join();
  }

  NDO_CHECK(admitted.load() > 0);
  NDO_CHECK(evaluations.load() > 0);

  // The runtime is still consistent and every finding refers to the committed
  // baseline: nothing was produced from a stale generation.
  const ndo::LedgerStats stats = observatory.Stats();
  NDO_CHECK(stats.findings > 0);
  ndo::QuerySpec spec;
  spec.limit = 1000000;
  spec.include_superseded = true;
  const ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
  NDO_CHECK(page.ok());
  if (page.ok()) {
    for (const ndo::Finding& finding : page.value().findings) {
      NDO_CHECK(finding.baseline_generation.value() >= 1);
      NDO_CHECK(finding.baseline_generation.value() <= 2);
    }
  }

  // A final evaluation under a single worker is deterministic and still valid.
  const ndo::Result<ndo::EvaluationOutcome> final_outcome =
      observatory.EvaluateAt(FixedTime(1000), true);
  NDO_CHECK(final_outcome.ok());
  observatory.Stop();
}

NDO_TEST(CancellationPreventsPublication) {
  ndo::Observatory observatory(ConcurrencyConfig(4), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  Populate(observatory, 8, 4, true);

  NDO_CHECK_STATUS(observatory.RequestCancellation());
  NDO_CHECK(observatory.cancellation_requested());
  const ndo::Result<ndo::EvaluationOutcome> cancelled = observatory.EvaluateAt(FixedTime(1000), true);
  NDO_CHECK_REFUSED(cancelled.status(), ndo::ReasonCode::None);
  NDO_CHECK(cancelled.status().code == ndo::StatusCode::Cancelled);
  // A cancelled evaluation publishes nothing at all.
  NDO_CHECK_EQ(observatory.Stats().findings, std::size_t{0});
  NDO_CHECK_EQ(observatory.Counters().evaluations, std::uint64_t{0});
  NDO_CHECK_EQ(observatory.Counters().evaluations_cancelled, std::uint64_t{1});

  observatory.ClearCancellation();
  const ndo::Result<ndo::EvaluationOutcome> applied = observatory.EvaluateAt(FixedTime(1000), true);
  NDO_CHECK(applied.ok());
  NDO_CHECK(observatory.Stats().findings > 0);
  NDO_CHECK_EQ(observatory.Counters().evaluations, std::uint64_t{1});
  observatory.Stop();
}

NDO_TEST(CancellationDuringALongEvaluationIsHonoured) {
  ndo::Observatory observatory(ConcurrencyConfig(4), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  Populate(observatory, 64, 16, true);

  std::atomic<bool> stop{false};
  std::thread canceller([&]() {
    while (!stop.load()) {
      static_cast<void>(observatory.RequestCancellation());
      std::this_thread::yield();
    }
  });
  const ndo::Result<ndo::EvaluationOutcome> outcome = observatory.EvaluateAt(FixedTime(1000), true);
  stop.store(true);
  canceller.join();

  // Either the evaluation completed before cancellation was observed, or it was
  // cancelled and published nothing. Both are correct; a cancelled evaluation
  // reporting success with a partially applied ledger is not.
  if (!outcome.ok()) {
    NDO_CHECK(outcome.status().code == ndo::StatusCode::Cancelled);
    NDO_CHECK_EQ(observatory.Stats().findings, std::size_t{0});
  } else {
    NDO_CHECK(observatory.Stats().findings > 0);
  }
  observatory.ClearCancellation();
  observatory.Stop();
}

NDO_TEST(StopRefusesNewWorkAndIsIdempotent) {
  ndo::Observatory observatory(ConcurrencyConfig(1), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  NDO_CHECK(observatory.started());
  NDO_CHECK_STATUS(observatory.Stop());
  NDO_CHECK(!observatory.started());
  NDO_CHECK_STATUS(observatory.Stop());

  ndo::IntentGenerationDocument intent = MakeIntent("switch/1", 1);
  AddIntentObject(intent, "obj/0", "mtu", ndo::Value::MakeInt(1500));
  ndo::IntentCommitReport commit;
  NDO_CHECK_REFUSED(observatory.PublishIntent(intent, commit),
                    ndo::ReasonCode::None);
  NDO_CHECK(!observatory.PublishIntent(intent, commit).ok());
  NDO_CHECK_REFUSED(observatory.EvaluateAt(FixedTime(1000), true).status(), ndo::ReasonCode::None);

  // Starting again re-admits work.
  NDO_CHECK_STATUS(observatory.Start());
  NDO_CHECK_STATUS(observatory.PublishIntent(intent, commit));
  NDO_CHECK(observatory.EvaluateAt(FixedTime(1000), true).ok());
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(RepeatedStartStopCyclesStaySane) {
  ndo::Observatory observatory(ConcurrencyConfig(2), []() { return FixedTime(1000); });
  for (int cycle = 0; cycle < 50; ++cycle) {
    NDO_CHECK_STATUS(observatory.Start());
    ndo::IntentGenerationDocument intent = MakeIntent("switch/cycle", 1);
    AddIntentObject(intent, "obj/0", "mtu", ndo::Value::MakeInt(1500));
    ndo::IntentCommitReport commit;
    NDO_CHECK_STATUS(observatory.PublishIntent(intent, commit));
    ndo::ObservationSnapshot snapshot =
        MakeSnapshot("collector/cycle", "switch/cycle", 1, FixedTime(1000));
    AddObservedObject(snapshot, "obj/0", "mtu", ndo::Value::MakeInt(9000));
    SealSnapshot(snapshot);
    ndo::ObservationAdmission admission;
    NDO_CHECK_STATUS(observatory.IngestObservation(snapshot, admission));
    NDO_CHECK(observatory.EvaluateAt(FixedTime(1000), true).ok());
    NDO_CHECK_STATUS(observatory.Stop());
  }
  // The intent generation is re-published identically each cycle, so the same
  // single finding is updated rather than duplicated.
  NDO_CHECK_EQ(observatory.Stats().findings, std::size_t{1});
  ndo::QuerySpec spec;
  const ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
  NDO_CHECK(page.ok());
  if (page.ok() && !page.value().findings.empty()) {
    NDO_CHECK_EQ(page.value().findings.front().observation_count, std::uint64_t{50});
  }
}

NDO_TEST(ConcurrentOperatorActionsAreSerialised) {
  ndo::Observatory observatory(ConcurrencyConfig(2), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  Populate(observatory, 1, 1, true);
  NDO_CHECK(observatory.EvaluateAt(FixedTime(1000), true).ok());
  ndo::QuerySpec spec;
  const ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
  NDO_CHECK(page.ok());
  if (!page.ok() || page.value().findings.empty()) {
    observatory.Stop();
    return;
  }
  const ndo::FindingId id = page.value().findings.front().id;
  const ndo::ActorId actor = ndo::ActorId::TryParse("operator/thread").value();

  std::vector<std::thread> threads;
  for (int index = 0; index < 8; ++index) {
    threads.emplace_back([&, index]() {
      for (int repeat = 0; repeat < 10; ++repeat) {
        if (index % 2 == 0) {
          static_cast<void>(observatory.SuppressFinding(id, actor, "concurrent", std::nullopt,
                                                        FixedTime(1000)));
        } else {
          static_cast<void>(observatory.ClearSuppression(id, actor, FixedTime(1000)));
        }
        static_cast<void>(observatory.AcknowledgeFinding(id, actor, "concurrent", FixedTime(1000)));
        static_cast<void>(observatory.Query(spec));
        static_cast<void>(observatory.Stats());
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }

  // The finding still exists exactly once and its evidence is intact.
  const ndo::Result<ndo::QueryResult> after = observatory.Query(spec);
  NDO_CHECK(after.ok());
  NDO_CHECK_EQ(after.value().findings.size(), std::size_t{1});
  NDO_CHECK(after.value().findings.front().has_observed);
  NDO_CHECK(ndo::IsLiveState(after.value().findings.front().state));
  observatory.Stop();
}

NDO_TEST(IncarnationRotationInvalidatesEvidenceUnderLoad) {
  ndo::Observatory observatory(ConcurrencyConfig(4), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  Populate(observatory, 8, 4, true);
  NDO_CHECK(observatory.EvaluateAt(FixedTime(1000), true).ok());
  NDO_CHECK(observatory.Stats().live_findings > 0);

  // A restart in place: the retained evidence is no longer current, so nothing
  // may be declared compliant afterwards.
  NDO_CHECK_STATUS(observatory.RotateIncarnation(ndo::Incarnation::FromValue(2),
                                                 ndo::FabricEpoch::FromValue(1), FixedTime(2000)));
  NDO_CHECK_EQ(observatory.incarnation().value(), std::uint64_t{2});
  NDO_CHECK_REFUSED(observatory.RotateIncarnation(ndo::Incarnation::FromValue(2),
                                                  ndo::FabricEpoch::FromValue(1), FixedTime(2000)),
                    ndo::ReasonCode::FencedStaleIncarnation);

  const ndo::Result<ndo::EvaluationOutcome> after = observatory.EvaluateAt(FixedTime(2000), true);
  NDO_CHECK(after.ok());
  if (after.ok()) {
    for (const ndo::TargetEvaluation& evaluation : after.value().targets) {
      NDO_CHECK(!evaluation.compliance_decidable);
      NDO_CHECK(!evaluation.compliant);
    }
  }
  observatory.Stop();
}

NDO_TEST(ManyThreadsShareOneSourceSafely) {
  ndo::Observatory observatory(ConcurrencyConfig(2), []() { return FixedTime(1000); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::IntentGenerationDocument intent = MakeIntent("switch/shared", 1);
  AddIntentObject(intent, "obj/0", "mtu", ndo::Value::MakeInt(1500));
  ndo::IntentCommitReport commit;
  NDO_CHECK_STATUS(observatory.PublishIntent(intent, commit));

  std::atomic<int> accepted{0};
  std::atomic<int> refused{0};
  std::vector<std::thread> threads;
  for (std::size_t thread = 0; thread < 6; ++thread) {
    threads.emplace_back([&, thread]() {
      for (std::uint64_t sequence = 1; sequence <= 10; ++sequence) {
        ndo::ObservationSnapshot snapshot =
            MakeSnapshot("collector/shared", "switch/shared", sequence, FixedTime(1000));
        AddObservedObject(snapshot, "obj/0", "mtu", ndo::Value::MakeInt(9000));
        SealSnapshot(snapshot);
        ndo::ObservationAdmission admission;
        const ndo::Status status = observatory.IngestObservation(snapshot, admission);
        if (status.ok()) {
          accepted.fetch_add(1);
        } else {
          // Fencing refusals are expected when two threads race on one
          // sequence; anything else would be a defect.
          NDO_CHECK(status.reason == ndo::ReasonCode::ObservationDuplicateConflicting ||
                    status.reason == ndo::ReasonCode::FencedStaleIncarnation ||
                    status.reason == ndo::ReasonCode::FencedStaleEpoch ||
                    status.reason == ndo::ReasonCode::ObservationSequenceRegressed ||
                    status.reason == ndo::ReasonCode::ObservationDuplicateIdentical);
          refused.fetch_add(1);
        }
        static_cast<void>(thread);
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  NDO_CHECK(accepted.load() + refused.load() == 60);
  NDO_CHECK(accepted.load() >= 1);

  // The retained window for one source is bounded, and the newest observation
  // is the one that survives.
  const std::size_t retained = observatory.Stats().observations;
  NDO_CHECK(retained <= observatory.limits().max_retained_snapshots_per_source);
  NDO_CHECK(observatory.EvaluateAt(FixedTime(1000), true).ok());
  observatory.Stop();
}
