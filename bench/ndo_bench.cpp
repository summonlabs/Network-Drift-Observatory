// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// ndo_bench -- measures completed work.
//
// Every measurement counts finished operations (documents parsed, targets
// evaluated, findings written, ledgers encoded, frames coded) and reports the
// rate of completed work. Nothing here measures queue submission or enqueue
// latency, and nothing here counts work that was merely scheduled.
//
// Results are printed as a table of {workload, units, seconds, units/second}.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <summon/network_drift_observatory/engine.hpp>
#include <summon/network_drift_observatory/interchange.hpp>
#include <summon/network_drift_observatory/json.hpp>
#include <summon/network_drift_observatory/persistence.hpp>
#include <summon/network_drift_observatory/report.hpp>
#include <summon/network_drift_observatory/wire.hpp>

namespace ndo = summon::network_drift_observatory;

namespace {

struct Options {
  std::size_t targets{64};
  std::size_t objects{32};
  std::size_t repeats{3};
  std::size_t documents{2000};
  bool quick{false};
};

struct Measurement {
  std::string workload;
  std::string units;
  double seconds{0.0};
  double completed{0.0};
  double bytes{0.0};
};

std::vector<Measurement> g_measurements;

void Record(const std::string& workload, const std::string& units, double seconds, double completed,
            double bytes = 0.0) {
  Measurement measurement;
  measurement.workload = workload;
  measurement.units = units;
  measurement.seconds = seconds;
  measurement.completed = completed;
  measurement.bytes = bytes;
  g_measurements.push_back(measurement);
}

std::uint64_t NowNanos() {
  return static_cast<std::uint64_t>(ndo::SystemNow().unix_nanos);
}

ndo::NdoTime At(std::int64_t seconds) { return ndo::NdoTime::FromSeconds(seconds); }

ndo::ObservationSnapshot MakeSnapshot(const std::string& source, const std::string& target,
                                      std::uint64_t sequence, std::size_t objects,
                                      std::int64_t drift_value) {
  ndo::ObservationSnapshot snapshot;
  snapshot.source = ndo::SourceId::TryParse(source).value();
  snapshot.epoch = ndo::FabricEpoch::FromValue(1);
  snapshot.incarnation = ndo::Incarnation::FromValue(1);
  snapshot.sequence = ndo::SourceSequence::FromValue(sequence);
  snapshot.target = ndo::TargetId::TryParse(target).value();
  snapshot.collected_at = At(1000);
  snapshot.received_at = At(1000);
  snapshot.coverage = ndo::ObservationCoverage::Complete;
  snapshot.capabilities.asserts_absence = true;
  snapshot.capabilities.complete_coverage = true;
  snapshot.capabilities.reports_nested_paths = true;
  snapshot.evidence = ndo::EvidenceClass::Synthetic;
  for (std::size_t index = 0; index < objects; ++index) {
    const std::string id = "obj/" + std::to_string(index);
    ndo::ObservedObject object;
    object.id = ndo::ObjectId::TryParse(id).value();
    object.presence = ndo::ObjectPresence::Present;
    object.fields.emplace(ndo::FieldPath::TryParse("mtu", 8, 64).value(),
                          ndo::Value::MakeInt(drift_value));
    object.fields.emplace(ndo::FieldPath::TryParse("admin-up", 8, 64).value(),
                          ndo::Value::MakeBool(true));
    snapshot.objects.emplace(object.id, std::move(object));
  }
  snapshot.snapshot_id = snapshot.ComputeSnapshotId();
  return snapshot;
}

ndo::IntentGenerationDocument MakeIntent(const std::string& target, std::size_t objects) {
  ndo::IntentGenerationDocument document;
  document.target = ndo::TargetId::TryParse(target).value();
  document.generation = ndo::IntentGeneration::FromValue(1);
  document.epoch = ndo::FabricEpoch::FromValue(1);
  document.authority = ndo::IntentAuthority::IntentFabric;
  document.policy = ndo::PolicyId::Trusted("policy/default");
  document.authored_at = At(900);
  document.evidence = ndo::EvidenceClass::Synthetic;
  for (std::size_t index = 0; index < objects; ++index) {
    const std::string id = "obj/" + std::to_string(index);
    ndo::IntentObject object;
    object.id = ndo::ObjectId::TryParse(id).value();
    ndo::IntentField mtu;
    mtu.path = ndo::FieldPath::TryParse("mtu", 8, 64).value();
    mtu.intended = ndo::Value::MakeInt(1500);
    object.fields.emplace(mtu.path, mtu);
    ndo::IntentField admin;
    admin.path = ndo::FieldPath::TryParse("admin-up", 8, 64).value();
    admin.intended = ndo::Value::MakeBool(true);
    object.fields.emplace(admin.path, admin);
    document.objects.emplace(object.id, std::move(object));
  }
  return document;
}

void BenchmarkHash() {
  const std::string payload(4u * 1024u * 1024u, 'n');
  ndo::Digest accumulator;
  const std::uint64_t start = NowNanos();
  accumulator = ndo::HashBytes(payload.data(), payload.size());
  const double seconds = static_cast<double>(NowNanos() - start) / 1e9;
  Record("sha256", "MiB", seconds, 4.0, static_cast<double>(payload.size()));
  std::cout << "# sha256 accumulator " << accumulator.ToShortHex() << "\n";
}

void BenchmarkJson(const Options& options) {
  const std::size_t documents = options.quick ? options.documents / 4 : options.documents;
  std::vector<std::string> encoded;
  encoded.reserve(documents);
  std::size_t bytes = 0;
  for (std::size_t index = 0; index < documents; ++index) {
    const ndo::ObservationSnapshot snapshot = MakeSnapshot(
        "collector/bench", "bench/target/" + std::to_string(index % 16), index + 1,
        options.objects, 1500);
    const std::string text = ndo::WriteCanonicalJson(ndo::EncodeObservationDocument(snapshot));
    bytes += text.size();
    encoded.push_back(text);
  }
  ndo::RuntimeLimits limits;
  std::size_t parsed_ok = 0;
  ndo::Digest accumulator;
  const std::uint64_t start = NowNanos();
  for (const std::string& text : encoded) {
    ndo::ObservationSnapshot snapshot;
    if (ndo::ParseObservationJson(text, limits, snapshot).ok()) {
      ++parsed_ok;
      accumulator = snapshot.ComputeContentDigest();
    }
  }
  const double seconds = static_cast<double>(NowNanos() - start) / 1e9;
  Record("json-observation-parse", "documents", seconds, static_cast<double>(parsed_ok),
         static_cast<double>(bytes));
  std::cout << "# json accumulator " << accumulator.ToShortHex() << ", parsed " << parsed_ok
            << " of " << documents << "\n";
}

void BenchmarkEvaluation(const Options& options) {
  const std::size_t targets = options.quick ? options.targets / 4 : options.targets;
  ndo::ObservatoryConfig config;
  config.policy = ndo::ObservatoryPolicy::Default();
  config.policy.evidence = ndo::EvidenceClass::Synthetic;
  config.epoch = ndo::FabricEpoch::FromValue(1);
  config.incarnation = ndo::Incarnation::FromValue(1);
  config.evaluation_workers = 1;

  ndo::Observatory observatory(config, []() { return At(1000); });
  if (!observatory.Start().ok()) {
    std::cerr << "the benchmark observatory refused to start\n";
    std::exit(1);
  }
  for (std::size_t index = 0; index < targets; ++index) {
    const std::string target = "bench/target/" + std::to_string(index);
    ndo::IntentCommitReport commit;
    static_cast<void>(observatory.PublishIntent(MakeIntent(target, options.objects), commit));
    ndo::ObservationAdmission admission;
    // Half of the targets report a value that differs from intent.
    const std::int64_t value = (index % 2 == 0) ? 1500 : 9000;
    static_cast<void>(observatory.IngestObservation(
        MakeSnapshot("collector/bench", target, 1, options.objects, value), admission));
  }

  std::size_t findings = 0;
  ndo::Digest accumulator;
  const std::uint64_t start = NowNanos();
  for (std::size_t repeat = 0; repeat < options.repeats; ++repeat) {
    const ndo::Result<ndo::EvaluationOutcome> outcome = observatory.EvaluateAt(At(1000 + static_cast<std::int64_t>(repeat)), true);
    if (!outcome.ok()) {
      std::cerr << "benchmark evaluation failed\n";
      std::exit(1);
    }
    findings += outcome.value().DraftCount();
    accumulator = outcome.value().ComputeDigest();
  }
  const double seconds = static_cast<double>(NowNanos() - start) / 1e9;
  Record("evaluate-targets", "target-passes", seconds,
         static_cast<double>(targets * options.repeats));
  Record("evaluate-drafts", "findings", seconds, static_cast<double>(findings));
  std::cout << "# evaluation accumulator " << accumulator.ToShortHex() << ", drafts " << findings
            << ", ledger findings " << observatory.Stats().findings << "\n";

  // Query throughput over the resulting ledger.
  std::size_t matched = 0;
  const std::uint64_t query_start = NowNanos();
  for (std::size_t repeat = 0; repeat < options.repeats * 8; ++repeat) {
    ndo::QuerySpec spec;
    spec.min_severity = ndo::Severity::Low;
    spec.limit = 1000000;
    const ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
    if (page.ok()) {
      matched += page.value().findings.size();
    }
  }
  const double query_seconds = static_cast<double>(NowNanos() - query_start) / 1e9;
  Record("query-findings", "findings-returned", query_seconds, static_cast<double>(matched));

  // Report construction over the same ledger.
  const std::uint64_t report_start = NowNanos();
  std::size_t report_bytes = 0;
  for (std::size_t repeat = 0; repeat < options.repeats; ++repeat) {
    ndo::ReportSpec spec;
    spec.id = ndo::ReportId::Trusted("report/bench");
    std::string json;
    if (ndo::BuildReportJson(observatory, spec, json).ok()) {
      report_bytes += json.size();
    }
  }
  const double report_seconds = static_cast<double>(NowNanos() - report_start) / 1e9;
  Record("build-report", "reports", report_seconds, static_cast<double>(options.repeats),
         static_cast<double>(report_bytes));

  // Persistence: completed encode plus completed decode of the full ledger.
  std::size_t ledger_bytes = 0;
  ndo::Digest recovered;
  const std::uint64_t ledger_start = NowNanos();
  for (std::size_t repeat = 0; repeat < options.repeats; ++repeat) {
    const ndo::Result<std::vector<std::uint8_t>> encoded = observatory.EncodeState();
    if (!encoded.ok()) {
      std::cerr << "benchmark encode failed\n";
      std::exit(1);
    }
    ledger_bytes += encoded.value().size();
    ndo::FindingLedger decoded(config.limits);
    ndo::LedgerRecoveryReport recovery;
    const ndo::Status decoded_status =
        ndo::DecodeLedger(encoded.value().data(), encoded.value().size(), config.limits,
                          config.epoch, decoded, recovery);
    if (!decoded_status.ok()) {
      std::cerr << "benchmark decode failed: " << ndo::ToText(decoded_status.reason) << " ("
                << decoded_status.detail << "), bytes " << encoded.value().size() << "\n";
      std::exit(1);
    }
    recovered = decoded.ContentDigest();
  }
  const double ledger_seconds = static_cast<double>(NowNanos() - ledger_start) / 1e9;
  Record("ledger-round-trip", "ledgers", ledger_seconds, static_cast<double>(options.repeats),
         static_cast<double>(ledger_bytes));
  std::cout << "# ledger accumulator " << recovered.ToShortHex() << ", bytes " << ledger_bytes
            << "\n";

  // Frame coding: encode plus decode plus verify of every frame.
  std::size_t frames = 0;
  std::size_t frame_bytes = 0;
  const std::uint64_t frame_start = NowNanos();
  for (std::size_t repeat = 0; repeat < options.repeats * 16; ++repeat) {
    const ndo::ObservationSnapshot snapshot =
        MakeSnapshot("collector/bench", "bench/frame", repeat + 1, options.objects, 1500);
    const std::string text = ndo::WriteCanonicalJson(ndo::EncodeObservationDocument(snapshot));
    std::vector<std::uint8_t> frame;
    if (!ndo::EncodeFrame(ndo::FrameType::Snapshot, 0, repeat + 1, text, config.limits, frame)
             .ok()) {
      std::cerr << "benchmark frame encode failed\n";
      std::exit(1);
    }
    ndo::FrameHeader header;
    if (!ndo::DecodeFrameHeader(frame.data(), ndo::kFrameHeaderBytes, config.limits, header).ok()) {
      std::cerr << "benchmark frame decode failed\n";
      std::exit(1);
    }
    if (!ndo::VerifyFramePayload(header, frame.data() + ndo::kFrameHeaderBytes,
                                 frame.size() - ndo::kFrameHeaderBytes)
             .ok()) {
      std::cerr << "benchmark frame verify failed\n";
      std::exit(1);
    }
    ++frames;
    frame_bytes += frame.size();
  }
  const double frame_seconds = static_cast<double>(NowNanos() - frame_start) / 1e9;
  Record("frame-round-trip", "frames", frame_seconds, static_cast<double>(frames),
         static_cast<double>(frame_bytes));

  observatory.Stop();
}

void PrintResults() {
  std::cout << "\n" << std::left << std::setw(26) << "workload" << std::right << std::setw(20)
            << "units" << std::setw(12) << "seconds" << std::setw(20) << "units/second"
            << std::setw(14) << "MiB/second" << "\n";
  for (const Measurement& measurement : g_measurements) {
    const double rate = measurement.seconds > 0 ? measurement.completed / measurement.seconds : 0.0;
    const double throughput =
        measurement.seconds > 0 && measurement.bytes > 0
            ? (measurement.bytes / (1024.0 * 1024.0)) / measurement.seconds
            : 0.0;
    std::cout << std::left << std::setw(26) << measurement.workload << std::right << std::setw(20)
              << measurement.units << std::setw(12) << std::fixed << std::setprecision(4)
              << measurement.seconds << std::setw(20) << std::fixed << std::setprecision(1) << rate;
    if (measurement.bytes > 0) {
      std::cout << std::setw(14) << std::fixed << std::setprecision(1) << throughput;
    } else {
      std::cout << std::setw(14) << "-";
    }
    std::cout << "\n";
  }
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  for (int index = 1; index < argc; ++index) {
    const std::string name = argv[index];
    const auto value = [&]() -> std::string {
      return index + 1 < argc ? argv[++index] : std::string();
    };
    if (name == "--targets") {
      options.targets = static_cast<std::size_t>(std::stoull(value()));
    } else if (name == "--objects") {
      options.objects = static_cast<std::size_t>(std::stoull(value()));
    } else if (name == "--repeats") {
      options.repeats = static_cast<std::size_t>(std::stoull(value()));
    } else if (name == "--documents") {
      options.documents = static_cast<std::size_t>(std::stoull(value()));
    } else if (name == "--quick") {
      options.quick = true;
    } else {
      std::cerr << "usage: ndo_bench [--targets N] [--objects N] [--repeats N] [--documents N]"
                   " [--quick]\n";
      return 1;
    }
  }
  if (options.targets == 0 || options.objects == 0 || options.repeats == 0) {
    std::cerr << "targets, objects and repeats must be positive\n";
    return 1;
  }
  std::cout << "# Network Drift Observatory benchmark: targets=" << options.targets
            << " objects=" << options.objects << " repeats=" << options.repeats
            << " documents=" << options.documents << "\n";
  BenchmarkHash();
  BenchmarkJson(options);
  BenchmarkEvaluation(options);
  PrintResults();
  return 0;
}
