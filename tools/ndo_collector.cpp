// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// ndo_collector -- an observation source that publishes over the framed
// transport in its own operating-system process.
//
// The tool exists so that the transport, the epoch/incarnation fencing and the
// restart behaviour of the runtime can be exercised with real processes and a
// real TCP connection rather than with an in-memory double. It synthesizes
// snapshots deterministically from its arguments; it never contacts a device.
//
// Exit codes:
//   0  every snapshot was accepted
//   1  usage error, connection failure, or at least one refused snapshot

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "summon/network_drift_observatory/client.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/version.hpp"

namespace ndo = summon::network_drift_observatory;

namespace {

constexpr int kExitOk = 0;
constexpr int kExitFailure = 1;

void PrintUsage() {
  std::cout <<
      "ndo_collector -- publish synthetic observations over the framed transport\n"
      "usage: ndo_collector --port N --source S [options]\n"
      "\n"
      "  --host H              server address (default 127.0.0.1)\n"
      "  --port N              server port (required)\n"
      "  --source S            source identity (required)\n"
      "  --epoch N             fabric epoch (default 1)\n"
      "  --incarnation N       source incarnation (default 1)\n"
      "  --sequence-start N    first sequence number (default 1)\n"
      "  --sequence-step N     increment per snapshot (default 1, 0 repeats a number)\n"
      "  --target T            target identity (default switch/1)\n"
      "  --objects N           objects per snapshot (default 2)\n"
      "  --fields N            managed fields per object (default 2)\n"
      "  --value V             value written to mtu (default 1500)\n"
      "  --count N             snapshots to publish (default 1)\n"
      "  --interval-ms M       delay between snapshots (default 0)\n"
      "  --age-seconds S       backdate the collection time (default 0)\n"
      "  --applied-generation G  report the generation applied at the target\n"
      "  --coverage C          unknown|partial|complete (default complete)\n"
      "  --unobserved U        comma-separated object identities to declare unobserved\n"
      "  --asserts-absence     declare the absence capability\n"
      "  --complete-coverage   declare the complete-coverage capability\n"
      "  --nested              declare the nested-path capability\n"
      "  --ttl-nanos N         request a stricter time to live\n"
      "  --evidence E          real|synthetic (default synthetic)\n"
      "  --provenance TEXT     free-form provenance note\n"
      "  --quiet               publish silently, print only the summary\n"
      "  --flood N             send N identical snapshots without reading replies\n";
}

struct Options {
  std::string host{"127.0.0.1"};
  std::string source{"collector/a"};
  std::string target{"switch/1"};
  std::string value{"1500"};
  std::string coverage{"complete"};
  std::string unobserved;
  std::string evidence{"synthetic"};
  std::string provenance{"ndo_collector"};
  std::uint64_t epoch{1};
  std::uint64_t incarnation{1};
  std::uint64_t sequence_start{1};
  std::uint64_t sequence_step{1};
  std::uint64_t objects{2};
  std::uint64_t fields{2};
  std::uint64_t count{1};
  std::uint64_t interval_ms{0};
  std::uint64_t age_seconds{0};
  std::uint64_t flood{0};
  std::optional<std::uint64_t> applied_generation;
  std::int64_t ttl_nanos{0};
  std::uint16_t port{0};
  bool asserts_absence{false};
  bool complete_coverage{false};
  bool nested{false};
  bool quiet{false};
};

bool ParseOptions(int argc, char** argv, Options& options) {
  for (int index = 1; index < argc; ++index) {
    const std::string name = argv[index];
    if (name == "--help" || name == "-h") {
      PrintUsage();
      std::exit(kExitOk);
    }
    if (name == "--asserts-absence") {
      options.asserts_absence = true;
      continue;
    }
    if (name == "--complete-coverage") {
      options.complete_coverage = true;
      continue;
    }
    if (name == "--nested") {
      options.nested = true;
      continue;
    }
    if (name == "--quiet") {
      options.quiet = true;
      continue;
    }
    if (index + 1 >= argc) {
      std::cerr << "option requires a value: " << name << "\n";
      return false;
    }
    const std::string value = argv[++index];
    try {
      if (name == "--host") {
        options.host = value;
      } else if (name == "--source") {
        options.source = value;
      } else if (name == "--target") {
        options.target = value;
      } else if (name == "--value") {
        options.value = value;
      } else if (name == "--coverage") {
        options.coverage = value;
      } else if (name == "--unobserved") {
        options.unobserved = value;
      } else if (name == "--evidence") {
        options.evidence = value;
      } else if (name == "--provenance") {
        options.provenance = value;
      } else if (name == "--epoch") {
        options.epoch = std::stoull(value);
      } else if (name == "--incarnation") {
        options.incarnation = std::stoull(value);
      } else if (name == "--sequence-start") {
        options.sequence_start = std::stoull(value);
      } else if (name == "--sequence-step") {
        options.sequence_step = std::stoull(value);
      } else if (name == "--objects") {
        options.objects = std::stoull(value);
      } else if (name == "--fields") {
        options.fields = std::stoull(value);
      } else if (name == "--count") {
        options.count = std::stoull(value);
      } else if (name == "--interval-ms") {
        options.interval_ms = std::stoull(value);
      } else if (name == "--age-seconds") {
        options.age_seconds = std::stoull(value);
      } else if (name == "--applied-generation") {
        options.applied_generation = std::stoull(value);
      } else if (name == "--ttl-nanos") {
        options.ttl_nanos = std::stoll(value);
      } else if (name == "--port") {
        options.port = static_cast<std::uint16_t>(std::stoul(value));
      } else if (name == "--flood") {
        options.flood = std::stoull(value);
      } else {
        std::cerr << "unknown option: " << name << "\n";
        return false;
      }
    } catch (const std::exception&) {
      std::cerr << "option value is not a number: " << name << "\n";
      return false;
    }
  }
  if (options.port == 0 || options.source.empty()) {
    std::cerr << "--port and --source are required\n";
    return false;
  }
  return true;
}

std::vector<std::string> SplitCommas(const std::string& text) {
  std::vector<std::string> parts;
  std::string current;
  for (char c : text) {
    if (c == ',') {
      if (!current.empty()) {
        parts.push_back(current);
      }
      current.clear();
      continue;
    }
    current.push_back(c);
  }
  if (!current.empty()) {
    parts.push_back(current);
  }
  return parts;
}

ndo::Value ParseScalar(const std::string& text) {
  // Deterministic literal reading: a signed integer stays an integer, anything
  // else is a string. The observatory never coerces kinds silently.
  if (!text.empty() && (text.front() == '-' || (text.front() >= '0' && text.front() <= '9'))) {
    try {
      std::size_t consumed = 0;
      const long long parsed = std::stoll(text, &consumed);
      if (consumed == text.size()) {
        return ndo::Value::MakeInt(static_cast<std::int64_t>(parsed));
      }
    } catch (const std::exception&) {
      // fall through to a string value
    }
  }
  if (text == "true") {
    return ndo::Value::MakeBool(true);
  }
  if (text == "false") {
    return ndo::Value::MakeBool(false);
  }
  return ndo::Value::MakeString(text);
}

ndo::ObservationSnapshot BuildSnapshot(const Options& options, std::uint64_t sequence) {
  ndo::ObservationSnapshot snapshot;
  snapshot.source = ndo::SourceId::TryParse(options.source).value();
  snapshot.epoch = ndo::FabricEpoch::FromValue(options.epoch);
  snapshot.incarnation = ndo::Incarnation::FromValue(options.incarnation);
  snapshot.sequence = ndo::SourceSequence::FromValue(sequence);
  snapshot.target = ndo::TargetId::TryParse(options.target).value();
  snapshot.collected_at = ndo::NdoTime::FromNanos(ndo::SystemNow().unix_nanos -
                                                  static_cast<std::int64_t>(options.age_seconds) *
                                                      1000000000LL);
  snapshot.ttl_nanos = options.ttl_nanos;
  snapshot.capabilities.asserts_absence = options.asserts_absence;
  snapshot.capabilities.complete_coverage = options.complete_coverage;
  snapshot.capabilities.reports_nested_paths = options.nested;
  if (options.evidence == "real") {
    snapshot.evidence = ndo::EvidenceClass::Real;
    snapshot.capabilities.evidence = ndo::EvidenceClass::Real;
  } else {
    snapshot.evidence = ndo::EvidenceClass::Synthetic;
    snapshot.capabilities.evidence = ndo::EvidenceClass::Synthetic;
  }
  if (options.coverage == "complete") {
    snapshot.coverage = ndo::ObservationCoverage::Complete;
  } else if (options.coverage == "partial") {
    snapshot.coverage = ndo::ObservationCoverage::Partial;
  } else {
    snapshot.coverage = ndo::ObservationCoverage::Unknown;
  }
  for (const std::string& id : SplitCommas(options.unobserved)) {
    const auto parsed = ndo::ObjectId::TryParse(id);
    if (parsed.has_value()) {
      snapshot.unobserved.push_back(*parsed);
    }
  }
  for (std::uint64_t index = 0; index < options.objects; ++index) {
    const std::string id = "obj/" + std::to_string(index);
    const auto object_id = ndo::ObjectId::TryParse(id);
    if (!object_id.has_value()) {
      continue;
    }
    ndo::ObservedObject object;
    object.id = *object_id;
    object.presence = ndo::ObjectPresence::Present;
    const auto mtu_path = ndo::FieldPath::TryParse("mtu", 8, 64);
    const auto admin_path = ndo::FieldPath::TryParse("admin-up", 8, 64);
    const auto applied_path = ndo::FieldPath::TryParse("@applied-generation", 8, 64);
    if (mtu_path.has_value()) {
      object.fields.emplace(*mtu_path, ParseScalar(options.value));
    }
    if (admin_path.has_value()) {
      object.fields.emplace(*admin_path, ndo::Value::MakeBool(true));
    }
    for (std::uint64_t field = 0; field < options.fields; ++field) {
      const auto path = ndo::FieldPath::TryParse("extra/" + std::to_string(field), 8, 64);
      if (path.has_value()) {
        object.fields.emplace(*path, ndo::Value::MakeString(options.value));
      }
    }
    if (options.applied_generation.has_value() && applied_path.has_value()) {
      object.fields.emplace(*applied_path,
                            ndo::Value::MakeInt(static_cast<std::int64_t>(*options.applied_generation)));
    }
    snapshot.objects.emplace(object.id, std::move(object));
  }
  snapshot.snapshot_id = snapshot.ComputeSnapshotId();
  return snapshot;
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!ParseOptions(argc, argv, options)) {
    PrintUsage();
    return kExitFailure;
  }
  ndo::ClientConfig config;
  config.host = options.host;
  config.port = options.port;
  config.source = ndo::SourceId::TryParse(options.source).value();
  config.epoch = ndo::FabricEpoch::FromValue(options.epoch);
  config.incarnation = ndo::Incarnation::FromValue(options.incarnation);
  config.start_sequence = ndo::SourceSequence::FromValue(options.sequence_start);
  config.capabilities.asserts_absence = options.asserts_absence;
  config.capabilities.complete_coverage = options.complete_coverage;
  config.capabilities.reports_nested_paths = options.nested;
  config.capabilities.evidence = options.evidence == "real" ? ndo::EvidenceClass::Real
                                                            : ndo::EvidenceClass::Synthetic;
  config.provenance = options.provenance;

  ndo::ObservationPublisher publisher(config);
  const ndo::Status connected = publisher.Connect();
  if (!connected.ok()) {
    std::cout << "{\"connected\":false,\"reason\":\"" << ndo::ToText(connected.reason)
              << "\",\"detail\":\"" << connected.detail << "\"}\n";
    return kExitFailure;
  }
  if (!options.quiet) {
    std::cout << "{\"connected\":true,\"session\":" << publisher.handshake().session_id
              << ",\"server_epoch\":" << publisher.handshake().server_epoch.value()
              << ",\"server_incarnation\":" << publisher.handshake().server_incarnation.value()
              << "}\n";
  }

  std::uint64_t accepted = 0;
  std::uint64_t refused = 0;
  std::uint64_t sequence = options.sequence_start;
  for (std::uint64_t index = 0; index < options.count; ++index) {
    ndo::ObservationSnapshot snapshot = BuildSnapshot(options, sequence);
    ndo::AckPayload ack;
    const ndo::Status status = publisher.Publish(snapshot, ack);
    if (!status.ok()) {
      std::cout << "{\"published\":false,\"sequence\":" << sequence << ",\"reason\":\""
                << ndo::ToText(status.reason) << "\",\"detail\":\"" << status.detail << "\"}\n";
      ++refused;
    } else if (ack.accepted) {
      ++accepted;
      if (!options.quiet) {
        std::cout << "{\"published\":true,\"sequence\":" << sequence << ",\"snapshot\":\""
                  << ack.snapshot.str() << "\"}\n";
      }
    } else {
      ++refused;
      std::cout << "{\"published\":false,\"sequence\":" << sequence << ",\"reason\":\""
                << ndo::ToText(ack.reason) << "\",\"detail\":\"" << ack.detail << "\"}\n";
    }
    std::cout.flush();
    sequence += options.sequence_step;
    if (options.interval_ms > 0 && index + 1 < options.count) {
      std::this_thread::sleep_for(std::chrono::milliseconds(options.interval_ms));
    }
  }
  std::cout << "{\"summary\":true,\"accepted\":" << accepted << ",\"refused\":" << refused
            << ",\"source\":\"" << options.source << "\",\"incarnation\":"
            << options.incarnation << "}\n";
  publisher.Close();
  return refused == 0 ? kExitOk : kExitFailure;
}
