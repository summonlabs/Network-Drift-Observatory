// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// ndo_cli -- inspection and control surface for the Network Drift Observatory.
//
// The tool is observational: it can commit intent, admit observations, evaluate,
// query, explain, export a report and manage durable state. It never contacts a
// network device.
//
// Exit codes:
//   0  the command completed and the target state is compliant or undecided
//   1  usage error, or the runtime refused the operation
//   2  the command completed and at least one live actionable finding exists
//   3  the command completed and compliance could not be decided from evidence

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "summon/network_drift_observatory/engine.hpp"
#include "summon/network_drift_observatory/interchange.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/persistence.hpp"
#include "summon/network_drift_observatory/report.hpp"
#include "summon/network_drift_observatory/server.hpp"
#include "summon/network_drift_observatory/version.hpp"

namespace ndo = summon::network_drift_observatory;

namespace {

constexpr int kExitOk = 0;
constexpr int kExitUsage = 1;
constexpr int kExitActionableDrift = 2;
constexpr int kExitUndecidable = 3;

void PrintUsage() {
  std::cout <<
      "Network Drift Observatory " << ndo::kVersionString << "\n"
      "usage: ndo_cli <command> [options]\n"
      "\n"
      "commands:\n"
      "  version                            print the runtime version\n"
      "  policy-default [--out FILE]        print the default policy\n"
      "  intent-commit  --file FILE         commit an intent generation document\n"
      "  observe        --file FILE         admit an observation document\n"
      "  evaluate                           evaluate and apply the outcome\n"
      "  query          [filters]           list findings (JSON)\n"
      "  explain        --finding HEX       explain one finding\n"
      "  timeline       [filters]           list timeline entries\n"
      "  report         [--out FILE]        export a machine-readable report\n"
      "  suppress       --finding HEX --actor A --reason R [--hours N]\n"
      "  acknowledge    --finding HEX --actor A --reason R\n"
      "  stats                              print ledger statistics\n"
      "  serve          --port N [--once]   serve observation sessions\n"
      "\n"
      "common options:\n"
      "  --state FILE       load the ledger at start and save it before exit\n"
      "  --epoch N          fabric epoch (default 1)\n"
      "  --incarnation N    process incarnation (default 1)\n"
      "  --now UNIXSECONDS  evaluate at an explicit clock reading\n"
      "  --policy FILE      load an observatory policy document (JSON)\n"
      "  --evaluate         evaluate in the same process after the command\n"
      "  --json             emit compact JSON instead of indented JSON\n"
      "\n"
      "query filters:\n"
      "  --target T --object O --class C --severity S --min-severity S --state S\n"
      "  --generation N --group HEX --source S --min-freshness F --root-cause C\n"
      "  --min-age SECONDS --max-age SECONDS --limit N --offset N --order O\n"
      "  --include-resolved --include-superseded --include-retired\n"
      "  --exclude-suppressed\n";
}

struct Options {
  std::string command;
  std::string state_path;
  std::string file_path;
  std::string out_path;
  std::string policy_path;
  std::string target;
  std::string object;
  std::string drift_class;
  std::string severity;
  std::string min_severity;
  std::string state_filter;
  std::string order;
  std::string group;
  std::string source;
  std::string min_freshness;
  std::string root_cause;
  std::string finding;
  std::string actor;
  std::string reason;
  std::string task;
  std::string bind_address = "127.0.0.1";
  std::optional<std::uint64_t> generation;
  std::optional<std::int64_t> min_age_seconds;
  std::optional<std::int64_t> max_age_seconds;
  std::optional<std::int64_t> now_seconds;
  std::optional<double> hours;
  std::uint64_t epoch{1};
  std::uint64_t incarnation{1};
  std::uint16_t port{0};
  std::size_t limit{1000};
  std::size_t offset{0};
  bool compact{false};
  bool include_resolved{false};
  bool include_superseded{false};
  bool include_retired{false};
  bool include_suppressed{true};
  bool once{false};
  bool evaluate_after{false};
  bool help{false};
};

bool NeedsValue(std::string_view name) {
  return name == "--state" || name == "--file" || name == "--out" || name == "--policy" ||
         name == "--target" || name == "--object" || name == "--class" || name == "--severity" ||
         name == "--min-severity" || name == "--state-filter" || name == "--order" ||
         name == "--generation" || name == "--min-age" || name == "--max-age" || name == "--limit" ||
         name == "--offset" || name == "--group" || name == "--source" || name == "--min-freshness" ||
         name == "--root-cause" || name == "--finding" || name == "--actor" || name == "--reason" ||
         name == "--hours" || name == "--now" || name == "--epoch" || name == "--incarnation" ||
         name == "--port" || name == "--bind" || name == "--task";
}

bool ParseOptions(int argc, char** argv, Options& options) {
  if (argc < 2) {
    return false;
  }
  options.command = argv[1];
  for (int index = 2; index < argc; ++index) {
    const std::string name = argv[index];
    if (name == "--help" || name == "-h") {
      options.help = true;
      continue;
    }
    if (name == "--json") {
      options.compact = true;
      continue;
    }
    if (name == "--include-resolved") {
      options.include_resolved = true;
      continue;
    }
    if (name == "--include-superseded") {
      options.include_superseded = true;
      continue;
    }
    if (name == "--include-retired") {
      options.include_retired = true;
      continue;
    }
    if (name == "--exclude-suppressed") {
      options.include_suppressed = false;
      continue;
    }
    if (name == "--once") {
      options.once = true;
      continue;
    }
    if (name == "--evaluate") {
      options.evaluate_after = true;
      continue;
    }
    if (!NeedsValue(name)) {
      std::cerr << "unknown option: " << name << "\n";
      return false;
    }
    if (index + 1 >= argc) {
      std::cerr << "option requires a value: " << name << "\n";
      return false;
    }
    const std::string value = argv[++index];
    try {
      if (name == "--state") {
        options.state_path = value;
      } else if (name == "--file") {
        options.file_path = value;
      } else if (name == "--out") {
        options.out_path = value;
      } else if (name == "--policy") {
        options.policy_path = value;
      } else if (name == "--target") {
        options.target = value;
      } else if (name == "--object") {
        options.object = value;
      } else if (name == "--class") {
        options.drift_class = value;
      } else if (name == "--severity") {
        options.severity = value;
      } else if (name == "--min-severity") {
        options.min_severity = value;
      } else if (name == "--state-filter") {
        options.state_filter = value;
      } else if (name == "--order") {
        options.order = value;
      } else if (name == "--group") {
        options.group = value;
      } else if (name == "--source") {
        options.source = value;
      } else if (name == "--min-freshness") {
        options.min_freshness = value;
      } else if (name == "--root-cause") {
        options.root_cause = value;
      } else if (name == "--finding") {
        options.finding = value;
      } else if (name == "--actor") {
        options.actor = value;
      } else if (name == "--reason") {
        options.reason = value;
        } else if (name == "--task") {
        options.task = value;
      } else if (name == "--generation") {
        options.generation = std::stoull(value);
      } else if (name == "--min-age") {
        options.min_age_seconds = std::stoll(value);
      } else if (name == "--max-age") {
        options.max_age_seconds = std::stoll(value);
      } else if (name == "--now") {
        options.now_seconds = std::stoll(value);
      } else if (name == "--hours") {
        options.hours = std::stod(value);
      } else if (name == "--epoch") {
        options.epoch = std::stoull(value);
      } else if (name == "--incarnation") {
        options.incarnation = std::stoull(value);
      } else if (name == "--port") {
        options.port = static_cast<std::uint16_t>(std::stoul(value));
      } else if (name == "--bind") {
        options.bind_address = value;
      } else if (name == "--limit") {
        options.limit = static_cast<std::size_t>(std::stoull(value));
      } else if (name == "--offset") {
        options.offset = static_cast<std::size_t>(std::stoull(value));
      }
    } catch (const std::exception&) {
      std::cerr << "option value is not a number: " << name << " " << value << "\n";
      return false;
    }
  }
  return true;
}

bool ReadFile(const std::string& path, std::string& out) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return false;
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  out = buffer.str();
  return true;
}

bool WriteFile(const std::string& path, const std::string& text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return false;
  }
  stream << text;
  return static_cast<bool>(stream);
}

ndo::NdoTime ResolveNow(const Options& options) {
  if (options.now_seconds.has_value()) {
    return ndo::NdoTime::FromSeconds(*options.now_seconds);
  }
  return ndo::SystemNow();
}

int Report(const ndo::Status& status) {
  std::cerr << "refused: " << ndo::ToText(status.code) << " / " << ndo::ToText(status.reason);
  if (!status.detail.empty()) {
    std::cerr << " (" << status.detail << ")";
  }
  std::cerr << "\n";
  return kExitUsage;
}

void Print(const ndo::Value& value, bool compact) {
  if (compact) {
    std::cout << ndo::WriteCanonicalJson(value) << "\n";
    return;
  }
  std::cout << ndo::WritePrettyJson(value, 2) << "\n";
}

ndo::ObservatoryPolicy LoadPolicy(const Options& options, ndo::Status& status) {
  ndo::ObservatoryPolicy policy = ndo::ObservatoryPolicy::Default();
  policy.evidence = ndo::EvidenceClass::Synthetic;
  if (options.policy_path.empty()) {
    status = ndo::Status::Ok();
    return policy;
  }
  std::string text;
  if (!ReadFile(options.policy_path, text)) {
    status = ndo::Status::NotFound(ndo::ReasonCode::EncodingMalformed, "the policy file could not be read");
    return policy;
  }
  ndo::Value value;
  status = ndo::ParseJson(text, ndo::RuntimeLimits{}, value);
  if (!status.ok()) {
    return policy;
  }
  const ndo::Result<ndo::ObservatoryPolicy> decoded = [&]() -> ndo::Result<ndo::ObservatoryPolicy> {
    ndo::ObservatoryPolicy parsed;
    ndo::Status decode = ndo::DecodePolicy(value, ndo::RuntimeLimits{}, parsed);
    if (!decode.ok()) {
      return decode;
    }
    return parsed;
  }();
  if (!decoded.ok()) {
    status = decoded.status();
    return policy;
  }
  status = ndo::Status::Ok();
  return decoded.value();
}

ndo::QuerySpec BuildQuerySpec(const Options& options, ndo::Status& status) {
  ndo::QuerySpec spec;
  status = ndo::Status::Ok();
  if (!options.target.empty()) {
    const auto parsed = ndo::TargetId::TryParse(options.target);
    if (!parsed.has_value()) {
      status = ndo::Status::Rejected(ndo::ReasonCode::EncodingMalformed, "target is not a valid identity");
      return spec;
    }
    spec.target = *parsed;
  }
  if (!options.object.empty()) {
    const auto parsed = ndo::ObjectId::TryParse(options.object);
    if (!parsed.has_value()) {
      status = ndo::Status::Rejected(ndo::ReasonCode::EncodingMalformed, "object is not a valid identity");
      return spec;
    }
    spec.object = *parsed;
  }
  if (!options.drift_class.empty()) {
    ndo::DriftClass parsed = ndo::DriftClass::None;
    if (!ndo::TryParseDriftClass(options.drift_class.c_str(), parsed)) {
      status = ndo::Status::Rejected(ndo::ReasonCode::EncodingMalformed, "drift class is not recognized");
      return spec;
    }
    spec.klass = parsed;
  }
  if (!options.severity.empty()) {
    ndo::Severity parsed = ndo::Severity::Medium;
    if (!ndo::TryParseSeverity(options.severity.c_str(), parsed)) {
      status = ndo::Status::Rejected(ndo::ReasonCode::EncodingMalformed, "severity is not recognized");
      return spec;
    }
    spec.exact_severity = parsed;
  }
  if (!options.min_severity.empty()) {
    ndo::Severity parsed = ndo::Severity::Medium;
    if (!ndo::TryParseSeverity(options.min_severity.c_str(), parsed)) {
      status = ndo::Status::Rejected(ndo::ReasonCode::EncodingMalformed, "severity is not recognized");
      return spec;
    }
    spec.min_severity = parsed;
  }
  if (!options.state_filter.empty()) {
    ndo::FindingState parsed = ndo::FindingState::Open;
    if (!ndo::TryParseFindingState(options.state_filter.c_str(), parsed)) {
      status = ndo::Status::Rejected(ndo::ReasonCode::EncodingMalformed, "finding state is not recognized");
      return spec;
    }
    spec.state = parsed;
  }
  if (!options.order.empty()) {
    ndo::QueryOrder parsed = ndo::QueryOrder::SeverityDescending;
    if (!ndo::TryParseQueryOrder(options.order.c_str(), parsed)) {
      status = ndo::Status::Rejected(ndo::ReasonCode::EncodingMalformed, "order is not recognized");
      return spec;
    }
    spec.order = parsed;
  }
  if (!options.group.empty()) {
    const auto parsed = ndo::GroupId::TryParse(options.group);
    if (!parsed.has_value()) {
      status = ndo::Status::Rejected(ndo::ReasonCode::EncodingMalformed, "group is not a group identity");
      return spec;
    }
    spec.group = *parsed;
  }
  if (!options.source.empty()) {
    const auto parsed = ndo::SourceId::TryParse(options.source);
    if (!parsed.has_value()) {
      status = ndo::Status::Rejected(ndo::ReasonCode::EncodingMalformed, "source is not a valid identity");
      return spec;
    }
    spec.source = *parsed;
  }
  if (!options.min_freshness.empty()) {
    ndo::FreshnessState parsed = ndo::FreshnessState::Fresh;
    if (!ndo::TryParseFreshnessState(options.min_freshness.c_str(), parsed)) {
      status = ndo::Status::Rejected(ndo::ReasonCode::EncodingMalformed,
                                     "freshness state is not recognized");
      return spec;
    }
    spec.min_freshness = parsed;
  }
  if (!options.root_cause.empty()) {
    bool recognized = false;
    for (std::uint8_t raw = 0; raw < ndo::kRootCauseKindCount; ++raw) {
      if (options.root_cause == ndo::ToText(static_cast<ndo::RootCauseKind>(raw))) {
        spec.root_cause = static_cast<ndo::RootCauseKind>(raw);
        recognized = true;
        break;
      }
    }
    if (!recognized) {
      status = ndo::Status::Rejected(ndo::ReasonCode::EncodingMalformed, "root cause is not recognized");
      return spec;
    }
  }
  if (options.generation.has_value()) {
    spec.generation = ndo::IntentGeneration::FromValue(*options.generation);
  }
  if (options.min_age_seconds.has_value()) {
    spec.min_age_nanos = *options.min_age_seconds * 1000000000LL;
  }
  if (options.max_age_seconds.has_value()) {
    spec.max_age_nanos = *options.max_age_seconds * 1000000000LL;
  }
  spec.limit = options.limit;
  spec.offset = options.offset;
  spec.include_resolved = options.include_resolved;
  spec.include_superseded = options.include_superseded;
  spec.include_retired = options.include_retired;
  spec.include_suppressed = options.include_suppressed;
  return spec;
}

ndo::ObservatoryConfig BuildConfig(const Options& options, const ndo::ObservatoryPolicy& policy) {
  ndo::ObservatoryConfig config;
  config.policy = policy;
  config.epoch = ndo::FabricEpoch::FromValue(options.epoch);
  config.incarnation = ndo::Incarnation::FromValue(options.incarnation);
  config.require_started = true;
  return config;
}

int CommandEvaluate(ndo::Observatory& observatory, const Options& options) {
  const ndo::Result<ndo::EvaluationOutcome> outcome = observatory.EvaluateAt(ResolveNow(options), true);
  if (!outcome.ok()) {
    return Report(outcome.status());
  }
  ndo::Value::Map root;
  ndo::Value::List targets;
  bool actionable = false;
  bool undecidable = false;
  for (const ndo::TargetEvaluation& evaluation : outcome.value().targets) {
    ndo::Value::Map entry;
    entry.emplace("target", ndo::Value::MakeString(evaluation.target.str()));
    entry.emplace("has_baseline", ndo::Value::MakeBool(evaluation.has_baseline));
    entry.emplace("baseline_generation",
                  ndo::Value::MakeUint(evaluation.baseline_generation.value()));
    entry.emplace("best_freshness", ndo::Value::MakeString(ndo::ToText(evaluation.best_freshness)));
    entry.emplace("sources_considered", ndo::Value::MakeUint(evaluation.sources_considered));
    entry.emplace("fresh_sources", ndo::Value::MakeUint(evaluation.fresh_sources));
    entry.emplace("compliance_decidable", ndo::Value::MakeBool(evaluation.compliance_decidable));
    entry.emplace("compliant", ndo::Value::MakeBool(evaluation.compliant));
    entry.emplace("decision_reason", ndo::Value::MakeString(ndo::ToText(evaluation.decision_reason)));
    entry.emplace("drafts", ndo::Value::MakeUint(evaluation.drafts.size()));
    if (!evaluation.compliance_decidable) {
      undecidable = true;
    }
    for (const ndo::FindingDraft& draft : evaluation.drafts) {
      if (ndo::IsActionableDrift(draft.klass)) {
        actionable = true;
      }
    }
    ndo::Value::List trace;
    for (const std::string& line : evaluation.trace) {
      trace.push_back(ndo::Value::MakeString(line));
    }
    entry.emplace("trace", ndo::Value::MakeList(std::move(trace)));
    targets.push_back(ndo::Value::MakeMap(std::move(entry)));
  }
  root.emplace("evaluated_at", ndo::Value::MakeString(ndo::FormatTime(outcome.value().now)));
  root.emplace("epoch", ndo::Value::MakeUint(outcome.value().epoch.value()));
  root.emplace("incarnation", ndo::Value::MakeUint(outcome.value().incarnation.value()));
  root.emplace("policy_digest", ndo::Value::MakeString(outcome.value().policy_digest.ToHex()));
  root.emplace("outcome_digest", ndo::Value::MakeString(outcome.value().ComputeDigest().ToHex()));
  root.emplace("targets", ndo::Value::MakeList(std::move(targets)));
  Print(ndo::Value::MakeMap(std::move(root)), options.compact);
  if (actionable) {
    return kExitActionableDrift;
  }
  if (undecidable) {
    return kExitUndecidable;
  }
  return kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!ParseOptions(argc, argv, options)) {
    PrintUsage();
    return kExitUsage;
  }
  if (options.help) {
    PrintUsage();
    return kExitOk;
  }
  if (options.command == "version") {
    std::cout << ndo::kProductName << " " << ndo::kVersionString << " (" << ndo::kProductVendor << ")\n";
    std::cout << "ledger format " << ndo::kLedgerFormatVersion << ", wire protocol "
              << ndo::kWireProtocolVersion << "\n";
    return kExitOk;
  }

  ndo::Status status = ndo::Status::Ok();
  ndo::ObservatoryPolicy policy = LoadPolicy(options, status);
  if (!status.ok()) {
    return Report(status);
  }
  {
    // A CLI invocation is one process incarnation. Policy identity and the
    // evidence class are recorded so a finding can always name its baseline.
    if (policy.id.empty()) {
      policy.id = ndo::PolicyId::Trusted("policy/default");
    }
  }

  if (options.command == "policy-default") {
    const ndo::Value encoded = ndo::EncodePolicy(ndo::ObservatoryPolicy::Default());
    std::string text = options.compact ? ndo::WriteCanonicalJson(encoded)
                                       : ndo::WritePrettyJson(encoded, 2);
    if (!options.out_path.empty()) {
      if (!WriteFile(options.out_path, text + "\n")) {
        std::cerr << "the output file could not be written\n";
        return kExitUsage;
      }
      return kExitOk;
    }
    std::cout << text << "\n";
    return kExitOk;
  }

  ndo::Observatory observatory(BuildConfig(options, policy));
  status = observatory.Start();
  if (!status.ok()) {
    return Report(status);
  }
  if (!options.state_path.empty()) {
    std::ifstream probe(options.state_path);
    if (probe.good()) {
      probe.close();
      ndo::LedgerRecoveryReport recovery;
      status = observatory.Load(options.state_path, recovery);
      if (!status.ok()) {
        return Report(status);
      }
    }
  }

  int result = kExitOk;
  const auto save = [&]() {
    if (options.state_path.empty()) {
      return;
    }
    const ndo::Status saved = observatory.Save(options.state_path);
    if (!saved.ok()) {
      std::cerr << "the state file could not be written: " << saved.detail << "\n";
      result = kExitUsage;
    }
  };

  if (options.command == "intent-commit" || options.command == "observe") {
    if (options.file_path.empty()) {
      PrintUsage();
      return kExitUsage;
    }
    std::string text;
    if (!ReadFile(options.file_path, text)) {
      std::cerr << "the input file could not be read\n";
      return kExitUsage;
    }
    if (options.command == "intent-commit") {
      ndo::IntentGenerationDocument document;
      status = ndo::ParseIntentJson(text, observatory.limits(), document);
      if (!status.ok()) {
        return Report(status);
      }
      ndo::IntentCommitReport report;
      status = observatory.PublishIntent(document, report);
      if (!status.ok()) {
        return Report(status);
      }
      ndo::Value::Map out;
      out.emplace("target", ndo::Value::MakeString(report.target.str()));
      out.emplace("committed_generation", ndo::Value::MakeUint(report.committed_generation.value()));
      out.emplace("previous_generation", ndo::Value::MakeUint(report.previous_generation.value()));
      out.emplace("duplicate_identical", ndo::Value::MakeBool(report.duplicate_identical));
      out.emplace("findings_rebased", ndo::Value::MakeUint(report.findings_rebased));
      Print(ndo::Value::MakeMap(std::move(out)), options.compact);
    } else {
      ndo::ObservationAdmission admission;
      status = observatory.IngestObservationJson(text, admission);
      if (!status.ok()) {
        return Report(status);
      }
      ndo::Value::Map out;
      out.emplace("snapshot", ndo::Value::MakeString(admission.snapshot.str()));
      out.emplace("source", ndo::Value::MakeString(admission.source.str()));
      out.emplace("freshness", ndo::Value::MakeString(ndo::ToText(admission.freshness)));
      out.emplace("duplicate_identical", ndo::Value::MakeBool(admission.duplicate_identical));
      out.emplace("superseded_older", ndo::Value::MakeBool(admission.superseded_older));
      Print(ndo::Value::MakeMap(std::move(out)), options.compact);
    }
  } else if (options.command == "evaluate") {
    result = CommandEvaluate(observatory, options);
  } else if (options.command == "query") {
    ndo::QuerySpec spec = BuildQuerySpec(options, status);
    if (!status.ok()) {
      return Report(status);
    }
    const ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
    if (!page.ok()) {
      return Report(page.status());
    }
    ndo::Value::List findings;
    for (const ndo::Finding& finding : page.value().findings) {
      ndo::Value::Map entry;
      entry.emplace("id", ndo::Value::MakeString(finding.id.ToHex()));
      entry.emplace("target", ndo::Value::MakeString(finding.identity.target.str()));
      entry.emplace("object", ndo::Value::MakeString(finding.identity.object.str()));
      entry.emplace("path", ndo::Value::MakeString(finding.identity.path.ToText()));
      entry.emplace("class", ndo::Value::MakeString(ndo::ToText(finding.klass)));
      entry.emplace("raw_class", ndo::Value::MakeString(ndo::ToText(finding.raw_class)));
      entry.emplace("severity", ndo::Value::MakeString(ndo::ToText(finding.severity)));
      entry.emplace("state", ndo::Value::MakeString(ndo::ToText(finding.state)));
      entry.emplace("reason", ndo::Value::MakeString(ndo::ToText(finding.reason)));
      entry.emplace("baseline_generation", ndo::Value::MakeUint(finding.baseline_generation.value()));
      entry.emplace("baseline_epoch", ndo::Value::MakeUint(finding.baseline_epoch.value()));
      entry.emplace("freshness", ndo::Value::MakeString(ndo::ToText(finding.evidence_freshness)));
      entry.emplace("group", ndo::Value::MakeString(finding.group.is_set() ? finding.group.ToHex() : ""));
      entry.emplace("observation_count", ndo::Value::MakeUint(finding.observation_count));
      entry.emplace("reopen_count", ndo::Value::MakeUint(finding.reopen_count));
      entry.emplace("first_seen", ndo::Value::MakeString(ndo::FormatTime(finding.first_seen)));
      entry.emplace("last_seen", ndo::Value::MakeString(ndo::FormatTime(finding.last_seen)));
      entry.emplace("suppressed", ndo::Value::MakeBool(finding.suppression.has_value()));
      entry.emplace("summary", ndo::Value::MakeString(finding.summary));
      findings.push_back(ndo::Value::MakeMap(std::move(entry)));
    }
    ndo::Value::Map root;
    root.emplace("total_matched", ndo::Value::MakeUint(page.value().total_matched));
    root.emplace("returned", ndo::Value::MakeUint(page.value().findings.size()));
    root.emplace("truncated", ndo::Value::MakeBool(page.value().truncated));
    root.emplace("page_digest", ndo::Value::MakeString(page.value().page_digest.ToHex()));
    root.emplace("findings", ndo::Value::MakeList(std::move(findings)));
    Print(ndo::Value::MakeMap(std::move(root)), options.compact);
  } else if (options.command == "explain") {
    if (options.finding.empty()) {
      PrintUsage();
      return kExitUsage;
    }
    const auto id = ndo::FindingId::TryParse(options.finding);
    if (!id.has_value()) {
      std::cerr << "--finding must be a finding identity\n";
      return kExitUsage;
    }
    ndo::QuerySpec spec;
    spec.limit = 1000000;
    spec.include_resolved = true;
    spec.include_superseded = true;
    spec.include_retired = true;
    const ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
    if (!page.ok()) {
      return Report(page.status());
    }
    for (const ndo::Finding& finding : page.value().findings) {
      if (finding.id == *id) {
        ndo::Value::Map root;
        root.emplace("summary", ndo::Value::MakeString(ndo::ExplainFinding(finding)));
        ndo::Value::List history;
        for (const ndo::TimelineEntry& entry : finding.timeline) {
          ndo::Value::Map item;
          item.emplace("kind", ndo::Value::MakeString(ndo::ToText(entry.kind)));
          item.emplace("sequence", ndo::Value::MakeUint(entry.sequence));
          item.emplace("at", ndo::Value::MakeString(ndo::FormatTime(entry.at)));
          item.emplace("state", ndo::Value::MakeString(ndo::ToText(entry.state_after)));
          item.emplace("reason", ndo::Value::MakeString(ndo::ToText(entry.reason)));
          item.emplace("detail", ndo::Value::MakeString(entry.detail));
          history.push_back(ndo::Value::MakeMap(std::move(item)));
        }
        root.emplace("history", ndo::Value::MakeList(std::move(history)));
        Print(ndo::Value::MakeMap(std::move(root)), options.compact);
        save();
        return kExitOk;
      }
    }
    std::cerr << "no finding exists with that identity\n";
    return kExitUsage;
  } else if (options.command == "timeline") {
    ndo::TimelineSpec spec;
    spec.limit = options.limit;
    spec.offset = options.offset;
    if (!options.finding.empty()) {
      const auto id = ndo::FindingId::TryParse(options.finding);
      if (!id.has_value()) {
        std::cerr << "--finding must be a finding identity\n";
        return kExitUsage;
      }
      spec.finding = *id;
    }
    if (!options.target.empty()) {
      const auto target = ndo::TargetId::TryParse(options.target);
      if (!target.has_value()) {
        std::cerr << "--target must be a valid identity\n";
        return kExitUsage;
      }
      spec.target = *target;
    }
    const ndo::Result<ndo::TimelinePage> page = observatory.QueryTimeline(spec);
    if (!page.ok()) {
      return Report(page.status());
    }
    ndo::Value::List entries;
    for (const ndo::TimelineEntry& entry : page.value().entries) {
      ndo::Value::Map item;
      item.emplace("kind", ndo::Value::MakeString(ndo::ToText(entry.kind)));
      item.emplace("sequence", ndo::Value::MakeUint(entry.sequence));
      item.emplace("at", ndo::Value::MakeString(ndo::FormatTime(entry.at)));
      item.emplace("target", ndo::Value::MakeString(entry.target.str()));
      item.emplace("object", ndo::Value::MakeString(entry.object.str()));
      item.emplace("finding", ndo::Value::MakeString(entry.finding.is_set() ? entry.finding.ToHex() : ""));
      item.emplace("state", ndo::Value::MakeString(ndo::ToText(entry.state_after)));
      item.emplace("class", ndo::Value::MakeString(ndo::ToText(entry.klass)));
      item.emplace("reason", ndo::Value::MakeString(ndo::ToText(entry.reason)));
      item.emplace("detail", ndo::Value::MakeString(entry.detail));
      entries.push_back(ndo::Value::MakeMap(std::move(item)));
    }
    ndo::Value::Map root;
    root.emplace("total_matched", ndo::Value::MakeUint(page.value().total_matched));
    root.emplace("returned", ndo::Value::MakeUint(page.value().entries.size()));
    root.emplace("entries", ndo::Value::MakeList(std::move(entries)));
    Print(ndo::Value::MakeMap(std::move(root)), options.compact);
  } else if (options.command == "report") {
    ndo::ReportSpec spec;
    spec.id = ndo::ReportId::TryParse(options.task.empty() ? "report/cli" : options.task)
                  .value_or(ndo::ReportId::Trusted("report/cli"));
    if (!options.target.empty()) {
      const auto target = ndo::TargetId::TryParse(options.target);
      if (!target.has_value()) {
        std::cerr << "--target must be a valid identity\n";
        return kExitUsage;
      }
      spec.target = *target;
    }
    spec.include_resolved = options.include_resolved;
    spec.include_superseded = options.include_superseded;
    spec.include_suppressed = options.include_suppressed;
    spec.max_findings = options.limit;
    std::string text;
    status = ndo::BuildReportJson(observatory, spec, text);
    if (!status.ok()) {
      return Report(status);
    }
    if (!options.out_path.empty()) {
      if (!WriteFile(options.out_path, text + "\n")) {
        std::cerr << "the report file could not be written\n";
        return kExitUsage;
      }
    } else {
      std::cout << text << "\n";
    }
  } else if (options.command == "suppress" || options.command == "acknowledge") {
    if (options.finding.empty() || options.actor.empty()) {
      PrintUsage();
      return kExitUsage;
    }
    const auto id = ndo::FindingId::TryParse(options.finding);
    if (!id.has_value()) {
      std::cerr << "--finding must be a finding identity\n";
      return kExitUsage;
    }
    const auto actor = ndo::ActorId::TryParse(options.actor);
    if (!actor.has_value()) {
      std::cerr << "--actor must be a valid identity\n";
      return kExitUsage;
    }
    if (options.command == "suppress") {
      std::optional<ndo::NdoTime> expires;
      if (options.hours.has_value()) {
        const double nanos = *options.hours * 3600.0 * 1000000000.0;
        expires = ndo::NdoTime::FromNanos(ResolveNow(options).unix_nanos +
                                          static_cast<std::int64_t>(nanos));
      }
      status = observatory.SuppressFinding(*id, *actor, options.reason, expires, ResolveNow(options));
    } else {
      status = observatory.AcknowledgeFinding(*id, *actor, options.reason, ResolveNow(options));
    }
    if (!status.ok()) {
      return Report(status);
    }
    std::cout << "{\"status\":\"recorded\",\"finding\":\"" << id->ToHex() << "\"}\n";
  } else if (options.command == "stats") {
    const ndo::LedgerStats stats = observatory.Stats();
    const ndo::ObservatoryCounters counters = observatory.Counters();
    ndo::Value::Map out;
    out.emplace("targets", ndo::Value::MakeUint(stats.targets));
    out.emplace("baselines", ndo::Value::MakeUint(stats.baselines));
    out.emplace("observations", ndo::Value::MakeUint(stats.observations));
    out.emplace("sources", ndo::Value::MakeUint(stats.sources));
    out.emplace("findings", ndo::Value::MakeUint(stats.findings));
    out.emplace("live_findings", ndo::Value::MakeUint(stats.live_findings));
    out.emplace("resolved_findings", ndo::Value::MakeUint(stats.resolved_findings));
    out.emplace("superseded_findings", ndo::Value::MakeUint(stats.superseded_findings));
    out.emplace("suppressed_findings", ndo::Value::MakeUint(stats.suppressed_findings));
    out.emplace("groups", ndo::Value::MakeUint(stats.groups));
    out.emplace("timeline_entries", ndo::Value::MakeUint(stats.timeline_entries));
    out.emplace("evaluations", ndo::Value::MakeUint(counters.evaluations));
    out.emplace("evaluations_cancelled", ndo::Value::MakeUint(counters.evaluations_cancelled));
    out.emplace("evaluations_fenced", ndo::Value::MakeUint(counters.evaluations_fenced));
    out.emplace("observations_rejected", ndo::Value::MakeUint(counters.observations_rejected));
    out.emplace("recoveries", ndo::Value::MakeUint(counters.recoveries));
    Print(ndo::Value::MakeMap(std::move(out)), options.compact);
  } else if (options.command == "serve") {
    if (options.port == 0) {
      std::cerr << "--port is required\n";
      return kExitUsage;
    }
    ndo::ServerConfig config;
    config.port = options.port;
    config.bind_address = options.bind_address;
    config.limits = observatory.limits();
    ndo::ObservationServer server(observatory, config);
    status = server.Start();
    if (!status.ok()) {
      return Report(status);
    }
    std::cout << "{\"listening\":\"" << config.bind_address << ":" << server.port()
              << "\",\"epoch\":" << observatory.epoch().value()
              << ",\"incarnation\":" << observatory.incarnation().value() << "}\n";
    std::cout.flush();
    if (options.once) {
      const ndo::Status served = server.ServeSingleSession();
      if (!served.ok()) {
        return Report(served);
      }
    } else {
      std::string line;
      while (std::getline(std::cin, line)) {
        if (line == "quit" || line == "stop") {
          break;
        }
        const ndo::Result<ndo::EvaluationOutcome> outcome = observatory.Evaluate();
        std::cout << "{\"evaluation\":\""
                  << (outcome.ok() ? "applied" : ndo::ToText(outcome.status().reason)) << "\"}\n";
        std::cout.flush();
      }
    }
    server.Stop();
    const ndo::ServerStats stats = server.Stats();
    ndo::Value::Map out;
    out.emplace("sessions_accepted", ndo::Value::MakeUint(stats.sessions_accepted));
    out.emplace("sessions_refused", ndo::Value::MakeUint(stats.sessions_refused));
    out.emplace("frames_received", ndo::Value::MakeUint(stats.frames_received));
    out.emplace("frames_refused", ndo::Value::MakeUint(stats.frames_refused));
    out.emplace("snapshots_admitted", ndo::Value::MakeUint(stats.snapshots_admitted));
    out.emplace("snapshots_refused", ndo::Value::MakeUint(stats.snapshots_refused));
    out.emplace("stale_fenced", ndo::Value::MakeUint(stats.stale_fenced));
    out.emplace("active_sessions", ndo::Value::MakeUint(stats.active_sessions));
    Print(ndo::Value::MakeMap(std::move(out)), options.compact);
  } else {
    PrintUsage();
    return kExitUsage;
  }

  if (options.evaluate_after) {
    // Evaluating in the same process keeps the evidence that this invocation
    // admitted fresh; a later invocation would see it as recovered.
    const int evaluated = CommandEvaluate(observatory, options);
    if (evaluated != kExitOk) {
      result = evaluated;
    }
  }
  save();
  observatory.Stop();
  return result;
}
