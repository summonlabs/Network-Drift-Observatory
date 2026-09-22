// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// End-to-end validation through the shipped command line tool.
//
// Every step runs the real tool as an independent process against a real state
// file, so this suite proves the whole path: document parsing, intent commit,
// observation admission, evaluation, query, suppression, report export and the
// conservative restart rules.

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

#include "summon/network_drift_observatory/json.hpp"

using namespace ndotest;

#if !defined(NDO_TOOL_ROOT) || !defined(NDO_TOOL_CONFIG)
#error "NDO_TOOL_ROOT and NDO_TOOL_CONFIG must name the built tools"
#endif

namespace {

std::string CliPath() {
  return std::string(NDO_TOOL_ROOT) + "/" + NDO_TOOL_CONFIG + "/ndo_cli.exe";
}

std::string Quote(const std::string& text) { return "\"" + text + "\""; }

/// Runs a command line through the platform shell. The whole command is
/// wrapped in one extra pair of quotes because the interpreter strips the
/// outermost quotes when the command begins with a quoted executable path.
int RunCommand(const std::string& command) {
  return std::system(("\"" + command + "\"").c_str());
}

std::string ReadText(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

void WriteText(const std::string& path, const std::string& text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream << text;
}

std::string IntentJson(const std::string& target, std::uint64_t generation) {
  std::ostringstream json;
  json << "{\"schema\":\"ndo/intent-generation/1\",\"target\":\"" << target
       << "\",\"generation\":" << generation
       << ",\"epoch\":1,\"authority\":\"intent-fabric\",\"policy\":\"policy/default\""
          ",\"authored_at\":\"2026-01-01T00:00:00.000000000Z\",\"evidence\":\"synthetic\""
          ",\"objects\":[{\"id\":\"port/eth0\",\"existence\":\"required\",\"fields\":["
          "{\"path\":\"mtu\",\"value\":1500,\"comparability\":\"managed\"}]}]}";
  return json.str();
}

std::string ObservationJson(const std::string& target, std::uint64_t sequence, std::int64_t value) {
  const std::string collected = ndo::FormatTime(ndo::SystemNow());
  std::ostringstream json;
  json << "{\"schema\":\"ndo/observation/1\",\"source\":\"collector/e2e\",\"epoch\":1"
          ",\"incarnation\":3,\"sequence\":"
       << sequence << ",\"target\":\"" << target << "\",\"collected_at\":\"" << collected
       << "\",\"ttl_nanos\":0,\"coverage\":\"complete\",\"evidence\":\"synthetic\""
          ",\"unobserved\":[]"
          ",\"capabilities\":{\"asserts_absence\":true,\"complete_coverage\":true,"
          "\"reports_nested_paths\":true,\"evidence\":\"synthetic\"}"
          ",\"objects\":[{\"id\":\"port/eth0\",\"presence\":\"present\",\"fields\":["
          "{\"path\":\"mtu\",\"value\":"
       << value << "}]}]}";
  return json.str();
}

/// The tool writes one complete JSON document per line in --json mode, so a
/// command that both admits evidence and evaluates produces two documents.
std::string LastJsonLine(const std::string& text) {
  std::string last;
  std::istringstream stream(text);
  std::string line;
  while (std::getline(stream, line)) {
    if (!line.empty() && line.front() == '{') {
      last = line;
    }
  }
  return last;
}

ndo::Value ParseOrDie(const std::string& text) {
  ndo::Value value;
  const ndo::Status status = ndo::ParseJson(text, ndo::RuntimeLimits{}, value);
  if (!status.ok()) {
    NDO_CHECK(false);
    return ndo::Value::MakeNull();
  }
  return value;
}

const ndo::Value* Member(const ndo::Value& value, const std::string& name) {
  const ndo::Value::Map* map = value.as_map();
  if (map == nullptr) {
    return nullptr;
  }
  const auto found = map->find(name);
  if (found == map->end()) {
    return nullptr;
  }
  return &found->second;
}

/// Extracts the first finding identity from a query page.
std::string FirstFindingId(const ndo::Value& page) {
  const ndo::Value* findings = Member(page, "findings");
  if (findings == nullptr || findings->as_list() == nullptr || findings->as_list()->empty()) {
    return std::string();
  }
  const ndo::Value* id = Member(findings->as_list()->front(), "id");
  if (id == nullptr || id->as_string() == nullptr) {
    return std::string();
  }
  return *id->as_string();
}

}  // namespace

NDO_TEST(CliEndToEndFlow) {
  const TempDir directory("e2e");
  const std::string ledger = directory.File("state.ndo");
  const std::string intent_path = directory.File("intent.json");
  const std::string observation_path = directory.File("observation.json");
  const std::string report_path = directory.File("report.json");
  const std::string query_path = directory.File("query.json");
  const std::string evaluate_path = directory.File("evaluate.json");
  const std::string stats_path = directory.File("stats.json");
  const std::string cli = CliPath();

  // The tool reports its version without touching any state.
  {
    const std::string output = directory.File("version.txt");
    NDO_CHECK_EQ(RunCommand(Quote(cli) + " version > " + Quote(output) + " 2>&1"), 0);
    NDO_CHECK(ReadText(output).find("Network Drift Observatory 1.0.0") != std::string::npos);
  }

  WriteText(intent_path, IntentJson("switch/e2e", 4));
  WriteText(observation_path, ObservationJson("switch/e2e", 1, 9000));

  // Committing intent alone produces nothing to report.
  NDO_CHECK_EQ(RunCommand(Quote(cli) + " intent-commit --file " + Quote(intent_path) + " --state " +
                          Quote(ledger) + " --json > " + Quote(directory.File("commit.txt")) +
                          " 2>&1"),
               0);

  // Admitting the observation and evaluating in the same process reports
  // actionable drift with exit code 2.
  NDO_CHECK_EQ(RunCommand(Quote(cli) + " observe --file " + Quote(observation_path) + " --state " +
                          Quote(ledger) + " --evaluate --json > " + Quote(evaluate_path) +
                          " 2>&1"),
               2);
  const ndo::Value evaluated = ParseOrDie(LastJsonLine(ReadText(evaluate_path)));
  const ndo::Value* targets = Member(evaluated, "targets");
  NDO_CHECK(targets != nullptr && targets->as_list() != nullptr);
  if (targets != nullptr && targets->as_list() != nullptr && !targets->as_list()->empty()) {
    const ndo::Value* compliant = Member(targets->as_list()->front(), "compliant");
    const ndo::Value* decidable = Member(targets->as_list()->front(), "compliance_decidable");
    NDO_CHECK(compliant != nullptr && compliant->as_bool() != nullptr && !*compliant->as_bool());
    NDO_CHECK(decidable != nullptr && decidable->as_bool() != nullptr && *decidable->as_bool());
  }

  // A later process sees the same finding, and its evidence is explicitly not
  // fresh: the observation did not survive the restart as current evidence.
  NDO_CHECK_EQ(RunCommand(Quote(cli) + " query --state " + Quote(ledger) + " --json > " +
                          Quote(query_path) + " 2>&1"),
               0);
  const ndo::Value queried = ParseOrDie(LastJsonLine(ReadText(query_path)));
  const std::string finding_id = FirstFindingId(queried);
  NDO_CHECK(!finding_id.empty());
  {
    const ndo::Value* findings = Member(queried, "findings");
    NDO_CHECK(findings != nullptr && findings->as_list() != nullptr &&
              !findings->as_list()->empty());
    if (findings != nullptr && findings->as_list() != nullptr && !findings->as_list()->empty()) {
      const ndo::Value& first = findings->as_list()->front();
      const ndo::Value* klass = Member(first, "class");
      const ndo::Value* state = Member(first, "state");
      const ndo::Value* freshness = Member(first, "freshness");
      NDO_CHECK(klass != nullptr && klass->as_string() != nullptr &&
                *klass->as_string() == "value-mismatch");
      NDO_CHECK(state != nullptr && state->as_string() != nullptr &&
                *state->as_string() == "open");
      NDO_CHECK(freshness != nullptr && freshness->as_string() != nullptr &&
                *freshness->as_string() == "recovered-not-fresh");
    }
  }

  // Evaluating in a fresh process cannot conclude compliance from the recovered
  // evidence, and reports the undecidable outcome with exit code 3.
  NDO_CHECK_EQ(RunCommand(Quote(cli) + " evaluate --state " + Quote(ledger) + " --json > " +
                          Quote(evaluate_path) + " 2>&1"),
               3);
  const ndo::Value recovered_evaluation = ParseOrDie(LastJsonLine(ReadText(evaluate_path)));
  const ndo::Value* recovered_targets = Member(recovered_evaluation, "targets");
  NDO_CHECK(recovered_targets != nullptr && recovered_targets->as_list() != nullptr);
  if (recovered_targets != nullptr && recovered_targets->as_list() != nullptr &&
      !recovered_targets->as_list()->empty()) {
    const ndo::Value* decidable = Member(recovered_targets->as_list()->front(),
                                         "compliance_decidable");
    const ndo::Value* compliant =
        Member(recovered_targets->as_list()->front(), "compliant");
    NDO_CHECK(decidable != nullptr && decidable->as_bool() != nullptr && !*decidable->as_bool());
    NDO_CHECK(compliant != nullptr && compliant->as_bool() != nullptr && !*compliant->as_bool());
  }

  // The exported report is machine readable and carries typed reconciliation
  // requests for another runtime.
  NDO_CHECK_EQ(RunCommand(Quote(cli) + " report --state " + Quote(ledger) + " --out " +
                          Quote(report_path)),
               0);
  // The exported report is a single indented document, not a JSON line.
  const ndo::Value report = ParseOrDie(ReadText(report_path));
  {
    const ndo::Value* schema = Member(report, "schema");
    NDO_CHECK(schema != nullptr && schema->as_string() != nullptr &&
              *schema->as_string() == "ndo/report/1");
    const ndo::Value* requests = Member(report, "reconciliation_requests");
    NDO_CHECK(requests != nullptr && requests->as_list() != nullptr);
    if (requests != nullptr && requests->as_list() != nullptr && !requests->as_list()->empty()) {
      const ndo::Value* action = Member(requests->as_list()->front(), "action");
      NDO_CHECK(action != nullptr && action->as_string() != nullptr &&
                *action->as_string() == "apply-intent");
      const ndo::Value* boundary = Member(report, "system_boundary");
      NDO_CHECK(boundary != nullptr && boundary->as_list() != nullptr &&
                !boundary->as_list()->empty());
    }
  }

  // Suppression changes reporting only: the finding keeps its evidence and the
  // compliance truth is unchanged.
  NDO_CHECK_EQ(RunCommand(Quote(cli) + " suppress --finding " + finding_id +
                          " --actor operator/e2e --reason \"end to end\" --state " +
                          Quote(ledger) + " > " + Quote(directory.File("suppress.txt")) + " 2>&1"),
               0);
  NDO_CHECK_EQ(RunCommand(Quote(cli) + " query --state " + Quote(ledger) + " --json > " +
                          Quote(query_path) + " 2>&1"),
               0);
  const ndo::Value suppressed = ParseOrDie(LastJsonLine(ReadText(query_path)));
  {
    const ndo::Value* findings = Member(suppressed, "findings");
    bool saw_suppressed = false;
    if (findings != nullptr && findings->as_list() != nullptr) {
      for (const ndo::Value& finding : *findings->as_list()) {
        const ndo::Value* id = Member(finding, "id");
        const ndo::Value* state = Member(finding, "state");
        if (id != nullptr && id->as_string() != nullptr && *id->as_string() == finding_id &&
            state != nullptr && state->as_string() != nullptr) {
          NDO_CHECK(*state->as_string() == "suppressed");
          const ndo::Value* suppressed_flag = Member(finding, "suppressed");
          NDO_CHECK(suppressed_flag != nullptr && suppressed_flag->as_bool() != nullptr &&
                    *suppressed_flag->as_bool());
          saw_suppressed = true;
        }
      }
    }
    NDO_CHECK(saw_suppressed);
  }

  NDO_CHECK_EQ(RunCommand(Quote(cli) + " stats --state " + Quote(ledger) + " --json > " +
                          Quote(stats_path) + " 2>&1"),
               0);
  const ndo::Value stats = ParseOrDie(LastJsonLine(ReadText(stats_path)));
  {
    const ndo::Value* findings = Member(stats, "findings");
    NDO_CHECK(findings != nullptr && findings->as_int() != nullptr && *findings->as_int() >= 1);
  }

  // Malformed input is refused and the durable state is left untouched.
  const std::string before = ReadText(ledger);
  const std::string malformed = directory.File("malformed.json");
  WriteText(malformed, "{\"schema\":\"ndo/observation/1\",\"source\":");
  NDO_CHECK(RunCommand(Quote(cli) + " observe --file " + Quote(malformed) + " --state " +
                       Quote(ledger) + " > " + Quote(directory.File("malformed.txt")) + " 2>&1") !=
           0);
  NDO_CHECK_EQ(ReadText(ledger), before);

  // A document that declares the wrong schema is refused as well.
  const std::string wrong_schema = directory.File("wrong-schema.json");
  WriteText(wrong_schema, "{\"schema\":\"ndo/intent-generation/2\",\"target\":\"switch/e2e\","
                          "\"generation\":9,\"epoch\":1,\"authority\":\"intent-fabric\","
                          "\"policy\":\"policy/default\",\"authored_at\":"
                          "\"2026-01-01T00:00:00.000000000Z\",\"evidence\":\"synthetic\","
                          "\"objects\":[]}");
  NDO_CHECK(RunCommand(Quote(cli) + " intent-commit --file " + Quote(wrong_schema) + " --state " +
                       Quote(ledger) + " > " + Quote(directory.File("schema.txt")) + " 2>&1") != 0);
  NDO_CHECK_EQ(ReadText(ledger), before);
}
