// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Independent collector processes over a real TCP connection.
//
// The observatory server runs in this process; the publishers are separate
// operating-system processes started from the built command line tool. The
// suite proves that framing, source authority, epoch/incarnation fencing and
// abrupt process death behave as documented when the peer really is another
// process.

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

#include "summon/network_drift_observatory/server.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <process.h>
#endif

using namespace ndotest;

#if !defined(NDO_TOOL_ROOT) || !defined(NDO_TOOL_CONFIG)
#error "NDO_TOOL_ROOT and NDO_TOOL_CONFIG must name the built tools"
#endif

namespace {

std::string CollectorPath() {
  return std::string(NDO_TOOL_ROOT) + "/" + NDO_TOOL_CONFIG + "/ndo_collector.exe";
}

std::string Quote(const std::string& text) { return "\"" + text + "\""; }

/// Runs a command line through the shell and returns its exit code.
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

ndo::ObservatoryConfig ServerObservatoryConfig() {
  ndo::ObservatoryConfig config;
  config.policy = SyntheticPolicy();
  config.epoch = ndo::FabricEpoch::FromValue(1);
  config.incarnation = ndo::Incarnation::FromValue(1);
  return config;
}

ndo::ServerConfig ServerConfiguration() {
  ndo::ServerConfig config;
  config.bind_address = "127.0.0.1";
  config.port = 0;
  config.session_idle_timeout_millis = 15000;
  return config;
}

ndo::IntentGenerationDocument IntentFor(const std::string& target) {
  ndo::IntentGenerationDocument intent = MakeIntent(target, 1);
  AddIntentObject(intent, "obj/0", "mtu", ndo::Value::MakeInt(1500));
  return intent;
}

/// Arguments for one collector run, without a shell and without redirection.
std::string CollectorArguments(const ndo::ObservationServer& server, const std::string& source,
                               std::uint64_t incarnation, const std::string& target,
                               std::uint64_t count, const std::string& value,
                               const std::string& extra = std::string()) {
  std::ostringstream arguments;
  arguments << "--host 127.0.0.1 --port " << server.port() << " --source " << source
            << " --epoch 1 --incarnation " << incarnation << " --target " << target << " --count "
            << count << " --value " << value
            << " --objects 1 --fields 0 --asserts-absence --complete-coverage --quiet";
  if (!extra.empty()) {
    arguments << " " << extra;
  }
  return arguments.str();
}

std::string CollectorCommand(const ndo::ObservationServer& server, const std::string& source,
                             std::uint64_t incarnation, const std::string& target,
                             std::uint64_t count, const std::string& value,
                             const std::string& extra = std::string()) {
  std::ostringstream command;
  command << Quote(CollectorPath()) << " --host 127.0.0.1 --port " << server.port()
          << " --source " << source << " --epoch 1 --incarnation " << incarnation << " --target "
          << target << " --count " << count << " --value " << value
          << " --objects 1 --fields 0 --asserts-absence --complete-coverage --quiet";
  if (!extra.empty()) {
    command << " " << extra;
  }
  return command.str();
}

/// A child process started through the platform shell.
struct ChildProcess {
  void* handle{nullptr};
};

/// Starts a command through the shell (used when the exit code and output file
/// matter more than the process identity).
bool SpawnShell(const std::string& command, ChildProcess& out) {
  std::string line = "cmd.exe /c \"" + command + "\"";
  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION info{};
  std::vector<char> buffer(line.begin(), line.end());
  buffer.push_back('\0');
  const BOOL created = CreateProcessA(nullptr, buffer.data(), nullptr, nullptr, TRUE,
                                      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info);
  if (created == 0) {
    return false;
  }
  CloseHandle(info.hThread);
  out.handle = info.hProcess;
  return true;
}

/// Starts the collector itself, with no shell in between, so that terminating
/// the returned process terminates the publisher rather than a wrapper around
/// it. Its output is inherited, which is enough for a test that inspects the
/// server rather than the process output.
bool SpawnCollector(const std::string& executable, const std::string& arguments,
                    ChildProcess& out) {
  std::string line = "\"" + executable + "\" " + arguments;
  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION info{};
  std::vector<char> buffer(line.begin(), line.end());
  buffer.push_back('\0');
  const BOOL created =
      CreateProcessA(executable.c_str(), buffer.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                     nullptr, nullptr, &startup, &info);
  if (created == 0) {
    return false;
  }
  CloseHandle(info.hThread);
  out.handle = info.hProcess;
  return true;
}

bool WaitForChild(const ChildProcess& child, std::uint32_t& exit_code) {
  if (child.handle == nullptr) {
    return false;
  }
  if (WaitForSingleObject(child.handle, INFINITE) != WAIT_OBJECT_0) {
    return false;
  }
  DWORD code = 0;
  if (GetExitCodeProcess(child.handle, &code) == 0) {
    return false;
  }
  exit_code = static_cast<std::uint32_t>(code);
  return true;
}

void CloseChild(ChildProcess& child) {
  if (child.handle != nullptr) {
    CloseHandle(child.handle);
    child.handle = nullptr;
  }
}

/// Waits until the server has admitted at least this many snapshots. A child
/// process establishes its fence at the greeting and admits snapshots after it,
/// so a test that needs published evidence must wait for the publication rather
/// than for the connection.
bool WaitForAdmissions(ndo::ObservationServer& server, std::uint64_t minimum) {
  for (int attempt = 0; attempt < 800; ++attempt) {
    if (server.Stats().snapshots_admitted >= minimum) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return false;
}

/// Waits until the server has retired every session it accepted. A peer that
/// has just exited is reaped asynchronously, so the assertion waits for the
/// server to observe the close rather than assuming it already did.
bool WaitForNoActiveSessions(ndo::ObservationServer& server) {
  for (int attempt = 0; attempt < 400; ++attempt) {
    if (server.Stats().active_sessions == 0) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return false;
}

/// Waits until the server has fenced the source, or gives up after the bound.
bool WaitForFence(const ndo::ObservationServer& server, const std::string& source) {
  for (int attempt = 0; attempt < 400; ++attempt) {
    if (server.FenceFor(Source(source)).has_value()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return false;
}

}  // namespace

NDO_TEST(SingleCollectorProcessPublishesOverTcp) {
  const TempDir directory("mp_single");
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::IntentCommitReport commit;
  NDO_CHECK_STATUS(observatory.PublishIntent(IntentFor("switch/mp"), commit));

  ndo::ObservationServer server(observatory, ServerConfiguration());
  NDO_CHECK_STATUS(server.Start());

  const std::string output = directory.File("collector.txt");
  const std::string command =
      CollectorCommand(server, "collector/proc", 5, "switch/mp", 3, "1500") + " > " +
      Quote(output) + " 2>&1";
  NDO_CHECK_EQ(RunCommand(command), 0);

  const std::string text = ReadText(output);
  NDO_CHECK(text.find("\"summary\":true") != std::string::npos);
  NDO_CHECK(text.find("\"accepted\":3") != std::string::npos);
  NDO_CHECK(text.find("\"refused\":0") != std::string::npos);

  const ndo::ServerStats stats = server.Stats();
  NDO_CHECK_EQ(stats.sessions_accepted, std::uint64_t{1});
  NDO_CHECK_EQ(stats.sessions_closed, std::uint64_t{1});
  NDO_CHECK(stats.snapshots_admitted >= 1);
  NDO_CHECK(observatory.Stats().observations >= 1);

  // The fence records the authority the process established.
  const std::optional<ndo::SourceFence> fence = server.FenceFor(Source("collector/proc"));
  NDO_CHECK(fence.has_value());
  if (fence.has_value()) {
    NDO_CHECK_EQ(fence->incarnation.value(), std::uint64_t{5});
    NDO_CHECK(fence->sequence.value() >= 1);
  }

  NDO_CHECK_STATUS(server.Stop());
  NDO_CHECK_EQ(server.Stats().active_sessions, std::uint64_t{0});
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(StaleIncarnationFromAnotherProcessIsFenced) {
  const TempDir directory("mp_stale");
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::ObservationServer server(observatory, ServerConfiguration());
  NDO_CHECK_STATUS(server.Start());

  const std::string first_output = directory.File("first.txt");
  NDO_CHECK_EQ(RunCommand(CollectorCommand(server, "collector/stale", 9, "switch/stale", 2, "1500") +
                          " > " + Quote(first_output) + " 2>&1"),
               0);

  // A process that claims an older incarnation than the one already fenced is
  // refused at the greeting, before it can publish anything.
  const std::string stale_output = directory.File("stale.txt");
  NDO_CHECK_EQ(RunCommand(CollectorCommand(server, "collector/stale", 4, "switch/stale", 1, "1500") +
                          " > " + Quote(stale_output) + " 2>&1"),
               1);
  const std::string stale_text = ReadText(stale_output);
  NDO_CHECK(stale_text.find("\"connected\":false") != std::string::npos);
  NDO_CHECK(stale_text.find("FencedStaleIncarnation") != std::string::npos);

  // The same incarnation may reconnect, but only forward in sequence.
  const std::string regression_output = directory.File("regression.txt");
  NDO_CHECK_EQ(RunCommand(CollectorCommand(server, "collector/stale", 9, "switch/stale", 1, "1500") +
                          " > " + Quote(regression_output) + " 2>&1"),
               1);
  const std::string regression_text = ReadText(regression_output);
  NDO_CHECK(regression_text.find("FencedStaleSequence") != std::string::npos);

  // Continuing the sequence under the same incarnation is accepted.
  const std::string continue_output = directory.File("continue.txt");
  NDO_CHECK_EQ(RunCommand(CollectorCommand(server, "collector/stale", 9, "switch/stale", 1, "1500",
                                            "--sequence-start 100") +
                          " > " + Quote(continue_output) + " 2>&1"),
               0);

  NDO_CHECK(server.Stats().stale_fenced >= 2);
  NDO_CHECK_STATUS(server.Stop());
  NDO_CHECK_STATUS(observatory.Stop());
}

#if defined(_WIN32)
NDO_TEST(KilledCollectorIsReplacedByAFreshIncarnation) {
  const TempDir directory("mp_kill");
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::ObservationServer server(observatory, ServerConfiguration());
  NDO_CHECK_STATUS(server.Start());

  ChildProcess child;
  NDO_CHECK(SpawnCollector(CollectorPath(),
                           CollectorArguments(server, "collector/killed", 11, "switch/killed", 500,
                                              "1500", "--interval-ms 10"),
                           child));
  if (child.handle == nullptr) {
    NDO_CHECK_STATUS(server.Stop());
    NDO_CHECK_STATUS(observatory.Stop());
    return;
  }

  // The process is publishing; kill it abruptly in the middle of its work.
  NDO_CHECK(WaitForFence(server, "collector/killed"));
  NDO_CHECK(WaitForAdmissions(server, 1));
  const std::optional<ndo::SourceFence> fence = server.FenceFor(Source("collector/killed"));
  NDO_CHECK(fence.has_value());
  const std::uint64_t sequence_at_kill = fence.has_value() ? fence->sequence.value() : 0;
  NDO_CHECK(sequence_at_kill >= 1);
  NDO_CHECK(TerminateProcess(static_cast<HANDLE>(child.handle), 1) != 0);
  std::uint32_t exit_code = 0;
  NDO_CHECK(WaitForChild(child, exit_code));
  CloseChild(child);

  // The killed process is gone; the server noticed the closed session.
  const std::uint64_t admitted_before = server.Stats().snapshots_admitted;
  NDO_CHECK(admitted_before >= 1);

  // Reusing the dead incarnation is refused: the observatory never accepts a
  // replay from a process that no longer exists. Depending on how far the dead
  // process got, the replay is either behind the sequence mark or a conflicting
  // repeat of the sequence it left behind; both are refusals.
  const std::string reuse_output = directory.File("reuse.txt");
  const int reuse_exit =
      RunCommand(CollectorCommand(server, "collector/killed", 11, "switch/killed", 1, "1500") +
                 " > " + Quote(reuse_output) + " 2>&1");
  const std::string reuse_text = ReadText(reuse_output);
  if (reuse_exit != 1) {
    std::cout << "reuse collector output: " << reuse_text << "\n";
  }
  NDO_CHECK_EQ(reuse_exit, 1);
  NDO_CHECK(reuse_text.find("\"published\":false") != std::string::npos);
  NDO_CHECK(reuse_text.find("FencedStaleSequence") != std::string::npos ||
            reuse_text.find("ObservationDuplicateConflicting") != std::string::npos);

  // A fresh incarnation takes over and publishes successfully.
  const std::uint64_t admitted_before_fresh = server.Stats().snapshots_admitted;
  const std::string fresh_output = directory.File("fresh.txt");
  const int fresh_exit =
      RunCommand(CollectorCommand(server, "collector/killed", 12, "switch/killed", 2, "1500") +
                 " > " + Quote(fresh_output) + " 2>&1");
  const std::string fresh_text = ReadText(fresh_output);
  if (fresh_exit != 0) {
    std::cout << "fresh collector output: " << fresh_text << "\n";
  }
  NDO_CHECK_EQ(fresh_exit, 0);
  NDO_CHECK(fresh_text.find("\"accepted\":2") != std::string::npos);
  NDO_CHECK(WaitForAdmissions(server, admitted_before_fresh + 2));
  const std::optional<ndo::SourceFence> updated = server.FenceFor(Source("collector/killed"));
  NDO_CHECK(updated.has_value());
  if (updated.has_value()) {
    NDO_CHECK_EQ(updated->incarnation.value(), std::uint64_t{12});
  }
  NDO_CHECK(server.Stats().snapshots_admitted > admitted_before);

  NDO_CHECK_STATUS(server.Stop());
  NDO_CHECK_EQ(server.Stats().active_sessions, std::uint64_t{0});
  NDO_CHECK_STATUS(observatory.Stop());
}
#endif  // _WIN32

NDO_TEST(TwoCollectorProcessesDisagreeingProduceASourceConflict) {
  const TempDir directory("mp_conflict");
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::IntentCommitReport commit;
  NDO_CHECK_STATUS(observatory.PublishIntent(IntentFor("switch/pair"), commit));

  ndo::ObservationServer server(observatory, ServerConfiguration());
  NDO_CHECK_STATUS(server.Start());

  NDO_CHECK_EQ(RunCommand(CollectorCommand(server, "collector/north", 1, "switch/pair", 1, "1500") +
                          " > " + Quote(directory.File("north.txt")) + " 2>&1"),
               0);
  NDO_CHECK_EQ(RunCommand(CollectorCommand(server, "collector/south", 1, "switch/pair", 1, "9000") +
                          " > " + Quote(directory.File("south.txt")) + " 2>&1"),
               0);

  const ndo::Result<ndo::EvaluationOutcome> outcome = observatory.EvaluateAt(ndo::SystemNow(), true);
  NDO_CHECK(outcome.ok());
  bool conflict = false;
  if (outcome.ok()) {
    for (const ndo::TargetEvaluation& evaluation : outcome.value().targets) {
      for (const ndo::FindingDraft& draft : evaluation.drafts) {
        if (draft.klass == ndo::DriftClass::SourceConflict) {
          conflict = true;
          NDO_CHECK_EQ(draft.evidence.size(), std::size_t{2});
        }
      }
      // A disagreement between sources is a decidable, non-compliant outcome:
      // the runtime knows the target does not match intent.
      NDO_CHECK(evaluation.compliance_decidable);
      NDO_CHECK(!evaluation.compliant);
    }
  }
  NDO_CHECK(conflict);
  NDO_CHECK_STATUS(server.Stop());
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(ManyCollectorProcessesPublishConcurrently) {
  const TempDir directory("mp_many");
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::ObservationServer server(observatory, ServerConfiguration());
  NDO_CHECK_STATUS(server.Start());

  std::vector<ChildProcess> children;
  for (int index = 0; index < 4; ++index) {
    const std::string source = "collector/many-" + std::to_string(index);
    const std::string output = directory.File("many-" + std::to_string(index) + ".txt");
    const std::string command = CollectorCommand(server, source, 1, "switch/many", 5, "1500") +
                                " > " + Quote(output) + " 2>&1";
    ChildProcess child;
    NDO_CHECK(SpawnShell(command, child));
    if (child.handle != nullptr) {
      children.push_back(child);
    }
  }
  int failures = 0;
  for (ChildProcess& child : children) {
    std::uint32_t exit_code = 0;
    if (!WaitForChild(child, exit_code) || exit_code != 0) {
      ++failures;
    }
    CloseChild(child);
  }
  NDO_CHECK_EQ(failures, 0);
  NDO_CHECK_EQ(server.Stats().sessions_accepted, std::uint64_t{4});
  NDO_CHECK(WaitForNoActiveSessions(server));
  NDO_CHECK_EQ(server.Stats().sessions_closed, std::uint64_t{4});
  NDO_CHECK_EQ(server.Stats().active_sessions, std::uint64_t{0});
  NDO_CHECK(server.Stats().snapshots_admitted >= 4);
  for (int index = 0; index < 4; ++index) {
    const std::string output = directory.File("many-" + std::to_string(index) + ".txt");
    NDO_CHECK(ReadText(output).find("\"refused\":0") != std::string::npos);
  }

  NDO_CHECK_STATUS(server.Stop());
  NDO_CHECK_STATUS(observatory.Stop());
}
