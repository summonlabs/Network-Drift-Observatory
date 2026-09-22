// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "test_framework.hpp"

#include <cstring>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace ndotest {

std::vector<TestCase>& Registry() {
  static std::vector<TestCase> registry;
  return registry;
}

int& FailureCount() {
  static int failures = 0;
  return failures;
}

int& CheckCount() {
  static int checks = 0;
  return checks;
}

namespace {
std::string g_current_test;
int g_current_failures = 0;
}

void ReportFailure(const char* file, int line, const std::string& message) {
  ++FailureCount();
  ++g_current_failures;
  std::cout << "  FAIL " << g_current_test << " @" << file << ":" << line << ": " << message
            << "\n";
}

Registrar::Registrar(const char* name, TestFunction function) {
  Registry().push_back(TestCase{name, function});
}

int RunAll(int argc, char** argv) {
  const std::string filter = argc > 1 ? argv[1] : std::string();
  int executed = 0;
  int failed = 0;
  for (const TestCase& test : Registry()) {
    if (!filter.empty() && std::strstr(test.name, filter.c_str()) == nullptr) {
      continue;
    }
    g_current_test = test.name;
    g_current_failures = 0;
    ++executed;
    try {
      test.function();
    } catch (const std::exception& error) {
      ReportFailure(__FILE__, __LINE__, std::string("uncaught exception: ") + error.what());
    } catch (...) {
      ReportFailure(__FILE__, __LINE__, "uncaught non-standard exception");
    }
    if (g_current_failures == 0) {
      std::cout << "PASS " << test.name << "\n";
    } else {
      std::cout << "FAIL " << test.name << " (" << g_current_failures << " failed check(s))\n";
      ++failed;
    }
  }
  std::cout << "---\n" << executed << " test(s) run, " << failed << " failed, "
            << CheckCount() << " check(s)\n";
  return failed == 0 ? 0 : 1;
}

}  // namespace ndotest

int main(int argc, char** argv) {
  return ndotest::RunAll(argc, argv);
}
