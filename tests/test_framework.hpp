// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Minimal test framework.
//
// Tests run plainly: there is no watchdog, no per-test timeout and no retry. A
// hanging test is a defect in the runtime under test, not something to hide.

#ifndef NDO_TESTS_TEST_FRAMEWORK_HPP
#define NDO_TESTS_TEST_FRAMEWORK_HPP

#include <cstddef>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace ndotest {

using TestFunction = void (*)();

struct TestCase {
  const char* name;
  TestFunction function;
};

std::vector<TestCase>& Registry();
int& FailureCount();
int& CheckCount();
void ReportFailure(const char* file, int line, const std::string& message);

struct Registrar {
  Registrar(const char* name, TestFunction function);
};

/// Streams a value into a diagnostic string. Values that support operator<< are
/// printed; everything else prints its type placeholder.
template <typename T>
std::string Show(const T& value) {
  std::ostringstream stream;
  stream << value;
  return stream.str();
}

inline std::string Show(const std::string& value) { return value; }
inline std::string Show(const char* value) { return value == nullptr ? "(null)" : value; }
inline std::string Show(bool value) { return value ? "true" : "false"; }

int RunAll(int argc, char** argv);

}  // namespace ndotest

#define NDO_TEST(name)                                                       \
  void name();                                                               \
  static ::ndotest::Registrar ndo_registrar_##name(#name, name);             \
  void name()

#define NDO_CHECK(condition)                                                 \
  do {                                                                       \
    ++::ndotest::CheckCount();                                               \
    if (!(condition)) {                                                      \
      ::ndotest::ReportFailure(__FILE__, __LINE__, "check failed: " #condition); \
    }                                                                        \
  } while (false)

#define NDO_CHECK_EQ(actual, expected)                                       \
  do {                                                                       \
    ++::ndotest::CheckCount();                                               \
    /* By value: binding a reference into a temporary result object would */ \
    /* leave the diagnostic reading freed storage. */                        \
    const auto ndo_actual = (actual);                                        \
    const auto ndo_expected = (expected);                                    \
    if (!(ndo_actual == ndo_expected)) {                                     \
      ::ndotest::ReportFailure(__FILE__, __LINE__,                           \
                               std::string("expected ") +                    \
                                   ::ndotest::Show(ndo_expected) + " but found " + \
                                   ::ndotest::Show(ndo_actual) + " (" #actual ")"); \
    }                                                                        \
  } while (false)

#define NDO_CHECK_STATUS(status)                                             \
  do {                                                                       \
    ++::ndotest::CheckCount();                                               \
    const auto ndo_status_value = (status);                                  \
    if (!ndo_status_value.ok()) {                                            \
      ::ndotest::ReportFailure(__FILE__, __LINE__,                           \
                               std::string("unexpected status ") +           \
                                   ::summon::network_drift_observatory::ToText( \
                                       ndo_status_value.reason) +            \
                                   " (" + ndo_status_value.detail + ")");    \
    }                                                                        \
  } while (false)

#define NDO_CHECK_REFUSED(status, expected_reason)                           \
  do {                                                                       \
    ++::ndotest::CheckCount();                                               \
    const auto ndo_status_value = (status);                                  \
    if (ndo_status_value.ok()) {                                             \
      ::ndotest::ReportFailure(__FILE__, __LINE__,                           \
                               "expected refusal " #expected_reason);        \
    } else if (ndo_status_value.reason != (expected_reason)) {               \
      ::ndotest::ReportFailure(                                              \
          __FILE__, __LINE__,                                                \
          std::string("expected reason ") +                                  \
              ::summon::network_drift_observatory::ToText(expected_reason) + \
              " but found " +                                                \
              ::summon::network_drift_observatory::ToText(ndo_status_value.reason)); \
    }                                                                        \
  } while (false)

#endif  // NDO_TESTS_TEST_FRAMEWORK_HPP
