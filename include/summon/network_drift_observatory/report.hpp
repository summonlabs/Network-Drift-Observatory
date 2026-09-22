// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Machine-readable export.
//
// The report is the hand-off surface to reconciliation runtimes: it carries
// findings, their groups, their history, the evidence behind them and typed
// requests that another runtime may act on. The observatory itself never
// mutates a device and never applies a request it emits.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_REPORT_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_REPORT_HPP

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "summon/network_drift_observatory/drift.hpp"
#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/time.hpp"
#include "summon/network_drift_observatory/value.hpp"

namespace summon {
namespace network_drift_observatory {

/// What kind of action a downstream runtime would have to take to close a
/// finding. The observatory only describes; it never performs these.
enum class ReconciliationAction : std::uint8_t {
  /// No action: the finding is informational or indeterminate.
  None = 0,
  /// Re-apply intent at the target (missing object, missing field, wrong value).
  ApplyIntent = 1,
  /// Remove state the intent does not declare.
  RemoveUnexpected = 2,
  /// Refresh observation: the evidence is stale or incomplete.
  CollectObservation = 3,
  /// Resolve a disagreement between two sources before acting.
  ResolveSourceConflict = 4,
  /// The intent, policy or runtime support must change; no device action helps.
  EscalateToOwner = 5,
};

NDO_API const char* ToText(ReconciliationAction value) noexcept;
NDO_NODISCARD NDO_API bool TryParseReconciliationAction(const char* text,
                                                        ReconciliationAction& out) noexcept;

struct NDO_API ReportSpec {
  ReportId id;
  /// Restrict the report to one target, or report everything when unset.
  std::optional<TargetId> target;
  bool include_resolved{false};
  bool include_superseded{false};
  bool include_suppressed{true};
  bool include_timeline{true};
  bool include_evidence{true};
  bool include_groups{true};
  bool include_reconciliation_requests{true};
  std::size_t max_findings{100000};
  /// Free-form note recorded in the report. Never interpreted.
  std::string note;
};

/// Builds a report value. The caller encodes it with WriteCanonicalJson or
/// WritePrettyJson.
NDO_NODISCARD NDO_API Status BuildReportValue(const class Observatory& observatory,
                                              const ReportSpec& spec, Value& out);

/// Convenience wrapper that returns canonical JSON.
NDO_NODISCARD NDO_API Status BuildReportJson(const class Observatory& observatory,
                                             const ReportSpec& spec, std::string& out);

/// Maps a drift class to the action a reconciliation runtime would take.
NDO_NODISCARD NDO_API ReconciliationAction ActionFor(DriftClass klass) noexcept;

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_REPORT_HPP
