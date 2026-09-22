// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Inspection and query surface.
//
// A query is a pure description of what the caller wants to see. It never
// mutates state, never hides a finding silently, and always reports how many
// findings matched before the caller's page limit was applied.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_QUERY_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_QUERY_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "summon/network_drift_observatory/drift.hpp"
#include "summon/network_drift_observatory/finding.hpp"
#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/time.hpp"

namespace summon {
namespace network_drift_observatory {

/// Ordering of query results. Every order is total: ties are broken by finding
/// identity so that two identical requests always return the same page.
enum class QueryOrder : std::uint8_t {
  SeverityDescending = 0,
  FirstSeenAscending = 1,
  LastSeenDescending = 2,
  TargetAscending = 3,
  IdentityAscending = 4,
};

NDO_API const char* ToText(QueryOrder value) noexcept;
NDO_NODISCARD NDO_API bool TryParseQueryOrder(const char* text, QueryOrder& out) noexcept;

struct NDO_API QuerySpec {
  std::optional<TargetId> target;
  std::optional<ObjectId> object;
  std::optional<FieldPath> path_prefix;
  std::optional<IntentGeneration> generation;
  std::optional<FabricEpoch> epoch;
  std::optional<DriftClass> klass;
  std::optional<Severity> min_severity;
  std::optional<Severity> exact_severity;
  std::optional<FindingState> state;
  std::optional<GroupId> group;
  std::optional<SourceId> source;
  std::optional<RootCauseKind> root_cause;
  /// Restrict to findings whose evidence is at least this fresh. Lets an
  /// operator ask "which of these are backed by current evidence".
  std::optional<FreshnessState> min_freshness;
  /// Age window in nanoseconds relative to the evaluation clock.
  std::optional<std::int64_t> min_age_nanos;
  std::optional<std::int64_t> max_age_nanos;
  bool include_resolved{false};
  bool include_superseded{false};
  bool include_retired{false};
  /// Suppressed findings are included by default: a suppression hides nothing
  /// from an inspection that explicitly asks for everything.
  bool include_suppressed{true};
  QueryOrder order{QueryOrder::SeverityDescending};
  std::size_t limit{1000};
  std::size_t offset{0};
};

struct NDO_API QueryResult {
  std::vector<Finding> findings;
  /// Findings that matched before limit and offset were applied.
  std::size_t total_matched{0};
  bool truncated{false};
  NdoTime evaluated_at;
  QuerySpec spec;
  /// Deterministic digest of the returned page.
  Digest page_digest;
};

/// One window of the global timeline.
struct NDO_API TimelineSpec {
  std::optional<FindingId> finding;
  std::optional<TargetId> target;
  std::optional<TimelineEventKind> kind;
  std::optional<NdoTime> since;
  std::optional<NdoTime> until;
  std::size_t limit{1000};
  std::size_t offset{0};
};

struct NDO_API TimelinePage {
  std::vector<TimelineEntry> entries;
  std::size_t total_matched{0};
  bool truncated{false};
};

/// Applies a query to a materialized set of findings. Pure and deterministic:
/// the returned page depends only on the findings, the specification and the
/// clock reading.
NDO_NODISCARD NDO_API Result<QueryResult> ExecuteQuery(const std::vector<Finding>& findings,
                                                       const QuerySpec& spec, NdoTime now);

/// Applies a timeline query to a materialized timeline.
NDO_NODISCARD NDO_API Result<TimelinePage> ExecuteTimelineQuery(
    const std::vector<TimelineEntry>& entries, const TimelineSpec& spec);

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_QUERY_HPP
