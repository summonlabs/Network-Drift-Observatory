// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/query.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "summon/network_drift_observatory/hash.hpp"

namespace summon {
namespace network_drift_observatory {
namespace {

struct NamePair {
  std::uint8_t value;
  const char* name;
};

constexpr NamePair kOrderNames[] = {
    {0, "severity-descending"}, {1, "first-seen-ascending"}, {2, "last-seen-descending"},
    {3, "target-ascending"},    {4, "identity-ascending"},
};

std::uint8_t FreshnessRank(FreshnessState state) noexcept {
  switch (state) {
    case FreshnessState::Fresh:
      return 4;
    case FreshnessState::Aging:
      return 3;
    case FreshnessState::Stale:
      return 2;
    case FreshnessState::Future:
    case FreshnessState::Expired:
      return 1;
    case FreshnessState::Unknown:
    case FreshnessState::RecoveredNotFresh:
      return 0;
  }
  return 0;
}

bool AgeMatches(const Finding& finding, const QuerySpec& spec, NdoTime now, std::int64_t& age_out) {
  std::int64_t age = 0;
  if (!TryDifference(now, finding.first_seen, age)) {
    age = 0;
  }
  age_out = age;
  if (spec.min_age_nanos.has_value() && age < *spec.min_age_nanos) {
    return false;
  }
  if (spec.max_age_nanos.has_value() && age > *spec.max_age_nanos) {
    return false;
  }
  return true;
}

bool Matches(const Finding& finding, const QuerySpec& spec, NdoTime now) {
  if (spec.target.has_value() && !(finding.identity.target == *spec.target)) {
    return false;
  }
  if (spec.object.has_value() && !(finding.identity.object == *spec.object)) {
    return false;
  }
  if (spec.path_prefix.has_value() && !spec.path_prefix->IsPrefixOf(finding.identity.path)) {
    return false;
  }
  if (spec.generation.has_value() && !(finding.baseline_generation == *spec.generation)) {
    return false;
  }
  if (spec.epoch.has_value() && !(finding.baseline_epoch == *spec.epoch)) {
    return false;
  }
  if (spec.klass.has_value() && !(finding.klass == *spec.klass)) {
    return false;
  }
  if (spec.min_severity.has_value() &&
      SeverityRank(finding.severity) < SeverityRank(*spec.min_severity)) {
    return false;
  }
  if (spec.exact_severity.has_value() && !(finding.severity == *spec.exact_severity)) {
    return false;
  }
  if (spec.state.has_value() && !(finding.state == *spec.state)) {
    return false;
  }
  if (spec.group.has_value() && !(finding.group == *spec.group)) {
    return false;
  }
  if (spec.root_cause.has_value() && !(finding.group_cause == *spec.root_cause)) {
    return false;
  }
  if (spec.source.has_value()) {
    bool found = false;
    for (const EvidenceRef& reference : finding.evidence) {
      if (reference.source == *spec.source) {
        found = true;
        break;
      }
    }
    if (!found) {
      return false;
    }
  }
  if (spec.min_freshness.has_value() &&
      FreshnessRank(finding.evidence_freshness) < FreshnessRank(*spec.min_freshness)) {
    return false;
  }
  std::int64_t age = 0;
  if (!AgeMatches(finding, spec, now, age)) {
    return false;
  }
  switch (finding.state) {
    case FindingState::Resolved:
      return spec.include_resolved;
    case FindingState::Superseded:
      return spec.include_superseded;
    case FindingState::Retired:
      return spec.include_retired;
    case FindingState::Suppressed:
      return spec.include_suppressed;
    default:
      return true;
  }
}

struct SortContext {
  QueryOrder order{QueryOrder::SeverityDescending};
};

bool OrderBefore(const Finding& lhs, const Finding& rhs, QueryOrder order) {
  switch (order) {
    case QueryOrder::SeverityDescending:
      if (lhs.severity != rhs.severity) {
        return SeverityRank(rhs.severity) < SeverityRank(lhs.severity);
      }
      if (!(lhs.last_seen == rhs.last_seen)) {
        return rhs.last_seen < lhs.last_seen;
      }
      break;
    case QueryOrder::FirstSeenAscending:
      if (!(lhs.first_seen == rhs.first_seen)) {
        return lhs.first_seen < rhs.first_seen;
      }
      break;
    case QueryOrder::LastSeenDescending:
      if (!(lhs.last_seen == rhs.last_seen)) {
        return rhs.last_seen < lhs.last_seen;
      }
      break;
    case QueryOrder::TargetAscending:
      if (!(lhs.identity.target == rhs.identity.target)) {
        return lhs.identity.target < rhs.identity.target;
      }
      if (!(lhs.identity.object == rhs.identity.object)) {
        return lhs.identity.object < rhs.identity.object;
      }
      if (!(lhs.identity.path == rhs.identity.path)) {
        return lhs.identity.path < rhs.identity.path;
      }
      break;
    case QueryOrder::IdentityAscending:
      break;
  }
  // Every order is total: identity breaks the remaining ties.
  return lhs.id < rhs.id;
}

}  // namespace

const char* ToText(QueryOrder value) noexcept {
  const std::uint8_t raw = static_cast<std::uint8_t>(value);
  for (const NamePair& entry : kOrderNames) {
    if (entry.value == raw) {
      return entry.name;
    }
  }
  return "invalid";
}

bool TryParseQueryOrder(const char* text, QueryOrder& out) noexcept {
  if (text == nullptr) {
    return false;
  }
  const std::string_view wanted(text);
  for (const NamePair& entry : kOrderNames) {
    if (wanted == entry.name) {
      out = static_cast<QueryOrder>(entry.value);
      return true;
    }
  }
  return false;
}

Result<QueryResult> ExecuteQuery(const std::vector<Finding>& findings, const QuerySpec& spec,
                                 NdoTime now) {
  if (spec.limit == 0) {
    return Status::Rejected(ReasonCode::LimitFindingsExceeded,
                            "a query limit of zero would hide every finding");
  }
  QueryResult result;
  result.evaluated_at = now;
  result.spec = spec;

  std::vector<const Finding*> matched;
  matched.reserve(findings.size());
  for (const Finding& finding : findings) {
    if (Matches(finding, spec, now)) {
      matched.push_back(&finding);
    }
  }
  result.total_matched = matched.size();
  std::sort(matched.begin(), matched.end(), [&spec](const Finding* lhs, const Finding* rhs) {
    return OrderBefore(*lhs, *rhs, spec.order);
  });

  const std::size_t begin = std::min(spec.offset, matched.size());
  const std::size_t end = std::min(begin + spec.limit, matched.size());
  result.truncated = end < matched.size() || begin > 0;
  for (std::size_t index = begin; index < end; ++index) {
    result.findings.push_back(*matched[index]);
  }

  Sha256 hasher;
  hasher.UpdateTag("ndo/query-page/v1");
  hasher.UpdateLengthPrefixed(ToText(spec.order));
  hasher.UpdateU64(result.total_matched);
  hasher.UpdateU64(begin);
  hasher.UpdateU64(result.findings.size());
  for (const Finding& finding : result.findings) {
    hasher.Update(finding.id.digest().bytes.data(), finding.id.digest().bytes.size());
    hasher.UpdateByte(static_cast<std::uint8_t>(finding.state));
    hasher.UpdateU64(finding.observation_count);
  }
  result.page_digest = hasher.Final();
  return result;
}

Result<TimelinePage> ExecuteTimelineQuery(const std::vector<TimelineEntry>& entries,
                                          const TimelineSpec& spec) {
  if (spec.limit == 0) {
    return Status::Rejected(ReasonCode::LimitTimelineExceeded,
                            "a timeline limit of zero would hide every entry");
  }
  TimelinePage page;
  std::vector<const TimelineEntry*> matched;
  matched.reserve(entries.size());
  for (const TimelineEntry& entry : entries) {
    if (spec.finding.has_value() && !(entry.finding == *spec.finding)) {
      continue;
    }
    if (spec.target.has_value() && !(entry.target == *spec.target)) {
      continue;
    }
    if (spec.kind.has_value() && !(entry.kind == *spec.kind)) {
      continue;
    }
    if (spec.since.has_value() && entry.at < *spec.since) {
      continue;
    }
    if (spec.until.has_value() && *spec.until < entry.at) {
      continue;
    }
    matched.push_back(&entry);
  }
  std::sort(matched.begin(), matched.end(),
            [](const TimelineEntry* lhs, const TimelineEntry* rhs) {
              if (lhs->sequence != rhs->sequence) {
                return lhs->sequence < rhs->sequence;
              }
              return lhs->at < rhs->at;
            });
  page.total_matched = matched.size();
  const std::size_t begin = std::min(spec.offset, matched.size());
  const std::size_t end = std::min(begin + spec.limit, matched.size());
  page.truncated = end < matched.size() || begin > 0;
  for (std::size_t index = begin; index < end; ++index) {
    page.entries.push_back(*matched[index]);
  }
  return page;
}

}  // namespace network_drift_observatory
}  // namespace summon
