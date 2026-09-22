// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/finding.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "json_help.hpp"

namespace summon {
namespace network_drift_observatory {
namespace {

struct NamePair {
  std::uint8_t value;
  const char* name;
};

constexpr NamePair kStateNames[] = {
    {0, "open"}, {1, "acknowledged"}, {2, "suppressed"}, {3, "resolved"}, {4, "superseded"},
    {5, "retired"},
};

constexpr NamePair kEventNames[] = {
    {0, "created"},        {1, "updated"},        {2, "reopened"},
    {3, "resolved"},       {4, "suppressed"},     {5, "suppression-expired"},
    {6, "suppression-cleared"}, {7, "acknowledged"}, {8, "acknowledgement-cleared"},
    {9, "reclassified"},   {10, "rebased"},       {11, "evidence-recovered"},
    {12, "grouped"},       {13, "retired"},
};

constexpr NamePair kSuppressionOriginNames[] = {
    {0, "none"},
    {1, "policy"},
    {2, "operator"},
};

constexpr NamePair kCauseNames[] = {
    {0, "none"},           {1, "single-field"},   {2, "generation-not-applied"},
    {3, "partial-application"}, {4, "source-conflict"}, {5, "stale-evidence"},
    {6, "insufficient-coverage"}, {7, "missing-intent"}, {8, "unsupported-field"},
};

constexpr const char* Lookup(const NamePair* table, std::size_t count, std::uint8_t value) noexcept {
  for (std::size_t index = 0; index < count; ++index) {
    if (table[index].value == value) {
      return table[index].name;
    }
  }
  return "invalid";
}

}  // namespace

const char* ToText(FindingState value) noexcept {
  return Lookup(kStateNames, sizeof(kStateNames) / sizeof(kStateNames[0]),
                static_cast<std::uint8_t>(value));
}

bool TryParseFindingState(const char* text, FindingState& out) noexcept {
  if (text == nullptr) {
    return false;
  }
  const std::string_view wanted(text);
  for (const NamePair& entry : kStateNames) {
    if (wanted == entry.name) {
      out = static_cast<FindingState>(entry.value);
      return true;
    }
  }
  return false;
}

bool IsLiveState(FindingState value) noexcept {
  return value == FindingState::Open || value == FindingState::Acknowledged ||
         value == FindingState::Suppressed;
}

const char* ToText(TimelineEventKind value) noexcept {
  return Lookup(kEventNames, sizeof(kEventNames) / sizeof(kEventNames[0]),
                static_cast<std::uint8_t>(value));
}

bool TryParseTimelineEventKind(const char* text, TimelineEventKind& out) noexcept {
  if (text == nullptr) {
    return false;
  }
  const std::string_view wanted(text);
  for (const NamePair& entry : kEventNames) {
    if (wanted == entry.name) {
      out = static_cast<TimelineEventKind>(entry.value);
      return true;
    }
  }
  return false;
}

const char* ToText(SuppressionOrigin value) noexcept {
  return Lookup(kSuppressionOriginNames,
                sizeof(kSuppressionOriginNames) / sizeof(kSuppressionOriginNames[0]),
                static_cast<std::uint8_t>(value));
}

bool TryParseSuppressionOrigin(const char* text, SuppressionOrigin& out) noexcept {
  if (text == nullptr) {
    return false;
  }
  const std::string_view wanted(text);
  for (const NamePair& entry : kSuppressionOriginNames) {
    if (wanted == entry.name) {
      out = static_cast<SuppressionOrigin>(entry.value);
      return true;
    }
  }
  return false;
}

const char* ToText(RootCauseKind value) noexcept {
  return Lookup(kCauseNames, sizeof(kCauseNames) / sizeof(kCauseNames[0]),
                static_cast<std::uint8_t>(value));
}

FindingId FindingIdentity::ComputeId() const {
  Sha256 hasher;
  hasher.UpdateTag(detail::kFindingIdentityTag);
  hasher.UpdateLengthPrefixed(target.str());
  hasher.UpdateLengthPrefixed(object.str());
  hasher.UpdateLengthPrefixed(path.ToText());
  hasher.UpdateLengthPrefixed(ToText(klass));
  hasher.UpdateU64(baseline_generation.value());
  hasher.UpdateU64(qualifier.is_set() ? 1u : 0u);
  if (qualifier.is_set()) {
    hasher.Update(qualifier.bytes.data(), qualifier.bytes.size());
  }
  return FindingId::FromDigest(hasher.Final());
}

std::int64_t Finding::AgeNanos(NdoTime now) const noexcept {
  std::int64_t age = 0;
  if (!TryDifference(now, first_seen, age)) {
    return 0;
  }
  return age;
}

std::string ExplainFinding(const Finding& finding) {
  std::string text;
  text.reserve(256);
  text.append(ToText(finding.klass));
  text.append(" at ");
  text.append(finding.identity.target.str());
  text.append(" ");
  text.append(finding.identity.object.str());
  text.append(" ");
  text.append(finding.identity.path.Describe());
  text.append("; baseline generation ");
  text.append(std::to_string(finding.baseline_generation.value()));
  text.append(" (");
  text.append(ToText(finding.baseline_authority));
  text.append(")");
  if (finding.has_intended) {
    text.append("; intended ");
    text.append(finding.intended.ToDisplayText(96));
  }
  if (finding.has_observed) {
    text.append("; observed ");
    text.append(finding.observed.ToDisplayText(96));
  }
  text.append("; evidence ");
  text.append(ToText(finding.evidence_freshness));
  if (!finding.evidence.empty()) {
    text.append(" from ");
    text.append(finding.evidence.front().source.str());
    text.append(" snapshot ");
    text.append(finding.evidence.front().snapshot.str().substr(0, 12));
    text.append(" collected ");
    text.append(FormatTime(finding.evidence.front().collected_at));
  }
  text.append("; state ");
  text.append(ToText(finding.state));
  text.append("; severity ");
  text.append(ToText(finding.severity));
  text.append("; reason ");
  text.append(ToText(finding.reason));
  if (finding.raw_class != finding.klass) {
    text.append("; raw class ");
    text.append(ToText(finding.raw_class));
  }
  if (finding.suppression.has_value()) {
    text.append("; suppressed by ");
    text.append(finding.suppressed_by.str());
    text.append(" (");
    text.append(finding.suppression->str());
    text.append(") reason ");
    text.append(finding.suppression_reason);
  }
  text.append("; observed ");
  text.append(std::to_string(finding.observation_count));
  text.append(" time(s); reopened ");
  text.append(std::to_string(finding.reopen_count));
  text.append(" time(s)");
  if (text.size() > 1024) {
    text.resize(1024);
    text.append("...");
  }
  return text;
}

}  // namespace network_drift_observatory
}  // namespace summon
