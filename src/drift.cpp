// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/drift.hpp"

#include <cstdint>
#include <string_view>

namespace summon {
namespace network_drift_observatory {
namespace {

struct NamePair {
  std::uint8_t value;
  const char* name;
};

constexpr NamePair kSeverityNames[] = {
    {0, "info"}, {1, "low"}, {2, "medium"}, {3, "high"}, {4, "critical"},
};

constexpr NamePair kDriftClassNames[] = {
    {0, "none"},
    {1, "missing"},
    {2, "unexpected"},
    {3, "value-mismatch"},
    {4, "field-missing"},
    {5, "field-unexpected"},
    {6, "stale-observation"},
    {7, "unknown"},
    {8, "unsupported"},
    {9, "generation-mismatch"},
    {10, "partial-application"},
    {11, "source-conflict"},
    {12, "intent-missing"},
    {13, "evidence-invalid"},
};

constexpr const char* Lookup(const NamePair* table, std::size_t count,
                             std::uint8_t value) noexcept {
  for (std::size_t index = 0; index < count; ++index) {
    if (table[index].value == value) {
      return table[index].name;
    }
  }
  return "invalid";
}

}  // namespace

const char* ToText(Severity value) noexcept {
  return Lookup(kSeverityNames, sizeof(kSeverityNames) / sizeof(kSeverityNames[0]),
                static_cast<std::uint8_t>(value));
}

bool TryParseSeverity(const char* text, Severity& out) noexcept {
  if (text == nullptr) {
    return false;
  }
  const std::string_view wanted(text);
  for (const NamePair& entry : kSeverityNames) {
    if (wanted == entry.name) {
      out = static_cast<Severity>(entry.value);
      return true;
    }
  }
  return false;
}

std::uint8_t SeverityRank(Severity value) noexcept {
  return static_cast<std::uint8_t>(value);
}

const char* ToText(DriftClass value) noexcept {
  return Lookup(kDriftClassNames, sizeof(kDriftClassNames) / sizeof(kDriftClassNames[0]),
                static_cast<std::uint8_t>(value));
}

bool TryParseDriftClass(const char* text, DriftClass& out) noexcept {
  if (text == nullptr) {
    return false;
  }
  const std::string_view wanted(text);
  for (const NamePair& entry : kDriftClassNames) {
    if (wanted == entry.name) {
      out = static_cast<DriftClass>(entry.value);
      return true;
    }
  }
  return false;
}

bool IsActionableDrift(DriftClass value) noexcept {
  switch (value) {
    case DriftClass::Missing:
    case DriftClass::Unexpected:
    case DriftClass::ValueMismatch:
    case DriftClass::FieldMissing:
    case DriftClass::FieldUnexpected:
    case DriftClass::GenerationMismatch:
    case DriftClass::PartialApplication:
    case DriftClass::SourceConflict:
      return true;
    default:
      return false;
  }
}

bool IsIndeterminateDrift(DriftClass value) noexcept {
  switch (value) {
    case DriftClass::StaleObservation:
    case DriftClass::Unknown:
    case DriftClass::EvidenceInvalid:
      return true;
    default:
      return false;
  }
}

bool IsStructuralDrift(DriftClass value) noexcept {
  switch (value) {
    case DriftClass::Unsupported:
    case DriftClass::IntentMissing:
    case DriftClass::EvidenceInvalid:
      return true;
    default:
      return false;
  }
}

}  // namespace network_drift_observatory
}  // namespace summon
