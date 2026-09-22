// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Drift vocabulary.
//
// Every condition the observatory can detect has its own enumerator. No
// condition is folded into success, and no condition is folded into ordinary
// absence. The vocabulary is part of the stable machine-readable contract.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_DRIFT_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_DRIFT_HPP

#include <cstddef>
#include <cstdint>

#include "summon/network_drift_observatory/platform.hpp"

namespace summon {
namespace network_drift_observatory {

/// How badly a finding diverges from intent.
enum class Severity : std::uint8_t {
  Info = 0,
  Low = 1,
  Medium = 2,
  High = 3,
  Critical = 4,
};

NDO_API const char* ToText(Severity value) noexcept;
NDO_NODISCARD NDO_API bool TryParseSeverity(const char* text, Severity& out) noexcept;
/// Numeric rank used for ordering and thresholds. Larger is more severe.
NDO_NODISCARD NDO_API std::uint8_t SeverityRank(Severity value) noexcept;

/// The complete drift vocabulary.
enum class DriftClass : std::uint8_t {
  /// No drift. Recorded so that a resolution is explainable, never as a finding.
  None = 0,
  /// Intent expects the object to exist; fresh evidence says it does not.
  Missing = 1,
  /// Fresh evidence reports an object the committed intent does not declare.
  Unexpected = 2,
  /// Both sides exist and a managed field differs.
  ValueMismatch = 3,
  /// A managed field is declared by intent and absent from a complete, fresh
  /// observation of an object that the source can see in full.
  FieldMissing = 4,
  /// A managed field is observed but not declared by intent.
  FieldUnexpected = 5,
  /// The best available evidence for the target is not fresh. The runtime never
  /// falls back to older evidence to declare compliance.
  StaleObservation = 6,
  /// Coverage is insufficient to decide: a partially visible target, an
  /// unobservable field, or a source that cannot assert absence.
  Unknown = 7,
  /// The field lies outside the supported comparison class of this runtime.
  Unsupported = 8,
  /// The observation was collected under a different intent generation or
  /// fabric epoch than the committed baseline, or the target reports an applied
  /// generation that is not the intended one.
  GenerationMismatch = 9,
  /// Fresh evidence shows some, but not all, intended fields of one generation
  /// applied at the target: a partially applied change.
  PartialApplication = 10,
  /// Two live sources disagree about the same field at the same generation.
  SourceConflict = 11,
  /// No intent exists for a target that policy requires to be managed.
  IntentMissing = 12,
  /// Reserved: evidence whose integrity is found broken *after* admission, for
  /// example by a future verification pass over durable state. Malformed,
  /// self-inconsistent or integrity-failing evidence is refused at the
  /// boundary and never becomes a finding, so this runtime does not currently
  /// emit this class; it stays in the vocabulary because a consumer may see it
  /// from a later release and must not misread it as compliance.
  EvidenceInvalid = 13,
};

inline constexpr std::size_t kDriftClassCount = 14;

NDO_API const char* ToText(DriftClass value) noexcept;
NDO_NODISCARD NDO_API bool TryParseDriftClass(const char* text, DriftClass& out) noexcept;

/// True when the class means "the runtime decided that state diverges from
/// intent and knows what the difference is".
NDO_NODISCARD NDO_API bool IsActionableDrift(DriftClass value) noexcept;
/// True when the class means "the runtime cannot decide from this evidence".
NDO_NODISCARD NDO_API bool IsIndeterminateDrift(DriftClass value) noexcept;
/// True when the class can never be satisfied by waiting for new evidence, and
/// therefore requires a change to intent, policy or the runtime itself.
NDO_NODISCARD NDO_API bool IsStructuralDrift(DriftClass value) noexcept;

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_DRIFT_HPP
