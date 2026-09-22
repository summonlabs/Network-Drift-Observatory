// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Explicit outcome vocabulary.
//
// The runtime never maps an indeterminate, stale, conflicting, corrupt or
// unsupported condition onto success, and never onto ordinary absence. Every
// such condition has its own status code and its own reason code, and both are
// part of the stable machine-readable contract.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_STATUS_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_STATUS_HPP

#include <cstdint>
#include <string>
#include <utility>

#include "summon/network_drift_observatory/platform.hpp"

namespace summon {
namespace network_drift_observatory {

/// Coarse outcome of one externally visible operation.
enum class StatusCode : std::uint16_t {
  Ok = 0,
  /// Input was malformed, out of range, or refused by policy.
  Rejected = 1,
  /// The call contradicts committed state (generation regression, duplicate
  /// identity with different content, divergent re-publication).
  ConflictState = 2,
  /// The named thing is genuinely absent from the runtime.
  NotFound = 3,
  /// The authority vector the caller supplied does not match live authority.
  StaleAuthority = 4,
  /// A configured bound would be exceeded; the call was refused up front.
  LimitExceeded = 5,
  /// Durable or wire state failed an integrity check. Never silently repaired.
  IntegrityFailure = 6,
  /// Outside the supported problem class.
  Unsupported = 7,
  /// The runtime cannot decide; a caller must never read this as success.
  Indeterminate = 8,
  /// A precondition that must hold did not hold.
  PreconditionFailed = 9,
  /// An internal invariant was violated. Always a defect.
  InternalError = 10,
  /// The operation was cancelled. A cancelled operation never publishes
  /// success, and it never partially mutates authoritative state.
  Cancelled = 11,
};

NDO_API const char* ToText(StatusCode value) noexcept;

/// Deterministic machine-readable explanation code.
///
/// Numeric ranges group codes by concern so a caller can branch on the concern
/// without enumerating every code:
///   100..199  classification
///   200..299  freshness, ordering and coverage
///   300..399  generation, epoch, incarnation and authority fencing
///   400..499  suppression, acknowledgement and lifecycle
///   500..599  persistence and integrity
///   600..699  transport and session
///   700..799  bounds, encoding and payload shape
enum class ReasonCode : std::uint16_t {
  None = 0,

  // ---- classification (100..199) ----
  ClassifiedConverged = 100,
  ClassifiedObjectMissing = 101,
  ClassifiedObjectUnexpected = 102,
  ClassifiedValueMismatch = 103,
  ClassifiedFieldMissing = 104,
  ClassifiedFieldUnexpected = 105,
  ClassifiedFieldNotComparable = 106,
  ClassifiedNotObservable = 107,
  ClassifiedUnsupportedField = 108,
  ClassifiedGenerationMismatch = 109,
  ClassifiedPartialApplication = 110,
  ClassifiedSourceConflict = 111,
  ClassifiedStaleObservation = 112,
  ClassifiedNoIntent = 113,

  // ---- freshness, ordering and coverage (200..299) ----
  ObservationExpired = 200,
  ObservationForeignEpoch = 201,
  ObservationForeignIncarnation = 202,
  ObservationClockRegression = 203,
  ObservationSequenceRegressed = 204,
  ObservationGenerationRegressed = 205,
  ObservationDuplicateIdentical = 206,
  ObservationDuplicateConflicting = 207,
  ObservationCoveragePartial = 208,
  ObservationCoverageUnknown = 209,
  ObservationSourceCannotAssertAbsence = 210,
  ObservationSourcesDisagree = 211,
  ObservationOutOfOrder = 212,
  ObservationSuperseded = 213,
  IntentGenerationRegressed = 220,
  IntentGenerationConflicting = 224,
  IntentGenerationDuplicateIdentical = 221,
  IntentTargetUndeclared = 222,
  IntentCoverageIncomplete = 223,
  NoFreshEvidence = 230,
  EvidenceRecoveredNotFresh = 231,

  // ---- generation, epoch, incarnation and authority fencing (300..399) ----
  FencedStaleEpoch = 300,
  FencedStaleIncarnation = 301,
  FencedStaleSequence = 302,
  FencedStaleGeneration = 303,
  FencedRetiredSource = 304,
  AuthorityMismatch = 310,
  ComparisonBaselineUnavailable = 311,

  // ---- suppression, acknowledgement and lifecycle (400..499) ----
  SuppressedByPolicy = 400,
  SuppressedByOperator = 401,
  SuppressionExpired = 402,
  SuppressionNotFound = 403,
  AcknowledgementRecorded = 404,
  FindingResolved = 410,
  FindingReopened = 411,
  FindingUnchanged = 412,
  FindingCreated = 413,
  FindingUpdated = 414,
  ResolutionRefusedNoFreshEvidence = 415,
  ResolutionRefusedCoverageIncomplete = 416,
  ResolutionRefusedConflict = 417,
  FindingRebasedToNewGeneration = 418,
  FindingReclassified = 419,
  FindingNotFound = 420,
  FindingRetired = 421,

  // ---- persistence and integrity (500..599) ----
  LedgerIntegrityDigestMismatch = 500,
  LedgerSchemaUnsupported = 501,
  LedgerTruncated = 502,
  LedgerHeaderInvalid = 503,
  LedgerPayloadTooLarge = 504,
  LedgerRecoveredConservatively = 505,
  LedgerVersionRegression = 506,
  LedgerDecodeFailed = 507,

  // ---- transport and session (600..699) ----
  WireFrameTruncated = 600,
  WireFrameOversize = 601,
  WireFrameChecksumMismatch = 602,
  WireProtocolVersionUnsupported = 603,
  WireFrameMagicMismatch = 604,
  WireHandshakeRequired = 605,
  WireHandshakeRejected = 606,
  WireSessionLimitExceeded = 607,
  WireSessionClosed = 608,
  WireFrameTypeUnsupported = 609,
  WireSessionIdleExpired = 610,

  // ---- bounds, encoding and payload shape (700..799) ----
  LimitObjectsExceeded = 700,
  LimitFieldsExceeded = 701,
  LimitDepthExceeded = 702,
  LimitBytesExceeded = 703,
  LimitFindingsExceeded = 704,
  LimitHistoryExceeded = 705,
  LimitTimelineExceeded = 706,
  EncodingMalformed = 710,
  EncodingUnexpectedToken = 711,
  EncodingInvalidUtf8 = 712,
  EncodingNumberOutOfRange = 713,
  EncodingDuplicateKey = 714,
  EncodingTrailingBytes = 715,
  ArithmeticOverflow = 720,
};

NDO_API const char* ToText(ReasonCode value) noexcept;
NDO_NODISCARD NDO_API bool TryParseReasonCode(const char* text, ReasonCode& out) noexcept;

/// Which concern a reason code belongs to. Deterministic, total.
NDO_API const char* ReasonCodeDomain(ReasonCode value) noexcept;

/// A coarse status plus the precise reason code that produced it.
struct NDO_API Status {
  StatusCode code{StatusCode::Ok};
  ReasonCode reason{ReasonCode::None};
  /// Optional human-readable detail. Never parsed, never used for decisions.
  std::string detail;

  Status() = default;
  Status(StatusCode c, ReasonCode r) : code(c), reason(r) {}
  Status(StatusCode c, ReasonCode r, std::string d)
      : code(c), reason(r), detail(std::move(d)) {}

  NDO_NODISCARD bool ok() const noexcept { return code == StatusCode::Ok; }
  NDO_NODISCARD explicit operator bool() const noexcept { return ok(); }

  NDO_NODISCARD static Status Ok() noexcept { return Status{}; }
  NDO_NODISCARD static Status Rejected(ReasonCode r, std::string d = {}) {
    return Status(StatusCode::Rejected, r, std::move(d));
  }
  NDO_NODISCARD static Status Conflict(ReasonCode r, std::string d = {}) {
    return Status(StatusCode::ConflictState, r, std::move(d));
  }
  NDO_NODISCARD static Status NotFound(ReasonCode r, std::string d = {}) {
    return Status(StatusCode::NotFound, r, std::move(d));
  }
  NDO_NODISCARD static Status Stale(ReasonCode r, std::string d = {}) {
    return Status(StatusCode::StaleAuthority, r, std::move(d));
  }
  NDO_NODISCARD static Status Limit(ReasonCode r, std::string d = {}) {
    return Status(StatusCode::LimitExceeded, r, std::move(d));
  }
  NDO_NODISCARD static Status Integrity(ReasonCode r, std::string d = {}) {
    return Status(StatusCode::IntegrityFailure, r, std::move(d));
  }
  NDO_NODISCARD static Status Unsupported(ReasonCode r, std::string d = {}) {
    return Status(StatusCode::Unsupported, r, std::move(d));
  }
  NDO_NODISCARD static Status Indeterminate(ReasonCode r, std::string d = {}) {
    return Status(StatusCode::Indeterminate, r, std::move(d));
  }
  NDO_NODISCARD static Status Precondition(ReasonCode r, std::string d = {}) {
    return Status(StatusCode::PreconditionFailed, r, std::move(d));
  }
  NDO_NODISCARD static Status Internal(ReasonCode r, std::string d = {}) {
    return Status(StatusCode::InternalError, r, std::move(d));
  }
  NDO_NODISCARD static Status Cancelled(ReasonCode r, std::string d = {}) {
    return Status(StatusCode::Cancelled, r, std::move(d));
  }
};

/// Fallible operation result. A default-constructed Result is a failure, so a
/// forgotten return path can never be read as success.
template <typename T>
class Result {
 public:
  Result() : status_(StatusCode::InternalError, ReasonCode::None, "unset result") {}

  Result(T value) : status_(), value_(std::move(value)) {}  // NOLINT(google-explicit-constructor)
  Result(Status status) : status_(std::move(status)) {  // NOLINT(google-explicit-constructor)
    if (status_.ok()) {
      status_ = Status(StatusCode::InternalError, ReasonCode::None, "ok status without value");
    }
  }

  NDO_NODISCARD bool ok() const noexcept { return status_.ok(); }
  NDO_NODISCARD explicit operator bool() const noexcept { return ok(); }
  NDO_NODISCARD const Status& status() const noexcept { return status_; }

  NDO_NODISCARD const T& value() const { return value_; }
  NDO_NODISCARD T& value() { return value_; }
  NDO_NODISCARD T&& take() { return std::move(value_); }

 private:
  Status status_;
  T value_{};
};

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_STATUS_HPP
