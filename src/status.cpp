// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/status.hpp"

#include <cstdint>
#include <string_view>

namespace summon {
namespace network_drift_observatory {
namespace {

struct CodeName {
  std::uint16_t code;
  const char* name;
};

constexpr CodeName kStatusNames[] = {
    {0, "Ok"},
    {1, "Rejected"},
    {2, "ConflictState"},
    {3, "NotFound"},
    {4, "StaleAuthority"},
    {5, "LimitExceeded"},
    {6, "IntegrityFailure"},
    {7, "Unsupported"},
    {8, "Indeterminate"},
    {9, "PreconditionFailed"},
    {10, "InternalError"},
    {11, "Cancelled"},
};

constexpr CodeName kReasonNames[] = {
    {0, "None"},
    {100, "ClassifiedConverged"},
    {101, "ClassifiedObjectMissing"},
    {102, "ClassifiedObjectUnexpected"},
    {103, "ClassifiedValueMismatch"},
    {104, "ClassifiedFieldMissing"},
    {105, "ClassifiedFieldUnexpected"},
    {106, "ClassifiedFieldNotComparable"},
    {107, "ClassifiedNotObservable"},
    {108, "ClassifiedUnsupportedField"},
    {109, "ClassifiedGenerationMismatch"},
    {110, "ClassifiedPartialApplication"},
    {111, "ClassifiedSourceConflict"},
    {112, "ClassifiedStaleObservation"},
    {113, "ClassifiedNoIntent"},
    {200, "ObservationExpired"},
    {201, "ObservationForeignEpoch"},
    {202, "ObservationForeignIncarnation"},
    {203, "ObservationClockRegression"},
    {204, "ObservationSequenceRegressed"},
    {205, "ObservationGenerationRegressed"},
    {206, "ObservationDuplicateIdentical"},
    {207, "ObservationDuplicateConflicting"},
    {208, "ObservationCoveragePartial"},
    {209, "ObservationCoverageUnknown"},
    {210, "ObservationSourceCannotAssertAbsence"},
    {211, "ObservationSourcesDisagree"},
    {212, "ObservationOutOfOrder"},
    {213, "ObservationSuperseded"},
    {220, "IntentGenerationRegressed"},
    {224, "IntentGenerationConflicting"},
    {221, "IntentGenerationDuplicateIdentical"},
    {222, "IntentTargetUndeclared"},
    {223, "IntentCoverageIncomplete"},
    {230, "NoFreshEvidence"},
    {231, "EvidenceRecoveredNotFresh"},
    {300, "FencedStaleEpoch"},
    {301, "FencedStaleIncarnation"},
    {302, "FencedStaleSequence"},
    {303, "FencedStaleGeneration"},
    {304, "FencedRetiredSource"},
    {310, "AuthorityMismatch"},
    {311, "ComparisonBaselineUnavailable"},
    {400, "SuppressedByPolicy"},
    {401, "SuppressedByOperator"},
    {402, "SuppressionExpired"},
    {403, "SuppressionNotFound"},
    {404, "AcknowledgementRecorded"},
    {410, "FindingResolved"},
    {411, "FindingReopened"},
    {412, "FindingUnchanged"},
    {413, "FindingCreated"},
    {414, "FindingUpdated"},
    {415, "ResolutionRefusedNoFreshEvidence"},
    {416, "ResolutionRefusedCoverageIncomplete"},
    {417, "ResolutionRefusedConflict"},
    {418, "FindingRebasedToNewGeneration"},
    {419, "FindingReclassified"},
    {420, "FindingNotFound"},
    {421, "FindingRetired"},
    {500, "LedgerIntegrityDigestMismatch"},
    {501, "LedgerSchemaUnsupported"},
    {502, "LedgerTruncated"},
    {503, "LedgerHeaderInvalid"},
    {504, "LedgerPayloadTooLarge"},
    {505, "LedgerRecoveredConservatively"},
    {506, "LedgerVersionRegression"},
    {507, "LedgerDecodeFailed"},
    {600, "WireFrameTruncated"},
    {601, "WireFrameOversize"},
    {602, "WireFrameChecksumMismatch"},
    {603, "WireProtocolVersionUnsupported"},
    {604, "WireFrameMagicMismatch"},
    {605, "WireHandshakeRequired"},
    {606, "WireHandshakeRejected"},
    {607, "WireSessionLimitExceeded"},
    {608, "WireSessionClosed"},
    {609, "WireFrameTypeUnsupported"},
    {610, "WireSessionIdleExpired"},
    {700, "LimitObjectsExceeded"},
    {701, "LimitFieldsExceeded"},
    {702, "LimitDepthExceeded"},
    {703, "LimitBytesExceeded"},
    {704, "LimitFindingsExceeded"},
    {705, "LimitHistoryExceeded"},
    {706, "LimitTimelineExceeded"},
    {710, "EncodingMalformed"},
    {711, "EncodingUnexpectedToken"},
    {712, "EncodingInvalidUtf8"},
    {713, "EncodingNumberOutOfRange"},
    {714, "EncodingDuplicateKey"},
    {715, "EncodingTrailingBytes"},
    {720, "ArithmeticOverflow"},
};

constexpr const char* Lookup(const CodeName* table, std::size_t count,
                             std::uint16_t code) noexcept {
  for (std::size_t index = 0; index < count; ++index) {
    if (table[index].code == code) {
      return table[index].name;
    }
  }
  return "Unknown";
}

}  // namespace

const char* ToText(StatusCode value) noexcept {
  return Lookup(kStatusNames, sizeof(kStatusNames) / sizeof(kStatusNames[0]),
                static_cast<std::uint16_t>(value));
}

const char* ToText(ReasonCode value) noexcept {
  return Lookup(kReasonNames, sizeof(kReasonNames) / sizeof(kReasonNames[0]),
                static_cast<std::uint16_t>(value));
}

bool TryParseReasonCode(const char* text, ReasonCode& out) noexcept {
  if (text == nullptr) {
    return false;
  }
  const std::string_view wanted(text);
  for (const CodeName& entry : kReasonNames) {
    if (wanted == entry.name) {
      out = static_cast<ReasonCode>(entry.code);
      return true;
    }
  }
  return false;
}

const char* ReasonCodeDomain(ReasonCode value) noexcept {
  const std::uint16_t code = static_cast<std::uint16_t>(value);
  if (code == 0) {
    return "none";
  }
  if (code < 100) {
    return "invalid";
  }
  if (code < 200) {
    return "classification";
  }
  if (code < 300) {
    return "freshness";
  }
  if (code < 400) {
    return "authority";
  }
  if (code < 500) {
    return "lifecycle";
  }
  if (code < 600) {
    return "persistence";
  }
  if (code < 700) {
    return "transport";
  }
  if (code < 800) {
    return "bounds";
  }
  return "unknown";
}

}  // namespace network_drift_observatory
}  // namespace summon
