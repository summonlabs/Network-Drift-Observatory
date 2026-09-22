// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Interchange codecs for intent and observation documents.
//
// These are the documents the observatory accepts from Intent Fabric,
// Configuration Fabric or any other vendor-neutral producer. Decoding is
// strict: every member is typed, every bound is checked, an unknown member is
// a refusal, and a document whose declared integrity digest does not match its
// content is rejected rather than repaired.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_INTERCHANGE_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_INTERCHANGE_HPP

#include <string>
#include <string_view>

#include "summon/network_drift_observatory/intent.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/observation.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/value.hpp"

namespace summon {
namespace network_drift_observatory {

/// Encodes an intent generation document.
NDO_NODISCARD NDO_API Value EncodeIntentDocument(const IntentGenerationDocument& document);
/// Decodes an intent generation document. received/stamped members are not
/// accepted: intent is never re-timed by the observatory.
NDO_NODISCARD NDO_API Status DecodeIntentDocument(const Value& value, const RuntimeLimits& limits,
                                                  IntentGenerationDocument& out);

/// Encodes an observation snapshot in its wire/interchange form. The snapshot
/// identity and payload digest are derived from the content and are therefore
/// not carried as free members.
NDO_NODISCARD NDO_API Value EncodeObservationDocument(const ObservationSnapshot& snapshot);
/// Decodes an observation snapshot. Refuses a document whose declared snapshot
/// identity does not match its content, refuses unknown members, and never
/// trusts a caller-supplied receive time.
NDO_NODISCARD NDO_API Status DecodeObservationDocument(const Value& value,
                                                       const RuntimeLimits& limits,
                                                       ObservationSnapshot& out);

/// Encodes and decodes a source descriptor.
NDO_NODISCARD NDO_API Value EncodeSourceDescriptor(const SourceDescriptor& descriptor);
NDO_NODISCARD NDO_API Status DecodeSourceDescriptor(const Value& value,
                                                    const RuntimeLimits& limits,
                                                    SourceDescriptor& out);

/// Parses a JSON text into an intent or observation document.
NDO_NODISCARD NDO_API Status ParseIntentJson(std::string_view text, const RuntimeLimits& limits,
                                             IntentGenerationDocument& out);
NDO_NODISCARD NDO_API Status ParseObservationJson(std::string_view text,
                                                  const RuntimeLimits& limits,
                                                  ObservationSnapshot& out);

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_INTERCHANGE_HPP
