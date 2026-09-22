// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Internal durable-record codecs.
//
// The durable ledger and the exported report must agree byte for byte about
// what a finding is, so both use one encoder. The encoders live in the internal
// detail namespace and are not part of the installed API surface.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_SRC_LEDGER_ENCODE_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_SRC_LEDGER_ENCODE_HPP

#include "summon/network_drift_observatory/finding.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/value.hpp"

namespace summon {
namespace network_drift_observatory {
namespace detail {

NDO_API Value EncodeFinding(const Finding& finding);
NDO_API Value EncodeTimelineEntry(const TimelineEntry& entry);
NDO_API Value EncodeEvidenceRef(const EvidenceRef& reference);
NDO_API Value EncodeGroup(const RootCauseGroup& group);

}  // namespace detail
}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_SRC_LEDGER_ENCODE_HPP
