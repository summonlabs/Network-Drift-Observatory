// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Strict, bounded canonical JSON codec.
//
// The codec is the interchange boundary of the runtime: observation documents,
// intent documents, reports and the CLI all pass through it. It refuses
// duplicate keys, trailing bytes, invalid UTF-8, out-of-range numbers and any
// document that exceeds the configured envelope, and it never repairs input.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_JSON_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_JSON_HPP

#include <string>
#include <string_view>

#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/value.hpp"

namespace summon {
namespace network_drift_observatory {

/// Writes a value as canonical JSON: members in ascending key order, shortest
/// round-trippable number forms, no insignificant whitespace when compact.
NDO_NODISCARD NDO_API std::string WriteCanonicalJson(const Value& value);

/// Writes canonical JSON with two-space indentation for human inspection. The
/// output parses back to exactly the same value.
NDO_NODISCARD NDO_API std::string WritePrettyJson(const Value& value, std::size_t indent_width = 2);

/// Parses a complete JSON document. Returns Rejected with a precise reason code
/// for any malformed input, and never publishes a partially built value.
NDO_NODISCARD NDO_API Status ParseJson(std::string_view text, const RuntimeLimits& limits,
                                       Value& out);

/// Escapes a string for inclusion in JSON text (including the quotes).
NDO_NODISCARD NDO_API std::string JsonQuote(std::string_view text);

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_JSON_HPP
