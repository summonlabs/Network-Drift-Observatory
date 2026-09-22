// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Bounded resource envelope and evidence classification.
//
// Every table, history, queue, document and report in the runtime is bounded.
// Exceeding a bound produces a deterministic refusal, never unbounded growth
// and never process instability. The envelope is explicit so that an operator
// can reason about the observatory's memory and file footprint up front.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_LIMITS_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_LIMITS_HPP

#include <cstddef>
#include <cstdint>

#include "summon/network_drift_observatory/platform.hpp"

namespace summon {
namespace network_drift_observatory {

/// How a piece of evidence was produced.
///
/// The label travels with every observation, finding, group and report so a
/// reader can never mistake a synthetic fixture for a physical network
/// element. The observatory performs no hardware-specific claim of its own.
enum class EvidenceClass : std::uint8_t {
  Unknown = 0,
  /// Produced by, or about, real network elements actually exercised.
  Real = 1,
  /// Produced by deterministic synthetic fixtures. No hardware involved.
  Synthetic = 2,
  /// The runtime cannot express this quantity at all, and says so instead of
  /// substituting a plausible value.
  Unsupported = 3,
};

NDO_API const char* ToText(EvidenceClass value) noexcept;
NDO_NODISCARD NDO_API bool TryParseEvidenceClass(const char* text, EvidenceClass& out) noexcept;

/// Hard resource envelope for one observatory incarnation.
struct NDO_API RuntimeLimits {
  /// Maximum distinct targets the observatory tracks.
  std::size_t max_targets = 4096;
  /// Maximum intent objects accepted for one target.
  std::size_t max_objects_per_target = 200000;
  /// Maximum fields accepted in one intent object or one observed object.
  std::size_t max_fields_per_object = 512;
  /// Maximum nesting depth of a value tree.
  std::size_t max_value_depth = 16;
  /// Maximum nodes (scalars plus containers) in one value tree.
  std::size_t max_value_nodes = 4096;
  /// Maximum byte length of one string or byte-string leaf.
  std::size_t max_leaf_bytes = 4096;
  /// Maximum size of one encoded observation document, checked before parse.
  std::size_t max_document_bytes = 32u * 1024u * 1024u;
  /// Maximum path segments in one field path.
  std::size_t max_path_segments = 32;
  /// Maximum byte length of one path key.
  std::size_t max_path_key_bytes = 256;
  /// Maximum distinct observation sources.
  std::size_t max_sources = 256;
  /// Retained observation snapshots per (target, source) pair.
  std::size_t max_retained_snapshots_per_source = 8;
  /// Maximum drift findings held in the ledger.
  std::size_t max_findings = 500000;
  /// Maximum timeline entries retained per finding.
  std::size_t max_timeline_entries_per_finding = 32;
  /// Maximum timeline entries retained globally.
  std::size_t max_global_timeline_entries = 200000;
  /// Maximum live suppression records.
  std::size_t max_suppressions = 65536;
  /// Maximum root-cause groups.
  std::size_t max_groups = 100000;
  /// Maximum evidence references attached to one finding.
  std::size_t max_evidence_refs_per_finding = 8;
  /// Maximum findings serialized into one report.
  std::size_t max_report_findings = 500000;
  /// Maximum byte size of a persisted ledger file the runtime will read.
  std::size_t max_ledger_bytes = 512u * 1024u * 1024u;
  /// Maximum byte size of any single persisted record payload.
  std::size_t max_record_payload_bytes = 64u * 1024u * 1024u;
  /// Maximum concurrent transport sessions served by one observatory.
  std::size_t max_sessions = 64;
  /// Maximum frames one session may have in flight before it is refused.
  std::size_t max_in_flight_frames_per_session = 8;
  /// Maximum byte length of one wire payload, checked before allocation.
  std::size_t max_wire_payload_bytes = 16u * 1024u * 1024u;
  /// Idle session deadline in nanoseconds. Enforced by the server as a real
  /// resource bound; the observatory disconnects a silent session.
  std::int64_t session_idle_timeout_nanos = 600LL * 1000LL * 1000LL * 1000LL;
  /// Maximum worker threads the observatory will start for evaluation.
  std::size_t max_evaluation_workers = 16;
};

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_LIMITS_HPP
