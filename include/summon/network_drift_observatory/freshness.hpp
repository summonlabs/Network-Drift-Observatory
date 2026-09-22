// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Freshness-aware state.
//
// The observatory never treats the absence of fresh evidence as compliance.
// Every conclusion about a target is derived from evidence that passed an
// explicit freshness, epoch and integrity test, and every refusal names the
// test that failed.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_FRESHNESS_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_FRESHNESS_HPP

#include <cstdint>

#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/observation.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/time.hpp"

namespace summon {
namespace network_drift_observatory {

/// Where a piece of evidence sits relative to policy time-to-live.
enum class FreshnessState : std::uint8_t {
  /// No evidence, or evidence whose age cannot be established.
  Unknown = 0,
  /// Within the aging threshold. May support a compliance conclusion.
  Fresh = 1,
  /// Past the aging threshold but within the time-to-live. May still support a
  /// compliance conclusion; reported so that the degradation is visible.
  Aging = 2,
  /// Past the time-to-live. Never supports a compliance conclusion.
  Stale = 3,
  /// The evidence is older than any tolerated age, or its epoch is foreign.
  Expired = 4,
  /// The collection time is in the future beyond the tolerated skew.
  Future = 5,
  /// The evidence was recovered from durable state. It is never fresh, whatever
  /// its age says, until a new observation replaces it.
  RecoveredNotFresh = 6,
};

NDO_API const char* ToText(FreshnessState value) noexcept;
NDO_NODISCARD NDO_API bool TryParseFreshnessState(const char* text, FreshnessState& out) noexcept;

/// Policy for how long evidence stays usable.
struct NDO_API FreshnessPolicy {
  /// Default time-to-live in nanoseconds for a target without a specific rule.
  std::int64_t ttl_nanos{300LL * 1000LL * 1000LL * 1000LL};
  /// Fraction of the time-to-live after which evidence is reported as Aging.
  std::int32_t aging_threshold_percent{80};
  /// Tolerated clock skew between source and observatory.
  std::int64_t max_clock_skew_nanos{5LL * 1000LL * 1000LL * 1000LL};
  /// When set, evidence whose receive time precedes the evaluation time by more
  /// than the time-to-live is expired even if the collection time is recent.
  bool ttl_applies_to_receive_time{true};

  friend bool operator==(const FreshnessPolicy&, const FreshnessPolicy&) = default;
};

/// The complete explanation of one freshness decision.
struct NDO_API FreshnessVerdict {
  FreshnessState state{FreshnessState::Unknown};
  ReasonCode reason{ReasonCode::NoFreshEvidence};
  /// now - collected_at. Negative for evidence from the future.
  std::int64_t age_nanos{0};
  /// The time-to-live that was applied (policy value, or a stricter value
  /// requested by the source).
  std::int64_t effective_ttl_nanos{0};
  /// True when this evidence may support a "target complies" conclusion.
  bool may_support_compliance{false};
  /// True when this evidence may support an "object is absent" conclusion.
  bool may_assert_absence{false};

  NDO_NODISCARD bool is_fresh() const noexcept {
    return state == FreshnessState::Fresh || state == FreshnessState::Aging;
  }
};

/// Evaluates one snapshot against policy, live epoch and live incarnation.
///
/// The verdict is a pure function of its inputs. It never consults a clock.
NDO_NODISCARD NDO_API FreshnessVerdict EvaluateFreshness(const ObservationSnapshot& snapshot,
                                                         const FreshnessPolicy& policy,
                                                         NdoTime now, FabricEpoch live_epoch,
                                                         bool recovered_from_durable_state);

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_FRESHNESS_HPP
