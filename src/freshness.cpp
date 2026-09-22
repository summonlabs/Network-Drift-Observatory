// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/freshness.hpp"

#include <cstdint>
#include <string_view>

namespace summon {
namespace network_drift_observatory {
namespace {

struct NamePair {
  std::uint8_t value;
  const char* name;
};

constexpr NamePair kStateNames[] = {
    {0, "unknown"},     {1, "fresh"}, {2, "aging"},      {3, "stale"},
    {4, "expired"},     {5, "future"}, {6, "recovered-not-fresh"},
};

}  // namespace

const char* ToText(FreshnessState value) noexcept {
  const std::uint8_t raw = static_cast<std::uint8_t>(value);
  for (const NamePair& entry : kStateNames) {
    if (entry.value == raw) {
      return entry.name;
    }
  }
  return "unknown";
}

bool TryParseFreshnessState(const char* text, FreshnessState& out) noexcept {
  if (text == nullptr) {
    return false;
  }
  const std::string_view wanted(text);
  for (const NamePair& entry : kStateNames) {
    if (wanted == entry.name) {
      out = static_cast<FreshnessState>(entry.value);
      return true;
    }
  }
  return false;
}

FreshnessVerdict EvaluateFreshness(const ObservationSnapshot& snapshot,
                                   const FreshnessPolicy& policy, NdoTime now,
                                   FabricEpoch live_epoch, bool recovered_from_durable_state) {
  FreshnessVerdict verdict;
  verdict.effective_ttl_nanos = policy.ttl_nanos;
  if (snapshot.ttl_nanos > 0 && snapshot.ttl_nanos < verdict.effective_ttl_nanos) {
    // A source may only ask for a stricter lifetime, never a longer one.
    verdict.effective_ttl_nanos = snapshot.ttl_nanos;
  }

  std::int64_t age = 0;
  if (!snapshot.collected_at.is_set() || !TryDifference(now, snapshot.collected_at, age)) {
    verdict.state = FreshnessState::Unknown;
    verdict.reason = ReasonCode::NoFreshEvidence;
    return verdict;
  }
  verdict.age_nanos = age;

  if (recovered_from_durable_state) {
    // Surviving a restart is not evidence of being current. The age is still
    // reported so an operator can see how old the recovered record is.
    verdict.state = FreshnessState::RecoveredNotFresh;
    verdict.reason = ReasonCode::EvidenceRecoveredNotFresh;
    return verdict;
  }

  if (live_epoch.is_set() && snapshot.epoch != live_epoch) {
    verdict.state = FreshnessState::Expired;
    verdict.reason = ReasonCode::ObservationForeignEpoch;
    return verdict;
  }

  if (age < -policy.max_clock_skew_nanos) {
    verdict.state = FreshnessState::Future;
    verdict.reason = ReasonCode::ObservationClockRegression;
    return verdict;
  }

  if (verdict.effective_ttl_nanos <= 0) {
    verdict.state = FreshnessState::Expired;
    verdict.reason = ReasonCode::ObservationExpired;
    return verdict;
  }

  if (age > verdict.effective_ttl_nanos) {
    verdict.state = FreshnessState::Stale;
    verdict.reason = ReasonCode::ObservationExpired;
    return verdict;
  }

  if (policy.ttl_applies_to_receive_time && snapshot.received_at.is_set()) {
    std::int64_t receive_age = 0;
    if (!TryDifference(now, snapshot.received_at, receive_age)) {
      verdict.state = FreshnessState::Unknown;
      verdict.reason = ReasonCode::ObservationClockRegression;
      return verdict;
    }
    if (receive_age > verdict.effective_ttl_nanos) {
      // The snapshot was collected recently but the observatory has been
      // holding it longer than the lifetime allows.
      verdict.state = FreshnessState::Stale;
      verdict.reason = ReasonCode::ObservationExpired;
      return verdict;
    }
  }

  // Aging threshold without overflowing the multiplication: divide first.
  const std::int64_t percent = policy.aging_threshold_percent < 0
                                   ? 0
                                   : (policy.aging_threshold_percent > 100
                                          ? 100
                                          : policy.aging_threshold_percent);
  const std::int64_t threshold =
      (verdict.effective_ttl_nanos / 100) * percent +
      ((verdict.effective_ttl_nanos % 100) * percent) / 100;
  verdict.state = age > threshold ? FreshnessState::Aging : FreshnessState::Fresh;
  verdict.reason = verdict.state == FreshnessState::Aging ? ReasonCode::NoFreshEvidence
                                                         : ReasonCode::None;
  if (verdict.state == FreshnessState::Aging) {
    // Aging evidence is still usable; the reason code records that the
    // observation is approaching the end of its lifetime rather than that the
    // target is non-compliant.
    verdict.reason = ReasonCode::None;
  }
  verdict.may_support_compliance = true;
  verdict.may_assert_absence = snapshot.capabilities.asserts_absence;
  return verdict;
}

}  // namespace network_drift_observatory
}  // namespace summon
