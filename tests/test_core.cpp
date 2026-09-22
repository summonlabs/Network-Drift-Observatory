// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Identities, digests, paths and time.

#include <string>
#include <type_traits>
#include <vector>

#include "summon/network_drift_observatory/checked.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

using namespace ndotest;

NDO_TEST(Sha256KnownAnswers) {
  NDO_CHECK_EQ(ndo::HashText("").ToHex(),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  NDO_CHECK_EQ(ndo::HashText("abc").ToHex(),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  NDO_CHECK_EQ(
      ndo::HashText("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").ToHex(),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

  // Incremental hashing must agree with one-shot hashing at every split point.
  const std::string long_text(1000, 'a');
  const ndo::Digest one_shot = ndo::HashText(long_text);
  for (std::size_t split = 0; split <= long_text.size(); split += 37) {
    ndo::Sha256 hasher;
    hasher.Update(long_text.substr(0, split));
    hasher.Update(long_text.substr(split));
    NDO_CHECK(hasher.Final() == one_shot);
  }

  // A one-megabyte input exercises multi-block compression.
  const std::string megabyte(1000000, 'a');
  NDO_CHECK_EQ(ndo::HashText(megabyte).ToHex(),
               std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

NDO_TEST(Crc32KnownAnswer) {
  const std::string text = "123456789";
  NDO_CHECK_EQ(ndo::Crc32(text.data(), text.size()), 0xCBF43926u);
  NDO_CHECK_EQ(ndo::Crc32(nullptr, 0), 0u);
}

NDO_TEST(DigestTextRoundTrip) {
  const ndo::Digest digest = ndo::HashText("payload");
  const std::string hex = digest.ToHex();
  NDO_CHECK_EQ(hex.size(), ndo::kDigestHexLength);
  const auto parsed = ndo::Digest::TryFromHex(hex);
  NDO_CHECK(parsed.has_value());
  if (parsed.has_value()) {
    NDO_CHECK(*parsed == digest);
  }
  NDO_CHECK(!ndo::Digest::TryFromHex("").has_value());
  NDO_CHECK(!ndo::Digest::TryFromHex(std::string(63, 'a')).has_value());
  NDO_CHECK(!ndo::Digest::TryFromHex(std::string(64, 'z')).has_value());
  std::string upper = hex;
  for (char& c : upper) {
    if (c >= 'a' && c <= 'f') {
      c = static_cast<char>(c - 'a' + 'A');
    }
  }
  const auto parsed_upper = ndo::Digest::TryFromHex(upper);
  NDO_CHECK(parsed_upper.has_value());
  if (parsed_upper.has_value()) {
    NDO_CHECK_EQ(parsed_upper->ToHex(), hex);
  }
  NDO_CHECK_EQ(digest.ToShortHex(), hex.substr(0, 12));
  NDO_CHECK(!ndo::Digest{}.is_set());
}

NDO_TEST(IdentityTextValidation) {
  NDO_CHECK(ndo::IsValidIdentityText("switch/rack-7/port-eth0"));
  NDO_CHECK(ndo::IsValidIdentityText("policy/default"));
  NDO_CHECK(ndo::IsValidIdentityText("collector@site-a"));
  NDO_CHECK(!ndo::IsValidIdentityText(""));
  NDO_CHECK(!ndo::IsValidIdentityText("/leading"));
  NDO_CHECK(!ndo::IsValidIdentityText("trailing/"));
  NDO_CHECK(!ndo::IsValidIdentityText("has space"));
  NDO_CHECK(!ndo::IsValidIdentityText(std::string(ndo::kMaxIdentityLength + 1, 'a')));
  NDO_CHECK(!ndo::IsValidIdentityText(".."));
  NDO_CHECK(!ndo::IsValidIdentityText("a/../b"));
  NDO_CHECK(!ndo::IsValidIdentityText(std::string("nul", 3) + std::string(1, '\0') + "byte"));

  const auto parsed = ndo::TargetId::TryParse("switch/1");
  NDO_CHECK(parsed.has_value());
  NDO_CHECK(!parsed->empty());
  NDO_CHECK(!ndo::TargetId::TryParse("switch 1").has_value());
}

NDO_TEST(StrongUintSemantics) {
  const ndo::IntentGeneration unset;
  NDO_CHECK(!unset.is_set());
  const ndo::IntentGeneration one = ndo::IntentGeneration::FromValue(1);
  NDO_CHECK(one.is_set());
  NDO_CHECK(unset < one);
  const ndo::FabricEpoch epoch = ndo::FabricEpoch::FromValue(2);
  NDO_CHECK(epoch.value() == 2);
  static_assert(!std::is_convertible_v<ndo::FabricEpoch, ndo::IntentGeneration>,
                "generation and epoch are distinct types");
}

NDO_TEST(FieldPathParsingAndOrdering) {
  const auto simple = ndo::FieldPath::TryParse("mtu", 32, 256);
  NDO_CHECK(simple.has_value());
  NDO_CHECK_EQ(simple->ToText(), std::string("mtu"));
  NDO_CHECK_EQ(simple->Describe(), std::string("mtu"));

  const auto nested = ndo::FieldPath::TryParse("acl.rules[3].action", 32, 256);
  NDO_CHECK(nested.has_value());
  NDO_CHECK_EQ(nested->size(), std::size_t{4});
  NDO_CHECK_EQ(nested->ToText(), std::string("acl.rules[3].action"));
  NDO_CHECK((*nested)[2].kind == ndo::PathSegment::Kind::Index);
  NDO_CHECK_EQ((*nested)[2].index, std::uint64_t{3});

  // A dot inside a key is escaped and survives a round trip.
  const std::string escaped_text = std::string("a") + "\\" + ".b";
  const auto escaped = ndo::FieldPath::TryParse(escaped_text, 32, 256);
  NDO_CHECK(escaped.has_value());
  if (escaped.has_value()) {
    NDO_CHECK_EQ(escaped->ToText(), escaped_text);
    NDO_CHECK_EQ((*escaped)[0].key, std::string("a.b"));
  }

  // The empty path is the object root.
  const auto root_path = ndo::FieldPath::TryParse("", 32, 256);
  NDO_CHECK(root_path.has_value());
  NDO_CHECK(root_path->empty());
  NDO_CHECK_EQ(root_path->ToText(), std::string(""));
  NDO_CHECK_EQ(root_path->Describe(), std::string("<root>"));

  // Refusals.
  NDO_CHECK(!ndo::FieldPath::TryParse("a..b", 32, 256).has_value());
  NDO_CHECK(!ndo::FieldPath::TryParse("a.", 32, 256).has_value());
  NDO_CHECK(!ndo::FieldPath::TryParse(".a", 32, 256).has_value());
  NDO_CHECK(!ndo::FieldPath::TryParse("a[", 32, 256).has_value());
  NDO_CHECK(!ndo::FieldPath::TryParse("a[]", 32, 256).has_value());
  NDO_CHECK(!ndo::FieldPath::TryParse("a[01]", 32, 256).has_value());
  NDO_CHECK(!ndo::FieldPath::TryParse("a[x]", 32, 256).has_value());
  NDO_CHECK(!ndo::FieldPath::TryParse("a[99999999999999999999999]", 32, 256).has_value());
  NDO_CHECK(!ndo::FieldPath::TryParse("a.b.c", 2, 256).has_value());

  // Ordering is total and stable.
  const auto first = ndo::FieldPath::TryParse("a.b", 32, 256).value();
  const auto second = ndo::FieldPath::TryParse("a[0]", 32, 256).value();
  const auto third = ndo::FieldPath::TryParse("a.c", 32, 256).value();
  const auto prefix = ndo::FieldPath::TryParse("a", 32, 256).value();
  // Keys sort before indices at the same depth, and shorter paths sort first.
  NDO_CHECK(first < third);
  NDO_CHECK(third < second);
  NDO_CHECK(prefix < first);
  NDO_CHECK(prefix.IsPrefixOf(first));
  NDO_CHECK(prefix.IsPrefixOf(third));
  NDO_CHECK(!first.IsPrefixOf(third));
  NDO_CHECK(!third.IsPrefixOf(first));
  NDO_CHECK(first.IsPrefixOf(first));
  NDO_CHECK(root_path->IsPrefixOf(first));
}

NDO_TEST(TimeParsingAndFormatting) {
  const ndo::NdoTime epoch = ndo::NdoTime::FromSeconds(0);
  NDO_CHECK_EQ(ndo::FormatTime(epoch), std::string("1970-01-01T00:00:00.000000000Z"));
  const ndo::NdoTime sample = ndo::NdoTime::FromNanos(1767225600123456789LL);
  const std::string text = ndo::FormatTime(sample);
  NDO_CHECK_EQ(text, std::string("2026-01-01T00:00:00.123456789Z"));
  ndo::NdoTime parsed;
  NDO_CHECK(ndo::TryParseTime(text, parsed));
  NDO_CHECK(parsed == sample);

  NDO_CHECK(!ndo::TryParseTime("2026-01-01", parsed));
  NDO_CHECK(!ndo::TryParseTime("2026-01-01T00:00:00", parsed));
  NDO_CHECK(!ndo::TryParseTime("2026-13-01T00:00:00Z", parsed));
  NDO_CHECK(!ndo::TryParseTime("2026-01-32T00:00:00Z", parsed));
  NDO_CHECK(!ndo::TryParseTime("2026-01-01T24:00:00Z", parsed));
  NDO_CHECK(!ndo::TryParseTime("2026-01-01T00:00:00.1234567890Z", parsed));
  NDO_CHECK(!ndo::TryParseTime("2026-01-01T00:00:00Ztrailing", parsed));

  std::int64_t difference = 0;
  NDO_CHECK(ndo::TryDifference(ndo::NdoTime::FromSeconds(10), ndo::NdoTime::FromSeconds(4),
                               difference));
  NDO_CHECK_EQ(difference, std::int64_t{6000000000LL});
  NDO_CHECK(ndo::TryDifference(ndo::NdoTime::FromSeconds(4), ndo::NdoTime::FromSeconds(10),
                               difference));
  NDO_CHECK_EQ(difference, std::int64_t{-6000000000LL});
  NDO_CHECK(!ndo::TryDifference(ndo::NdoTime::FromNanos(INT64_MAX),
                                ndo::NdoTime::FromNanos(INT64_MIN), difference));
}

NDO_TEST(EnumTextRoundTrips) {
  for (std::uint8_t raw = 0; raw < ndo::kDriftClassCount; ++raw) {
    const auto value = static_cast<ndo::DriftClass>(raw);
    ndo::DriftClass parsed = ndo::DriftClass::None;
    NDO_CHECK(ndo::TryParseDriftClass(ndo::ToText(value), parsed));
    NDO_CHECK(parsed == value);
  }
  for (std::uint8_t raw = 0; raw < ndo::kRootCauseKindCount; ++raw) {
    const auto value = static_cast<ndo::RootCauseKind>(raw);
    NDO_CHECK(std::string(ndo::ToText(value)) != "invalid");
  }
  for (std::uint8_t raw = 0; raw < ndo::kTimelineEventKindCount; ++raw) {
    const auto value = static_cast<ndo::TimelineEventKind>(raw);
    ndo::TimelineEventKind parsed = ndo::TimelineEventKind::Created;
    NDO_CHECK(ndo::TryParseTimelineEventKind(ndo::ToText(value), parsed));
    NDO_CHECK(parsed == value);
  }
  const ndo::Severity severities[] = {ndo::Severity::Info, ndo::Severity::Low, ndo::Severity::Medium,
                                      ndo::Severity::High, ndo::Severity::Critical};
  for (ndo::Severity severity : severities) {
    ndo::Severity parsed = ndo::Severity::Info;
    NDO_CHECK(ndo::TryParseSeverity(ndo::ToText(severity), parsed));
    NDO_CHECK(parsed == severity);
  }
  const ndo::FreshnessState states[] = {
      ndo::FreshnessState::Unknown, ndo::FreshnessState::Fresh, ndo::FreshnessState::Aging,
      ndo::FreshnessState::Stale,   ndo::FreshnessState::Expired,
      ndo::FreshnessState::Future,  ndo::FreshnessState::RecoveredNotFresh};
  for (ndo::FreshnessState state : states) {
    ndo::FreshnessState parsed = ndo::FreshnessState::Unknown;
    NDO_CHECK(ndo::TryParseFreshnessState(ndo::ToText(state), parsed));
    NDO_CHECK(parsed == state);
  }
  const ndo::FindingState finding_states[] = {
      ndo::FindingState::Open,        ndo::FindingState::Acknowledged,
      ndo::FindingState::Suppressed,  ndo::FindingState::Resolved,
      ndo::FindingState::Superseded,  ndo::FindingState::Retired};
  for (ndo::FindingState state : finding_states) {
    ndo::FindingState parsed = ndo::FindingState::Open;
    NDO_CHECK(ndo::TryParseFindingState(ndo::ToText(state), parsed));
    NDO_CHECK(parsed == state);
  }
  NDO_CHECK_EQ(std::string(ndo::ReasonCodeDomain(ndo::ReasonCode::ClassifiedValueMismatch)),
               std::string("classification"));
  NDO_CHECK_EQ(std::string(ndo::ReasonCodeDomain(ndo::ReasonCode::LedgerTruncated)),
               std::string("persistence"));
  NDO_CHECK_EQ(std::string(ndo::ReasonCodeDomain(ndo::ReasonCode::WireFrameOversize)),
               std::string("transport"));
}

NDO_TEST(CheckedArithmeticRefusesOverflow) {
  NDO_CHECK(ndo::CheckedAdd<std::uint64_t>(1, 2).value() == 3);
  NDO_CHECK(!ndo::CheckedAdd<std::uint64_t>(UINT64_MAX, 1).has_value());
  NDO_CHECK(!ndo::CheckedMul<std::uint64_t>(UINT64_MAX, 2).has_value());
  NDO_CHECK(!ndo::CheckedSub<std::uint64_t>(1, 2).has_value());
  NDO_CHECK(!ndo::CheckedCast<std::uint8_t>(300).has_value());
  NDO_CHECK(ndo::CheckedCast<std::uint8_t>(255).value() == 255);
  NDO_CHECK(!ndo::CheckedCast<std::uint8_t>(-1).has_value());
  NDO_CHECK(!ndo::CheckedAddSigned(INT64_MAX, 1).has_value());
  NDO_CHECK(!ndo::CheckedSubSigned(INT64_MIN, 1).has_value());
}
