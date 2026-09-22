// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Canonical values and the strict JSON codec.

#include <limits>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

using namespace ndotest;

NDO_TEST(ValueCanonicalTextIsDeterministicAndTyped) {
  const ndo::Value integer = ndo::Value::MakeInt(80);
  const ndo::Value unsigned_integer = ndo::Value::MakeUint(80);
  const ndo::Value real = ndo::Value::TryMakeDouble(80.0).value();
  const ndo::Value text = ndo::Value::MakeString("80");

  // A small unsigned literal normalizes to the signed kind, so one numeric
  // value has exactly one canonical encoding and the JSON codec stays
  // injective. An unsigned value outside the signed range keeps its own kind.
  NDO_CHECK(integer == unsigned_integer);
  NDO_CHECK(integer.ToCanonicalText() == unsigned_integer.ToCanonicalText());
  const ndo::Value large = ndo::Value::MakeUint(UINT64_MAX);
  NDO_CHECK(large.as_uint() != nullptr);
  NDO_CHECK(large.ToCanonicalText() != ndo::Value::MakeInt(-1).ToCanonicalText());
  NDO_CHECK(integer.ToCanonicalText() != real.ToCanonicalText());
  NDO_CHECK(integer.ToCanonicalText() != text.ToCanonicalText());

  // The same tree always produces the same text and the same digest.
  ndo::Value::Map map;
  map.emplace("b", ndo::Value::MakeInt(2));
  map.emplace("a", ndo::Value::MakeList({ndo::Value::MakeInt(1), ndo::Value::MakeBool(true)}));
  const ndo::Value first = ndo::Value::MakeMap(map);
  ndo::Value::Map reversed;
  reversed.emplace("a", ndo::Value::MakeList({ndo::Value::MakeInt(1), ndo::Value::MakeBool(true)}));
  reversed.emplace("b", ndo::Value::MakeInt(2));
  const ndo::Value second = ndo::Value::MakeMap(reversed);
  NDO_CHECK_EQ(first.ToCanonicalText(), second.ToCanonicalText());
  NDO_CHECK(first.DigestOf() == second.DigestOf());
  NDO_CHECK_EQ(first.NodeCount(), std::size_t{5});
  NDO_CHECK(first.MaxDepth() > 0);
  NDO_CHECK(first.ApproximateBytes() > 0);

  // Non-finite doubles cannot be represented and are refused up front.
  NDO_CHECK(!ndo::Value::TryMakeDouble(std::numeric_limits<double>::infinity()).has_value());
  NDO_CHECK(!ndo::Value::TryMakeDouble(std::numeric_limits<double>::quiet_NaN()).has_value());
}

NDO_TEST(ValueOrderingIsTotal) {
  std::vector<ndo::Value> values = {
      ndo::Value::MakeNull(),        ndo::Value::MakeBool(false),
      ndo::Value::MakeBool(true),    ndo::Value::MakeInt(-3),
      ndo::Value::MakeInt(0),        ndo::Value::MakeUint(7),
      ndo::Value::TryMakeDouble(1.5).value(),
      ndo::Value::MakeString("a"),   ndo::Value::MakeString("b"),
      ndo::Value::MakeBytes({1, 2}), ndo::Value::MakeList({}),
      ndo::Value::MakeMap({})};
  for (const ndo::Value& left : values) {
    for (const ndo::Value& right : values) {
      const std::strong_ordering forward = left <=> right;
      const std::strong_ordering backward = right <=> left;
      if (forward == std::strong_ordering::equal) {
        NDO_CHECK(backward == std::strong_ordering::equal);
      } else if (forward == std::strong_ordering::less) {
        NDO_CHECK(backward == std::strong_ordering::greater);
      } else {
        NDO_CHECK(backward == std::strong_ordering::less);
      }
    }
  }
}

NDO_TEST(RelateValuesNumericEquivalence) {
  const ndo::Value int_value = ndo::Value::MakeInt(1500);
  const ndo::Value uint_value = ndo::Value::MakeUint(1500);
  NDO_CHECK(int_value == uint_value);
  const ndo::Value double_value = ndo::Value::TryMakeDouble(1500.0).value();
  const ndo::Value other = ndo::Value::MakeInt(9000);

  NDO_CHECK(ndo::RelateValues(int_value, uint_value, ndo::NumericEquivalence::Numeric) ==
            ndo::ValueRelation::Equal);
  // A small unsigned literal is the same canonical value as its signed form, so
  // even exact comparison sees one value. A different kind is still different.
  NDO_CHECK(ndo::RelateValues(int_value, uint_value, ndo::NumericEquivalence::Exact) ==
            ndo::ValueRelation::Equal);
  NDO_CHECK(ndo::RelateValues(int_value, double_value, ndo::NumericEquivalence::Exact) ==
            ndo::ValueRelation::Different);
  NDO_CHECK(ndo::RelateValues(int_value, double_value, ndo::NumericEquivalence::Numeric) ==
            ndo::ValueRelation::Equal);
  NDO_CHECK(ndo::RelateValues(int_value, other, ndo::NumericEquivalence::Numeric) ==
            ndo::ValueRelation::Different);

  // Symmetry: comparison is a pure function of the pair.
  const ndo::Value text = ndo::Value::MakeString("1500");
  NDO_CHECK(ndo::RelateValues(int_value, text, ndo::NumericEquivalence::Numeric) ==
            ndo::RelateValues(text, int_value, ndo::NumericEquivalence::Numeric));
  NDO_CHECK(ndo::RelateValues(int_value, text, ndo::NumericEquivalence::Numeric) ==
            ndo::ValueRelation::Incomparable);

  // Nested containers.
  const ndo::Value left = ndo::Value::MakeMap(
      {{"a", ndo::Value::MakeInt(1)}, {"b", ndo::Value::MakeList({ndo::Value::MakeInt(2)})}});
  const ndo::Value right = ndo::Value::MakeMap(
      {{"a", ndo::Value::MakeUint(1)}, {"b", ndo::Value::MakeList({ndo::Value::MakeInt(2)})}});
  NDO_CHECK(ndo::RelateValues(left, right, ndo::NumericEquivalence::Numeric) ==
            ndo::ValueRelation::Equal);
  const ndo::Value changed = ndo::Value::MakeMap(
      {{"a", ndo::Value::MakeInt(1)}, {"b", ndo::Value::MakeList({ndo::Value::MakeInt(3)})}});
  NDO_CHECK(ndo::RelateValues(left, changed, ndo::NumericEquivalence::Numeric) ==
            ndo::ValueRelation::Different);
  NDO_CHECK(ndo::RelateValues(left, ndo::Value::MakeInt(1), ndo::NumericEquivalence::Numeric) ==
            ndo::ValueRelation::Incomparable);
  NDO_CHECK(ndo::RelateValues(ndo::Value::MakeNull(), ndo::Value::MakeInt(1),
                              ndo::NumericEquivalence::Numeric) ==
            ndo::ValueRelation::Incomparable);
}

NDO_TEST(JsonRoundTripIsStable) {
  ndo::Value::Map nested;
  nested.emplace("name", ndo::Value::MakeString("port/eth0"));
  nested.emplace("mtu", ndo::Value::MakeInt(9000));
  nested.emplace("enabled", ndo::Value::MakeBool(true));
  nested.emplace("ratio", ndo::Value::TryMakeDouble(0.25).value());
  nested.emplace("tags", ndo::Value::MakeList(
                             {ndo::Value::MakeString("a"), ndo::Value::MakeString("b\"c")}));
  nested.emplace("blob", ndo::Value::MakeBytes({0x00, 0x7F, 0xFF}));
  nested.emplace("nothing", ndo::Value::MakeNull());
  const ndo::Value original = ndo::Value::MakeMap(nested);

  const std::string compact = ndo::WriteCanonicalJson(original);
  const std::string pretty = ndo::WritePrettyJson(original, 2);
  ndo::RuntimeLimits limits;

  ndo::Value parsed_compact;
  NDO_CHECK_STATUS(ndo::ParseJson(compact, limits, parsed_compact));
  ndo::Value parsed_pretty;
  NDO_CHECK_STATUS(ndo::ParseJson(pretty, limits, parsed_pretty));
  NDO_CHECK(parsed_compact == original);
  NDO_CHECK(parsed_pretty == original);

  // Re-encoding a parsed document is byte-identical: the codec is canonical.
  NDO_CHECK_EQ(ndo::WriteCanonicalJson(parsed_compact), compact);

  // Member order in the source does not matter.
  ndo::Value shuffled;
  NDO_CHECK_STATUS(ndo::ParseJson(
      "{\"mtu\":9000,\"name\":\"port/eth0\",\"enabled\":true,\"ratio\":0.25,"
      "\"tags\":[\"a\",\"b\\\"c\"],\"blob\":{\"$bytes\":\"007fff\"},"
      "\"nothing\":null}",
      limits, shuffled));
  NDO_CHECK(shuffled == original);
}

NDO_TEST(JsonRefusesMalformedInput) {
  ndo::RuntimeLimits limits;
  ndo::Value value;
  const auto reason_of = [&](const std::string& text) {
    ndo::Value ignored;
    const ndo::Status status = ndo::ParseJson(text, limits, ignored);
    return status.ok() ? ndo::ReasonCode::None : status.reason;
  };

  NDO_CHECK(reason_of("") == ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK(reason_of("{") == ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK(reason_of("{\"a\":1,}") == ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK(reason_of("{\"a\":1} trailing") == ndo::ReasonCode::EncodingTrailingBytes);
  NDO_CHECK(reason_of("{\"a\":1,\"a\":2}") == ndo::ReasonCode::EncodingDuplicateKey);
  NDO_CHECK(reason_of("[1,2") == ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK(reason_of("nul") == ndo::ReasonCode::EncodingUnexpectedToken);
  NDO_CHECK(reason_of("01") == ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK(reason_of("1e") == ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK(reason_of("-") == ndo::ReasonCode::EncodingUnexpectedToken);
  NDO_CHECK(reason_of("1e999999") == ndo::ReasonCode::EncodingNumberOutOfRange);
  NDO_CHECK(reason_of("\"\\q\"") == ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK(reason_of("\"\\ud800\"") == ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK(reason_of("\"\\udc00\"") == ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK(reason_of("\"\\ud800\\u0041\"") == ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK(reason_of(std::string("\"") + std::string(1, '\x01') + "\"") ==
            ndo::ReasonCode::EncodingMalformed);
  // A truncated multi-byte sequence and an overlong form are both invalid.
  NDO_CHECK(reason_of(std::string("\"") + std::string(1, '\xC3') + "\"") ==
            ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK(reason_of(std::string("\"") + std::string(1, '\xC0') + std::string(1, '\x80') + "\"") ==
            ndo::ReasonCode::EncodingInvalidUtf8);
  // A valid surrogate pair decodes to one code point.
  NDO_CHECK(reason_of("\"\\ud83d\\ude00\"") == ndo::ReasonCode::None);
  NDO_CHECK(reason_of("true") == ndo::ReasonCode::None);
  NDO_CHECK(reason_of("[1,2,3]") == ndo::ReasonCode::None);
}

NDO_TEST(JsonEnforcesTheEnvelope) {
  ndo::RuntimeLimits limits;
  limits.max_value_depth = 4;
  limits.max_value_nodes = 8;
  limits.max_leaf_bytes = 16;
  limits.max_document_bytes = 256;

  ndo::Value value;
  NDO_CHECK(ndo::ParseJson("[[[[[1]]]]]", limits, value).reason ==
            ndo::ReasonCode::LimitDepthExceeded);
  NDO_CHECK(ndo::ParseJson("[1,2,3,4,5,6,7,8,9,10]", limits, value).reason ==
            ndo::ReasonCode::LimitObjectsExceeded);
  NDO_CHECK(ndo::ParseJson("\"this string is far too long\"", limits, value).reason ==
            ndo::ReasonCode::LimitBytesExceeded);
  const std::string huge = "\"" + std::string(300, 'a') + "\"";
  NDO_CHECK(ndo::ParseJson(huge, limits, value).reason == ndo::ReasonCode::LimitBytesExceeded);

  // A bound failure never publishes a partially parsed value.
  ndo::RuntimeLimits tight;
  tight.max_value_nodes = 3;
  ndo::Value untouched = ndo::Value::MakeString("sentinel");
  NDO_CHECK(!ndo::ParseJson("[1,2,3,4,5]", tight, untouched).ok());
  NDO_CHECK_EQ(untouched.ToCanonicalText(), std::string("s8:sentinel"));
}

NDO_TEST(Utf8Validation) {
  NDO_CHECK(ndo::IsValidUtf8(""));
  NDO_CHECK(ndo::IsValidUtf8("plain ascii"));
  NDO_CHECK(ndo::IsValidUtf8("caf\xC3\xA9"));
  NDO_CHECK(ndo::IsValidUtf8("\xE2\x82\xAC"));
  NDO_CHECK(ndo::IsValidUtf8("\xF0\x9F\x98\x80"));
  NDO_CHECK(!ndo::IsValidUtf8("\xC3"));
  NDO_CHECK(!ndo::IsValidUtf8("\xC3\x28"));
  NDO_CHECK(!ndo::IsValidUtf8("\xC0\x80"));
  NDO_CHECK(!ndo::IsValidUtf8("\xED\xA0\x80"));
  NDO_CHECK(!ndo::IsValidUtf8("\xF5\x80\x80\x80"));
  NDO_CHECK(!ndo::IsValidUtf8("\xF0\x9F\x98"));
}

NDO_TEST(ValueValidationEnvelope) {
  ndo::RuntimeLimits limits;
  limits.max_value_depth = 2;
  const ndo::Value shallow = ndo::Value::MakeList({ndo::Value::MakeInt(1)});
  NDO_CHECK(shallow.Validate(limits).ok());
  const ndo::Value deep = ndo::Value::MakeList(
      {ndo::Value::MakeList({ndo::Value::MakeList({ndo::Value::MakeInt(1)})})});
  NDO_CHECK(deep.Validate(limits).reason == ndo::ReasonCode::LimitDepthExceeded);
  NDO_CHECK(ndo::Value::MakeString("ok").Validate(limits).ok());
  NDO_CHECK(ndo::Value::MakeString(std::string(limits.max_leaf_bytes + 1, 'x')).Validate(limits).reason ==
            ndo::ReasonCode::LimitBytesExceeded);
}
