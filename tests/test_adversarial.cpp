// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Adversarial input-boundary suite.
//
// Every test in this file hands the runtime input that is malformed, corrupt,
// truncated, oversized or self-inconsistent, and requires the runtime to refuse
// that input with the reason code the design names, to refuse it as a whole, and
// to leave whatever state it already held untouched. Where exactly one reason
// code is defensible the exact code is asserted; where the shape of the input
// leaves several codes defensible only a refusal is required.

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "summon/network_drift_observatory/finding.hpp"
#include "summon/network_drift_observatory/hash.hpp"
#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/interchange.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/ledger.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/observation.hpp"
#include "summon/network_drift_observatory/persistence.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/value.hpp"
#include "summon/network_drift_observatory/version.hpp"
#include "summon/network_drift_observatory/wire.hpp"

#include "test_framework.hpp"
#include "test_support.hpp"

using namespace ndotest;

namespace {

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

void AppendLe16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void AppendLe64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu));
  }
}

void AppendText(std::vector<std::uint8_t>& out, std::string_view text) {
  for (char character : text) {
    out.push_back(static_cast<std::uint8_t>(character));
  }
}

void PatchLe16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}

void PatchLe32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu);
  }
}

void PatchLe64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu);
  }
}

std::string ByteText(std::initializer_list<unsigned char> bytes) {
  std::string text;
  for (unsigned char byte : bytes) {
    text.push_back(static_cast<char>(byte));
  }
  return text;
}

std::string JsonStringWithBytes(std::initializer_list<unsigned char> bytes) {
  std::string text = "\"";
  for (unsigned char byte : bytes) {
    text.push_back(static_cast<char>(byte));
  }
  text.push_back('"');
  return text;
}

std::string DeepPath(std::size_t segments, const std::string& key) {
  std::string text;
  for (std::size_t index = 0; index < segments; ++index) {
    if (index != 0) {
      text.push_back('.');
    }
    text += key;
  }
  return text;
}

bool WriteFileBytes(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return false;
  }
  if (!bytes.empty()) {
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
  }
  return stream.good();
}

// ---------------------------------------------------------------------------
// Value-tree helpers
// ---------------------------------------------------------------------------

ndo::Value::Map AsMap(const ndo::Value& value) {
  if (value.as_map() == nullptr) {
    return {};
  }
  return *value.as_map();
}

ndo::Value::List AsList(const ndo::Value& value) {
  if (value.as_list() == nullptr) {
    return {};
  }
  return *value.as_list();
}

ndo::Value::Map MemberMap(const ndo::Value::Map& map, const std::string& key) {
  const auto found = map.find(key);
  return found == map.end() ? ndo::Value::Map{} : AsMap(found->second);
}

ndo::Value::List MemberList(const ndo::Value::Map& map, const std::string& key) {
  const auto found = map.find(key);
  return found == map.end() ? ndo::Value::List{} : AsList(found->second);
}

void SetMember(ndo::Value::Map& map, const std::string& key, ndo::Value value) {
  map.insert_or_assign(key, std::move(value));
}

void EraseMember(ndo::Value::Map& map, const std::string& key) { map.erase(key); }

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

ndo::Status ParseSimple(std::string_view text) {
  ndo::Value value;
  return ndo::ParseJson(text, ndo::RuntimeLimits{}, value);
}

// ---------------------------------------------------------------------------
// Observation-document fixtures
// ---------------------------------------------------------------------------

ndo::ObservationSnapshot BaselineObservation() {
  ndo::ObservationSnapshot snapshot =
      MakeSnapshot("collector/one", "device/one", 7, FixedTime(1000));
  AddObservedObject(snapshot, "port/eth0", "admin_state", ndo::Value::MakeString("up"));
  SealSnapshot(snapshot);
  return snapshot;
}

ndo::Value ObservationDocument() {
  return ndo::EncodeObservationDocument(BaselineObservation());
}

ndo::Value::Map ObservationDocumentMap() { return AsMap(ObservationDocument()); }

ndo::Value ObservationDocumentWith(const std::string& key, ndo::Value value) {
  ndo::Value::Map document = ObservationDocumentMap();
  SetMember(document, key, std::move(value));
  return ndo::Value::MakeMap(std::move(document));
}

ndo::Value ObservationDocumentWithCapability(const std::string& key, ndo::Value value) {
  ndo::Value::Map document = ObservationDocumentMap();
  ndo::Value::Map capabilities = MemberMap(document, "capabilities");
  SetMember(capabilities, key, std::move(value));
  SetMember(document, "capabilities", ndo::Value::MakeMap(std::move(capabilities)));
  return ndo::Value::MakeMap(std::move(document));
}

ndo::Value ObservationDocumentWithObjectMember(const std::string& key, ndo::Value value) {
  ndo::Value::Map document = ObservationDocumentMap();
  ndo::Value::List objects = MemberList(document, "objects");
  ndo::Value::Map object = AsMap(objects.at(0));
  SetMember(object, key, std::move(value));
  objects.at(0) = ndo::Value::MakeMap(std::move(object));
  SetMember(document, "objects", ndo::Value::MakeList(std::move(objects)));
  return ndo::Value::MakeMap(std::move(document));
}

ndo::Value ObservationDocumentWithFieldMember(const std::string& key, ndo::Value value) {
  ndo::Value::Map document = ObservationDocumentMap();
  ndo::Value::List objects = MemberList(document, "objects");
  ndo::Value::Map object = AsMap(objects.at(0));
  ndo::Value::List fields = MemberList(object, "fields");
  ndo::Value::Map field = AsMap(fields.at(0));
  SetMember(field, key, std::move(value));
  fields.at(0) = ndo::Value::MakeMap(std::move(field));
  SetMember(object, "fields", ndo::Value::MakeList(std::move(fields)));
  objects.at(0) = ndo::Value::MakeMap(std::move(object));
  SetMember(document, "objects", ndo::Value::MakeList(std::move(objects)));
  return ndo::Value::MakeMap(std::move(document));
}

ndo::Value ObservationDocumentWithPresence(const std::string& presence, bool carries_field,
                                           bool asserts_absence) {
  ndo::Value::Map document =
      AsMap(ObservationDocumentWithCapability("asserts_absence",
                                              ndo::Value::MakeBool(asserts_absence)));
  ndo::Value::List objects = MemberList(document, "objects");
  ndo::Value::Map object = AsMap(objects.at(0));
  SetMember(object, "presence", ndo::Value::MakeString(presence));
  ndo::Value::List fields = MemberList(object, "fields");
  if (!carries_field) {
    fields.clear();
  }
  SetMember(object, "fields", ndo::Value::MakeList(std::move(fields)));
  objects.at(0) = ndo::Value::MakeMap(std::move(object));
  SetMember(document, "objects", ndo::Value::MakeList(std::move(objects)));
  return ndo::Value::MakeMap(std::move(document));
}

ndo::Status DecodeObservationValue(const ndo::Value& value,
                                   const ndo::RuntimeLimits& limits = ndo::RuntimeLimits{}) {
  ndo::ObservationSnapshot snapshot;
  return ndo::DecodeObservationDocument(value, limits, snapshot);
}

// ---------------------------------------------------------------------------
// Intent-document fixtures
// ---------------------------------------------------------------------------

ndo::Value IntentDocument() {
  ndo::IntentGenerationDocument document = MakeIntent("device/one", 3);
  AddIntentObject(document, "port/eth0", "admin_state", ndo::Value::MakeString("up"));
  return ndo::EncodeIntentDocument(document);
}

ndo::Value::Map IntentDocumentMap() { return AsMap(IntentDocument()); }

ndo::Value IntentDocumentWith(const std::string& key, ndo::Value value) {
  ndo::Value::Map document = IntentDocumentMap();
  SetMember(document, key, std::move(value));
  return ndo::Value::MakeMap(std::move(document));
}

ndo::Value IntentDocumentWithObjectMember(const std::string& key, ndo::Value value) {
  ndo::Value::Map document = IntentDocumentMap();
  ndo::Value::List objects = MemberList(document, "objects");
  ndo::Value::Map object = AsMap(objects.at(0));
  SetMember(object, key, std::move(value));
  objects.at(0) = ndo::Value::MakeMap(std::move(object));
  SetMember(document, "objects", ndo::Value::MakeList(std::move(objects)));
  return ndo::Value::MakeMap(std::move(document));
}

ndo::Value IntentDocumentWithFieldMember(const std::string& key, ndo::Value value) {
  ndo::Value::Map document = IntentDocumentMap();
  ndo::Value::List objects = MemberList(document, "objects");
  ndo::Value::Map object = AsMap(objects.at(0));
  ndo::Value::List fields = MemberList(object, "fields");
  ndo::Value::Map field = AsMap(fields.at(0));
  SetMember(field, key, std::move(value));
  fields.at(0) = ndo::Value::MakeMap(std::move(field));
  SetMember(object, "fields", ndo::Value::MakeList(std::move(fields)));
  objects.at(0) = ndo::Value::MakeMap(std::move(object));
  SetMember(document, "objects", ndo::Value::MakeList(std::move(objects)));
  return ndo::Value::MakeMap(std::move(document));
}

ndo::Value IntentDocumentWithoutFieldMember(const std::string& key) {
  ndo::Value::Map document = IntentDocumentMap();
  ndo::Value::List objects = MemberList(document, "objects");
  ndo::Value::Map object = AsMap(objects.at(0));
  ndo::Value::List fields = MemberList(object, "fields");
  ndo::Value::Map field = AsMap(fields.at(0));
  EraseMember(field, key);
  fields.at(0) = ndo::Value::MakeMap(std::move(field));
  SetMember(object, "fields", ndo::Value::MakeList(std::move(fields)));
  objects.at(0) = ndo::Value::MakeMap(std::move(object));
  SetMember(document, "objects", ndo::Value::MakeList(std::move(objects)));
  return ndo::Value::MakeMap(std::move(document));
}

ndo::Status DecodeIntentValue(const ndo::Value& value,
                              const ndo::RuntimeLimits& limits = ndo::RuntimeLimits{}) {
  ndo::IntentGenerationDocument document;
  return ndo::DecodeIntentDocument(value, limits, document);
}

// ---------------------------------------------------------------------------
// Ledger fixtures
// ---------------------------------------------------------------------------

/// Rebuilds a complete ledger byte string around an arbitrary payload. The
/// payload digest is recomputed, so a test that mutates the payload exercises
/// the decoder's structural checks rather than the integrity check.
std::vector<std::uint8_t> FrameLedgerPayload(std::string_view payload, std::uint16_t format,
                                             std::uint64_t write_epoch) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(ndo::kLedgerHeaderBytes + payload.size());
  for (char character : ndo::kLedgerMagic) {
    bytes.push_back(static_cast<std::uint8_t>(character));
  }
  AppendLe16(bytes, format);
  AppendLe16(bytes, 0);
  AppendLe64(bytes, static_cast<std::uint64_t>(payload.size()));
  const ndo::Digest digest = ndo::LedgerPayloadDigest(
      reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size());
  bytes.insert(bytes.end(), digest.bytes.begin(), digest.bytes.end());
  AppendLe64(bytes, write_epoch);
  AppendLe64(bytes, 1);
  AppendText(bytes, payload);
  return bytes;
}

std::string LedgerPayloadText(const std::vector<std::uint8_t>& bytes) {
  return std::string(reinterpret_cast<const char*>(bytes.data()) + ndo::kLedgerHeaderBytes,
                     bytes.size() - ndo::kLedgerHeaderBytes);
}

std::vector<std::uint8_t> EncodeLedgerBytes(const ndo::FindingLedger& ledger) {
  std::vector<std::uint8_t> bytes;
  const ndo::Status status = ndo::EncodeLedger(ledger, ndo::FabricEpoch::FromValue(1),
                                               ndo::Incarnation::FromValue(1), bytes);
  NDO_CHECK_STATUS(status);
  return bytes;
}

template <typename Mutation>
std::vector<std::uint8_t> MutateLedgerPayload(const std::vector<std::uint8_t>& original,
                                              Mutation mutate) {
  ndo::Value root;
  const ndo::Status parsed =
      ndo::ParseJson(LedgerPayloadText(original), ndo::RuntimeLimits{}, root);
  if (!parsed.ok() || root.as_map() == nullptr) {
    return {};
  }
  ndo::Value::Map map = *root.as_map();
  mutate(map);
  return FrameLedgerPayload(ndo::WriteCanonicalJson(ndo::Value::MakeMap(std::move(map))), 1, 1);
}

ndo::FindingLedger MakeLedgerWithIntent(const std::string& target, std::uint64_t generation) {
  ndo::FindingLedger ledger;
  ndo::IntentGenerationDocument intent = MakeIntent(target, generation);
  AddIntentObject(intent, "port/eth0", "admin_state", ndo::Value::MakeString("up"));
  ndo::IntentCommitReport report;
  NDO_CHECK_STATUS(ledger.CommitIntent(intent, FixedTime(1000), report));
  return ledger;
}

/// A ledger with one baseline, one retained observation, one finding, one group
/// and two global timeline entries: every decode section has content, so a
/// refusal that happens late still has earlier sections to leave unapplied.
ndo::FindingLedger MakeRichLedger() {
  ndo::FindingLedger ledger = MakeLedgerWithIntent("device/one", 4);

  ndo::ObservationSnapshot snapshot =
      MakeSnapshot("collector/one", "device/one", 3, FixedTime(1100));
  AddObservedObject(snapshot, "port/eth0", "admin_state", ndo::Value::MakeString("down"));
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));

  ndo::Finding finding;
  finding.identity.target = Target("device/one");
  finding.identity.object = Object("port/eth0");
  finding.identity.path = Path("admin_state");
  finding.identity.klass = ndo::DriftClass::ValueMismatch;
  finding.identity.baseline_generation = ndo::IntentGeneration::FromValue(4);
  finding.id = finding.identity.ComputeId();
  finding.klass = ndo::DriftClass::ValueMismatch;
  // The durable record carries its own copy of the generation as well; a
  // fixture that set only one of the two would be self-inconsistent on purpose.
  finding.baseline_generation = ndo::IntentGeneration::FromValue(4);
  finding.state = ndo::FindingState::Open;
  finding.policy = ndo::PolicyId::Trusted("policy/default");
  finding.summary = "admin_state differs";
  finding.first_seen = FixedTime(1100);
  finding.last_seen = FixedTime(1100);
  finding.last_evaluated = FixedTime(1100);
  NDO_CHECK_STATUS(ledger.RestoreFinding(finding));

  ndo::RootCauseGroup group;
  group.id = ndo::GroupId::FromDigest(ndo::HashText("ndo/test/group/one"));
  group.target = Target("device/one");
  group.baseline_generation = ndo::IntentGeneration::FromValue(4);
  group.baseline_epoch = ndo::FabricEpoch::FromValue(1);
  group.cause = ndo::RootCauseKind::SingleField;
  group.summary = "one field differs";
  group.first_seen = FixedTime(1100);
  group.last_seen = FixedTime(1100);
  group.members.push_back(finding.id);
  group.objects.push_back(Object("port/eth0"));
  NDO_CHECK_STATUS(ledger.RestoreGroup(group));

  ndo::TimelineEntry trailing;
  trailing.kind = ndo::TimelineEventKind::Updated;
  trailing.target = Target("device/one");
  trailing.object = Object("port/eth0");
  trailing.finding = finding.id;
  trailing.at = FixedTime(1200);
  trailing.detail = "updated by the adversarial fixture";
  NDO_CHECK_STATUS(ledger.RestoreTimeline(trailing));

  return ledger;
}

std::string LedgerFingerprint(const ndo::FindingLedger& ledger) {
  const ndo::LedgerStats stats = ledger.Stats();
  std::string text = ledger.ContentDigest().ToHex();
  text += ":";
  text += std::to_string(ledger.revision().value());
  text += ":";
  text += std::to_string(stats.targets);
  text += ":";
  text += std::to_string(stats.baselines);
  text += ":";
  text += std::to_string(stats.observations);
  text += ":";
  text += std::to_string(stats.findings);
  text += ":";
  text += std::to_string(stats.groups);
  text += ":";
  text += std::to_string(stats.timeline_entries);
  return text;
}

}  // namespace

// ===========================================================================
// 1. JSON payloads
// ===========================================================================

NDO_TEST(JsonRefusesEmptyAndTruncatedDocuments) {
  NDO_CHECK_REFUSED(ParseSimple(""), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("   "), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\""), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":1"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":1,"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":[1,2"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("["), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("[1,2"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("\"abc"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("\"abc\\"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("tru"), ndo::ReasonCode::EncodingUnexpectedToken);
  NDO_CHECK_REFUSED(ParseSimple("fals"), ndo::ReasonCode::EncodingUnexpectedToken);
  NDO_CHECK_REFUSED(ParseSimple("nul"), ndo::ReasonCode::EncodingUnexpectedToken);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":tru}"), ndo::ReasonCode::EncodingUnexpectedToken);

  // The same codec accepts complete documents, so the refusals above are not an
  // artifact of a codec that refuses everything.
  NDO_CHECK_STATUS(ParseSimple("{\"a\":1}"));
  NDO_CHECK_STATUS(ParseSimple("[]"));
  NDO_CHECK_STATUS(ParseSimple("null"));
}

NDO_TEST(JsonRefusesBrokenStructure) {
  NDO_CHECK_REFUSED(ParseSimple("{\"a\" 1}"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{a:1}"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{1:2}"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("[1 2]"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":1,}"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("[1,]"), ndo::ReasonCode::EncodingUnexpectedToken);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":}"), ndo::ReasonCode::EncodingUnexpectedToken);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":01}"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":1.}"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":1e}"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":+1}"), ndo::ReasonCode::EncodingUnexpectedToken);
  NDO_CHECK_REFUSED(ParseSimple(std::string("\"raw") + '\x01' + "control\""),
                    ndo::ReasonCode::EncodingMalformed);

  // A malformed byte-string tag is a refusal, never an ordinary member map.
  NDO_CHECK_REFUSED(ParseSimple("{\"$bytes\":1}"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{\"$bytes\":\"zz\"}"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple("{\"$bytes\":\"0\"}"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_STATUS(ParseSimple("{\"$bytes\":\"00ff\"}"));
}

NDO_TEST(JsonRefusesDuplicateMembers) {
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":1,\"a\":2}"), ndo::ReasonCode::EncodingDuplicateKey);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":1,\"a\":1}"), ndo::ReasonCode::EncodingDuplicateKey);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":1,\"b\":2,\"a\":3}"),
                    ndo::ReasonCode::EncodingDuplicateKey);
  NDO_CHECK_REFUSED(ParseSimple("{\"outer\":{\"b\":1,\"b\":2}}"),
                    ndo::ReasonCode::EncodingDuplicateKey);
  NDO_CHECK_REFUSED(ParseSimple("{\"outer\":[{\"c\":1,\"c\":2}]}"),
                    ndo::ReasonCode::EncodingDuplicateKey);
  // Member names are case-sensitive, so these are distinct members.
  NDO_CHECK_STATUS(ParseSimple("{\"a\":1,\"A\":2}"));
}

NDO_TEST(JsonRefusesInvalidEscapes) {
  NDO_CHECK_REFUSED(ParseSimple(R"("\q")"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple(R"("\x41")"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple(R"("\u12")"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple(R"("\uZZZZ")"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple(R"("\u12g4")"), ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(ParseSimple(R"("\')"), ndo::ReasonCode::EncodingMalformed);

  // Well-formed escapes are still accepted and decode to the intended text.
  ndo::Value parsed;
  NDO_CHECK_STATUS(ndo::ParseJson(R"("\u0041")", ndo::RuntimeLimits{}, parsed));
  NDO_CHECK(parsed.as_string() != nullptr);
  NDO_CHECK_EQ(*parsed.as_string(), std::string("A"));
  NDO_CHECK_STATUS(ndo::ParseJson(R"("\"\\\/\b\f\n\r\t")", ndo::RuntimeLimits{}, parsed));
  NDO_CHECK_EQ(*parsed.as_string(), std::string("\"\\/\b\f\n\r\t"));
}

NDO_TEST(JsonRefusesLoneSurrogates) {
  NDO_CHECK_REFUSED(ParseSimple(R"("\ud800")"), ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(R"("\udbff")"), ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(R"("\udc00")"), ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(R"("\udfff")"), ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(R"("\ud800\u0041")"), ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(R"("\ud800\ud800")"), ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(R"("\ud800x")"), ndo::ReasonCode::EncodingInvalidUtf8);

  // A well-formed surrogate pair is accepted and becomes one code point.
  ndo::Value parsed;
  NDO_CHECK_STATUS(ndo::ParseJson(R"("\ud83d\ude00")", ndo::RuntimeLimits{}, parsed));
  NDO_CHECK(parsed.as_string() != nullptr);
  NDO_CHECK_EQ(*parsed.as_string(), std::string("\xf0\x9f\x98\x80"));
}

NDO_TEST(JsonRefusesInvalidUtf8Bytes) {
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0x80})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xBF})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xC0, 0x80})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xC1, 0xBF})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xE0, 0x80, 0x80})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xF0, 0x80, 0x80, 0x80})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xED, 0xA0, 0x80})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xF4, 0x90, 0x80, 0x80})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xFE})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xFF})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xC3})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xE2, 0x82})),
                    ndo::ReasonCode::EncodingInvalidUtf8);
  NDO_CHECK_REFUSED(ParseSimple(JsonStringWithBytes({0xF0, 0x9F, 0x98})),
                    ndo::ReasonCode::EncodingInvalidUtf8);

  // An invalid byte inside a member name is refused as well.
  std::string member = "{\"";
  member.push_back(static_cast<char>(0xFF));
  member += "\":1}";
  NDO_CHECK_REFUSED(ParseSimple(member), ndo::ReasonCode::EncodingInvalidUtf8);

  // Valid multi-byte sequences are accepted.
  NDO_CHECK_STATUS(ParseSimple(JsonStringWithBytes({0xC3, 0xA9})));
  NDO_CHECK_STATUS(ParseSimple(JsonStringWithBytes({0xE2, 0x82, 0xAC})));
  NDO_CHECK_STATUS(ParseSimple(JsonStringWithBytes({0xF0, 0x9F, 0x98, 0x80})));
}

NDO_TEST(JsonRefusesOutOfRangeNumbers) {
  NDO_CHECK_REFUSED(ParseSimple("1e400"), ndo::ReasonCode::EncodingNumberOutOfRange);
  NDO_CHECK_REFUSED(ParseSimple("-1e400"), ndo::ReasonCode::EncodingNumberOutOfRange);
  NDO_CHECK_REFUSED(ParseSimple("1e309"), ndo::ReasonCode::EncodingNumberOutOfRange);
  NDO_CHECK_REFUSED(ParseSimple("[0,1e309]"), ndo::ReasonCode::EncodingNumberOutOfRange);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":1e999}"), ndo::ReasonCode::EncodingNumberOutOfRange);

  // Boundary forms that are representable keep their exact kind.
  ndo::Value parsed;
  NDO_CHECK_STATUS(ndo::ParseJson("18446744073709551615", ndo::RuntimeLimits{}, parsed));
  NDO_CHECK(parsed.as_uint() != nullptr);
  NDO_CHECK_STATUS(ndo::ParseJson("-9223372036854775808", ndo::RuntimeLimits{}, parsed));
  NDO_CHECK(parsed.as_int() != nullptr);
  NDO_CHECK_STATUS(ndo::ParseJson("1.7976931348623157e308", ndo::RuntimeLimits{}, parsed));
  NDO_CHECK(parsed.as_double() != nullptr);
}

NDO_TEST(JsonRefusesTrailingBytes) {
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":1} x"), ndo::ReasonCode::EncodingTrailingBytes);
  NDO_CHECK_REFUSED(ParseSimple("{}[]"), ndo::ReasonCode::EncodingTrailingBytes);
  NDO_CHECK_REFUSED(ParseSimple("1 2"), ndo::ReasonCode::EncodingTrailingBytes);
  NDO_CHECK_REFUSED(ParseSimple("null,null"), ndo::ReasonCode::EncodingTrailingBytes);
  NDO_CHECK_REFUSED(ParseSimple("{\"a\":1}\n}"), ndo::ReasonCode::EncodingTrailingBytes);
  NDO_CHECK_STATUS(ParseSimple("{\"a\":1}   \n\t "));
}

NDO_TEST(JsonRefusesDocumentsBeyondBounds) {
  ndo::RuntimeLimits depth_limits;
  depth_limits.max_value_depth = 4;
  ndo::Value parsed;
  NDO_CHECK_STATUS(ndo::ParseJson("[[[[1]]]]", depth_limits, parsed));
  NDO_CHECK_REFUSED(ndo::ParseJson("[[[[[1]]]]]", depth_limits, parsed),
                    ndo::ReasonCode::LimitDepthExceeded);

  ndo::RuntimeLimits node_limits;
  node_limits.max_value_nodes = 4;
  NDO_CHECK_STATUS(ndo::ParseJson("[1,2,3]", node_limits, parsed));
  NDO_CHECK_REFUSED(ndo::ParseJson("[1,2,3,4]", node_limits, parsed),
                    ndo::ReasonCode::LimitObjectsExceeded);

  ndo::RuntimeLimits byte_limits;
  byte_limits.max_document_bytes = 8;
  NDO_CHECK_STATUS(ndo::ParseJson("{\"ab\":1}", byte_limits, parsed));
  NDO_CHECK_REFUSED(ndo::ParseJson("{\"abc\":1}", byte_limits, parsed),
                    ndo::ReasonCode::LimitBytesExceeded);

  ndo::RuntimeLimits leaf_limits;
  leaf_limits.max_leaf_bytes = 3;
  NDO_CHECK_STATUS(ndo::ParseJson("{\"a\":\"abc\"}", leaf_limits, parsed));
  NDO_CHECK_REFUSED(ndo::ParseJson("{\"a\":\"abcd\"}", leaf_limits, parsed),
                    ndo::ReasonCode::LimitBytesExceeded);

  ndo::RuntimeLimits field_limits;
  field_limits.max_fields_per_object = 2;
  NDO_CHECK_STATUS(ndo::ParseJson("{\"a\":1,\"b\":2}", field_limits, parsed));
  NDO_CHECK_REFUSED(ndo::ParseJson("{\"a\":1,\"b\":2,\"c\":3}", field_limits, parsed),
                    ndo::ReasonCode::LimitFieldsExceeded);

  // A refused parse never publishes a partially built value.
  const ndo::Value sentinel = ndo::Value::MakeString("sentinel");
  ndo::Value target = sentinel;
  NDO_CHECK_REFUSED(ndo::ParseJson("{\"a\":", ndo::RuntimeLimits{}, target),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK(target == sentinel);
}

// ===========================================================================
// 2. Observation documents
// ===========================================================================

NDO_TEST(ObservationDocumentRefusesMissingRequiredMembers) {
  const ndo::Value::Map base = ObservationDocumentMap();
  // The schema member is required: a versioned document names the format it is
  // written in, and a decoder refuses a document that does not.
  const char* required[] = {"schema", "source",   "epoch", "incarnation",
                            "sequence", "target", "collected_at", "objects"};
  for (const char* member : required) {
    ndo::Value::Map document = base;
    EraseMember(document, member);
    NDO_CHECK_REFUSED(DecodeObservationValue(ndo::Value::MakeMap(std::move(document))),
                      ndo::ReasonCode::EncodingMalformed);
  }

  const char* optional[] = {"ttl_nanos", "coverage", "evidence", "unobserved", "capabilities"};
  for (const char* member : optional) {
    ndo::Value::Map document = base;
    EraseMember(document, member);
    NDO_CHECK_STATUS(DecodeObservationValue(ndo::Value::MakeMap(std::move(document))));
  }

  // A well-formed document decodes and its identity is recomputed, not trusted.
  ndo::ObservationSnapshot decoded;
  NDO_CHECK_STATUS(ndo::DecodeObservationDocument(ObservationDocument(), ndo::RuntimeLimits{},
                                                  decoded));
  NDO_CHECK_EQ(decoded.target.str(), std::string("device/one"));
  NDO_CHECK_EQ(decoded.source.str(), std::string("collector/one"));
  // Copy the expected identity out of the temporary snapshot before comparing:
  // a reference into a destroyed temporary would read freed memory.
  const std::string expected_identity = BaselineObservation().ComputeSnapshotId().str();
  NDO_CHECK_EQ(decoded.snapshot_id.str(), expected_identity);
}

NDO_TEST(ObservationDocumentRefusesUnknownAndWrongKindMembers) {
  // Unknown members are refused at every level of the document.
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "received_at", ndo::Value::MakeString("2026-01-01T00:00:00Z"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "unexpected", ndo::Value::MakeBool(true))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWithCapability(
                        "teleports", ndo::Value::MakeBool(true))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWithObjectMember(
                        "extra", ndo::Value::MakeInt(1))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWithFieldMember(
                        "unit", ndo::Value::MakeString("dBm"))),
                    ndo::ReasonCode::EncodingMalformed);

  // Declared members of the wrong kind are refused, never defaulted.
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "ttl_nanos", ndo::Value::MakeString("soon"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "epoch", ndo::Value::MakeString("1"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "coverage", ndo::Value::MakeInt(2))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "objects", ndo::Value::MakeMap({}))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "capabilities", ndo::Value::MakeList({}))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "unobserved", ndo::Value::MakeList({ndo::Value::MakeInt(1)}))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "objects", ndo::Value::MakeList({ndo::Value::MakeInt(1)}))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWithObjectMember(
                        "fields", ndo::Value::MakeList({ndo::Value::MakeString("x")}))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWithFieldMember(
                        "path", ndo::Value::MakeInt(3))),
                    ndo::ReasonCode::EncodingMalformed);

  // Unrecognized enum names are refusals, not defaults.
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "coverage", ndo::Value::MakeString("sometimes"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "evidence", ndo::Value::MakeString("imaginary"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWithObjectMember(
                        "presence", ndo::Value::MakeString("maybe"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWithCapability(
                        "evidence", ndo::Value::MakeString("imaginary"))),
                    ndo::ReasonCode::EncodingMalformed);

  // The top-level value must be an object, and a field path must be well formed.
  NDO_CHECK_REFUSED(DecodeObservationValue(ndo::Value::MakeList({})),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWithFieldMember(
                        "path", ndo::Value::MakeString("a..b"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWithFieldMember(
                        "path", ndo::Value::MakeString("a[01]"))),
                    ndo::ReasonCode::EncodingMalformed);
}

NDO_TEST(ObservationDocumentRefusesSelfInconsistentIdentity) {
  // A declared identity that does not match the content is refused.
  ndo::Value::Map document = ObservationDocumentMap();
  SetMember(document, "snapshot_id", ndo::Value::MakeString(std::string(64, '0')));
  NDO_CHECK_REFUSED(DecodeObservationValue(ndo::Value::MakeMap(document)),
                    ndo::ReasonCode::LedgerIntegrityDigestMismatch);

  // A declared identity that does match the content is accepted.
  const ndo::ObservationSnapshot baseline = BaselineObservation();
  const std::string identity = baseline.ComputeSnapshotId().str();
  SetMember(document, "snapshot_id", ndo::Value::MakeString(identity));
  NDO_CHECK_STATUS(DecodeObservationValue(ndo::Value::MakeMap(document)));

  // Changing the content under the declared identity is refused: the digest is
  // recomputed, so this cannot be mistaken for the snapshot that was sealed.
  SetMember(document, "sequence", ndo::Value::MakeUint(8));
  NDO_CHECK_REFUSED(DecodeObservationValue(ndo::Value::MakeMap(document)),
                    ndo::ReasonCode::LedgerIntegrityDigestMismatch);

  // A malformed declared identity is a mismatch, never a silent recompute.
  SetMember(document, "snapshot_id", ndo::Value::MakeString("not-a-digest"));
  NDO_CHECK_REFUSED(DecodeObservationValue(ndo::Value::MakeMap(document)),
                    ndo::ReasonCode::LedgerIntegrityDigestMismatch);
}

NDO_TEST(ObservationDocumentRefusesInconsistentPresence) {
  // An absent object may not carry observed fields.
  NDO_CHECK_REFUSED(
      DecodeObservationValue(ObservationDocumentWithPresence("absent", true, true)),
      ndo::ReasonCode::EncodingMalformed);

  // A source without the absence capability may not assert absence at all, and
  // that capability check precedes the field-shape check.
  NDO_CHECK_REFUSED(
      DecodeObservationValue(ObservationDocumentWithPresence("absent", false, false)),
      ndo::ReasonCode::ObservationSourceCannotAssertAbsence);
  NDO_CHECK_REFUSED(
      DecodeObservationValue(ObservationDocumentWithPresence("absent", true, false)),
      ndo::ReasonCode::ObservationSourceCannotAssertAbsence);

  // The same shape from a capable source is coherent and is accepted.
  NDO_CHECK_STATUS(DecodeObservationValue(ObservationDocumentWithPresence("absent", false, true)));
  NDO_CHECK_STATUS(
      DecodeObservationValue(ObservationDocumentWithPresence("present", true, false)));
  // An unknown presence is never read as absence and needs no capability.
  NDO_CHECK_STATUS(
      DecodeObservationValue(ObservationDocumentWithPresence("unknown", false, false)));
}

NDO_TEST(ObservationDocumentRefusesNonPositiveAuthority) {
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "epoch", ndo::Value::MakeUint(0))),
                    ndo::ReasonCode::FencedStaleEpoch);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "incarnation", ndo::Value::MakeUint(0))),
                    ndo::ReasonCode::FencedStaleIncarnation);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "sequence", ndo::Value::MakeUint(0))),
                    ndo::ReasonCode::ObservationSequenceRegressed);

  // A negative time to live can never become an effective time to live.
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "ttl_nanos", ndo::Value::MakeInt(-1))),
                    ndo::ReasonCode::EncodingMalformed);

  // A snapshot must say when it was collected, and the reading must parse.
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "collected_at", ndo::Value::MakeString("yesterday"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "collected_at", ndo::Value::MakeString("1970-01-01T00:00:00Z"))),
                    ndo::ReasonCode::ObservationClockRegression);

  // Identities that are not valid identity text are refused.
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "source", ndo::Value::MakeString(".."))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocumentWith(
                        "target", ndo::Value::MakeString("has space"))),
                    ndo::ReasonCode::EncodingMalformed);

  // A refused decode leaves the caller's snapshot untouched.
  ndo::ObservationSnapshot sentinel = BaselineObservation();
  sentinel.target = Target("device/sentinel");
  const ndo::Status status = ndo::DecodeObservationDocument(
      ObservationDocumentWith("epoch", ndo::Value::MakeUint(0)), ndo::RuntimeLimits{}, sentinel);
  NDO_CHECK(!status.ok());
  NDO_CHECK(status.reason == ndo::ReasonCode::FencedStaleEpoch);
  NDO_CHECK_EQ(sentinel.target.str(), std::string("device/sentinel"));
}

NDO_TEST(ObservationDocumentRefusesPayloadsBeyondBounds) {
  const std::string text = ndo::WriteCanonicalJson(ObservationDocument());
  ndo::RuntimeLimits document_limits;
  document_limits.max_document_bytes = 16;
  ndo::ObservationSnapshot decoded;
  NDO_CHECK_REFUSED(ndo::ParseObservationJson(text, document_limits, decoded),
                    ndo::ReasonCode::LimitBytesExceeded);

  ndo::RuntimeLimits object_limits;
  object_limits.max_objects_per_target = 0;
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocument(), object_limits),
                    ndo::ReasonCode::LimitObjectsExceeded);

  ndo::RuntimeLimits field_limits;
  field_limits.max_fields_per_object = 0;
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocument(), field_limits),
                    ndo::ReasonCode::LimitFieldsExceeded);

  ndo::RuntimeLimits leaf_limits;
  leaf_limits.max_leaf_bytes = 1;
  NDO_CHECK_REFUSED(DecodeObservationValue(ObservationDocument(), leaf_limits),
                    ndo::ReasonCode::LimitBytesExceeded);

  // A value tree that is too deep or too large is refused by the envelope.
  ndo::ObservationSnapshot deep =
      MakeSnapshot("collector/one", "device/one", 1, FixedTime(1000));
  AddObservedObject(deep, "port/eth0", "admin_state",
                    ndo::Value::MakeList({ndo::Value::MakeInt(1)}));
  SealSnapshot(deep);
  const ndo::Value deep_document = ndo::EncodeObservationDocument(deep);

  ndo::RuntimeLimits depth_limits;
  depth_limits.max_value_depth = 0;
  NDO_CHECK_REFUSED(DecodeObservationValue(deep_document, depth_limits),
                    ndo::ReasonCode::LimitDepthExceeded);

  ndo::RuntimeLimits node_limits;
  node_limits.max_value_nodes = 1;
  NDO_CHECK_REFUSED(DecodeObservationValue(deep_document, node_limits),
                    ndo::ReasonCode::LimitObjectsExceeded);

  // The envelope bounds the document as a whole: a document inflated by one
  // member is refused before it can be admitted, even though every individual
  // object and field inside it stays within its own bound.
  ndo::RuntimeLimits node_cap;
  node_cap.max_value_nodes = 40;
  NDO_CHECK_STATUS(ndo::ParseObservationJson(text, node_cap, decoded));

  ndo::Value::Map inflated = ObservationDocumentMap();
  ndo::Value::List unobserved;
  unobserved.reserve(100);
  for (std::size_t index = 0; index < 100; ++index) {
    unobserved.push_back(ndo::Value::MakeString("object/" + std::to_string(index)));
  }
  SetMember(inflated, "unobserved", ndo::Value::MakeList(std::move(unobserved)));
  NDO_CHECK_REFUSED(ndo::ParseObservationJson(
                        ndo::WriteCanonicalJson(ndo::Value::MakeMap(std::move(inflated))), node_cap,
                        decoded),
                    ndo::ReasonCode::LimitObjectsExceeded);
}

// ===========================================================================
// 3. Intent documents
// ===========================================================================

NDO_TEST(IntentDocumentRefusesMissingAndUnknownMembers) {
  const ndo::Value::Map base = IntentDocumentMap();
  const char* required[] = {"target", "generation", "epoch", "authority",
                            "policy", "authored_at", "objects"};
  for (const char* member : required) {
    ndo::Value::Map document = base;
    EraseMember(document, member);
    NDO_CHECK_REFUSED(DecodeIntentValue(ndo::Value::MakeMap(std::move(document))),
                      ndo::ReasonCode::EncodingMalformed);
  }

  const char* optional[] = {"evidence"};
  for (const char* member : optional) {
    ndo::Value::Map document = base;
    EraseMember(document, member);
    NDO_CHECK_STATUS(DecodeIntentValue(ndo::Value::MakeMap(std::move(document))));
  }

  // Unknown members are refused, including a receive time the observatory
  // stamps itself: intent is never re-timed.
  const char* unknown[] = {"received_at", "stamped_at", "unexpected"};
  for (const char* member : unknown) {
    NDO_CHECK_REFUSED(
        DecodeIntentValue(IntentDocumentWith(member, ndo::Value::MakeString("x"))),
        ndo::ReasonCode::EncodingMalformed);
  }

  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("objects", ndo::Value::MakeMap({}))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("generation", ndo::Value::MakeInt(-1))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("epoch", ndo::Value::MakeString("1"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("evidence",
                                                         ndo::Value::MakeString("imaginary"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(ndo::Value::MakeList({})),
                    ndo::ReasonCode::EncodingMalformed);

  // The well-formed document still decodes.
  ndo::IntentGenerationDocument decoded;
  NDO_CHECK_STATUS(ndo::DecodeIntentDocument(IntentDocument(), ndo::RuntimeLimits{}, decoded));
  NDO_CHECK_EQ(decoded.generation.value(), std::uint64_t{3});
  NDO_CHECK_EQ(decoded.ObjectCount(), std::size_t{1});
  NDO_CHECK_EQ(decoded.FieldCount(), std::size_t{1});
}

NDO_TEST(IntentDocumentRefusesUnknownAuthorityAndUnsetGeneration) {
  // "unknown" is a declared enumerator but never an authority the observatory
  // will compare against; an unrecognized name is not even a valid document.
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("authority",
                                                         ndo::Value::MakeString("unknown"))),
                    ndo::ReasonCode::AuthorityMismatch);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("authority",
                                                         ndo::Value::MakeString("rogue-fabric"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("authority",
                                                         ndo::Value::MakeString(""))),
                    ndo::ReasonCode::EncodingMalformed);

  // Generation zero and epoch zero are unset authority, not ordinary values.
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("generation",
                                                         ndo::Value::MakeUint(0))),
                    ndo::ReasonCode::IntentTargetUndeclared);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("epoch", ndo::Value::MakeUint(0))),
                    ndo::ReasonCode::FencedStaleEpoch);

  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("policy", ndo::Value::MakeString(""))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("policy",
                                                         ndo::Value::MakeString("bad policy"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("target",
                                                         ndo::Value::MakeString("a/../b"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWith("authored_at",
                                                         ndo::Value::MakeString("soon"))),
                    ndo::ReasonCode::EncodingMalformed);
}

NDO_TEST(IntentDocumentRefusesMalformedAndDeepFieldPaths) {
  const char* malformed[] = {".a",   "a.",   "a..b", "a[]",  "a[01]",
                             "a[1",  "a]",   "a.[]", "a[ ]", "a[99999999999999999999]",
                             "a[18446744073709551616]", "a\\b", "a\\"};
  for (const char* path : malformed) {
    NDO_CHECK_REFUSED(
        DecodeIntentValue(IntentDocumentWithFieldMember("path", ndo::Value::MakeString(path))),
        ndo::ReasonCode::EncodingMalformed);
  }

  // A path wider or deeper than the envelope is refused by the decoder.
  const std::string long_key(300, 'k');
  NDO_CHECK_REFUSED(
      DecodeIntentValue(IntentDocumentWithFieldMember("path", ndo::Value::MakeString(long_key))),
      ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWithFieldMember(
                        "path", ndo::Value::MakeString(DeepPath(33, "a")))),
                    ndo::ReasonCode::EncodingMalformed);

  // Escaped separators are legal and round-trip through the canonical form.
  NDO_CHECK_STATUS(DecodeIntentValue(IntentDocumentWithFieldMember(
      "path", ndo::Value::MakeString(R"(a\.b)"))));

  // Object-level malformations.
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWithObjectMember(
                        "id", ndo::Value::MakeString(".."))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWithObjectMember(
                        "existence", ndo::Value::MakeString("maybe"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWithObjectMember(
                        "fields", ndo::Value::MakeMap({}))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWithFieldMember(
                        "comparability", ndo::Value::MakeString("sort-of"))),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_REFUSED(DecodeIntentValue(IntentDocumentWithoutFieldMember("value")),
                    ndo::ReasonCode::EncodingMalformed);

  // The structure validator refuses a path that is deeper or wider than the
  // configured envelope even when it was parsed under a laxer bound.
  const auto deep = ndo::FieldPath::TryParse(DeepPath(33, "a"), 64, 256);
  NDO_CHECK(deep.has_value());
  ndo::IntentGenerationDocument deep_document = MakeIntent("device/one", 3);
  ndo::IntentObject deep_object;
  deep_object.id = Object("port/eth0");
  ndo::IntentField deep_field;
  deep_field.path = *deep;
  deep_field.intended = ndo::Value::MakeInt(1);
  deep_object.fields.emplace(deep_field.path, deep_field);
  deep_document.objects.emplace(deep_object.id, deep_object);
  NDO_CHECK_REFUSED(deep_document.Validate(ndo::RuntimeLimits{}),
                    ndo::ReasonCode::LimitDepthExceeded);

  const std::string wide_key(512, 'w');
  const auto wide = ndo::FieldPath::TryParse(wide_key, 32, 1024);
  NDO_CHECK(wide.has_value());
  ndo::IntentGenerationDocument wide_document = MakeIntent("device/one", 3);
  ndo::IntentObject wide_object;
  wide_object.id = Object("port/eth0");
  ndo::IntentField wide_field;
  wide_field.path = *wide;
  wide_field.intended = ndo::Value::MakeInt(1);
  wide_object.fields.emplace(wide_field.path, wide_field);
  wide_document.objects.emplace(wide_object.id, wide_object);
  NDO_CHECK_REFUSED(wide_document.Validate(ndo::RuntimeLimits{}),
                    ndo::ReasonCode::LimitBytesExceeded);
}

NDO_TEST(IntentCommitRefusesRegressionAndDivergentRepublication) {
  ndo::FindingLedger ledger;
  const ndo::TargetId target = Target("device/one");

  ndo::IntentGenerationDocument generation_two = MakeIntent("device/one", 2);
  AddIntentObject(generation_two, "port/eth0", "admin_state", ndo::Value::MakeString("up"));
  ndo::IntentCommitReport report;
  NDO_CHECK_STATUS(ledger.CommitIntent(generation_two, FixedTime(1000), report));

  const ndo::IntentBaseline* committed = ledger.FindBaseline(target);
  NDO_CHECK(committed != nullptr);
  NDO_CHECK_EQ(committed->generation.value(), std::uint64_t{2});
  const ndo::Digest baseline_digest = committed->content_digest;
  const ndo::LedgerRevision revision_after_commit = ledger.revision();

  // A divergent re-publication of the same generation is a conflict, and the
  // committed baseline is not rewritten.
  ndo::IntentGenerationDocument divergent = generation_two;
  AddIntentObject(divergent, "port/eth0", "admin_state", ndo::Value::MakeString("down"));
  NDO_CHECK_REFUSED(ledger.CommitIntent(divergent, FixedTime(1100), report),
                    ndo::ReasonCode::IntentGenerationConflicting);
  NDO_CHECK_EQ(ledger.FindBaseline(target)->generation.value(), std::uint64_t{2});
  NDO_CHECK(ledger.FindBaseline(target)->content_digest == baseline_digest);
  NDO_CHECK(ledger.revision() == revision_after_commit);

  // An identical re-publication is a no-op, not a rewrite.
  NDO_CHECK_STATUS(ledger.CommitIntent(generation_two, FixedTime(1200), report));
  NDO_CHECK(report.duplicate_identical);
  NDO_CHECK(ledger.revision() == revision_after_commit);
  NDO_CHECK(ledger.FindBaseline(target)->content_digest == baseline_digest);

  // A generation regression is refused and leaves the newer baseline in place.
  ndo::IntentGenerationDocument generation_one = MakeIntent("device/one", 1);
  AddIntentObject(generation_one, "port/eth0", "admin_state", ndo::Value::MakeString("up"));
  NDO_CHECK_REFUSED(ledger.CommitIntent(generation_one, FixedTime(1300), report),
                    ndo::ReasonCode::IntentGenerationRegressed);
  NDO_CHECK_EQ(ledger.FindBaseline(target)->generation.value(), std::uint64_t{2});
  NDO_CHECK(ledger.FindBaseline(target)->content_digest == baseline_digest);

  // Generation zero never becomes a baseline of its own.
  ndo::IntentGenerationDocument generation_zero = MakeIntent("device/one", 0);
  NDO_CHECK_REFUSED(ledger.CommitIntent(generation_zero, FixedTime(1400), report),
                    ndo::ReasonCode::IntentTargetUndeclared);
  NDO_CHECK_EQ(ledger.FindBaseline(target)->generation.value(), std::uint64_t{2});
  NDO_CHECK_EQ(ledger.Stats().baselines, std::size_t{1});

  // A separate target keeps a separate baseline.
  ndo::IntentGenerationDocument other = MakeIntent("device/two", 1);
  NDO_CHECK_STATUS(ledger.CommitIntent(other, FixedTime(1500), report));
  NDO_CHECK_EQ(ledger.Stats().baselines, std::size_t{2});
  NDO_CHECK_EQ(ledger.Stats().targets, std::size_t{2});
}

NDO_TEST(ObservatoryRefusesInvalidInputWithoutPartialState) {
  ndo::ObservatoryConfig config;
  config.policy = SyntheticPolicy();
  config.epoch = ndo::FabricEpoch::FromValue(1);
  config.incarnation = ndo::Incarnation::FromValue(1);
  ndo::Observatory observatory(config, []() { return FixedTime(5000); });

  ndo::IntentCommitReport commit_report;
  ndo::ObservationAdmission admission;
  ndo::IntentGenerationDocument intent = MakeIntent("device/one", 1);
  AddIntentObject(intent, "port/eth0", "admin_state", ndo::Value::MakeString("up"));

  // Ingestion before Start is a precondition failure, not a silent admission.
  NDO_CHECK_REFUSED(observatory.PublishIntent(intent, commit_report),
                    ndo::ReasonCode::None);
  NDO_CHECK_STATUS(observatory.Start());

  NDO_CHECK_STATUS(observatory.PublishIntent(intent, commit_report));
  NDO_CHECK_EQ(observatory.Stats().baselines, std::size_t{1});

  // Generation zero is refused and creates no baseline.
  NDO_CHECK_REFUSED(observatory.PublishIntent(MakeIntent("device/one", 0), commit_report),
                    ndo::ReasonCode::IntentTargetUndeclared);
  NDO_CHECK_EQ(observatory.Stats().baselines, std::size_t{1});
  NDO_CHECK_EQ(observatory.Counters().intents_rejected, std::uint64_t{1});

  // A divergent re-publication is refused and the accepted generation stands.
  ndo::IntentGenerationDocument divergent = intent;
  AddIntentObject(divergent, "port/eth0", "admin_state", ndo::Value::MakeString("down"));
  NDO_CHECK_REFUSED(observatory.PublishIntent(divergent, commit_report),
                    ndo::ReasonCode::IntentGenerationConflicting);
  NDO_CHECK_EQ(observatory.Stats().baselines, std::size_t{1});
  NDO_CHECK_EQ(observatory.Counters().intents_accepted, std::uint64_t{1});
  NDO_CHECK_EQ(observatory.Counters().intents_rejected, std::uint64_t{2});

  // Malformed observation JSON is refused before anything is stored.
  NDO_CHECK_REFUSED(observatory.IngestObservationJson("{\"source\":", admission),
                    ndo::ReasonCode::EncodingMalformed);
  NDO_CHECK_EQ(observatory.Stats().observations, std::size_t{0});
  NDO_CHECK_EQ(observatory.Counters().observations_rejected, std::uint64_t{1});

  // A self-inconsistent document is refused and still stores nothing.
  NDO_CHECK_REFUSED(observatory.IngestObservationJson(
                        ndo::WriteCanonicalJson(ObservationDocumentWith(
                            "epoch", ndo::Value::MakeUint(0))),
                        admission),
                    ndo::ReasonCode::FencedStaleEpoch);
  NDO_CHECK_EQ(observatory.Stats().observations, std::size_t{0});
  NDO_CHECK_EQ(observatory.Counters().observations_rejected, std::uint64_t{2});

  // The pipeline still works afterwards: nothing above was partially applied.
  ndo::ObservationSnapshot snapshot =
      MakeSnapshot("collector/one", "device/one", 1, FixedTime(4000));
  AddObservedObject(snapshot, "port/eth0", "admin_state", ndo::Value::MakeString("up"));
  SealSnapshot(snapshot);
  NDO_CHECK_STATUS(observatory.IngestObservationJson(
      ndo::WriteCanonicalJson(ndo::EncodeObservationDocument(snapshot)), admission));
  NDO_CHECK_EQ(observatory.Stats().observations, std::size_t{1});
  NDO_CHECK_EQ(observatory.Counters().observations_accepted, std::uint64_t{1});
}

// ===========================================================================
// 4. Wire frames
// ===========================================================================

NDO_TEST(WireRefusesMalformedFrames) {
  const ndo::RuntimeLimits limits;
  const std::string payload = "observation-payload";
  std::vector<std::uint8_t> frame;
  NDO_CHECK_STATUS(ndo::EncodeFrame(ndo::FrameType::Snapshot, std::uint16_t{1},
                                    std::uint64_t{9}, payload, limits, frame));
  NDO_CHECK_EQ(frame.size(), ndo::kFrameHeaderBytes + payload.size());

  ndo::FrameHeader header;
  NDO_CHECK_STATUS(ndo::DecodeFrameHeader(frame.data(), frame.size(), limits, header));
  NDO_CHECK(header.type == ndo::FrameType::Snapshot);
  NDO_CHECK_EQ(header.version, static_cast<std::uint16_t>(ndo::kWireProtocolVersion));
  NDO_CHECK_EQ(header.payload_bytes, static_cast<std::uint32_t>(payload.size()));
  NDO_CHECK_EQ(header.sequence, std::uint64_t{9});
  NDO_CHECK_STATUS(ndo::VerifyFramePayload(header, frame.data() + ndo::kFrameHeaderBytes,
                                           payload.size()));

  // A header shorter than the fixed envelope is truncated, never guessed at.
  NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(frame.data(), ndo::kFrameHeaderBytes - 1, limits,
                                           header),
                    ndo::ReasonCode::WireFrameTruncated);
  NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(frame.data(), 0, limits, header),
                    ndo::ReasonCode::WireFrameTruncated);
  NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(nullptr, 0, limits, header),
                    ndo::ReasonCode::WireFrameTruncated);

  // Bad magic.
  std::vector<std::uint8_t> bad_magic = frame;
  bad_magic[0] = static_cast<std::uint8_t>('X');
  NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(bad_magic.data(), bad_magic.size(), limits, header),
                    ndo::ReasonCode::WireFrameMagicMismatch);
  bad_magic = frame;
  bad_magic[3] = static_cast<std::uint8_t>('9');
  NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(bad_magic.data(), bad_magic.size(), limits, header),
                    ndo::ReasonCode::WireFrameMagicMismatch);

  // Unsupported protocol version.
  std::vector<std::uint8_t> bad_version = frame;
  PatchLe16(bad_version, 4, 2);
  NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(bad_version.data(), bad_version.size(), limits, header),
                    ndo::ReasonCode::WireProtocolVersionUnsupported);
  PatchLe16(bad_version, 4, 0);
  NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(bad_version.data(), bad_version.size(), limits, header),
                    ndo::ReasonCode::WireProtocolVersionUnsupported);

  // Unsupported frame type.
  std::vector<std::uint8_t> bad_type = frame;
  PatchLe16(bad_type, 6, 0);
  NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(bad_type.data(), bad_type.size(), limits, header),
                    ndo::ReasonCode::WireFrameTypeUnsupported);
  PatchLe16(bad_type, 6, 99);
  NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(bad_type.data(), bad_type.size(), limits, header),
                    ndo::ReasonCode::WireFrameTypeUnsupported);
  PatchLe16(bad_type, 6, 4242);
  NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(bad_type.data(), bad_type.size(), limits, header),
                    ndo::ReasonCode::WireFrameTypeUnsupported);

  // A declared payload beyond the receiver's envelope is refused before any
  // allocation proportional to it.
  std::vector<std::uint8_t> oversize = frame;
  PatchLe32(oversize, 12, static_cast<std::uint32_t>(limits.max_wire_payload_bytes + 1));
  const ndo::Status oversize_status =
      ndo::DecodeFrameHeader(oversize.data(), oversize.size(), limits, header);
  NDO_CHECK_REFUSED(oversize_status, ndo::ReasonCode::WireFrameOversize);
  NDO_CHECK(oversize_status.code == ndo::StatusCode::LimitExceeded);

  // A payload shorter than declared, or a buffer that still carries the header.
  NDO_CHECK_REFUSED(ndo::VerifyFramePayload(header, frame.data() + ndo::kFrameHeaderBytes,
                                            payload.size() - 1),
                    ndo::ReasonCode::WireFrameTruncated);
  NDO_CHECK_REFUSED(ndo::VerifyFramePayload(header, frame.data(), frame.size()),
                    ndo::ReasonCode::WireFrameTruncated);

  // A flipped payload byte and a flipped header checksum are both mismatches.
  std::vector<std::uint8_t> bad_payload = frame;
  bad_payload[ndo::kFrameHeaderBytes] =
      static_cast<std::uint8_t>(bad_payload[ndo::kFrameHeaderBytes] ^ 0x20u);
  NDO_CHECK_REFUSED(ndo::VerifyFramePayload(header, bad_payload.data() + ndo::kFrameHeaderBytes,
                                            payload.size()),
                    ndo::ReasonCode::WireFrameChecksumMismatch);

  std::vector<std::uint8_t> bad_checksum = frame;
  bad_checksum[16] = static_cast<std::uint8_t>(bad_checksum[16] ^ 0xFFu);
  ndo::FrameHeader checksum_header;
  NDO_CHECK_STATUS(
      ndo::DecodeFrameHeader(bad_checksum.data(), bad_checksum.size(), limits, checksum_header));
  NDO_CHECK_REFUSED(ndo::VerifyFramePayload(checksum_header,
                                            bad_checksum.data() + ndo::kFrameHeaderBytes,
                                            payload.size()),
                    ndo::ReasonCode::WireFrameChecksumMismatch);
}

NDO_TEST(WireRefusesPayloadsBeyondTheSenderEnvelope) {
  ndo::RuntimeLimits wire_limits;
  wire_limits.max_wire_payload_bytes = 4;
  std::vector<std::uint8_t> encoded;
  const ndo::Status oversize_status = ndo::EncodeFrame(
      ndo::FrameType::Hello, std::uint16_t{0}, std::uint64_t{1}, "12345", wire_limits, encoded);
  NDO_CHECK_REFUSED(oversize_status, ndo::ReasonCode::WireFrameOversize);
  NDO_CHECK(oversize_status.code == ndo::StatusCode::LimitExceeded);
  NDO_CHECK(encoded.empty());

  NDO_CHECK_STATUS(ndo::EncodeFrame(ndo::FrameType::Hello, std::uint16_t{0}, std::uint64_t{1},
                                    "1234", wire_limits, encoded));
  NDO_CHECK_EQ(encoded.size(), ndo::kFrameHeaderBytes + std::size_t{4});

  // The same frame is oversize for a receiver with a smaller envelope.
  ndo::RuntimeLimits tiny_limits;
  tiny_limits.max_wire_payload_bytes = 2;
  ndo::FrameHeader header;
  NDO_CHECK_REFUSED(
      ndo::DecodeFrameHeader(encoded.data(), encoded.size(), tiny_limits, header),
      ndo::ReasonCode::WireFrameOversize);
  NDO_CHECK_STATUS(ndo::DecodeFrameHeader(encoded.data(), encoded.size(), wire_limits, header));
}

// ===========================================================================
// 5. Ledger persistence
// ===========================================================================

NDO_TEST(LedgerRefusesCorruptHeaderBytes) {
  const ndo::FindingLedger source = MakeRichLedger();
  const std::vector<std::uint8_t> valid = EncodeLedgerBytes(source);
  NDO_CHECK(valid.size() > ndo::kLedgerHeaderBytes);

  ndo::FindingLedger out;
  ndo::LedgerRecoveryReport report;
  const ndo::RuntimeLimits limits;
  const ndo::FabricEpoch live_epoch = ndo::FabricEpoch::FromValue(1);

  NDO_CHECK_REFUSED(ndo::DecodeLedger(nullptr, 0, limits, live_epoch, out, report),
                    ndo::ReasonCode::LedgerHeaderInvalid);
  NDO_CHECK_REFUSED(ndo::DecodeLedger(valid.data(), 0, limits, live_epoch, out, report),
                    ndo::ReasonCode::LedgerTruncated);
  NDO_CHECK_REFUSED(ndo::DecodeLedger(valid.data(), ndo::kLedgerHeaderBytes - 1, limits,
                                      live_epoch, out, report),
                    ndo::ReasonCode::LedgerTruncated);

  // Corrupted magic.
  std::vector<std::uint8_t> bad_magic = valid;
  bad_magic[0] = static_cast<std::uint8_t>('X');
  NDO_CHECK_REFUSED(
      ndo::DecodeLedger(bad_magic.data(), bad_magic.size(), limits, live_epoch, out, report),
      ndo::ReasonCode::LedgerHeaderInvalid);
  bad_magic = valid;
  bad_magic[7] = static_cast<std::uint8_t>('2');
  NDO_CHECK_REFUSED(
      ndo::DecodeLedger(bad_magic.data(), bad_magic.size(), limits, live_epoch, out, report),
      ndo::ReasonCode::LedgerHeaderInvalid);

  // Unsupported format version in the fixed header and in the payload.
  std::vector<std::uint8_t> bad_format = valid;
  PatchLe16(bad_format, 8, 2);
  NDO_CHECK_REFUSED(
      ndo::DecodeLedger(bad_format.data(), bad_format.size(), limits, live_epoch, out, report),
      ndo::ReasonCode::LedgerSchemaUnsupported);
  PatchLe16(bad_format, 8, static_cast<std::uint16_t>(ndo::kLedgerFormatVersion + 1));
  NDO_CHECK_REFUSED(
      ndo::DecodeLedger(bad_format.data(), bad_format.size(), limits, live_epoch, out, report),
      ndo::ReasonCode::LedgerSchemaUnsupported);
  const std::vector<std::uint8_t> bad_payload_format =
      MutateLedgerPayload(valid, [](ndo::Value::Map& root) {
        SetMember(root, "format_version", ndo::Value::MakeUint(2));
      });
  NDO_CHECK(!bad_payload_format.empty());
  NDO_CHECK_REFUSED(ndo::DecodeLedger(bad_payload_format.data(), bad_payload_format.size(), limits,
                                      live_epoch, out, report),
                    ndo::ReasonCode::LedgerSchemaUnsupported);

  // A declared payload beyond the record envelope.
  std::vector<std::uint8_t> enormouse = valid;
  PatchLe64(enormouse, 12, static_cast<std::uint64_t>(limits.max_record_payload_bytes) + 1);
  const ndo::Status payload_status =
      ndo::DecodeLedger(enormouse.data(), enormouse.size(), limits, live_epoch, out, report);
  NDO_CHECK_REFUSED(payload_status, ndo::ReasonCode::LedgerPayloadTooLarge);
  NDO_CHECK(payload_status.code == ndo::StatusCode::LimitExceeded);

  // A ledger taller than the file envelope is refused before it is read.
  ndo::RuntimeLimits byte_limits;
  byte_limits.max_ledger_bytes = 16;
  NDO_CHECK_REFUSED(ndo::DecodeLedger(valid.data(), valid.size(), byte_limits, live_epoch, out,
                                      report),
                    ndo::ReasonCode::LedgerPayloadTooLarge);

  // Truncated payload and trailing bytes.
  NDO_CHECK_REFUSED(
      ndo::DecodeLedger(valid.data(), valid.size() - 1, limits, live_epoch, out, report),
      ndo::ReasonCode::LedgerTruncated);
  std::vector<std::uint8_t> trailing = valid;
  trailing.push_back(0);
  NDO_CHECK_REFUSED(
      ndo::DecodeLedger(trailing.data(), trailing.size(), limits, live_epoch, out, report),
      ndo::ReasonCode::LedgerTruncated);

  // Bit-flipped payload and bit-flipped header digest.
  std::vector<std::uint8_t> flipped = valid;
  flipped[ndo::kLedgerHeaderBytes + 3] =
      static_cast<std::uint8_t>(flipped[ndo::kLedgerHeaderBytes + 3] ^ 0x01u);
  const ndo::Status flip_status =
      ndo::DecodeLedger(flipped.data(), flipped.size(), limits, live_epoch, out, report);
  NDO_CHECK_REFUSED(flip_status, ndo::ReasonCode::LedgerIntegrityDigestMismatch);
  NDO_CHECK(flip_status.code == ndo::StatusCode::IntegrityFailure);

  std::vector<std::uint8_t> digest_flip = valid;
  digest_flip[20] = static_cast<std::uint8_t>(digest_flip[20] ^ 0x80u);
  NDO_CHECK_REFUSED(
      ndo::DecodeLedger(digest_flip.data(), digest_flip.size(), limits, live_epoch, out, report),
      ndo::ReasonCode::LedgerIntegrityDigestMismatch);

  // A correctly hashed payload that is not the document it claims to be.
  const std::vector<std::uint8_t> not_json = FrameLedgerPayload("not json at all", 1, 1);
  const ndo::Status not_json_status =
      ndo::DecodeLedger(not_json.data(), not_json.size(), limits, live_epoch, out, report);
  NDO_CHECK_REFUSED(not_json_status, ndo::ReasonCode::LedgerDecodeFailed);
  NDO_CHECK(not_json_status.code == ndo::StatusCode::IntegrityFailure);
  const std::vector<std::uint8_t> not_object = FrameLedgerPayload("[]", 1, 1);
  NDO_CHECK_REFUSED(
      ndo::DecodeLedger(not_object.data(), not_object.size(), limits, live_epoch, out, report),
      ndo::ReasonCode::LedgerDecodeFailed);
  const std::vector<std::uint8_t> empty_object = FrameLedgerPayload("{}", 1, 1);
  NDO_CHECK_REFUSED(
      ndo::DecodeLedger(empty_object.data(), empty_object.size(), limits, live_epoch, out, report),
      ndo::ReasonCode::EncodingMalformed);
  const std::vector<std::uint8_t> unknown_member =
      MutateLedgerPayload(valid, [](ndo::Value::Map& root) {
        SetMember(root, "unexpected", ndo::Value::MakeBool(true));
      });
  NDO_CHECK(!unknown_member.empty());
  NDO_CHECK_REFUSED(
      ndo::DecodeLedger(unknown_member.data(), unknown_member.size(), limits, live_epoch, out,
                        report),
      ndo::ReasonCode::EncodingMalformed);

  // A ledger written by a newer epoch than the live one is stale, not applied.
  const std::vector<std::uint8_t> future = FrameLedgerPayload(LedgerPayloadText(valid), 1, 5);
  NDO_CHECK_REFUSED(ndo::DecodeLedger(future.data(), future.size(), limits,
                                      ndo::FabricEpoch::FromValue(3), out, report),
                    ndo::ReasonCode::LedgerVersionRegression);

  // The untouched bytes still decode: none of the refusals above was a false
  // negative on the valid ledger.
  ndo::FindingLedger decoded;
  NDO_CHECK_STATUS(ndo::DecodeLedger(valid.data(), valid.size(), limits, live_epoch, decoded,
                                     report));
  NDO_CHECK_EQ(report.baselines_restored, std::size_t{1});
  NDO_CHECK_EQ(report.observations_restored, std::size_t{1});
  NDO_CHECK_EQ(report.findings_restored, std::size_t{1});
  NDO_CHECK(report.conservative);
  NDO_CHECK(report.reason == ndo::ReasonCode::LedgerRecoveredConservatively);
}

NDO_TEST(LedgerRefusesSelfInconsistentRecords) {
  const ndo::FindingLedger source = MakeRichLedger();
  const std::vector<std::uint8_t> valid = EncodeLedgerBytes(source);
  NDO_CHECK(valid.size() > ndo::kLedgerHeaderBytes);

  ndo::FindingLedger out;
  ndo::LedgerRecoveryReport report;
  const ndo::RuntimeLimits limits;
  const ndo::FabricEpoch live_epoch = ndo::FabricEpoch::FromValue(1);

  // Positive control: the encoder's own output decodes.
  NDO_CHECK_STATUS(ndo::DecodeLedger(valid.data(), valid.size(), limits, live_epoch, out, report));
  NDO_CHECK_EQ(report.findings_restored, std::size_t{1});
  NDO_CHECK_EQ(report.groups_restored, std::size_t{1});

  // A finding whose stored identity does not match its identity members.
  const std::vector<std::uint8_t> bad_finding =
      MutateLedgerPayload(valid, [](ndo::Value::Map& root) {
        ndo::Value::List findings = MemberList(root, "findings");
        ndo::Value::Map finding = AsMap(findings.at(0));
        SetMember(finding, "id", ndo::Value::MakeString(std::string(64, '0')));
        findings.at(0) = ndo::Value::MakeMap(std::move(finding));
        SetMember(root, "findings", ndo::Value::MakeList(std::move(findings)));
      });
  NDO_CHECK(!bad_finding.empty());
  const ndo::Status finding_status = ndo::DecodeLedger(bad_finding.data(), bad_finding.size(),
                                                       limits, live_epoch, out, report);
  NDO_CHECK_REFUSED(finding_status, ndo::ReasonCode::LedgerIntegrityDigestMismatch);
  NDO_CHECK(finding_status.code == ndo::StatusCode::Rejected);

  // The same record with an identity member changed is also inconsistent: the
  // identity is recomputed from the members, not read from the stored digest.
  const std::vector<std::uint8_t> rebased_finding =
      MutateLedgerPayload(valid, [](ndo::Value::Map& root) {
        ndo::Value::List findings = MemberList(root, "findings");
        ndo::Value::Map finding = AsMap(findings.at(0));
        SetMember(finding, "baseline_generation", ndo::Value::MakeUint(5));
        findings.at(0) = ndo::Value::MakeMap(std::move(finding));
        SetMember(root, "findings", ndo::Value::MakeList(std::move(findings)));
      });
  NDO_CHECK(!rebased_finding.empty());
  NDO_CHECK_REFUSED(ndo::DecodeLedger(rebased_finding.data(), rebased_finding.size(), limits,
                                      live_epoch, out, report),
                    ndo::ReasonCode::LedgerIntegrityDigestMismatch);

  // An unrecognized enum name in the last record of the document: the decoder
  // has already restored every earlier section when it refuses.
  const std::vector<std::uint8_t> bad_timeline =
      MutateLedgerPayload(valid, [](ndo::Value::Map& root) {
        ndo::Value::List timeline = MemberList(root, "timeline");
        ndo::Value::Map entry = AsMap(timeline.back());
        SetMember(entry, "kind", ndo::Value::MakeString("teleported"));
        timeline.back() = ndo::Value::MakeMap(std::move(entry));
        SetMember(root, "timeline", ndo::Value::MakeList(std::move(timeline)));
      });
  NDO_CHECK(!bad_timeline.empty());
  NDO_CHECK_REFUSED(ndo::DecodeLedger(bad_timeline.data(), bad_timeline.size(), limits,
                                      live_epoch, out, report),
                    ndo::ReasonCode::EncodingMalformed);

  // An unrecognized root-cause name is refused as well.
  const std::vector<std::uint8_t> bad_group =
      MutateLedgerPayload(valid, [](ndo::Value::Map& root) {
        ndo::Value::List groups = MemberList(root, "groups");
        ndo::Value::Map group = AsMap(groups.at(0));
        SetMember(group, "cause", ndo::Value::MakeString("gravity"));
        groups.at(0) = ndo::Value::MakeMap(std::move(group));
        SetMember(root, "groups", ndo::Value::MakeList(std::move(groups)));
      });
  NDO_CHECK(!bad_group.empty());
  NDO_CHECK_REFUSED(
      ndo::DecodeLedger(bad_group.data(), bad_group.size(), limits, live_epoch, out, report),
      ndo::ReasonCode::EncodingMalformed);

  // An observation document inside the ledger whose identity does not match its
  // content is refused, exactly as it would be at the ingest boundary.
  const std::vector<std::uint8_t> bad_observation =
      MutateLedgerPayload(valid, [](ndo::Value::Map& root) {
        ndo::Value::List observations = MemberList(root, "observations");
        ndo::Value::Map entry = AsMap(observations.at(0));
        ndo::Value::Map document = MemberMap(entry, "document");
        SetMember(document, "snapshot_id", ndo::Value::MakeString(std::string(64, '0')));
        SetMember(entry, "document", ndo::Value::MakeMap(std::move(document)));
        observations.at(0) = ndo::Value::MakeMap(std::move(entry));
        SetMember(root, "observations", ndo::Value::MakeList(std::move(observations)));
      });
  NDO_CHECK(!bad_observation.empty());
  NDO_CHECK_REFUSED(ndo::DecodeLedger(bad_observation.data(), bad_observation.size(), limits,
                                      live_epoch, out, report),
                    ndo::ReasonCode::LedgerIntegrityDigestMismatch);

  // An unknown member on a ledger observation entry is refused too.
  const std::vector<std::uint8_t> bad_observation_member =
      MutateLedgerPayload(valid, [](ndo::Value::Map& root) {
        ndo::Value::List observations = MemberList(root, "observations");
        ndo::Value::Map entry = AsMap(observations.at(0));
        SetMember(entry, "trusted", ndo::Value::MakeBool(true));
        observations.at(0) = ndo::Value::MakeMap(std::move(entry));
        SetMember(root, "observations", ndo::Value::MakeList(std::move(observations)));
      });
  NDO_CHECK(!bad_observation_member.empty());
  NDO_CHECK_REFUSED(ndo::DecodeLedger(bad_observation_member.data(),
                                      bad_observation_member.size(), limits, live_epoch, out,
                                      report),
                    ndo::ReasonCode::EncodingMalformed);
}

NDO_TEST(LedgerRecoveryIsAllOrNothing) {
  ndo::FindingLedger existing = MakeLedgerWithIntent("device/keep", 9);
  const std::string before = LedgerFingerprint(existing);
  const ndo::TargetId kept = Target("device/keep");
  NDO_CHECK(existing.FindBaseline(kept) != nullptr);

  const std::vector<std::uint8_t> valid = EncodeLedgerBytes(MakeRichLedger());
  NDO_CHECK(valid.size() > ndo::kLedgerHeaderBytes);

  std::vector<std::uint8_t> truncated = valid;
  truncated.resize(valid.size() - 1);
  std::vector<std::uint8_t> flipped = valid;
  flipped[ndo::kLedgerHeaderBytes + 5] =
      static_cast<std::uint8_t>(flipped[ndo::kLedgerHeaderBytes + 5] ^ 0x40u);
  std::vector<std::uint8_t> bad_magic = valid;
  bad_magic[1] = static_cast<std::uint8_t>('X');
  std::vector<std::uint8_t> bad_version = valid;
  PatchLe16(bad_version, 8, 9);
  const std::vector<std::uint8_t> late_failure =
      MutateLedgerPayload(valid, [](ndo::Value::Map& root) {
        ndo::Value::List timeline = MemberList(root, "timeline");
        ndo::Value::Map entry = AsMap(timeline.back());
        SetMember(entry, "kind", ndo::Value::MakeString("teleported"));
        timeline.back() = ndo::Value::MakeMap(std::move(entry));
        SetMember(root, "timeline", ndo::Value::MakeList(std::move(timeline)));
      });
  NDO_CHECK(!late_failure.empty());

  const ndo::RuntimeLimits limits;
  const ndo::FabricEpoch live_epoch = ndo::FabricEpoch::FromValue(1);
  const auto expect_refused_and_unchanged = [&](const std::vector<std::uint8_t>& bytes,
                                                ndo::ReasonCode reason) {
    NDO_CHECK(!bytes.empty());
    ndo::LedgerRecoveryReport report;
    const ndo::Status status = ndo::DecodeLedger(bytes.data(), bytes.size(), limits, live_epoch,
                                                 existing, report);
    NDO_CHECK(!status.ok());
    NDO_CHECK(status.reason == reason);
    NDO_CHECK_EQ(LedgerFingerprint(existing), before);
  };

  expect_refused_and_unchanged(truncated, ndo::ReasonCode::LedgerTruncated);
  expect_refused_and_unchanged(flipped, ndo::ReasonCode::LedgerIntegrityDigestMismatch);
  expect_refused_and_unchanged(bad_magic, ndo::ReasonCode::LedgerHeaderInvalid);
  expect_refused_and_unchanged(bad_version, ndo::ReasonCode::LedgerSchemaUnsupported);
  expect_refused_and_unchanged(late_failure, ndo::ReasonCode::EncodingMalformed);

  // The pre-existing content is not merely equal by digest: it is still usable.
  const ndo::IntentBaseline* baseline = existing.FindBaseline(kept);
  NDO_CHECK(baseline != nullptr);
  NDO_CHECK_EQ(baseline->generation.value(), std::uint64_t{9});
  NDO_CHECK(existing.FindBaseline(Target("device/one")) == nullptr);
  NDO_CHECK_EQ(existing.Stats().baselines, std::size_t{1});
  NDO_CHECK_EQ(existing.Stats().findings, std::size_t{0});

  // The same valid bytes do decode into a fresh ledger.
  ndo::FindingLedger fresh;
  ndo::LedgerRecoveryReport report;
  NDO_CHECK_STATUS(ndo::DecodeLedger(valid.data(), valid.size(), limits, live_epoch, fresh,
                                     report));
  NDO_CHECK_EQ(fresh.Stats().findings, std::size_t{1});
}

NDO_TEST(LedgerFileCorruptionIsRefused) {
  TempDir dir("adversarial");
  const ndo::FindingLedger source = MakeRichLedger();
  const std::vector<std::uint8_t> valid = EncodeLedgerBytes(source);
  NDO_CHECK(valid.size() > ndo::kLedgerHeaderBytes);

  const std::string path = dir.File("ledger.ndo");
  NDO_CHECK_STATUS(ndo::SaveLedgerFile(source, path, ndo::FabricEpoch::FromValue(1),
                                       ndo::Incarnation::FromValue(1),
                                       ndo::RuntimeLimits{}.max_ledger_bytes));
  ndo::FindingLedger loaded;
  ndo::LedgerRecoveryReport report;
  NDO_CHECK_STATUS(ndo::LoadLedgerFile(path, ndo::RuntimeLimits{}, ndo::FabricEpoch::FromValue(1),
                                       loaded, report));
  NDO_CHECK_EQ(report.findings_restored, std::size_t{1});

  // A file that ends early is truncated, never partially recovered.
  std::vector<std::uint8_t> truncated = valid;
  truncated.resize(valid.size() - 1);
  const std::string truncated_path = dir.File("truncated.ndo");
  NDO_CHECK(WriteFileBytes(truncated_path, truncated));
  NDO_CHECK_REFUSED(ndo::LoadLedgerFile(truncated_path, ndo::RuntimeLimits{},
                                        ndo::FabricEpoch::FromValue(1), loaded, report),
                    ndo::ReasonCode::LedgerTruncated);

  // A bit-flipped payload fails the digest check.
  std::vector<std::uint8_t> flipped = valid;
  flipped[ndo::kLedgerHeaderBytes + 11] =
      static_cast<std::uint8_t>(flipped[ndo::kLedgerHeaderBytes + 11] ^ 0x10u);
  const std::string flipped_path = dir.File("flipped.ndo");
  NDO_CHECK(WriteFileBytes(flipped_path, flipped));
  NDO_CHECK_REFUSED(ndo::LoadLedgerFile(flipped_path, ndo::RuntimeLimits{},
                                        ndo::FabricEpoch::FromValue(1), loaded, report),
                    ndo::ReasonCode::LedgerIntegrityDigestMismatch);

  // Corrupted magic, a file that is not a ledger at all, and an absent file.
  std::vector<std::uint8_t> bad_magic = valid;
  bad_magic[2] = static_cast<std::uint8_t>('X');
  const std::string bad_magic_path = dir.File("magic.ndo");
  NDO_CHECK(WriteFileBytes(bad_magic_path, bad_magic));
  NDO_CHECK_REFUSED(ndo::LoadLedgerFile(bad_magic_path, ndo::RuntimeLimits{},
                                        ndo::FabricEpoch::FromValue(1), loaded, report),
                    ndo::ReasonCode::LedgerHeaderInvalid);

  const std::string garbage_path = dir.File("garbage.ndo");
  NDO_CHECK(WriteFileBytes(garbage_path, std::vector<std::uint8_t>(200, 0x41)));
  NDO_CHECK_REFUSED(ndo::LoadLedgerFile(garbage_path, ndo::RuntimeLimits{},
                                        ndo::FabricEpoch::FromValue(1), loaded, report),
                    ndo::ReasonCode::LedgerHeaderInvalid);

  NDO_CHECK_REFUSED(ndo::LoadLedgerFile(dir.File("missing.ndo"), ndo::RuntimeLimits{},
                                        ndo::FabricEpoch::FromValue(1), loaded, report),
                    ndo::ReasonCode::LedgerHeaderInvalid);
}

// ===========================================================================
// 6. Values, paths and digests
// ===========================================================================

NDO_TEST(FieldPathRefusesMalformedForms) {
  const char* malformed[] = {".a",     "a.",     "a..b",   "a[]",     "a[01]",
                             "a[1",    "a]",     "a.[]",   "a[ ]",    "[0",
                             "[0.",    "a[+1]",  "a[-1]",  "a\\b",    "a\\",
                             "[99999999999999999999]", "a[18446744073709551616]"};
  for (const char* path : malformed) {
    NDO_CHECK(!ndo::FieldPath::TryParse(path, 32, 256).has_value());
  }

  // Bounds: too many segments, too long a key, a document larger than the
  // parser's own guard.
  NDO_CHECK(!ndo::FieldPath::TryParse(DeepPath(33, "a"), 32, 256).has_value());
  NDO_CHECK(!ndo::FieldPath::TryParse(std::string(257, 'k'), 32, 256).has_value());

  // Control bytes are never part of a canonical key.
  std::string control = "a";
  control.push_back(static_cast<char>(0x1F));
  control += "b";
  NDO_CHECK(!ndo::FieldPath::TryParse(control, 32, 256).has_value());

  // The empty path is the object root, by design, and renders as such.
  const auto root = ndo::FieldPath::TryParse("", 32, 256);
  NDO_CHECK(root.has_value());
  NDO_CHECK(root->empty());
  NDO_CHECK_EQ(root->Describe(), std::string("<root>"));

  // A canonical path parses to the expected segments and round-trips.
  const auto parsed = ndo::FieldPath::TryParse("a.b[3].c", 32, 256);
  NDO_CHECK(parsed.has_value());
  NDO_CHECK_EQ(parsed->size(), std::size_t{4});
  NDO_CHECK((*parsed)[0].kind == ndo::PathSegment::Kind::Key);
  NDO_CHECK_EQ((*parsed)[0].key, std::string("a"));
  NDO_CHECK((*parsed)[1].kind == ndo::PathSegment::Kind::Key);
  NDO_CHECK_EQ((*parsed)[1].key, std::string("b"));
  NDO_CHECK((*parsed)[2].kind == ndo::PathSegment::Kind::Index);
  NDO_CHECK_EQ((*parsed)[2].index, std::uint64_t{3});
  NDO_CHECK((*parsed)[3].kind == ndo::PathSegment::Kind::Key);
  NDO_CHECK_EQ((*parsed)[3].key, std::string("c"));
  NDO_CHECK_EQ(parsed->ToText(), std::string("a.b[3].c"));

  // Escaped separators inside a key round-trip exactly.
  const auto escaped = ndo::FieldPath::TryParse(R"(a\.b\[c\])", 32, 256);
  NDO_CHECK(escaped.has_value());
  NDO_CHECK_EQ(escaped->size(), std::size_t{1});
  NDO_CHECK_EQ((*escaped)[0].key, std::string("a.b[c]"));
  NDO_CHECK_EQ(escaped->ToText(), std::string(R"(a\.b\[c\])"));

  // A large but representable index is accepted exactly.
  const auto large = ndo::FieldPath::TryParse("a[18446744073709551615]", 32, 256);
  NDO_CHECK(large.has_value());
  NDO_CHECK_EQ((*large)[1].index, std::uint64_t{18446744073709551615ULL});
  NDO_CHECK_EQ(large->ToText(), std::string("a[18446744073709551615]"));
}

NDO_TEST(DigestHexRefusesMalformedText) {
  const std::string valid_hex = std::string(64, 'a');
  const auto parsed = ndo::Digest::TryFromHex(valid_hex);
  NDO_CHECK(parsed.has_value());
  NDO_CHECK(parsed->is_set());
  NDO_CHECK_EQ(parsed->ToHex(), valid_hex);
  NDO_CHECK_EQ(parsed->ToShortHex(), std::string(12, 'a'));

  NDO_CHECK(!ndo::Digest::TryFromHex("").has_value());
  NDO_CHECK(!ndo::Digest::TryFromHex(std::string(63, 'a')).has_value());
  NDO_CHECK(!ndo::Digest::TryFromHex(std::string(65, 'a')).has_value());
  NDO_CHECK(!ndo::Digest::TryFromHex(std::string(64, 'g')).has_value());
  NDO_CHECK(!ndo::Digest::TryFromHex("0x" + std::string(62, 'a')).has_value());
  NDO_CHECK(!ndo::Digest::TryFromHex(" " + std::string(63, 'a')).has_value());
  NDO_CHECK(!ndo::Digest::TryFromHex(std::string(64, 'a') + " ").has_value());
  NDO_CHECK(!ndo::Digest::TryFromHex(std::string("--") + std::string(62, 'a')).has_value());

  // An embedded NUL is not a hex digit.
  std::string embedded = std::string(64, 'a');
  embedded[17] = '\0';
  NDO_CHECK(!ndo::Digest::TryFromHex(embedded).has_value());

  // The all-zero digest parses but is unset: boundaries must reject it.
  const auto unset = ndo::Digest::TryFromHex(std::string(64, '0'));
  NDO_CHECK(unset.has_value());
  NDO_CHECK(!unset->is_set());
  const auto finding_id = ndo::FindingId::TryParse(std::string(64, '0'));
  NDO_CHECK(finding_id.has_value());
  NDO_CHECK(!finding_id->is_set());
  NDO_CHECK(!ndo::FindingId::TryParse("too-short").has_value());
}

NDO_TEST(Utf8ValidatorRefusesMalformedSequences) {
  NDO_CHECK(ndo::IsValidUtf8(""));
  NDO_CHECK(ndo::IsValidUtf8("plain ascii"));
  NDO_CHECK(ndo::IsValidUtf8(ByteText({0xC3, 0xA9})));
  NDO_CHECK(ndo::IsValidUtf8(ByteText({0xE2, 0x82, 0xAC})));
  NDO_CHECK(ndo::IsValidUtf8(ByteText({0xF0, 0x9F, 0x98, 0x80})));
  NDO_CHECK(ndo::IsValidUtf8(ByteText({0x7F})));

  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0x80})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xBF})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xC0, 0x80})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xC1, 0xBF})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xE0, 0x80, 0x80})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xF0, 0x80, 0x80, 0x80})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xED, 0xA0, 0x80})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xED, 0xBF, 0xBF})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xF4, 0x90, 0x80, 0x80})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xF5, 0x80, 0x80, 0x80})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xFE})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xFF})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xC3})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xE2, 0x82})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xF0, 0x9F, 0x98})));
  NDO_CHECK(!ndo::IsValidUtf8(ByteText({0xC3, 0x28})));
  NDO_CHECK(!ndo::IsValidUtf8(std::string("ok") + ByteText({0xFF}) + "tail"));
}
