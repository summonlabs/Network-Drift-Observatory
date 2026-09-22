// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/wire.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "json_help.hpp"
#include "summon/network_drift_observatory/hash.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/version.hpp"

namespace summon {
namespace network_drift_observatory {
namespace {

struct NamePair {
  std::uint16_t value;
  const char* name;
};

constexpr NamePair kFrameTypeNames[] = {
    {1, "hello"},        {2, "hello-ack"}, {3, "snapshot"},   {4, "snapshot-ack"},
    {5, "intent"},       {6, "intent-ack"}, {7, "error"},     {8, "bye"},
    {9, "heartbeat"},
};

void AppendU16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void AppendU32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  for (int index = 0; index < 4; ++index) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu));
  }
}

void AppendU64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (int index = 0; index < 8; ++index) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu));
  }
}

std::uint16_t ReadU16(const std::uint8_t* data) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[0]) |
                                    static_cast<std::uint16_t>(data[1] << 8));
}

std::uint32_t ReadU32(const std::uint8_t* data) {
  std::uint32_t value = 0;
  for (int index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(data[index]) << (8 * index);
  }
  return value;
}

std::uint64_t ReadU64(const std::uint8_t* data) {
  std::uint64_t value = 0;
  for (int index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(data[index]) << (8 * index);
  }
  return value;
}

}  // namespace

const char* ToText(FrameType value) noexcept {
  const std::uint16_t raw = static_cast<std::uint16_t>(value);
  for (const NamePair& entry : kFrameTypeNames) {
    if (entry.value == raw) {
      return entry.name;
    }
  }
  return "unknown";
}

bool TryParseFrameType(std::uint16_t raw, FrameType& out) noexcept {
  for (const NamePair& entry : kFrameTypeNames) {
    if (entry.value == raw) {
      out = static_cast<FrameType>(entry.value);
      return true;
    }
  }
  return false;
}

Status EncodeFrame(FrameType type, std::uint16_t flags, std::uint64_t sequence,
                   std::string_view payload, const RuntimeLimits& limits,
                   std::vector<std::uint8_t>& out) {
  if (payload.size() > limits.max_wire_payload_bytes) {
    return Status::Limit(ReasonCode::WireFrameOversize, "frame payload exceeds the envelope");
  }
  out.clear();
  out.reserve(kFrameHeaderBytes + payload.size());
  out.insert(out.end(), kFrameMagic, kFrameMagic + sizeof(kFrameMagic));
  AppendU16(out, kWireProtocolVersion);
  AppendU16(out, static_cast<std::uint16_t>(type));
  AppendU16(out, flags);
  AppendU16(out, 0);  // reserved
  AppendU32(out, static_cast<std::uint32_t>(payload.size()));
  AppendU32(out, Crc32(payload.data(), payload.size()));
  AppendU64(out, sequence);
  out.insert(out.end(), payload.begin(), payload.end());
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status DecodeFrameHeader(const std::uint8_t* header, std::size_t size, const RuntimeLimits& limits,
                         FrameHeader& out) {
  if (header == nullptr || size < kFrameHeaderBytes) {
    return Status::Rejected(ReasonCode::WireFrameTruncated, "the frame header is incomplete");
  }
  for (std::size_t index = 0; index < sizeof(kFrameMagic); ++index) {
    if (header[index] != kFrameMagic[index]) {
      return Status::Rejected(ReasonCode::WireFrameMagicMismatch, "the frame magic does not match");
    }
  }
  const std::uint16_t version = ReadU16(header + 4);
  if (version != kWireProtocolVersion) {
    return Status::Rejected(ReasonCode::WireProtocolVersionUnsupported,
                            "the frame protocol version is not supported");
  }
  const std::uint16_t raw_type = ReadU16(header + 6);
  FrameType type = FrameType::ErrorFrame;
  if (!TryParseFrameType(raw_type, type)) {
    return Status::Rejected(ReasonCode::WireFrameTypeUnsupported, "the frame type is not recognized");
  }
  const std::uint32_t payload_bytes = ReadU32(header + 12);
  if (payload_bytes > limits.max_wire_payload_bytes) {
    return Status::Limit(ReasonCode::WireFrameOversize, "the declared payload exceeds the envelope");
  }
  out.version = version;
  out.type = type;
  out.flags = ReadU16(header + 8);
  out.payload_bytes = payload_bytes;
  out.checksum = ReadU32(header + 16);
  out.sequence = ReadU64(header + 20);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status VerifyFramePayload(const FrameHeader& header, const std::uint8_t* payload,
                          std::size_t size) {
  if (size != header.payload_bytes) {
    return Status::Rejected(ReasonCode::WireFrameTruncated,
                            "the payload length does not match the header");
  }
  const std::uint32_t computed = Crc32(payload, size);
  if (computed != header.checksum) {
    return Status::Rejected(ReasonCode::WireFrameChecksumMismatch,
                            "the payload checksum does not match the header");
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

Value EncodeHello(const HelloPayload& payload) {
  Value::Map map;
  map.emplace("schema", Value::MakeString("ndo/hello/1"));
  map.emplace("source", Value::MakeString(payload.source.str()));
  map.emplace("epoch", Value::MakeUint(payload.epoch.value()));
  map.emplace("incarnation", Value::MakeUint(payload.incarnation.value()));
  map.emplace("start_sequence", Value::MakeUint(payload.start_sequence.value()));
  map.emplace("provenance", Value::MakeString(payload.provenance));
  map.emplace("product_version", Value::MakeString(payload.product_version));
  Value::Map capabilities;
  capabilities.emplace("asserts_absence", Value::MakeBool(payload.capabilities.asserts_absence));
  capabilities.emplace("complete_coverage", Value::MakeBool(payload.capabilities.complete_coverage));
  capabilities.emplace("reports_nested_paths",
                       Value::MakeBool(payload.capabilities.reports_nested_paths));
  capabilities.emplace("evidence", Value::MakeString(ToText(payload.capabilities.evidence)));
  map.emplace("capabilities", Value::MakeMap(std::move(capabilities)));
  return Value::MakeMap(std::move(map));
}

Status DecodeHello(const Value& value, const RuntimeLimits& limits, HelloPayload& out) {
  const Value::Map* map = value.as_map();
  if (map == nullptr) {
    return Status::Rejected(ReasonCode::WireHandshakeRejected, "the hello payload must be an object");
  }
  Status status = detail::CheckMembers(*map,
                                       {"schema", "source", "epoch", "incarnation", "start_sequence",
                                        "provenance", "product_version", "capabilities"},
                                       "hello");
  if (!status.ok()) {
    return status;
  }
  HelloPayload payload;
  std::string text;
  status = detail::RequireString(*map, "source", "hello", text);
  if (!status.ok()) {
    return status;
  }
  const auto source = SourceId::TryParse(text);
  if (!source.has_value()) {
    return detail::MemberError("hello", "source", "is not a valid identity");
  }
  payload.source = *source;
  std::uint64_t number = 0;
  status = detail::RequireUint(*map, "epoch", "hello", number);
  if (!status.ok()) {
    return status;
  }
  payload.epoch = FabricEpoch::FromValue(number);
  status = detail::RequireUint(*map, "incarnation", "hello", number);
  if (!status.ok()) {
    return status;
  }
  payload.incarnation = Incarnation::FromValue(number);
  if (const std::optional<std::uint64_t> sequence = detail::OptionalUint(*map, "start_sequence");
      sequence.has_value()) {
    payload.start_sequence = SourceSequence::FromValue(*sequence);
  }
  if (const std::optional<std::string> provenance = detail::OptionalString(*map, "provenance");
      provenance.has_value()) {
    if (provenance->size() > limits.max_leaf_bytes) {
      return Status::Limit(ReasonCode::LimitBytesExceeded, "provenance exceeds the envelope");
    }
    payload.provenance = *provenance;
  }
  if (const std::optional<std::string> version = detail::OptionalString(*map, "product_version");
      version.has_value()) {
    if (version->size() > limits.max_leaf_bytes) {
      return Status::Limit(ReasonCode::LimitBytesExceeded, "product version exceeds the envelope");
    }
    payload.product_version = *version;
  }
  if (const Value* capabilities = detail::FindMember(*map, "capabilities"); capabilities != nullptr) {
    const Value::Map* capability_map = capabilities->as_map();
    if (capability_map == nullptr) {
      return detail::MemberError("hello", "capabilities", "must be an object");
    }
    if (const std::optional<bool> flag = detail::OptionalBool(*capability_map, "asserts_absence");
        flag.has_value()) {
      payload.capabilities.asserts_absence = *flag;
    }
    if (const std::optional<bool> flag = detail::OptionalBool(*capability_map, "complete_coverage");
        flag.has_value()) {
      payload.capabilities.complete_coverage = *flag;
    }
    if (const std::optional<bool> flag =
            detail::OptionalBool(*capability_map, "reports_nested_paths");
        flag.has_value()) {
      payload.capabilities.reports_nested_paths = *flag;
    }
    if (const std::optional<std::string> evidence =
            detail::OptionalString(*capability_map, "evidence");
        evidence.has_value()) {
      EvidenceClass parsed = EvidenceClass::Unknown;
      if (!TryParseEvidenceClass(evidence->c_str(), parsed)) {
        return detail::MemberError("hello.capabilities", "evidence", "is not recognized");
      }
      payload.capabilities.evidence = parsed;
    }
  }
  if (!payload.epoch.is_set() || !payload.incarnation.is_set()) {
    return Status::Rejected(ReasonCode::FencedStaleIncarnation,
                            "hello must declare a positive epoch and incarnation");
  }
  out = std::move(payload);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Value EncodeHelloAck(const HelloAckPayload& payload) {
  Value::Map map;
  map.emplace("schema", Value::MakeString("ndo/hello-ack/1"));
  map.emplace("accepted", Value::MakeBool(payload.accepted));
  map.emplace("reason", Value::MakeString(ToText(payload.reason)));
  map.emplace("protocol_version", Value::MakeUint(payload.protocol_version));
  map.emplace("server_epoch", Value::MakeUint(payload.server_epoch.value()));
  map.emplace("server_incarnation", Value::MakeUint(payload.server_incarnation.value()));
  map.emplace("session_id", Value::MakeUint(payload.session_id));
  map.emplace("max_payload_bytes", Value::MakeUint(payload.max_payload_bytes));
  map.emplace("detail", Value::MakeString(payload.detail));
  return Value::MakeMap(std::move(map));
}

Status DecodeHelloAck(const Value& value, HelloAckPayload& out) {
  const Value::Map* map = value.as_map();
  if (map == nullptr) {
    return Status::Rejected(ReasonCode::WireHandshakeRejected, "the hello acknowledgement must be an object");
  }
  HelloAckPayload payload;
  if (const std::optional<bool> accepted = detail::OptionalBool(*map, "accepted");
      accepted.has_value()) {
    payload.accepted = *accepted;
  }
  if (const std::optional<std::string> reason = detail::OptionalString(*map, "reason");
      reason.has_value()) {
    if (!TryParseReasonCode(reason->c_str(), payload.reason)) {
      return detail::MemberError("hello-ack", "reason", "is not recognized");
    }
  }
  if (const std::optional<std::uint64_t> version = detail::OptionalUint(*map, "protocol_version");
      version.has_value()) {
    payload.protocol_version = static_cast<std::uint16_t>(*version & 0xFFFFu);
  }
  if (const std::optional<std::uint64_t> epoch = detail::OptionalUint(*map, "server_epoch");
      epoch.has_value()) {
    payload.server_epoch = FabricEpoch::FromValue(*epoch);
  }
  if (const std::optional<std::uint64_t> incarnation =
          detail::OptionalUint(*map, "server_incarnation");
      incarnation.has_value()) {
    payload.server_incarnation = Incarnation::FromValue(*incarnation);
  }
  if (const std::optional<std::uint64_t> session = detail::OptionalUint(*map, "session_id");
      session.has_value()) {
    payload.session_id = *session;
  }
  if (const std::optional<std::uint64_t> maximum = detail::OptionalUint(*map, "max_payload_bytes");
      maximum.has_value()) {
    payload.max_payload_bytes = static_cast<std::uint32_t>(*maximum & 0xFFFFFFFFu);
  }
  if (const std::optional<std::string> detail = detail::OptionalString(*map, "detail");
      detail.has_value()) {
    payload.detail = *detail;
  }
  out = std::move(payload);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Value EncodeAck(const AckPayload& payload) {
  Value::Map map;
  map.emplace("schema", Value::MakeString("ndo/ack/1"));
  map.emplace("accepted", Value::MakeBool(payload.accepted));
  map.emplace("reason", Value::MakeString(ToText(payload.reason)));
  map.emplace("sequence", Value::MakeUint(payload.sequence.value()));
  map.emplace("snapshot", Value::MakeString(payload.snapshot.str()));
  map.emplace("generation", Value::MakeUint(payload.generation.value()));
  map.emplace("detail", Value::MakeString(payload.detail));
  return Value::MakeMap(std::move(map));
}

Status DecodeAck(const Value& value, AckPayload& out) {
  const Value::Map* map = value.as_map();
  if (map == nullptr) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "the acknowledgement must be an object");
  }
  AckPayload payload;
  if (const std::optional<bool> accepted = detail::OptionalBool(*map, "accepted");
      accepted.has_value()) {
    payload.accepted = *accepted;
  }
  if (const std::optional<std::string> reason = detail::OptionalString(*map, "reason");
      reason.has_value()) {
    if (!TryParseReasonCode(reason->c_str(), payload.reason)) {
      return detail::MemberError("ack", "reason", "is not recognized");
    }
  }
  if (const std::optional<std::uint64_t> sequence = detail::OptionalUint(*map, "sequence");
      sequence.has_value()) {
    payload.sequence = SourceSequence::FromValue(*sequence);
  }
  if (const std::optional<std::string> snapshot = detail::OptionalString(*map, "snapshot");
      snapshot.has_value() && !snapshot->empty()) {
    const auto parsed = SnapshotId::TryParse(*snapshot);
    if (!parsed.has_value()) {
      return detail::MemberError("ack", "snapshot", "is not a valid identity");
    }
    payload.snapshot = *parsed;
  }
  if (const std::optional<std::uint64_t> generation = detail::OptionalUint(*map, "generation");
      generation.has_value()) {
    payload.generation = IntentGeneration::FromValue(*generation);
  }
  if (const std::optional<std::string> detail = detail::OptionalString(*map, "detail");
      detail.has_value()) {
    payload.detail = *detail;
  }
  out = std::move(payload);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Value EncodeError(ReasonCode reason, std::string_view detail) {
  Value::Map map;
  map.emplace("schema", Value::MakeString("ndo/error/1"));
  map.emplace("reason", Value::MakeString(ToText(reason)));
  map.emplace("domain", Value::MakeString(ReasonCodeDomain(reason)));
  map.emplace("detail", Value::MakeString(std::string(detail)));
  return Value::MakeMap(std::move(map));
}

}  // namespace network_drift_observatory
}  // namespace summon
