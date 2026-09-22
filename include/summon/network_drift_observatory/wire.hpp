// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Framed observation transport.
//
// Every message is a fixed header followed by a length-delimited payload:
//
//   magic[4]="NDO1" | version u16 | type u16 | flags u16 | reserved u16
//   | payload_bytes u32 | checksum u32 (CRC-32 of the payload) | sequence u64
//
// The reader validates magic, version, declared length and checksum before it
// allocates or trusts anything. A frame that fails any check is refused with a
// precise reason code and the session is closed; nothing is "repaired".

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_WIRE_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_WIRE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/observation.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/value.hpp"

namespace summon {
namespace network_drift_observatory {

inline constexpr std::uint8_t kFrameMagic[4] = {'N', 'D', 'O', '1'};
/// magic(4) + version(2) + type(2) + flags(2) + reserved(2) + payload(4) +
/// checksum(4) + sequence(8).
inline constexpr std::size_t kFrameHeaderBytes = 28;

enum class FrameType : std::uint16_t {
  /// Client greeting: source identity, epoch, incarnation and capabilities.
  Hello = 1,
  /// Server greeting response: accepted or refused, plus server authority.
  HelloAck = 2,
  /// One observation snapshot document.
  Snapshot = 3,
  /// Server response to one snapshot.
  SnapshotAck = 4,
  /// One intent generation document.
  Intent = 5,
  /// Server response to one intent document.
  IntentAck = 6,
  /// A refusal with a reason code.
  ErrorFrame = 7,
  /// Graceful session close.
  Bye = 8,
  /// Keep-alive. Carries no document.
  Heartbeat = 9,
};

NDO_API const char* ToText(FrameType value) noexcept;
NDO_NODISCARD NDO_API bool TryParseFrameType(std::uint16_t raw, FrameType& out) noexcept;

enum class FrameFlags : std::uint16_t {
  None = 0,
  /// The sender expects exactly one response frame.
  ExpectResponse = 1,
  /// The session ends after this frame.
  Final = 2,
};

struct NDO_API FrameHeader {
  std::uint16_t version{0};
  FrameType type{FrameType::ErrorFrame};
  std::uint16_t flags{0};
  std::uint32_t payload_bytes{0};
  std::uint32_t checksum{0};
  std::uint64_t sequence{0};
};

/// Encodes a complete frame. Refuses a payload larger than the configured
/// bound before any allocation proportional to it.
NDO_NODISCARD NDO_API Status EncodeFrame(FrameType type, std::uint16_t flags,
                                          std::uint64_t sequence, std::string_view payload,
                                          const RuntimeLimits& limits,
                                          std::vector<std::uint8_t>& out);

/// Decodes and validates a header. Never reads beyond kFrameHeaderBytes.
NDO_NODISCARD NDO_API Status DecodeFrameHeader(const std::uint8_t* header, std::size_t size,
                                               const RuntimeLimits& limits, FrameHeader& out);

/// Validates a payload against its header: length and checksum.
NDO_NODISCARD NDO_API Status VerifyFramePayload(const FrameHeader& header, const std::uint8_t* payload,
                                                std::size_t size);

/// Payload of a Hello frame.
struct NDO_API HelloPayload {
  SourceId source;
  FabricEpoch epoch;
  Incarnation incarnation;
  SourceSequence start_sequence;
  SourceCapabilities capabilities;
  std::string provenance;
  std::string product_version;
};

struct NDO_API HelloAckPayload {
  bool accepted{false};
  ReasonCode reason{ReasonCode::None};
  std::uint16_t protocol_version{0};
  FabricEpoch server_epoch;
  Incarnation server_incarnation;
  std::uint64_t session_id{0};
  std::uint32_t max_payload_bytes{0};
  std::string detail;
};

struct NDO_API AckPayload {
  bool accepted{false};
  ReasonCode reason{ReasonCode::None};
  SourceSequence sequence;
  SnapshotId snapshot;
  IntentGeneration generation;
  std::string detail;
};

NDO_NODISCARD NDO_API Value EncodeHello(const HelloPayload& payload);
NDO_NODISCARD NDO_API Status DecodeHello(const Value& value, const RuntimeLimits& limits,
                                         HelloPayload& out);
NDO_NODISCARD NDO_API Value EncodeHelloAck(const HelloAckPayload& payload);
NDO_NODISCARD NDO_API Status DecodeHelloAck(const Value& value, HelloAckPayload& out);
NDO_NODISCARD NDO_API Value EncodeAck(const AckPayload& payload);
NDO_NODISCARD NDO_API Status DecodeAck(const Value& value, AckPayload& out);
NDO_NODISCARD NDO_API Value EncodeError(ReasonCode reason, std::string_view detail);

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_WIRE_HPP
