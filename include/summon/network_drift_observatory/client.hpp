// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Observation publisher.
//
// The client half of the framed transport. It is what an independent collector
// process runs: connect, handshake with an explicit epoch and incarnation,
// publish snapshots, read one acknowledgement per frame, and close.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_CLIENT_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_CLIENT_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "summon/network_drift_observatory/intent.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/net.hpp"
#include "summon/network_drift_observatory/observation.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/wire.hpp"

namespace summon {
namespace network_drift_observatory {

struct NDO_API ClientConfig {
  std::string host{"127.0.0.1"};
  std::uint16_t port{0};
  SourceId source;
  FabricEpoch epoch;
  Incarnation incarnation;
  SourceSequence start_sequence{SourceSequence::FromValue(1)};
  SourceCapabilities capabilities;
  std::string provenance;
  RuntimeLimits limits;
  std::uint32_t io_timeout_millis{30000};
};

/// One connected, handshaken publishing session.
class NDO_API ObservationPublisher {
 public:
  ObservationPublisher(ClientConfig config);
  ~ObservationPublisher();
  ObservationPublisher(const ObservationPublisher&) = delete;
  ObservationPublisher& operator=(const ObservationPublisher&) = delete;

  /// Connects and completes the handshake. A refused handshake leaves the
  /// publisher closed and reports the server's reason code.
  Status Connect();
  NDO_NODISCARD bool connected() const noexcept { return socket_.valid() && handshaken_; }
  NDO_NODISCARD const HelloAckPayload& handshake() const noexcept { return handshake_; }

  /// Publishes one snapshot. The snapshot identity is recomputed locally before
  /// send, so the client cannot publish a self-inconsistent document.
  Status Publish(ObservationSnapshot& snapshot, AckPayload& ack);
  /// Publishes one intent generation document.
  Status PublishIntent(const IntentGenerationDocument& document, AckPayload& ack);
  /// Publishes a raw, caller-supplied payload. Used by adversarial tests that
  /// need to send a document the library would refuse to build.
  Status PublishRaw(std::string_view payload, FrameType type, AckPayload& ack);

  /// Sends a graceful close. Safe to call on an already-closed publisher.
  Status Close();

  NDO_NODISCARD SourceSequence next_sequence() const noexcept { return next_sequence_; }
  NDO_NODISCARD const ClientConfig& config() const noexcept { return config_; }

 private:
  Status SendFrame(FrameType type, std::uint16_t flags, const Value& payload);
  Status ReadFrame(FrameHeader& header, std::vector<std::uint8_t>& payload);

  ClientConfig config_;
  Socket socket_;
  bool handshaken_{false};
  SourceSequence next_sequence_;
  std::uint64_t frame_sequence_{0};
  HelloAckPayload handshake_;
};

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_CLIENT_HPP
