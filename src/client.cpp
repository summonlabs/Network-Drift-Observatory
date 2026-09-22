// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/client.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "json_help.hpp"

namespace detail_ = summon::network_drift_observatory::detail;
#include "summon/network_drift_observatory/interchange.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/version.hpp"

namespace summon {
namespace network_drift_observatory {

ObservationPublisher::ObservationPublisher(ClientConfig config) : config_(std::move(config)) {}

ObservationPublisher::~ObservationPublisher() {
  try {
    Close();
  } catch (...) {
    // A destructor must not propagate.
  }
}

Status ObservationPublisher::Connect() {
  if (config_.source.empty() || !IsValidIdentityText(config_.source.str())) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "the source identity is invalid");
  }
  if (!config_.epoch.is_set() || !config_.incarnation.is_set()) {
    return Status::Rejected(ReasonCode::FencedStaleIncarnation,
                            "the publisher requires an explicit epoch and incarnation");
  }
  if (config_.port == 0) {
    return Status::Rejected(ReasonCode::EncodingMalformed, "the publisher requires a port");
  }
  auto socket = Socket::Connect(config_.host, config_.port);
  if (!socket.ok()) {
    return socket.status();
  }
  socket_ = std::move(socket.value());
  socket_.SetNoDelay(true);
  socket_.SetReceiveTimeoutMillis(config_.io_timeout_millis);
  socket_.SetSendTimeoutMillis(config_.io_timeout_millis);

  HelloPayload hello;
  hello.source = config_.source;
  hello.epoch = config_.epoch;
  hello.incarnation = config_.incarnation;
  hello.start_sequence = config_.start_sequence;
  hello.capabilities = config_.capabilities;
  hello.provenance = config_.provenance;
  hello.product_version = kVersionString;
  Status status = SendFrame(FrameType::Hello, 0, EncodeHello(hello));
  FrameHeader header;
  std::vector<std::uint8_t> payload;
  if (status.ok()) {
    status = ReadFrame(header, payload);
  } else {
    // The write may have failed because the server already refused the session
    // and closed its side. The refusal itself is the more useful answer.
    const Status read_status = ReadFrame(header, payload);
    if (!read_status.ok()) {
      socket_.Close();
      return status;
    }
  }
  if (!status.ok() && payload.empty()) {
    socket_.Close();
    return status;
  }
  Value document;
  status = ParseJson(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()),
                     config_.limits, document);
  if (!status.ok()) {
    socket_.Close();
    return status;
  }
  if (header.type == FrameType::ErrorFrame) {
    // The server refused before the greeting completed (for example because it
    // is at its session limit). Its reason code is the authoritative one.
    ReasonCode reason = ReasonCode::WireHandshakeRejected;
    std::string detail = "the server refused the greeting";
    if (const Value::Map* map = document.as_map(); map != nullptr) {
      if (const std::optional<std::string> text = detail_::OptionalString(*map, "reason");
          text.has_value()) {
        const bool recognized = TryParseReasonCode(text->c_str(), reason);
        static_cast<void>(recognized);
      }
      if (const std::optional<std::string> text = detail_::OptionalString(*map, "detail");
          text.has_value()) {
        detail = *text;
      }
    }
    socket_.Close();
    return Status::Rejected(reason, detail);
  }
  if (header.type != FrameType::HelloAck) {
    socket_.Close();
    return Status::Rejected(ReasonCode::WireHandshakeRejected,
                            "the server did not answer the greeting");
  }
  status = DecodeHelloAck(document, handshake_);
  if (!status.ok()) {
    socket_.Close();
    return status;
  }
  if (!handshake_.accepted) {
    const ReasonCode reason = handshake_.reason;
    const std::string detail = handshake_.detail;
    socket_.Close();
    return Status::Rejected(reason == ReasonCode::None ? ReasonCode::WireHandshakeRejected : reason,
                            detail.empty() ? "the handshake was refused" : detail);
  }
  next_sequence_ = config_.start_sequence;
  handshaken_ = true;
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status ObservationPublisher::Close() {
  if (!socket_.valid()) {
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  if (handshaken_) {
    Value::Map bye;
    bye.emplace("schema", Value::MakeString("ndo/bye/1"));
    bye.emplace("session_closed", Value::MakeBool(true));
    SendFrame(FrameType::Bye, static_cast<std::uint16_t>(FrameFlags::Final),
              Value::MakeMap(std::move(bye)));
  }
  socket_.ShutdownBoth();
  socket_.Close();
  handshaken_ = false;
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status ObservationPublisher::SendFrame(FrameType type, std::uint16_t flags, const Value& payload) {
  std::vector<std::uint8_t> frame;
  const std::string text = WriteCanonicalJson(payload);
  Status status = EncodeFrame(type, flags, ++frame_sequence_, text, config_.limits, frame);
  if (!status.ok()) {
    return status;
  }
  return socket_.SendAll(frame.data(), frame.size());
}

Status ObservationPublisher::ReadFrame(FrameHeader& header, std::vector<std::uint8_t>& payload) {
  std::uint8_t raw_header[kFrameHeaderBytes];
  Status status = socket_.ReceiveExact(raw_header, kFrameHeaderBytes);
  if (!status.ok()) {
    return status;
  }
  status = DecodeFrameHeader(raw_header, kFrameHeaderBytes, config_.limits, header);
  if (!status.ok()) {
    return status;
  }
  payload.assign(header.payload_bytes, 0);
  if (!payload.empty()) {
    status = socket_.ReceiveExact(payload.data(), payload.size());
    if (!status.ok()) {
      return status;
    }
  }
  return VerifyFramePayload(header, payload.data(), payload.size());
}

Status ObservationPublisher::Publish(ObservationSnapshot& snapshot, AckPayload& ack) {
  if (!connected()) {
    return Status::Rejected(ReasonCode::WireHandshakeRequired, "the publisher is not connected");
  }
  // The client refuses to publish a self-inconsistent document: the identity is
  // recomputed locally before the frame leaves the process.
  const Digest digest = snapshot.ComputeContentDigest();
  snapshot.snapshot_id = SnapshotId::Trusted(digest.ToHex());
  Status status = snapshot.Validate(config_.limits);
  if (!status.ok()) {
    return status;
  }
  status = SendFrame(FrameType::Snapshot, static_cast<std::uint16_t>(FrameFlags::ExpectResponse),
                     EncodeObservationDocument(snapshot));
  if (!status.ok()) {
    return status;
  }
  FrameHeader header;
  std::vector<std::uint8_t> payload;
  status = ReadFrame(header, payload);
  if (!status.ok()) {
    return status;
  }
  Value document;
  status = ParseJson(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()),
                     config_.limits, document);
  if (!status.ok()) {
    return status;
  }
  if (header.type != FrameType::SnapshotAck) {
    return Status::Rejected(ReasonCode::WireFrameTypeUnsupported,
                            "the server did not acknowledge the snapshot");
  }
  status = DecodeAck(document, ack);
  if (!status.ok()) {
    return status;
  }
  if (ack.accepted) {
    next_sequence_ = SourceSequence::FromValue(snapshot.sequence.value() + 1);
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status ObservationPublisher::PublishIntent(const IntentGenerationDocument& document,
                                           AckPayload& ack) {
  if (!connected()) {
    return Status::Rejected(ReasonCode::WireHandshakeRequired, "the publisher is not connected");
  }
  Status status = document.Validate(config_.limits);
  if (!status.ok()) {
    return status;
  }
  status = SendFrame(FrameType::Intent, static_cast<std::uint16_t>(FrameFlags::ExpectResponse),
                     EncodeIntentDocument(document));
  if (!status.ok()) {
    return status;
  }
  FrameHeader header;
  std::vector<std::uint8_t> payload;
  status = ReadFrame(header, payload);
  if (!status.ok()) {
    return status;
  }
  Value value;
  status = ParseJson(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()),
                     config_.limits, value);
  if (!status.ok()) {
    return status;
  }
  if (header.type != FrameType::IntentAck) {
    return Status::Rejected(ReasonCode::WireFrameTypeUnsupported,
                            "the server did not acknowledge the intent document");
  }
  return DecodeAck(value, ack);
}

Status ObservationPublisher::PublishRaw(std::string_view payload, FrameType type, AckPayload& ack) {
  if (!connected()) {
    return Status::Rejected(ReasonCode::WireHandshakeRequired, "the publisher is not connected");
  }
  Status status = SendFrame(type, static_cast<std::uint16_t>(FrameFlags::ExpectResponse), 
                            Value::MakeString(std::string(payload)));
  if (!status.ok()) {
    return status;
  }
  FrameHeader header;
  std::vector<std::uint8_t> response;
  status = ReadFrame(header, response);
  if (!status.ok()) {
    return status;
  }
  Value value;
  status = ParseJson(
      std::string_view(reinterpret_cast<const char*>(response.data()), response.size()),
      config_.limits, value);
  if (!status.ok()) {
    return status;
  }
  if (header.type != FrameType::ErrorFrame) {
    return DecodeAck(value, ack);
  }
  const Value::Map* map = value.as_map();
  if (map != nullptr) {
    if (const std::optional<std::string> reason = detail::OptionalString(*map, "reason");
        reason.has_value()) {
      const bool recognized = TryParseReasonCode(reason->c_str(), ack.reason);
      static_cast<void>(recognized);
    }
  }
  ack.accepted = false;
  return Status(StatusCode::Ok, ReasonCode::None);
}

}  // namespace network_drift_observatory
}  // namespace summon
