// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Real framed transport over real TCP sockets.
//
// The server binds a loopback port and serves independent connections. Raw
// sockets are used to send frames the library would never build, so the
// reader's validation is exercised rather than its writer's.

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

#include "summon/network_drift_observatory/client.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/server.hpp"
#include "summon/network_drift_observatory/version.hpp"
#include "summon/network_drift_observatory/wire.hpp"

using namespace ndotest;

namespace {

ndo::ObservatoryConfig ServerObservatoryConfig() {
  ndo::ObservatoryConfig config;
  config.policy = SyntheticPolicy();
  config.epoch = ndo::FabricEpoch::FromValue(1);
  config.incarnation = ndo::Incarnation::FromValue(1);
  config.require_registered_sources = false;
  return config;
}

ndo::ServerConfig ServerConfig() {
  ndo::ServerConfig config;
  config.bind_address = "127.0.0.1";
  config.port = 0;
  config.session_idle_timeout_millis = 5000;
  return config;
}

ndo::IntentGenerationDocument IntentFor(const std::string& target) {
  ndo::IntentGenerationDocument intent = MakeIntent(target, 1);
  AddIntentObject(intent, "port/eth0", "mtu", ndo::Value::MakeInt(1500));
  return intent;
}

ndo::ObservationSnapshot SnapshotFor(const std::string& source, const std::string& target,
                                     std::uint64_t sequence, std::int64_t value,
                                     std::uint64_t incarnation = 1) {
  ndo::ObservationSnapshot snapshot = MakeSnapshot(source, target, sequence, ndo::SystemNow(),
                                                  1, incarnation);
  AddObservedObject(snapshot, "port/eth0", "mtu", ndo::Value::MakeInt(value));
  SealSnapshot(snapshot);
  return snapshot;
}

/// Sends one frame on a raw socket and reads the server's answer.
ndo::Status ExchangeFrame(ndo::Socket& socket, ndo::FrameType type, const std::string& payload,
                          ndo::FrameHeader& header, std::vector<std::uint8_t>& response) {
  std::vector<std::uint8_t> frame;
  ndo::Status status = ndo::EncodeFrame(type, 0, 1, payload, ndo::RuntimeLimits{}, frame);
  if (!status.ok()) {
    return status;
  }
  status = socket.SendAll(frame.data(), frame.size());
  if (!status.ok()) {
    return status;
  }
  std::uint8_t raw_header[ndo::kFrameHeaderBytes];
  status = socket.ReceiveExact(raw_header, ndo::kFrameHeaderBytes);
  if (!status.ok()) {
    return status;
  }
  status = ndo::DecodeFrameHeader(raw_header, ndo::kFrameHeaderBytes, ndo::RuntimeLimits{}, header);
  if (!status.ok()) {
    return status;
  }
  response.assign(header.payload_bytes, 0);
  if (!response.empty()) {
    status = socket.ReceiveExact(response.data(), response.size());
    if (!status.ok()) {
      return status;
    }
  }
  return ndo::VerifyFramePayload(header, response.data(), response.size());
}

}  // namespace

NDO_TEST(HandshakePublishAndAcknowledgeOverRealSockets) {
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::IntentCommitReport commit;
  NDO_CHECK_STATUS(observatory.PublishIntent(IntentFor("switch/net"), commit));

  ndo::ObservationServer server(observatory, ServerConfig());
  NDO_CHECK_STATUS(server.Start());
  NDO_CHECK(server.port() != 0);

  ndo::ClientConfig client_config;
  client_config.host = "127.0.0.1";
  client_config.port = server.port();
  client_config.source = Source("collector/socket");
  client_config.epoch = ndo::FabricEpoch::FromValue(1);
  client_config.incarnation = ndo::Incarnation::FromValue(4);
  client_config.capabilities.asserts_absence = true;
  client_config.capabilities.complete_coverage = true;
  client_config.capabilities.reports_nested_paths = true;
  client_config.capabilities.evidence = ndo::EvidenceClass::Synthetic;

  ndo::ObservationPublisher publisher(client_config);
  NDO_CHECK_STATUS(publisher.Connect());
  NDO_CHECK(publisher.connected());
  NDO_CHECK_EQ(publisher.handshake().server_epoch.value(), std::uint64_t{1});
  NDO_CHECK_EQ(publisher.handshake().server_incarnation.value(), std::uint64_t{1});
  NDO_CHECK(publisher.handshake().session_id > 0);

  ndo::ObservationSnapshot first = SnapshotFor("collector/socket", "switch/net", 1, 9000, 4);
  ndo::AckPayload ack;
  NDO_CHECK_STATUS(publisher.Publish(first, ack));
  NDO_CHECK(ack.accepted);
  NDO_CHECK(ack.snapshot == first.snapshot_id);

  // The same snapshot again is an exact duplicate, not a conflict.
  ndo::ObservationSnapshot duplicate = first;
  NDO_CHECK_STATUS(publisher.Publish(duplicate, ack));
  NDO_CHECK(ack.accepted);

  NDO_CHECK_STATUS(publisher.Close());
  NDO_CHECK_STATUS(server.Stop());

  const ndo::ServerStats stats = server.Stats();
  NDO_CHECK_EQ(stats.sessions_accepted, std::uint64_t{1});
  NDO_CHECK_EQ(stats.sessions_closed, std::uint64_t{1});
  NDO_CHECK_EQ(stats.active_sessions, std::uint64_t{0});
  NDO_CHECK(stats.snapshots_admitted >= 1);
  NDO_CHECK(observatory.Stats().observations >= 1);
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(IncarnationAndSequenceFencingOverTheWire) {
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::IntentCommitReport commit;
  NDO_CHECK_STATUS(observatory.PublishIntent(IntentFor("switch/fence"), commit));

  ndo::ObservationServer server(observatory, ServerConfig());
  NDO_CHECK_STATUS(server.Start());

  const auto make_config = [&](std::uint64_t incarnation) {
    ndo::ClientConfig config;
    config.host = "127.0.0.1";
    config.port = server.port();
    config.source = Source("collector/fenced");
    config.epoch = ndo::FabricEpoch::FromValue(1);
    config.incarnation = ndo::Incarnation::FromValue(incarnation);
    config.capabilities.asserts_absence = true;
    config.capabilities.complete_coverage = true;
    config.capabilities.evidence = ndo::EvidenceClass::Synthetic;
    return config;
  };

  // The first incarnation establishes the fence.
  {
    ndo::ObservationPublisher publisher(make_config(7));
    NDO_CHECK_STATUS(publisher.Connect());
    ndo::AckPayload ack;
    ndo::ObservationSnapshot snapshot = SnapshotFor("collector/fenced", "switch/fence", 5, 9000, 7);
    NDO_CHECK_STATUS(publisher.Publish(snapshot, ack));
    NDO_CHECK(ack.accepted);
    NDO_CHECK_STATUS(publisher.Close());
  }

  // An older incarnation is refused at the greeting.
  {
    ndo::ObservationPublisher publisher(make_config(6));
    const ndo::Status status = publisher.Connect();
    NDO_CHECK(!status.ok());
    NDO_CHECK(status.reason == ndo::ReasonCode::FencedStaleIncarnation);
    NDO_CHECK(!publisher.connected());
  }

  // The same incarnation may reconnect, but it may not go backwards in time.
  {
    ndo::ObservationPublisher publisher(make_config(7));
    NDO_CHECK_STATUS(publisher.Connect());
    ndo::AckPayload ack;
    ndo::ObservationSnapshot stale = SnapshotFor("collector/fenced", "switch/fence", 4, 1500, 7);
    NDO_CHECK_STATUS(publisher.Publish(stale, ack));
    NDO_CHECK(!ack.accepted);
    NDO_CHECK(ack.reason == ndo::ReasonCode::FencedStaleSequence);

    // A replay of the sequence with different content is a conflict.
    ndo::ObservationSnapshot conflicting =
        SnapshotFor("collector/fenced", "switch/fence", 5, 1500, 7);
    NDO_CHECK_STATUS(publisher.Publish(conflicting, ack));
    NDO_CHECK(!ack.accepted);
    NDO_CHECK(ack.reason == ndo::ReasonCode::ObservationDuplicateConflicting);

    // A newer sequence is accepted.
    ndo::ObservationSnapshot fresh = SnapshotFor("collector/fenced", "switch/fence", 6, 1500, 7);
    NDO_CHECK_STATUS(publisher.Publish(fresh, ack));
    NDO_CHECK(ack.accepted);
    NDO_CHECK_STATUS(publisher.Close());
  }

  // A higher incarnation takes over the fence, and the old one is refused.
  {
    ndo::ObservationPublisher publisher(make_config(8));
    NDO_CHECK_STATUS(publisher.Connect());
    ndo::AckPayload ack;
    ndo::ObservationSnapshot snapshot = SnapshotFor("collector/fenced", "switch/fence", 1, 9000, 8);
    NDO_CHECK_STATUS(publisher.Publish(snapshot, ack));
    NDO_CHECK(ack.accepted);
    NDO_CHECK_STATUS(publisher.Close());
  }
  NDO_CHECK(server.Stats().stale_fenced >= 3);
  NDO_CHECK_STATUS(server.Stop());
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(RawFramesAreValidatedBeforeTheyAreTrusted) {
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::ObservationServer server(observatory, ServerConfig());
  NDO_CHECK_STATUS(server.Start());

  // A snapshot frame before any greeting is refused.
  {
    auto socket = ndo::Socket::Connect("127.0.0.1", server.port());
    NDO_CHECK(socket.ok());
    ndo::FrameHeader header;
    std::vector<std::uint8_t> response;
    NDO_CHECK_STATUS(ExchangeFrame(socket.value(), ndo::FrameType::Snapshot, "{}", header, response));
    NDO_CHECK(header.type == ndo::FrameType::ErrorFrame);
    ndo::Value document;
    NDO_CHECK_STATUS(ndo::ParseJson(
        std::string_view(reinterpret_cast<const char*>(response.data()), response.size()),
        ndo::RuntimeLimits{}, document));
    const ndo::Value::Map* map = document.as_map();
    NDO_CHECK(map != nullptr);
    if (map != nullptr) {
      const auto reason = map->find("reason");
      NDO_CHECK(reason != map->end());
      if (reason != map->end() && reason->second.as_string() != nullptr) {
        NDO_CHECK_EQ(*reason->second.as_string(), std::string("WireHandshakeRequired"));
      }
    }
  }

  // A frame whose checksum does not match its payload is refused.
  {
    auto socket = ndo::Socket::Connect("127.0.0.1", server.port());
    NDO_CHECK(socket.ok());
    std::vector<std::uint8_t> frame;
    NDO_CHECK_STATUS(ndo::EncodeFrame(ndo::FrameType::Hello, 0, 1, "{}", ndo::RuntimeLimits{}, frame));
    // Corrupt one payload byte without touching the checksum.
    frame.back() = static_cast<std::uint8_t>(frame.back() ^ 0x5A);
    NDO_CHECK_STATUS(socket.value().SendAll(frame.data(), frame.size()));
    std::uint8_t raw_header[ndo::kFrameHeaderBytes];
    std::size_t received = 0;
    ndo::Status read_status = socket.value().ReceiveSome(raw_header, ndo::kFrameHeaderBytes, received);
    NDO_CHECK(read_status.ok());
    if (read_status.ok() && received == ndo::kFrameHeaderBytes) {
      ndo::FrameHeader header;
      NDO_CHECK_STATUS(ndo::DecodeFrameHeader(raw_header, received, ndo::RuntimeLimits{}, header));
      NDO_CHECK(header.type == ndo::FrameType::ErrorFrame);
      std::vector<std::uint8_t> payload(header.payload_bytes, 0);
      if (!payload.empty()) {
        NDO_CHECK_STATUS(socket.value().ReceiveExact(payload.data(), payload.size()));
      }
      ndo::Value document;
      NDO_CHECK_STATUS(ndo::ParseJson(
          std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()),
          ndo::RuntimeLimits{}, document));
      const ndo::Value::Map* map = document.as_map();
      NDO_CHECK(map != nullptr);
      if (map != nullptr) {
        const auto reason = map->find("reason");
        NDO_CHECK(reason != map->end());
        if (reason != map->end() && reason->second.as_string() != nullptr) {
          NDO_CHECK_EQ(*reason->second.as_string(), std::string("WireFrameChecksumMismatch"));
        }
      }
    }
  }

  // A header that declares a payload beyond the envelope is refused before the
  // payload is allocated.
  {
    ndo::RuntimeLimits limits;
    std::vector<std::uint8_t> header(ndo::kFrameHeaderBytes, 0);
    for (std::size_t index = 0; index < sizeof(ndo::kFrameMagic); ++index) {
      header[index] = ndo::kFrameMagic[index];
    }
    header[4] = static_cast<std::uint8_t>(ndo::kWireProtocolVersion & 0xFF);
    header[6] = static_cast<std::uint8_t>(ndo::FrameType::Hello);
    const std::uint32_t oversize = static_cast<std::uint32_t>(limits.max_wire_payload_bytes + 1);
    header[12] = static_cast<std::uint8_t>(oversize & 0xFF);
    header[13] = static_cast<std::uint8_t>((oversize >> 8) & 0xFF);
    header[14] = static_cast<std::uint8_t>((oversize >> 16) & 0xFF);
    header[15] = static_cast<std::uint8_t>((oversize >> 24) & 0xFF);
    ndo::FrameHeader decoded;
    NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(header.data(), header.size(), limits, decoded),
                      ndo::ReasonCode::WireFrameOversize);
  }

  // Bad magic and an unsupported version are refused.
  {
    std::vector<std::uint8_t> header(ndo::kFrameHeaderBytes, 0);
    ndo::FrameHeader decoded;
    NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(header.data(), header.size(), ndo::RuntimeLimits{}, decoded),
                      ndo::ReasonCode::WireFrameMagicMismatch);
    for (std::size_t index = 0; index < sizeof(ndo::kFrameMagic); ++index) {
      header[index] = ndo::kFrameMagic[index];
    }
    header[4] = 0x7F;
    NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(header.data(), header.size(), ndo::RuntimeLimits{}, decoded),
                      ndo::ReasonCode::WireProtocolVersionUnsupported);
    header[4] = static_cast<std::uint8_t>(ndo::kWireProtocolVersion & 0xFF);
    header[6] = 0x7F;
    NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(header.data(), header.size(), ndo::RuntimeLimits{}, decoded),
                      ndo::ReasonCode::WireFrameTypeUnsupported);
    // A short buffer is refused without reading past it.
    NDO_CHECK_REFUSED(ndo::DecodeFrameHeader(header.data(), 4, ndo::RuntimeLimits{}, decoded),
                      ndo::ReasonCode::WireFrameTruncated);
  }

  NDO_CHECK_STATUS(server.Stop());
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(SessionLimitIsEnforced) {
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::ServerConfig config = ServerConfig();
  config.limits.max_sessions = 1;
  // A generous idle bound: this test is about the session limit, not about
  // expiry, so a silent session must stay open for the duration.
  config.session_idle_timeout_millis = 60000;
  ndo::ObservationServer server(observatory, config);
  NDO_CHECK_STATUS(server.Start());

  ndo::ClientConfig client_config;
  client_config.host = "127.0.0.1";
  client_config.port = server.port();
  client_config.source = Source("collector/limit");
  client_config.epoch = ndo::FabricEpoch::FromValue(1);
  client_config.incarnation = ndo::Incarnation::FromValue(1);
  ndo::ObservationPublisher first(client_config);
  NDO_CHECK_STATUS(first.Connect());
  // A session becomes active when the server accepts it, which is asynchronous
  // to the client handshake; wait for the server to see it before asserting the
  // limit.
  for (int attempt = 0; attempt < 400 && server.Stats().active_sessions != 1; ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  NDO_CHECK_EQ(server.Stats().active_sessions, std::uint64_t{1});

  // A second session is refused while the first is open, and the refusal names
  // the bound it hit.
  ndo::ClientConfig second_config = client_config;
  second_config.source = Source("collector/limit-2");
  ndo::ObservationPublisher second(second_config);
  const ndo::Status second_status = second.Connect();
  NDO_CHECK(!second_status.ok());
  NDO_CHECK_EQ(std::string(ndo::ToText(second_status.reason)),
               std::string("WireSessionLimitExceeded"));
  NDO_CHECK(server.Stats().sessions_refused >= 1);

  NDO_CHECK_STATUS(first.Close());
  NDO_CHECK_STATUS(server.Stop());
  NDO_CHECK_EQ(server.Stats().active_sessions, std::uint64_t{0});
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(IdleSessionIsToldWhyItWasClosed) {
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::ServerConfig config = ServerConfig();
  config.session_idle_timeout_millis = 400;
  ndo::ObservationServer server(observatory, config);
  NDO_CHECK_STATUS(server.Start());

  auto idle = ndo::Socket::Connect("127.0.0.1", server.port());
  NDO_CHECK(idle.ok());
  idle.value().SetReceiveTimeoutMillis(10000);
  // A silent session is told why it was closed rather than held forever.
  std::uint8_t raw_header[ndo::kFrameHeaderBytes];
  const ndo::Status idle_status = idle.value().ReceiveExact(raw_header, ndo::kFrameHeaderBytes);
  NDO_CHECK_STATUS(idle_status);
  if (idle_status.ok()) {
    ndo::FrameHeader idle_frame;
    NDO_CHECK_STATUS(ndo::DecodeFrameHeader(raw_header, ndo::kFrameHeaderBytes,
                                            ndo::RuntimeLimits{}, idle_frame));
    NDO_CHECK(idle_frame.type == ndo::FrameType::ErrorFrame);
    std::vector<std::uint8_t> idle_payload(idle_frame.payload_bytes, 0);
    if (!idle_payload.empty()) {
      NDO_CHECK_STATUS(idle.value().ReceiveExact(idle_payload.data(), idle_payload.size()));
    }
    NDO_CHECK_STATUS(ndo::VerifyFramePayload(idle_frame, idle_payload.data(), idle_payload.size()));
    ndo::Value document;
    NDO_CHECK_STATUS(ndo::ParseJson(
        std::string_view(reinterpret_cast<const char*>(idle_payload.data()), idle_payload.size()),
        ndo::RuntimeLimits{}, document));
    const ndo::Value::Map* map = document.as_map();
    NDO_CHECK(map != nullptr);
    if (map != nullptr) {
      const auto reason = map->find("reason");
      NDO_CHECK(reason != map->end());
      if (reason != map->end() && reason->second.as_string() != nullptr) {
        NDO_CHECK_EQ(*reason->second.as_string(), std::string("WireSessionIdleExpired"));
      }
    }
  }
  NDO_CHECK(server.Stats().idle_expired >= 1);
  NDO_CHECK_STATUS(server.Stop());
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(StopRetiresLiveSessionsAndReturnsAccounting) {
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::ObservationServer server(observatory, ServerConfig());
  NDO_CHECK_STATUS(server.Start());

  std::vector<std::unique_ptr<ndo::ObservationPublisher>> publishers;
  for (int index = 0; index < 3; ++index) {
    ndo::ClientConfig config;
    config.host = "127.0.0.1";
    config.port = server.port();
    config.source = Source("collector/stop-" + std::to_string(index));
    config.epoch = ndo::FabricEpoch::FromValue(1);
    config.incarnation = ndo::Incarnation::FromValue(1);
    auto publisher = std::make_unique<ndo::ObservationPublisher>(config);
    NDO_CHECK_STATUS(publisher->Connect());
    publishers.push_back(std::move(publisher));
  }
  NDO_CHECK_EQ(server.Stats().active_sessions, std::uint64_t{3});

  // Stopping the server shuts every session down and joins every thread.
  NDO_CHECK_STATUS(server.Stop());
  NDO_CHECK_EQ(server.Stats().active_sessions, std::uint64_t{0});
  NDO_CHECK_EQ(server.Stats().sessions_closed, std::uint64_t{3});
  NDO_CHECK_STATUS(server.Stop());

  // A publisher whose session was retired observes a closed connection.
  ndo::AckPayload ack;
  ndo::ObservationSnapshot snapshot = SnapshotFor("collector/stop-0", "switch/any", 1, 1500, 1);
  const ndo::Status status = publishers.front()->Publish(snapshot, ack);
  NDO_CHECK(!status.ok());
  for (auto& publisher : publishers) {
    static_cast<void>(publisher->Close());
  }
  NDO_CHECK_STATUS(observatory.Stop());
}

NDO_TEST(IntentCanBePublishedOverTheWire) {
  ndo::Observatory observatory(ServerObservatoryConfig(), []() { return ndo::SystemNow(); });
  NDO_CHECK_STATUS(observatory.Start());
  ndo::ObservationServer server(observatory, ServerConfig());
  NDO_CHECK_STATUS(server.Start());

  ndo::ClientConfig config;
  config.host = "127.0.0.1";
  config.port = server.port();
  config.source = Source("publisher/intent");
  config.epoch = ndo::FabricEpoch::FromValue(1);
  config.incarnation = ndo::Incarnation::FromValue(1);
  ndo::ObservationPublisher publisher(config);
  NDO_CHECK_STATUS(publisher.Connect());

  ndo::IntentGenerationDocument intent = IntentFor("switch/wire");
  ndo::AckPayload ack;
  NDO_CHECK_STATUS(publisher.PublishIntent(intent, ack));
  NDO_CHECK(ack.accepted);
  NDO_CHECK_EQ(ack.generation.value(), std::uint64_t{1});
  NDO_CHECK(observatory.Stats().baselines == 1);

  // A generation regression published over the wire is refused with a reason.
  ndo::IntentGenerationDocument divergent = IntentFor("switch/wire");
  divergent.objects.find(Object("port/eth0"))->second.fields.begin()->second.intended =
      ndo::Value::MakeInt(9000);
  NDO_CHECK_STATUS(publisher.PublishIntent(divergent, ack));
  NDO_CHECK(!ack.accepted);
  NDO_CHECK(ack.reason == ndo::ReasonCode::IntentGenerationConflicting);

  NDO_CHECK_STATUS(publisher.Close());
  NDO_CHECK_STATUS(server.Stop());
  NDO_CHECK_STATUS(observatory.Stop());
}
