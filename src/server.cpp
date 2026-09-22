// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/server.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "summon/network_drift_observatory/interchange.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/version.hpp"

namespace summon {
namespace network_drift_observatory {
namespace {

/// Upper bound on the number of frames one session may have outstanding. A
/// client that pipelines more than this is refused instead of buffered.
constexpr std::size_t kMaxPipelinedFrames = 8;

}  // namespace

ObservationServer::ObservationServer(Observatory& observatory, ServerConfig config)
    : observatory_(observatory), config_(std::move(config)) {}

ObservationServer::~ObservationServer() {
  try {
    Stop();
  } catch (...) {
    // A destructor must not propagate.
  }
}

Status ObservationServer::Start() {
  if (running_.load()) {
    return Status::Precondition(ReasonCode::None, "the server is already running");
  }
  Status status = InitializeNetworking();
  if (!status.ok()) {
    return status;
  }
  auto listener = Listener::Bind(config_.bind_address, config_.port, config_.backlog);
  if (!listener.ok()) {
    return listener.status();
  }
  listener_ = std::move(listener.value());
  bound_port_ = listener_.local_port();
  if (bound_port_ == 0) {
    listener_.Close();
    return Status::Rejected(ReasonCode::WireSessionClosed, "the listener did not report a port");
  }
  stop_requested_.store(false);
  running_.store(true);
  accept_thread_ = std::thread([this]() {
    try {
      AcceptLoop();
    } catch (...) {
      running_.store(false);
    }
  });
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status ObservationServer::Stop() {
  if (!running_.load() && !accept_thread_.joinable()) {
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  stop_requested_.store(true);
  running_.store(false);
  // Closing the listener unblocks a thread waiting in accept().
  listener_.Close();
  CloseAllSessions();
  if (accept_thread_.joinable()) {
    accept_thread_.join();
  }
  std::vector<std::thread> threads;
  {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (auto& entry : sessions_) {
      if (entry.second.thread.joinable()) {
        threads.push_back(std::move(entry.second.thread));
      }
    }
    sessions_.clear();
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.active_sessions = 0;
  }
  sessions_cv_.notify_all();
  return Status(StatusCode::Ok, ReasonCode::None);
}

bool ObservationServer::running() const noexcept {
  return running_.load();
}

ServerStats ObservationServer::Stats() {
  // Sessions whose peer has gone away are retired here, not only when the next
  // connection arrives: accounting must return to its baseline on its own.
  ReapFinishedSessions();
  std::lock_guard<std::mutex> lock(stats_mutex_);
  ServerStats stats = stats_;
  std::lock_guard<std::mutex> sessions_lock(sessions_mutex_);
  stats.active_sessions = sessions_.size();
  return stats;
}

std::optional<SourceFence> ObservationServer::FenceFor(const SourceId& source) const {
  std::lock_guard<std::mutex> lock(fence_mutex_);
  const auto found = fences_.find(source);
  if (found == fences_.end()) {
    return std::nullopt;
  }
  return found->second;
}

void ObservationServer::CloseAllSessions() {
  std::lock_guard<std::mutex> lock(sessions_mutex_);
  for (auto& entry : sessions_) {
    if (entry.second.socket != nullptr) {
      entry.second.socket->ShutdownBoth();
    }
  }
}

void ObservationServer::ReapFinishedSessions() {
  std::vector<std::thread> finished;
  {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (auto entry = sessions_.begin(); entry != sessions_.end();) {
      if (entry->second.done != nullptr && entry->second.done->load()) {
        if (entry->second.thread.joinable()) {
          finished.push_back(std::move(entry->second.thread));
        }
        entry = sessions_.erase(entry);
        continue;
      }
      ++entry;
    }
  }
  for (std::thread& thread : finished) {
    thread.join();
  }
}

void ObservationServer::AcceptLoop() {
  while (!stop_requested_.load()) {
    Socket socket;
    const Status status = listener_.Accept(socket);
    if (!status.ok()) {
      if (stop_requested_.load()) {
        break;
      }
      continue;
    }
    ReapFinishedSessions();
    const std::uint64_t session_id = next_session_id_.fetch_add(1);
    bool refused = false;
    {
      std::lock_guard<std::mutex> lock(sessions_mutex_);
      if (sessions_.size() >= config_.limits.max_sessions) {
        refused = true;
      } else {
        SessionSlot slot;
        slot.socket = std::make_shared<Socket>(std::move(socket));
        slot.done = std::make_shared<std::atomic<bool>>(false);
        sessions_.emplace(session_id, std::move(slot));
      }
    }
    if (refused) {
      // The refusal is accounted for before it is sent, so a peer that has seen
      // the refusal can rely on the counter being updated.
      {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.sessions_refused;
      }
      // The refusal is delivered before the socket is closed, and the peer's
      // pending greeting is drained first: closing with unread data in the
      // receive buffer would send a reset and could destroy the refusal.
      std::vector<std::uint8_t> frame;
      const Value payload = EncodeError(ReasonCode::WireSessionLimitExceeded,
                                        "the server is at its session limit");
      if (EncodeFrame(FrameType::ErrorFrame, 0, 0, WriteCanonicalJson(payload), config_.limits,
                      frame)
              .ok()) {
        socket.SendAll(frame.data(), frame.size());
      }
      socket.ShutdownSend();
      socket.SetReceiveTimeoutMillis(250);
      std::uint8_t scratch[512];
      for (int attempt = 0; attempt < 8; ++attempt) {
        std::size_t received = 0;
        if (!socket.ReceiveSome(scratch, sizeof(scratch), received).ok() || received == 0) {
          break;
        }
      }
      socket.Close();
      continue;
    }
    {
      std::lock_guard<std::mutex> lock(stats_mutex_);
      ++stats_.sessions_accepted;
      if (stats_.active_sessions + 1 > stats_.high_water_sessions) {
        stats_.high_water_sessions = stats_.active_sessions + 1;
      }
    }
    std::shared_ptr<Socket> session_socket;
    std::shared_ptr<std::atomic<bool>> done;
    {
      std::lock_guard<std::mutex> lock(sessions_mutex_);
      const auto found = sessions_.find(session_id);
      if (found == sessions_.end()) {
        continue;
      }
      session_socket = found->second.socket;
      done = found->second.done;
      found->second.thread = std::thread([this, session_socket, done, session_id]() {
        try {
          SessionLoop(*session_socket, session_id);
        } catch (...) {
          // A session must never take the server down with it.
        }
        session_socket->Close();
        done->store(true);
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.sessions_closed;
        sessions_cv_.notify_all();
      });
    }
  }
}

void ObservationServer::SessionLoop(Socket& socket, std::uint64_t session_id) {
  socket.SetNoDelay(true);
  socket.SetReceiveTimeoutMillis(config_.session_idle_timeout_millis);
  socket.SetSendTimeoutMillis(config_.session_idle_timeout_millis);
  SessionContext context;
  context.session_id = session_id;
  while (!stop_requested_.load()) {
    FrameHeader header;
    std::vector<std::uint8_t> payload;
    const Status read_status = ReadFrame(socket, header, payload);
    if (!read_status.ok()) {
      if (read_status.reason == ReasonCode::WireSessionClosed) {
        // The peer closed the session; nothing to report back.
        break;
      }
      if (read_status.reason == ReasonCode::WireSessionIdleExpired ||
          read_status.reason == ReasonCode::WireFrameTruncated) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.idle_expired;
      }
      {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.frames_refused;
      }
      // The peer is told why it was disconnected, then the session ends.
      SendError(socket, read_status.reason, read_status.detail);
      break;
    }
    {
      std::lock_guard<std::mutex> lock(stats_mutex_);
      ++stats_.frames_received;
    }
    const Status handled = HandleFrame(socket, header, payload, context);
    if (!handled.ok()) {
      break;
    }
    if ((header.flags & static_cast<std::uint16_t>(FrameFlags::Final)) != 0) {
      break;
    }
  }
}

Status ObservationServer::ReadFrame(Socket& socket, FrameHeader& header,
                                    std::vector<std::uint8_t>& payload) {
  std::uint8_t raw_header[kFrameHeaderBytes];
  std::size_t received = 0;
  Status status = socket.ReceiveSome(raw_header, kFrameHeaderBytes, received);
  if (!status.ok()) {
    return status;
  }
  if (received == 0) {
    return Status::Rejected(ReasonCode::WireSessionClosed, "the peer closed the session");
  }
  std::size_t filled = received;
  while (filled < kFrameHeaderBytes) {
    status = socket.ReceiveSome(raw_header + filled, kFrameHeaderBytes - filled, received);
    if (!status.ok()) {
      return status;
    }
    if (received == 0) {
      return Status::Rejected(ReasonCode::WireFrameTruncated, "the frame header is truncated");
    }
    filled += received;
  }
  status = DecodeFrameHeader(raw_header, kFrameHeaderBytes, config_.limits, header);
  if (!status.ok()) {
    return status;
  }
  payload.assign(header.payload_bytes, 0);
  if (!payload.empty()) {
    status = socket.ReceiveExact(payload.data(), payload.size());
    if (!status.ok()) {
      return status;
    }
  }
  return VerifyFramePayload(header, payload.data(), payload.size());
}

Status ObservationServer::SendFrame(Socket& socket, FrameType type, std::uint16_t flags,
                                    std::uint64_t sequence, const Value& payload) {
  std::vector<std::uint8_t> frame;
  const std::string text = WriteCanonicalJson(payload);
  Status status = EncodeFrame(type, flags, sequence, text, config_.limits, frame);
  if (!status.ok()) {
    return status;
  }
  status = socket.SendAll(frame.data(), frame.size());
  if (!status.ok()) {
    return status;
  }
  std::lock_guard<std::mutex> lock(stats_mutex_);
  ++stats_.frames_sent;
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status ObservationServer::SendError(Socket& socket, ReasonCode reason, const std::string& detail) {
  return SendFrame(socket, FrameType::ErrorFrame, 0, 0, EncodeError(reason, detail));
}

Status ObservationServer::HandleFrame(Socket& socket, FrameHeader header,
                                      const std::vector<std::uint8_t>& payload,
                                      SessionContext& context) {
  if (!context.handshaken && header.type != FrameType::Hello) {
    SendError(socket, ReasonCode::WireHandshakeRequired, "the session has not completed a handshake");
    return Status::Rejected(ReasonCode::WireHandshakeRequired, "handshake required");
  }
  switch (header.type) {
    case FrameType::Hello:
      return HandleHello(socket, payload, context);
    case FrameType::Snapshot:
      return HandleSnapshot(socket, payload, context);
    case FrameType::Intent:
      return HandleIntent(socket, payload, context);
    case FrameType::Heartbeat: {
      Value::Map map;
      map.emplace("schema", Value::MakeString("ndo/heartbeat/1"));
      map.emplace("session_id", Value::MakeUint(context.session_id));
      return SendFrame(socket, FrameType::Heartbeat, 0, header.sequence, Value::MakeMap(std::move(map)));
    }
    case FrameType::Bye:
      return Status::Rejected(ReasonCode::WireSessionClosed, "the peer closed the session");
    default:
      SendError(socket, ReasonCode::WireFrameTypeUnsupported, "the frame type is not accepted here");
      return Status::Rejected(ReasonCode::WireFrameTypeUnsupported, "unsupported frame type");
  }
}

Status ObservationServer::HandleHello(Socket& socket, const std::vector<std::uint8_t>& payload,
                                      SessionContext& context) {
  Value document;
  Status status = ParseJson(std::string_view(reinterpret_cast<const char*>(payload.data()),
                                             payload.size()),
                            config_.limits, document);
  if (!status.ok()) {
    SendError(socket, status.reason, status.detail);
    return status;
  }
  HelloPayload hello;
  status = DecodeHello(document, config_.limits, hello);
  if (!status.ok()) {
    SendError(socket, status.reason, status.detail);
    return status;
  }
  HelloAckPayload ack;
  ack.protocol_version = kWireProtocolVersion;
  ack.server_epoch = observatory_.epoch();
  ack.server_incarnation = observatory_.incarnation();
  ack.session_id = context.session_id;
  ack.max_payload_bytes = static_cast<std::uint32_t>(config_.limits.max_wire_payload_bytes);

  // Fence the source authority: a restarted process must never be able to
  // resume publishing under the incarnation of the process it replaced.
  {
    std::lock_guard<std::mutex> lock(fence_mutex_);
    const auto found = fences_.find(hello.source);
    if (found != fences_.end()) {
      if (hello.epoch < found->second.epoch) {
        ack.accepted = false;
        ack.reason = ReasonCode::FencedStaleEpoch;
        ack.detail = "the source epoch precedes the fenced epoch";
      } else if (hello.epoch == found->second.epoch &&
                 hello.incarnation < found->second.incarnation) {
        ack.accepted = false;
        ack.reason = ReasonCode::FencedStaleIncarnation;
        ack.detail = "the source incarnation precedes the fenced incarnation";
      }
    }
    if (ack.accepted || ack.reason == ReasonCode::None) {
      SourceFence& fence = fences_[hello.source];
      if (!fence.source.str().empty() && hello.incarnation < fence.incarnation) {
        ack.accepted = false;
        ack.reason = ReasonCode::FencedStaleIncarnation;
        ack.detail = "the source incarnation precedes the fenced incarnation";
      } else {
        // The greeting establishes which authority may publish. The sequence
        // high-water mark is established by the first accepted snapshot, not by
        // the greeting, so reconnecting never fences the publisher's own work.
        const bool new_incarnation =
            !fence.source.str().empty() && hello.incarnation > fence.incarnation;
        fence.source = hello.source;
        fence.epoch = hello.epoch;
        fence.incarnation = hello.incarnation;
        if (new_incarnation) {
          // A restarted process numbers its observations from the beginning, so
          // the sequence mark belongs to the incarnation that set it.
          fence.sequence = SourceSequence{};
          fence.content_digest = Digest{};
        }
        ack.accepted = true;
        ack.reason = ReasonCode::None;
      }
    } else {
      std::lock_guard<std::mutex> stats_lock(stats_mutex_);
      ++stats_.stale_fenced;
    }
  }

  if (ack.accepted) {
    SourceDescriptor descriptor;
    descriptor.id = hello.source;
    descriptor.capabilities = hello.capabilities;
    descriptor.registered_at = observatory_.now();
    descriptor.epoch = hello.epoch;
    descriptor.incarnation = hello.incarnation;
    descriptor.provenance = hello.provenance;
    descriptor.evidence = hello.capabilities.evidence;
    const Status registration = observatory_.RegisterSource(descriptor);
    if (!registration.ok()) {
      ack.accepted = false;
      ack.reason = registration.reason;
      ack.detail = registration.detail;
    }
  }

  status = SendFrame(socket, FrameType::HelloAck, 0, 0, EncodeHelloAck(ack));
  if (!status.ok()) {
    return status;
  }
  if (!ack.accepted) {
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    ++stats_.sessions_refused;
    return Status::Rejected(ReasonCode::WireHandshakeRejected, ack.detail);
  }
  context.source = hello.source;
  context.epoch = hello.epoch;
  context.incarnation = hello.incarnation;
  context.sequence = hello.start_sequence;
  context.handshaken = true;
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status ObservationServer::HandleSnapshot(Socket& socket, const std::vector<std::uint8_t>& payload,
                                         SessionContext& context) {
  Value document;
  Status status = ParseJson(std::string_view(reinterpret_cast<const char*>(payload.data()),
                                             payload.size()),
                            config_.limits, document);
  AckPayload ack;
  ack.reason = status.ok() ? ReasonCode::None : status.reason;
  if (!status.ok()) {
    ack.detail = status.detail;
    SendFrame(socket, FrameType::SnapshotAck, 0, 0, EncodeAck(ack));
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    ++stats_.snapshots_refused;
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  ObservationSnapshot snapshot;
  status = DecodeObservationDocument(document, config_.limits, snapshot);
  if (!status.ok()) {
    ack.reason = status.reason;
    ack.detail = status.detail;
    SendFrame(socket, FrameType::SnapshotAck, 0, 0, EncodeAck(ack));
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    ++stats_.snapshots_refused;
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  ack.sequence = snapshot.sequence;
  ack.snapshot = snapshot.snapshot_id;

  // A session may only publish for the source and incarnation it greeted with.
  // A frame that claims another authority is refused before it reaches the
  // observatory.
  if (!(snapshot.source == context.source)) {
    ack.reason = ReasonCode::AuthorityMismatch;
    ack.detail = "the snapshot source differs from the handshaken source";
    SendFrame(socket, FrameType::SnapshotAck, 0, 0, EncodeAck(ack));
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    ++stats_.snapshots_refused;
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  if (!(snapshot.incarnation == context.incarnation) || !(snapshot.epoch == context.epoch)) {
    ack.reason = ReasonCode::FencedStaleIncarnation;
    ack.detail = "the snapshot authority differs from the handshaken authority";
    SendFrame(socket, FrameType::SnapshotAck, 0, 0, EncodeAck(ack));
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    ++stats_.snapshots_refused;
    ++stats_.stale_fenced;
    return Status(StatusCode::Ok, ReasonCode::None);
  }

  ReasonCode fence_reason = ReasonCode::None;
  const Digest digest = snapshot.ComputeContentDigest();
  if (!FenceSnapshot(snapshot.source, snapshot.epoch, snapshot.incarnation, snapshot.sequence,
                     digest, fence_reason)) {
    ack.reason = fence_reason;
    ack.detail = "the snapshot was fenced by the transport authority";
    SendFrame(socket, FrameType::SnapshotAck, 0, 0, EncodeAck(ack));
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    ++stats_.snapshots_refused;
    ++stats_.stale_fenced;
    return Status(StatusCode::Ok, ReasonCode::None);
  }

  ObservationAdmission admission;
  const Status ingest = observatory_.IngestObservation(std::move(snapshot), admission);
  ack.accepted = ingest.ok();
  ack.reason = ingest.ok() ? ReasonCode::None : ingest.reason;
  ack.detail = ingest.detail;
  ack.snapshot = admission.snapshot;
  {
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    if (ingest.ok()) {
      ++stats_.snapshots_admitted;
    } else {
      ++stats_.snapshots_refused;
    }
  }
  return SendFrame(socket, FrameType::SnapshotAck, 0, 0, EncodeAck(ack));
}

Status ObservationServer::HandleIntent(Socket& socket, const std::vector<std::uint8_t>& payload,
                                       SessionContext& context) {
  Value document;
  Status status = ParseJson(std::string_view(reinterpret_cast<const char*>(payload.data()),
                                             payload.size()),
                            config_.limits, document);
  AckPayload ack;
  if (!status.ok()) {
    ack.reason = status.reason;
    ack.detail = status.detail;
    SendFrame(socket, FrameType::IntentAck, 0, 0, EncodeAck(ack));
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  IntentGenerationDocument intent;
  status = DecodeIntentDocument(document, config_.limits, intent);
  if (!status.ok()) {
    ack.reason = status.reason;
    ack.detail = status.detail;
    SendFrame(socket, FrameType::IntentAck, 0, 0, EncodeAck(ack));
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  ack.generation = intent.generation;
  IntentCommitReport report;
  const Status committed = observatory_.PublishIntent(intent, report);
  ack.accepted = committed.ok();
  ack.reason = committed.ok() ? ReasonCode::None : committed.reason;
  ack.detail = committed.detail;
  {
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    if (committed.ok()) {
      ++stats_.intents_admitted;
    }
  }
  static_cast<void>(context);
  return SendFrame(socket, FrameType::IntentAck, 0, 0, EncodeAck(ack));
}

bool ObservationServer::FenceSnapshot(const SourceId& source, FabricEpoch epoch,
                                      Incarnation incarnation, SourceSequence sequence,
                                      const Digest& digest, ReasonCode& reason) {
  std::lock_guard<std::mutex> lock(fence_mutex_);
  SourceFence& fence = fences_[source];
  if (fence.source.str().empty()) {
    fence.source = source;
    fence.epoch = epoch;
    fence.incarnation = incarnation;
    fence.sequence = sequence;
    fence.content_digest = digest;
    return true;
  }

  // Authority first: a frame from another epoch or incarnation may only be
  // accepted when it is strictly newer, and a stale authority must never be
  // able to move the high-water mark.
  if (!(epoch == fence.epoch) || !(incarnation == fence.incarnation)) {
    if (epoch < fence.epoch) {
      reason = ReasonCode::FencedStaleEpoch;
      return false;
    }
    if (epoch == fence.epoch && incarnation < fence.incarnation) {
      reason = ReasonCode::FencedStaleIncarnation;
      return false;
    }
    // A strictly newer authority takes over the mark.
    fence.epoch = epoch;
    fence.incarnation = incarnation;
    fence.sequence = sequence;
    fence.content_digest = digest;
    return true;
  }

  // Same authority: the sequence only moves forward, and a repeat must be the
  // same observation.
  if (!fence.sequence.is_set() && !fence.content_digest.is_set()) {
    fence.sequence = sequence;
    fence.content_digest = digest;
    return true;
  }
  if (sequence < fence.sequence) {
    reason = ReasonCode::FencedStaleSequence;
    return false;
  }
  if (sequence == fence.sequence && !(digest == fence.content_digest)) {
    reason = ReasonCode::ObservationDuplicateConflicting;
    return false;
  }
  if (sequence > fence.sequence) {
    fence.sequence = sequence;
    fence.content_digest = digest;
  }
  return true;
}

Status ObservationServer::ServeSingleSession() {
  if (!listener_.valid()) {
    Status status = InitializeNetworking();
    if (!status.ok()) {
      return status;
    }
    auto listener = Listener::Bind(config_.bind_address, config_.port, config_.backlog);
    if (!listener.ok()) {
      return listener.status();
    }
    listener_ = std::move(listener.value());
    bound_port_ = listener_.local_port();
  }
  Socket socket;
  Status status = listener_.Accept(socket);
  if (!status.ok()) {
    return status;
  }
  {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ++stats_.sessions_accepted;
  }
  SessionLoop(socket, next_session_id_.fetch_add(1));
  socket.Close();
  {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ++stats_.sessions_closed;
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

}  // namespace network_drift_observatory
}  // namespace summon
