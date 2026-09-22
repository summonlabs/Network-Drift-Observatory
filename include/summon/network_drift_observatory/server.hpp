// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Observation ingestion server.
//
// The server accepts framed observation sessions on a real TCP socket, fences
// stale epochs, incarnations and sequence numbers per source, and hands every
// accepted snapshot to the observatory. It never blocks the observatory: the
// accept loop and each session run on their own bounded thread.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_SERVER_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_SERVER_HPP

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "summon/network_drift_observatory/engine.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/net.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"
#include "summon/network_drift_observatory/wire.hpp"

namespace summon {
namespace network_drift_observatory {

struct NDO_API ServerConfig {
  std::string bind_address{"127.0.0.1"};
  std::uint16_t port{0};
  int backlog{16};
  RuntimeLimits limits;
  /// Idle deadline applied to every session socket. A silent session is closed
  /// with reason WireSessionIdleExpired rather than held forever.
  std::uint32_t session_idle_timeout_millis{60000};
};

struct NDO_API ServerStats {
  std::uint64_t sessions_accepted{0};
  std::uint64_t sessions_refused{0};
  std::uint64_t sessions_closed{0};
  std::uint64_t frames_received{0};
  std::uint64_t frames_sent{0};
  std::uint64_t frames_refused{0};
  std::uint64_t snapshots_admitted{0};
  std::uint64_t snapshots_refused{0};
  std::uint64_t intents_admitted{0};
  std::uint64_t stale_fenced{0};
  std::uint64_t idle_expired{0};
  std::uint64_t active_sessions{0};
  std::uint64_t high_water_sessions{0};
};

/// Per-source fencing high-water mark. A snapshot at or below the mark with a
/// different content digest is a replay or a conflict and is refused.
struct NDO_API SourceFence {
  SourceId source;
  FabricEpoch epoch;
  Incarnation incarnation;
  SourceSequence sequence;
  Digest content_digest;
};

class NDO_API ObservationServer {
 public:
  ObservationServer(Observatory& observatory, ServerConfig config);
  ~ObservationServer();
  ObservationServer(const ObservationServer&) = delete;
  ObservationServer& operator=(const ObservationServer&) = delete;

  /// Binds, listens and starts the accept loop. Returns a failure status if the
  /// address is unusable; the server is then not running.
  Status Start();
  /// Stops admission, closes the listener, shuts down every session socket and
  /// joins every thread. Idempotent. Accounting returns to zero active
  /// sessions before this call returns.
  Status Stop();
  NDO_NODISCARD bool running() const noexcept;
  NDO_NODISCARD std::uint16_t port() const noexcept { return bound_port_; }
  /// Returns the live counters. Finished sessions are reaped first, so the
  /// reported active-session count reflects the present rather than the last
  /// connection that happened to arrive.
  NDO_NODISCARD ServerStats Stats();

  /// Serves exactly one session on the calling thread. Used by tooling and by
  /// tests that need deterministic single-threaded session handling.
  Status ServeSingleSession();

  /// The fencing high-water mark for one source, if any.
  NDO_NODISCARD std::optional<SourceFence> FenceFor(const SourceId& source) const;

 private:
  struct SessionContext {
    SourceId source;
    FabricEpoch epoch;
    Incarnation incarnation;
    SourceSequence sequence;
    std::uint64_t session_id{0};
    bool handshaken{false};
    std::size_t in_flight{0};
  };

  void AcceptLoop();
  void SessionLoop(Socket& socket, std::uint64_t session_id);
  Status HandleFrame(Socket& socket, FrameHeader header, const std::vector<std::uint8_t>& payload,
                     SessionContext& context);
  Status HandleHello(Socket& socket, const std::vector<std::uint8_t>& payload,
                     SessionContext& context);
  Status HandleSnapshot(Socket& socket, const std::vector<std::uint8_t>& payload,
                        SessionContext& context);
  Status HandleIntent(Socket& socket, const std::vector<std::uint8_t>& payload,
                      SessionContext& context);
  Status SendFrame(Socket& socket, FrameType type, std::uint16_t flags, std::uint64_t sequence,
                   const Value& payload);
  Status SendError(Socket& socket, ReasonCode reason, const std::string& detail);
  Status ReadFrame(Socket& socket, FrameHeader& header, std::vector<std::uint8_t>& payload);
  bool FenceSnapshot(const SourceId& source, FabricEpoch epoch, Incarnation incarnation,
                     SourceSequence sequence, const Digest& digest, ReasonCode& reason);

  /// One accepted session: the socket, its completion flag and its thread.
  /// A session slot is removed by whichever thread observes its completion, so
  /// the slot table is bounded by the session envelope rather than by uptime.
  struct SessionSlot {
    std::shared_ptr<Socket> socket;
    std::shared_ptr<std::atomic<bool>> done;
    std::thread thread;
    bool joined{false};
  };

  void ReapFinishedSessions();
  void CloseAllSessions();

  Observatory& observatory_;
  ServerConfig config_;
  Listener listener_;
  std::atomic<bool> running_{false};
  std::atomic<bool> stop_requested_{false};
  std::thread accept_thread_;
  mutable std::mutex sessions_mutex_;
  std::condition_variable sessions_cv_;
  std::map<std::uint64_t, SessionSlot> sessions_;
  mutable std::mutex fence_mutex_;
  std::map<SourceId, SourceFence> fences_;
  std::atomic<std::uint64_t> next_session_id_{1};
  mutable std::mutex stats_mutex_;
  ServerStats stats_;
  std::uint16_t bound_port_{0};
};

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_SERVER_HPP
