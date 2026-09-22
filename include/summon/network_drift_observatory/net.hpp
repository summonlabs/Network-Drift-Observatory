// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Platform sockets.
//
// The only place in the runtime that talks to the operating system's socket
// API. Everything above it works on spans of bytes, so the transport can be
// exercised by an independent process over a real TCP connection.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_NET_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_NET_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"

namespace summon {
namespace network_drift_observatory {

/// Initializes the platform networking subsystem. Idempotent.
NDO_API Status InitializeNetworking();
/// Releases the platform networking subsystem. Idempotent.
NDO_API void ShutdownNetworking();

/// Human-readable description of the last socket error on this thread.
NDO_NODISCARD NDO_API std::string LastSocketError();

/// Connection-oriented socket with an explicit lifetime.
class NDO_API Socket {
 public:
  Socket() = default;
  explicit Socket(std::intptr_t handle) : handle_(handle) {}
  ~Socket();
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  NDO_NODISCARD bool valid() const noexcept { return handle_ >= 0; }
  NDO_NODISCARD std::intptr_t handle() const noexcept { return handle_; }

  /// Connects to a numeric address or host name. Returns a failure status when
  /// no candidate address accepted the connection.
  NDO_NODISCARD static Result<Socket> Connect(const std::string& host, std::uint16_t port);

  /// Sends the whole buffer. Returns a failure status on a short or refused
  /// write; never reports success for a partial send.
  Status SendAll(const std::uint8_t* data, std::size_t size);
  /// Receives up to size bytes. Sets received to 0 on an orderly peer close.
  Status ReceiveSome(std::uint8_t* data, std::size_t size, std::size_t& received);
  /// Receives exactly size bytes or fails.
  Status ReceiveExact(std::uint8_t* data, std::size_t size);
  /// Half-closes the send direction so a peer blocked in read returns.
  void ShutdownSend();
  /// Shuts down both directions. Safe to call from another thread to unblock a
  /// reader: this is how the server cancels an idle or stopping session.
  void ShutdownBoth();
  void Close();
  /// Sets a receive deadline in milliseconds. Zero disables the deadline.
  Status SetReceiveTimeoutMillis(std::uint32_t millis);
  Status SetSendTimeoutMillis(std::uint32_t millis);
  Status SetNoDelay(bool enabled);
  NDO_NODISCARD std::uint16_t local_port() const;

 private:
  std::intptr_t handle_{-1};
};

/// Listening socket bound to one address.
class NDO_API Listener {
 public:
  Listener() = default;
  ~Listener();
  Listener(Listener&& other) noexcept;
  Listener& operator=(Listener&& other) noexcept;
  Listener(const Listener&) = delete;
  Listener& operator=(const Listener&) = delete;

  /// Binds and listens on the given address. Port 0 asks the platform for an
  /// ephemeral port, which LocalPort() then reports.
  NDO_NODISCARD static Result<Listener> Bind(const std::string& address, std::uint16_t port,
                                             int backlog);
  /// Accepts one connection. Returns a failure status when the listener is
  /// closed underneath the caller, which is how shutdown unblocks accept.
  NDO_NODISCARD Status Accept(Socket& out);
  NDO_NODISCARD bool valid() const noexcept { return handle_ >= 0; }
  NDO_NODISCARD std::uint16_t local_port() const;
  /// Closes the listener and unblocks any thread blocked in Accept.
  void Close();

 private:
  std::intptr_t handle_{-1};
};

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_NET_HPP
