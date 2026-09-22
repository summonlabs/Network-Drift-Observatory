// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/net.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
// The framed transport is implemented for Windows in this release. On other
// platforms the runtime still builds and every transport call reports that the
// socket backend is unavailable, rather than pretending to connect.
#endif

namespace summon {
namespace network_drift_observatory {
namespace {

std::atomic<int> g_initialize_count{0};
#if defined(_WIN32)
std::mutex g_initialize_mutex;
#endif

}  // namespace

Status InitializeNetworking() {
#if defined(_WIN32)
  std::lock_guard<std::mutex> lock(g_initialize_mutex);
  if (g_initialize_count.load() == 0) {
    WSADATA data;
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
      return Status::Rejected(ReasonCode::WireSessionClosed,
                              "the platform networking subsystem could not be initialized");
    }
  }
  g_initialize_count.fetch_add(1);
  return Status(StatusCode::Ok, ReasonCode::None);
#else
  g_initialize_count.fetch_add(1);
  return Status::Unsupported(ReasonCode::WireSessionClosed,
                             "the socket transport is implemented for Windows in this release");
#endif
}

void ShutdownNetworking() {
#if defined(_WIN32)
  std::lock_guard<std::mutex> lock(g_initialize_mutex);
  if (g_initialize_count.load() > 0) {
    g_initialize_count.fetch_sub(1);
    if (g_initialize_count.load() == 0) {
      WSACleanup();
    }
  }
#else
  if (g_initialize_count.load() > 0) {
    g_initialize_count.fetch_sub(1);
  }
#endif
}

std::string LastSocketError() {
#if defined(_WIN32)
  const int code = WSAGetLastError();
  switch (code) {
    case WSAECONNRESET:
      return "connection reset by peer";
    case WSAECONNABORTED:
      return "connection aborted";
    case WSAETIMEDOUT:
      return "connection timed out";
    case WSAEWOULDBLOCK:
      return "operation would block";
    case WSAENOTCONN:
      return "socket is not connected";
    case WSAESHUTDOWN:
      return "socket has been shut down";
    case WSAEADDRINUSE:
      return "address already in use";
    case WSAEACCES:
      return "address access denied";
    case WSAHOST_NOT_FOUND:
      return "host not found";
    default:
      break;
  }
  return "socket error " + std::to_string(code);
#else
  return "the socket transport is unavailable on this platform";
#endif
}

Socket::~Socket() {
  Close();
}

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) {
  other.handle_ = -1;
}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    Close();
    handle_ = other.handle_;
    other.handle_ = -1;
  }
  return *this;
}

Result<Socket> Socket::Connect(const std::string& host, std::uint16_t port) {
#if defined(_WIN32)
  Status status = InitializeNetworking();
  if (!status.ok()) {
    return status;
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_NUMERICSERV;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  const std::string node = host.empty() ? std::string("127.0.0.1") : host;
  if (getaddrinfo(node.c_str(), service.c_str(), &hints, &results) != 0) {
    return Status::Rejected(ReasonCode::WireSessionClosed,
                            "the endpoint could not be resolved: " + node);
  }
  Socket socket;
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const SOCKET handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == INVALID_SOCKET) {
      continue;
    }
    if (::connect(handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) == 0) {
      socket.Close();
      socket.handle_ = static_cast<std::intptr_t>(handle);
      break;
    }
    closesocket(handle);
  }
  freeaddrinfo(results);
  if (!socket.valid()) {
    return Status::Rejected(ReasonCode::WireSessionClosed,
                            std::string("the connection could not be established: ") +
                                LastSocketError());
  }
  return socket;
#else
  static_cast<void>(host);
  static_cast<void>(port);
  return Status::Unsupported(ReasonCode::WireSessionClosed,
                             "the socket transport is implemented for Windows in this release");
#endif
}

void Socket::Close() {
#if defined(_WIN32)
  if (handle_ >= 0) {
    closesocket(static_cast<SOCKET>(handle_));
  }
#endif
  handle_ = -1;
}

void Socket::ShutdownSend() {
#if defined(_WIN32)
  if (handle_ >= 0) {
    ::shutdown(static_cast<SOCKET>(handle_), SD_SEND);
  }
#endif
}

void Socket::ShutdownBoth() {
#if defined(_WIN32)
  if (handle_ >= 0) {
    ::shutdown(static_cast<SOCKET>(handle_), SD_BOTH);
  }
#endif
}

Status Socket::SendAll(const std::uint8_t* data, std::size_t size) {
#if defined(_WIN32)
  if (handle_ < 0) {
    return Status::Rejected(ReasonCode::WireSessionClosed, "the socket is not open");
  }
  std::size_t sent = 0;
  while (sent < size) {
    const std::size_t remaining = size - sent;
    const int chunk = remaining > 0x7FFFFFFFu ? 0x7FFFFFFF : static_cast<int>(remaining);
    const int result = ::send(static_cast<SOCKET>(handle_),
                              reinterpret_cast<const char*>(data + sent), chunk, 0);
    if (result <= 0) {
      return Status::Rejected(ReasonCode::WireSessionClosed,
                              std::string("send failed: ") + LastSocketError());
    }
    sent += static_cast<std::size_t>(result);
  }
  return Status(StatusCode::Ok, ReasonCode::None);
#else
  static_cast<void>(data);
  static_cast<void>(size);
  return Status::Unsupported(ReasonCode::WireSessionClosed, "the socket transport is unavailable");
#endif
}

Status Socket::ReceiveSome(std::uint8_t* data, std::size_t size, std::size_t& received) {
  received = 0;
#if defined(_WIN32)
  if (handle_ < 0) {
    return Status::Rejected(ReasonCode::WireSessionClosed, "the socket is not open");
  }
  const int chunk = size > 0x7FFFFFFFu ? 0x7FFFFFFF : static_cast<int>(size);
  const int result =
      ::recv(static_cast<SOCKET>(handle_), reinterpret_cast<char*>(data), chunk, 0);
  if (result == 0) {
    // An orderly close: the caller sees a zero-length read, not an error.
    return Status(StatusCode::Ok, ReasonCode::WireSessionClosed);
  }
  if (result < 0) {
    // A deadline is a resource bound, not a protocol error: the caller must be
    // able to tell them apart so it can report the right reason to the peer.
    if (WSAGetLastError() == WSAETIMEDOUT) {
      return Status::Rejected(ReasonCode::WireSessionIdleExpired,
                              "the session idle deadline expired");
    }
    return Status::Rejected(ReasonCode::WireSessionClosed,
                            std::string("receive failed: ") + LastSocketError());
  }
  received = static_cast<std::size_t>(result);
  return Status(StatusCode::Ok, ReasonCode::None);
#else
  static_cast<void>(data);
  static_cast<void>(size);
  return Status::Unsupported(ReasonCode::WireSessionClosed, "the socket transport is unavailable");
#endif
}

Status Socket::ReceiveExact(std::uint8_t* data, std::size_t size) {
  std::size_t received_total = 0;
  while (received_total < size) {
    std::size_t received = 0;
    Status status = ReceiveSome(data + received_total, size - received_total, received);
    if (!status.ok()) {
      return status;
    }
    if (received == 0) {
      return Status::Rejected(ReasonCode::WireFrameTruncated,
                              "the peer closed before the frame was complete");
    }
    received_total += received;
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status Socket::SetReceiveTimeoutMillis(std::uint32_t millis) {
#if defined(_WIN32)
  if (handle_ < 0) {
    return Status::Rejected(ReasonCode::WireSessionClosed, "the socket is not open");
  }
  const DWORD timeout = static_cast<DWORD>(millis);
  if (::setsockopt(static_cast<SOCKET>(handle_), SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0) {
    return Status::Rejected(ReasonCode::WireSessionClosed, LastSocketError());
  }
  return Status(StatusCode::Ok, ReasonCode::None);
#else
  static_cast<void>(millis);
  return Status::Unsupported(ReasonCode::WireSessionClosed, "the socket transport is unavailable");
#endif
}

Status Socket::SetSendTimeoutMillis(std::uint32_t millis) {
#if defined(_WIN32)
  if (handle_ < 0) {
    return Status::Rejected(ReasonCode::WireSessionClosed, "the socket is not open");
  }
  const DWORD timeout = static_cast<DWORD>(millis);
  if (::setsockopt(static_cast<SOCKET>(handle_), SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0) {
    return Status::Rejected(ReasonCode::WireSessionClosed, LastSocketError());
  }
  return Status(StatusCode::Ok, ReasonCode::None);
#else
  static_cast<void>(millis);
  return Status::Unsupported(ReasonCode::WireSessionClosed, "the socket transport is unavailable");
#endif
}

Status Socket::SetNoDelay(bool enabled) {
#if defined(_WIN32)
  if (handle_ < 0) {
    return Status::Rejected(ReasonCode::WireSessionClosed, "the socket is not open");
  }
  const BOOL value = enabled ? TRUE : FALSE;
  if (::setsockopt(static_cast<SOCKET>(handle_), IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
    return Status::Rejected(ReasonCode::WireSessionClosed, LastSocketError());
  }
  return Status(StatusCode::Ok, ReasonCode::None);
#else
  static_cast<void>(enabled);
  return Status::Unsupported(ReasonCode::WireSessionClosed, "the socket transport is unavailable");
#endif
}

std::uint16_t Socket::local_port() const {
#if defined(_WIN32)
  if (handle_ < 0) {
    return 0;
  }
  sockaddr_storage address{};
  int length = static_cast<int>(sizeof(address));
  if (getsockname(static_cast<SOCKET>(handle_), reinterpret_cast<sockaddr*>(&address), &length) !=
      0) {
    return 0;
  }
  if (address.ss_family == AF_INET) {
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
    return ntohs(ipv4->sin_port);
  }
  if (address.ss_family == AF_INET6) {
    const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(&address);
    return ntohs(ipv6->sin6_port);
  }
#endif
  return 0;
}

Listener::~Listener() {
  Close();
}

Listener::Listener(Listener&& other) noexcept : handle_(other.handle_) {
  other.handle_ = -1;
}

Listener& Listener::operator=(Listener&& other) noexcept {
  if (this != &other) {
    Close();
    handle_ = other.handle_;
    other.handle_ = -1;
  }
  return *this;
}

void Listener::Close() {
#if defined(_WIN32)
  if (handle_ >= 0) {
    closesocket(static_cast<SOCKET>(handle_));
  }
#endif
  handle_ = -1;
}

Result<Listener> Listener::Bind(const std::string& address, std::uint16_t port, int backlog) {
#if defined(_WIN32)
  Status status = InitializeNetworking();
  if (!status.ok()) {
    return status;
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_NUMERICSERV;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  if (getaddrinfo(address.empty() ? nullptr : address.c_str(), service.c_str(), &hints, &results) !=
      0) {
    return Status::Rejected(ReasonCode::WireSessionClosed,
                            "the bind address could not be resolved: " + address);
  }
  Listener listener;
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const SOCKET socket_handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (socket_handle == INVALID_SOCKET) {
      continue;
    }
    const BOOL reuse = TRUE;
    ::setsockopt(socket_handle, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    if (::bind(socket_handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) != 0) {
      closesocket(socket_handle);
      continue;
    }
    if (::listen(socket_handle, backlog) != 0) {
      closesocket(socket_handle);
      continue;
    }
    listener.handle_ = static_cast<std::intptr_t>(socket_handle);
    break;
  }
  freeaddrinfo(results);
  if (!listener.valid()) {
    return Status::Rejected(ReasonCode::WireSessionClosed,
                            std::string("the listener could not be bound: ") + LastSocketError());
  }
  return listener;
#else
  static_cast<void>(address);
  static_cast<void>(port);
  static_cast<void>(backlog);
  return Status::Unsupported(ReasonCode::WireSessionClosed,
                             "the socket transport is implemented for Windows in this release");
#endif
}

Status Listener::Accept(Socket& out) {
#if defined(_WIN32)
  if (handle_ < 0) {
    return Status::Rejected(ReasonCode::WireSessionClosed, "the listener is closed");
  }
  const SOCKET accepted = ::accept(static_cast<SOCKET>(handle_), nullptr, nullptr);
  if (accepted == INVALID_SOCKET) {
    return Status::Rejected(ReasonCode::WireSessionClosed,
                            std::string("accept failed: ") + LastSocketError());
  }
  out = Socket(static_cast<std::intptr_t>(accepted));
  return Status(StatusCode::Ok, ReasonCode::None);
#else
  static_cast<void>(out);
  return Status::Unsupported(ReasonCode::WireSessionClosed, "the socket transport is unavailable");
#endif
}

std::uint16_t Listener::local_port() const {
#if defined(_WIN32)
  if (handle_ < 0) {
    return 0;
  }
  sockaddr_storage address{};
  int length = static_cast<int>(sizeof(address));
  if (getsockname(static_cast<SOCKET>(handle_), reinterpret_cast<sockaddr*>(&address), &length) !=
      0) {
    return 0;
  }
  if (address.ss_family == AF_INET) {
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
    return ntohs(ipv4->sin_port);
  }
  if (address.ss_family == AF_INET6) {
    const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(&address);
    return ntohs(ipv6->sin6_port);
  }
#endif
  return 0;
}

}  // namespace network_drift_observatory
}  // namespace summon
