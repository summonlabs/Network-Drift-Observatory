// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/hash.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace summon {
namespace network_drift_observatory {
namespace {

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

constexpr std::uint32_t RotateRight(std::uint32_t value, std::uint32_t bits) noexcept {
  return (value >> bits) | (value << (32u - bits));
}

// A compile-time CRC-32 table: no lazy initialization and therefore no data
// race when two sessions compute checksums concurrently.
struct Crc32Table {
  std::array<std::uint32_t, 256> values{};
  constexpr Crc32Table() noexcept {
    for (std::uint32_t index = 0; index < 256; ++index) {
      std::uint32_t value = index;
      for (int bit = 0; bit < 8; ++bit) {
        value = (value & 1u) != 0u ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
      }
      values[index] = value;
    }
  }
};

constexpr Crc32Table kCrc32Table{};

}  // namespace

Sha256::Sha256() noexcept
    : state_{0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu,
             0x1f83d9abu, 0x5be0cd19u},
      buffer_{},
      buffered_(0),
      total_bytes_(0),
      finalized_(false) {}

void Sha256::Compress(const std::uint8_t* block) noexcept {
  std::uint32_t w[64];
  for (std::size_t index = 0; index < 16; ++index) {
    w[index] = (static_cast<std::uint32_t>(block[index * 4]) << 24) |
               (static_cast<std::uint32_t>(block[index * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[index * 4 + 2]) << 8) |
               static_cast<std::uint32_t>(block[index * 4 + 3]);
  }
  for (std::size_t index = 16; index < 64; ++index) {
    const std::uint32_t s0 = RotateRight(w[index - 15], 7) ^ RotateRight(w[index - 15], 18) ^
                             (w[index - 15] >> 3);
    const std::uint32_t s1 = RotateRight(w[index - 2], 17) ^ RotateRight(w[index - 2], 19) ^
                             (w[index - 2] >> 10);
    w[index] = w[index - 16] + s0 + w[index - 7] + s1;
  }
  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];
  for (std::size_t index = 0; index < 64; ++index) {
    const std::uint32_t s1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[index] + w[index];
    const std::uint32_t s0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }
  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::Update(const void* data, std::size_t bytes) noexcept {
  if (finalized_ || data == nullptr || bytes == 0) {
    return;
  }
  const auto* cursor = static_cast<const std::uint8_t*>(data);
  std::size_t remaining = bytes;
  total_bytes_ += static_cast<std::uint64_t>(bytes);
  if (buffered_ > 0) {
    const std::size_t needed = 64 - buffered_;
    const std::size_t take = remaining < needed ? remaining : needed;
    std::memcpy(buffer_ + buffered_, cursor, take);
    buffered_ += take;
    cursor += take;
    remaining -= take;
    if (buffered_ == 64) {
      Compress(buffer_);
      buffered_ = 0;
    }
  }
  while (remaining >= 64) {
    Compress(cursor);
    cursor += 64;
    remaining -= 64;
  }
  if (remaining > 0) {
    std::memcpy(buffer_, cursor, remaining);
    buffered_ = remaining;
  }
}

void Sha256::Update(std::string_view text) noexcept {
  Update(text.data(), text.size());
}

void Sha256::UpdateByte(std::uint8_t value) noexcept {
  Update(&value, 1);
}

void Sha256::UpdateU64(std::uint64_t value) noexcept {
  std::uint8_t raw[8];
  for (std::size_t index = 0; index < 8; ++index) {
    raw[index] = static_cast<std::uint8_t>((value >> ((7 - index) * 8)) & 0xFFu);
  }
  Update(raw, sizeof(raw));
}

void Sha256::UpdateLengthPrefixed(std::string_view text) noexcept {
  UpdateU64(static_cast<std::uint64_t>(text.size()));
  Update(text.data(), text.size());
}

void Sha256::UpdateTag(std::string_view tag) noexcept {
  UpdateLengthPrefixed(tag);
}

Digest Sha256::Final() {
  Digest digest;
  if (finalized_) {
    return digest;
  }
  const std::uint64_t total_bits = total_bytes_ * 8ULL;
  const std::uint8_t padding = 0x80u;
  Update(&padding, 1);
  const std::uint8_t zero = 0x00u;
  while (buffered_ != 56) {
    Update(&zero, 1);
  }
  std::uint8_t length_bytes[8];
  for (std::size_t index = 0; index < 8; ++index) {
    length_bytes[index] = static_cast<std::uint8_t>((total_bits >> ((7 - index) * 8)) & 0xFFu);
  }
  Update(length_bytes, sizeof(length_bytes));
  for (std::size_t index = 0; index < 8; ++index) {
    digest.bytes[index * 4] = static_cast<std::uint8_t>((state_[index] >> 24) & 0xFFu);
    digest.bytes[index * 4 + 1] = static_cast<std::uint8_t>((state_[index] >> 16) & 0xFFu);
    digest.bytes[index * 4 + 2] = static_cast<std::uint8_t>((state_[index] >> 8) & 0xFFu);
    digest.bytes[index * 4 + 3] = static_cast<std::uint8_t>(state_[index] & 0xFFu);
  }
  finalized_ = true;
  return digest;
}

Digest HashBytes(const void* data, std::size_t bytes) {
  Sha256 hasher;
  hasher.Update(data, bytes);
  return hasher.Final();
}

Digest HashText(std::string_view text) {
  return HashBytes(text.data(), text.size());
}

std::uint32_t Crc32(const void* data, std::size_t bytes) noexcept {
  const auto* cursor = static_cast<const std::uint8_t*>(data);
  std::uint32_t crc = 0xFFFFFFFFu;
  for (std::size_t index = 0; index < bytes; ++index) {
    crc = kCrc32Table.values[(crc ^ cursor[index]) & 0xFFu] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFu;
}

std::string ToHex(const void* data, std::size_t bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  const auto* cursor = static_cast<const std::uint8_t*>(data);
  std::string out;
  out.resize(bytes * 2);
  for (std::size_t index = 0; index < bytes; ++index) {
    out[2 * index] = kDigits[cursor[index] >> 4];
    out[2 * index + 1] = kDigits[cursor[index] & 0x0F];
  }
  return out;
}

bool FromHex(std::string_view hex, std::vector<std::uint8_t>& out) {
  if (hex.size() % 2 != 0) {
    return false;
  }
  out.clear();
  out.reserve(hex.size() / 2);
  for (std::size_t index = 0; index < hex.size(); index += 2) {
    int high = -1;
    int low = -1;
    const char h = hex[index];
    const char l = hex[index + 1];
    if (h >= '0' && h <= '9') {
      high = h - '0';
    } else if (h >= 'a' && h <= 'f') {
      high = h - 'a' + 10;
    } else if (h >= 'A' && h <= 'F') {
      high = h - 'A' + 10;
    }
    if (l >= '0' && l <= '9') {
      low = l - '0';
    } else if (l >= 'a' && l <= 'f') {
      low = l - 'a' + 10;
    } else if (l >= 'A' && l <= 'F') {
      low = l - 'A' + 10;
    }
    if (high < 0 || low < 0) {
      out.clear();
      return false;
    }
    out.push_back(static_cast<std::uint8_t>((high << 4) | low));
  }
  return true;
}

}  // namespace network_drift_observatory
}  // namespace summon
