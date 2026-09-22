// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Deterministic hashing.
//
// Finding identity, evidence integrity and ledger integrity are all derived
// from SHA-256 over a canonical byte encoding. Two runs that see the same
// inputs compute the same digest on every platform, and a frame checksum that
// does not match is refused rather than repaired.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_HASH_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_HASH_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/platform.hpp"

namespace summon {
namespace network_drift_observatory {

/// Incremental SHA-256.
class NDO_API Sha256 {
 public:
  Sha256() noexcept;
  Sha256(const Sha256&) = delete;
  Sha256& operator=(const Sha256&) = delete;

  void Update(const void* data, std::size_t bytes) noexcept;
  void Update(std::string_view text) noexcept;
  void UpdateByte(std::uint8_t value) noexcept;
  void UpdateU64(std::uint64_t value) noexcept;
  /// Length-prefixed update: makes concatenation unambiguous.
  void UpdateLengthPrefixed(std::string_view text) noexcept;
  void UpdateTag(std::string_view tag) noexcept;

  /// Finalizes and returns the digest. Further updates are refused (no-op).
  NDO_NODISCARD Digest Final();

 private:
  void Compress(const std::uint8_t* block) noexcept;

  std::uint32_t state_[8];
  std::uint8_t buffer_[64];
  std::size_t buffered_;
  std::uint64_t total_bytes_;
  bool finalized_;
};

/// One-shot digest over a byte range.
NDO_NODISCARD NDO_API Digest HashBytes(const void* data, std::size_t bytes);
NDO_NODISCARD NDO_API Digest HashText(std::string_view text);

/// Deterministic CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320).
/// Used for wire frame checksums only; never for identity.
NDO_NODISCARD NDO_API std::uint32_t Crc32(const void* data, std::size_t bytes) noexcept;

/// Hex encoding helpers used by every text format in the runtime.
NDO_NODISCARD NDO_API std::string ToHex(const void* data, std::size_t bytes);
NDO_NODISCARD NDO_API bool FromHex(std::string_view hex, std::vector<std::uint8_t>& out);

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_HASH_HPP
