// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Versioned, integrity-checked durable state.
//
// A persisted ledger is a length-delimited record with a fixed header, a
// schema version, a content digest and a trailer. A reader verifies the digest
// before it trusts a single byte, refuses a schema it does not understand, and
// recovers conservatively: evidence that survives a restart is marked as not
// fresh, findings keep their history but lose any claim to be current.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_PERSISTENCE_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_PERSISTENCE_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "summon/network_drift_observatory/identity.hpp"
#include "summon/network_drift_observatory/ledger.hpp"
#include "summon/network_drift_observatory/limits.hpp"
#include "summon/network_drift_observatory/platform.hpp"
#include "summon/network_drift_observatory/status.hpp"

namespace summon {
namespace network_drift_observatory {

/// Magic bytes at the start of every persisted ledger ("NDOLEDG1").
inline constexpr char kLedgerMagic[8] = {'N', 'D', 'O', 'L', 'E', 'D', 'G', '1'};
/// Fixed header size before the payload: magic(8) + format(2) + flags(2) +
/// payload_bytes(8) + digest(32) + write_epoch(8) + write_incarnation(8).
inline constexpr std::size_t kLedgerHeaderBytes = 8 + 2 + 2 + 8 + 32 + 8 + 8;

/// Encodes the ledger into a versioned, integrity-checked byte string.
NDO_NODISCARD NDO_API Status EncodeLedger(const FindingLedger& ledger, FabricEpoch write_epoch,
                                          Incarnation write_incarnation,
                                          std::vector<std::uint8_t>& out);

/// Decodes a ledger. On any integrity failure the output ledger is left
/// untouched: recovery is all-or-nothing.
NDO_NODISCARD NDO_API Status DecodeLedger(const std::uint8_t* bytes, std::size_t size,
                                          const RuntimeLimits& limits, FabricEpoch live_epoch,
                                          FindingLedger& out, LedgerRecoveryReport& report);

/// Writes the encoded ledger to a file, replacing it atomically through a
/// temporary file in the same directory.
NDO_NODISCARD NDO_API Status SaveLedgerFile(const FindingLedger& ledger, const std::string& path,
                                            FabricEpoch write_epoch, Incarnation write_incarnation,
                                            std::size_t max_bytes);

/// Reads and decodes a ledger file.
NDO_NODISCARD NDO_API Status LoadLedgerFile(const std::string& path, const RuntimeLimits& limits,
                                            FabricEpoch live_epoch, FindingLedger& out,
                                            LedgerRecoveryReport& report);

/// The digest that the encoder writes into the header for a given payload.
NDO_NODISCARD NDO_API Digest LedgerPayloadDigest(const std::uint8_t* payload, std::size_t size);

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_PERSISTENCE_HPP
