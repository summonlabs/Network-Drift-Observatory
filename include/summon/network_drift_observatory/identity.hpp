// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Strongly typed identities, generations, epochs, incarnations and digests.
//
// Nothing in this runtime is allowed to compare two differently tagged
// quantities, and matching identity text is never treated as matching
// generation. A generation, epoch or incarnation value of zero means "unset"
// and is rejected at every boundary that requires authority.

#ifndef SUMMON_NETWORK_DRIFT_OBSERVATORY_IDENTITY_HPP
#define SUMMON_NETWORK_DRIFT_OBSERVATORY_IDENTITY_HPP

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "summon/network_drift_observatory/platform.hpp"

namespace summon {
namespace network_drift_observatory {

/// Maximum accepted length of a textual identity.
inline constexpr std::size_t kMaxIdentityLength = 200;
/// Byte length of a SHA-256 digest.
inline constexpr std::size_t kDigestBytes = 32;
/// Hex character length of a SHA-256 digest.
inline constexpr std::size_t kDigestHexLength = 2 * kDigestBytes;

/// Validates textual identity content.
///
/// Accepted: ASCII letters, digits and the separators '.', '_', '-', '/', ':',
/// '@', '#'. Rejected: empty text, text longer than kMaxIdentityLength, control
/// bytes, backslash, embedded NUL, a leading '/', a leading or trailing
/// separator, and any path-traversal component ("." or "..").
NDO_NODISCARD NDO_API bool IsValidIdentityText(std::string_view text) noexcept;

/// Tagged, validated, ordered textual identity.
template <typename Tag>
class StringId {
 public:
  StringId() = default;

  NDO_NODISCARD static std::optional<StringId> TryParse(std::string_view text) {
    if (!IsValidIdentityText(text)) {
      return std::nullopt;
    }
    StringId result;
    result.value_.assign(text);
    return result;
  }

  /// Unchecked construction for values already validated by the runtime.
  NDO_NODISCARD static StringId Trusted(std::string text) {
    StringId result;
    result.value_ = std::move(text);
    return result;
  }

  NDO_NODISCARD bool empty() const noexcept { return value_.empty(); }
  NDO_NODISCARD const std::string& str() const noexcept { return value_; }

  friend bool operator==(const StringId&, const StringId&) = default;
  friend std::strong_ordering operator<=>(const StringId& lhs, const StringId& rhs) {
    return lhs.value_ <=> rhs.value_;
  }

 private:
  std::string value_;
};

/// Tagged unsigned quantity with an explicit "unset" value of zero.
template <typename Tag, typename T = std::uint64_t>
class StrongUint {
 public:
  using value_type = T;

  constexpr StrongUint() noexcept = default;
  constexpr explicit StrongUint(T value) noexcept : value_(value) {}

  NDO_NODISCARD static constexpr StrongUint FromValue(T value) noexcept {
    return StrongUint(value);
  }

  NDO_NODISCARD constexpr T value() const noexcept { return value_; }
  /// A default-constructed quantity is unset; boundaries must reject it.
  NDO_NODISCARD constexpr bool is_set() const noexcept { return value_ != 0; }

  friend constexpr bool operator==(const StrongUint&, const StrongUint&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const StrongUint& lhs,
                                                    const StrongUint& rhs) noexcept {
    return lhs.value_ <=> rhs.value_;
  }

 private:
  T value_{0};
};

/// A SHA-256 digest. Used for finding identity, evidence integrity, ledger
/// integrity, policy identity and grouping keys.
struct NDO_API Digest {
  std::array<std::uint8_t, kDigestBytes> bytes{};

  NDO_NODISCARD bool is_set() const noexcept;
  NDO_NODISCARD std::string ToHex() const;
  NDO_NODISCARD static std::optional<Digest> TryFromHex(std::string_view hex);
  /// Short display form: the first 12 hex characters. Never used for identity.
  NDO_NODISCARD std::string ToShortHex() const;

  friend bool operator==(const Digest&, const Digest&) = default;
  friend std::strong_ordering operator<=>(const Digest& lhs, const Digest& rhs) {
    return lhs.bytes <=> rhs.bytes;
  }
};

/// Tagged digest identity. A default-constructed value is unset and must be
/// rejected by any boundary that requires an identity.
template <typename Tag>
class DigestId {
 public:
  DigestId() = default;
  explicit DigestId(Digest digest) : digest_(digest) {}

  NDO_NODISCARD static DigestId FromDigest(Digest digest) { return DigestId(digest); }
  NDO_NODISCARD static std::optional<DigestId> TryParse(std::string_view hex) {
    const auto digest = Digest::TryFromHex(hex);
    if (!digest.has_value()) {
      return std::nullopt;
    }
    return DigestId(*digest);
  }

  NDO_NODISCARD bool is_set() const noexcept { return digest_.is_set(); }
  NDO_NODISCARD const Digest& digest() const noexcept { return digest_; }
  NDO_NODISCARD std::string ToHex() const { return digest_.ToHex(); }
  NDO_NODISCARD std::string ToShortHex() const { return digest_.ToShortHex(); }

  friend bool operator==(const DigestId&, const DigestId&) = default;
  friend std::strong_ordering operator<=>(const DigestId& lhs, const DigestId& rhs) {
    return lhs.digest_ <=> rhs.digest_;
  }

 private:
  Digest digest_{};
};

struct TargetIdTag;
struct ObjectIdTag;
struct SourceIdTag;
struct SnapshotIdTag;
struct PolicyIdTag;
struct SuppressionIdTag;
struct ActorIdTag;
struct ReportIdTag;
struct FindingIdTag;
struct GroupIdTag;
struct RequestIdTag;

/// The observable unit: a device, port, link, tunnel or fabric element.
using TargetId = StringId<TargetIdTag>;
/// The identity of one intent object inside a target, e.g. "port/eth0".
using ObjectId = StringId<ObjectIdTag>;
/// The producer of observations, e.g. "collector/snmp-rack7".
using SourceId = StringId<SourceIdTag>;
/// The identity of one concrete observation snapshot document.
using SnapshotId = StringId<SnapshotIdTag>;
/// A named observatory policy document.
using PolicyId = StringId<PolicyIdTag>;
/// The identity of one suppression record.
using SuppressionId = StringId<SuppressionIdTag>;
/// The identity of an actor that acknowledged or suppressed drift.
using ActorId = StringId<ActorIdTag>;
/// The identity of one exported report.
using ReportId = StringId<ReportIdTag>;
/// The identity of a typed reconciliation request emitted for another runtime.
using RequestId = StringId<RequestIdTag>;

/// The deterministic identity of one drift finding.
using FindingId = DigestId<FindingIdTag>;
/// The deterministic identity of one root-cause group.
using GroupId = DigestId<GroupIdTag>;

struct IntentGenerationTag;
struct FabricEpochTag;
struct IncarnationTag;
struct SourceSequenceTag;
struct LedgerRevisionTag;

/// Monotonic generation of authoritative intent for one target.
using IntentGeneration = StrongUint<IntentGenerationTag>;
/// Fabric-wide epoch. A change of epoch invalidates every observation that was
/// collected under the previous epoch.
using FabricEpoch = StrongUint<FabricEpochTag>;
/// Process incarnation of a source or of the observatory itself. A restarted
/// process always has a strictly greater incarnation than the one it replaced.
using Incarnation = StrongUint<IncarnationTag>;
/// Monotonic per-source sequence number of an observation snapshot.
using SourceSequence = StrongUint<SourceSequenceTag>;
/// Monotonic revision of the persisted ledger.
using LedgerRevision = StrongUint<LedgerRevisionTag>;

/// One segment of a field path: either a named member or a sequence index.
struct NDO_API PathSegment {
  enum class Kind : std::uint8_t { Key = 0, Index = 1 };

  Kind kind{Kind::Key};
  std::string key;
  std::uint64_t index{0};

  NDO_NODISCARD static PathSegment MakeKey(std::string text);
  NDO_NODISCARD static PathSegment MakeIndex(std::uint64_t value);

  friend bool operator==(const PathSegment&, const PathSegment&) = default;
  friend std::strong_ordering operator<=>(const PathSegment& lhs, const PathSegment& rhs);
};

/// A canonical path from an intent object root to one leaf field.
///
/// The textual form is "a.b[3].c". Keys escape '\', '.', '[' and ']' with a
/// backslash. The empty path denotes the object root itself and renders as an
/// empty string; Describe() renders it as "<root>".
class NDO_API FieldPath {
 public:
  FieldPath() = default;

  NDO_NODISCARD static std::optional<FieldPath> TryParse(std::string_view text,
                                                         std::size_t max_segments,
                                                         std::size_t max_key_bytes);
  NDO_NODISCARD static FieldPath Root() { return FieldPath(); }

  NDO_NODISCARD bool empty() const noexcept { return segments_.empty(); }
  NDO_NODISCARD std::size_t size() const noexcept { return segments_.size(); }
  NDO_NODISCARD const PathSegment& operator[](std::size_t position) const {
    return segments_[position];
  }
  NDO_NODISCARD const std::vector<PathSegment>& segments() const noexcept { return segments_; }

  /// Appends one segment. The caller has already checked the segment bound.
  void Push(PathSegment segment) { segments_.push_back(std::move(segment)); }
  NDO_NODISCARD FieldPath Child(PathSegment segment) const;

  NDO_NODISCARD std::string ToText() const;
  NDO_NODISCARD std::string Describe() const;

  /// True when this path is a strict prefix of, or equal to, other.
  NDO_NODISCARD bool IsPrefixOf(const FieldPath& other) const noexcept;

  friend bool operator==(const FieldPath&, const FieldPath&) = default;
  friend std::strong_ordering operator<=>(const FieldPath& lhs, const FieldPath& rhs);

 private:
  std::vector<PathSegment> segments_;
};

}  // namespace network_drift_observatory
}  // namespace summon

#endif  // SUMMON_NETWORK_DRIFT_OBSERVATORY_IDENTITY_HPP
