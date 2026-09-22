// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/identity.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace summon {
namespace network_drift_observatory {
namespace {

constexpr bool IsAlnum(char c) noexcept {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

constexpr bool IsIdentitySeparator(char c) noexcept {
  return c == '.' || c == '_' || c == '-' || c == '/' || c == ':' || c == '@' || c == '#';
}

constexpr int HexValue(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

constexpr char kHexDigits[] = "0123456789abcdef";

}  // namespace

bool IsValidIdentityText(std::string_view text) noexcept {
  if (text.empty() || text.size() > kMaxIdentityLength) {
    return false;
  }
  if (text.front() == '/' || text.front() == '.' || text.front() == '-') {
    return false;
  }
  const char last = text.back();
  if (IsIdentitySeparator(last) || last == '\\') {
    return false;
  }
  for (char c : text) {
    const unsigned char raw = static_cast<unsigned char>(c);
    if (raw < 0x20 || raw == 0x7F) {
      return false;
    }
    if (c == '\\') {
      return false;
    }
    if (!IsAlnum(c) && !IsIdentitySeparator(c)) {
      return false;
    }
  }
  // Reject path-traversal components so an identity can never be read as a
  // relative filesystem path by a careless consumer.
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t slash = text.find('/', start);
    const std::size_t end = slash == std::string_view::npos ? text.size() : slash;
    const std::string_view component = text.substr(start, end - start);
    if (component == "." || component == "..") {
      return false;
    }
    if (slash == std::string_view::npos) {
      break;
    }
    start = slash + 1;
  }
  return true;
}

bool Digest::is_set() const noexcept {
  for (std::uint8_t byte : bytes) {
    if (byte != 0) {
      return true;
    }
  }
  return false;
}

std::string Digest::ToHex() const {
  std::string out;
  out.resize(kDigestHexLength);
  for (std::size_t index = 0; index < kDigestBytes; ++index) {
    out[2 * index] = kHexDigits[bytes[index] >> 4];
    out[2 * index + 1] = kHexDigits[bytes[index] & 0x0F];
  }
  return out;
}

std::optional<Digest> Digest::TryFromHex(std::string_view hex) {
  if (hex.size() != kDigestHexLength) {
    return std::nullopt;
  }
  Digest digest;
  for (std::size_t index = 0; index < kDigestBytes; ++index) {
    const int high = HexValue(hex[2 * index]);
    const int low = HexValue(hex[2 * index + 1]);
    if (high < 0 || low < 0) {
      return std::nullopt;
    }
    digest.bytes[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return digest;
}

std::string Digest::ToShortHex() const {
  const std::string full = ToHex();
  return full.substr(0, 12);
}

PathSegment PathSegment::MakeKey(std::string text) {
  PathSegment segment;
  segment.kind = Kind::Key;
  segment.key = std::move(text);
  return segment;
}

PathSegment PathSegment::MakeIndex(std::uint64_t value) {
  PathSegment segment;
  segment.kind = Kind::Index;
  segment.index = value;
  return segment;
}

std::strong_ordering operator<=>(const PathSegment& lhs, const PathSegment& rhs) {
  if (lhs.kind != rhs.kind) {
    return lhs.kind <=> rhs.kind;
  }
  if (lhs.kind == PathSegment::Kind::Key) {
    return lhs.key <=> rhs.key;
  }
  return lhs.index <=> rhs.index;
}

namespace {

bool IsEscapable(char c) noexcept {
  return c == '\\' || c == '.' || c == '[' || c == ']';
}

void AppendEscapedKey(std::string& out, std::string_view key) {
  for (char c : key) {
    if (IsEscapable(c)) {
      out.push_back('\\');
    }
    out.push_back(c);
  }
}

}  // namespace

std::optional<FieldPath> FieldPath::TryParse(std::string_view text, std::size_t max_segments,
                                             std::size_t max_key_bytes) {
  FieldPath path;
  if (text.empty()) {
    return path;
  }
  if (text.size() > max_segments * (max_key_bytes + 4)) {
    return std::nullopt;
  }
  std::size_t position = 0;
  while (position < text.size()) {
    if (path.size() >= max_segments) {
      return std::nullopt;
    }
    if (text[position] == '[') {
      const std::size_t close = text.find(']', position + 1);
      if (close == std::string_view::npos || close == position + 1) {
        return std::nullopt;
      }
      const std::string_view digits = text.substr(position + 1, close - position - 1);
      if (digits.size() > 20) {
        return std::nullopt;
      }
      if (digits.size() > 1 && digits.front() == '0') {
        return std::nullopt;  // canonical form has no leading zeros
      }
      std::uint64_t value = 0;
      for (char c : digits) {
        if (c < '0' || c > '9') {
          return std::nullopt;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10ULL) {
          return std::nullopt;
        }
        value = value * 10ULL + digit;
      }
      path.Push(PathSegment::MakeIndex(value));
      position = close + 1;
      if (position == text.size()) {
        break;
      }
      if (text[position] != '.' && text[position] != '[') {
        return std::nullopt;
      }
      if (text[position] == '.') {
        ++position;
        if (position == text.size() || text[position] == '.' || text[position] == ']' ||
            text[position] == '[') {
          // "a.[0]" is a non-canonical spelling of "a[0]" and is refused rather
          // than normalized, so one path has exactly one textual form.
          return std::nullopt;
        }
      }
      continue;
    }
    // Key segment.
    std::string key;
    bool terminated = false;
    while (position < text.size()) {
      const char c = text[position];
      if (c == '\\') {
        if (position + 1 >= text.size() || !IsEscapable(text[position + 1])) {
          return std::nullopt;
        }
        key.push_back(text[position + 1]);
        position += 2;
        continue;
      }
      if (c == '.' || c == '[') {
        terminated = true;
        break;
      }
      if (c == ']') {
        return std::nullopt;
      }
      const unsigned char raw = static_cast<unsigned char>(c);
      if (raw < 0x20 || raw == 0x7F) {
        return std::nullopt;
      }
      key.push_back(c);
      ++position;
    }
    if (key.empty() || key.size() > max_key_bytes) {
      return std::nullopt;
    }
    path.Push(PathSegment::MakeKey(std::move(key)));
    if (!terminated) {
      break;
    }
    if (text[position] == '[') {
      continue;
    }
    ++position;  // consume '.'
    if (position >= text.size() || text[position] == '.' || text[position] == ']' ||
        text[position] == '[') {
      return std::nullopt;
    }
  }
  return path;
}

FieldPath FieldPath::Child(PathSegment segment) const {
  FieldPath copy = *this;
  copy.Push(std::move(segment));
  return copy;
}

std::string FieldPath::ToText() const {
  std::string out;
  bool first = true;
  for (const PathSegment& segment : segments_) {
    if (segment.kind == PathSegment::Kind::Index) {
      out.push_back('[');
      out.append(std::to_string(segment.index));
      out.push_back(']');
      first = false;
      continue;
    }
    if (!first) {
      out.push_back('.');
    }
    AppendEscapedKey(out, segment.key);
    first = false;
  }
  return out;
}

std::string FieldPath::Describe() const {
  if (segments_.empty()) {
    return "<root>";
  }
  return ToText();
}

bool FieldPath::IsPrefixOf(const FieldPath& other) const noexcept {
  if (segments_.size() > other.segments_.size()) {
    return false;
  }
  for (std::size_t index = 0; index < segments_.size(); ++index) {
    if (!(segments_[index] == other.segments_[index])) {
      return false;
    }
  }
  return true;
}

std::strong_ordering operator<=>(const FieldPath& lhs, const FieldPath& rhs) {
  const std::size_t common = lhs.segments_.size() < rhs.segments_.size() ? lhs.segments_.size()
                                                                        : rhs.segments_.size();
  for (std::size_t index = 0; index < common; ++index) {
    if (auto cmp = lhs.segments_[index] <=> rhs.segments_[index]; cmp != 0) {
      return cmp;
    }
  }
  return lhs.segments_.size() <=> rhs.segments_.size();
}

}  // namespace network_drift_observatory
}  // namespace summon
