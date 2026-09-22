// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/json.hpp"

#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

#include "summon/network_drift_observatory/hash.hpp"

namespace summon {
namespace network_drift_observatory {
namespace {

constexpr const char* kHexDigits = "0123456789abcdef";
/// The canonical tag for a byte string. Decoding is the exact inverse of the
/// writer, so a document written by this runtime parses back to the same value.
constexpr const char* kBytesMember = "$bytes";

void AppendEscaped(std::string& out, std::string_view text) {
  out.push_back('"');
  for (char raw : text) {
    const unsigned char c = static_cast<unsigned char>(raw);
    switch (c) {
      case '"':
        out.append("\\\"");
        break;
      case '\\':
        out.append("\\\\");
        break;
      case '\b':
        out.append("\\b");
        break;
      case '\f':
        out.append("\\f");
        break;
      case '\n':
        out.append("\\n");
        break;
      case '\r':
        out.append("\\r");
        break;
      case '\t':
        out.append("\\t");
        break;
      default:
        if (c < 0x20) {
          out.append("\\u00");
          out.push_back(kHexDigits[(c >> 4) & 0x0F]);
          out.push_back(kHexDigits[c & 0x0F]);
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  out.push_back('"');
}

std::string FormatDoubleCanonical(double value) {
  char buffer[64];
  const std::to_chars_result result =
      std::to_chars(buffer, buffer + sizeof(buffer), value, std::chars_format::general);
  if (result.ec != std::errc{}) {
    return "0";
  }
  std::string text(buffer, result.ptr);
  if (text.find('.') == std::string::npos && text.find('e') == std::string::npos &&
      text.find('E') == std::string::npos) {
    text += ".0";
  }
  return text;
}

void WriteCompact(std::string& out, const Value& value, std::size_t depth);

void WriteCompactMap(std::string& out, const Value::Map& map, std::size_t depth) {
  out.push_back('{');
  bool first = true;
  for (const auto& entry : map) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    AppendEscaped(out, entry.first);
    out.push_back(':');
    WriteCompact(out, entry.second, depth + 1);
  }
  out.push_back('}');
}

void WriteCompact(std::string& out, const Value& value, std::size_t depth) {
  switch (value.kind()) {
    case ValueKind::Null:
      out.append("null");
      return;
    case ValueKind::Bool:
      out.append(*value.as_bool() ? "true" : "false");
      return;
    case ValueKind::Int:
      out += std::to_string(*value.as_int());
      return;
    case ValueKind::Uint:
      out += std::to_string(*value.as_uint());
      return;
    case ValueKind::Double:
      out += FormatDoubleCanonical(*value.as_double());
      return;
    case ValueKind::String:
      AppendEscaped(out, *value.as_string());
      return;
    case ValueKind::Bytes: {
      // Byte strings have no JSON spelling of their own; the canonical form is
      // an explicitly tagged member so it can never be mistaken for text.
      const std::vector<std::uint8_t>& bytes = *value.as_bytes();
      out.append("{\"$bytes\":\"");
      out += ToHex(bytes.data(), bytes.size());
      out.append("\"}");
      return;
    }
    case ValueKind::List: {
      const Value::List& list = *value.as_list();
      out.push_back('[');
      for (std::size_t index = 0; index < list.size(); ++index) {
        if (index != 0) {
          out.push_back(',');
        }
        WriteCompact(out, list[index], depth + 1);
      }
      out.push_back(']');
      return;
    }
    case ValueKind::Map:
      WriteCompactMap(out, *value.as_map(), depth);
      return;
  }
}

void WriteIndent(std::string& out, std::size_t width, std::size_t depth) {
  if (width == 0) {
    return;
  }
  out.push_back('\n');
  out.append(width * depth, ' ');
}

void WritePretty(std::string& out, const Value& value, std::size_t depth, std::size_t width);

void WritePrettyMap(std::string& out, const Value::Map& map, std::size_t depth, std::size_t width) {
  if (map.empty()) {
    out.append("{}");
    return;
  }
  out.push_back('{');
  bool first = true;
  for (const auto& entry : map) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    WriteIndent(out, width, depth + 1);
    AppendEscaped(out, entry.first);
    out.append(": ");
    WritePretty(out, entry.second, depth + 1, width);
  }
  WriteIndent(out, width, depth);
  out.push_back('}');
}

void WritePretty(std::string& out, const Value& value, std::size_t depth, std::size_t width) {
  switch (value.kind()) {
    case ValueKind::List: {
      const Value::List& list = *value.as_list();
      if (list.empty()) {
        out.append("[]");
        return;
      }
      out.push_back('[');
      for (std::size_t index = 0; index < list.size(); ++index) {
        if (index != 0) {
          out.push_back(',');
        }
        WriteIndent(out, width, depth + 1);
        WritePretty(out, list[index], depth + 1, width);
      }
      WriteIndent(out, width, depth);
      out.push_back(']');
      return;
    }
    case ValueKind::Map:
      WritePrettyMap(out, *value.as_map(), depth, width);
      return;
    default:
      WriteCompact(out, value, depth);
      return;
  }
}

class Parser {
 public:
  Parser(std::string_view text, const RuntimeLimits& limits) : text_(text), limits_(limits) {}

  Status Parse(Value& out) {
    SkipWhitespace();
    if (position_ >= text_.size()) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "empty document");
    }
    Value value;
    Status status = ParseValue(value, 0);
    if (!status.ok()) {
      return status;
    }
    SkipWhitespace();
    if (position_ != text_.size()) {
      return Status::Rejected(ReasonCode::EncodingTrailingBytes,
                              "document has bytes after the top-level value");
    }
    out = std::move(value);
    return Status::Ok();
  }

 private:
  void SkipWhitespace() {
    while (position_ < text_.size()) {
      const char c = text_[position_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++position_;
        continue;
      }
      return;
    }
  }

  Status Fail(ReasonCode reason, const char* detail) {
    return Status::Rejected(reason, detail);
  }

  Status ParseValue(Value& out, std::size_t depth) {
    if (depth > limits_.max_value_depth) {
      return Status::Limit(ReasonCode::LimitDepthExceeded, "document nesting exceeds the envelope");
    }
    if (++nodes_ > limits_.max_value_nodes) {
      return Status::Limit(ReasonCode::LimitObjectsExceeded, "document node count exceeds the envelope");
    }
    if (position_ >= text_.size()) {
      return Fail(ReasonCode::EncodingMalformed, "document ended before a value");
    }
    switch (text_[position_]) {
      case '{':
        return ParseObject(out, depth);
      case '[':
        return ParseArray(out, depth);
      case '"': {
        std::string text;
        Status status = ParseString(text);
        if (!status.ok()) {
          return status;
        }
        out = Value::MakeString(std::move(text));
        return Status::Ok();
      }
      case 't':
        return ParseLiteral("true", Value::MakeBool(true), out);
      case 'f':
        return ParseLiteral("false", Value::MakeBool(false), out);
      case 'n':
        return ParseLiteral("null", Value::MakeNull(), out);
      default:
        return ParseNumber(out);
    }
  }

  Status ParseLiteral(std::string_view literal, Value value, Value& out) {
    if (text_.size() - position_ < literal.size() ||
        text_.substr(position_, literal.size()) != literal) {
      return Fail(ReasonCode::EncodingUnexpectedToken, "unrecognized literal");
    }
    position_ += literal.size();
    out = std::move(value);
    return Status::Ok();
  }

  Status ParseObject(Value& out, std::size_t depth) {
    ++position_;  // consume '{'
    Value::Map map;
    SkipWhitespace();
    if (position_ < text_.size() && text_[position_] == '}') {
      ++position_;
      return FinishObject(std::move(map), out);
    }
    for (;;) {
      SkipWhitespace();
      if (position_ >= text_.size() || text_[position_] != '"') {
        return Fail(ReasonCode::EncodingMalformed, "member name must be a string");
      }
      std::string key;
      Status status = ParseString(key);
      if (!status.ok()) {
        return status;
      }
      if (key.size() > limits_.max_leaf_bytes) {
        return Status::Limit(ReasonCode::LimitBytesExceeded, "member name exceeds the envelope");
      }
      SkipWhitespace();
      if (position_ >= text_.size() || text_[position_] != ':') {
        return Fail(ReasonCode::EncodingMalformed, "member name must be followed by a colon");
      }
      ++position_;
      SkipWhitespace();
      Value member;
      status = ParseValue(member, depth + 1);
      if (!status.ok()) {
        return status;
      }
      const auto inserted = map.emplace(std::move(key), std::move(member));
      if (!inserted.second) {
        return Fail(ReasonCode::EncodingDuplicateKey, "duplicate member name");
      }

      if (map.size() > limits_.max_fields_per_object) {
        return Status::Limit(ReasonCode::LimitFieldsExceeded, "member count exceeds the envelope");
      }
      SkipWhitespace();
      if (position_ >= text_.size()) {
        return Fail(ReasonCode::EncodingMalformed, "unterminated object");
      }
      if (text_[position_] == ',') {
        ++position_;
        continue;
      }
      if (text_[position_] == '}') {
        ++position_;
        return FinishObject(std::move(map), out);
      }
      return Fail(ReasonCode::EncodingMalformed, "expected ',' or '}'");
    }
  }

  Status ParseArray(Value& out, std::size_t depth) {
    ++position_;  // consume '['
    Value::List list;
    SkipWhitespace();
    if (position_ < text_.size() && text_[position_] == ']') {
      ++position_;
      out = Value::MakeList(std::move(list));
      return Status::Ok();
    }
    for (;;) {
      SkipWhitespace();
      Value element;
      Status status = ParseValue(element, depth + 1);
      if (!status.ok()) {
        return status;
      }
      list.push_back(std::move(element));
      if (list.size() > limits_.max_value_nodes) {
        return Status::Limit(ReasonCode::LimitObjectsExceeded, "sequence exceeds the envelope");
      }
      SkipWhitespace();
      if (position_ >= text_.size()) {
        return Fail(ReasonCode::EncodingMalformed, "unterminated sequence");
      }
      if (text_[position_] == ',') {
        ++position_;
        continue;
      }
      if (text_[position_] == ']') {
        ++position_;
        out = Value::MakeList(std::move(list));
        return Status::Ok();
      }
      return Fail(ReasonCode::EncodingMalformed, "expected ',' or ']'");
    }
  }

  /// The canonical encoding of a byte string is the single-member object
  /// {"$bytes":"<hex>"}. Decoding it once the object is complete keeps the
  /// codec a true inverse pair: anything the writer produces parses back to the
  /// same value, and a malformed tag is a refusal rather than a map.
  Status FinishObject(Value::Map map, Value& out) {
    if (map.size() == 1) {
      const auto bytes_member = map.find(kBytesMember);
      if (bytes_member != map.end()) {
        const std::string* hex = bytes_member->second.as_string();
        if (hex == nullptr) {
          return Fail(ReasonCode::EncodingMalformed, "the byte-string tag must carry a hex string");
        }
        std::vector<std::uint8_t> raw;
        if (!FromHex(*hex, raw)) {
          return Fail(ReasonCode::EncodingMalformed, "the byte-string tag carries invalid hex");
        }
        if (raw.size() > limits_.max_leaf_bytes) {
          return Status::Limit(ReasonCode::LimitBytesExceeded, "byte string exceeds the envelope");
        }
        out = Value::MakeBytes(std::move(raw));
        return Status(StatusCode::Ok, ReasonCode::None);
      }
    }
    out = Value::MakeMap(std::move(map));
    return Status(StatusCode::Ok, ReasonCode::None);
  }

  static int HexValue(char c) {
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

  Status ParseHex4(std::uint32_t& out) {
    if (position_ + 4 > text_.size()) {
      return Fail(ReasonCode::EncodingMalformed, "truncated escape sequence");
    }
    std::uint32_t value = 0;
    for (int index = 0; index < 4; ++index) {
      const int digit = HexValue(text_[position_ + static_cast<std::size_t>(index)]);
      if (digit < 0) {
        return Fail(ReasonCode::EncodingMalformed, "invalid escape digit");
      }
      value = (value << 4) | static_cast<std::uint32_t>(digit);
    }
    position_ += 4;
    out = value;
    return Status(StatusCode::Ok, ReasonCode::None);
  }

  static void AppendUtf8(std::string& out, std::uint32_t codepoint) {
    if (codepoint < 0x80) {
      out.push_back(static_cast<char>(codepoint));
      return;
    }
    if (codepoint < 0x800) {
      out.push_back(static_cast<char>(0xC0u | (codepoint >> 6)));
      out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
      return;
    }
    if (codepoint < 0x10000) {
      out.push_back(static_cast<char>(0xE0u | (codepoint >> 12)));
      out.push_back(static_cast<char>(0x80u | ((codepoint >> 6) & 0x3Fu)));
      out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
      return;
    }
    out.push_back(static_cast<char>(0xF0u | (codepoint >> 18)));
    out.push_back(static_cast<char>(0x80u | ((codepoint >> 12) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | ((codepoint >> 6) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
  }

  Status ParseString(std::string& out) {
    ++position_;  // consume opening quote
    out.clear();
    for (;;) {
      if (position_ >= text_.size()) {
        return Fail(ReasonCode::EncodingMalformed, "unterminated string");
      }
      const char c = text_[position_];
      if (c == '"') {
        ++position_;
        if (!IsValidUtf8(out)) {
          return Fail(ReasonCode::EncodingInvalidUtf8, "string is not valid UTF-8");
        }
        if (out.size() > limits_.max_leaf_bytes) {
          return Status::Limit(ReasonCode::LimitBytesExceeded, "string exceeds the envelope");
        }
        return Status(StatusCode::Ok, ReasonCode::None);
      }
      if (c == '\\') {
        ++position_;
        if (position_ >= text_.size()) {
          return Fail(ReasonCode::EncodingMalformed, "truncated escape sequence");
        }
        const char escape = text_[position_++];
        switch (escape) {
          case '"':
            out.push_back('"');
            break;
          case '\\':
            out.push_back('\\');
            break;
          case '/':
            out.push_back('/');
            break;
          case 'b':
            out.push_back('\b');
            break;
          case 'f':
            out.push_back('\f');
            break;
          case 'n':
            out.push_back('\n');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'u': {
            std::uint32_t codepoint = 0;
            Status status = ParseHex4(codepoint);
            if (!status.ok()) {
              return status;
            }
            if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
              if (position_ + 1 >= text_.size() || text_[position_] != '\\' ||
                  text_[position_ + 1] != 'u') {
                return Fail(ReasonCode::EncodingInvalidUtf8, "lone high surrogate");
              }
              position_ += 2;
              std::uint32_t low = 0;
              status = ParseHex4(low);
              if (!status.ok()) {
                return status;
              }
              if (low < 0xDC00 || low > 0xDFFF) {
                return Fail(ReasonCode::EncodingInvalidUtf8, "high surrogate without a low surrogate");
              }
              codepoint = 0x10000u + ((codepoint - 0xD800u) << 10) + (low - 0xDC00u);
            } else if (codepoint >= 0xDC00 && codepoint <= 0xDFFF) {
              return Fail(ReasonCode::EncodingInvalidUtf8, "lone low surrogate");
            }
            AppendUtf8(out, codepoint);
            break;
          }
          default:
            return Fail(ReasonCode::EncodingMalformed, "invalid escape sequence");
        }
        if (out.size() > limits_.max_leaf_bytes) {
          return Status::Limit(ReasonCode::LimitBytesExceeded, "string exceeds the envelope");
        }
        continue;
      }
      const unsigned char raw = static_cast<unsigned char>(c);
      if (raw < 0x20) {
        return Fail(ReasonCode::EncodingMalformed, "raw control character in string");
      }
      out.push_back(c);
      if (out.size() > limits_.max_leaf_bytes) {
        return Status::Limit(ReasonCode::LimitBytesExceeded, "string exceeds the envelope");
      }
      ++position_;
    }
  }

  Status ParseNumber(Value& out) {
    const std::size_t start = position_;
    if (position_ < text_.size() && text_[position_] == '-') {
      ++position_;
    }
    if (position_ >= text_.size() || text_[position_] < '0' || text_[position_] > '9') {
      return Fail(ReasonCode::EncodingUnexpectedToken, "not a value");
    }
    if (text_[position_] == '0') {
      ++position_;
      if (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') {
        return Fail(ReasonCode::EncodingMalformed, "number has a leading zero");
      }
    } else {
      while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') {
        ++position_;
      }
    }
    bool integral = true;
    if (position_ < text_.size() && text_[position_] == '.') {
      integral = false;
      ++position_;
      if (position_ >= text_.size() || text_[position_] < '0' || text_[position_] > '9') {
        return Fail(ReasonCode::EncodingMalformed, "fraction has no digits");
      }
      while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') {
        ++position_;
      }
    }
    if (position_ < text_.size() && (text_[position_] == 'e' || text_[position_] == 'E')) {
      integral = false;
      ++position_;
      if (position_ < text_.size() && (text_[position_] == '+' || text_[position_] == '-')) {
        ++position_;
      }
      if (position_ >= text_.size() || text_[position_] < '0' || text_[position_] > '9') {
        return Fail(ReasonCode::EncodingMalformed, "exponent has no digits");
      }
      while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') {
        ++position_;
      }
    }
    const std::string_view token = text_.substr(start, position_ - start);
    if (integral && token.size() <= 20) {
      if (!token.empty() && token.front() == '-') {
        std::int64_t value = 0;
        const auto result = std::from_chars(token.data(), token.data() + token.size(), value);
        if (result.ec == std::errc{} && result.ptr == token.data() + token.size()) {
          out = Value::MakeInt(value);
          return Status(StatusCode::Ok, ReasonCode::None);
        }
      } else {
        std::uint64_t unsigned_value = 0;
        const auto unsigned_result =
            std::from_chars(token.data(), token.data() + token.size(), unsigned_value);
        if (unsigned_result.ec == std::errc{} &&
            unsigned_result.ptr == token.data() + token.size()) {
          if (unsigned_value <= 9223372036854775807ULL) {
            out = Value::MakeInt(static_cast<std::int64_t>(unsigned_value));
          } else {
            out = Value::MakeUint(unsigned_value);
          }
          return Status(StatusCode::Ok, ReasonCode::None);
        }
      }
    }
    double value = 0.0;
    const auto result =
        std::from_chars(token.data(), token.data() + token.size(), value, std::chars_format::general);
    if (result.ec != std::errc{} || result.ptr != token.data() + token.size() ||
        !std::isfinite(value)) {
      return Fail(ReasonCode::EncodingNumberOutOfRange, "number is outside the representable range");
    }
    const std::optional<Value> parsed = Value::TryMakeDouble(value);
    if (!parsed.has_value()) {
      return Fail(ReasonCode::EncodingNumberOutOfRange, "number is not finite");
    }
    out = *parsed;
    return Status(StatusCode::Ok, ReasonCode::None);
  }

  std::string_view text_;
  const RuntimeLimits& limits_;
  std::size_t position_{0};
  std::size_t nodes_{0};
};

}  // namespace

std::string JsonQuote(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 2);
  AppendEscaped(out, text);
  return out;
}

std::string WriteCanonicalJson(const Value& value) {
  std::string out;
  out.reserve(256);
  WriteCompact(out, value, 0);
  return out;
}

std::string WritePrettyJson(const Value& value, std::size_t indent_width) {
  std::string out;
  out.reserve(512);
  WritePretty(out, value, 0, indent_width);
  return out;
}

Status ParseJson(std::string_view text, const RuntimeLimits& limits, Value& out) {
  if (text.size() > limits.max_document_bytes) {
    return Status::Limit(ReasonCode::LimitBytesExceeded, "document exceeds the envelope");
  }
  Parser parser(text, limits);
  Value parsed;
  Status status = parser.Parse(parsed);
  if (!status.ok()) {
    return status;
  }
  out = std::move(parsed);
  return Status(StatusCode::Ok, ReasonCode::None);
}

}  // namespace network_drift_observatory
}  // namespace summon
