// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/time.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <string_view>

#include "summon/network_drift_observatory/checked.hpp"

namespace summon {
namespace network_drift_observatory {
namespace {

constexpr std::int64_t kNanosPerSecond = 1000000000LL;
constexpr std::int64_t kSecondsPerDay = 86400LL;

/// Days from 1970-01-01 for a proleptic Gregorian date. Portable and total, so
/// parsing never depends on the platform's timezone database.
constexpr std::int64_t DaysFromCivil(std::int64_t year, unsigned month, unsigned day) noexcept {
  year -= month <= 2 ? 1 : 0;
  const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
  const unsigned year_of_era = static_cast<unsigned>(year - era * 400);
  const unsigned adjusted_month = month > 2u ? month - 3u : month + 9u;
  const unsigned day_of_year = (153u * adjusted_month + 2u) / 5u + day - 1u;
  const unsigned day_of_era =
      year_of_era * 365u + year_of_era / 4u - year_of_era / 100u + day_of_year;
  return era * 146097LL + static_cast<std::int64_t>(day_of_era) - 719468LL;
}

void CivilFromDays(std::int64_t days, std::int64_t& year, unsigned& month, unsigned& day) noexcept {
  days += 719468LL;
  const std::int64_t era = (days >= 0 ? days : days - 146096LL) / 146097LL;
  const unsigned day_of_era = static_cast<unsigned>(days - era * 146097LL);
  const unsigned year_of_era =
      (day_of_era - day_of_era / 1460u + day_of_era / 36524u - day_of_era / 146096u) / 365u;
  year = static_cast<std::int64_t>(year_of_era) + era * 400LL;
  const unsigned day_of_year = day_of_era - (365u * year_of_era + year_of_era / 4u - year_of_era / 100u);
  const unsigned mp = (5u * day_of_year + 2u) / 153u;
  day = day_of_year - (153u * mp + 2u) / 5u + 1u;
  month = mp < 10u ? mp + 3u : mp - 9u;
  year += (month <= 2u) ? 1 : 0;
}

bool ParseDigits(std::string_view text, std::size_t offset, std::size_t count,
                 std::int64_t& out) noexcept {
  if (offset + count > text.size()) {
    return false;
  }
  std::int64_t value = 0;
  for (std::size_t index = 0; index < count; ++index) {
    const char c = text[offset + index];
    if (c < '0' || c > '9') {
      return false;
    }
    value = value * 10 + (c - '0');
  }
  out = value;
  return true;
}

}  // namespace

NdoTime SystemNow() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  return NdoTime::FromNanos(static_cast<std::int64_t>(nanos));
}

std::string FormatTime(NdoTime time) {
  const std::int64_t nanos = time.unix_nanos;
  std::int64_t seconds = nanos / kNanosPerSecond;
  std::int64_t fraction = nanos % kNanosPerSecond;
  if (fraction < 0) {
    fraction += kNanosPerSecond;
    seconds -= 1;
  }
  const std::int64_t days = seconds / kSecondsPerDay;
  std::int64_t remainder = seconds % kSecondsPerDay;
  if (remainder < 0) {
    remainder += kSecondsPerDay;
  }
  std::int64_t year = 0;
  unsigned month = 0;
  unsigned day = 0;
  CivilFromDays(days, year, month, day);
  const int hour = static_cast<int>(remainder / 3600);
  const int minute = static_cast<int>((remainder % 3600) / 60);
  const int second = static_cast<int>(remainder % 60);
  char buffer[64];
  std::snprintf(buffer, sizeof(buffer), "%04lld-%02u-%02uT%02d:%02d:%02d.%09lldZ",
                static_cast<long long>(year), month, day, hour, minute, second,
                static_cast<long long>(fraction));
  return std::string(buffer);
}

bool TryParseTime(std::string_view text, NdoTime& out) noexcept {
  // YYYY-MM-DDTHH:MM:SS[.fraction]Z, strictly.
  if (text.size() < 20) {
    return false;
  }
  if (text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' || text[16] != ':') {
    return false;
  }
  if (text.back() != 'Z') {
    return false;
  }
  std::int64_t year = 0;
  std::int64_t month = 0;
  std::int64_t day = 0;
  std::int64_t hour = 0;
  std::int64_t minute = 0;
  std::int64_t second = 0;
  if (!ParseDigits(text, 0, 4, year) || !ParseDigits(text, 5, 2, month) ||
      !ParseDigits(text, 8, 2, day) || !ParseDigits(text, 11, 2, hour) ||
      !ParseDigits(text, 14, 2, minute) || !ParseDigits(text, 17, 2, second)) {
    return false;
  }
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) {
    return false;
  }
  std::int64_t fraction = 0;
  std::size_t position = 19;
  if (position < text.size() && text[position] == '.') {
    ++position;
    const std::size_t start = position;
    while (position < text.size() && text[position] >= '0' && text[position] <= '9') {
      ++position;
    }
    const std::size_t digits = position - start;
    if (digits == 0 || digits > 9) {
      return false;
    }
    std::int64_t raw = 0;
    if (!ParseDigits(text, start, digits, raw)) {
      return false;
    }
    for (std::size_t index = digits; index < 9; ++index) {
      raw *= 10;
    }
    fraction = raw;
  }
  if (position != text.size() - 1) {
    return false;
  }
  const std::int64_t days = DaysFromCivil(year, static_cast<unsigned>(month),
                                          static_cast<unsigned>(day));
  const std::int64_t seconds = days * kSecondsPerDay + hour * 3600 + minute * 60 + second;
  // seconds * 1e9 can overflow for absurd years; refuse rather than wrap.
  if (seconds > (INT64_MAX - fraction) / kNanosPerSecond ||
      seconds < (INT64_MIN + fraction) / kNanosPerSecond) {
    return false;
  }
  out = NdoTime::FromNanos(seconds * kNanosPerSecond + fraction);
  return true;
}

bool TryDifference(NdoTime later, NdoTime earlier, std::int64_t& out_nanos) noexcept {
  const auto difference = CheckedSubSigned(later.unix_nanos, earlier.unix_nanos);
  if (!difference.has_value()) {
    return false;
  }
  out_nanos = *difference;
  return true;
}

}  // namespace network_drift_observatory
}  // namespace summon
