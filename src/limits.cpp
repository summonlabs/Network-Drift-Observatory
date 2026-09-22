// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/limits.hpp"

#include <string_view>

namespace summon {
namespace network_drift_observatory {

const char* ToText(EvidenceClass value) noexcept {
  switch (value) {
    case EvidenceClass::Unknown:
      return "unknown";
    case EvidenceClass::Real:
      return "real";
    case EvidenceClass::Synthetic:
      return "synthetic";
    case EvidenceClass::Unsupported:
      return "unsupported";
  }
  return "unknown";
}

bool TryParseEvidenceClass(const char* text, EvidenceClass& out) noexcept {
  if (text == nullptr) {
    return false;
  }
  const std::string_view wanted(text);
  if (wanted == "unknown") {
    out = EvidenceClass::Unknown;
    return true;
  }
  if (wanted == "real") {
    out = EvidenceClass::Real;
    return true;
  }
  if (wanted == "synthetic") {
    out = EvidenceClass::Synthetic;
    return true;
  }
  if (wanted == "unsupported") {
    out = EvidenceClass::Unsupported;
    return true;
  }
  return false;
}

}  // namespace network_drift_observatory
}  // namespace summon
