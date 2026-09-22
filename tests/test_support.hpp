// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Shared fixtures for the test suites.
//
// Every fixture is deterministic: fixed clock readings, fixed identities and a
// seeded pseudo-random generator. No test depends on wall-clock timing or on
// the order in which an operating system happens to schedule threads.

#ifndef NDO_TESTS_TEST_SUPPORT_HPP
#define NDO_TESTS_TEST_SUPPORT_HPP

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "summon/network_drift_observatory/comparison.hpp"
#include "summon/network_drift_observatory/engine.hpp"
#include "summon/network_drift_observatory/interchange.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/persistence.hpp"

namespace ndotest {

namespace ndo = summon::network_drift_observatory;

/// Deterministic splitmix64 generator. Reproducible on every platform.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed) {}

  std::uint64_t Next() {
    state_ += 0x9E3779B97F4A7C15ULL;
    std::uint64_t z = state_;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }

  std::uint64_t Below(std::uint64_t bound) { return bound == 0 ? 0 : Next() % bound; }

  bool Chance(std::uint32_t percent) { return Below(100) < percent; }

 private:
  std::uint64_t state_;
};

inline ndo::NdoTime FixedTime(std::int64_t seconds) {
  return ndo::NdoTime::FromSeconds(seconds);
}

/// A clock that returns the same reading every time it is consulted.
struct FixedClock {
  ndo::NdoTime value;
  ndo::NdoTime operator()() const { return value; }
};

inline ndo::TargetId Target(const std::string& text) {
  return ndo::TargetId::TryParse(text).value();
}

inline ndo::ObjectId Object(const std::string& text) {
  return ndo::ObjectId::TryParse(text).value();
}

inline ndo::SourceId Source(const std::string& text) {
  return ndo::SourceId::TryParse(text).value();
}

inline ndo::FieldPath Path(const std::string& text) {
  return ndo::FieldPath::TryParse(text, 32, 256).value();
}

/// Builds an intent document with the given objects and a single managed field
/// per object unless a field map is supplied.
inline ndo::IntentGenerationDocument MakeIntent(const std::string& target,
                                                std::uint64_t generation,
                                                std::uint64_t epoch = 1) {
  ndo::IntentGenerationDocument document;
  document.target = Target(target);
  document.generation = ndo::IntentGeneration::FromValue(generation);
  document.epoch = ndo::FabricEpoch::FromValue(epoch);
  document.authority = ndo::IntentAuthority::IntentFabric;
  document.policy = ndo::PolicyId::Trusted("policy/default");
  document.authored_at = FixedTime(1000);
  document.evidence = ndo::EvidenceClass::Synthetic;
  return document;
}

inline void AddIntentObject(ndo::IntentGenerationDocument& document, const std::string& object,
                            const std::string& field, ndo::Value value) {
  const ndo::ObjectId id = Object(object);
  auto found = document.objects.find(id);
  if (found == document.objects.end()) {
    ndo::IntentObject entry;
    entry.id = id;
    found = document.objects.emplace(id, std::move(entry)).first;
  }
  ndo::IntentField intent_field;
  intent_field.path = Path(field);
  intent_field.intended = std::move(value);
  intent_field.comparability = ndo::FieldComparability::Managed;
  found->second.fields.insert_or_assign(intent_field.path, std::move(intent_field));
}

inline ndo::ObservationSnapshot MakeSnapshot(const std::string& source, const std::string& target,
                                             std::uint64_t sequence, ndo::NdoTime collected_at,
                                             std::uint64_t epoch = 1,
                                             std::uint64_t incarnation = 1) {
  ndo::ObservationSnapshot snapshot;
  snapshot.source = Source(source);
  snapshot.epoch = ndo::FabricEpoch::FromValue(epoch);
  snapshot.incarnation = ndo::Incarnation::FromValue(incarnation);
  snapshot.sequence = ndo::SourceSequence::FromValue(sequence);
  snapshot.target = Target(target);
  snapshot.collected_at = collected_at;
  snapshot.received_at = collected_at;
  snapshot.coverage = ndo::ObservationCoverage::Complete;
  snapshot.capabilities.asserts_absence = true;
  snapshot.capabilities.complete_coverage = true;
  snapshot.capabilities.reports_nested_paths = true;
  snapshot.capabilities.evidence = ndo::EvidenceClass::Synthetic;
  snapshot.evidence = ndo::EvidenceClass::Synthetic;
  return snapshot;
}

inline void AddObservedObject(ndo::ObservationSnapshot& snapshot, const std::string& object,
                              const std::string& field, ndo::Value value) {
  const ndo::ObjectId id = Object(object);
  auto found = snapshot.objects.find(id);
  if (found == snapshot.objects.end()) {
    ndo::ObservedObject entry;
    entry.id = id;
    entry.presence = ndo::ObjectPresence::Present;
    found = snapshot.objects.emplace(id, std::move(entry)).first;
  }
  found->second.fields.insert_or_assign(Path(field), std::move(value));
}

inline void SealSnapshot(ndo::ObservationSnapshot& snapshot) {
  snapshot.snapshot_id = snapshot.ComputeSnapshotId();
}

inline ndo::ObservatoryPolicy SyntheticPolicy() {
  ndo::ObservatoryPolicy policy = ndo::ObservatoryPolicy::Default();
  policy.evidence = ndo::EvidenceClass::Synthetic;
  policy.freshness.ttl_nanos = 300LL * 1000000000LL;
  return policy;
}

/// A policy whose only declared target is require-managed.
inline ndo::ObservatoryPolicy PolicyRequiringTarget(const std::string& target) {
  ndo::ObservatoryPolicy policy = SyntheticPolicy();
  policy.required_targets.push_back(Target(target));
  return policy;
}

/// A temporary directory that removes itself. Used for persistence tests.
class TempDir {
 public:
  explicit TempDir(const std::string& label) {
    path_ = std::filesystem::temp_directory_path() /
            ("ndo_test_" + label + "_" + std::to_string(counter()++));
    std::filesystem::remove_all(path_);
    std::filesystem::create_directories(path_);
  }
  ~TempDir() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  std::string File(const std::string& name) const { return (path_ / name).string(); }
  const std::filesystem::path& path() const { return path_; }

 private:
  static std::uint64_t& counter() {
    static std::uint64_t value = 0;
    return value;
  }
  std::filesystem::path path_;
};

/// Builds an intent document from a value tree: every leaf of the tree becomes
/// a managed field path.
inline void AddIntentTree(ndo::IntentGenerationDocument& document, const std::string& object,
                          const std::string& prefix, const ndo::Value& value) {
  if (value.is_container()) {
    if (const ndo::Value::Map* map = value.as_map(); map != nullptr) {
      for (const auto& entry : *map) {
        const std::string path = prefix.empty() ? entry.first : prefix + "." + entry.first;
        AddIntentTree(document, object, path, entry.second);
      }
      return;
    }
    const ndo::Value::List* list = value.as_list();
    for (std::size_t index = 0; list != nullptr && index < list->size(); ++index) {
      const std::string path = prefix + "[" + std::to_string(index) + "]";
      AddIntentTree(document, object, path, (*list)[index]);
    }
    return;
  }
  AddIntentObject(document, object, prefix, value);
}

inline void AddObservedTree(ndo::ObservationSnapshot& snapshot, const std::string& object,
                            const std::string& prefix, const ndo::Value& value) {
  if (value.is_container()) {
    if (const ndo::Value::Map* map = value.as_map(); map != nullptr) {
      for (const auto& entry : *map) {
        const std::string path = prefix.empty() ? entry.first : prefix + "." + entry.first;
        AddObservedTree(snapshot, object, path, entry.second);
      }
      return;
    }
    const ndo::Value::List* list = value.as_list();
    for (std::size_t index = 0; list != nullptr && index < list->size(); ++index) {
      const std::string path = prefix + "[" + std::to_string(index) + "]";
      AddObservedTree(snapshot, object, path, (*list)[index]);
    }
    return;
  }
  AddObservedObject(snapshot, object, prefix, value);
}

}  // namespace ndotest

#endif  // NDO_TESTS_TEST_SUPPORT_HPP
