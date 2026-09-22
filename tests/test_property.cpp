// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Randomized property tests over nested state trees.
//
// Every property is stated over a seeded generator, so a failure is
// reproducible from the printed seed. The properties are invariants of the
// runtime, not examples: they must hold for every generated tree.

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

using namespace ndotest;

namespace {

/// A generator of nested state trees whose leaves are scalars.
class TreeGenerator {
 public:
  explicit TreeGenerator(std::uint64_t seed) : rng_(seed) {}

  ndo::Value Tree(std::size_t depth) {
    if (depth == 0 || rng_.Chance(45)) {
      return Scalar();
    }
    if (rng_.Chance(50)) {
      const std::size_t count = 1 + rng_.Below(3);
      ndo::Value::List list;
      for (std::size_t index = 0; index < count; ++index) {
        list.push_back(Tree(depth - 1));
      }
      return ndo::Value::MakeList(std::move(list));
    }
    const std::size_t count = 1 + rng_.Below(3);
    ndo::Value::Map map;
    for (std::size_t index = 0; index < count; ++index) {
      map.emplace(Key(), Tree(depth - 1));
    }
    return ndo::Value::MakeMap(std::move(map));
  }

  std::string Key() {
    static const char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz";
    std::string key;
    const std::size_t length = 1 + rng_.Below(6);
    for (std::size_t index = 0; index < length; ++index) {
      key.push_back(kAlphabet[rng_.Below(sizeof(kAlphabet) - 1)]);
    }
    return key;
  }

  ndo::Value Scalar() {
    switch (rng_.Below(5)) {
      case 0:
        return ndo::Value::MakeInt(static_cast<std::int64_t>(rng_.Below(10000)) - 5000);
      case 1:
        return ndo::Value::MakeUint(rng_.Below(10000));
      case 2:
        return ndo::Value::MakeBool(rng_.Chance(50));
      case 3: {
        const auto value = ndo::Value::TryMakeDouble(static_cast<double>(rng_.Below(1000)) / 8.0);
        return value.has_value() ? *value : ndo::Value::MakeInt(0);
      }
      default:
        return ndo::Value::MakeString("v" + std::to_string(rng_.Below(1000)));
    }
  }

  /// A tree whose root is always a member set, so every leaf has a non-empty
  /// path and the root path is never used as a field.
  ndo::Value RootTree(std::size_t depth) {
    ndo::Value::Map map;
    const std::size_t count = 1 + rng_.Below(3);
    for (std::size_t index = 0; index < count; ++index) {
      map.emplace(Key(), Tree(depth));
    }
    return ndo::Value::MakeMap(std::move(map));
  }

  /// A scalar guaranteed to differ from the supplied one.
  ndo::Value DifferentScalar(const ndo::Value& reference) {
    for (int attempt = 0; attempt < 32; ++attempt) {
      const ndo::Value candidate = Scalar();
      if (ndo::RelateValues(reference, candidate, ndo::NumericEquivalence::Numeric) ==
          ndo::ValueRelation::Different) {
        return candidate;
      }
    }
    // A structurally different kind always differs.
    if (reference.as_string() != nullptr) {
      return ndo::Value::MakeInt(4242);
    }
    return ndo::Value::MakeString("perturbed");
  }

 private:
  Rng rng_;
};

/// Collects every leaf path of a tree, in canonical order.
void CollectLeaves(const ndo::Value& value, const std::string& prefix,
                   std::vector<std::pair<std::string, ndo::Value>>& out) {
  if (const ndo::Value::Map* map = value.as_map(); map != nullptr) {
    for (const auto& entry : *map) {
      CollectLeaves(entry.second, prefix.empty() ? entry.first : prefix + "." + entry.first, out);
    }
    return;
  }
  if (const ndo::Value::List* list = value.as_list(); list != nullptr) {
    for (std::size_t index = 0; index < list->size(); ++index) {
      CollectLeaves((*list)[index], prefix + "[" + std::to_string(index) + "]", out);
    }
    return;
  }
  out.emplace_back(prefix, value);
}

/// Replaces the leaf at the given path with a different value.
bool PerturbLeaf(ndo::Value& value, const std::string& path, const ndo::Value& replacement) {
  const auto parsed = ndo::FieldPath::TryParse(path, 32, 256);
  if (!parsed.has_value()) {
    return false;
  }
  const std::vector<ndo::PathSegment>& segments = parsed->segments();
  if (segments.empty()) {
    return false;
  }
  ndo::Value* cursor = &value;
  for (std::size_t index = 0; index < segments.size(); ++index) {
    const ndo::PathSegment& segment = segments[index];
    const bool last = index + 1 == segments.size();
    if (segment.kind == ndo::PathSegment::Kind::Key) {
      ndo::Value::Map* map =
          cursor->as_map() != nullptr ? const_cast<ndo::Value::Map*>(cursor->as_map()) : nullptr;
      if (map == nullptr) {
        return false;
      }
      const auto found = map->find(segment.key);
      if (found == map->end()) {
        return false;
      }
      if (last) {
        found->second = replacement;
        return true;
      }
      cursor = &found->second;
      continue;
    }
    ndo::Value::List* list =
        cursor->as_list() != nullptr ? const_cast<ndo::Value::List*>(cursor->as_list()) : nullptr;
    if (list == nullptr || segment.index >= list->size()) {
      return false;
    }
    if (last) {
      (*list)[segment.index] = replacement;
      return true;
    }
    cursor = &(*list)[segment.index];
  }
  return false;
}

struct Scenario {
  ndo::FindingLedger ledger;
  std::size_t leaves{0};
};

/// Builds a ledger with one intent object holding the whole tree, plus one
/// observation carrying the (possibly perturbed) tree.
Scenario BuildScenario(const ndo::Value& intent_tree, const ndo::Value& observed_tree) {
  Scenario scenario;
  ndo::IntentGenerationDocument intent = MakeIntent("switch/prop", 1);
  AddIntentTree(intent, "object/0", "", intent_tree);
  ndo::IntentCommitReport commit;
  NDO_CHECK_STATUS(scenario.ledger.CommitIntent(intent, FixedTime(100), commit));

  ndo::ObservationSnapshot snapshot = MakeSnapshot("collector/a", "switch/prop", 1, FixedTime(995));
  AddObservedTree(snapshot, "object/0", "", observed_tree);
  SealSnapshot(snapshot);
  ndo::ObservationAdmission admission;
  NDO_CHECK_STATUS(scenario.ledger.RecordObservation(snapshot, ndo::FreshnessVerdict{}, false, admission));
  return scenario;
}

ndo::EvaluationOutcome Compare(const ndo::FindingLedger& ledger) {
  const ndo::Result<ndo::EvaluationOutcome> outcome =
      ndo::EvaluateLedgerOnce(ledger, SyntheticPolicy(), ndo::RuntimeLimits{},
                              ndo::FabricEpoch::FromValue(1), ndo::Incarnation::FromValue(1),
                              FixedTime(1000));
  if (!outcome.ok()) {
    NDO_CHECK(false);
    return ndo::EvaluationOutcome{};
  }
  return outcome.value();
}

}  // namespace

NDO_TEST(PropertyJsonRoundTripPreservesEveryGeneratedTree) {
  for (std::uint64_t seed = 1; seed <= 40; ++seed) {
    TreeGenerator generator(seed);
    const ndo::Value tree = generator.RootTree(4);
    const std::string canonical = ndo::WriteCanonicalJson(tree);
    const std::string pretty = ndo::WritePrettyJson(tree, 2);

    ndo::Value from_canonical;
    ndo::Value from_pretty;
    NDO_CHECK(ndo::ParseJson(canonical, ndo::RuntimeLimits{}, from_canonical).ok());
    NDO_CHECK(ndo::ParseJson(pretty, ndo::RuntimeLimits{}, from_pretty).ok());
    NDO_CHECK(from_canonical == tree);
    NDO_CHECK(from_pretty == tree);
    // The codec is canonical: re-encoding a parsed document is a fixed point.
    NDO_CHECK_EQ(ndo::WriteCanonicalJson(from_canonical), canonical);
    NDO_CHECK_EQ(ndo::WriteCanonicalJson(from_pretty), canonical);
  }
}

NDO_TEST(PropertyValueComparisonIsSymmetricAndReflexive) {
  for (std::uint64_t seed = 100; seed <= 140; ++seed) {
    TreeGenerator generator(seed);
    const ndo::Value first = generator.RootTree(3);
    const ndo::Value second = generator.RootTree(3);

    NDO_CHECK(ndo::RelateValues(first, first, ndo::NumericEquivalence::Numeric) ==
              ndo::ValueRelation::Equal);
    NDO_CHECK(ndo::RelateValues(second, second, ndo::NumericEquivalence::Numeric) ==
              ndo::ValueRelation::Equal);
    for (const ndo::NumericEquivalence equivalence :
         {ndo::NumericEquivalence::Exact, ndo::NumericEquivalence::Numeric}) {
      const ndo::ValueRelation forward = ndo::RelateValues(first, second, equivalence);
      const ndo::ValueRelation backward = ndo::RelateValues(second, first, equivalence);
      NDO_CHECK(forward == backward);
      // Structural equality and the relation agree.
      if (first == second) {
        NDO_CHECK(forward == ndo::ValueRelation::Equal);
      }
    }
    // The canonical encoding is injective enough to detect structural equality.
    NDO_CHECK_EQ(first == second, first.ToCanonicalText() == second.ToCanonicalText());
    // Ordering is antisymmetric.
    const std::strong_ordering forward = first <=> second;
    const std::strong_ordering backward = second <=> first;
    if (forward == std::strong_ordering::less) {
      NDO_CHECK(backward == std::strong_ordering::greater);
    } else if (forward == std::strong_ordering::greater) {
      NDO_CHECK(backward == std::strong_ordering::less);
    } else {
      NDO_CHECK(backward == std::strong_ordering::equal);
    }
  }
}

NDO_TEST(PropertyIdenticalTreesProduceNoDrift) {
  for (std::uint64_t seed = 200; seed <= 230; ++seed) {
    TreeGenerator generator(seed);
    const ndo::Value tree = generator.RootTree(4);
    const Scenario scenario = BuildScenario(tree, tree);
    const ndo::EvaluationOutcome outcome = Compare(scenario.ledger);
    NDO_CHECK_EQ(outcome.targets.size(), std::size_t{1});
    const ndo::TargetEvaluation& evaluation = outcome.targets.front();
    NDO_CHECK_EQ(evaluation.drafts.size(), std::size_t{0});
    NDO_CHECK(evaluation.compliance_decidable);
    NDO_CHECK(evaluation.compliant);
  }
}

NDO_TEST(PropertyOnePerturbedLeafProducesExactlyOneFinding) {
  for (std::uint64_t seed = 300; seed <= 340; ++seed) {
    TreeGenerator generator(seed);
    const ndo::Value tree = generator.RootTree(4);
    std::vector<std::pair<std::string, ndo::Value>> leaves;
    CollectLeaves(tree, "", leaves);
    if (leaves.empty()) {
      continue;
    }
    const std::size_t chosen = static_cast<std::size_t>(seed % leaves.size());
    const std::string path = leaves[chosen].first;
    ndo::Value observed = tree;
    const ndo::Value replacement = generator.DifferentScalar(leaves[chosen].second);
    NDO_CHECK(PerturbLeaf(observed, path, replacement));

    const Scenario scenario = BuildScenario(tree, observed);
    const ndo::EvaluationOutcome outcome = Compare(scenario.ledger);
    const ndo::TargetEvaluation& evaluation = outcome.targets.front();
    NDO_CHECK_EQ(evaluation.drafts.size(), std::size_t{1});
    if (evaluation.drafts.size() == 1) {
      const ndo::FindingDraft& draft = evaluation.drafts.front();
      NDO_CHECK_EQ(draft.path.ToText(), path);
      NDO_CHECK(draft.klass == ndo::DriftClass::ValueMismatch);
      NDO_CHECK(draft.intended == leaves[chosen].second);
      NDO_CHECK(draft.observed == replacement);
    }
    NDO_CHECK(!evaluation.compliant);
    NDO_CHECK(evaluation.compliance_decidable);
  }
}

NDO_TEST(PropertyComparisonIsReversibleInRoles) {
  // Swapping which side is intent and which is observation must mirror every
  // difference: a value mismatch stays a value mismatch with the two values
  // exchanged, a field only intent declares becomes a field only the
  // observation declares, and the location is unchanged.
  for (std::uint64_t seed = 400; seed <= 420; ++seed) {
    TreeGenerator generator(seed);
    const ndo::Value first = generator.RootTree(3);
    const ndo::Value second = generator.RootTree(3);
    std::vector<std::pair<std::string, ndo::Value>> first_leaves;
    std::vector<std::pair<std::string, ndo::Value>> second_leaves;
    CollectLeaves(first, "", first_leaves);
    CollectLeaves(second, "", second_leaves);
    if (first_leaves.empty() || second_leaves.empty()) {
      continue;
    }
    const Scenario forward = BuildScenario(first, second);
    const Scenario backward = BuildScenario(second, first);
    const ndo::EvaluationOutcome forward_outcome = Compare(forward.ledger);
    const ndo::EvaluationOutcome backward_outcome = Compare(backward.ledger);

    std::map<std::string, const ndo::FindingDraft*> forward_by_path;
    std::map<std::string, const ndo::FindingDraft*> backward_by_path;
    for (const ndo::FindingDraft& draft : forward_outcome.targets.front().drafts) {
      forward_by_path.emplace(draft.path.ToText(), &draft);
    }
    for (const ndo::FindingDraft& draft : backward_outcome.targets.front().drafts) {
      backward_by_path.emplace(draft.path.ToText(), &draft);
    }
    NDO_CHECK_EQ(forward_by_path.size(), backward_by_path.size());
    for (const auto& entry : forward_by_path) {
      const ndo::FindingDraft& lhs = *entry.second;
      const auto mirrored = backward_by_path.find(entry.first);
      NDO_CHECK(mirrored != backward_by_path.end());
      if (mirrored == backward_by_path.end()) {
        continue;
      }
      const ndo::FindingDraft& rhs = *mirrored->second;
      switch (lhs.klass) {
        case ndo::DriftClass::ValueMismatch:
          NDO_CHECK(rhs.klass == ndo::DriftClass::ValueMismatch);
          NDO_CHECK(rhs.has_intended && rhs.has_observed);
          NDO_CHECK(lhs.intended == rhs.observed);
          NDO_CHECK(lhs.observed == rhs.intended);
          break;
        case ndo::DriftClass::FieldMissing:
          NDO_CHECK(rhs.klass == ndo::DriftClass::FieldUnexpected);
          NDO_CHECK(rhs.has_observed && !rhs.has_intended);
          NDO_CHECK(lhs.intended == rhs.observed);
          break;
        case ndo::DriftClass::FieldUnexpected:
          NDO_CHECK(rhs.klass == ndo::DriftClass::FieldMissing);
          NDO_CHECK(rhs.has_intended && !rhs.has_observed);
          NDO_CHECK(lhs.observed == rhs.intended);
          break;
        default:
          NDO_CHECK(rhs.klass == lhs.klass);
          break;
      }
    }
    // The two directions agree about whether the pair differs at all.
    NDO_CHECK_EQ(forward_outcome.DraftCount() == 0, backward_outcome.DraftCount() == 0);
  }
}

NDO_TEST(PropertyRepeatedEvaluationDeduplicatesEveryTime) {
  for (std::uint64_t seed = 500; seed <= 520; ++seed) {
    TreeGenerator generator(seed);
    const ndo::Value intent_tree = generator.RootTree(3);
    ndo::Value observed_tree = intent_tree;
    std::vector<std::pair<std::string, ndo::Value>> leaves;
    CollectLeaves(observed_tree, "", leaves);
    if (leaves.empty()) {
      continue;
    }
    NDO_CHECK(PerturbLeaf(observed_tree, leaves.front().first,
                          generator.DifferentScalar(leaves.front().second)));

    ndo::ObservatoryConfig config;
    config.policy = SyntheticPolicy();
    config.epoch = ndo::FabricEpoch::FromValue(1);
    config.incarnation = ndo::Incarnation::FromValue(1);
    ndo::Observatory observatory(config, []() { return FixedTime(1000); });
    NDO_CHECK_STATUS(observatory.Start());

    ndo::IntentGenerationDocument intent = MakeIntent("switch/prop", 1);
    AddIntentTree(intent, "object/0", "", intent_tree);
    ndo::IntentCommitReport commit;
    NDO_CHECK_STATUS(observatory.PublishIntent(intent, commit));
    ndo::ObservationSnapshot snapshot =
        MakeSnapshot("collector/a", "switch/prop", 1, FixedTime(995));
    AddObservedTree(snapshot, "object/0", "", observed_tree);
    SealSnapshot(snapshot);
    ndo::ObservationAdmission admission;
    NDO_CHECK_STATUS(observatory.IngestObservation(snapshot, admission));

    for (int repeat = 0; repeat < 5; ++repeat) {
      const ndo::Result<ndo::EvaluationOutcome> outcome =
          observatory.EvaluateAt(FixedTime(1000 + repeat), true);
      NDO_CHECK(outcome.ok());
      if (!outcome.ok()) {
        break;
      }
      NDO_CHECK_EQ(outcome.value().DraftCount(), std::size_t{1});
    }
    const ndo::LedgerStats stats = observatory.Stats();
    NDO_CHECK_EQ(stats.findings, std::size_t{1});
    NDO_CHECK_EQ(stats.live_findings, std::size_t{1});
    ndo::QuerySpec spec;
    const ndo::Result<ndo::QueryResult> page = observatory.Query(spec);
    NDO_CHECK(page.ok());
    if (page.ok() && !page.value().findings.empty()) {
      NDO_CHECK_EQ(page.value().findings.front().observation_count, std::uint64_t{5});
    }
    observatory.Stop();
  }
}

NDO_TEST(PropertyEvaluationOutcomeIsReproducibleFromASeed) {
  for (std::uint64_t seed = 600; seed <= 610; ++seed) {
    TreeGenerator generator(seed);
    const ndo::Value tree = generator.RootTree(4);
    ndo::Value observed = tree;
    std::vector<std::pair<std::string, ndo::Value>> leaves;
    CollectLeaves(observed, "", leaves);
    if (leaves.empty()) {
      continue;
    }
    const std::size_t chosen = static_cast<std::size_t>(seed % leaves.size());
    NDO_CHECK(PerturbLeaf(observed, leaves[chosen].first,
                          generator.DifferentScalar(leaves[chosen].second)));

    const Scenario first = BuildScenario(tree, observed);
    const Scenario second = BuildScenario(tree, observed);
    const ndo::EvaluationOutcome first_outcome = Compare(first.ledger);
    const ndo::EvaluationOutcome second_outcome = Compare(second.ledger);
    NDO_CHECK(first_outcome.ComputeDigest() == second_outcome.ComputeDigest());
    NDO_CHECK_EQ(first_outcome.DraftCount(), second_outcome.DraftCount());
    NDO_CHECK_EQ(ndo::WriteCanonicalJson(ndo::EncodeObservationDocument(
                     first.ledger.ObservationsFor(Target("switch/prop")).empty()
                         ? ndo::ObservationSnapshot{}
                         : first.ledger.ObservationsFor(Target("switch/prop")).front().snapshot)),
                 ndo::WriteCanonicalJson(ndo::EncodeObservationDocument(
                     second.ledger.ObservationsFor(Target("switch/prop")).front().snapshot)));
  }
}
