// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Example: two sources, disagreement, and how the observatory explains it.
//
// Two sources report the same target with different values. The observatory
// does not pick a winner silently: it records a source-conflict finding with
// both pieces of evidence attached, and it refuses to declare compliance.

#include <initializer_list>
#include <iostream>
#include <string>

#include <summon/network_drift_observatory/engine.hpp>
#include <summon/network_drift_observatory/report.hpp>

namespace ndo = summon::network_drift_observatory;

namespace {

ndo::NdoTime At(std::int64_t seconds) { return ndo::NdoTime::FromSeconds(seconds); }

ndo::ObservationSnapshot Snapshot(const std::string& source, std::int64_t value,
                                  std::uint64_t sequence) {
  ndo::ObservationSnapshot snapshot;
  snapshot.source = ndo::SourceId::TryParse(source).value();
  snapshot.epoch = ndo::FabricEpoch::FromValue(1);
  snapshot.incarnation = ndo::Incarnation::FromValue(1);
  snapshot.sequence = ndo::SourceSequence::FromValue(sequence);
  snapshot.target = ndo::TargetId::TryParse("switch/pair").value();
  snapshot.collected_at = At(995);
  snapshot.received_at = At(1000);
  snapshot.coverage = ndo::ObservationCoverage::Complete;
  snapshot.capabilities.asserts_absence = true;
  snapshot.capabilities.complete_coverage = true;
  snapshot.evidence = ndo::EvidenceClass::Synthetic;
  ndo::ObservedObject object;
  object.id = ndo::ObjectId::TryParse("port/eth0").value();
  object.presence = ndo::ObjectPresence::Present;
  object.fields.emplace(ndo::FieldPath::TryParse("mtu", 8, 64).value(),
                        ndo::Value::MakeInt(value));
  snapshot.objects.emplace(object.id, object);
  snapshot.snapshot_id = snapshot.ComputeSnapshotId();
  return snapshot;
}

}  // namespace

int main() {
  ndo::ObservatoryConfig config;
  config.policy = ndo::ObservatoryPolicy::Default();
  config.policy.evidence = ndo::EvidenceClass::Synthetic;
  config.epoch = ndo::FabricEpoch::FromValue(1);
  config.incarnation = ndo::Incarnation::FromValue(1);

  ndo::Observatory observatory(config, []() { return At(1000); });
  static_cast<void>(observatory.Start());

  ndo::IntentGenerationDocument intent;
  intent.target = ndo::TargetId::TryParse("switch/pair").value();
  intent.generation = ndo::IntentGeneration::FromValue(1);
  intent.epoch = config.epoch;
  intent.authority = ndo::IntentAuthority::ConfigurationFabric;
  intent.policy = ndo::PolicyId::Trusted("policy/default");
  intent.authored_at = At(900);
  intent.evidence = ndo::EvidenceClass::Synthetic;
  ndo::IntentObject object;
  object.id = ndo::ObjectId::TryParse("port/eth0").value();
  ndo::IntentField field;
  field.path = ndo::FieldPath::TryParse("mtu", 8, 64).value();
  field.intended = ndo::Value::MakeInt(1500);
  object.fields.emplace(field.path, field);
  intent.objects.emplace(object.id, object);
  ndo::IntentCommitReport commit;
  static_cast<void>(observatory.PublishIntent(intent, commit));

  const ndo::ObservationSnapshot snapshots[] = {Snapshot("collector/north", 1500, 1),
                                                Snapshot("collector/south", 9000, 1)};
  for (const ndo::ObservationSnapshot& snapshot : snapshots) {
    ndo::ObservationAdmission admission;
    if (!observatory.IngestObservation(snapshot, admission).ok()) {
      std::cerr << "observation was refused\n";
      return 1;
    }
  }

  const ndo::Result<ndo::EvaluationOutcome> outcome = observatory.Evaluate();
  if (!outcome.ok()) {
    std::cerr << "evaluation failed\n";
    return 1;
  }
  ndo::QuerySpec query;
  const ndo::Result<ndo::QueryResult> page = observatory.Query(query);
  if (page.ok()) {
    for (const ndo::Finding& finding : page.value().findings) {
      std::cout << ndo::ToText(finding.klass) << " at " << finding.identity.path.Describe() << ": "
                << finding.summary << "\n";
      for (const ndo::EvidenceRef& reference : finding.evidence) {
        std::cout << "  evidence: " << reference.source.str() << " -> "
                  << reference.content_digest.ToShortHex() << "\n";
      }
    }
  }
  std::cout << "compliance decidable="
            << (outcome.value().targets.front().compliance_decidable ? "yes" : "no") << "\n";
  observatory.Stop();
  return 0;
}
