// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Example: conservative recovery across a restart.
//
// Evidence that survives a restart is never treated as current. The example
// saves a ledger with a live finding, loads it into a fresh incarnation, and
// shows that the finding survives while the evidence loses its freshness.

#include <cstdio>
#include <iostream>
#include <string>

#include <summon/network_drift_observatory/engine.hpp>
#include <summon/network_drift_observatory/persistence.hpp>
#include <summon/network_drift_observatory/report.hpp>

namespace ndo = summon::network_drift_observatory;

namespace {

ndo::NdoTime At(std::int64_t seconds) { return ndo::NdoTime::FromSeconds(seconds); }

void Seed(ndo::Observatory& observatory) {
  ndo::IntentGenerationDocument intent;
  intent.target = ndo::TargetId::TryParse("switch/restart").value();
  intent.generation = ndo::IntentGeneration::FromValue(2);
  intent.epoch = ndo::FabricEpoch::FromValue(1);
  intent.authority = ndo::IntentAuthority::IntentFabric;
  intent.policy = ndo::PolicyId::Trusted("policy/default");
  intent.authored_at = At(100);
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

  ndo::ObservationSnapshot snapshot;
  snapshot.source = ndo::SourceId::TryParse("collector/restart").value();
  snapshot.epoch = ndo::FabricEpoch::FromValue(1);
  snapshot.incarnation = ndo::Incarnation::FromValue(1);
  snapshot.sequence = ndo::SourceSequence::FromValue(1);
  snapshot.target = intent.target;
  snapshot.collected_at = At(995);
  snapshot.received_at = At(1000);
  snapshot.coverage = ndo::ObservationCoverage::Complete;
  snapshot.capabilities.asserts_absence = true;
  snapshot.capabilities.complete_coverage = true;
  snapshot.evidence = ndo::EvidenceClass::Synthetic;
  ndo::ObservedObject observed;
  observed.id = object.id;
  observed.presence = ndo::ObjectPresence::Present;
  observed.fields.emplace(field.path, ndo::Value::MakeInt(9000));
  snapshot.objects.emplace(observed.id, observed);
  snapshot.snapshot_id = snapshot.ComputeSnapshotId();
  ndo::ObservationAdmission admission;
  static_cast<void>(observatory.IngestObservation(snapshot, admission));
  static_cast<void>(observatory.Evaluate());
}

}  // namespace

int main() {
  const std::string path = "ndo_example_restart.ledger";

  ndo::ObservatoryConfig first_config;
  first_config.policy = ndo::ObservatoryPolicy::Default();
  first_config.policy.evidence = ndo::EvidenceClass::Synthetic;
  first_config.epoch = ndo::FabricEpoch::FromValue(1);
  first_config.incarnation = ndo::Incarnation::FromValue(1);
  {
    ndo::Observatory first(first_config, []() { return At(1000); });
    static_cast<void>(first.Start());
    Seed(first);
    const ndo::LedgerStats stats = first.Stats();
    std::cout << "before restart: findings=" << stats.findings << " live=" << stats.live_findings
              << "\n";
    if (!first.Save(path).ok()) {
      std::cerr << "the ledger could not be saved\n";
      return 1;
    }
    first.Stop();
  }

  ndo::ObservatoryConfig second_config = first_config;
  second_config.incarnation = ndo::Incarnation::FromValue(2);
  ndo::Observatory second(second_config, []() { return At(2000); });
  ndo::LedgerRecoveryReport recovery;
  const ndo::Status loaded = second.Load(path, recovery);
  if (!loaded.ok()) {
    std::cerr << "the ledger could not be recovered: " << loaded.detail << "\n";
    return 1;
  }
  static_cast<void>(second.Start());
  std::cout << "recovered: findings=" << recovery.findings_restored
            << " observations=" << recovery.observations_restored
            << " conservative=" << (recovery.conservative ? "yes" : "no") << "\n";

  const ndo::Result<ndo::EvaluationOutcome> outcome = second.Evaluate();
  if (!outcome.ok()) {
    std::cerr << "evaluation after recovery failed\n";
    return 1;
  }
  const ndo::TargetEvaluation& evaluation = outcome.value().targets.front();
  std::cout << "after restart: best evidence " << ndo::ToText(evaluation.best_freshness)
            << ", compliance decidable=" << (evaluation.compliance_decidable ? "yes" : "no")
            << "\n";

  ndo::QuerySpec query;
  const ndo::Result<ndo::QueryResult> page = second.Query(query);
  if (page.ok()) {
    for (const ndo::Finding& finding : page.value().findings) {
      std::cout << "finding " << finding.id.ToShortHex()
                << " state=" << ndo::ToText(finding.state)
                << " evidence=" << ndo::ToText(finding.evidence_freshness) << "\n";
    }
  }
  second.Stop();
  std::remove(path.c_str());
  return 0;
}
