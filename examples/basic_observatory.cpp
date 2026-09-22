// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Example: the smallest complete observatory flow.
//
// Commit one intent generation, admit one observation, evaluate, and print the
// finding, its explanation and the reconciliation request a downstream runtime
// would receive. Nothing here contacts a device.

#include <iostream>
#include <string>

#include <summon/network_drift_observatory/engine.hpp>
#include <summon/network_drift_observatory/json.hpp>
#include <summon/network_drift_observatory/report.hpp>

namespace ndo = summon::network_drift_observatory;

namespace {

ndo::NdoTime At(std::int64_t seconds) { return ndo::NdoTime::FromSeconds(seconds); }

}  // namespace

int main() {
  ndo::ObservatoryConfig config;
  config.policy = ndo::ObservatoryPolicy::Default();
  config.policy.evidence = ndo::EvidenceClass::Synthetic;
  config.epoch = ndo::FabricEpoch::FromValue(11);
  config.incarnation = ndo::Incarnation::FromValue(1);

  // A deterministic clock keeps the example reproducible.
  ndo::Observatory observatory(config, []() { return At(1000); });
  if (!observatory.Start().ok()) {
    std::cerr << "the observatory refused to start\n";
    return 1;
  }

  ndo::IntentGenerationDocument intent;
  intent.target = ndo::TargetId::TryParse("switch/leaf-7").value();
  intent.generation = ndo::IntentGeneration::FromValue(4);
  intent.epoch = config.epoch;
  intent.authority = ndo::IntentAuthority::IntentFabric;
  intent.policy = ndo::PolicyId::Trusted("policy/default");
  intent.authored_at = At(900);
  intent.evidence = ndo::EvidenceClass::Synthetic;

  ndo::IntentObject port;
  port.id = ndo::ObjectId::TryParse("port/eth0").value();
  ndo::IntentField mtu;
  mtu.path = ndo::FieldPath::TryParse("mtu", 8, 64).value();
  mtu.intended = ndo::Value::MakeInt(1500);
  port.fields.emplace(mtu.path, mtu);
  intent.objects.emplace(port.id, port);

  ndo::IntentCommitReport commit;
  if (!observatory.PublishIntent(intent, commit).ok()) {
    std::cerr << "intent was refused\n";
    return 1;
  }
  std::cout << "committed intent generation " << commit.committed_generation.value() << " for "
            << commit.target.str() << "\n";

  ndo::ObservationSnapshot snapshot;
  snapshot.source = ndo::SourceId::TryParse("collector/leaf-7").value();
  snapshot.epoch = config.epoch;
  snapshot.incarnation = ndo::Incarnation::FromValue(3);
  snapshot.sequence = ndo::SourceSequence::FromValue(1);
  snapshot.target = intent.target;
  snapshot.collected_at = At(995);
  snapshot.received_at = At(1000);
  snapshot.coverage = ndo::ObservationCoverage::Complete;
  snapshot.capabilities.asserts_absence = true;
  snapshot.capabilities.complete_coverage = true;
  snapshot.capabilities.reports_nested_paths = true;
  snapshot.evidence = ndo::EvidenceClass::Synthetic;
  ndo::ObservedObject observed_port;
  observed_port.id = port.id;
  observed_port.presence = ndo::ObjectPresence::Present;
  observed_port.fields.emplace(mtu.path, ndo::Value::MakeInt(9000));
  snapshot.objects.emplace(observed_port.id, observed_port);
  snapshot.snapshot_id = snapshot.ComputeSnapshotId();

  ndo::ObservationAdmission admission;
  if (!observatory.IngestObservation(snapshot, admission).ok()) {
    std::cerr << "the observation was refused\n";
    return 1;
  }

  const ndo::Result<ndo::EvaluationOutcome> outcome = observatory.Evaluate();
  if (!outcome.ok()) {
    std::cerr << "evaluation failed: " << outcome.status().detail << "\n";
    return 1;
  }
  std::cout << "compliant=" << (outcome.value().targets.front().compliant ? "yes" : "no")
            << " decidable="
            << (outcome.value().targets.front().compliance_decidable ? "yes" : "no") << "\n";

  ndo::QuerySpec query;
  query.min_severity = ndo::Severity::Low;
  const ndo::Result<ndo::QueryResult> page = observatory.Query(query);
  if (!page.ok()) {
    std::cerr << "query failed\n";
    return 1;
  }
  for (const ndo::Finding& finding : page.value().findings) {
    std::cout << "finding " << finding.id.ToShortHex() << ": " << finding.summary << "\n";
    std::cout << "  action: " << ndo::ToText(ndo::ActionFor(finding.klass)) << "\n";
  }

  ndo::ReportSpec report;
  report.id = ndo::ReportId::Trusted("report/example");
  std::string json;
  if (!ndo::BuildReportJson(observatory, report, json).ok()) {
    std::cerr << "report failed\n";
    return 1;
  }
  std::cout << "report bytes: " << json.size() << "\n";
  observatory.Stop();
  return 0;
}
