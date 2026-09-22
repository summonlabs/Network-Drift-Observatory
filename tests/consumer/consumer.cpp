// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Consumer program built outside this repository's build tree.
//
// It links the installed package through find_package and exercises the public
// API surface end to end: policy, intent, observation, evaluation, query,
// persistence and report.

#include <cstdlib>
#include <iostream>
#include <string>

#include <summon/network_drift_observatory/engine.hpp>
#include <summon/network_drift_observatory/interchange.hpp>
#include <summon/network_drift_observatory/json.hpp>
#include <summon/network_drift_observatory/persistence.hpp>
#include <summon/network_drift_observatory/report.hpp>
#include <summon/network_drift_observatory/version.hpp>

namespace ndo = summon::network_drift_observatory;

int main() {
  ndo::ObservatoryConfig config;
  config.policy = ndo::ObservatoryPolicy::Default();
  config.policy.evidence = ndo::EvidenceClass::Synthetic;
  config.epoch = ndo::FabricEpoch::FromValue(1);
  config.incarnation = ndo::Incarnation::FromValue(1);

  ndo::Observatory observatory(config, []() { return ndo::NdoTime::FromSeconds(1000); });
  if (!observatory.Start().ok()) {
    std::cerr << "start failed\n";
    return EXIT_FAILURE;
  }

  ndo::IntentGenerationDocument intent;
  intent.target = ndo::TargetId::TryParse("switch/consumer").value();
  intent.generation = ndo::IntentGeneration::FromValue(3);
  intent.epoch = ndo::FabricEpoch::FromValue(1);
  intent.authority = ndo::IntentAuthority::ConfigurationFabric;
  intent.policy = ndo::PolicyId::Trusted("policy/default");
  intent.authored_at = ndo::NdoTime::FromSeconds(900);
  intent.evidence = ndo::EvidenceClass::Synthetic;
  ndo::IntentObject object;
  object.id = ndo::ObjectId::TryParse("port/eth0").value();
  ndo::IntentField field;
  field.path = ndo::FieldPath::TryParse("mtu", 8, 64).value();
  field.intended = ndo::Value::MakeInt(1500);
  object.fields.emplace(field.path, field);
  intent.objects.emplace(object.id, object);

  ndo::IntentCommitReport commit;
  if (!observatory.PublishIntent(intent, commit).ok()) {
    std::cerr << "intent publish failed\n";
    return EXIT_FAILURE;
  }

  ndo::ObservationSnapshot snapshot;
  snapshot.source = ndo::SourceId::TryParse("collector/consumer").value();
  snapshot.epoch = ndo::FabricEpoch::FromValue(1);
  snapshot.incarnation = ndo::Incarnation::FromValue(1);
  snapshot.sequence = ndo::SourceSequence::FromValue(1);
  snapshot.target = intent.target;
  snapshot.collected_at = ndo::NdoTime::FromSeconds(995);
  snapshot.received_at = snapshot.collected_at;
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
  if (!observatory.IngestObservation(snapshot, admission).ok()) {
    std::cerr << "observation refused\n";
    return EXIT_FAILURE;
  }

  const ndo::Result<ndo::EvaluationOutcome> outcome = observatory.Evaluate();
  if (!outcome.ok() || outcome.value().targets.size() != 1) {
    std::cerr << "evaluation failed\n";
    return EXIT_FAILURE;
  }
  if (outcome.value().targets.front().drafts.size() != 1) {
    std::cerr << "expected one drift draft\n";
    return EXIT_FAILURE;
  }

  ndo::QuerySpec query;
  const ndo::Result<ndo::QueryResult> page = observatory.Query(query);
  if (!page.ok() || page.value().findings.size() != 1) {
    std::cerr << "query failed\n";
    return EXIT_FAILURE;
  }
  if (page.value().findings.front().klass != ndo::DriftClass::ValueMismatch) {
    std::cerr << "unexpected drift class\n";
    return EXIT_FAILURE;
  }

  ndo::ReportSpec report_spec;
  report_spec.id = ndo::ReportId::Trusted("report/consumer");
  std::string report;
  if (!ndo::BuildReportJson(observatory, report_spec, report).ok() || report.empty()) {
    std::cerr << "report failed\n";
    return EXIT_FAILURE;
  }

  std::cout << "consumer ok: " << ndo::kProductName << " " << ndo::kVersionString
            << ", findings=" << page.value().findings.size() << "\n";
  observatory.Stop();
  return EXIT_SUCCESS;
}
