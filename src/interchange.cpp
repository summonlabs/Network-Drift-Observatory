// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "summon/network_drift_observatory/interchange.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "json_help.hpp"
#include "summon/network_drift_observatory/json.hpp"
#include "summon/network_drift_observatory/version.hpp"

namespace summon {
namespace network_drift_observatory {
namespace {

using detail::CheckMembers;
using detail::FindMember;
using detail::MemberError;
using detail::OptionalBool;
using detail::OptionalInt;
using detail::OptionalString;
using detail::OptionalUint;
using detail::RequireList;
using detail::RequireMap;
using detail::RequireObject;
using detail::RequireString;
using detail::RequireUint;

/// Refuses a document whose declared schema is missing or is not the schema
/// this decoder implements. A versioned interchange document names itself.
Status RequireSchema(const Value::Map& map, const char* expected, const char* what) {
  std::string schema;
  Status status = detail::RequireString(map, "schema", what, schema);
  if (!status.ok()) {
    return status;
  }
  if (schema != expected) {
    return Status::Rejected(ReasonCode::LedgerSchemaUnsupported,
                            std::string(what) + ": schema " + schema + " is not supported");
  }
  return Status(StatusCode::Ok, ReasonCode::None);
}

Value EncodeField(const FieldPath& path, const Value& value) {
  Value::Map map;
  map.emplace("path", Value::MakeString(path.ToText()));
  map.emplace("value", value);
  return Value::MakeMap(std::move(map));
}

Status DecodeFieldPath(const Value::Map& map, const RuntimeLimits& limits, const char* what,
                       FieldPath& out) {
  std::string text;
  Status status = RequireString(map, "path", what, text);
  if (!status.ok()) {
    return status;
  }
  const auto parsed = FieldPath::TryParse(text, limits.max_path_segments, limits.max_path_key_bytes);
  if (!parsed.has_value()) {
    return MemberError(what, "path", "is not a valid field path");
  }
  out = *parsed;
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status DecodeIdentity(const Value::Map& map, std::string_view name, const char* what, bool required,
                      std::string& out) {
  const Value* member = FindMember(map, name);
  if (member == nullptr) {
    if (required) {
      return MemberError(what, name, "missing required member");
    }
    return Status(StatusCode::Ok, ReasonCode::None);
  }
  const std::string* text = member->as_string();
  if (text == nullptr) {
    return MemberError(what, name, "must be a string");
  }
  out = *text;
  return Status(StatusCode::Ok, ReasonCode::None);
}

}  // namespace

Value EncodeIntentDocument(const IntentGenerationDocument& document) {
  Value::Map root;
  root.emplace("schema", Value::MakeString("ndo/intent-generation/1"));
  root.emplace("target", Value::MakeString(document.target.str()));
  root.emplace("generation", Value::MakeUint(document.generation.value()));
  root.emplace("epoch", Value::MakeUint(document.epoch.value()));
  root.emplace("authority", Value::MakeString(ToText(document.authority)));
  root.emplace("policy", Value::MakeString(document.policy.str()));
  root.emplace("authored_at", Value::MakeString(FormatTime(document.authored_at)));
  root.emplace("evidence", Value::MakeString(ToText(document.evidence)));
  Value::List objects;
  for (const auto& entry : document.objects) {
    Value::Map object;
    object.emplace("id", Value::MakeString(entry.first.str()));
    object.emplace("existence", Value::MakeString(ToText(entry.second.existence)));
    Value::List fields;
    for (const auto& field : entry.second.fields) {
      Value::Map encoded;
      encoded.emplace("path", Value::MakeString(field.first.ToText()));
      encoded.emplace("value", field.second.intended);
      encoded.emplace("comparability", Value::MakeString(ToText(field.second.comparability)));
      fields.push_back(Value::MakeMap(std::move(encoded)));
    }
    object.emplace("fields", Value::MakeList(std::move(fields)));
    objects.push_back(Value::MakeMap(std::move(object)));
  }
  root.emplace("objects", Value::MakeList(std::move(objects)));
  return Value::MakeMap(std::move(root));
}

Status DecodeIntentDocument(const Value& value, const RuntimeLimits& limits,
                            IntentGenerationDocument& out) {
  const Value::Map* root = nullptr;
  Status status = RequireObject(value, "intent document", root);
  if (!status.ok()) {
    return status;
  }
  status = CheckMembers(*root,
                        {"schema", "target", "generation", "epoch", "authority", "policy",
                         "authored_at", "evidence", "objects"},
                        "intent document");
  if (!status.ok()) {
    return status;
  }
  status = detail::CheckMemberKinds(*root,
                                    {{"target", detail::MemberKind::Text},
                                     {"generation", detail::MemberKind::Integer},
                                     {"epoch", detail::MemberKind::Integer},
                                     {"authority", detail::MemberKind::Text},
                                     {"policy", detail::MemberKind::Text},
                                     {"authored_at", detail::MemberKind::Text},
                                     {"evidence", detail::MemberKind::Text},
                                     {"objects", detail::MemberKind::Sequence}},
                                    "intent document");
  if (!status.ok()) {
    return status;
  }
  status = RequireSchema(*root, "ndo/intent-generation/1", "intent document");
  if (!status.ok()) {
    return status;
  }
  IntentGenerationDocument document;
  std::string text;
  status = RequireString(*root, "target", "intent document", text);
  if (!status.ok()) {
    return status;
  }
  const auto target = TargetId::TryParse(text);
  if (!target.has_value()) {
    return MemberError("intent document", "target", "is not a valid identity");
  }
  document.target = *target;
  std::uint64_t generation = 0;
  status = RequireUint(*root, "generation", "intent document", generation);
  if (!status.ok()) {
    return status;
  }
  document.generation = IntentGeneration::FromValue(generation);
  std::uint64_t epoch = 0;
  status = RequireUint(*root, "epoch", "intent document", epoch);
  if (!status.ok()) {
    return status;
  }
  document.epoch = FabricEpoch::FromValue(epoch);
  status = RequireString(*root, "authority", "intent document", text);
  if (!status.ok()) {
    return status;
  }
  IntentAuthority authority = IntentAuthority::Unknown;
  if (!TryParseIntentAuthority(text.c_str(), authority)) {
    return MemberError("intent document", "authority", "is not recognized");
  }
  document.authority = authority;
  status = RequireString(*root, "policy", "intent document", text);
  if (!status.ok()) {
    return status;
  }
  const auto policy = PolicyId::TryParse(text);
  if (!policy.has_value()) {
    return MemberError("intent document", "policy", "is not a valid identity");
  }
  document.policy = *policy;
  status = RequireString(*root, "authored_at", "intent document", text);
  if (!status.ok()) {
    return status;
  }
  if (!TryParseTime(text, document.authored_at)) {
    return MemberError("intent document", "authored_at", "is not an RFC 3339 timestamp");
  }
  if (const std::optional<std::string> evidence = OptionalString(*root, "evidence");
      evidence.has_value()) {
    EvidenceClass parsed = EvidenceClass::Unknown;
    if (!TryParseEvidenceClass(evidence->c_str(), parsed)) {
      return MemberError("intent document", "evidence", "is not recognized");
    }
    document.evidence = parsed;
  }
  const Value::List* objects = nullptr;
  status = RequireList(*root, "objects", "intent document", objects);
  if (!status.ok()) {
    return status;
  }
  if (objects->size() > limits.max_objects_per_target) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded, "intent object count exceeds the envelope");
  }
  for (const Value& entry : *objects) {
    const Value::Map* object_map = entry.as_map();
    if (object_map == nullptr) {
      return Status::Rejected(ReasonCode::EncodingMalformed, "intent document: object must be an object");
    }
    status = CheckMembers(*object_map, {"id", "existence", "fields"}, "intent document.object");
    if (!status.ok()) {
      return status;
    }
    status = detail::CheckMemberKinds(*object_map,
                                      {{"id", detail::MemberKind::Text},
                                       {"existence", detail::MemberKind::Text},
                                       {"fields", detail::MemberKind::Sequence}},
                                      "intent document.object");
    if (!status.ok()) {
      return status;
    }
    IntentObject object;
    status = RequireString(*object_map, "id", "intent document.object", text);
    if (!status.ok()) {
      return status;
    }
    const auto id = ObjectId::TryParse(text);
    if (!id.has_value()) {
      return MemberError("intent document.object", "id", "is not a valid identity");
    }
    object.id = *id;
    if (const std::optional<std::string> existence = OptionalString(*object_map, "existence");
        existence.has_value()) {
      if (*existence == "required") {
        object.existence = ObjectExistence::Required;
      } else if (*existence == "forbidden") {
        object.existence = ObjectExistence::Forbidden;
      } else {
        return MemberError("intent document.object", "existence", "is not recognized");
      }
    }
    const Value::List* fields = nullptr;
    status = RequireList(*object_map, "fields", "intent document.object", fields);
    if (!status.ok()) {
      return status;
    }
    if (fields->size() > limits.max_fields_per_object) {
      return Status::Limit(ReasonCode::LimitFieldsExceeded, "intent field count exceeds the envelope");
    }
    for (const Value& field_value : *fields) {
      const Value::Map* field_map = field_value.as_map();
      if (field_map == nullptr) {
        return Status::Rejected(ReasonCode::EncodingMalformed, "intent document: field must be an object");
      }
      status = CheckMembers(*field_map, {"path", "value", "comparability"}, "intent document.field");
      if (!status.ok()) {
        return status;
      }
      status = detail::CheckMemberKinds(*field_map,
                                        {{"path", detail::MemberKind::Text},
                                         {"comparability", detail::MemberKind::Text}},
                                        "intent document.field");
      if (!status.ok()) {
        return status;
      }
      IntentField field;
      status = DecodeFieldPath(*field_map, limits, "intent document.field", field.path);
      if (!status.ok()) {
        return status;
      }
      const Value* raw = FindMember(*field_map, "value");
      if (raw == nullptr) {
        return MemberError("intent document.field", "value", "missing required member");
      }
      field.intended = *raw;
      if (const std::optional<std::string> comparability =
              OptionalString(*field_map, "comparability");
          comparability.has_value()) {
        FieldComparability parsed = FieldComparability::Managed;
        if (!TryParseFieldComparability(comparability->c_str(), parsed)) {
          return MemberError("intent document.field", "comparability", "is not recognized");
        }
        field.comparability = parsed;
      }
      object.fields.emplace(field.path, std::move(field));
    }
    document.objects.emplace(object.id, std::move(object));
  }
  status = document.Validate(limits);
  if (!status.ok()) {
    return status;
  }
  out = std::move(document);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Value EncodeObservationDocument(const ObservationSnapshot& snapshot) {
  Value::Map root;
  root.emplace("schema", Value::MakeString("ndo/observation/1"));
  root.emplace("source", Value::MakeString(snapshot.source.str()));
  root.emplace("epoch", Value::MakeUint(snapshot.epoch.value()));
  root.emplace("incarnation", Value::MakeUint(snapshot.incarnation.value()));
  root.emplace("sequence", Value::MakeUint(snapshot.sequence.value()));
  root.emplace("target", Value::MakeString(snapshot.target.str()));
  root.emplace("collected_at", Value::MakeString(FormatTime(snapshot.collected_at)));
  root.emplace("ttl_nanos", Value::MakeInt(snapshot.ttl_nanos));
  root.emplace("coverage", Value::MakeString(ToText(snapshot.coverage)));
  root.emplace("evidence", Value::MakeString(ToText(snapshot.evidence)));
  {
    Value::List unobserved;
    for (const ObjectId& id : snapshot.unobserved) {
      unobserved.push_back(Value::MakeString(id.str()));
    }
    root.emplace("unobserved", Value::MakeList(std::move(unobserved)));
  }
  {
    Value::Map capabilities;
    capabilities.emplace("asserts_absence", Value::MakeBool(snapshot.capabilities.asserts_absence));
    capabilities.emplace("complete_coverage",
                         Value::MakeBool(snapshot.capabilities.complete_coverage));
    capabilities.emplace("reports_nested_paths",
                         Value::MakeBool(snapshot.capabilities.reports_nested_paths));
    capabilities.emplace("evidence", Value::MakeString(ToText(snapshot.capabilities.evidence)));
    root.emplace("capabilities", Value::MakeMap(std::move(capabilities)));
  }
  Value::List objects;
  for (const auto& entry : snapshot.objects) {
    Value::Map object;
    object.emplace("id", Value::MakeString(entry.first.str()));
    object.emplace("presence", Value::MakeString(ToText(entry.second.presence)));
    Value::List fields;
    for (const auto& field : entry.second.fields) {
      fields.push_back(EncodeField(field.first, field.second));
    }
    object.emplace("fields", Value::MakeList(std::move(fields)));
    objects.push_back(Value::MakeMap(std::move(object)));
  }
  root.emplace("objects", Value::MakeList(std::move(objects)));
  return Value::MakeMap(std::move(root));
}

Status DecodeObservationDocument(const Value& value, const RuntimeLimits& limits,
                                 ObservationSnapshot& out) {
  const Value::Map* root = nullptr;
  Status status = RequireObject(value, "observation document", root);
  if (!status.ok()) {
    return status;
  }
  status = CheckMembers(*root,
                        {"schema", "source", "epoch", "incarnation", "sequence", "target",
                         "collected_at", "ttl_nanos", "coverage", "evidence", "unobserved",
                         "capabilities", "objects", "snapshot_id"},
                        "observation document");
  if (!status.ok()) {
    return status;
  }
  status = detail::CheckMemberKinds(*root,
                                    {{"source", detail::MemberKind::Text},
                                     {"epoch", detail::MemberKind::Integer},
                                     {"incarnation", detail::MemberKind::Integer},
                                     {"sequence", detail::MemberKind::Integer},
                                     {"target", detail::MemberKind::Text},
                                     {"collected_at", detail::MemberKind::Text},
                                     {"ttl_nanos", detail::MemberKind::Integer},
                                     {"coverage", detail::MemberKind::Text},
                                     {"evidence", detail::MemberKind::Text},
                                     {"unobserved", detail::MemberKind::Sequence},
                                     {"capabilities", detail::MemberKind::Object},
                                     {"objects", detail::MemberKind::Sequence},
                                     {"snapshot_id", detail::MemberKind::Text}},
                                    "observation document");
  if (!status.ok()) {
    return status;
  }
  status = RequireSchema(*root, "ndo/observation/1", "observation document");
  if (!status.ok()) {
    return status;
  }
  ObservationSnapshot snapshot;
  std::string text;
  status = RequireString(*root, "source", "observation document", text);
  if (!status.ok()) {
    return status;
  }
  const auto source = SourceId::TryParse(text);
  if (!source.has_value()) {
    return MemberError("observation document", "source", "is not a valid identity");
  }
  snapshot.source = *source;
  std::uint64_t number = 0;
  status = RequireUint(*root, "epoch", "observation document", number);
  if (!status.ok()) {
    return status;
  }
  snapshot.epoch = FabricEpoch::FromValue(number);
  status = RequireUint(*root, "incarnation", "observation document", number);
  if (!status.ok()) {
    return status;
  }
  snapshot.incarnation = Incarnation::FromValue(number);
  status = RequireUint(*root, "sequence", "observation document", number);
  if (!status.ok()) {
    return status;
  }
  snapshot.sequence = SourceSequence::FromValue(number);
  status = RequireString(*root, "target", "observation document", text);
  if (!status.ok()) {
    return status;
  }
  const auto target = TargetId::TryParse(text);
  if (!target.has_value()) {
    return MemberError("observation document", "target", "is not a valid identity");
  }
  snapshot.target = *target;
  status = RequireString(*root, "collected_at", "observation document", text);
  if (!status.ok()) {
    return status;
  }
  if (!TryParseTime(text, snapshot.collected_at)) {
    return MemberError("observation document", "collected_at", "is not an RFC 3339 timestamp");
  }
  if (const std::optional<std::int64_t> ttl = OptionalInt(*root, "ttl_nanos"); ttl.has_value()) {
    if (*ttl < 0) {
      return MemberError("observation document", "ttl_nanos", "must not be negative");
    }
    snapshot.ttl_nanos = *ttl;
  }
  if (const std::optional<std::string> coverage = OptionalString(*root, "coverage");
      coverage.has_value()) {
    ObservationCoverage parsed = ObservationCoverage::Unknown;
    if (!TryParseObservationCoverage(coverage->c_str(), parsed)) {
      return MemberError("observation document", "coverage", "is not recognized");
    }
    snapshot.coverage = parsed;
  }
  if (const std::optional<std::string> evidence = OptionalString(*root, "evidence");
      evidence.has_value()) {
    EvidenceClass parsed = EvidenceClass::Unknown;
    if (!TryParseEvidenceClass(evidence->c_str(), parsed)) {
      return MemberError("observation document", "evidence", "is not recognized");
    }
    snapshot.evidence = parsed;
  }
  if (const Value* unobserved = FindMember(*root, "unobserved"); unobserved != nullptr) {
    const Value::List* list = unobserved->as_list();
    if (list == nullptr) {
      return MemberError("observation document", "unobserved", "must be a sequence");
    }
    for (const Value& entry : *list) {
      const std::string* id_text = entry.as_string();
      if (id_text == nullptr) {
        return MemberError("observation document", "unobserved", "entries must be strings");
      }
      const auto id = ObjectId::TryParse(*id_text);
      if (!id.has_value()) {
        return MemberError("observation document", "unobserved", "entry is not a valid identity");
      }
      snapshot.unobserved.push_back(*id);
    }
  }
  if (const Value* capabilities = FindMember(*root, "capabilities"); capabilities != nullptr) {
    const Value::Map* map = capabilities->as_map();
    if (map == nullptr) {
      return MemberError("observation document", "capabilities", "must be an object");
    }
    status = CheckMembers(*map,
                          {"asserts_absence", "complete_coverage", "reports_nested_paths", "evidence"},
                          "observation document.capabilities");
    if (!status.ok()) {
      return status;
    }
    status = detail::CheckMemberKinds(*map,
                                      {{"asserts_absence", detail::MemberKind::Boolean},
                                       {"complete_coverage", detail::MemberKind::Boolean},
                                       {"reports_nested_paths", detail::MemberKind::Boolean},
                                       {"evidence", detail::MemberKind::Text}},
                                      "observation document.capabilities");
    if (!status.ok()) {
      return status;
    }
    if (const std::optional<bool> value_opt = OptionalBool(*map, "asserts_absence");
        value_opt.has_value()) {
      snapshot.capabilities.asserts_absence = *value_opt;
    }
    if (const std::optional<bool> value_opt = OptionalBool(*map, "complete_coverage");
        value_opt.has_value()) {
      snapshot.capabilities.complete_coverage = *value_opt;
    }
    if (const std::optional<bool> value_opt = OptionalBool(*map, "reports_nested_paths");
        value_opt.has_value()) {
      snapshot.capabilities.reports_nested_paths = *value_opt;
    }
    if (const std::optional<std::string> value_opt = OptionalString(*map, "evidence");
        value_opt.has_value()) {
      EvidenceClass parsed = EvidenceClass::Unknown;
      if (!TryParseEvidenceClass(value_opt->c_str(), parsed)) {
        return MemberError("observation document.capabilities", "evidence", "is not recognized");
      }
      snapshot.capabilities.evidence = parsed;
    }
  }
  const Value::List* objects = nullptr;
  status = RequireList(*root, "objects", "observation document", objects);
  if (!status.ok()) {
    return status;
  }
  if (objects->size() > limits.max_objects_per_target) {
    return Status::Limit(ReasonCode::LimitObjectsExceeded,
                         "observation object count exceeds the envelope");
  }
  for (const Value& entry : *objects) {
    const Value::Map* object_map = entry.as_map();
    if (object_map == nullptr) {
      return Status::Rejected(ReasonCode::EncodingMalformed,
                              "observation document: object must be an object");
    }
    status = CheckMembers(*object_map, {"id", "presence", "fields"}, "observation document.object");
    if (!status.ok()) {
      return status;
    }
    status = detail::CheckMemberKinds(*object_map,
                                      {{"id", detail::MemberKind::Text},
                                       {"presence", detail::MemberKind::Text},
                                       {"fields", detail::MemberKind::Sequence}},
                                      "observation document.object");
    if (!status.ok()) {
      return status;
    }
    ObservedObject object;
    status = RequireString(*object_map, "id", "observation document.object", text);
    if (!status.ok()) {
      return status;
    }
    const auto id = ObjectId::TryParse(text);
    if (!id.has_value()) {
      return MemberError("observation document.object", "id", "is not a valid identity");
    }
    object.id = *id;
    if (const std::optional<std::string> presence = OptionalString(*object_map, "presence");
        presence.has_value()) {
      ObjectPresence parsed = ObjectPresence::Unknown;
      if (!TryParseObjectPresence(presence->c_str(), parsed)) {
        return MemberError("observation document.object", "presence", "is not recognized");
      }
      object.presence = parsed;
    }
    const Value::List* fields = nullptr;
    status = RequireList(*object_map, "fields", "observation document.object", fields);
    if (!status.ok()) {
      return status;
    }
    if (fields->size() > limits.max_fields_per_object) {
      return Status::Limit(ReasonCode::LimitFieldsExceeded,
                           "observed field count exceeds the envelope");
    }
    for (const Value& field_value : *fields) {
      const Value::Map* field_map = field_value.as_map();
      if (field_map == nullptr) {
        return Status::Rejected(ReasonCode::EncodingMalformed,
                                "observation document: field must be an object");
      }
      status = CheckMembers(*field_map, {"path", "value"}, "observation document.field");
      if (!status.ok()) {
        return status;
      }
      status = detail::CheckMemberKinds(*field_map, {{"path", detail::MemberKind::Text}},
                                        "observation document.field");
      if (!status.ok()) {
        return status;
      }
      FieldPath path;
      status = DecodeFieldPath(*field_map, limits, "observation document.field", path);
      if (!status.ok()) {
        return status;
      }
      const Value* raw = FindMember(*field_map, "value");
      if (raw == nullptr) {
        return MemberError("observation document.field", "value", "missing required member");
      }
      object.fields.emplace(path, *raw);
    }
    snapshot.objects.emplace(object.id, std::move(object));
  }

  const Digest digest = snapshot.ComputeContentDigest();
  snapshot.snapshot_id = SnapshotId::Trusted(digest.ToHex());
  if (const std::optional<std::string> declared = OptionalString(*root, "snapshot_id");
      declared.has_value()) {
    if (*declared != digest.ToHex()) {
      return Status::Rejected(ReasonCode::LedgerIntegrityDigestMismatch,
                              "declared snapshot identity does not match observation content");
    }
  }
  status = snapshot.Validate(limits);
  if (!status.ok()) {
    return status;
  }
  out = std::move(snapshot);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Value EncodeSourceDescriptor(const SourceDescriptor& descriptor) {
  Value::Map root;
  root.emplace("schema", Value::MakeString("ndo/source/1"));
  root.emplace("id", Value::MakeString(descriptor.id.str()));
  root.emplace("epoch", Value::MakeUint(descriptor.epoch.value()));
  root.emplace("incarnation", Value::MakeUint(descriptor.incarnation.value()));
  root.emplace("registered_at", Value::MakeString(FormatTime(descriptor.registered_at)));
  root.emplace("provenance", Value::MakeString(descriptor.provenance));
  root.emplace("evidence", Value::MakeString(ToText(descriptor.evidence)));
  Value::Map capabilities;
  capabilities.emplace("asserts_absence", Value::MakeBool(descriptor.capabilities.asserts_absence));
  capabilities.emplace("complete_coverage", Value::MakeBool(descriptor.capabilities.complete_coverage));
  capabilities.emplace("reports_nested_paths",
                       Value::MakeBool(descriptor.capabilities.reports_nested_paths));
  capabilities.emplace("evidence", Value::MakeString(ToText(descriptor.capabilities.evidence)));
  root.emplace("capabilities", Value::MakeMap(std::move(capabilities)));
  return Value::MakeMap(std::move(root));
}

Status DecodeSourceDescriptor(const Value& value, const RuntimeLimits& limits,
                              SourceDescriptor& out) {
  const Value::Map* root = nullptr;
  Status status = RequireObject(value, "source descriptor", root);
  if (!status.ok()) {
    return status;
  }
  status = CheckMembers(*root,
                        {"schema", "id", "epoch", "incarnation", "registered_at", "provenance",
                         "evidence", "capabilities"},
                        "source descriptor");
  if (!status.ok()) {
    return status;
  }
  status = detail::CheckMemberKinds(*root,
                                    {{"id", detail::MemberKind::Text},
                                     {"epoch", detail::MemberKind::Integer},
                                     {"incarnation", detail::MemberKind::Integer},
                                     {"registered_at", detail::MemberKind::Text},
                                     {"provenance", detail::MemberKind::Text},
                                     {"evidence", detail::MemberKind::Text},
                                     {"capabilities", detail::MemberKind::Object}},
                                    "source descriptor");
  if (!status.ok()) {
    return status;
  }
  status = RequireSchema(*root, "ndo/source/1", "source descriptor");
  if (!status.ok()) {
    return status;
  }
  SourceDescriptor descriptor;
  std::string text;
  status = RequireString(*root, "id", "source descriptor", text);
  if (!status.ok()) {
    return status;
  }
  const auto id = SourceId::TryParse(text);
  if (!id.has_value()) {
    return MemberError("source descriptor", "id", "is not a valid identity");
  }
  descriptor.id = *id;
  std::uint64_t number = 0;
  status = RequireUint(*root, "epoch", "source descriptor", number);
  if (!status.ok()) {
    return status;
  }
  descriptor.epoch = FabricEpoch::FromValue(number);
  status = RequireUint(*root, "incarnation", "source descriptor", number);
  if (!status.ok()) {
    return status;
  }
  descriptor.incarnation = Incarnation::FromValue(number);
  if (const std::optional<std::string> registered = OptionalString(*root, "registered_at");
      registered.has_value()) {
    if (!TryParseTime(*registered, descriptor.registered_at)) {
      return MemberError("source descriptor", "registered_at", "is not an RFC 3339 timestamp");
    }
  }
  if (const std::optional<std::string> provenance = OptionalString(*root, "provenance");
      provenance.has_value()) {
    if (provenance->size() > limits.max_leaf_bytes) {
      return Status::Limit(ReasonCode::LimitBytesExceeded, "provenance exceeds the envelope");
    }
    descriptor.provenance = *provenance;
  }
  if (const std::optional<std::string> evidence = OptionalString(*root, "evidence");
      evidence.has_value()) {
    EvidenceClass parsed = EvidenceClass::Unknown;
    if (!TryParseEvidenceClass(evidence->c_str(), parsed)) {
      return MemberError("source descriptor", "evidence", "is not recognized");
    }
    descriptor.evidence = parsed;
  }
  if (const Value* capabilities = FindMember(*root, "capabilities"); capabilities != nullptr) {
    const Value::Map* map = capabilities->as_map();
    if (map == nullptr) {
      return MemberError("source descriptor", "capabilities", "must be an object");
    }
    status = CheckMembers(*map,
                          {"asserts_absence", "complete_coverage", "reports_nested_paths", "evidence"},
                          "source descriptor.capabilities");
    if (!status.ok()) {
      return status;
    }
    status = detail::CheckMemberKinds(*map,
                                      {{"asserts_absence", detail::MemberKind::Boolean},
                                       {"complete_coverage", detail::MemberKind::Boolean},
                                       {"reports_nested_paths", detail::MemberKind::Boolean},
                                       {"evidence", detail::MemberKind::Text}},
                                      "source descriptor.capabilities");
    if (!status.ok()) {
      return status;
    }
    if (const std::optional<bool> value_opt = OptionalBool(*map, "asserts_absence");
        value_opt.has_value()) {
      descriptor.capabilities.asserts_absence = *value_opt;
    }
    if (const std::optional<bool> value_opt = OptionalBool(*map, "complete_coverage");
        value_opt.has_value()) {
      descriptor.capabilities.complete_coverage = *value_opt;
    }
    if (const std::optional<bool> value_opt = OptionalBool(*map, "reports_nested_paths");
        value_opt.has_value()) {
      descriptor.capabilities.reports_nested_paths = *value_opt;
    }
    if (const std::optional<std::string> value_opt = OptionalString(*map, "evidence");
        value_opt.has_value()) {
      EvidenceClass parsed = EvidenceClass::Unknown;
      if (!TryParseEvidenceClass(value_opt->c_str(), parsed)) {
        return MemberError("source descriptor.capabilities", "evidence", "is not recognized");
      }
      descriptor.capabilities.evidence = parsed;
    }
  }
  if (!descriptor.epoch.is_set() || !descriptor.incarnation.is_set()) {
    return Status::Rejected(ReasonCode::FencedStaleIncarnation,
                            "source descriptor must declare its epoch and incarnation");
  }
  out = std::move(descriptor);
  return Status(StatusCode::Ok, ReasonCode::None);
}

Status ParseIntentJson(std::string_view text, const RuntimeLimits& limits,
                       IntentGenerationDocument& out) {
  Value value;
  Status status = ParseJson(text, limits, value);
  if (!status.ok()) {
    return status;
  }
  return DecodeIntentDocument(value, limits, out);
}

Status ParseObservationJson(std::string_view text, const RuntimeLimits& limits,
                            ObservationSnapshot& out) {
  Value value;
  Status status = ParseJson(text, limits, value);
  if (!status.ok()) {
    return status;
  }
  return DecodeObservationDocument(value, limits, out);
}

}  // namespace network_drift_observatory
}  // namespace summon
