# Network Drift Observatory

A standalone, vendor-neutral Fabric OS runtime that detects and explains drift
between intended authoritative state and actual observed state.

**Network Drift Observatory is observational and analytical.** It ingests
observations with provenance, compares them canonically against committed intent,
and publishes typed findings, root-cause groups and reconciliation requests. It
never mutates a device, never rolls out a fix and never silently reconciles
drift. Every action it emits is a request for another runtime, tagged with the
evidence and the policy that produced it.

- Version: 1.0.0
- Language: C++20, no third-party dependency (the standard library plus the
  platform sockets library that ships with the operating system)
- License: Apache License 2.0, Copyright 2026 Summon Software Labs.
- Telemetry: none. The runtime transmits nothing on its own behalf.

## Contents

- [What it does](#what-it-does)
- [Systems boundary](#systems-boundary)
- [Architecture](#architecture)
- [Domain model](#domain-model)
- [Freshness and compliance truth](#freshness-and-compliance-truth)
- [Finding identity, deduplication and history](#finding-identity-deduplication-and-history)
- [Suppression and acknowledgement](#suppression-and-acknowledgement)
- [Root-cause grouping](#root-cause-grouping)
- [Observation transport](#observation-transport)
- [Interchange documents](#interchange-documents)
- [Command line tools](#command-line-tools)
- [Report and reconciliation requests](#report-and-reconciliation-requests)
- [Persistence and recovery](#persistence-and-recovery)
- [Resource envelope](#resource-envelope)
- [Build, test and install](#build-test-and-install)
- [Validation](#validation)
- [Benchmarks](#benchmarks)
- [Proof surfaces: REAL, SYNTHETIC, UNSUPPORTED](#proof-surfaces-real-synthetic-unsupported)
- [Limitations](#limitations)
- [License](#license)

## What it does

1. **Commits typed intent generations.** An intent generation is a versioned,
   content-addressed document produced by Intent Fabric, Configuration Fabric or
   any other producer: for one target it declares objects, whether each object
   must exist or must not exist, and the managed fields each object must have.
2. **Admits observation snapshots with provenance.** A snapshot carries its
   source, the fabric epoch, the source incarnation, a per-source sequence
   number, a collection time, a requested time to live, a coverage declaration,
   the capabilities of the source, and a content digest that is recomputed on
   arrival.
3. **Compares canonically.** The comparator is a pure function of the committed
   baseline, the live evidence and its freshness verdicts, the policy and the
   evaluation clock. Identical inputs produce identical findings on every run.
4. **Classifies drift explicitly.** Missing, unexpected, value mismatch, field
   missing, field unexpected, stale observation, unknown or unobservable,
   unsupported, generation mismatch, partial application, conflict between
   observation sources, missing intent and invalid evidence are distinct classes
   with their own reason codes.
5. **Maintains a durable ledger.** Findings have deterministic identities, so
   persistent drift is updated rather than duplicated; history records
   first-seen, last-seen, resolution, reopening, reclassification, rebasing and
   suppression transitions.
6. **Answers questions.** A query API and a CLI filter findings by target,
   intent object, generation, drift class, severity, state, root cause, source
   and age.
7. **Exports a machine-readable report** with findings, groups, timeline,
   evidence and typed reconciliation requests.

## Systems boundary

| The observatory does | The observatory never does |
| --- | --- |
| Detect divergence between intent and observation | Change a device, a port or a configuration |
| Explain a divergence with the evidence behind it | Apply, schedule or simulate a fix |
| Group related findings under one cause | Hide a finding because it is inconvenient |
| Emit typed reconciliation requests | Execute a request it emitted |
| Record suppression without losing evidence | Let suppression change compliance truth |

## Architecture

```
include/summon/network_drift_observatory/
  platform.hpp      export macros
  version.hpp       product identity and durable/wire format versions
  limits.hpp        the resource envelope and the evidence classification
  checked.hpp       checked arithmetic for every externally derived size
  status.hpp        outcome vocabulary: StatusCode, ReasonCode, Status, Result
  identity.hpp      tagged identities, digests, generations, epochs, FieldPath
  hash.hpp          SHA-256 and CRC-32
  value.hpp         canonical bounded values and their comparison
  json.hpp          strict bounded JSON codec (an inverse pair)
  time.hpp          observation time
  intent.hpp        typed intent generations and committed baselines
  observation.hpp   snapshots, sources, capabilities, coverage
  freshness.hpp     freshness policy and verdicts
  drift.hpp         the drift vocabulary and severity
  policy.hpp        declarative, digestible observatory policy
  comparison.hpp    the canonical comparator and the evaluation outcome
  finding.hpp       finding identity, lifecycle, timeline, root-cause groups
  ledger.hpp        the finding ledger: baselines, evidence window, findings
  engine.hpp        the observatory runtime (threading contract at the top)
  query.hpp         inspection and query surface
  report.hpp        machine-readable export and reconciliation requests
  persistence.hpp   versioned, integrity-checked durable state
  interchange.hpp   intent/observation/source document codecs
  wire.hpp          framed transport codec
  net.hpp           platform sockets
  server.hpp        observation ingestion server with source fencing
  client.hpp        observation publisher

src/                one translation unit per header, plus internal helpers
tools/              ndo_cli (inspection and control), ndo_collector (publisher)
tests/              fourteen suites, listed under Validation
examples/           three runnable examples
bench/              ndo_bench, measures completed work
docs/               concurrency audit and proof surfaces
```

The library is layered: values and identities depend on nothing; documents depend
on values; the comparator depends on documents and policy; the ledger depends on
the comparator; the engine depends on the ledger; transport depends on the
engine. No layer reaches upward.
## Domain model

- **TargetId** - the observable unit: a device, port, link, tunnel or element.
- **ObjectId** - one intent object inside a target.
- **FieldPath** - a canonical path inside an object, for example
  `acl.rules[3].action`. One path has exactly one textual spelling; a
  non-canonical spelling is refused rather than normalized.
- **IntentGeneration** - a monotonic, positive generation per target. Zero means
  unset and is refused everywhere.
- **FabricEpoch** - a fabric-wide epoch. Evidence collected under another epoch
  is retained as history but can never support a compliance conclusion.
- **Incarnation** - a process incarnation for a source or for the observatory. A
  restarted process carries a strictly greater incarnation; the transport fences
  anything older.
- **SourceSequence** - a monotonic per-source observation number, scoped to one
  incarnation. A new incarnation starts a new sequence space.
- **SnapshotId** - the SHA-256 of the canonical snapshot content. A snapshot
  whose declared identity does not match its content is refused.
- **FindingId** - the SHA-256 of the finding identity: target, object, path,
  drift class, baseline generation and an optional divergence qualifier. The
  differing values are deliberately not part of the identity.
- **GroupId** - the SHA-256 of the target, baseline generation, root cause and
  the digest of the members divergence qualifiers.
- **Digest** - SHA-256 over a canonical byte encoding; every identity, ledger
  payload and report revision is derived from one.

Every identity is a distinct C++ type. Comparing a generation with an epoch, or
an object with a target, does not compile.

## Freshness and compliance truth

A snapshot is judged by `EvaluateFreshness`, a pure function of the snapshot, the
policy, the evaluation clock, the live epoch and whether the record survived a
restart. The verdict is one of:

| State | Meaning | May support compliance |
| --- | --- | --- |
| Fresh | Inside the aging threshold | yes |
| Aging | Past the aging threshold, inside the time to live | yes |
| Stale | Past the time to live, or held past it after receipt | no |
| Expired | Foreign epoch, or a zero time to live | no |
| Future | Collection time beyond the tolerated clock skew | no |
| RecoveredNotFresh | Recovered from durable state after a restart | no |
| Unknown | No collection time, or an unreadable clock relation | no |

Three rules follow, and all three are tested:

1. A source may ask for a *stricter* time to live than policy allows, never a
   longer one.
2. If the best available evidence for a target is not fresh, the comparator
   produces a stale-observation finding and reports `compliance_decidable:
   false`. The absence of fresh evidence is never compliance.
3. Evidence that survives a restart is `RecoveredNotFresh` even when its age is
   inside the time to live, until a live observation replaces it.

## Finding identity, deduplication and history

A finding is identified by *where* it is, *what class* of divergence it is and
*which baseline generation* it was compared against - never by the values that
happen to differ today. Consequences:

- Persistent drift updates one finding: `observation_count` grows, `last_seen`
  advances and the evidence list is refreshed. No duplicate is created.
- A finding resolves only when fresh, sufficiently covering evidence agrees with
  intent, for the number of confirmations policy requires. Stale or partial
  evidence never resolves a finding.
- Drift that returns after a resolution **reopens the same identity** and
  increments `reopen_count`.
- A baseline change supersedes findings compared against the old generation with
  the explicit reason `FindingRebasedToNewGeneration`; the next evaluation
  derives findings against the new baseline.
- A differently classified explanation of the same location supersedes the old
  finding with `FindingReclassified` instead of pretending the drift went away.

Every transition is recorded on the finding own bounded timeline and on the
global timeline, with a monotonic sequence number so ordering is total even when
two events share a timestamp.

## Suppression and acknowledgement

- A **suppression** marks a finding as suppressed for reporting and export. The
  finding, its values, its evidence and its contribution to compliance truth are
  unchanged: a suppressed target is still reported as non-compliant.
- Suppressions come from two sources with different lifetimes. A **policy**
  suppression ends when policy no longer matches. An **operator** suppression
  ends only when it is cleared or expires. An evaluation never silently revokes
  an operator suppression.
- An **acknowledgement** records that a human has seen a finding. It never
  changes compliance truth and never removes the finding from the live set.
- Queries can hide suppressed findings, which changes reporting only.

## Root-cause grouping

When several leaf mismatches derive from one divergence, the observatory groups
them: one root-cause group per target, baseline generation, cause and divergence
qualifier. Grouping never replaces the raw findings - each leaf keeps its own
identity, its own class, its own evidence and its own history, and additionally
records the group it belongs to and the leaf class before regrouping
(`raw_class`).

The divergence qualifier is derived from what the source reported:

- the target reports an older `@applied-generation` for every object that
  deviates: **generation-not-applied**
- some objects report the intended generation and others do not:
  **partial-application**
- two live sources disagree: **source-conflict**, qualified by the digest of the
  ordered source pair

## Observation transport

The transport is a framed protocol over TCP:

```
magic[4]="NDO1" | version u16 | type u16 | flags u16 | reserved u16
| payload_bytes u32 | checksum u32 (CRC-32 of the payload) | sequence u64
| payload (a canonical JSON document)
```

- The reader validates magic, version, declared length and checksum **before** it
  allocates or trusts anything, and refuses with a precise reason code.
- A session begins with a greeting that names the source, its epoch, its
  incarnation and its capabilities. The greeting establishes authority; the
  first accepted snapshot establishes the sequence high-water mark.
- Fencing rules: an older epoch or incarnation is refused at the greeting; a
  sequence that goes backwards within one incarnation is refused; a repeat of a
  sequence with different content is refused as a conflict; a session may only
  publish for the source and incarnation it greeted with; the session table is
  bounded and a silent session is told why it is being closed.
- Sessions run on their own threads. Finished sessions are retired by the first
  thread that observes completion, so accounting returns to its baseline without
  waiting for another connection.

## Interchange documents

Intent, observation and source documents are canonical JSON with an explicit
`schema` member that a decoder validates. Decoding is strict: an unknown member,
a wrong kind, a missing required member, a malformed path, an out-of-range
number or a document that exceeds the envelope is a refusal, never a default and
never a repair. Byte strings use the tagged form `{"$bytes":"<hex>"}`, and the
codec is an inverse pair: everything the writer produces parses back to the same
value.

An example intent document:

```json
{
  "schema": "ndo/intent-generation/1",
  "target": "switch/leaf-7",
  "generation": 4,
  "epoch": 11,
  "authority": "intent-fabric",
  "policy": "policy/default",
  "authored_at": "2026-01-01T00:00:00.000000000Z",
  "evidence": "synthetic",
  "objects": [
    {
      "id": "port/eth0",
      "existence": "required",
      "fields": [
        { "path": "mtu", "value": 1500, "comparability": "managed" }
      ]
    }
  ]
}
```

Policy is data, not code, and its digest is recorded in every finding and report:

```json
{
  "schema": "ndo/policy/1",
  "id": "policy/default",
  "format_version": 1,
  "freshness": {
    "ttl_nanos": 300000000000,
    "aging_threshold_percent": 80,
    "max_clock_skew_nanos": 5000000000,
    "ttl_applies_to_receive_time": true
  },
  "resolution_confirmations": 1,
  "require_complete_coverage_for_compliance": true,
  "require_absence_authority": true,
  "numeric_equivalence": "numeric",
  "default_severity": "medium",
  "evidence": "synthetic",
  "severity_rules": [],
  "freshness_rules": [],
  "field_class_rules": [],
  "suppressions": [],
  "source_priority": [],
  "required_targets": []
}
```

## Command line tools

`ndo_cli` is the inspection and control surface. It is observational: it can
commit intent, admit observations, evaluate, query, explain, export a report and
manage durable state, and it never contacts a network device. In `--json` mode
each line of output is one complete JSON document.

```
ndo_cli version
ndo_cli policy-default [--out FILE]
ndo_cli intent-commit --file FILE [--state FILE] [--evaluate]
ndo_cli observe       --file FILE [--state FILE] [--evaluate]
ndo_cli evaluate      [--state FILE] [--json]
ndo_cli query         [--target T] [--object O] [--class C] [--severity S]
                      [--min-severity S] [--state S] [--generation N] [--group HEX]
                      [--source S] [--min-freshness F] [--root-cause C]
                      [--min-age SECONDS] [--max-age SECONDS] [--limit N]
                      [--offset N] [--order O] [--include-resolved]
                      [--include-superseded] [--include-retired] [--exclude-suppressed]
ndo_cli explain       --finding HEX
ndo_cli timeline      [--finding HEX] [--target T]
ndo_cli report        [--out FILE] [--target T]
ndo_cli suppress      --finding HEX --actor A --reason R [--hours N]
ndo_cli acknowledge   --finding HEX --actor A --reason R
ndo_cli stats
ndo_cli serve         --port N [--once]
```

Exit codes: `0` completed (compliant, or nothing to decide), `1` usage error or a
refused operation, `2` completed with at least one live actionable finding, `3`
completed and compliance could not be decided from the available evidence.

`ndo_collector` is an observation source that runs as its own operating-system
process and publishes over the framed transport. It synthesizes snapshots
deterministically from its arguments, and it is what the multi-process test suite
uses:

```
ndo_collector --port N --source S [--host H] [--epoch N] [--incarnation N]
              [--sequence-start N] [--sequence-step N] [--target T]
              [--objects N] [--fields N] [--value V] [--count N] [--interval-ms M]
              [--age-seconds S] [--applied-generation G]
              [--coverage unknown|partial|complete] [--unobserved A,B]
              [--asserts-absence] [--complete-coverage] [--nested]
              [--ttl-nanos N] [--evidence real|synthetic] [--provenance TEXT] [--quiet]
```

A single CLI invocation with a state file is a whole process incarnation, so
evidence admitted by one invocation and read by the next is correctly reported as
recovered-not-fresh. Use `--evaluate` to evaluate in the same process that
admitted the evidence.

## Report and reconciliation requests

A report is a single canonical JSON document with schema `ndo/report/1`
containing the product identity, the observatory authority (epoch, incarnation,
policy digest, ledger revision, state digest), counters, statistics, findings by
class, severity and state, the findings themselves, the full finding records with
evidence, root-cause groups, the timeline and `reconciliation_requests`.

Each request names the finding it derives from, the action a downstream runtime
would take, and the evidence:

| Drift class | Action |
| --- | --- |
| missing, value-mismatch, field-missing, generation-mismatch, partial-application | apply-intent |
| unexpected, field-unexpected | remove-unexpected |
| stale-observation, unknown | collect-observation |
| source-conflict | resolve-source-conflict |
| unsupported, intent-missing, evidence-invalid | escalate-to-owner |

The report also carries an explicit `system_boundary` list stating what the
runtime does not claim, so a consumer cannot mistake a finding for an executed
action.

## Persistence and recovery

A persisted ledger is a versioned, integrity-checked record:

```
magic[8]="NDOLEDG1" | format u16 | flags u16 | payload_bytes u64
| SHA-256(payload)[32] | write_epoch u64 | write_incarnation u64 | payload
```

- The reader verifies magic, format version, declared length and payload digest
  before trusting a byte. Any failure is a refusal with a precise reason code.
- Recovery is all-or-nothing: a refused decode leaves the existing ledger
  untouched, and a ledger written by a newer epoch than the live one is refused.
- Recovery is conservative: baselines, findings, groups and history are restored,
  while every observation is marked recovered-not-fresh, every finding loses any
  claim to be current, and the recovery transition is recorded once on the
  finding timeline. Encoding a recovered ledger twice is a fixed point.
- Durable state is written through a temporary file in the same directory and an
  atomic replace, so a crash mid-write cannot truncate the previous ledger.

## Resource envelope

Every table, history, queue, document and report is bounded by `RuntimeLimits`:
targets, objects per target, fields per object, value depth and node count, leaf
bytes, document bytes, retained snapshots per source, findings, timeline entries,
groups, evidence references, report findings, ledger bytes, record payload bytes,
sessions, frames in flight, idle deadline and evaluation workers. A breach is a
deterministic refusal carrying the bound that was exceeded, never unbounded
growth. Every size derived from external input passes through checked arithmetic
before it is used to allocate, index or accumulate. An evaluation that would
exceed the finding or group envelope is refused as a whole: nothing is applied.

## Build, test and install

```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake --install build --config Release --prefix <prefix>
```

Options: `NDO_BUILD_TOOLS`, `NDO_BUILD_TESTS`, `NDO_BUILD_EXAMPLES`,
`NDO_BUILD_BENCH`, `NDO_WARNINGS_AS_ERRORS` (default ON),
`NDO_ENABLE_SANITIZERS`, `NDO_BUILD_SHARED`.

The build uses `/W4 /permissive- /utf-8` with a set of additional enabled
warnings and `/WX`; the first-party warning count is zero in Release and Debug.

Installed package: `find_package(NetworkDriftObservatory 1.0 REQUIRED)` provides
the imported target
`SummonLabs::NetworkDriftObservatory::network_drift_observatory`. The test suite
`test_downstream_package` installs the runtime into a private prefix, configures a
separate consumer project against that prefix only, builds it and runs it, which
is the proof that the exported package is usable from outside this build tree.

## Validation

Fourteen suites run under CTest. No suite uses a timeout or a watchdog: a hanging
test is treated as a defect, not as something to hide behind a timer.

| Suite | What it proves |
| --- | --- |
| test_core | SHA-256 and CRC-32 known answers, identity validation, path canonical form and ordering, time parsing, enum round trips, checked arithmetic |
| test_value_json | canonical value encoding and ordering, numeric equivalence, JSON round trip and idempotence, strict refusals, envelope enforcement, UTF-8 validation |
| test_intent_policy | intent commit lifecycle (duplicate, divergent, regression, epoch), intent validation, policy round trip and digest, rule specificity, classification narrowing, suppression lookup |
| test_freshness | every freshness state, source-versus-policy time to live, the receive-time rule, determinism, content-addressed snapshot identity, snapshot validation refusals |
| test_comparison | every drift class, partial visibility, absence authority, unmanaged and observe-only and unobservable fields, generation divergence, partial application, source conflict, primary source selection, determinism, order independence |
| test_ledger | deduplication, resolution, reopening, stale evidence never resolving, suppression semantics, acknowledgement, root-cause grouping, rebasing, reclassification, envelope refusal, timeline ordering |
| test_property | seeded randomized nested trees: JSON round trip, comparison symmetry and reflexivity, identical trees produce no drift, one perturbed leaf produces exactly one finding, role reversal mirrors every difference, deduplication under repetition, reproducible outcomes |
| test_adversarial | 29 groups of malformed, corrupt, truncated, oversized and self-inconsistent input across JSON, documents, wire frames, ledger records, values, paths and UTF-8, each asserting the refusal code and that nothing is partially applied |
| test_concurrency | parallel evaluation equals sequential evaluation, concurrent ingestion with evaluation, cancellation before and during evaluation, stop and start lifecycle, repeated cycles, concurrent operator actions, incarnation rotation under load, many threads on one source |
| test_persistence | round trip with history, recovered evidence never fresh, unresolved drift surviving a restart, reopening after resolution, operator suppressions surviving, corruption refusals with no partial recovery, atomic replace, epoch regression, canonical re-encoding, bounded growth |
| test_scale | 20,000-object generations, bounded refusals, finding-budget atomicity, per-finding timeline bounds, retained-window bounds, report truncation, query bounds, deep values |
| test_transport | real sockets: handshake, publish and acknowledge, incarnation and sequence fencing, raw-frame validation, session limit, idle expiry, stop retiring live sessions, intent over the wire |
| test_e2e | the shipped CLI as an independent process: version, intent commit, observation admission with in-process evaluation, restart freshness, undecidable evaluation, report and requests, suppression, statistics, malformed and wrong-schema documents leaving state untouched |
| test_multiprocess | independent collector processes over TCP: publication, stale-incarnation fencing, kill and replace with a fresh incarnation, same-incarnation replay refusal, two sources disagreeing, four concurrent processes with accounting returning to zero |
| test_downstream_package | install into a private prefix, configure and build an independent consumer against it, run it |

## Benchmarks

`ndo_bench` measures completed work: documents parsed, targets evaluated, findings
written, ledgers round-tripped and frames coded. It never measures enqueue or
submission latency, and every workload accumulates a digest so that the work
cannot be optimized away.

```
build/bench/Release/ndo_bench --targets 64 --objects 32 --repeats 3
```

## Proof surfaces: REAL, SYNTHETIC, UNSUPPORTED

Every observation carries an evidence class and the class travels with findings,
groups, reports and examples. The classification is not decoration: it states
what was actually exercised. See `docs/PROOF-SURFACES.md` for the full account.

**REAL (independent operating-system processes and real sockets).** The
transport, source fencing and restart behaviour are exercised with real
processes: `test_multiprocess` starts `ndo_collector.exe` as its own process
against a loopback TCP server, kills a running publisher mid-flight with
`TerminateProcess`, replaces it with a fresh incarnation, and proves that the dead
incarnation cannot resume. `test_e2e` runs the shipped `ndo_cli.exe` as an
independent process for the whole flow. `test_transport` uses real TCP sockets
and sends deliberately corrupted frames from a raw socket.

**SYNTHETIC (deterministic fixtures, no hardware).** All intent, observation and
policy content used by the tests, the examples and the benchmark is synthesized.
No network element was contacted, no device state was read, and no vendor
protocol, firmware or switch operating system was involved.

**UNSUPPORTED (not implemented and not claimed).**

- No device interaction of any kind: no SNMP, NETCONF, gNMI, RESTCONF, CLI
  scraping, OpenConfig or vendor-specific collection.
- No RDMA, InfiniBand, NVLink, NVSwitch, PCIe, multi-GPU or accelerator-specific
  observation, and no hardware counters.
- No comparison against a live Intent Fabric or Configuration Fabric process: the
  interchange between them is documents, and no binary integration with those
  repositories is implemented or claimed.
- No distributed observatory: the ledger is single-process and the transport
  connects collectors to one observatory. There is no replication, no quorum and
  no cross-observatory agreement protocol.
- The socket backend is implemented for Windows. On other platforms the runtime
  builds and every transport call reports that the backend is unavailable rather
  than pretending to connect.

## Limitations

- The comparator selects one primary source per target (declared priority, then
  declared coverage, then identity) and reports disagreements over the first
  eight usable sources. Sources beyond that bound are recorded in the decision
  trace rather than compared pairwise.
- Coverage is trusted as declared. A source that claims complete coverage and
  cannot assert absence still cannot produce a missing-object finding under the
  default policy, but a source that lies about its coverage cannot be detected
  from inside the observatory.
- Clock skew between a source and the observatory is tolerated up to the
  configured bound and reported beyond it; the runtime does not correct time.
- Root-cause grouping explains divergence that the observation itself reports
  (the applied-generation marker) or that sources disagree about. It does not
  model a change plan and does not infer intent history.
- The persisted ledger is a whole-file snapshot replaced atomically. There is no
  incremental journal and no compaction.
- A target that policy does not require and that has never been observed is not
  evaluated at all: the runtime makes no claim about it. Add it to
  `required_targets` to have its absence of intent reported.
- The drift class `evidence-invalid` is part of the vocabulary but is not
  emitted: invalid evidence is refused at the boundary rather than stored as a
  finding. The class is reserved for evidence found broken after admission by a
  future verification pass.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
