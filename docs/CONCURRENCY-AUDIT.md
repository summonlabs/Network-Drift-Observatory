# Concurrency audit

Scope: the Network Drift Observatory runtime at version 1.0.0. This document is
the manual audit required before release. It lists every lock, states what each
one guards, records the acquisition order, and walks each path that could
deadlock, invert, re-enter or publish after cancellation.

## 1. Lock inventory

| Lock | Owner | Guards | Acquired by |
| --- | --- | --- | --- |
| `Observatory::mutex_` | engine | ledger, source registry, policy, counters, lifecycle flags, `evaluation_sequence_` | every engine method |
| `ObservationServer::sessions_mutex_` | server | the session slot table | accept loop, session reaping, `Stats()`, `Stop()` |
| `ObservationServer::stats_mutex_` | server | server counters | every frame handler, `Stats()`, session threads |
| `ObservationServer::fence_mutex_` | server | per-source epoch/incarnation/sequence high-water marks | greeting, snapshot admission, `FenceFor()` |
| `g_initialize_mutex` | net | platform networking reference count | `InitializeNetworking()`, `ShutdownNetworking()` |

The `FindingLedger` and the comparator take no locks at all. They are single-
threaded data structures whose owner (the engine) serializes access. This is
deliberate: a second lock inside the ledger would create an ordering question
for no benefit.

## 2. Acquisition order

The engine holds exactly one lock at a time and never acquires a second one.
The server acquires at most two, always in this order:

1. `stats_mutex_` then `sessions_mutex_` inside `Stats()` (the only nesting in
   the server).
2. `sessions_mutex_` alone (accept loop, reaping, `CloseAllSessions()`).
3. `stats_mutex_` alone (frame accounting).
4. `fence_mutex_` alone (greeting and snapshot fencing).

No path acquires `sessions_mutex_` and then `stats_mutex_`, so order (1) cannot
invert. The engine mutex is never acquired while any server lock is held: the
server calls into the observatory with no server lock held, and takes its own
counters after the call returns.

## 3. Callbacks and event emission

- The engine invokes exactly one caller-supplied callback: the injected clock. It
  is consulted **before** the engine mutex is taken in `PublishIntent`,
  `IngestObservation`, `Query`, `CollectReportInputs` and `Evaluate`, so a clock
  that re-enters the observatory cannot deadlock.
- No callback, listener, observer or hook is registered anywhere else, and no
  event is emitted while a lock is held. The ledger appends timeline entries to
  plain containers and returns; the engine publishes results only after the
  ledger call returns.
- The server never calls the observatory from inside a `stats_mutex_`,
  `sessions_mutex_` or `fence_mutex_` critical section.

## 4. Read to write upgrades

There are none. The engine uses `std::mutex`, not `std::shared_mutex`, so there
is no shared-to-exclusive upgrade path. Every method that reads authoritative
state takes the same exclusive lock it would need to write it.

## 5. Evaluation without the lock

`Observatory::EvaluateAt` is the only method that releases the lock while doing
work:

1. Under the lock: validate lifecycle, build an immutable `EvaluationInput`
   (copies of baselines, retained snapshots and freshness verdicts), and
   increment `active_evaluations_`.
2. Without the lock: compare every target, optionally on a bounded worker pool.
   The input is read-only and no shared state is touched.
3. Under the lock again: decrement `active_evaluations_`, notify `idle_cv_`, and
   decide whether the result may be published.

Publication is refused, with the outcome discarded, when:

- cancellation was requested (`StatusCode::Cancelled`, and the counter
  `evaluations_cancelled` is incremented), or
- the observatory stopped while the evaluation ran, or
- the epoch or incarnation changed while the evaluation ran
  (`FencedStaleEpoch`, counter `evaluations_fenced`).

Additionally, `FindingLedger::ApplyEvaluation` fences each target individually:
if the committed baseline generation for a target is no longer the generation the
outcome was computed against, that target outcome is skipped and counted in
`LedgerApplyReport::fenced_targets`. A completed evaluation therefore never
writes findings derived from a stale baseline.

## 6. Shutdown and joins

`Observatory::Stop()` sets `stopping_`, clears `started_`, and waits on
`idle_cv_` until `active_evaluations_` reaches zero. The wait releases the mutex,
and the worker threads only need that mutex to decrement the counter, so the wait
always makes progress. No thread is joined while a lock is held.

`ObservationServer::Stop()` sets the stop flag, closes the listener (which
unblocks `accept()`), shuts down every session socket (which unblocks a reader),
joins the accept thread, moves the session threads out of the slot table **under
the lock**, releases the lock, and joins them outside it. A session thread needs
no server lock to finish, and `done` is an atomic flag, so the join cannot
deadlock and the slot table is empty when `Stop()` returns.

A session thread that is writing to a peer that stopped reading cannot block
forever: every session socket has a send deadline equal to the idle bound, and
`Stop()` shuts the socket down first.

## 7. Reentrancy that was found and removed

The audit found one real hazard and one accounting defect:

1. **Clock beneath the lock.** The injected clock was originally consulted while
   the engine mutex was held (`PublishIntent`, `IngestObservation`, `Query`,
   `CollectReportInputs`, `Evaluate`). A clock that called back into the
   observatory would have deadlocked on a non-recursive mutex. The clock is now
   read before the lock is taken.
2. **Finished sessions retained.** Session slots were only reaped from the accept
   loop, so a server that received no further connection reported a stale
   active-session count forever. `Stats()` now reaps finished sessions before it
   reports, and `Stop()` retires everything it accepted.

## 8. Cancellation

- `RequestCancellation()` sets an atomic flag; it takes no lock and cannot block.
- An evaluation checks the flag between targets, so a long pass stops promptly.
- A cancelled evaluation publishes nothing: the finding counter and the ledger are
  unchanged, and the counters record the cancellation. `test_concurrency` proves
  this by cancelling before the pass and again during a long pass, and by
  asserting that a cancelled run leaves `Stats().findings` at zero.
- Cancellation is cleared explicitly with `ClearCancellation()`; it is also
  cleared by `Start()`, so a restart never inherits a stale cancellation.

## 9. Verified by test

| Claim | Where it is exercised |
| --- | --- |
| Parallel evaluation equals sequential evaluation | `test_concurrency`, `ParallelEvaluationMatchesSequentialEvaluation` |
| Concurrent ingestion, intent publication and evaluation stay consistent | `test_concurrency`, `ConcurrentIngestionWhileEvaluatingStaysConsistent` |
| Cancellation prevents publication | `test_concurrency`, `CancellationPreventsPublication`, `CancellationDuringALongEvaluationIsHonoured` |
| Stop refuses work, is idempotent, and restarts cleanly | `test_concurrency`, `StopRefusesNewWorkAndIsIdempotent`, `RepeatedStartStopCyclesStaySane` |
| Concurrent operator actions are serialized and keep evidence intact | `test_concurrency`, `ConcurrentOperatorActionsAreSerialised` |
| Restart in place invalidates evidence and fences the old incarnation | `test_concurrency`, `IncarnationRotationInvalidatesEvidenceUnderLoad` |
| Many threads sharing one source are fenced, and the retained window stays bounded | `test_concurrency`, `ManyThreadsShareOneSourceSafely` |
| The server retires live sessions and returns accounting to zero | `test_transport`, `StopRetiresLiveSessionsAndReturnsAccounting` |
| Sessions are bounded and silent sessions are closed with a reason | `test_transport`, `SessionLimitAndIdleExpiryAreEnforced` |
| Independent processes can be killed and replaced without corrupting accounting | `test_multiprocess`, `KilledCollectorIsReplacedByAFreshIncarnation`, `ManyCollectorProcessesPublishConcurrently` |

## 10. Residual risks

- `Stats()` joins threads that have already finished; a session that is still
  finishing delays the call by at most the send deadline. This is a bounded wait
  on a real resource bound, not a retry loop.
- Timers are not used anywhere in the runtime; every deadline is a socket option
  or an explicit comparison of clock readings.

