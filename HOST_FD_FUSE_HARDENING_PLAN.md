# Implementation Guide: Hardening gVisor's Host-FD FUSE Transport

**Status:** working document for the `claude/project-implementation-plan-ldsms2` branch.
**Audience:** the engineer/agent implementing the change. This document is standalone —
you do NOT need to read any external design doc. Everything you need is here.
**Do not ship this file in an upstream PR.** It is a scratch plan for the feature branch.

---

## 0. Orientation — what exists today and what we are changing

gVisor's Sentry has a FUSE client (`pkg/sentry/fsimpl/fuse/`). A fusefs mount normally
talks to an in-sandbox `/dev/fuse` device (`deviceConn`). It *also* has a newer transport,
`hostConnection` (`host_connection.go`), where the mount's `-o fd=N` resolves to a **host
FD**, letting a FUSE server *outside* the sandbox serve the filesystem. Data crosses the FD
by plain `read`/`write` copies ("copy-through-FD").

Today that host FD is only reachable if something *inside* the container calls
`mount -t fuse -o fd=N` itself (see `test/fuse_host/workload/workload.go`). There is no
runsc-side provisioning.

The host transport works but is minimal. This project hardens it for a high-throughput
external backend and makes it a first-class runsc storage option. Target shape: **one FD
per mount, few mounts per sandbox, high I/O parallelism within a mount. RAM is the
budgeted resource.**

### The problems we fix
1. **Request leak on no-reply requests.** `FUSE_FORGET` gets no reply; the host path still
   registers a completion + active-request slot that nothing ever clears. Permanent leak.
2. **One-read-one-message reader with a hard 8 KB cap.** The reader does one `unix.Read`
   per reply into an 8 KB buffer and *drops* any reply whose header says it's larger. That
   caps every reply at 8 KB and requires a message-preserving FD (SEQPACKET).
3. **80 MB of dead buffer.** Every outstanding request embeds a fixed
   `[8192]byte` (`futureResponse.buf`). At the default depth of 10000 that is ~80 MB per
   mount, and it is *also* the reply-size cap.
4. **No backpressure on the host path.** `hostConnection.call` increments the in-flight
   count unconditionally. The device path blocks when full; the host path does not.
5. **Memory limits are hardcoded constants**, not tunable per mount.
6. **Server-initiated notifications are undefined behavior** on this path.
7. **No runsc provisioning.** The mount can't be declared in the OCI spec / pod
   annotations; a privileged in-container agent has to issue it.
8. **Checkpoint/restore silently corrupts.** `save_restore.go`'s `afterLoad`
   unconditionally resets `conn.fuseConn = &deviceConn{...}`; the host FD and reader
   goroutine are never restored. A checkpoint of a host-FUSE sandbox restores broken.

### Locked design decisions — DO NOT REVISIT (deviation needs explicit sign-off)
- **Framing:** stream-frame on the FUSE header's self-describing `Len` field. No added
  length prefix. Works over SOCK_STREAM and pipes; SEQPACKET still works but is no longer
  required.
- **Reader model:** one blocking reader goroutine per mount, blocking FD (keep the existing
  `O_NONBLOCK`-clearing in `getFilesystemHostFD`). No epoll.
- **FD count:** one FD per mount. Do NOT build multi-FD, but do NOT break the property that
  keeps it possible: `Unique` allocation stays global per connection under `conn.mu`; the
  `completions` map stays shared.
- **Buffers:** two size classes. Small = 8 KB (`FUSE_MIN_READ_BUFFER`), pooled, for metadata
  replies. Large = lazily allocated, variable capacity growing on demand up to a configured
  ceiling (`reply_buf_max`), pooled, for READ/READDIR replies. **Ownership transfers**
  framer → futureResponse → opcode handler; no payload copy under `conn.mu`.
- **Reply-memory bound is decoupled from queue depth.** A counting gate
  (`reply_buf_concurrency`) limits live large-class buffers; the framer blocks on it before
  taking a large buffer. Worst-case reply RAM ≈
  `8KB × max_inflight + reply_buf_max × reply_buf_concurrency`.
- **Admission control = blocking-guest.** Port the device path's `fullQueueCh` wait loop
  into the host path. No EAGAIN-style rejection.
- **Release enforcement = both mechanisms.** A permanent acquire/release leak counter
  asserted in tests, plus a finalizer-based missed-release detector behind a compile-time
  debug constant.
- **Notifications: consume, discard, log, document.** No notify handling. Backends must not
  send `FUSE_NOTIFY_RETRIEVE` (it expects a reply that will never come).
- **Data plane: copy-through-FD only.** No shared memory, no fd-passing, no DAX.
- **Config precedence:** Sentry hard clamp > per-container annotation > runsc flag >
  built-in default. The Sentry clamps are the security boundary; everything from runsc /
  annotations is *untrusted input* to the Sentry.
- **Backend provisioning = UDS.** runsc connects to a backend-owned Unix domain socket and
  donates the connected FD into the sandbox; runsc does NOT spawn backend processes.
  (A spawned-backend convenience mode could be layered on later; not in this plan.)
- **Checkpoint/restore = Sentry-driven replay (gofer precedent; user-confirmed).** On
  restore, re-dial the UDS, re-INIT, then re-LOOKUP/re-OPEN from the Sentry's own saved
  state. **No backend state blob in the checkpoint; backends need zero checkpoint code.**
  Accepted trade-offs, decided with eyes open: restore re-binds by *path* (a file replaced
  at the same path between save and restore is silently re-bound to the new file;
  unlinked-but-open files may fail restore), and restore cost scales with live
  dentries/handles. A vhost-user `DEVICE_STATE`-style backend blob was considered in depth
  and rejected — see Stage 7.

### Explicitly rejected — do not resurrect
vhost-user-fs frontend; length-prefix framing; EAGAIN admission; reply buffers sized
`max_read × depth`; epoll/shared-reader across mounts; SCM_RIGHTS / shared-memory data
channel; implementing notification handling now; backend-serialized checkpoint blob (a
vhost-user `DEVICE_STATE` analog — rejected in favor of the gofer replay precedent; if a
future backend needs blob-level fidelity it can be added later as an optional negotiated
extension, not in this plan); runsc-spawned FUSE backend processes.

---

## 1. Ground rules for the implementer (read this before you touch anything)

- **Pure Go only.** This is a security-conscious codebase. No cgo, no new `unsafe`, no
  assembly, no new host syscalls. The Sentry may only do plain `read`/`write` on the
  existing FD (the seccomp filters in `runsc/boot/filter/` allow those; `readv`/`writev`
  are NOT to be added). `UnmarshalUnsafe`/`MarshalUnsafe` on ABI structs are the codebase's
  established pattern and are fine — they are not new `unsafe`. **If you think you need
  anything cgo/unsafe/new-syscall-shaped, STOP and ask the user first.** (Note: the runsc
  CLI process connecting to a UDS in Stage 4 is *not* a Sentry syscall — runsc-side code
  runs unsandboxed before boot and may use ordinary net/unix dials.)
- **Stick to this plan.** Do not reimplement standard-library primitives, do not add new
  third-party dependencies, do not pull in a new test framework or mocking library. The
  existing test scaffolding (`host_connection_test.go`, socketpair + fake server) is what
  you extend. If you believe you genuinely need a new dependency or a large new test
  harness, STOP and ask the user first.
- **Keep production code per commit under ~200 lines** where reasonable. Test code is
  unbounded. Going a little over occasionally is fine; going far over or doing it every
  commit is not — split the commit instead.
- **TDD religiously.** Wherever practical, split each feature into two commits:
  (a) interface/signature changes + tests that are all initially **failing (red)**, then
  (b) the implementation that makes them pass **(green)**. Commit messages should say which.
- **Before EVERY commit: auto-format and run the tests.**
  - Format every touched Go file with `gofmt` (and keep imports goimports-clean, matching
    the file's existing grouping style). If you touched BUILD files, format them with
    buildifier conventions (match surrounding style if the tool isn't available). Never
    commit unformatted code.
  - Run the affected package tests. **All tests must be green**, with exactly one
    exception: a **[RED]** commit may be committed with its *newly added* tests failing —
    that's the point of a RED commit. Even then, every *pre-existing* test must still pass
    and the tree must compile. The immediately following **[GREEN]** commit must turn those
    new tests green; never leave red tests dangling across more than that one commit
    boundary.
- **Cleanup commits are allowed.** If you discover you need a small refactor / bug fix /
  rename that wasn't in this plan, it's fine to insert a focused commit for it. Keep it
  focused and say so in the message.
- **Every stage ends green and is independently revertable.** Do NOT reorder stages; later
  stages depend on earlier ones.
- **Verify before every commit** (see "Invariants" at the end). Run the fuse package tests
  and, when the toolchain allows, `-race` and the nogo/checklocks static checks.

### Build / test toolchain note
gVisor builds with **Bazel**, and the tree does not compile with a bare `go test` because
many files are generated (go_marshal `*_abi_autogen.go`, stateify, checklocks, protobufs).
This environment has **Docker but not Bazel**. The canonical way to run the FUSE package
tests here is Bazel-in-Docker via the Makefile:

```
make test TARGETS=//pkg/sentry/fsimpl/fuse:fuse_test
```

**Before starting Stage 1, confirm you can actually run that target** (it pulls a builder
image and needs network through the proxy). If it does not work in this environment, stop
and ask the user how they want tests run — do NOT silently skip test execution, and do NOT
try to hand-roll a parallel pure-`go` build of the Sentry.

If you add new `+checklocks` annotations or new savable fields, the nogo pass
(`make nogo-tests`) and stateify generation must still pass; mirror the existing annotation
style exactly.

---

## 2. Key facts about the current code (so you don't have to rediscover them)

Files you will touch live in `pkg/sentry/fsimpl/fuse/` (Sentry) and `runsc/` (provisioning):

- **`connection.go`** — the shared `connection` struct and the `fuseConn` interface
  (`call`, `release`). Two implementations: `deviceConn` (in-file) and `hostConnection`
  (`host_connection.go`). Shared state: `mu`, `nextOpID`, `completions
  map[linux.FUSEOpID]*futureResponse`, `numActiveRequests` (`+checklocks:mu`),
  `maxActiveRequests`, `fullQueueCh chan struct{}` (capacity `maxActiveRequests`, made in
  `newFUSEConnectionOpts`), `connected`, negotiated limits (`maxRead`, `maxWrite`,
  `maxPages`).
  - The **device path's admission wait loop** is in `callFuture` (around line 425–452):
    `for conn.numActiveRequests == conn.maxActiveRequests { conn.mu.Unlock();
    b.Block(conn.fullQueueCh); conn.mu.Lock(); ... }`. Barging is possible and documented.
  - The **device path's noReply handling** is in `read()` (around line 577): when it
    dequeues a `req.noReply` request it does `conn.numActiveRequests--;
    delete(conn.completions, req.hdr.Unique)`.
  - `sendResponse` (device path) is where the device path signals `fullQueueCh` and
    decrements `numActiveRequests`.
- **`host_connection.go`** (~250 lines) — the whole host transport:
  - `respBufPool` — `sync.Pool` of `*[]byte` of `FUSE_MIN_READ_BUFFER` (8192).
  - `readLoop()` — one `unix.Read` per reply into an 8 KB buffer, parses `FUSEHeaderOut`,
    **drops** replies where `hdr.Len > n` (this is the cap we remove), matches `Unique`,
    copies payload into `fut.buf` **under `conn.mu`** (the copy we remove), signals
    `fullQueueCh`, decrements `numActiveRequests`, closes `fut.ch`.
  - `abortPending()` — on reader exit, closes all pending futures and decrements the count.
  - `call()` — locks, checks `connected`, **unconditionally** `numActiveRequests++`,
    registers the completion, writes the request under `writeMu`, then `fut.resolve(ctx)`.
    On write error it deletes the completion and decrements. **No admission wait, no noReply
    bypass.**
  - `writeRequest()` — loop over `unix.Write` handling short writes. Keep it.
  - `InitSend()` — sends FUSE_INIT, does its **own hand-rolled `unix.Read`** for the reply,
    then `startReader()`. We will replace the hand-rolled read with the shared framer.
  - `release()` — `conn.DecRef` + `unix.Close(hostFD)`.
- **`request_response.go`**:
  - `futureResponse` embeds `buf [linux.FUSE_MIN_READ_BUFFER]byte` (line ~150). **This
    field is used ONLY by the host path.** The device path fills `fut.data` via
    `make([]byte, ...)` in `connection.write()`. So removing/repurposing `buf` only affects
    the host path.
  - `resolve(b)` — for async returns `(nil,nil)` immediately; otherwise `b.Block(f.ch)`
    then `getResponse()`. **On `b.Block` error (interruption) it returns `(nil, err)` and
    does NOT touch `completions` or `numActiveRequests`** — the caller's error path must do
    that. (This matters for the interruption-ownership rule in Stage 6.)
  - `Response` = `{opcode, hdr linux.FUSEHeaderOut, data []byte}`. `Error()`, `DataLen()`,
    `UnmarshalPayload()`.
  - `NewRequest` steps `nextOpID` by `reqIDStep = 2` under `conn.mu`. Keep global.
- **`read_write.go`** — `ReadInPages` (line ~91) does `out := res.data[res.hdr.SizeBytes():]`
  and **returns those slices upward**. The payload is aliased and used *after* `resolve()`
  returns. This is why reply buffers cannot be reclaimed at resolve time and why we need an
  explicit `Release()` at the copy-out point rather than a `defer` in the handler.
- **`fusefs.go`**:
  - `maxActiveRequestsDefault = 10000` (line 39).
  - `filesystemOptions` (line ~47): `maxActiveRequests uint64`, `maxRead uint32`
    (default `math.MaxUint32`), plus uid/gid/rootMode/etc.
  - `parseOptions` (line ~235): parses `fd`, `user_id`, `group_id`, `rootmode`, `max_read`
    (floor-clamped to `fuseMinMaxRead = 4096`, **no upper clamp** — we add one).
  - `getFilesystemHostFD` (line ~188): dups the host FD, clears `O_NONBLOCK`, builds the
    connection via `newFUSEConnectionOpts`, calls `InitSend`. Keep the blocking-FD model.
- **`connection_control.go`**: `fuseDefaultInitFlags = linux.FUSE_MAX_PAGES` only;
  `fuseMaxMaxPages = 256` (1 MiB frames); `fuseMinMaxWrite = 4096`; `fuseMinMaxRead = 4096`.
  `InitRecv` negotiates limits. **Do not change the negotiated-flags set** (WRITEBACK_CACHE,
  READDIRPLUS, locks, ASYNC_DIO, PARALLEL_DIROPS, auto-inval all stay unsupported).
- **`save_restore.go`**: `connection.afterLoad` sets `conn.fuseConn = &deviceConn{conn:
  conn}` unconditionally; no host-FD restore of the FD or reader goroutine. Stage 2 makes
  checkpoint of host-FUSE mounts fail loudly; Stage 7 implements real support.
- **ABI** (`pkg/abi/linux/fuse.go`): defines `FUSE_NOTIFY_REPLY = 41` and
  `FUSE_MIN_READ_BUFFER = 8192`. The individual notify codes (POLL=1, INVAL_INODE=2,
  INVAL_ENTRY=3, STORE=4, RETRIEVE=5, DELETE=6) are **not** defined and we do **not** need
  to add them — we only read `hdr.Error` and log it. (You may add named consts if it makes
  the log message clearer, but it's optional and must not change existing ABI values.)
- **Existing tests** (`host_connection_test.go`): socketpair + fake echo server. Currently
  uses `SOCK_SEQPACKET`. Helpers: `newTestHostConnection`, `echoServer`, `echoServerN`,
  `setup(t)` (from `utils_test.go`), `echoTestOpcode`. **New framing tests must use
  `SOCK_STREAM`** to actually exercise the framer.
- **runsc mount machinery** (for Stage 4):
  - `runsc/boot/vfs.go:getMountNameAndOptions` (~line 987) dispatches spec mounts by type:
    gofer/Bind mounts get `goferMountData(fd, ...)`; EROFS gets
    `data = []string{fmt.Sprintf("ifd=%d", m.goferFD.Release())}` (line ~1073). FDs arrive
    via the `fdDispenser` (`goferFDs`) — FDs donated to the sandbox process across exec.
    A `case fuse.Name:` here is the natural insertion point.
  - **Per-mount annotation overrides already exist**: `dev.gvisor.spec.mount.<name>.
    {type,source,share,options}` (`runsc/boot/mount_hints.go:32`, `MountPrefix`). This is
    the k8s-friendly way a pod volume becomes a fuse mount without touching the OCI spec.
  - Per-container annotation precedent: `specutils.AnnotationCPUFeatures` read in
    `runsc/boot/loader.go` (~line 692).
  - runsc flags: `runsc/config/config.go` (`flag:"name"` tags) + `runsc/config/flags.go`
    registration; flags must be accepted identically by `create` and `boot`.
  - **Restore FD donation precedent**: `runsc/boot/vfs.go:configureRestore` (~line 1510)
    builds an fdmap keyed by `checkpoint.ResourceID`; gofer mounts consume fresh FDs from
    it on restore.
- **gofer save/restore precedent** (for Stage 7): `pkg/sentry/fsimpl/gofer/save_restore.go`
  implements `vfs.FilesystemImplSaveRestoreExtension`: `PrepareSave` purges cached dentries
  that can't be reopened after restore; `CompleteRestore` pulls a fresh connection FD from
  `vfs.RestoreFilesystemFDMapFromContext(ctx)`, re-walks live dentries recursively
  (`restoreDescendantsRecursive`), and even recovers deleted-but-open files
  (`restoreDeleted`). Stage 7 mirrors this shape for fusefs.

### The Release call sites you must audit (Stage 5)
Every code path that gets a `*Response` from a `Call`/`callRaw` must end by calling
`res.Release()` on **every** exit including error-only replies. Known sites (grep
`\.Call(`, `callRaw(`, `UnmarshalPayload(` under the package to confirm none were added):
- `inode_connection.go:27` — generic `call` (unmarshal into `out`) and `:48` `callRaw`.
  These are the choke points most handlers funnel through; releasing here covers a lot, but
  **audit each caller** because some read `res.data` after the call returns.
- `inode.go:622` LOOKUP, `:766` READLINK, `:875` GETXATTR, `:918` LISTXATTR, plus
  GETATTR/SETATTR/CREATE/MKDIR/MKNOD/SYMLINK/UNLINK/RMDIR/RENAME/STATFS/OPEN wherever they
  call. Enumerate them all.
- `file.go:94` (release, response ignored), `:116` OPEN, `:186` `CallAsync` (flush/release
  discard path — still must Release).
- `read_write.go:74` READ via `callRaw` — **the aliasing case**: `res.data` slices escape
  through `ReadInPages`' return value. Release must happen at the **copy-out point in the
  caller**, after the bytes have been copied toward the application, NOT with a `defer` in
  `ReadInPages`.
- `connection_control.go` FUSE_INIT (async path).

---

## 3. Commit-by-commit plan

Legend: **[RED]** = adds only tests/signatures, expected to fail. **[GREEN]** = makes them
pass. **[REFACTOR/DOC]** = no behavior change. Aim <200 production LOC/commit.

Stage order and why: the framer (Stage 2) is the prerequisite for SOCK_STREAM transport,
which the UDS provisioning needs. Configuration (Stage 3) and the runsc surface (Stage 4)
come next so that (a) later stages consume real, clamped option values instead of test
defaults, and (b) an end-to-end runsc→UDS→backend harness exists *before* the two riskiest
stages (buffer ownership, admission control) so they get integration coverage. Buffer pools
(Stage 5) precede admission (Stage 6) because the admission tests assert buffer/permit
reclamation. Checkpoint/restore (Stage 7) is last: it depends on the quiesce machinery from
admission, the restore-time re-dial from Stage 4, and stable buffer ownership from Stage 5.

### Stage 1 — D1: no-reply request leak (fix first, self-contained)

**Commit 1.1 [RED] — failing test for FORGET invariance**
- File: `host_connection_test.go`.
- Add `TestHostConnectionNoReplyDoesNotLeak`:
  - Build a host connection over a socketpair (reuse `newTestHostConnection`).
  - Construct a `FUSE_FORGET` request (any opcode with `req.noReply = true`; use a real
    `FUSEForgetIn` payload). Send N of them via `hc.Call` (or `CallAsync`).
  - Drain them on the server side (read and discard; never reply).
  - Assert after each: `hc.conn.completions` length does not grow and
    `hc.conn.numActiveRequests` returns to 0 (take `conn.mu` to read).
  - This fails today because `call()` registers a completion and increments the count for a
    reply that never arrives.
- Also add a table-style sub-test that interleaves a normal reply-bearing request between
  FORGETs and asserts the normal one still completes and the counts settle to 0.

**Commit 1.2 [GREEN] — bypass completion for no-reply on the host path**
- File: `host_connection.go`, `call()`.
- At the top of `call()` (after the `connected` check, before `numActiveRequests++`): if
  `r.noReply`, take `writeMu`, write the request, and `return (nil, nil)` **without**
  registering a completion or touching `numActiveRequests`. Mirror the device path's
  semantics (`connection.go` `read()` ~577). Keep the existing write-error handling.
- Net production change: a handful of lines.
- Verify: 1.1 passes; existing tests still pass.

> Note: design item "D2 — large-reply drop" is intentionally NOT patched here; it is
> subsumed by the framer in Stage 2.

---

### Stage 2 — F1: stream framer + notification discard + docs + explicit S/R rejection

Goal: remove the 8 KB reply cap and the message-preserving-FD requirement. A single
`readFrame()` owns wire parsing for both the reader goroutine and the synchronous INIT
path. **In this stage buffers are still plain `make([]byte, Len)` allocations** (pooling is
Stage 5) — just size them to `Len` instead of a fixed 8 KB, and transfer the slice to the
future. Stop copying under `conn.mu`.

**Commit 2.1 [RED] — framing test matrix + `readFrame` signature**
- File: `host_connection_test.go` (extend), plus a new `host_connection.go` method stub
  `readFrame()` returning `(hdr linux.FUSEHeaderOut, buf []byte, err error)` that
  panics/returns an error so tests link but fail.
- Switch the framing tests' socketpair to **`SOCK_STREAM`**. Add a scriptable fake server
  helper that lets a test write arbitrary byte sequences to the client FD (so you can
  control read boundaries). Cover the full matrix:
  1. Header split across reads: first read delivers 1..15 header bytes, remainder later.
  2. Payload split across many small reads.
  3. Multiple complete replies coalesced into one `write` (one client read returns 2+).
  4. A reply plus the first partial bytes of the next reply in one read (read-ahead
     remainder must be retained and used for the next frame).
  5. Notification (`Unique == 0`) interleaved between replies, including a notification
     whose bytes are split across reads. Assert it is discarded, the stream stays framed,
     and surrounding replies still resolve.
  6. `Len < SizeOfFUSEHeaderOut` → connection teardown: pending callers get an error, the
     reader exits, `connected` goes false. **No resync.**
  7. `Len > maxFrame` → same teardown behavior.
  8. Late/unknown `Unique` (no matching completion) → frame dropped, no crash, reader
     continues.
  9. INIT parsed through the same `readFrame` (see 2.3).
- These fail because `readFrame` isn't implemented and `readLoop` still drops large replies.

**Commit 2.2 [GREEN] — implement `readFrame` and rewire `readLoop`**
- File: `host_connection.go`.
- Add a small persistent accumulation buffer field on `hostConnection` (e.g.
  `readBuf []byte`, initial cap ~4 KB) owned solely by the reader goroutine (no lock — only
  the reader touches it).
- `readFrame()` algorithm:
  1. Read from the FD until ≥ `SizeOfFUSEHeaderOut` (16) bytes are buffered.
  2. Parse `FUSEHeaderOut{Len,Error,Unique}` via `UnmarshalUnsafe`.
  3. Validate `Len`: `>= SizeOfFUSEHeaderOut` and `<= maxFrame`. Invalid ⇒ return a
     sentinel error; the caller tears the connection down. **Never skip-and-continue** —
     FUSE stream framing has no resync point.
  4. Allocate `buf := make([]byte, Len)` (Stage 5 replaces this with a pooled buffer). Copy
     the already-buffered bytes in, then loop reading directly into `buf[filled:]` until
     `Len` bytes are present. Any bytes past `Len` already in the accumulation buffer are
     the start of the next frame — retain them.
  5. Return `(hdr, buf, nil)`.
- `maxFrame`: for this stage define it as `conn.maxRead + SizeOfFUSEHeaderOut` (Stage 3 ties
  it to `reply_buf_max` and enforces the coupling rule so a well-behaved backend can never
  trip teardown). Keep it a single clearly-named local/const so Stage 3 can redefine it.
- Rewrite `readLoop()` to loop on `readFrame()` and dispatch each frame:
  - `err != nil` (EOF, read error, or invalid `Len`): `abortPending()`, mark disconnected
    (`connected = false` under `conn.mu`), close the FD if appropriate, return.
  - `hdr.Unique == 0`: **notification.** Log the code (`hdr.Error`) at Warning, drop the
    buffer, continue. Put the required documentation comment block here (see 2.3).
  - `hdr.Unique` in `completions`: delete entry, `fut.hdr = &hdr`, `fut.data = buf`
    (transfer ownership; **no copy under `conn.mu`**), decrement `numActiveRequests`,
    non-blocking signal `fullQueueCh`, close `fut.ch`.
  - `hdr.Unique` not matched: unknown/late reply — drop buffer, log at Debug, continue.
- `InitSend()`: delete the hand-rolled `unix.Read`; call `readFrame()` synchronously for the
  INIT reply (INIT fits the small class), build the `Response`, then `startReader()`. One
  parser, no duplicated header logic.
- Because `fut.data` now carries a right-sized slice, the host path no longer uses
  `futureResponse.buf`. Prefer deleting the field in Stage 5 to keep this commit small.

**Commit 2.3 [DOC] — documentation deliverables**
- File: `host_connection.go` (at the notification-discard path) — insert verbatim (adjust
  only code-reference wording to match final structure):
  ```
  // Server-initiated notifications are NOT supported on the host-FD path.
  //
  // A FUSE server may send unsolicited notifications, identified by a header
  // Unique of 0 with the notification code in the header's Error field:
  // FUSE_NOTIFY_POLL (1), _INVAL_INODE (2), _INVAL_ENTRY (3), _STORE (4),
  // _RETRIEVE (5), and _DELETE (6). The reader consumes and discards them: it
  // advances past Len bytes so the stream stays framed, logs the code, and takes
  // no further action.
  //
  // Consequences for a backend served over this transport:
  //
  //  - Invalidation (_INVAL_INODE, _INVAL_ENTRY, _DELETE) does not reach the
  //    Sentry. Client-side caches expire only via the per-reply validity
  //    timeouts a backend sets on LOOKUP/GETATTR replies (entry and attribute
  //    durations). A backend must drive coherence through those timeouts and
  //    must not depend on pushed invalidation. The connection correspondingly
  //    does not negotiate FUSE_WRITEBACK_CACHE or the auto-invalidation flags.
  //
  //  - Cache push/pull (_STORE, _RETRIEVE) is unsupported. _RETRIEVE is the one
  //    notification that expects a FUSE_NOTIFY_REPLY from the client; because it
  //    is discarded, a backend that sends _RETRIEVE and waits for the reply will
  //    block forever. Backends on this transport must not send _RETRIEVE.
  //
  // Supporting notifications would mean handling these codes in the reader
  // (routing _INVAL_* into VFS dentry and page-cache invalidation) and, for
  // _RETRIEVE, adding a page-cache read plus a FUSE_NOTIFY_REPLY writer that
  // carries the server's notify_unique and bypasses the completions map, since
  // that reply is correlated by the server rather than the client.
  ```
- File: `connection_control.go`, at `fuseDefaultInitFlags`:
  ```
  // fuseDefaultInitFlags intentionally omits FUSE_WRITEBACK_CACHE and the
  // auto-invalidation flags: the host-FD path discards server notifications, so
  // pushed cache invalidation is unavailable. See hostConnection's reader.
  ```
- `g3doc/user_guide/fuse.md`: add a limitations paragraph: the host-FD transport does not
  deliver server-initiated notifications; cache coherence must come from entry/attribute
  validity timeouts; backends must not send `FUSE_NOTIFY_RETRIEVE`.

**Commit 2.4 [GREEN, small] — reject checkpoint of host-FUSE mounts loudly**
- Today a checkpoint of a sandbox with a host-FUSE mount *silently corrupts*: `afterLoad`
  reverts the transport to a `deviceConn` and the host FD/reader are gone. Until Stage 7
  lands real support, make save **fail with a clear error** for filesystems whose
  connection uses a `hostConnection` (follow the codebase's existing pattern for
  save-rejection — e.g. a `beforeSave` hook or the `PrepareSave` extension returning an
  error; find the idiomatic mechanism in-tree and use it).
- Test: attempt a save of a host-connection fusefs in the unit harness (or at minimum a
  direct `beforeSave` invocation) and assert the error.
- Stage 7 deletes this rejection and replaces it with real support.

---

### Stage 3 — Sentry configuration: options, clamps, coupling rule

Land the per-mount options and hard clamps now so every later stage consumes real,
clamped values. Two of the three options wire into behavior immediately (`max_inflight` →
`maxActiveRequests`/`fullQueueCh`; `reply_buf_max` → `maxFrame`); `reply_buf_concurrency`
is parsed, clamped, and stored now, and consumed by the pools in Stage 5.

**Commit 3.1 [RED] — option parsing, clamps, coupling tests**
- `fusefs_test.go` (create if absent, or extend the existing package tests): test
  `parseOptions` for `max_inflight`, `reply_buf_max`, `reply_buf_concurrency`:
  - Defaults applied when absent.
  - Values above ceilings **clamp, not error**; values below floors clamp up.
  - Invalid (non-numeric) values → error, matching existing `max_read` behavior.
  - New **upper** clamp on `max_read`.
  - Coupling rule: effective `max_read ≤ reply_buf_max − SizeOfFUSEHeaderOut`; conflicting
    values clamp `max_read` down (and log), never error.
- Framer test: `maxFrame` now equals the parsed/clamped `reply_buf_max`; a frame larger
  than it tears down the connection (adjust the Stage 2 matrix test if it hardcoded the
  old formula).

**Commit 3.2 [GREEN] — implement options + clamps + wiring**
- `fusefs.go` `filesystemOptions`: add `maxInflight uint64` (mount opt `max_inflight`;
  for host-FD mounts this replaces the hardcoded `maxActiveRequestsDefault`; device path
  keeps its default), `replyBufMax uint32` (mount opt `reply_buf_max`, bytes — the
  large-class ceiling), `replyBufConcurrency uint32` (mount opt `reply_buf_concurrency`).
- Hard clamp constants near `fuseMinMaxRead`: `fuseMaxMaxInflight`, `fuseMaxReplyBuf`
  (suggest 4 MiB), `fuseMaxReplyBufConcurrency`, plus the `max_read` upper clamp. Parse →
  clamp → store for each. Sane built-in defaults. Values are untrusted (they may originate
  from container annotations).
- Thread `maxInflight` into `newFUSEConnectionOpts` (it sizes `maxActiveRequests` and
  `fullQueueCh` — the option value is available there via `opts`). Redefine the framer's
  `maxFrame` as the connection's `replyBufMax`.
- Store `replyBufMax`/`replyBufConcurrency` on the connection for Stage 5. Add
  `+checklocks` annotations for any new mutable connection fields, matching existing style.

---

### Stage 4 — runsc surface: flags, annotations, UDS mount provisioning

Makes host-FUSE a declarable mount instead of an in-container privileged action, and gives
the rest of the plan an end-to-end harness. Precedence throughout: **Sentry hard clamp >
per-container annotation > runsc flag > built-in default.**

> **Design decisions (user-confirmed; flag deviations to the user):** the backend endpoint
> is a **Unix domain socket path in the mount's `source`** field; socket paths must fall
> under a directory allowlisted by a new runsc flag (empty allowlist = feature disabled);
> backend not listening at container start = **fail container creation** (single connect
> attempt with a short timeout, no retry loop).

**Commit 4.1 [GREEN] — runsc global flags**
- `runsc/config/config.go`: `Config` fields with `flag:"fuse-max-inflight"`,
  `flag:"fuse-reply-buf-max"`, `flag:"fuse-reply-buf-concurrency"`, and
  `flag:"fuse-allowed-socket-dirs"` (comma-separated list; empty disables UDS fuse
  provisioning). Host-wide defaults for the first three.
- `runsc/config/flags.go`: register them. Accepted identically by `create` and `boot`.
- Tests: extend the existing config round-trip/flag tests.

**Commit 4.2 [GREEN] — per-container annotations**
- `runsc/specutils`: constants `dev.gvisor.fuse.max-inflight`,
  `dev.gvisor.fuse.reply-buf-max`, `dev.gvisor.fuse.reply-buf-concurrency`.
- `runsc/boot/loader.go`: read them following the `specutils.AnnotationCPUFeatures`
  pattern (~line 692), overriding the flag defaults for that container. Do NOT use the
  debug-only `dev.gvisor.flag.<name>` override.
- Note: *per-mount* values need no new annotation surface — the existing
  `dev.gvisor.spec.mount.<name>.options` mount-hint annotations can carry
  `max_inflight=`/`reply_buf_max=`/`reply_buf_concurrency=` once 4.3 lands.
- Tests: annotation parsing + precedence (annotation beats flag; garbage values rejected
  or clamped — decide to match `AnnotationCPUFeatures` error behavior; Sentry clamps
  still bound everything downstream).

**Commit 4.3 [RED] — provisioning tests (mount assembly)**
- Tests for a new `case fuse.Name:` in `runsc/boot/vfs.go:getMountNameAndOptions` (unit
  level, mirroring how gofer/erofs mount assembly is tested in `runsc/boot/` tests if such
  tests exist — check first; otherwise test the option-string builder as a pure function):
  - A spec mount `type=fuse, source=/allowed/dir/backend.sock` produces mount data
    containing `fd=N` (a dispensed FD), synthesized `user_id`/`group_id` (container root
    uid/gid), `rootmode=40000`, and the three tuning options resolved per precedence.
  - Source outside the allowlist → error at create time.
  - Empty allowlist → fuse spec mounts rejected with a clear error.
- Tests for the connect step (pure runsc-side, can use a real listening UDS in a temp
  dir): success path donates a SOCK_STREAM FD; no listener → error containing the socket
  path; connect timeout honored.

**Commit 4.4 [GREEN] — implement UDS connect + FD donation + mount emission**
- runsc CLI side (create/boot, pre-sandbox): for each spec mount of type `fuse`, validate
  the source against `--fuse-allowed-socket-dirs`, `net.Dial("unix", ...)` with a short
  timeout, and donate the connected FD to the sandbox process via the existing FD-passing
  channel the gofer FDs use (find the exact plumbing — `donations`/`fdDispenser` — and
  ride it; do not invent a parallel mechanism).
- `runsc/boot/vfs.go`: `case fuse.Name:` in `getMountNameAndOptions` consuming the
  dispensed FD and emitting the option string from 4.3. The Sentry's existing
  `parseOptions`/`getFilesystemHostFD` path takes it from there unchanged.
- Fail-fast: any error here fails container creation with a message naming the mount and
  socket path.
- Keep the existing in-container `mount -t fuse -o fd=N` path working unchanged (it's
  covered by `test/fuse_host/`); the new path is additive.
- This commit may run over 200 production lines with the dial + donation + emission
  pieces; if so split CLI-side (dial+donate) and boot-side (emission) into two commits.

**Commit 4.5 [GREEN] — e2e integration test**
- Extend `test/fuse_host/` (check what exists and extend rather than invent): a test where
  runsc provisions the mount from a spec/annotation against a test FUSE backend listening
  on a UDS, exercising mount + I/O + unmount, and one failure case (no listener → create
  fails). This harness is then reused by Stages 5–6 for integration coverage.

**Commit 4.6 [DOC] — document options, flags, annotations**
- `g3doc/user_guide/fuse.md`: the new mount options (`max_inflight`, `reply_buf_max`,
  `reply_buf_concurrency`), the runsc flags, the annotations, the UDS provisioning flow
  (allowlist, fail-fast), the `max_read`/`reply_buf_max` coupling rule, and the RAM formula
  `8KB × max_inflight + reply_buf_max × reply_buf_concurrency`.

---

### Stage 5 — F2: buffer pools, `Response.Release()`, enforcement

The wide-blast-radius stage. Land the pool + Release + counters + finalizer with handlers
converted mechanically first, then the READ-path aliasing audit as its own commit. The
gate and large pool are **connection-scoped** (their ceiling/size come from the per-mount
options landed in Stage 3); the small pool stays the global `respBufPool`.

**Commit 5.1 [RED] — pool/Release/gate/counter API + tests**
- New file `pool.go` (or add to `request_response.go`) with the *types and signatures*, plus
  tests, no wiring yet:
  - `pooledBuf struct { bytes []byte; class uint8; released bool }` (+ under the debug const,
    an acquire-site stack field).
  - Class constants: `bufClassSmall`, `bufClassLarge`.
  - Small pool: repurpose `respBufPool` (8 KB slices).
  - Large pool: `sync.Pool` of variable-capacity slices. `Get(need int)` returns a buffer
    with `cap >= need`; if the pooled slice is too small, allocate rounded up to a 64 KB
    multiple, capped at the connection's `replyBufMax`.
  - Large-class **gate**: a counting semaphore = buffered `chan struct{}` of size
    `replyBufConcurrency`, acquired before taking a large buffer, released when the buffer
    is released.
  - Per-class atomic acquire/release counters, exported for tests
    (e.g. `bufPoolStats()` returning acquired/released per class).
  - `debugFUSEBuffers` compile-time `const bool` (false in checked-in code).
  - `(*Response).Release()`: idempotent (check-and-set `released`), returns the buffer to
    its pool, releases the large-class permit iff `class == large`, and under the debug
    const clears the finalizer (`runtime.SetFinalizer(pb, nil)`) before pooling. For a
    `Response` with `pbuf == nil` (device path) `Release()` is a **no-op**.
- Tests (`pool_test.go`):
  - Acquire/release balance per class after quiescence.
  - Large `Get(need)` returns cap ≥ need, rounds to 64 KB multiple, respects the ceiling.
  - Gate blocks when `replyBufConcurrency` large buffers are live and unblocks on release
    (use a goroutine + timeout).
  - `Release()` is idempotent (double Release does not double-count, does not double-release
    the permit).
  - Finalizer detector: with `debugFUSEBuffers` forced true in a build-tagged test file, a
    deliberately-leaked buffer that gets GC'd triggers the detector (log/panic) and its
    recovery path also releases the permit. (Gate this test so it only runs in the debug
    build; if the debug const can't be toggled per-test without a build tag, put it in a
    `*_debug_test.go` with a build tag and document how to run it.)
- These fail: no implementation yet.

**Commit 5.2 [GREEN] — implement pools/gate/counters/finalizer + Response carries pbuf**
- Implement everything from 5.1, sizing the gate and ceiling from the Stage 3 options.
- Add `pbuf *pooledBuf` to `Response` (and thread it through `futureResponse` →
  `getResponse`). Host path: framer attaches the pooled buffer; `getResponse` copies the
  pointer into the `Response`. Device path: constructs `Response` with `pbuf == nil` as
  today.
- **Delete `futureResponse.buf [FUSE_MIN_READ_BUFFER]byte`** (host path no longer uses it
  after Stage 2).
- Wire `readFrame` to take buffers from the pools: small if `Len <= 8192`, else acquire the
  gate then a large buffer. Wire every reader dispatch path to release when it does not
  transfer ownership: **notification discard, unknown-Unique drop, and teardown** all
  `Release`/return the buffer + permit. The only path that does NOT release in the reader
  is the successful transfer to a live future (the handler releases later).
- `abortPending`: any pending future that already owns a buffer isn't the reader's to
  release; but buffers held by the reader mid-frame on teardown must be released. Ensure no
  large permit is stranded on any exit.
- Verify counters balance in existing round-trip tests.
- If this commit exceeds ~200 LOC (likely), split it: pool + counters + Release in one
  commit, framer/reader wiring in the next.

**Commit 5.3 [GREEN] — thread `Release()` through opcode handlers (mechanical)**
- Convert the ~dozen handlers to call `res.Release()` on every exit path, including
  error-only replies (`Len == header size` still holds a small buffer) and early error
  returns. Prefer `defer res.Release()` immediately after a successful `Call` wherever the
  payload is fully consumed inside the function.
- Do the easy funnel first: `inode_connection.go`'s generic `call`/`callRaw` wrappers where
  the response does not escape. Then each site from the audit list in §2.
- **Do NOT convert the READ path here** — it's the aliasing case, handled next.
- Tests: per-opcode round-trip tests (extend existing device + host tests) asserting
  acquire == release at quiescence for LOOKUP, GETATTR, SETATTR, OPEN/CREATE, READLINK,
  READDIR, xattr ops, STATFS, and the `CallAsync` discard path, and the error-reply path.
- Handlers must stay transport-agnostic: they call `Release()` unconditionally and never
  know which transport served them (device path Release is a no-op).

**Commit 5.4 [GREEN] — READ-path aliasing audit + release-at-copy-out**
- `read_write.go` `ReadInPages` returns slices aliasing `res.data`. Move the `Release()` to
  the **copy-out point in the caller** (where the read bytes are copied toward the
  application), after the last read of the aliased slice. Ensure every early return in the
  READ path also releases.
- Audit package-wide whether `Response`/`res.data` escapes anywhere else beyond
  `ReadInPages` (grep for `res.data` and `Response` retention); document findings in the
  commit message.
- Test: a READ round-trip with a payload larger than 8 KB (exercising the large class),
  verifying data integrity end-to-end. Add an aliasing-after-release regression test: under
  `debugFUSEBuffers`, have the pool **poison** returned buffers (overwrite with a sentinel
  on Release); assert the copied-out application data is intact, proving Release does not
  precede copy-out.
- Stress test: sustained mixed load (many concurrent LOOKUP/GETATTR/READ), assert counters
  stay balanced and bounded with no monotonic growth. Run the Stage 4 e2e harness against
  this stage as an integration check.

---

### Stage 6 — F3: admission control (blocking-guest) + interruption ownership

**Commit 6.1 [RED] — admission + abort + interruption tests**
- `host_connection_test.go`: a fake server that **withholds replies** on demand.
  - Issue `max_inflight` (`maxActiveRequests`) requests that never get replies; assert the
    next `Call` **blocks** (goroutine + timeout).
  - Reply to one; assert the blocked caller unblocks and completes.
  - Interrupt a blocked *slot-waiter* (cancel its blocker); assert it returns cleanly and
    the slot accounting is correct (no leak, no double-decrement).
  - Interrupt an *in-flight* caller (one already registered, waiting on `fut.ch`), then let
    its reply arrive **late**; assert the reply hits the unknown-`Unique` path, its buffer
    and large permit are reclaimed, and `numActiveRequests` was already decremented by the
    canceller (no double decrement).
  - Teardown (close FD / abort) while waiters are blocked ⇒ **all** return
    `ECONNABORTED`.
  - `noReply` requests proceed even while the gate is full (they consume no slot).
- These fail: no host-path admission wait yet.

**Commit 6.2 [GREEN] — shared `waitForSlot` + host gate + abort drain + ownership rule**
- `connection.go`: extract the device path's wait loop into a shared helper, e.g.
  `func (conn *connection) waitForSlot(b context.Blocker) error` that, under `conn.mu`,
  loops while `numActiveRequests == maxActiveRequests`, unlocking around
  `b.Block(conn.fullQueueCh)`, re-checking after wakeup, and **checking `conn.connected`
  every iteration** — returning `ECONNABORTED` if disconnected. Have `callFuture` (device
  path) use it so behavior is shared, not copy-pasted. Preserve the documented barging
  caveat.
- `host_connection.go` `call()`: before registering the completion, call `waitForSlot`.
  `noReply` requests bypass the gate entirely (they already return early from Stage 1).
- `abortPending`: on abort, wake all slot-waiters — either signal `fullQueueCh` enough times
  or rely on the `connected`-recheck in `waitForSlot` (the loop must observe `connected ==
  false` and return `ECONNABORTED`). Ensure both in-flight callers (closed futures) and
  slot-waiters are released.
- **Interruption ownership rule (encode as an invariant + comment):** if `fut.resolve(ctx)`
  returns early due to interruption, `call()`'s error path must, under `conn.mu`, remove its
  `completions` entry and decrement `numActiveRequests` (signaling `fullQueueCh`) — exactly
  like the existing write-error path. The late reply then hits the unknown-`Unique` reader
  path, which releases buffer + permit. Result: **the reader is the sole owner of a reply
  buffer until it transfers to a live future or releases it; an abandoned future never owns
  a buffer.** No path may have both resolver and reader believing they own the buffer.
  Verify `futureResponse.resolve`'s current behavior (it returns `(nil, err)` and touches
  nothing) matches this and align the caller.

---

### Stage 7 — Checkpoint/restore via Sentry-driven replay

> **Model (user-confirmed):** restore by **replay from Sentry state**, mirroring gofer.
> The checkpoint contains ONLY Sentry-side state; the backend contributes nothing and
> needs zero checkpoint-specific code. This preserves the "any FUSE backend behind a UDS"
> ecosystem goal. The rejected alternative — the backend serializing a state blob into
> gVisor's checkpoint, analogous to vhost-user `VHOST_USER_PROTOCOL_F_DEVICE_STATE` — was
> evaluated in depth and rejected: it requires a custom gVisor↔backend protocol beyond
> FUSE plus versioned serialization logic in every backend. Its known advantages (binds by
> inode identity rather than path, survives unlinked-open files and same-path replacement,
> O(state-bytes) restore) are consciously traded away; if a future backend needs that
> fidelity, a negotiated blob extension can be layered on later without disturbing this
> design.

How it works:
- **Save:** quiesce the connection — stop admitting new requests (reuse the Stage 6
  admission machinery / `connected` handling), drain in-flight requests (wait with a
  timeout; on timeout, **fail the checkpoint**, don't kill requests), then save: the mount
  options (including the UDS source path), negotiated INIT parameters, the dentry/inode
  tree (paths, nodeids, open handles with their flags). The host FD, reader goroutine,
  pools, and gate are `nosave` and reconstructed.
- **Restore:** runsc re-dials the UDS (same path from the saved mount source; allow an
  override in the restore spec like gofer allows new FDs) and donates a fresh FD via the
  restore fdmap (`configureRestore`, `vfs.go` ~1510). The Sentry implements
  `vfs.FilesystemImplSaveRestoreExtension` for fusefs: `CompleteRestore` takes the FD,
  re-runs FUSE_INIT (re-negotiate; **fail restore** if the new negotiation is incompatible
  with saved assumptions, e.g. maxWrite shrank below what saved state requires), then
  re-LOOKUPs live dentries by path to obtain fresh nodeids and re-OPENs open handles to
  obtain fresh Fh, rewriting both in place. FORGET bookkeeping resets (old lookup counts
  belong to the dead session). Follow gofer's `PrepareSave` (purge non-reopenable cached
  dentries) + `restoreDescendantsRecursive` shape.
- **Backend contract (document in g3doc):** at restore the backend must be reachable at
  the socket path and serve the same underlying data; nodeids and file handles do NOT need
  to be stable across sessions (they are session-scoped and re-learned); a backend that
  keeps per-handle state beyond what OPEN flags reconstruct will lose it. Two accepted
  limitations to state explicitly in the user-facing docs:
  - **Path re-binding:** restore re-binds every dentry and handle *by path*. If the file
    at a saved path was replaced between save and restore, the restored mount silently
    binds to the new file. Snapshot users must treat the backend's data as
    consistent/immutable across the save→restore gap.
  - **Unlinked-but-open files** cannot be re-looked-up by path — restore fails on them
    (same class of limitation gofer handles via `restoreDeleted`; a fusefs analog can be
    scoped later if needed).

Commit sketch (expand into proper [RED]/[GREEN] pairs — **present the expansion to the
user for review before writing code for this stage**; it is the largest and subtlest):
1. Quiesce/drain on save (uses Stage 6 machinery) + failing-save-on-timeout tests.
2. Savable-state audit: make fusefs host-connection state stateify-correct (`nosave` the
   transport bits, save options/negotiated params), delete the Stage 2.4 loud rejection,
   replace the silent `afterLoad` deviceConn revert with host-aware reconstruction.
3. runsc restore path: re-dial + fdmap donation for fuse mounts (rides `configureRestore`).
4. `CompleteRestore`: re-INIT + compatibility validation.
5. Replay walk: re-LOOKUP dentries / re-OPEN handles, rewrite nodeids/Fh.
6. e2e: checkpoint/restore round-trip against the Stage 4 test backend (data intact across
   restore, open FDs usable, failure cases: backend absent at restore, incompatible INIT).

---

## 4. Invariants — verify before EVERY commit

- Code formatted (gofmt/goimports); all tests green except a [RED] commit's own new tests.
- The device (`/dev/fuse`) path's observable behavior is unchanged. `Release()` is a no-op
  there; handlers stay transport-agnostic (they must not know which transport served them).
- The `fuseConn` interface stays as-is unless a change is strictly required; if changed,
  both implementations are updated together.
- `Unique` allocation stays global per connection under `conn.mu`; `completions` stays
  shared (multi-FD door stays open).
- **Exactly one owner per reply buffer at all times.** Reader owns until transfer-to-live-
  future or self-release; abandoned futures never own.
- Every large-buffer acquire pairs with exactly one permit release on **every** path: normal
  completion, abort, teardown, notification discard, unknown-`Unique`, and finalizer
  recovery.
- No allocation or copying under `conn.mu` in the completion hot path.
- Invalid frame `Len` ⇒ connection death, never resync-and-continue.
- Sentry-side clamps bound every externally supplied value; runsc/annotation values are
  untrusted input.
- No new host syscalls from the Sentry — plain `read`/`write` only. (runsc CLI pre-boot
  code may dial UDSes; the *Sentry* may not.)
- `noReply` requests: no completion entry, no active-request slot, no admission gate.
- Run new tests under `-race`; nogo/checklocks must pass; new `connection` fields carry
  `+checklocks` annotations matching existing style.

## 5. Failure-direction note (for reviewers)
A missed `Release` in Go is a pool-miss (extra allocation, GC-collected) or a stuck
large-class permit — **never a use-after-free**. The stuck permit is the dangerous one: it
ratchets down large-reply concurrency until reads hang. That is exactly why the finalizer
releases the permit too if it fires, and logs loudly.
