# Safety of the C ABI

`src/ffi.rs` is the crate's only module allowed to contain `unsafe` code; every
other module declares `#![forbid(unsafe_code)]`, and the crate denies unsafe
operations in `unsafe fn` and `unsafe` blocks without a `SAFETY` comment. This
file records what the exported functions assume from their callers and what
they guarantee in return.

## What callers guarantee

These are the preconditions of the header; violating them is undefined
behaviour the library cannot detect.

1. A non-null `XsBytes::ptr` is readable for `len` bytes for the duration of
   the call, and the bytes do not change during it.
2. A non-null output pointer is writable for one value of its type for the
   duration of the call. Input structures (`XsCompileContext`,
   `XsAuthorization`, `XsVerifyRequest`) are readable for one value, and a
   request's ID array is readable for its count of `XsBytes`.
3. `xs_buffer_free` receives exactly a buffer the library returned, once.
4. Text the library returns is read only while the handle it came from lives.
5. A non-null `XsKeyLookup` names a function that may be called with its
   `user_data` until the call that received it returns, and that does not
   unwind. The `XsKeyQuery` it receives is read only during the invocation.

## What the library checks

- Null pointers: an output or a required input that is null returns
  `XS_INVALID_ARGUMENT`; optional ones (`error`, `audit`, `authorization`) are
  skipped. A null `XsBytes::ptr` is accepted only with a zero length.
- Alignment of every typed pointer before it is dereferenced.
- Lengths: a byte length or an array count whose size exceeds `isize::MAX` is
  refused before a slice is formed.
- Text is UTF-8; enumerators and usage bits are known values.
- Handles: never dereferenced. The table resolves each one by slot index and
  generation, checks its type tag against the type the slot records, and
  reports wrong, stale or destroyed handles. Slot generations never wrap: a
  slot whose generation is exhausted is retired.
- Inputs bounded by the compiled policy (document and key bytes) are checked
  against it before the library copies them.

## What the library guarantees

- No unwinding crosses the boundary: every body runs under
  `catch_unwind`, and a panic returns `XS_INTERNAL`.
- No output is written on failure except the error handle. A call that
  changes a document holds the table slot of the handle it returns before the
  change, so a full table refuses it with the document unchanged.
- An object is dropped only when its handle is destroyed and no running call
  or other object uses it. A call keeps every handle it reads in use until it
  returns, so destruction during the call returns `XS_BUSY`, and the object is
  released outside the table lock.
- A document is used by one operation at a time; a concurrent one returns
  `XS_BUSY`. All other objects are `Send + Sync` and serve concurrent calls.
- Text views returned in `XsBytes` point into memory owned by the handle they
  were read from, which does not move or change while the handle lives.
- Buffers are allocated as `Box<[u8]>` and released by `xs_buffer_free` with
  the same layout.
- Error messages are the diagnostics the Rust API reports for the same
  failure; key bytes and passwords never enter them.

## Callbacks

- A key lookup runs on the calling thread, only inside the call that received
  it, and no table, document or key-manager lock is held while it runs, so it
  may reenter the library. The running call's own handles stay in use and its
  document stays locked: destroying them, or operating on that document,
  returns `XS_BUSY` rather than reaching state the call is using.
- The query and the names it points to live on the library's stack for the
  invocation only. The key manager handle it receives is destroyed when the
  invocation returns; the call keeps the manager itself for its remaining
  lookups, and a later use of that handle reports it destroyed. A handle
  still in use on another thread when the invocation returns fails the call
  with `XS_BUSY`.
- Keys imported by a lookup reach the operation only through the key
  manager's validation and resource policy, counted once for the whole call,
  never as raw pointers into application memory.
- A lookup's status other than `XS_OK` ends the call with that status, or
  `XS_INTERNAL` for a value the header does not name, and no output is
  written.
