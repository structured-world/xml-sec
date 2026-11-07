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

## What the library checks

- Null pointers: an output or a required input that is null returns
  `XS_INVALID_ARGUMENT`; optional ones (`error`, `audit`, `authorization`) are
  skipped. A null `XsBytes::ptr` is accepted only with a zero length.
- Alignment of every typed pointer before it is dereferenced.
- Lengths: a byte length or an array count whose size exceeds `isize::MAX` is
  refused before a slice is formed.
- Text is UTF-8; enumerators and usage bits are known values.
- Handles: never dereferenced. The table resolves each one by type tag, slot
  index and generation, and reports wrong, stale or destroyed handles. Slot
  generations never wrap: a slot whose generation is exhausted is retired.

## What the library guarantees

- No unwinding crosses the boundary: every body runs under
  `catch_unwind`, and a panic returns `XS_INTERNAL`.
- No output is written on failure except the error handle.
- An object is dropped only when its handle is destroyed and no running call
  or other object uses it. Destruction during a call returns `XS_BUSY`, and
  the object is released outside the table lock.
- A document is used by one operation at a time; a concurrent one returns
  `XS_BUSY`. All other objects are `Send + Sync` and serve concurrent calls.
- Text views returned in `XsBytes` point into memory owned by the handle they
  were read from, which does not move or change while the handle lives.
- Buffers are allocated as `Box<[u8]>` and released by `xs_buffer_free` with
  the same layout.
- Error messages are the diagnostics the Rust API reports for the same
  failure; key bytes and passwords never enter them.
