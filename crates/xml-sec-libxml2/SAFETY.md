# Safety of the libxml2 bridge

`src/ffi.rs` is the crate's only module with `unsafe` code. It reads and links
the caller's libxml2 nodes directly and calls the libxml2 functions that create,
unlink and free them. The clean C API it reexports keeps its own contract
([`xml-sec-capi/SAFETY.md`](../xml-sec-capi/SAFETY.md)); this file records what
the bridge adds.

## What callers guarantee

1. The `xmlDocPtr` given to `xs_libxml2_document` is a live document and stays
   live until the handle is destroyed.
2. While a call on the handle runs, no other code reads, changes or frees the
   document. Between calls the caller may change it freely.
3. The document is not freed while the handle exists.

## What the bridge checks

- A null, misaligned or non-document pointer is refused with
  `XS_INVALID_ARGUMENT` before anything else is read.
- The structure members and constants the bridge uses are declared in Rust and
  compared, once per process, with their offsets and values in the headers the
  crate is built against (`src/layout.c`). A mismatch refuses the handle with
  `XS_INTERNAL`, and a projection on an existing handle fails, so no tree is
  read through a wrong declaration. Structure sizes are not compared: the bridge
  never allocates a libxml2 structure itself, and later releases append members.
- Each operation projects the whole tree into the library's semantic model
  under the operation's compiled policy (depth, node count, namespace bindings,
  bytes, DTD admission) before anything is evaluated; a tree beyond those limits
  is refused, as text would be.
- Every edit names a node the last projection reported. Fragments are parsed and
  checked by the library before any libxml2 node is created for them.

## What the bridge guarantees

- Nodes are created only with libxml2's own constructors (`xmlNewDocNode`,
  `xmlNewNs`, `xmlNewNsProp`, `xmlNewDocText` and the comment and processing
  instruction counterparts) and freed only with `xmlFreeNode`, so the
  document's allocator and dictionary own them.
- `new_document` creates its document with `xmlNewDoc`, sets only its
  `encoding` (a copy made with `xmlStrdup`, which `xmlFreeDoc` releases) and
  `standalone` members before any node exists, and frees the whole document
  with `xmlFreeDoc` when a node cannot be built.
- Edits link nodes by hand rather than through `xmlAddChild`, so adjacent text
  nodes are never merged and the pointers the projection recorded stay valid.
- Every edit is journaled. A failed operation unlinks and frees what it created
  and relinks what it removed, newest first, leaving the tree as it was. Removed
  nodes are freed only when the outermost operation succeeds; until then nothing
  in the tree points to them and they can be restored.
- Nodes an operation does not edit keep their addresses and contents.
- No libxml2 global state is changed: no parser options, error handlers,
  allocators or dictionaries are installed.
- No unwinding crosses the boundary; the entry point and every operation run
  under the clean C API's `catch_unwind`.
