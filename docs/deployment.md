# Restrictive Policy Deployment Runbook

## Select The Contract

Choose a [profile](policy-profiles.md) in trusted application code. `Modern`
is the general starting point; `SecureSaml`, `WsSecurity` and `Xades` additionally
require their declared target/placement integration. They are not full protocol
validators. Keep tenant identity, expected element identities, trusted keys,
external bytes and UTC facts in request context, never in untrusted XML policy hints.

Select one [provider](crypto-providers.md#capability-summary) before compilation.
Check native platform/module requirements separately from Cargo feature availability.
Provider capability, operation policy permission and an approved FIPS service
are different facts. Unsupported capability is terminal, never a software fallback.

## Compose And Validate

1. Start from the trusted system profile, then apply application and tenant
   restrictions through `PolicyCompiler::restrict` or explicit config inheritance.
2. Permissions intersect, minima increase and ceilings decrease. Disabled
   operations cannot be re-enabled. Interpretation modes are not security levels:
   contradictory XPath/ID/OPC/XSLT semantics fail instead of silently winning.
3. Supply truthful `PolicyCompileContext` promises. `target_evidence = true`
   does not create expected targets; `external_resources = true` does not fetch bytes.
4. Compile against the actual selected provider, then bind `XmlSecurity` to those
   immutable snapshots. A low-level builder must not override that binding.

The [schema sample](examples/policy-v1.toml) has system/application/tenant ceilings
of 10000/5000/1000 nodes and disables tenant signing. These are illustrative
restrictions, not universal capacity recommendations. Size deployment limits
from accepted document shapes and measured workloads, within the hard ceilings.

```sh
config=docs/examples/policy-v1.toml
cargo run -p xml-sec-cli --bin xmlsec1 -- policy check --file "$config" --profile tenant --target-evidence
cargo run -p xml-sec-cli --bin xmlsec1 -- policy show-effective --file "$config" --profile tenant --target-evidence
```

Effective output shows the actual intersection, including inherited settings.
Round-trip it using the same engine, compile-context promises and authenticated
grant, if any. Review `policy diff` classifications before rollout: exit zero
only means both inputs compile. A mixed or incomparable change can be relaxing.
These CLI commands inspect configuration; they do not silently configure a later
`sign`/`verify` invocation.

## Execute And Accept

Capture one immutable compiled object for the whole operation. Pass request
resources explicitly, reject missing payloads, and authorize only the expected
targets returned by `VerifyEvidence::accepted` for that same retained generation.
Do not let a valid certificate or mathematical signature authorize an unsigned
sibling. Preserve typed processing/resource errors separately from invalid
signature evidence. Do not retry either under a more permissive profile.

For legacy acceptance, an application must authenticate a `PolicyValidity` grant
with authority, reason and expiry before using `authorize_replacement` or
`LegacyVerify`. A TOML audit record cannot mint authority. Keep a grant narrowly
scoped and time-limited; earlier grant lifetimes still intersect and operation
entry rechecks expiry. Never choose compatibility from the document's algorithms.

## Hot Reload

`xml_sec_config::PolicyStore` publishes one profile's compiled snapshot and
replaces it atomically. The application decides when to reload: watching files
or a database, debouncing changes and retrying failed reads stay with it.

1. Create one store per tenant profile with `PolicyStore::new`; it publishes
   revision 1. A store never publishes another profile, so replacing one
   tenant's policy cannot change what another tenant enforces.
2. Start every operation with `store.load()` and bind `XmlSecurity` to that
   snapshot before parsing. The operation enforces it to the end; snapshots
   already taken stay alive and unchanged while a replacement is published.
3. On a change, load the new configuration with the usual bounded loaders and
   call `store.replace` with the same provider, compile-context promises and
   authenticated grant. The replacement is validated and compiled completely
   first; a refusal (schema, composition, provider capability, an expired or
   missing grant) publishes nothing and the previous revision stays in force.
4. Review `policy diff` between the effective outputs before publishing a
   relaxing change. A relaxation needs authenticated authority, not a changed
   file or a higher revision number.

Each publication carries a `PolicyIdentity`: the profile name, the schema
version, a revision that increases by one per publication of the store (also
under concurrent publishers), and the SHA-256 of the canonical effective
settings. Equal digests mean equal enforced settings whatever the file layout,
so a digest change, not a revision change, shows that enforcement changed.
Every operation returns it in its `PolicyAudit`, together with the decisions
its policy made: the algorithms and URI classes it permitted, the Manifest
processing it applied, the exception grant it ran under and the inputs it
refused while continuing. The records hold no document content, URIs, keys or
resource bytes, so they can go to the audit log as they are; see the
[Rust API guide](rust-api.md#policy-audit).

Rollback is a replacement with the earlier configuration: it is published as the
next revision with the earlier digest. The store keeps no history; applications
own rollback storage, redaction and correlation, and never log passwords,
private key material, recovered plaintext or raw token errors.
