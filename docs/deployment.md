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

## Replacement And Rollback

Configuration loading and compilation are explicit, not a watcher or policy
store. Applications can construct a complete replacement off to the side and
pass it only to newly created operations after successful validation. Keep old
snapshots alive for in-flight operations. Failed replacement must leave the
previous selection intact. Relaxing replacement requires authenticated authority,
not a changed config file or a claimed newer revision.

There is currently no built-in hot-reload store, canonical policy audit identity
or deployment watcher. This runbook does not claim those future APIs exist.
Applications own atomic publication, rollback storage, redaction and correlation;
never log passwords, private key material, recovered plaintext or raw token errors.
