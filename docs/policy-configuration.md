# Explicit Policy Configuration

`xml-sec-config` is the versioned TOML boundary above `xml-sec`. It uses the
existing typed compiler and one caller-selected `CryptoProvider`. It neither
implements cryptography nor reads environment variables, searches directories,
fetches resources, reloads policies, loads keys or decides caller authority.
Both the config and native CLI packages currently build from the workspace;
their manifests do not opt into the core's single-package release workflow.

## Schema Version 1

See the [complete field/type reference](policy-schema-v1.md) and the tested
[system/application/tenant example](examples/policy-v1.toml). The
[deployment runbook](deployment.md) covers restrictive composition and rollout.

```toml
schema_version = 1

[profiles.system]
base = "Modern"

[profiles.system.verification.resources]
max_xml_nodes = 10000
max_canonicalized_bytes = 1048576

[profiles.tenant]
extends = "system"

[profiles.tenant.signing]
enabled = false
```

The document contains only `schema_version` and `profiles`. Each named profile
requires exactly one `base` or `extends`. `base` is one of `XmlSecCompatible`,
`Modern`, `SecureSaml`, `WsSecurity`, `Xades`, `LegacyVerify`. Inheritance is
iterative and ordered parent first; missing parents and cycles fail at loading.
Every profile and nested setting is checked, including unselected profiles.
Unknown fields, duplicate selections, invalid types and unsupported schema
versions fail rather than being silently ignored. TOML syntax follows TOML 1.1.

Profiles have optional `verification`, `signing`, `encryption`, `decryption`
tables. Omission inherits the parent; `enabled = false` disables an operation
and may not be combined with settings. A child cannot re-enable it.
Ordinary settings intersect with the inherited policy: permissions cannot grow,
minima cannot fall, limits cannot rise. `show-effective` displays the actual
intersection, not the requested overlay. Conflicting interpretation modes fail.

Each operation exposes its applicable typed policy fields, with the same names:

| Table | Settings |
| --- | --- |
| verification/signing | `signature_algorithms`, `digest_algorithms`, `parameterized_rsa_pss`, `signature_constraints`, `ecdsa_signature_value_encoding`, `manifest_processing`, `hmac`, `uris`, `transforms`, `key_establishment`, `xml`, `resources`, `validity` |
| verification | `key_trust`, `key_sources` |
| signing | `rsa_keys`, `dsa_keys` |
| encryption/decryption | `data_algorithms`, `key_transport_algorithms`, `key_wrap_algorithms`, `oaep_digests`, `rsa_keys`, `key_establishment`, `xml`, `resources`, `validity` |
| decryption | `uris`, `transforms` |

Nested fields use their public typed-policy names, including all `ResourcePolicy`
ceilings. Enum values use their documented Rust variant names. Algorithm sets
are arrays of exact public algorithm URIs; an empty array denies all. The string
`"default"` represents the core field's `None` semantics, not universal permission.
URI sets are arrays of `"empty"`, `"same-document"`, `"external"`. Integers are
nonnegative and must satisfy the core policy compiler's bounds and contradictions.

An exact RSA-PSS selection may be an inline table containing `uri`, `digest`,
`mgf_digest`, `salt_len`; digest values are exact digest URIs. Certificate/CRL
permissions are independent: `"default"`, `"AllSupported"`, or an array of
descriptors. Each descriptor has `kind` (`Dsa`, `RsaPkcs1v15`, `RsaPss`, `Ecdsa`,
`Ed25519`, `Ed448`, `PostQuantum`), `digest` when applicable, explicit PSS
`mgf_digest`/`salt_len`, or the `uri` of a pure post-quantum signature. These
translate to existing typed provider parameters; they do not introduce OID
decoding or a second algorithm registry. Provider capability is checked by the
core compiler after policy composition, never interpreted as permission.

## Authority and Request Context

Legacy grants must arrive as authenticated `PolicyValidity` from the application.
A file cannot manufacture one. A `validity` table can match its audit metadata
and restrict its interval; `"none"` is valid only without an inherited grant.
The CLI offers explicit authorization metadata and signed Unix-second interval flags
(`--not-before -1` means one second before epoch);
the operator/application is responsible for authenticating the authority.
Time settings accept signed Unix seconds or `{ seconds = -1, nanoseconds = 0 }`;
effective output uses the exact seconds/nanoseconds form, including dates before
1970. These are explicit clock values, not a civil-time/leap-second conversion;
they become `xml_sec::policy::Instant` labels, which cover every signed second
on every platform.

`PolicyCompileContext` promises external maps and expected-target integration.
It does not supply keys, document targets, URI bytes, UTC facts or trust anchors.
Compiled policies are passed explicitly to existing operation contexts. Loading
configuration never changes global or already constructed processing contexts.

## Loading and Effective Output

`Configuration::from_str`, `from_reader`, `from_path` accept explicit input and
`LoadLimits`. Defaults bound source bytes to 1 MiB and profiles to 256. Readers
admit bytes before buffer growth and use a one-byte stack probe at the limit.
These are loader limits for trusted configuration, not XML resource policy.
Loading configuration needs `std`; the compiled policies it produces are the
same typed values the core uses without `std`.

`compile` receives a profile name, borrowed selected provider, compile context
and optional application grant. `EffectivePolicy::compiled` exposes the actual
immutable snapshots. `to_toml` emits an `effective` profile with explicit settings,
stable field/set order and no keys or request bytes. The output can be parsed
and compiled again with the same provider, context and authenticated grant.

`diff` compares effective settings, not TOML layout or inheritance spelling.
Changes are restrictive, neutral or relaxing. Non-ordered interpretation changes
are conservatively relaxing and require review; they are not declared comparable
merely because both inputs are valid. Mixed array changes include a relaxation.
For `signature_constraints`, `General` is the composition identity: selecting
`Saml`, `WsSecurity` or `Xades` narrows it, while returning to `General` relaxes it.
Different specialized constraints are incomparable, not successive security levels.
Adding a validity window is one restrictive change; removing it is relaxing.
When both policies have a window, its boundaries remain individually classified.
The CLI prints all changes and exits successfully when both inputs compile;
operators must inspect classifications rather than equating exit zero with a
safe rollout. Store/reload atomicity and policy audit identity are separate APIs.
