# Feature and provider qualification

Cargo features compile capabilities; they never authorize untrusted XML to use
an algorithm or select a provider. The immutable operation policy still applies.
See [provider boundaries](crypto-providers.md) and [policy profiles](policy-profiles.md).

## Core combinations

| Selection | Compiled surface |
| --- | --- |
| Defaults | `std`, `c14n`, `xmldsig`, `xmldsig-sign`, `xmlenc`, `xml-backend-xmloxide` |
| `c14n` plus one XML backend | Canonicalization without signature/encryption dependencies |
| `xmldsig` plus one XML backend | Signature verification, policy and the public-key inventory; implies `std` |
| `xmldsig-sign` plus one XML backend | Adds signing, signature templates, private-key import (PEM, PKCS#8, encrypted PKCS#8, PKCS#12) and the bundled randomness source; implies `xmldsig` |
| `xmlenc` plus one XML backend | Encryption and its shared signature/key-inventory graph; implies `xmldsig-sign` and `std` |
| `xslt` plus one XML backend | XMLDSig XSLT support; implies `xmldsig` |
| `experimental-pq` plus one XML backend | Experimental signature verification and key establishment; implies `xmldsig`, not `xmlenc`; PQ signing keys also need `xmldsig-sign` |
| `xmldsig,legacy-algorithms` plus one XML backend | Optional compatibility algorithms, still denied by secure policy defaults |
| `aws-lc-fips` plus one XML backend | Adds the official FIPS provider; implies `xmldsig` and `std`, not encryption |
| `pkcs11` plus one XML backend | Adds explicit external-key operations; implies `xmlenc` and `std` |
| `--all-features` | All available providers and mechanisms coexist; runtime selection is still explicit |

Every core build must select `xml-backend-xmloxide` or
`xml-backend-roxmltree`; omitting both is an intentional compile error.
`xml-backends-all` compiles both. `xml-backend-differential` also chooses
differential parsing as the default runtime backend.

RustCrypto is bundled with the signature graph, not a separate Cargo feature
named `rustcrypto`. Compiling an optional provider does not remove RustCrypto
key/container codecs and does not make the whole build FIPS approved. There is
no ordinary AWS-LC adapter and no missing-operation fallback between providers.
The optional provider temporarily pins official `aws-lc-rs =1.18.2` and
`aws-lc-fips-sys =0.14.3`: the newer sys release's bindgen dependency can resolve
incompatible `syn`/`prettyplease` major versions. The direct optional sys
dependency constrains published consumer resolution only; no sys API is used.
This also defers newer AWS build/linking changes until a compatible update is
qualified; it is not a fork or an additional provider.
`legacy-algorithms` alone does not enable XMLDSig or XMLEnc. Canonicalization
helpers remain available with an XML backend even without the `c14n` marker.
`no-unsafe` and `embedded` are compatibility markers, not separate security modes.

The root XMLDSig graph currently requires `std`. Disabling Cargo defaults is
not proof of a `no_std` build. The independent `xml-sec-xml-input` package and
shared PKIX dependencies retain their separately tested alloc-only contracts.

### Verification-only builds

`xmldsig` without `xmldsig-sign` compiles verification, key resolution from
public material, X.509 path and CRL validation and the public-key inventory.
It compiles no signing pipeline, signature templates, private-key import,
password-based key derivation or operating-system randomness: `pkcs12`,
`pkcs5`, `scrypt`, `pbkdf2`, `cms`, `x509-cert`, `x509-parser` and `getrandom`
are absent from its dependency graph. Certificates are read only through the
shared PKIX reader and PEM through one RFC 7468 decoder.

`CryptoProvider` keeps one method set in every build, so an external provider
compiles unchanged whichever features another crate enables. The bundled
RustCrypto provider reports `Random` and signing-key import unsupported in a
verification-only build. An xmlsec key store's DSA entry keeps its public tuple
there; its private `X` is not retained.

## Reproduce a configuration

Run from the repository root with Rust 1.92 or newer and cargo-nextest installed:

```sh
bash scripts/check-features.sh default
bash scripts/check-features.sh dsig-roxmltree
bash scripts/check-features.sh xmlenc-xmloxide
bash scripts/check-features.sh c14n-roxmltree
bash scripts/check-features.sh no-backend
```

Each positive profile runs strict all-target clippy, library tests, applicable
public facade/provider tests and doctests against **only** `-p xml-sec`.
It does not select workspace siblings that could enrich the tested graph.
Pass `lint`, `test` or `doc` as the second argument to run just that phase.
The negative `no-backend` profile requires the intended missing-backend diagnostic;
dependency/setup errors cannot satisfy it.

The `dsig-xmloxide` and `dsig-roxmltree` profiles are verification-only: before
linting they fail if any crate listed above enters the normal dependency graph,
and they run the library tests and `tests/verify_only_build.rs`. Tests that
create their fixtures by signing run in the signing profiles.

Other profiles are `dom-xmloxide`, `dom-roxmltree`, `c14n-xmloxide`,
`dsig-xmloxide`, `dsig-sign-xmloxide`, `xmlenc-roxmltree`, `xslt`, `legacy`,
`experimental`, `fips-dsig` and `pkcs11`. Native FIPS requirements are documented by
[AWS](https://aws.github.io/aws-lc-rs/requirements/index.html).
For token execution supply an explicit test module:

```sh
PKCS11_MODULE=/absolute/path/to/libsofthsm2.so bash scripts/check-features.sh pkcs11
```

The maintained token harness creates a disposable store; no existing token or
application PIN is used. Missing setup fails, rather than skipping the test.

## CI coverage

Stable and MSRV Linux jobs run every minimal profile. Portable default-core
qualification additionally runs on macOS and Windows. Workspace default and
all-feature jobs run on Linux; all-feature execution uses disposable SoftHSM
storage and real provider tests. The existing backend, native FIPS, token,
legacy, experimental, XSLT and independent-oracle matrices remain separate.
Passing the portable Windows core does not claim Windows native-provider or
oracle qualification.

The required aggregate test check includes the feature-contract jobs. The
alloc-only XML-input, embedded target, shared PKIX and actual WASM C14N checks
remain independent mandatory gates. This is a meaningful feature/provider
matrix, not a claim that every subset of all Cargo features has been tested.
