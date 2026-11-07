//! Canonical audit identity of one published policy snapshot.

use alloc::string::String;

/// Which published policy an operation enforced: the named profile, the
/// configuration schema it was read under, the publication revision and the
/// digest of its canonical effective settings.
///
/// The trusted application (or `xml-sec-config`) assigns it when it publishes
/// a compiled snapshot; it is audit metadata and never grants permission.
/// Equal digests mean equal effective settings, whatever the revision.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyIdentity {
    profile: String,
    schema_version: u32,
    revision: u64,
    digest: [u8; 32],
}

impl PolicyIdentity {
    /// Identify a snapshot of `profile`, read under `schema_version`, published
    /// as `revision`, whose canonical effective settings have SHA-256 `digest`.
    #[must_use]
    pub fn new(
        profile: impl Into<String>,
        schema_version: u32,
        revision: u64,
        digest: [u8; 32],
    ) -> Self {
        Self {
            profile: profile.into(),
            schema_version,
            revision,
            digest,
        }
    }

    /// The configured profile name the snapshot was compiled from.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The configuration schema version the profile was read under.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The publication revision, increasing with every published replacement.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// SHA-256 of the canonical effective settings.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}
