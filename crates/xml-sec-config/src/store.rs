//! Caller-driven publication of compiled policy snapshots.
//!
//! The application decides when to reload (file watching, database change
//! feeds and their retries stay with it); the store only validates and
//! compiles a replacement completely, then publishes it atomically. An
//! operation takes one snapshot with [`PolicyStore::load`] before it parses
//! anything and keeps enforcing that snapshot whatever is published later.

use crate::{Configuration, EffectivePolicy, Error, SCHEMA_VERSION};
use arc_swap::ArcSwap;
use std::sync::Arc;
use xml_sec::{
    policy::{CompiledPolicies, PolicyCompileContext, PolicyIdentity, PolicyValidity},
    provider::CryptoProvider,
    xmldsig::{DigestAlgorithm, compute_digest},
};

/// Everything a publication compiles: the configuration, the profile it
/// selects, and the caller's engine, contract and authenticated grant.
pub struct Source<'a> {
    /// The validated configuration to compile.
    pub configuration: &'a Configuration,
    /// The profile of `configuration` this store publishes.
    pub profile: &'a str,
    /// The one engine the snapshot is checked against.
    pub provider: &'a dyn CryptoProvider,
    /// The caller's promises to the operations using the snapshot.
    pub context: &'a PolicyCompileContext,
    /// The application-authenticated exception grant, if any.
    pub authorization: Option<PolicyValidity>,
}

/// The current published snapshot of one profile, replaced atomically.
///
/// Every publication carries a [`PolicyIdentity`] with the profile name, the
/// schema version, a revision that increases by one per publication of this
/// store, and the SHA-256 of the canonical effective settings. Separate
/// tenants use separate stores; a store never publishes another profile.
pub struct PolicyStore {
    profile: String,
    current: ArcSwap<CompiledPolicies>,
}

impl PolicyStore {
    /// Compile `source` and publish it as revision 1.
    ///
    /// # Errors
    /// Returns every [`Configuration::compile`] refusal.
    pub fn new(source: Source<'_>) -> Result<Self, Error> {
        let profile = source.profile.to_owned();
        let (compiled, digest) = compile(source)?;
        let identity = PolicyIdentity::new(profile.clone(), SCHEMA_VERSION, 1, digest);
        Ok(Self {
            profile,
            current: ArcSwap::from_pointee(compiled.with_identity(identity)),
        })
    }

    /// The snapshot to enforce for one operation. Later publications do not
    /// change it.
    #[must_use]
    pub fn load(&self) -> Arc<CompiledPolicies> {
        self.current.load_full()
    }

    /// Validate and compile `source` completely, then publish it as the next
    /// revision. A refused replacement publishes nothing, and the current
    /// snapshot stays in force.
    ///
    /// # Errors
    /// Returns a schema error when `source` names another profile than this
    /// store's, and every [`Configuration::compile`] refusal.
    pub fn replace(&self, source: Source<'_>) -> Result<Arc<CompiledPolicies>, Error> {
        if source.profile != self.profile {
            return Err(Error::Schema(format!(
                "store publishes profile {}, not {}",
                self.profile, source.profile
            )));
        }
        let (compiled, digest) = compile(source)?;
        // Concurrent publications each take the revision after the one they
        // replace; a lost race renumbers instead of recompiling.
        let mut published = None;
        self.current.rcu(|current| {
            let revision = current
                .identity()
                .map_or(0, PolicyIdentity::revision)
                .checked_add(1)
                .expect("a store publishes fewer than 2^64 revisions");
            let identity =
                PolicyIdentity::new(self.profile.clone(), SCHEMA_VERSION, revision, digest);
            let next = Arc::new(compiled.clone().with_identity(identity));
            published = Some(Arc::clone(&next));
            next
        });
        Ok(published.expect("rcu publishes at least once"))
    }
}

fn compile(source: Source<'_>) -> Result<(CompiledPolicies, [u8; 32]), Error> {
    let effective: EffectivePolicy = source.configuration.compile(
        source.profile,
        source.provider,
        source.context,
        source.authorization,
    )?;
    let digest = canonical_digest(&effective)?;
    Ok((effective.compiled, digest))
}

/// SHA-256 of the canonical effective settings: their stable TOML form, which
/// is independent of layout, inheritance spelling and the selected engine.
fn canonical_digest(effective: &EffectivePolicy) -> Result<[u8; 32], Error> {
    let canonical = effective.to_toml()?;
    let digest = compute_digest(DigestAlgorithm::Sha256, canonical.as_bytes());
    Ok(digest.try_into().expect("SHA-256 produces 32 bytes"))
}
