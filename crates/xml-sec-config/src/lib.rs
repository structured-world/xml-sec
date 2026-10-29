//! Explicit, versioned policy configuration. No discovery, environment reads,
//! provider selection, key loading or implicit authorization occurs here.
#![forbid(unsafe_code)]

mod settings;

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read, path::Path};
use xml_sec::{
    policy::{
        CompiledPolicies, PolicyCompileContext, PolicyCompiler, PolicyProfile, PolicyValidity,
    },
    provider::CryptoProvider,
};

/// Version of the application schema (independent of the TOML language version).
pub const SCHEMA_VERSION: u32 = 1;

/// Located configuration, processing or policy error. Never grants permission.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// TOML syntax or schema decoding failed.
    #[error("invalid configuration: {0}")]
    Toml(#[from] toml::de::Error),
    /// Explicit I/O failed.
    #[error("configuration I/O: {0}")]
    Io(#[from] std::io::Error),
    /// The requested schema or policy cannot be interpreted safely.
    #[error("{0}")]
    Schema(String),
    /// The existing policy compiler rejected the resulting snapshot.
    #[error(transparent)]
    Policy(#[from] xml_sec::policy::PolicyViolation),
    /// Effective output could not be serialized.
    #[error("effective output: {0}")]
    Output(#[from] toml::ser::Error),
}

/// Limits for trusted configuration ingestion, separate from document policy.
/// These restrict the loader itself; they never grant XML processing permissions.
#[derive(Debug, Clone, Copy)]
pub struct LoadLimits {
    /// Admit source bytes before parsing or heap growth.
    pub max_bytes: usize,
    /// Bound profile count and iterative inheritance traversal.
    pub max_profiles: usize,
}

impl Default for LoadLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_profiles: 256,
        }
    }
}

/// Strict application-selected document. Merely parsing it performs no crypto.
/// Construction must pass through the bounded, validating loaders:
///
/// ```compile_fail
/// let unchecked: xml_sec_config::Configuration =
///     toml::from_str("schema_version = 99").unwrap();
/// ```
#[derive(Debug)]
pub struct Configuration {
    profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    base: Option<Base>,
    extends: Option<String>,
    verification: Option<toml::Table>,
    signing: Option<toml::Table>,
    encryption: Option<toml::Table>,
    decryption: Option<toml::Table>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
enum Base {
    XmlSecCompatible,
    Modern,
    SecureSaml,
    WsSecurity,
    Xades,
    LegacyVerify,
}

impl Base {
    fn policy(self) -> PolicyProfile {
        match self {
            Self::XmlSecCompatible => PolicyProfile::XmlSecCompatible,
            Self::Modern => PolicyProfile::Modern,
            Self::SecureSaml => PolicyProfile::SecureSaml,
            Self::WsSecurity => PolicyProfile::WsSecurity,
            Self::Xades => PolicyProfile::Xades,
            Self::LegacyVerify => PolicyProfile::LegacyVerify,
        }
    }
}

impl Configuration {
    /// Parse only caller-provided text. Check the byte bound before TOML work.
    ///
    /// # Errors
    /// Returns a schema error for exceeded limits, an unsupported version,
    /// invalid profile settings or inheritance, and a TOML error for bad syntax.
    pub fn from_str(text: &str, limits: LoadLimits) -> Result<Self, Error> {
        if text.len() > limits.max_bytes {
            return Err(Error::Schema("configuration byte limit exceeded".into()));
        }
        let document: Document = toml::from_str(text)?;
        if document.schema_version != SCHEMA_VERSION {
            return Err(Error::Schema(format!(
                "unsupported schema_version {}",
                document.schema_version
            )));
        }
        let config = Self {
            profiles: document.profiles,
        };
        if config.profiles.is_empty() || config.profiles.len() > limits.max_profiles {
            return Err(Error::Schema("profile count outside loader limits".into()));
        }
        for (name, profile) in &config.profiles {
            if name.trim().is_empty() {
                return Err(Error::Schema("profile name is empty".into()));
            }
            if profile.base.is_some() == profile.extends.is_some() {
                return Err(Error::Schema(format!(
                    "profile {name} requires exactly one of base or extends"
                )));
            }
            for (operation, table) in profile.tables() {
                settings::validate(operation, table)?;
            }
            config.chain(name)?;
        }
        Ok(config)
    }

    /// Explicit bounded reader, with a one-byte stack probe at the boundary.
    ///
    /// # Errors
    /// Returns read failures, a schema error for oversized or non-UTF-8 input,
    /// and every [`Configuration::from_str`] refusal.
    pub fn from_reader(mut reader: impl Read, limits: LoadLimits) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        while bytes.len() < limits.max_bytes {
            let available = (limits.max_bytes - bytes.len()).min(chunk.len());
            let count = reader.read(&mut chunk[..available])?;
            if count == 0 {
                return Self::from_bytes(&bytes, limits);
            }
            reserve_input(&mut bytes, count, limits.max_bytes)?;
            bytes.extend_from_slice(&chunk[..count]);
        }
        if reader.read(&mut chunk[..1])? != 0 {
            return Err(Error::Schema("configuration byte limit exceeded".into()));
        }
        Self::from_bytes(&bytes, limits)
    }

    fn from_bytes(bytes: &[u8], limits: LoadLimits) -> Result<Self, Error> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| Error::Schema("TOML configuration must be UTF-8".into()))?;
        Self::from_str(text, limits)
    }

    /// Open exactly this caller-selected path; no search paths or include files.
    ///
    /// # Errors
    /// Returns the open failure and every [`Configuration::from_reader`] refusal.
    pub fn from_path(path: impl AsRef<Path>, limits: LoadLimits) -> Result<Self, Error> {
        Self::from_reader(std::fs::File::open(path)?, limits)
    }

    fn chain(&self, name: &str) -> Result<Vec<&Profile>, Error> {
        let mut chain = Vec::new();
        let mut names = Vec::new();
        let mut current = name;
        loop {
            if names.contains(&current) {
                return Err(Error::Schema(format!("inheritance cycle at {current}")));
            }
            let profile = self
                .profiles
                .get(current)
                .ok_or_else(|| Error::Schema(format!("unknown inherited profile {current}")))?;
            names.push(current);
            chain.push(profile);
            match &profile.extends {
                Some(parent) => current = parent,
                None => break,
            }
        }
        chain.reverse();
        Ok(chain)
    }

    /// Borrow names in stable order, without compiling or cloning their settings.
    pub fn profile_names(&self) -> impl Iterator<Item = &str> {
        self.profiles.keys().map(String::as_str)
    }

    /// Compile against the one caller-selected engine. Authorization is supplied
    /// by trusted application code, never fabricated from configuration metadata.
    ///
    /// # Errors
    /// Returns an unknown or cyclic profile, invalid layer settings, and every
    /// policy compilation or authorization refusal.
    pub fn compile(
        &self,
        name: &str,
        provider: &dyn CryptoProvider,
        context: &PolicyCompileContext,
        authorization: Option<PolicyValidity>,
    ) -> Result<EffectivePolicy, Error> {
        let chain = self.chain(name)?;
        let base = chain[0]
            .base
            .ok_or_else(|| Error::Schema("inheritance root has no base".into()))?
            .policy();
        let mut compiler = PolicyCompiler::new(base, provider, authorization)?;
        for profile in chain {
            let mut layer = compiler.policies().clone();
            settings::apply(profile, &mut layer)?;
            compiler = compiler.restrict(&layer)?;
        }
        let policies = compiler.compile(context)?;
        let document = settings::snapshot(&policies)?;
        Ok(EffectivePolicy {
            compiled: policies,
            document,
        })
    }
}

fn reserve_input(bytes: &mut Vec<u8>, additional: usize, maximum: usize) -> Result<(), Error> {
    if bytes.len() > maximum || additional > maximum - bytes.len() {
        return Err(Error::Schema("configuration byte limit exceeded".into()));
    }
    let required = bytes.len() + additional;
    if required <= bytes.capacity() {
        return Ok(());
    }
    // Short reads must not cause one realloc/copy per byte. Every geometric
    // capacity request is admitted against the same explicit source ceiling.
    let capacity = if bytes.capacity() == 0 {
        4096.min(maximum)
    } else if bytes.capacity() > maximum / 2 {
        maximum
    } else {
        bytes.capacity() * 2
    };
    bytes
        .try_reserve_exact(capacity.max(required) - bytes.len())
        .map_err(|_| Error::Schema("configuration allocation failed".into()))
}

#[cfg(test)]
mod tests;

impl Profile {
    fn tables(&self) -> impl Iterator<Item = (&'static str, &toml::Table)> {
        [
            ("verification", self.verification.as_ref()),
            ("signing", self.signing.as_ref()),
            ("encryption", self.encryption.as_ref()),
            ("decryption", self.decryption.as_ref()),
        ]
        .into_iter()
        .filter_map(|(name, table)| table.map(|table| (name, table)))
    }
}

/// Actual compiled policy plus deterministic, complete effective settings.
pub struct EffectivePolicy {
    compiled: CompiledPolicies,
    document: toml::Table,
}

impl EffectivePolicy {
    /// Pass these snapshots to existing processing contexts.
    #[must_use]
    pub const fn compiled(&self) -> &CompiledPolicies {
        &self.compiled
    }
    /// Stable field and set order, independent of TOML layout.
    ///
    /// # Errors
    /// Returns a TOML serialization failure.
    pub fn to_toml(&self) -> Result<String, Error> {
        #[derive(Serialize)]
        struct Profiles<'a> {
            effective: &'a toml::Table,
        }
        #[derive(Serialize)]
        struct Document<'a> {
            schema_version: u32,
            profiles: Profiles<'a>,
        }
        let document = Document {
            schema_version: SCHEMA_VERSION,
            profiles: Profiles {
                effective: &self.document,
            },
        };
        Ok(toml::to_string(&document)?)
    }
    /// Classify every effective leaf change, with validity presence transitions
    /// reported as one constraint change. Non-ordered interpretation changes
    /// are conservatively relaxing and require operator review, never a silent
    /// claim that two different processing models are equally restrictive.
    #[must_use]
    pub fn diff(&self, next: &Self) -> Vec<Change> {
        settings::diff(&self.document, &next.document)
    }
}

/// Direction of one effective setting change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Narrows permission or tightens an enforcement constraint.
    Restrictive,
    /// Changes descriptive metadata without changing effective restrictions.
    Neutral,
    /// Broadens permission or changes incomparable semantics; requires review.
    Relaxing,
}

/// A changed effective setting; validity presence is reported atomically.
/// Secret/key/request data cannot enter this snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    /// Fully qualified operation/setting.
    pub field: String,
    /// Previous canonical value.
    pub before: Option<toml::Value>,
    /// Replacement canonical value.
    pub after: Option<toml::Value>,
    /// Whether permission is narrowed, unchanged or potentially broadened.
    pub direction: Direction,
}
