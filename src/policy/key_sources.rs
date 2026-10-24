//! Independent permissions for the existing XML verification key sources.

/// A verification key source, not a claim that its key is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeySourceKind {
    /// Caller-supplied, pre-resolved verification key.
    PresetKey = 1,
    /// Key selected by document `KeyName`.
    KeyName = 2,
    /// Public key embedded in `KeyValue`.
    KeyValue = 4,
    /// Public key embedded in `DEREncodedKeyValue`.
    DerEncodedKeyValue = 8,
    /// Certificates and selectors embedded in `X509Data`.
    X509Data = 16,
    /// Bounded indirection through `KeyInfoReference`.
    KeyInfoReference = 32,
}

impl KeySourceKind {
    /// Every implemented source permission, in stable declaration order.
    pub const ALL: [Self; 6] = [
        Self::PresetKey,
        Self::KeyName,
        Self::KeyValue,
        Self::DerEncodedKeyValue,
        Self::X509Data,
        Self::KeyInfoReference,
    ];
}

/// Permitted sources for XML verification keys; path/key authorization is separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct KeySourcePolicy {
    bits: u8,
}

impl KeySourcePolicy {
    /// Deny every key source.
    pub const NONE: Self = Self { bits: 0 };
    /// Permit all six existing sources, matching the default policy.
    pub const ALL: Self = Self {
        bits: KeySourceKind::PresetKey as u8
            | KeySourceKind::KeyName as u8
            | KeySourceKind::KeyValue as u8
            | KeySourceKind::DerEncodedKeyValue as u8
            | KeySourceKind::X509Data as u8
            | KeySourceKind::KeyInfoReference as u8,
    };

    /// Whether this snapshot permits the selected source.
    #[must_use]
    pub const fn contains(self, source: KeySourceKind) -> bool {
        self.bits & source as u8 != 0
    }

    /// Permit one source without changing other permissions.
    pub const fn insert(&mut self, source: KeySourceKind) {
        self.bits |= source as u8;
    }

    /// Deny one source without changing other permissions.
    pub const fn remove(&mut self, source: KeySourceKind) {
        self.bits &= !(source as u8);
    }

    /// Apply an explicitly supplied permission for one source.
    pub const fn set(&mut self, source: KeySourceKind, permitted: bool) {
        if permitted {
            self.insert(source);
        } else {
            self.remove(source);
        }
    }

    /// Retain only sources permitted by both snapshots.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }
}

impl Default for KeySourcePolicy {
    fn default() -> Self {
        Self::ALL
    }
}

impl FromIterator<KeySourceKind> for KeySourcePolicy {
    fn from_iter<T: IntoIterator<Item = KeySourceKind>>(sources: T) -> Self {
        let mut policy = Self::NONE;
        for source in sources {
            policy.insert(source);
        }
        policy
    }
}

impl<const N: usize> From<[KeySourceKind; N]> for KeySourcePolicy {
    fn from(sources: [KeySourceKind; N]) -> Self {
        sources.into_iter().collect()
    }
}

#[cfg(test)]
mod tests;
