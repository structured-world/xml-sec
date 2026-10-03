//! Explicit experimental XML method identifiers, not W3C-standardized algorithms.

/// FIPS 204/205 parameter sets exposed by libxmlsec1's experimental XML methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqAlgorithm {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
    /// SLH-DSA-SHA2-128f.
    SlhDsaSha2_128f,
    /// SLH-DSA-SHA2-128s.
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-192f.
    SlhDsaSha2_192f,
    /// SLH-DSA-SHA2-192s.
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-256f.
    SlhDsaSha2_256f,
    /// SLH-DSA-SHA2-256s.
    SlhDsaSha2_256s,
}

impl PqAlgorithm {
    /// Recognized experimental parameter sets; permission still requires policy.
    pub const ALL: [Self; 9] = [
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
        Self::SlhDsaSha2_128f,
        Self::SlhDsaSha2_128s,
        Self::SlhDsaSha2_192f,
        Self::SlhDsaSha2_192s,
        Self::SlhDsaSha2_256f,
        Self::SlhDsaSha2_256s,
    ];

    /// Experimental XML URI used by libxmlsec1 1.3.13.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::MlDsa44 => "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#ml-dsa-44",
            Self::MlDsa65 => "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#ml-dsa-65",
            Self::MlDsa87 => "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#ml-dsa-87",
            Self::SlhDsaSha2_128f => {
                "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#slh-dsa-sha2-128f"
            }
            Self::SlhDsaSha2_128s => {
                "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#slh-dsa-sha2-128s"
            }
            Self::SlhDsaSha2_192f => {
                "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#slh-dsa-sha2-192f"
            }
            Self::SlhDsaSha2_192s => {
                "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#slh-dsa-sha2-192s"
            }
            Self::SlhDsaSha2_256f => {
                "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#slh-dsa-sha2-256f"
            }
            Self::SlhDsaSha2_256s => {
                "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#slh-dsa-sha2-256s"
            }
        }
    }

    /// PKIX OID, with parameters absent (RFC 9881 section 2 / RFC 9909 section 3).
    /// https://www.rfc-editor.org/rfc/rfc9881.html#section-2
    /// https://www.rfc-editor.org/rfc/rfc9909.html#section-3
    pub const fn oid(self) -> &'static str {
        match self {
            Self::MlDsa44 => "2.16.840.1.101.3.4.3.17",
            Self::MlDsa65 => "2.16.840.1.101.3.4.3.18",
            Self::MlDsa87 => "2.16.840.1.101.3.4.3.19",
            Self::SlhDsaSha2_128s => "2.16.840.1.101.3.4.3.20",
            Self::SlhDsaSha2_128f => "2.16.840.1.101.3.4.3.21",
            Self::SlhDsaSha2_192s => "2.16.840.1.101.3.4.3.22",
            Self::SlhDsaSha2_192f => "2.16.840.1.101.3.4.3.23",
            Self::SlhDsaSha2_256s => "2.16.840.1.101.3.4.3.24",
            Self::SlhDsaSha2_256f => "2.16.840.1.101.3.4.3.25",
        }
    }

    pub(crate) const fn object_oid(self) -> pkcs8::der::asn1::ObjectIdentifier {
        pkcs8::der::asn1::ObjectIdentifier::new_unwrap(self.oid())
    }

    pub(crate) fn from_oid(oid: pkcs8::der::asn1::ObjectIdentifier) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.object_oid() == oid)
    }

    /// Exact signature wire width (FIPS 204 table 2 / FIPS 205 table 2).
    pub const fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
            Self::SlhDsaSha2_128f => 17088,
            Self::SlhDsaSha2_128s => 7856,
            Self::SlhDsaSha2_192f => 35664,
            Self::SlhDsaSha2_192s => 16224,
            Self::SlhDsaSha2_256f => 49856,
            Self::SlhDsaSha2_256s => 29792,
        }
    }

    pub(crate) const fn context_element(self) -> &'static str {
        match self {
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => "MLDSAContextString",
            _ => "SLHDSAContextString",
        }
    }
}
