//! CMS signature creation and verification library.
//!
//! This library provides high-level operations for creating and verifying [CMS
//! (Cryptographic Message Syntax) signatures](https://datatracker.ietf.org/doc/html/rfc5652).
//!
//! # Features
//!
//! - Create CMS SignedData structures with embedded content
//! - Inspect encapsulated content and claimed signer subjects without verification
//! - Verify CMS signatures against a trusted root certificate
//! - Certificate chain validation
//! - Support for ECDSA (P-256, P-384), RSA PKCS#1 v1.5, RSA-PSS, and Ed25519 signatures
//!
//! # Example
//!
//! ```
//! use rugix_pki::{CmsSigner, CmsVerifier};
//! #
//! # let ca_key = rcgen::KeyPair::generate().unwrap();
//! # let ca_cert = rcgen::CertificateParams::new(["Test CA".to_string()])
//! #    .unwrap()
//! #    .self_signed(&ca_key)
//! #    .unwrap();
//! # let signer_key = rcgen::KeyPair::generate().unwrap();
//! # let signer_cert = rcgen::CertificateParams::new(["Test Signer".to_string()])
//! #    .unwrap()
//! #    .signed_by(&signer_key, &ca_cert, &ca_key)
//! #    .unwrap();
//! # let signer_cert_pem = signer_cert.pem();
//! # let signer_key_pem = signer_key.serialize_pem();
//! # let signer_cert_pem = signer_cert_pem.as_bytes();
//! # let signer_key_pem = signer_key_pem.as_bytes();
//! # let ca_cert_pem = ca_cert.pem();
//! # let ca_cert_pem = ca_cert_pem.as_bytes();
//!
//! let signer = CmsSigner::new(signer_cert_pem, signer_key_pem).unwrap();
//! let signature = signer.sign(b"Hello, World!").unwrap();
//!
//! let verifier = CmsVerifier::new(ca_cert_pem).unwrap();
//! let result = verifier.verify(&signature).unwrap();
//! assert_eq!(result.content, b"Hello, World!");
//! ```

mod inspect;
mod pem;
mod sign;
mod verify;

pub use inspect::CmsInspection;
pub use inspect::inspect_cms;
pub use sign::CmsSigner;
pub use sign::CmsSignerBuilder;
pub use sign::RsaHashAlgorithm;
pub use sign::RsaSignatureMode;
pub use verify::CmsVerifier;
pub use verify::VerificationResult;

use thiserror::Error;

/// Errors that can occur during PKI operations.
#[derive(Debug, Error)]
pub enum PkiError {
    /// Failed to parse PEM-encoded data.
    #[error("failed to parse PEM data: {0}")]
    PemParse(String),

    /// Failed to parse DER-encoded data.
    #[error("failed to parse DER data: {0}")]
    DerParse(String),

    /// Failed to parse a certificate.
    #[error("failed to parse certificate: {0}")]
    CertificateParse(String),

    /// Failed to parse a private key.
    #[error("failed to parse private key: {0}")]
    PrivateKeyParse(String),

    /// The private key algorithm is not supported.
    #[error("unsupported private key algorithm: {0}")]
    UnsupportedKeyAlgorithm(String),

    /// The signature algorithm is not supported.
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),

    /// Signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// The CMS structure is invalid.
    #[error("invalid CMS structure: {0}")]
    InvalidCms(String),

    /// No certificates found in the CMS structure.
    #[error("no certificates found in CMS structure")]
    NoCertificates,

    /// No signer information found.
    #[error("no signer information found")]
    NoSignerInfo,

    /// Certificate chain validation failed.
    #[error("certificate chain validation failed: {0}")]
    ChainValidation(String),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    /// The signed content does not match.
    #[error("content mismatch")]
    ContentMismatch,

    /// No encapsulated content in CMS structure.
    #[error("no encapsulated content in CMS structure")]
    NoEncapsulatedContent,

    /// The private key does not correspond to the public key in the certificate.
    #[error("private key does not match the public key in the certificate")]
    KeyMismatch,
}

/// Result type for PKI operations.
pub type PkiResult<T> = Result<T, PkiError>;

/// Supported signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA with P-256 and SHA-256.
    EcdsaP256Sha256,
    /// ECDSA with P-384 and SHA-384.
    EcdsaP384Sha384,
    /// RSA with PKCS#1 v1.5 padding and SHA-256.
    RsaPkcs1Sha256,
    /// RSA with PKCS#1 v1.5 padding and SHA-384.
    RsaPkcs1Sha384,
    /// RSA with PKCS#1 v1.5 padding and SHA-512.
    RsaPkcs1Sha512,
    /// RSA-PSS with SHA-256.
    RsaPssSha256,
    /// RSA-PSS with SHA-384.
    RsaPssSha384,
    /// RSA-PSS with SHA-512.
    RsaPssSha512,
    /// Ed25519 (EdDSA with Curve25519).
    Ed25519,
}

/// RSA-PSS parameters as defined in RFC 4055.
#[derive(Clone, Debug, Eq, PartialEq, der::Sequence)]
pub(crate) struct RsaPssParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub hash_algorithm: Option<spki::AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub mask_gen_algorithm: Option<spki::AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub salt_length: Option<u8>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub trailer_field: Option<u8>,
}

/// Compute a digest of the given content using the specified algorithm.
///
/// Returns `None` if the digest algorithm OID is not supported.
pub(crate) fn compute_digest(
    content: &[u8],
    digest_oid: &const_oid::ObjectIdentifier,
) -> Option<Vec<u8>> {
    use aws_lc_rs::digest::SHA256;
    use aws_lc_rs::digest::SHA384;
    use aws_lc_rs::digest::SHA512;
    use aws_lc_rs::digest::digest;
    use const_oid::db::rfc5912::ID_SHA_256;
    use const_oid::db::rfc5912::ID_SHA_384;
    use const_oid::db::rfc5912::ID_SHA_512;

    if *digest_oid == ID_SHA_256 {
        Some(digest(&SHA256, content).as_ref().to_vec())
    } else if *digest_oid == ID_SHA_384 {
        Some(digest(&SHA384, content).as_ref().to_vec())
    } else if *digest_oid == ID_SHA_512 {
        Some(digest(&SHA512, content).as_ref().to_vec())
    } else {
        None
    }
}
