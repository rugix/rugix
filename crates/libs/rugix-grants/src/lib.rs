//! Signed, constrained grants for typed device operations.
//!
//! [`sign`] creates a CMS envelope containing a [`Grant`]. [`GrantVerifier`]
//! verifies that envelope for a specific service, operation type, device identity,
//! and trusted time. Signatures cover the original bytes; JSON is never
//! reserialized for verification.
//!
//! Verification is one part of authorization. Executors must select trusted
//! issuers for the requested operation, enforce their resource policy, compare
//! the signed operation with the request, and durably enforce their replay policy
//! before side effects. This crate performs no I/O and executes no operations.
//! In particular, a [`VerifiedGrant`] is not proof that a grant is unused.

use std::time::Duration;
use std::time::SystemTime;

use rugix_pki::CmsSigner;
use rugix_pki::CmsVerifier;
use rugix_pki::PkiError;
use serde::de::DeserializeOwned;
use thiserror::Error;

sidex::include_bundle! {
    #[allow(
        clippy::redundant_static_lifetimes,
        clippy::empty_docs,
        clippy::manual_unwrap_or_default,
        clippy::match_single_binding
    )]
    rugix_grants as generated
}

pub mod authority;

pub use generated::grant;
pub use generated::grant::Audience;
pub use generated::grant::AudienceTarget;
pub use generated::grant::Grant;

/// Cryptographic domain separator preceding the UTF-8 JSON envelope.
///
/// The prefix also prevents ordinary bundle metadata from being accepted as a
/// grant. Changing either the framing or its interpretation requires a new version.
pub const CONTENT_PREFIX: &[u8] = b"rugix.operation-grant.v1\0";

/// Default maximum CMS envelope size, including certificates.
pub const DEFAULT_MAX_GRANT_SIZE: usize = 1024 * 1024;

/// Default maximum grant validity window.
pub const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// A typed operation with a globally distinct, versioned wire identifier.
///
/// Define the payload in Sidex. Deserialization must report unknown fields to
/// Serde and reject duplicate fields. Use externally tagged Sidex variants so
/// deserialization preserves unknown-field reporting through nested payloads.
/// Internally tagged variants buffer their content and can hide unknown fields
/// from Serde's tracking adapter. Test rejection of unknown nested constraints.
/// Permissive maps or arbitrary JSON values cannot express enforceable constraints.
pub trait Operation: sidex_serde::SidexType {
    /// For example, `rugix.install.v1`.
    const TYPE: &'static str;

    /// Permission required by this operation's authenticated arguments.
    ///
    /// Override this for operations with distinct authority scopes. Identifiers
    /// must be globally distinct and versioned, and must never depend on untrusted
    /// caller configuration. A future change in meaning requires a new identifier.
    fn permission(&self) -> &'static str {
        Self::TYPE
    }
}

/// Device facts supplied by the executor's trusted identity provider.
///
/// These must not originate from the untrusted operation request or the grant.
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    /// Provisioned namespace shared with the issuing authority.
    pub namespace: String,
    /// Provisioned device identifier.
    pub device_id: String,
    /// Provisioned or independently authenticated group membership.
    pub groups: Vec<String>,
}

/// Inputs supplied by the executor for this verification.
pub struct VerificationContext<'a> {
    /// Exact service identifier expected by the executor.
    pub verifier: &'a str,
    /// Independently established device identity and membership.
    pub identity: &'a DeviceIdentity,
    /// Trusted current time, used for both grants and certificate validity.
    ///
    /// The caller must refuse verification if trustworthy current time is
    /// unavailable. Neither a grant timestamp nor CMS signing-time establishes it.
    pub now: SystemTime,
}

/// Verifies grants against one locally authorized certificate authority.
///
/// Construct separate verifiers when authorities have different permissions.
/// The trust root comes from local policy, never from the submitted grant.
pub struct GrantVerifier {
    cms: CmsVerifier,
    authority_cms: CmsVerifier,
    max_size: usize,
    max_lifetime: Duration,
}

impl GrantVerifier {
    /// Use a PEM root certificate and the default resource and lifetime limits.
    pub fn new(root_certificate: &[u8]) -> Result<Self, GrantError> {
        Ok(Self {
            cms: CmsVerifier::new(root_certificate).map_err(GrantError::Signature)?,
            authority_cms: CmsVerifier::new(root_certificate)
                .map_err(GrantError::Signature)?
                .with_required_key_usage(authority::GRANT_AUTHORITY_EKU.as_bytes()),
            max_size: DEFAULT_MAX_GRANT_SIZE,
            max_lifetime: DEFAULT_MAX_LIFETIME,
        })
    }

    /// Set the maximum accepted CMS size and signed validity window.
    pub fn with_limits(mut self, max_size: usize, max_lifetime: Duration) -> Self {
        self.max_size = max_size;
        self.max_lifetime = max_lifetime;
        self
    }

    /// Verify a signed grant for the expected typed operation and device context.
    ///
    /// Unknown envelope and operation fields are rejected, including constraints
    /// added by a future issuer that this executor does not understand.
    pub fn verify<T: Operation>(
        &self,
        signed_grant: &[u8],
        context: &VerificationContext<'_>,
    ) -> Result<VerifiedGrant<T>, GrantError> {
        if signed_grant.len() > self.max_size {
            return Err(GrantError::SizeLimit);
        }
        let (verified, constrained) = self.authority_cms
            .verify_at(signed_grant, context.now)
            .map(|verified| (verified, true))
            .or_else(|authority_error| {
                self.cms.verify_at(signed_grant, context.now)
                    .map(|verified| (verified, false))
                    .map_err(|legacy_error| PkiError::SignatureVerification(format!(
                        "grant authority verification failed: {authority_error}; code signing verification failed: {legacy_error}"
                    )))
            })
            .map_err(GrantError::Signature)?;
        let content = verified
            .content
            .strip_prefix(CONTENT_PREFIX)
            .ok_or(GrantError::UnsupportedFormat)?;
        let grant: Grant<T> = decode_strict(content)?;
        validate_structure(&grant)?;
        if Duration::from_secs(grant.expires_at - grant.not_before) > self.max_lifetime {
            return Err(GrantError::LifetimeLimit);
        }
        validate_context(&grant, context)?;
        authority::verify(&verified.certificate_chain, constrained, &grant)?;
        Ok(VerifiedGrant {
            grant,
            signer_certificate: verified.signer_certificate,
        })
    }
}

/// A grant authenticated for the context passed to [`GrantVerifier::verify`].
///
/// Fields are immutable to keep the authenticated operation bound to its context.
/// Local authorization and replay checks remain the executor's responsibility.
pub struct VerifiedGrant<T> {
    grant: Grant<T>,
    signer_certificate: Vec<u8>,
}

impl<T> VerifiedGrant<T> {
    /// Authenticated envelope and operation.
    pub fn grant(&self) -> &Grant<T> {
        &self.grant
    }

    /// DER certificate of the signer accepted by the configured trust root.
    pub fn signer_certificate(&self) -> &[u8] {
        &self.signer_certificate
    }
}

/// Encode an unsigned grant for an external CMS signer.
///
/// The external signer must sign these exact bytes with encapsulated content.
pub fn prepare<T: Operation>(grant: &Grant<T>) -> Result<Vec<u8>, GrantError> {
    validate_structure(grant)?;
    let mut content = CONTENT_PREFIX.to_vec();
    serde_json::to_writer(&mut content, grant).map_err(GrantError::Encoding)?;
    Ok(content)
}

/// Sign a typed grant using the existing CMS certificate infrastructure.
pub fn sign<T: Operation>(grant: &Grant<T>, signer: &CmsSigner) -> Result<Vec<u8>, GrantError> {
    signer.sign(&prepare(grant)?).map_err(GrantError::Signature)
}

/// Failures callers can distinguish when deciding whether to retry or reject.
#[derive(Debug, Error)]
pub enum GrantError {
    /// CMS signature or certificate chain validation failed.
    #[error("grant signature verification or signing failed")]
    Signature(#[source] PkiError),
    /// The framing or envelope version is unsupported.
    #[error("unsupported grant format")]
    UnsupportedFormat,
    /// Typed JSON decoding failed.
    #[error("invalid grant encoding")]
    Encoding(#[source] serde_json::Error),
    /// A field was not understood by this verifier.
    #[error("grant contains an unsupported field")]
    UnsupportedField,
    /// Required identifiers or validity bounds are invalid.
    #[error("invalid grant identifiers or validity window")]
    InvalidGrant,
    /// The type of the signed operation differs from the requested operation.
    #[error("grant operation type does not match")]
    OperationMismatch,
    /// The signed service differs from the executor.
    #[error("grant verifier does not match")]
    VerifierMismatch,
    /// The device is not in the signed audience.
    #[error("grant audience does not match")]
    AudienceMismatch,
    /// Trusted time is outside the signed validity window.
    #[error("grant is outside its validity window")]
    OutsideValidity,
    /// The grant exceeds the local validity window limit.
    #[error("grant validity window exceeds the configured limit")]
    LifetimeLimit,
    /// The CMS envelope exceeds the local size limit.
    #[error("grant size exceeds the configured limit")]
    SizeLimit,
    /// A certificate has an unsupported or malformed authority policy.
    #[error("invalid grant authority certificate or constraints")]
    InvalidAuthority,
    /// A subordinate authority exceeds its parent's scope, validity, or delegation depth.
    #[error("grant authority exceeds its parent delegation")]
    AuthorityEscalation,
    /// The grant exceeds its issuing authority's permissions or validity.
    #[error("grant exceeds its issuing authority")]
    AuthorityDenied,
}

/// Decode without accepting unknown constraints, duplicate fields, or trailing data.
fn decode_strict<T: DeserializeOwned>(content: &[u8]) -> Result<T, GrantError> {
    let mut decoder = serde_json::Deserializer::from_slice(content);
    let mut ignored = false;
    let value = serde_ignored::deserialize(&mut decoder, |_| ignored = true)
        .map_err(GrantError::Encoding)?;
    decoder.end().map_err(GrantError::Encoding)?;
    if ignored {
        return Err(GrantError::UnsupportedField);
    }
    Ok(value)
}

/// Validate structural invariants independently of the verifier's environment.
fn validate_structure<T: Operation>(grant: &Grant<T>) -> Result<(), GrantError> {
    if grant.version != 1 {
        return Err(GrantError::UnsupportedFormat);
    }
    if grant.operation_type != T::TYPE {
        return Err(GrantError::OperationMismatch);
    }
    let target = match &grant.audience.target {
        AudienceTarget::Device(id) | AudienceTarget::Group(id) => id,
    };
    if grant.id.is_empty()
        || grant.verifier.is_empty()
        || grant.audience.namespace.is_empty()
        || target.is_empty()
        || grant.not_before >= grant.expires_at
    {
        return Err(GrantError::InvalidGrant);
    }
    Ok(())
}

/// Match signed restrictions against independently established context.
fn validate_context<T>(
    grant: &Grant<T>,
    context: &VerificationContext<'_>,
) -> Result<(), GrantError> {
    if grant.verifier != context.verifier {
        return Err(GrantError::VerifierMismatch);
    }
    let identity = context.identity;
    let matches = grant.audience.namespace == identity.namespace
        && match &grant.audience.target {
            AudienceTarget::Device(id) => id == &identity.device_id,
            AudienceTarget::Group(id) => identity.groups.contains(id),
        };
    if !matches {
        return Err(GrantError::AudienceMismatch);
    }
    let now = context
        .now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| GrantError::OutsideValidity)?
        .as_secs();
    if now < grant.not_before || now >= grant.expires_at {
        return Err(GrantError::OutsideValidity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;
    use serde::Deserialize;
    use serde::Serialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Restart {
        service: String,
    }
    sidex_serde::impl_sidex_type!(Restart);
    impl Operation for Restart {
        const TYPE: &'static str = "example.restart.v1";
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Remove {
        service: String,
    }
    sidex_serde::impl_sidex_type!(Remove);
    impl Operation for Remove {
        const TYPE: &'static str = "example.remove.v1";
    }

    struct Fixture {
        signer: CmsSigner,
        verifier: GrantVerifier,
        identity: DeviceIdentity,
    }

    impl Fixture {
        fn new() -> Self {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec![]).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let ca = params.self_signed(&key).unwrap();
            let signing_key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec![]).unwrap();
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2030, 1, 1);
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let cert = params.signed_by(&signing_key, &ca, &key).unwrap();
            Self {
                signer: CmsSigner::new(
                    cert.pem().as_bytes(),
                    signing_key.serialize_pem().as_bytes(),
                )
                .unwrap(),
                verifier: GrantVerifier::new(ca.pem().as_bytes()).unwrap(),
                identity: DeviceIdentity {
                    namespace: "example".into(),
                    device_id: "device-1".into(),
                    groups: vec!["canary".into()],
                },
            }
        }
        fn grant(&self) -> Grant<Restart> {
            Grant {
                version: 1,
                id: "grant-1".into(),
                verifier: "example-agent".into(),
                audience: Audience {
                    namespace: "example".into(),
                    target: AudienceTarget::Device("device-1".into()),
                },
                not_before: 1_800_000_000,
                expires_at: 1_800_000_060,
                operation_type: Restart::TYPE.into(),
                operation: Restart {
                    service: "demo".into(),
                },
            }
        }
        fn context(&self, now: u64) -> VerificationContext<'_> {
            VerificationContext {
                verifier: "example-agent",
                identity: &self.identity,
                now: SystemTime::UNIX_EPOCH + Duration::from_secs(now),
            }
        }
        fn sign_content(&self, content: &[u8]) -> Vec<u8> {
            self.signer.sign(content).unwrap()
        }
    }

    /// A signed operation round-trips and is valid only inside its half-open window.
    #[test]
    fn typed_grant_round_trip_and_time_boundaries() {
        let fixture = Fixture::new();
        let grant = fixture.grant();
        let signed = sign(&grant, &fixture.signer).unwrap();
        for now in [grant.not_before, grant.expires_at - 1] {
            let verified = fixture
                .verifier
                .verify::<Restart>(&signed, &fixture.context(now))
                .unwrap();
            assert_eq!(verified.grant(), &grant);
            assert!(!verified.signer_certificate().is_empty());
        }
        for now in [grant.not_before - 1, grant.expires_at] {
            assert!(matches!(
                fixture
                    .verifier
                    .verify::<Restart>(&signed, &fixture.context(now)),
                Err(GrantError::OutsideValidity)
            ));
        }
    }

    /// Service and operation bindings prevent reusing a valid grant in another protocol.
    #[test]
    fn service_and_operation_are_bound() {
        let fixture = Fixture::new();
        let signed = sign(&fixture.grant(), &fixture.signer).unwrap();
        let mut context = fixture.context(1_800_000_000);
        assert!(matches!(
            fixture.verifier.verify::<Remove>(&signed, &context),
            Err(GrantError::OperationMismatch)
        ));
        context.verifier = "other-agent";
        assert!(matches!(
            fixture.verifier.verify::<Restart>(&signed, &context),
            Err(GrantError::VerifierMismatch)
        ));
    }

    /// Device and group matching uses independently supplied, namespaced identity.
    #[test]
    fn audience_is_checked_against_provisioned_identity() {
        let fixture = Fixture::new();
        let mut grant = fixture.grant();
        let context = fixture.context(grant.not_before);
        for target in [
            AudienceTarget::Device("device-2".into()),
            AudienceTarget::Group("production".into()),
        ] {
            grant.audience.target = target;
            let signed = sign(&grant, &fixture.signer).unwrap();
            assert!(matches!(
                fixture.verifier.verify::<Restart>(&signed, &context),
                Err(GrantError::AudienceMismatch)
            ));
        }
        grant.audience.target = AudienceTarget::Group("canary".into());
        assert!(
            fixture
                .verifier
                .verify::<Restart>(&sign(&grant, &fixture.signer).unwrap(), &context)
                .is_ok()
        );
        grant.audience.namespace = "other".into();
        assert!(matches!(
            fixture
                .verifier
                .verify::<Restart>(&sign(&grant, &fixture.signer).unwrap(), &context),
            Err(GrantError::AudienceMismatch)
        ));
    }

    /// Unknown constraints and ambiguous or trailing JSON are rejected despite valid
    /// signatures.
    #[test]
    fn unsupported_and_ambiguous_content_is_rejected() {
        let fixture = Fixture::new();
        let content = String::from_utf8(prepare(&fixture.grant()).unwrap()).unwrap();
        let context = fixture.context(1_800_000_000);
        for altered in [
            content.replace("\"version\":1", "\"version\":2"),
            content.replace(
                "\"id\":\"grant-1\"",
                "\"id\":\"grant-1\",\"futureConstraint\":true",
            ),
            content.replace(
                "\"service\":\"demo\"",
                "\"service\":\"demo\",\"futureConstraint\":true",
            ),
            content.replace("\"id\":\"grant-1\"", "\"id\":\"grant-1\",\"id\":\"other\""),
            content.replace(
                "\"namespace\":\"example\"",
                "\"namespace\":\"example\",\"namespace\":\"other\"",
            ),
            content.replace(
                "\"service\":\"demo\"",
                "\"service\":\"demo\",\"service\":\"other\"",
            ),
            format!("{content}{{}}"),
            content.replace("rugix.operation-grant.v1", "rugix.operation-grant.v2"),
        ] {
            assert_ne!(altered, content);
            assert!(
                fixture
                    .verifier
                    .verify::<Restart>(&fixture.sign_content(altered.as_bytes()), &context)
                    .is_err(),
                "accepted altered content: {altered}"
            );
        }
        assert!(
            fixture
                .verifier
                .verify::<Restart>(&fixture.sign_content(b"ordinary bundle metadata"), &context)
                .is_err()
        );
    }

    /// Altered signed bytes and a different issuer cannot authenticate an operation.
    #[test]
    fn signature_and_issuer_are_verified() {
        let fixture = Fixture::new();
        let other = Fixture::new();
        let mut signed = sign(&fixture.grant(), &fixture.signer).unwrap();
        let context = fixture.context(1_800_000_000);
        assert!(matches!(
            other.verifier.verify::<Restart>(&signed, &context),
            Err(GrantError::Signature(_))
        ));
        let offset = signed
            .windows(4)
            .position(|bytes| bytes == b"demo")
            .unwrap();
        signed[offset] = b'x';
        assert!(matches!(
            fixture.verifier.verify::<Restart>(&signed, &context),
            Err(GrantError::Signature(_))
        ));
    }

    /// Grant and certificate expiry use the same caller-established time.
    #[test]
    fn certificate_validity_uses_supplied_time() {
        let fixture = Fixture::new();
        let mut grant = fixture.grant();
        grant.not_before = 2_000_000_000;
        grant.expires_at = grant.not_before + 60;
        let signed = sign(&grant, &fixture.signer).unwrap();
        assert!(matches!(
            fixture
                .verifier
                .verify::<Restart>(&signed, &fixture.context(grant.not_before)),
            Err(GrantError::Signature(_))
        ));
    }

    /// Local limits and invalid windows are enforced without timestamp arithmetic
    /// overflow.
    #[test]
    fn limits_and_invalid_windows_are_enforced() {
        let mut fixture = Fixture::new();
        let mut grant = fixture.grant();
        let signed = sign(&grant, &fixture.signer).unwrap();
        fixture.verifier.max_size = signed.len() - 1;
        assert!(matches!(
            fixture
                .verifier
                .verify::<Restart>(&signed, &fixture.context(grant.not_before)),
            Err(GrantError::SizeLimit)
        ));
        fixture.verifier.max_size = signed.len();
        fixture.verifier.max_lifetime = Duration::from_secs(59);
        assert!(matches!(
            fixture
                .verifier
                .verify::<Restart>(&signed, &fixture.context(grant.not_before)),
            Err(GrantError::LifetimeLimit)
        ));
        grant.expires_at = grant.not_before;
        assert!(matches!(prepare(&grant), Err(GrantError::InvalidGrant)));
        grant.not_before = u64::MAX;
        grant.expires_at = 0;
        assert!(matches!(prepare(&grant), Err(GrantError::InvalidGrant)));
    }
}
