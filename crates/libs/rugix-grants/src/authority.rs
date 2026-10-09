//! Certificate-bound authority for operation grants.
//!
//! A grant authority certificate carries a critical extended key usage holding
//! [`GRANT_AUTHORITY_EKU`] plus one purpose per operation it may authorize, and a
//! non-critical [`AUTHORITY_SCOPE_OID`] extension holding a DER [`AuthorityScope`].
//! Both are mandatory on every certificate below the trust anchor, so a
//! certificate that was not prepared for this purpose cannot authorize anything.
//!
//! Delegation depth, certificate validity, and purpose propagation use standard
//! X.509 basic constraints, validity periods, and extended key usage, which the
//! X.509 path verifier already enforces for every certificate in the path. Only
//! the namespace and audience selectors need checking here.

use const_oid::ObjectIdentifier;
use der::Decode;
use der::Encode;
use der::asn1::Null;
use x509_cert::Certificate;
use x509_cert::ext::pkix::ExtendedKeyUsage;

use crate::AudienceTarget;
use crate::Grant;
use crate::GrantError;
use crate::Operation;

/// Dedicated key purpose for grant authorities.
///
/// Assigned under Rugix's `1.3.6.1.4.1.67013.100` namespace (Silitics PEN 67013).
/// Requiring it keeps code-signing certificates from authorizing operations and
/// keeps grant authorities from signing bundles.
pub const GRANT_AUTHORITY_EKU: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.67013.100.1");

/// Extension holding the DER-encoded [`AuthorityScope`].
///
/// Assigned alongside [`GRANT_AUTHORITY_EKU`] under the Rugix namespace.
pub const AUTHORITY_SCOPE_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.67013.100.2");

/// Standard extended key usage extension, which authority certificates must carry.
pub const EXTENDED_KEY_USAGE_OID: ObjectIdentifier = const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE;

/// Key purposes an authority certificate must carry for `permissions`.
///
/// The extended key usage must hold [`GRANT_AUTHORITY_EKU`] and every operation
/// purpose the certificate may authorize, including purposes it only delegates to
/// subordinate authorities.
pub fn purposes(permissions: &[ObjectIdentifier]) -> Vec<ObjectIdentifier> {
    let mut purposes = vec![GRANT_AUTHORITY_EKU];
    purposes.extend_from_slice(permissions);
    purposes
}

/// Encode the value of the critical extended key usage extension.
pub fn purposes_extension_der(permissions: &[ObjectIdentifier]) -> Result<Vec<u8>, GrantError> {
    ExtendedKeyUsage(purposes(permissions))
        .to_der()
        .map_err(|_| GrantError::InvalidAuthority)
}

/// Only version of the scope encoding.
const SCOPE_VERSION: u8 = 1;

/// Identity namespace and audience selectors delegated to a certificate's key.
///
/// ```text
/// AuthorityScope ::= SEQUENCE {
///     version    INTEGER,
///     namespace  UTF8String,
///     targets    SEQUENCE OF ScopeTarget
/// }
/// ```
///
/// DER decoding rejects unknown elements and trailing data, so a scope this
/// verifier does not fully understand authorizes nothing.
#[derive(Debug, Clone, PartialEq, Eq, der::Sequence)]
pub struct AuthorityScope {
    /// Scope encoding version. Must be `1`.
    pub version: u8,
    /// Exact identity namespace of every grant this key may sign.
    pub namespace: String,
    /// Audience selectors this key may address. An empty list authorizes nothing.
    pub targets: Vec<ScopeTarget>,
}

/// One audience selector.
///
/// ```text
/// ScopeTarget ::= CHOICE {
///     any       [0] NULL,
///     recipient [1] UTF8String,
///     group     [2] UTF8String
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, der::Choice)]
pub enum ScopeTarget {
    /// Every audience within the namespace. Breadth is always stated explicitly.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Any(Null),
    /// One recipient identity.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT")]
    Recipient(String),
    /// One provisioned group.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Group(String),
}

impl ScopeTarget {
    /// Selector matching every audience within the namespace.
    pub fn any() -> Self {
        Self::Any(Null)
    }
}

impl AuthorityScope {
    /// Delegate `targets` within `namespace`.
    pub fn new(namespace: impl Into<String>, targets: Vec<ScopeTarget>) -> Self {
        Self {
            version: SCOPE_VERSION,
            namespace: namespace.into(),
            targets,
        }
    }

    /// Encode the value of the authority scope extension.
    ///
    /// Certificate issuance must also set a critical extended key usage holding
    /// [`GRANT_AUTHORITY_EKU`] and the permitted operation purposes. The scope
    /// extension itself is non-critical because the X.509 verifier rejects
    /// critical extensions it does not recognize.
    pub fn to_extension_der(&self) -> Result<Vec<u8>, GrantError> {
        self.validate()?;
        self.to_der().map_err(|_| GrantError::InvalidAuthority)
    }

    /// Reject scopes whose meaning is undefined.
    fn validate(&self) -> Result<(), GrantError> {
        let targets_valid = self.targets.iter().all(|target| match target {
            ScopeTarget::Any(_) => true,
            ScopeTarget::Recipient(id) | ScopeTarget::Group(id) => !id.is_empty(),
        });
        if self.version != SCOPE_VERSION || self.namespace.is_empty() || !targets_valid {
            return Err(GrantError::InvalidAuthority);
        }
        Ok(())
    }

    /// A child may drop selectors but never add one its parent does not permit.
    fn is_subset_of(&self, parent: &Self) -> bool {
        self.namespace == parent.namespace
            && self.targets.iter().all(|target| {
                parent.targets.iter().any(|permitted| match permitted {
                    ScopeTarget::Any(_) => true,
                    _ => permitted == target,
                })
            })
    }

    /// Check a concrete grant against the narrowest scope in the path.
    fn permits<T>(&self, grant: &Grant<T>) -> bool {
        self.namespace == grant.audience.namespace
            && self
                .targets
                .iter()
                .any(|permitted| match (permitted, &grant.audience.target) {
                    (ScopeTarget::Any(_), _) => true,
                    (ScopeTarget::Recipient(id), AudienceTarget::Recipient(target))
                    | (ScopeTarget::Group(id), AudienceTarget::Group(target)) => id == target,
                    _ => false,
                })
    }
}

/// Enforce authority on exactly the path authenticated by the X.509 verifier.
///
/// The final entry is the locally selected trust anchor. Local configuration
/// authorizes the anchor, so it may omit the purpose and the scope extension. A
/// scope attached to the anchor is still enforced.
pub(crate) fn verify<T: Operation>(chain: &[Vec<u8>], grant: &Grant<T>) -> Result<(), GrantError> {
    let permission = grant.operation.permission();
    let mut narrowest: Option<AuthorityScope> = None;
    for (index, der) in chain.iter().enumerate().rev() {
        let certificate = Certificate::from_der(der).map_err(|_| GrantError::InvalidAuthority)?;
        let is_anchor = index == chain.len() - 1;
        let Some(scope) = scope_extension(&certificate)? else {
            if !is_anchor {
                return Err(GrantError::InvalidAuthority);
            }
            continue;
        };
        if !is_anchor {
            require_purposes(&certificate, permission)?;
        }
        if let Some(parent) = &narrowest
            && !scope.is_subset_of(parent)
        {
            return Err(GrantError::AuthorityEscalation);
        }
        narrowest = Some(scope);
    }
    match narrowest {
        Some(scope) if scope.permits(grant) => Ok(()),
        Some(_) => Err(GrantError::AuthorityDenied),
        None => Err(GrantError::InvalidAuthority),
    }
}

/// Read the mandatory scope extension, rejecting duplicate or critical encodings.
fn scope_extension(certificate: &Certificate) -> Result<Option<AuthorityScope>, GrantError> {
    // Read the extensions directly to reject duplicates rather than accept the first.
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default();
    let mut found = extensions
        .iter()
        .filter(|extension| extension.extn_id == AUTHORITY_SCOPE_OID);
    let Some(extension) = found.next() else {
        return Ok(None);
    };
    if found.next().is_some() {
        return Err(GrantError::InvalidAuthority);
    }
    let scope = AuthorityScope::from_der(extension.extn_value.as_bytes())
        .map_err(|_| GrantError::InvalidAuthority)?;
    scope.validate()?;
    Ok(Some(scope))
}

/// Require the grant purpose and the operation's own purpose on one certificate.
///
/// The X.509 verifier requires [`GRANT_AUTHORITY_EKU`] on every certificate below
/// the anchor. Requiring the operation purpose here extends that to delegation:
/// an authority without the purpose cannot issue a key that has it.
fn require_purposes(
    certificate: &Certificate,
    permission: ObjectIdentifier,
) -> Result<(), GrantError> {
    let (critical, purposes) = certificate
        .tbs_certificate
        .get::<ExtendedKeyUsage>()
        .map_err(|_| GrantError::InvalidAuthority)?
        .ok_or(GrantError::InvalidAuthority)?;
    if !critical || !purposes.0.contains(&GRANT_AUTHORITY_EKU) {
        return Err(GrantError::InvalidAuthority);
    }
    if !purposes.0.contains(&permission) {
        return Err(GrantError::PermissionDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::SystemTime;

    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::CustomExtension;
    use rcgen::DnType;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;
    use rugix_pki::CmsSignerBuilder;
    use rugix_pki::CmsVerifier;
    use serde::Deserialize;
    use serde::Serialize;

    use super::*;
    use crate::Audience;
    use crate::GrantVerifier;
    use crate::RecipientIdentity;
    use crate::VerificationContext;
    use crate::sign;

    const NOW: u64 = 1_800_000_000;
    const RESTART: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.67013.100.1.9001");
    const REMOVE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.67013.100.1.9002");
    static NEXT_NAME: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Restart {}
    sidex_serde::impl_sidex_type!(Restart);
    impl Operation for Restart {
        const TYPE: &'static str = "example.restart.v1";

        fn permission(&self) -> ObjectIdentifier {
            RESTART
        }
    }

    struct Issued {
        cert: rcgen::Certificate,
        key: KeyPair,
    }

    /// Issue a certificate, prepared as a grant authority for `RESTART` when a
    /// scope is supplied.
    fn issue(
        parent: Option<&Issued>,
        scope: Option<&AuthorityScope>,
        ca: bool,
        change: impl FnOnce(&mut CertificateParams),
    ) -> Issued {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.distinguished_name.push(
            DnType::CommonName,
            format!("authority-{}", NEXT_NAME.fetch_add(1, Ordering::Relaxed)),
        );
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        params.is_ca = if ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::NoCa
        };
        params.key_usages = vec![if ca {
            KeyUsagePurpose::KeyCertSign
        } else {
            KeyUsagePurpose::DigitalSignature
        }];
        if let Some(scope) = scope {
            params.custom_extensions.push(purposes(&[RESTART]));
            params
                .custom_extensions
                .push(scope_extension_for(&scope.to_extension_der().unwrap()));
        }
        change(&mut params);
        let key = KeyPair::generate().unwrap();
        let cert = match parent {
            Some(parent) => params.signed_by(&key, &parent.cert, &parent.key).unwrap(),
            None => params.self_signed(&key).unwrap(),
        };
        Issued { cert, key }
    }

    /// Critical extended key usage holding the grant purpose and `permissions`.
    fn purposes(permissions: &[ObjectIdentifier]) -> CustomExtension {
        let mut extension = CustomExtension::from_oid_content(
            &arcs(EXTENDED_KEY_USAGE_OID),
            purposes_extension_der(permissions).unwrap(),
        );
        extension.set_criticality(true);
        extension
    }

    fn scope_extension_for(der: &[u8]) -> CustomExtension {
        CustomExtension::from_oid_content(&arcs(AUTHORITY_SCOPE_OID), der.to_vec())
    }

    fn arcs(oid: ObjectIdentifier) -> Vec<u64> {
        oid.arcs().map(u64::from).collect()
    }

    fn scope() -> AuthorityScope {
        AuthorityScope::new("example", vec![ScopeTarget::any()])
    }

    fn grant() -> Grant<Restart> {
        Grant {
            version: 1,
            id: "test".into(),
            service: "agent".into(),
            audience: Audience {
                namespace: "example".into(),
                target: AudienceTarget::Recipient("recipient-1".into()),
            },
            not_before: NOW,
            expires_at: NOW + 60,
            operation_type: Restart::TYPE.into(),
            operation: Restart {},
        }
    }

    fn signed(chain: &[&Issued], grant: &Grant<Restart>) -> Vec<u8> {
        let mut signer = CmsSignerBuilder::new(
            chain[0].cert.pem().as_bytes(),
            chain[0].key.serialize_pem().as_bytes(),
        )
        .unwrap();
        for cert in &chain[1..] {
            signer = signer
                .with_intermediate_cert(cert.cert.pem().as_bytes())
                .unwrap();
        }
        sign(grant, &signer.build().unwrap()).unwrap()
    }

    fn verify(root: &Issued, chain: &[&Issued], grant: &Grant<Restart>) -> Result<(), GrantError> {
        verify_for(root, chain, grant, vec![RESTART])
    }

    fn verify_for(
        root: &Issued,
        chain: &[&Issued],
        grant: &Grant<Restart>,
        permissions: Vec<ObjectIdentifier>,
    ) -> Result<(), GrantError> {
        let identity = RecipientIdentity {
            namespace: grant.audience.namespace.clone(),
            recipient_id: "recipient-1".into(),
            groups: vec!["canary".into(), "production".into()],
        };
        GrantVerifier::new(root.cert.pem().as_bytes(), permissions)
            .unwrap()
            .verify::<Restart>(
                &signed(chain, grant),
                &VerificationContext {
                    service: &grant.service,
                    identity: &identity,
                    now: SystemTime::UNIX_EPOCH + Duration::from_secs(grant.not_before),
                },
            )
            .map(|_| ())
    }

    /// A prepared authority key works and cannot be reused for code signing.
    #[test]
    fn prepared_authority_is_usable_and_separate_from_code_signing() {
        let root = issue(None, None, true, |_| {});
        let leaf = issue(Some(&root), Some(&scope()), false, |_| {});
        verify(&root, &[&leaf], &grant()).unwrap();
        let code_signing = CmsVerifier::new(root.cert.pem().as_bytes()).unwrap();
        assert!(
            code_signing
                .verify_at(
                    &signed(&[&leaf], &grant()),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(NOW)
                )
                .is_err()
        );
    }

    /// A certificate without the grant purpose and scope cannot sign grants, which
    /// covers every ordinary code-signing certificate.
    #[test]
    fn unprepared_certificates_cannot_sign_grants() {
        let root = issue(None, None, true, |_| {});
        let bare = issue(Some(&root), None, false, |_| {});
        assert!(matches!(
            verify(&root, &[&bare], &grant()),
            Err(GrantError::Signature(_))
        ));
        let code_signing = issue(Some(&root), None, false, |params| {
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
        });
        assert!(matches!(
            verify(&root, &[&code_signing], &grant()),
            Err(GrantError::Signature(_))
        ));
        let purpose_only = issue(Some(&root), None, false, |params| {
            params.custom_extensions.push(purposes(&[RESTART]));
        });
        assert!(matches!(
            verify(&root, &[&purpose_only], &grant()),
            Err(GrantError::InvalidAuthority)
        ));
        let self_anchored = issue(None, None, false, |params| {
            params.custom_extensions.push(purposes(&[RESTART]));
        });
        assert!(matches!(
            verify(&self_anchored, &[&self_anchored], &grant()),
            Err(GrantError::InvalidAuthority)
        ));
    }

    /// A grant must satisfy the signer's namespace and audience selectors.
    #[test]
    fn grant_audience_is_bounded_by_the_signer() {
        let root = issue(None, None, true, |_| {});
        let scoped = AuthorityScope::new("example", vec![ScopeTarget::Group("canary".into())]);
        let leaf = issue(Some(&root), Some(&scoped), false, |_| {});
        let mut allowed = grant();
        allowed.audience.target = AudienceTarget::Group("canary".into());
        verify(&root, &[&leaf], &allowed).unwrap();
        assert!(matches!(
            verify(&root, &[&leaf], &grant()),
            Err(GrantError::AuthorityDenied)
        ));
        let mut other_group = allowed.clone();
        other_group.audience.target = AudienceTarget::Group("production".into());
        assert!(matches!(
            verify(&root, &[&leaf], &other_group),
            Err(GrantError::AuthorityDenied)
        ));
        let mut other_namespace = allowed;
        other_namespace.audience.namespace = "other".into();
        assert!(matches!(
            verify(&root, &[&leaf], &other_namespace),
            Err(GrantError::AuthorityDenied)
        ));
    }

    /// Permission comes from both the certificate purposes and local policy, and
    /// an authority cannot delegate a purpose it does not hold.
    #[test]
    fn permission_requires_purpose_and_local_policy() {
        let root = issue(None, None, true, |_| {});
        let leaf = issue(Some(&root), Some(&scope()), false, |_| {});
        assert!(matches!(
            verify_for(&root, &[&leaf], &grant(), vec![REMOVE]),
            Err(GrantError::PermissionDenied)
        ));
        let wrong_purpose = issue(Some(&root), Some(&scope()), false, |params| {
            params.custom_extensions[0] = purposes(&[REMOVE]);
        });
        assert!(matches!(
            verify(&root, &[&wrong_purpose], &grant()),
            Err(GrantError::PermissionDenied)
        ));
        let restricted_ca = issue(Some(&root), Some(&scope()), true, |params| {
            params.custom_extensions[0] = purposes(&[REMOVE]);
        });
        let escaping_leaf = issue(Some(&restricted_ca), Some(&scope()), false, |_| {});
        assert!(matches!(
            verify(&root, &[&escaping_leaf, &restricted_ca], &grant()),
            Err(GrantError::PermissionDenied)
        ));
    }

    /// A child authority cannot widen its parent's namespace or audience.
    #[test]
    fn child_scope_cannot_escalate() {
        let root = issue(None, None, true, |_| {});
        let parent_scope = AuthorityScope::new(
            "example",
            vec![ScopeTarget::Recipient("recipient-1".into())],
        );
        let parent = issue(Some(&root), Some(&parent_scope), true, |_| {});
        let leaf = issue(Some(&parent), Some(&parent_scope), false, |_| {});
        verify(&root, &[&leaf, &parent], &grant()).unwrap();
        for wider in [
            AuthorityScope::new("other", vec![ScopeTarget::Recipient("recipient-1".into())]),
            AuthorityScope::new("example", vec![ScopeTarget::any()]),
            AuthorityScope::new(
                "example",
                vec![
                    ScopeTarget::Recipient("recipient-1".into()),
                    ScopeTarget::Group("canary".into()),
                ],
            ),
        ] {
            let leaf = issue(Some(&parent), Some(&wider), false, |_| {});
            assert!(
                matches!(
                    verify(&root, &[&leaf, &parent], &grant()),
                    Err(GrantError::AuthorityEscalation)
                ),
                "accepted wider scope: {wider:?}"
            );
        }
    }

    /// Delegation depth and certificate validity come from standard X.509 path
    /// validation, so an unauthorized subordinate CA or an expired parent fails.
    #[test]
    fn standard_path_validation_bounds_delegation() {
        let root = issue(None, None, true, |_| {});
        let flat = issue(Some(&root), Some(&scope()), true, |params| {
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        });
        let middle = issue(Some(&flat), Some(&scope()), true, |_| {});
        let leaf = issue(Some(&middle), Some(&scope()), false, |_| {});
        assert!(matches!(
            verify(&root, &[&leaf, &middle, &flat], &grant()),
            Err(GrantError::Signature(_))
        ));
        let deep = issue(Some(&root), Some(&scope()), true, |params| {
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        });
        let middle = issue(Some(&deep), Some(&scope()), true, |_| {});
        let leaf = issue(Some(&middle), Some(&scope()), false, |_| {});
        verify(&root, &[&leaf, &middle, &deep], &grant()).unwrap();
        let expired = issue(Some(&root), Some(&scope()), true, |params| {
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        });
        let leaf = issue(Some(&expired), Some(&scope()), false, |_| {});
        assert!(matches!(
            verify(&root, &[&leaf, &expired], &grant()),
            Err(GrantError::Signature(_))
        ));
    }

    /// Malformed, critical, duplicate, and unknown scope encodings fail closed.
    #[test]
    fn invalid_scope_encodings_fail_closed() {
        let root = issue(None, None, true, |_| {});
        let valid = scope().to_extension_der().unwrap();
        let mut unknown_element = valid.clone();
        unknown_element.extend_from_slice(&[0x05, 0x00]);
        for invalid in [
            vec![],
            b"not der".to_vec(),
            unknown_element,
            AuthorityScope {
                version: 2,
                namespace: "example".into(),
                targets: vec![ScopeTarget::any()],
            }
            .to_der()
            .unwrap(),
            AuthorityScope {
                version: 1,
                namespace: String::new(),
                targets: vec![ScopeTarget::any()],
            }
            .to_der()
            .unwrap(),
            AuthorityScope {
                version: 1,
                namespace: "example".into(),
                targets: vec![ScopeTarget::Group(String::new())],
            }
            .to_der()
            .unwrap(),
        ] {
            let leaf = issue(Some(&root), Some(&scope()), false, |params| {
                params.custom_extensions[1] = scope_extension_for(&invalid);
            });
            assert!(
                matches!(
                    verify(&root, &[&leaf], &grant()),
                    Err(GrantError::InvalidAuthority)
                ),
                "accepted scope encoding: {invalid:?}"
            );
        }
        // The X.509 path verifier rejects critical extensions it does not
        // recognize, which is why issuance marks the scope non-critical.
        let critical = issue(Some(&root), Some(&scope()), false, |params| {
            params.custom_extensions[1].set_criticality(true);
        });
        assert!(matches!(
            verify(&root, &[&critical], &grant()),
            Err(GrantError::Signature(_))
        ));
        let duplicated = issue(Some(&root), Some(&scope()), false, |params| {
            params.custom_extensions.push(scope_extension_for(&valid));
        });
        assert!(verify(&root, &[&duplicated], &grant()).is_err());
        let empty_targets = issue(
            Some(&root),
            Some(&AuthorityScope::new("example", vec![])),
            false,
            |_| {},
        );
        assert!(matches!(
            verify(&root, &[&empty_targets], &grant()),
            Err(GrantError::AuthorityDenied)
        ));
    }

    /// An unrelated certificate in the envelope neither adds nor removes authority.
    #[test]
    fn unrelated_certificate_does_not_change_authority() {
        let root = issue(None, None, true, |_| {});
        let leaf = issue(Some(&root), Some(&scope()), false, |_| {});
        let unrelated = issue(
            Some(&root),
            Some(&AuthorityScope::new("example", vec![])),
            true,
            |_| {},
        );
        verify(&root, &[&leaf, &unrelated], &grant()).unwrap();
        let denied_leaf = issue(Some(&unrelated), Some(&scope()), false, |_| {});
        let permissive = issue(Some(&root), Some(&scope()), true, |_| {});
        assert!(matches!(
            verify(&root, &[&denied_leaf, &unrelated, &permissive], &grant()),
            Err(GrantError::AuthorityEscalation)
        ));
    }

    /// A scope on the locally configured anchor constrains every descendant.
    #[test]
    fn anchor_scope_is_enforced() {
        let scoped = AuthorityScope::new("example", vec![ScopeTarget::Group("canary".into())]);
        let root = issue(None, Some(&scoped), true, |_| {});
        let leaf = issue(Some(&root), Some(&scope()), false, |_| {});
        assert!(matches!(
            verify(&root, &[&leaf], &grant()),
            Err(GrantError::AuthorityEscalation)
        ));
        let leaf = issue(Some(&root), Some(&scoped), false, |_| {});
        let mut allowed = grant();
        allowed.audience.target = AudienceTarget::Group("canary".into());
        verify(&root, &[&leaf], &allowed).unwrap();
    }
}
