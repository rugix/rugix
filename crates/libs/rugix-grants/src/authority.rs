//! Certificate-bound authority for operation grants.
//!
//! Constrained certificates use a dedicated, critical extended key usage and
//! a mandatory constraints extension. The separate purpose prevents legacy
//! code-signing verifiers from accepting these keys without applying policy.

use const_oid::ObjectIdentifier;
use der::Decode;
use der::Encode;
use der::asn1::Utf8StringRef;
use x509_cert::Certificate;
use x509_cert::ext::pkix::ExtendedKeyUsage;

use crate::AudienceTarget;
use crate::Grant;
use crate::GrantError;
use crate::Operation;
use crate::decode_strict;

pub use crate::generated::authority::*;

/// Dedicated key purpose for constrained grant authorities.
///
/// Assigned under Rugix's `1.3.6.1.4.1.67013.100` namespace (Silitics PEN 67013).
pub const GRANT_AUTHORITY_EKU: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.67013.100.1");

/// Extension containing a DER UTF8String with the Sidex authority JSON.
///
/// Assigned alongside [`GRANT_AUTHORITY_EKU`] under the Rugix namespace.
pub const AUTHORITY_CONSTRAINTS_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.67013.100.2");

impl AuthorityConstraints {
    /// Parse and validate an authority policy, rejecting unknown or duplicate fields.
    pub fn from_json(json: &[u8]) -> Result<Self, GrantError> {
        let constraints: Self = decode_strict(json)?;
        constraints.validate()?;
        Ok(constraints)
    }

    /// Encode the value of the authority constraints extension.
    ///
    /// Certificate issuance must also set a critical extended key usage containing
    /// only [`GRANT_AUTHORITY_EKU`]. The constraints extension itself is non-critical.
    pub fn to_extension_der(&self) -> Result<Vec<u8>, GrantError> {
        self.validate()?;
        let json = serde_json::to_string(self).map_err(GrantError::Encoding)?;
        Utf8StringRef::new(&json)
            .and_then(|value| value.to_der())
            .map_err(|_| GrantError::InvalidAuthority)
    }

    /// Reject policies whose meaning is undefined.
    fn validate(&self) -> Result<(), GrantError> {
        if self.version != 1
            || self.namespace.is_empty()
            || self.max_grant_lifetime == 0
            || self
                .permissions
                .iter()
                .any(|p| p.verifier.is_empty() || p.operation.is_empty())
        {
            return Err(GrantError::InvalidAuthority);
        }
        if let AuthorityAudience::Targets(targets) = &self.audiences {
            for target in targets {
                let (AudienceTarget::Device(id) | AudienceTarget::Group(id)) = target;
                if id.is_empty() {
                    return Err(GrantError::InvalidAuthority);
                }
            }
        }
        Ok(())
    }

    /// A child may remove permissions, shorten lifetimes, or narrow audience selectors.
    fn is_subset_of(&self, parent: &Self) -> bool {
        self.namespace == parent.namespace
            && self.max_grant_lifetime <= parent.max_grant_lifetime
            && self
                .permissions
                .iter()
                .all(|p| parent.permissions.contains(p))
            && match (&self.audiences, &parent.audiences) {
                (_, AuthorityAudience::Any) => true,
                (AuthorityAudience::Targets(child), AuthorityAudience::Targets(parent)) => {
                    child.iter().all(|target| parent.contains(target))
                }
                (AuthorityAudience::Any, AuthorityAudience::Targets(_)) => false,
            }
    }

    /// Check the concrete grant against the final narrowed authority.
    fn permits<T: Operation>(&self, grant: &Grant<T>) -> bool {
        self.namespace == grant.audience.namespace
            && grant.expires_at - grant.not_before <= self.max_grant_lifetime
            && self.permissions.iter().any(|p| {
                p.verifier == grant.verifier && p.operation == grant.operation.permission()
            })
            && match &self.audiences {
                AuthorityAudience::Any => true,
                AuthorityAudience::Targets(targets) => targets.contains(&grant.audience.target),
            }
    }
}

/// Enforce constraints on exactly the path authenticated by the X.509 verifier.
///
/// The final entry is the locally selected trust anchor. An unconstrained anchor's
/// certificate validity is not a limit on local trust. A policy attached to that
/// anchor is enforced, including its validity window.
pub(crate) fn verify<T: Operation>(
    chain: &[Vec<u8>],
    constrained: bool,
    grant: &Grant<T>,
) -> Result<(), GrantError> {
    let mut parent: Option<(AuthorityConstraints, u64, u64)> = None;
    for (index, der) in chain.iter().enumerate().rev() {
        let cert = Certificate::from_der(der).map_err(|_| GrantError::InvalidAuthority)?;
        let is_root = index == chain.len() - 1;
        // Decode manually to reject duplicate extensions rather than accepting the first.
        let extensions = cert
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or_default();
        let mut policies = extensions
            .iter()
            .filter(|e| e.extn_id == AUTHORITY_CONSTRAINTS_OID);
        let policy = policies.next();
        if policies.next().is_some() {
            return Err(GrantError::InvalidAuthority);
        }
        let Some(policy) = policy else {
            if constrained && !is_root {
                return Err(GrantError::InvalidAuthority);
            }
            continue;
        };
        if !constrained || policy.critical {
            return Err(GrantError::InvalidAuthority);
        }
        if !is_root {
            let eku = cert
                .tbs_certificate
                .get::<ExtendedKeyUsage>()
                .map_err(|_| GrantError::InvalidAuthority)?
                .ok_or(GrantError::InvalidAuthority)?;
            if !eku.0 || eku.1.0.as_slice() != [GRANT_AUTHORITY_EKU] {
                return Err(GrantError::InvalidAuthority);
            }
        }
        let json = Utf8StringRef::from_der(policy.extn_value.as_bytes())
            .map_err(|_| GrantError::InvalidAuthority)?;
        let constraints = AuthorityConstraints::from_json(json.as_str().as_bytes())?;
        let start = cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let end = cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();
        if start >= end {
            return Err(GrantError::InvalidAuthority);
        }
        if let Some((parent_constraints, parent_start, parent_end)) = &parent {
            if !constraints.is_subset_of(parent_constraints)
                || start < *parent_start
                || end > *parent_end
            {
                return Err(GrantError::AuthorityEscalation);
            }
            if index > 0
                && !parent_constraints
                    .max_delegation_depth
                    .unwrap_or(0)
                    .checked_sub(1)
                    .is_some_and(|depth| constraints.max_delegation_depth.unwrap_or(0) <= depth)
            {
                return Err(GrantError::AuthorityEscalation);
            }
        }
        if index == 0 && constraints.max_delegation_depth.unwrap_or(0) != 0 {
            return Err(GrantError::InvalidAuthority);
        }
        parent = Some((constraints, start, end));
    }
    if let Some((constraints, start, end)) = parent
        && (grant.not_before < start || grant.expires_at > end || !constraints.permits(grant))
    {
        return Err(GrantError::AuthorityDenied);
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
    use crate::DeviceIdentity;
    use crate::GrantVerifier;
    use crate::VerificationContext;
    use crate::sign;

    const NOW: u64 = 1_800_000_000;
    static NEXT_NAME: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Serialize, Deserialize)]
    struct Restart {}
    sidex_serde::impl_sidex_type!(Restart);
    impl Operation for Restart {
        const TYPE: &'static str = "example.restart.v1";
    }

    struct Issued {
        cert: rcgen::Certificate,
        key: KeyPair,
    }

    fn issue(
        parent: Option<&Issued>,
        policy: Option<&[u8]>,
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
        if parent.is_some() || policy.is_some() {
            let eku = ExtendedKeyUsage(vec![GRANT_AUTHORITY_EKU])
                .to_der()
                .unwrap();
            let mut extension = CustomExtension::from_oid_content(&[2, 5, 29, 37], eku);
            extension.set_criticality(true);
            params.custom_extensions.push(extension);
        }
        if let Some(policy) = policy {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &AUTHORITY_CONSTRAINTS_OID
                        .arcs()
                        .map(u64::from)
                        .collect::<Vec<_>>(),
                    policy.to_vec(),
                ));
        }
        change(&mut params);
        let key = KeyPair::generate().unwrap();
        let cert = match parent {
            Some(parent) => params.signed_by(&key, &parent.cert, &parent.key).unwrap(),
            None => params.self_signed(&key).unwrap(),
        };
        Issued { cert, key }
    }

    fn policy() -> AuthorityConstraints {
        AuthorityConstraints {
            version: 1,
            namespace: "example".into(),
            audiences: AuthorityAudience::Any,
            permissions: vec![OperationPermission {
                verifier: "agent".into(),
                operation: Restart::TYPE.into(),
            }],
            max_grant_lifetime: 600,
            max_delegation_depth: None,
        }
    }

    fn grant() -> Grant<Restart> {
        Grant {
            version: 1,
            id: "test".into(),
            verifier: "agent".into(),
            audience: Audience {
                namespace: "example".into(),
                target: AudienceTarget::Device("device-1".into()),
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
        let identity = DeviceIdentity {
            namespace: grant.audience.namespace.clone(),
            device_id: "device-1".into(),
            groups: vec!["canary".into()],
        };
        GrantVerifier::new(root.cert.pem().as_bytes())
            .unwrap()
            .verify::<Restart>(
                &signed(chain, grant),
                &VerificationContext {
                    verifier: &grant.verifier,
                    identity: &identity,
                    now: SystemTime::UNIX_EPOCH + Duration::from_secs(grant.not_before),
                },
            )
            .map(|_| ())
    }

    /// Dedicated authority keys work locally and cannot be reused by legacy code-signing
    /// verification.
    #[test]
    fn constrained_signer_and_legacy_separation() {
        let root = issue(None, None, true, |_| {});
        let leaf = issue(
            Some(&root),
            Some(&policy().to_extension_der().unwrap()),
            false,
            |_| {},
        );
        verify(&root, &[&leaf], &grant()).unwrap();
        let legacy = CmsVerifier::new(root.cert.pem().as_bytes()).unwrap();
        assert!(
            legacy
                .verify_at(
                    &signed(&[&leaf], &grant()),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(NOW)
                )
                .is_err()
        );
    }

    /// A grant must satisfy the authority's audience, namespace, service, permission, and
    /// lifetime.
    #[test]
    fn grant_scope_and_lifetime_are_bounded() {
        let root = issue(None, None, true, |_| {});
        let mut policy = policy();
        policy.audiences = AuthorityAudience::Targets(vec![AudienceTarget::Group("canary".into())]);
        let leaf = issue(
            Some(&root),
            Some(&policy.to_extension_der().unwrap()),
            false,
            |_| {},
        );
        let mut allowed = grant();
        allowed.audience.target = AudienceTarget::Group("canary".into());
        verify(&root, &[&leaf], &allowed).unwrap();
        assert!(matches!(
            verify(&root, &[&leaf], &grant()),
            Err(GrantError::AuthorityDenied)
        ));
        let mut wrong = grant();
        wrong.audience.namespace = "other".into();
        assert!(matches!(
            verify(&root, &[&leaf], &wrong),
            Err(GrantError::AuthorityDenied)
        ));
        wrong = allowed;
        wrong.verifier = "other".into();
        assert!(matches!(
            verify(&root, &[&leaf], &wrong),
            Err(GrantError::AuthorityDenied)
        ));
        wrong.verifier = "agent".into();
        wrong.expires_at = NOW + 601;
        assert!(matches!(
            verify(&root, &[&leaf], &wrong),
            Err(GrantError::AuthorityDenied)
        ));
        policy.permissions[0].operation = "example.remove.v1".into();
        let leaf = issue(
            Some(&root),
            Some(&policy.to_extension_der().unwrap()),
            false,
            |_| {},
        );
        let mut request = grant();
        request.audience.target = AudienceTarget::Group("canary".into());
        assert!(matches!(
            verify(&root, &[&leaf], &request),
            Err(GrantError::AuthorityDenied)
        ));
    }

    /// Wider child policies are rejected even when the final grant would fit the parent's
    /// scope.
    #[test]
    fn child_scope_cannot_escalate() {
        let root = issue(None, None, true, |_| {});
        let mut parent_policy = policy();
        parent_policy.audiences =
            AuthorityAudience::Targets(vec![AudienceTarget::Device("device-1".into())]);
        let parent = issue(
            Some(&root),
            Some(&parent_policy.to_extension_der().unwrap()),
            true,
            |_| {},
        );
        let leaf = issue(
            Some(&parent),
            Some(&parent_policy.to_extension_der().unwrap()),
            false,
            |_| {},
        );
        verify(&root, &[&leaf, &parent], &grant()).unwrap();
        let mut wider = Vec::new();
        let mut p = parent_policy.clone();
        p.namespace = "other".into();
        wider.push(p);
        let mut p = parent_policy.clone();
        p.audiences = AuthorityAudience::Any;
        wider.push(p);
        let mut p = parent_policy.clone();
        p.permissions.push(OperationPermission {
            verifier: "agent".into(),
            operation: "example.remove.v1".into(),
        });
        wider.push(p);
        let mut p = parent_policy.clone();
        p.max_grant_lifetime += 1;
        wider.push(p);
        for p in wider {
            let leaf = issue(
                Some(&parent),
                Some(&p.to_extension_der().unwrap()),
                false,
                |_| {},
            );
            assert!(matches!(
                verify(&root, &[&leaf, &parent], &grant()),
                Err(GrantError::AuthorityEscalation)
            ));
        }
    }

    /// Delegation defaults to no subordinate CAs and requires decreasing explicit depth
    /// at each CA level.
    #[test]
    fn delegation_depth_is_bounded() {
        let root = issue(None, None, true, |_| {});
        for depth in [None, Some(1)] {
            let mut parent_policy = policy();
            parent_policy.max_delegation_depth = depth;
            let parent = issue(
                Some(&root),
                Some(&parent_policy.to_extension_der().unwrap()),
                true,
                |_| {},
            );
            let child = issue(
                Some(&parent),
                Some(&policy().to_extension_der().unwrap()),
                true,
                |_| {},
            );
            let leaf = issue(
                Some(&child),
                Some(&policy().to_extension_der().unwrap()),
                false,
                |_| {},
            );
            let result = verify(&root, &[&leaf, &parent, &child], &grant());
            if depth.is_some() {
                result.unwrap();
            } else {
                assert!(matches!(result, Err(GrantError::AuthorityEscalation)));
            }
        }
    }

    /// Whole grant and child-certificate windows must fit, including grants verified
    /// before certificate expiry.
    #[test]
    fn validity_windows_cannot_escape_authority() {
        let root = issue(None, None, true, |_| {});
        let parent = issue(
            Some(&root),
            Some(&policy().to_extension_der().unwrap()),
            true,
            |p| {
                p.not_before = rcgen::date_time_ymd(2021, 1, 1);
                p.not_after = rcgen::date_time_ymd(2029, 1, 1);
            },
        );
        let leaf = issue(
            Some(&parent),
            Some(&policy().to_extension_der().unwrap()),
            false,
            |_| {},
        );
        assert!(matches!(
            verify(&root, &[&leaf, &parent], &grant()),
            Err(GrantError::AuthorityEscalation)
        ));
        let leaf = issue(
            Some(&parent),
            Some(&policy().to_extension_der().unwrap()),
            false,
            |p| {
                p.not_before = rcgen::date_time_ymd(2022, 1, 1);
                p.not_after = rcgen::date_time_ymd(2028, 1, 1);
            },
        );
        verify(&root, &[&leaf, &parent], &grant()).unwrap();
        let expiry = rcgen::date_time_ymd(2028, 1, 1).unix_timestamp() as u64;
        let mut crossing = grant();
        crossing.not_before = expiry - 10;
        crossing.expires_at = expiry + 1;
        assert!(matches!(
            verify(&root, &[&leaf, &parent], &crossing),
            Err(GrantError::AuthorityDenied)
        ));
        crossing.expires_at = expiry;
        verify(&root, &[&leaf, &parent], &crossing).unwrap();
        crossing.not_before = expiry + 1;
        crossing.expires_at = expiry + 10;
        assert!(verify(&root, &[&leaf, &parent], &crossing).is_err());
    }

    /// Omitting constraints, adding unknown fields, or relaxing the purpose must fail
    /// closed.
    #[test]
    fn missing_unknown_and_ambiguous_constraints_fail_closed() {
        let root = issue(None, None, true, |_| {});
        let leaf = issue(Some(&root), None, false, |_| {});
        assert!(matches!(
            verify(&root, &[&leaf], &grant()),
            Err(GrantError::InvalidAuthority)
        ));
        let json = serde_json::to_string(&policy()).unwrap();
        for invalid in [
            json.replacen('{', "{\"unknown\":true,", 1),
            json.replacen('{', "{\"version\":1,", 1),
            json.replace("\"version\":1", "\"version\":2"),
            format!("{json} trailing"),
        ] {
            let der = Utf8StringRef::new(&invalid).unwrap().to_der().unwrap();
            let leaf = issue(Some(&root), Some(&der), false, |_| {});
            assert!(verify(&root, &[&leaf], &grant()).is_err(), "{invalid}");
        }
        let der = policy().to_extension_der().unwrap();
        let leaf = issue(Some(&root), Some(&der), false, |p| {
            p.custom_extensions[0].set_criticality(false)
        });
        assert!(matches!(
            verify(&root, &[&leaf], &grant()),
            Err(GrantError::InvalidAuthority)
        ));
        let leaf = issue(Some(&root), Some(&der), false, |p| {
            p.custom_extensions.remove(0);
            p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
        });
        assert!(matches!(
            verify(&root, &[&leaf], &grant()),
            Err(GrantError::InvalidAuthority)
        ));
        let leaf = issue(Some(&root), Some(&der), false, |p| {
            p.custom_extensions.push(p.custom_extensions[1].clone())
        });
        assert!(verify(&root, &[&leaf], &grant()).is_err());
    }

    /// An unrelated CMS certificate can neither add nor remove authority from the
    /// validated path.
    #[test]
    fn unrelated_certificate_does_not_change_authority() {
        let root = issue(None, None, true, |_| {});
        let leaf = issue(
            Some(&root),
            Some(&policy().to_extension_der().unwrap()),
            false,
            |_| {},
        );
        let mut denied = policy();
        denied.permissions.clear();
        let unrelated = issue(
            Some(&root),
            Some(&denied.to_extension_der().unwrap()),
            true,
            |_| {},
        );
        verify(&root, &[&leaf, &unrelated], &grant()).unwrap();
        let denied_leaf = issue(
            Some(&unrelated),
            Some(&policy().to_extension_der().unwrap()),
            false,
            |_| {},
        );
        let permissive = issue(
            Some(&root),
            Some(&policy().to_extension_der().unwrap()),
            true,
            |_| {},
        );
        assert!(matches!(
            verify(&root, &[&denied_leaf, &unrelated, &permissive], &grant()),
            Err(GrantError::AuthorityEscalation)
        ));
    }

    /// An intermediate cannot escape its constraints by issuing an ordinary code-signing
    /// certificate.
    #[test]
    fn legacy_child_cannot_bypass_a_constrained_parent() {
        let root = issue(None, None, true, |_| {});
        let parent = issue(
            Some(&root),
            Some(&policy().to_extension_der().unwrap()),
            true,
            |_| {},
        );
        let leaf = issue(Some(&parent), None, false, |p| {
            p.custom_extensions.clear();
            p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
        });
        assert!(verify(&root, &[&leaf, &parent], &grant()).is_err());
        assert!(
            CmsVerifier::new(root.cert.pem().as_bytes())
                .unwrap()
                .verify_at(
                    &signed(&[&leaf, &parent], &grant()),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(NOW),
                )
                .is_err()
        );
    }

    /// Locally provisioned root policies constrain descendants, including CA depth.
    #[test]
    fn root_constraints_are_enforced() {
        let root = issue(
            None,
            Some(&policy().to_extension_der().unwrap()),
            true,
            |_| {},
        );
        let leaf = issue(
            Some(&root),
            Some(&policy().to_extension_der().unwrap()),
            false,
            |_| {},
        );
        verify(&root, &[&leaf], &grant()).unwrap();
        let parent = issue(
            Some(&root),
            Some(&policy().to_extension_der().unwrap()),
            true,
            |_| {},
        );
        let leaf = issue(
            Some(&parent),
            Some(&policy().to_extension_der().unwrap()),
            false,
            |_| {},
        );
        assert!(matches!(
            verify(&root, &[&leaf, &parent], &grant()),
            Err(GrantError::AuthorityEscalation)
        ));
    }

    /// A future constraint nested in an allowlist is rejected instead of silently
    /// granting broader authority.
    #[test]
    fn unknown_nested_constraints_are_rejected() {
        let root = issue(None, None, true, |_| {});
        let mut p = policy();
        p.audiences = AuthorityAudience::Targets(vec![AudienceTarget::Device("device-1".into())]);
        let json = serde_json::to_string(&p).unwrap();
        for invalid in [
            json.replace("\"verifier\":", "\"unknownConstraint\":true,\"verifier\":"),
            json.replace(
                "\"Device\":\"device-1\"",
                "\"Device\":\"device-1\",\"unknownConstraint\":true",
            ),
        ] {
            assert_ne!(invalid, json);
            let der = Utf8StringRef::new(&invalid).unwrap().to_der().unwrap();
            let leaf = issue(Some(&root), Some(&der), false, |_| {});
            assert!(verify(&root, &[&leaf], &grant()).is_err());
        }
    }
}
