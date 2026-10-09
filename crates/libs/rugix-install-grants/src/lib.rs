//! Installation operation authorized by a detached Rugix grant.
//!
//! This crate is the contract between a grant issuer, such as Rugix Bundler or a
//! fleet service, and the Rugix Ctrl installer. It defines the signed operation,
//! the permissions an issuing certificate must hold, and [`InstallTarget::permits`]
//! for comparing a grant with a concrete request.
//!
//! The reusable envelope and CMS verification live in `rugix-grants`, and the
//! bundle format lives in `rugix-bundle`. Installers must additionally
//! authenticate the bundle hash and enforce their replay policy.

use const_oid::ObjectIdentifier;

sidex::include_bundle! {
    #[allow(
        clippy::redundant_static_lifetimes,
        clippy::empty_docs,
        clippy::manual_unwrap_or_default,
        clippy::match_single_binding
    )]
    rugix_install_grants as generated
}

pub use generated::install;
pub use generated::install::BootGroupConstraint;
pub use generated::install::InstallOperation;
pub use generated::install::InstallTarget;
pub use generated::install::RebootConstraint;
pub use generated::install::RebootMode;
pub use generated::install::SystemInstallConstraints;

/// Service identifier of the Rugix Ctrl installer.
pub const SERVICE: &str = "rugix-ctrl";

/// Key purpose authorizing application installation.
///
/// Assigned under Rugix's `1.3.6.1.4.1.67013.100.3` operation purpose namespace.
pub const PERMISSION_APPS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.67013.100.3.1");

/// Key purpose authorizing system installation.
///
/// Assigned under Rugix's `1.3.6.1.4.1.67013.100.3` operation purpose namespace.
pub const PERMISSION_SYSTEM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.67013.100.3.2");

impl rugix_grants::Operation for InstallOperation {
    const TYPE: &'static str = "rugix.install.v1";

    fn permission(&self) -> ObjectIdentifier {
        match self.target {
            InstallTarget::Apps => PERMISSION_APPS,
            InstallTarget::System(_) => PERMISSION_SYSTEM,
        }
    }
}

/// Installation actually requested by the caller.
///
/// The executor builds this from the untrusted request and compares it with the
/// authenticated grant. Every field that changes what the installer does to the
/// device belongs here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallRequest {
    /// Install application payloads.
    Apps,
    /// Install system payloads.
    System {
        /// Explicitly requested boot group, or local selection when absent.
        boot_group: Option<String>,
        /// Whether the caller asked to retain the target's overlay.
        keep_overlay: bool,
        /// Explicitly requested reboot behavior, or the bundle default when absent.
        reboot: Option<RebootMode>,
    },
}

impl InstallTarget {
    /// Whether this grant permits `request`.
    pub fn permits(&self, request: &InstallRequest) -> bool {
        match (self, request) {
            (Self::Apps, InstallRequest::Apps) => true,
            (
                Self::System(constraints),
                InstallRequest::System {
                    boot_group,
                    keep_overlay,
                    reboot,
                },
            ) => {
                constraints.permits_boot_group(boot_group.as_deref())
                    && constraints
                        .keep_overlay
                        .is_none_or(|permitted| permitted == *keep_overlay)
                    && constraints.permits_reboot(reboot.as_ref())
            }
            _ => false,
        }
    }
}

impl SystemInstallConstraints {
    /// Permit any boot group unless the grant names one or requires local selection.
    fn permits_boot_group(&self, requested: Option<&str>) -> bool {
        match (&self.boot_group, requested) {
            (None, _) => true,
            (Some(BootGroupConstraint::Local), None) => true,
            (Some(BootGroupConstraint::Named(permitted)), Some(requested)) => {
                permitted == requested
            }
            _ => false,
        }
    }

    /// Permit any reboot behavior unless the grant names one.
    fn permits_reboot(&self, requested: Option<&RebootMode>) -> bool {
        match (&self.reboot, requested) {
            (None, _) => true,
            (Some(RebootConstraint::BundleDefault), None) => true,
            (Some(RebootConstraint::Mode(permitted)), Some(requested)) => permitted == requested,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system(
        boot_group: Option<&str>,
        keep_overlay: bool,
        reboot: Option<RebootMode>,
    ) -> InstallRequest {
        InstallRequest::System {
            boot_group: boot_group.map(str::to_owned),
            keep_overlay,
            reboot,
        }
    }

    /// An absent constraint permits every requested value for that option.
    #[test]
    fn absent_constraints_permit_any_request() {
        let target = InstallTarget::System(SystemInstallConstraints {
            boot_group: None,
            keep_overlay: None,
            reboot: None,
        });
        for request in [
            system(None, false, None),
            system(Some("B"), true, Some(RebootMode::Yes)),
            system(Some("C"), false, Some(RebootMode::Deferred)),
        ] {
            assert!(target.permits(&request), "rejected {request:?}");
        }
        assert!(!target.permits(&InstallRequest::Apps));
    }

    /// A present constraint requires exactly the described request.
    #[test]
    fn present_constraints_require_an_exact_request() {
        let target = InstallTarget::System(SystemInstallConstraints {
            boot_group: Some(BootGroupConstraint::Named("B".into())),
            keep_overlay: Some(false),
            reboot: Some(RebootConstraint::Mode(RebootMode::Set)),
        });
        assert!(target.permits(&system(Some("B"), false, Some(RebootMode::Set))));
        for request in [
            system(Some("C"), false, Some(RebootMode::Set)),
            system(None, false, Some(RebootMode::Set)),
            system(Some("B"), true, Some(RebootMode::Set)),
            system(Some("B"), false, Some(RebootMode::Yes)),
            system(Some("B"), false, None),
        ] {
            assert!(!target.permits(&request), "accepted {request:?}");
        }
    }

    /// Local boot group selection and the bundle's default reboot behavior are
    /// distinct from any explicit request.
    #[test]
    fn local_selection_and_bundle_default_are_explicit() {
        let target = InstallTarget::System(SystemInstallConstraints {
            boot_group: Some(BootGroupConstraint::Local),
            keep_overlay: None,
            reboot: Some(RebootConstraint::BundleDefault),
        });
        assert!(target.permits(&system(None, false, None)));
        assert!(!target.permits(&system(Some("B"), false, None)));
        assert!(!target.permits(&system(None, false, Some(RebootMode::No))));
    }

    /// The two installation purposes must stay distinct, since a certificate may
    /// hold either one without holding the other.
    #[test]
    fn installation_purposes_are_distinct() {
        assert_ne!(PERMISSION_APPS, PERMISSION_SYSTEM);
    }
}
