//! Admission policy for operations crossing the privilege boundary.

use reportify::bail;

use super::config::DaemonFeatureSettings;
use super::config::DaemonSettings;
use super::protocol::Request;
use crate::operations::install::BundleInstallOptions;
use crate::operations::install::InstallTarget;
use crate::operations::install::SystemRebootMode;
use crate::system::SystemResult;

#[derive(Debug, Clone)]
pub(crate) struct AdmissionPolicy {
    dangerously_insecure: bool,
    features: DaemonFeatureSettings,
}

impl AdmissionPolicy {
    pub(crate) fn new(settings: &DaemonSettings) -> Self {
        Self {
            dangerously_insecure: settings.dangerously_insecure,
            features: settings.features,
        }
    }

    pub(crate) fn authorize(&self, request: &Request) -> SystemResult<()> {
        match request {
            Request::QueryInfo => {}
            Request::InstallBundle(operation) => {
                self.authorize_install_options(&operation.options)?;
                if let InstallTarget::System { reboot, .. } = &operation.target {
                    let explicitly_reboots = matches!(
                        reboot,
                        Some(SystemRebootMode::Yes | SystemRebootMode::Deferred)
                    );
                    if explicitly_reboots {
                        self.require_feature(
                            self.features.system_reboot,
                            "system-reboot",
                            "explicit system update reboot",
                        )?;
                    }
                }
            }
            Request::FactoryReset(_) => self.require_feature(
                self.features.factory_reset,
                "factory-reset",
                "factory reset",
            )?,
            Request::CommitSystem(_) => self.require_feature(
                self.features.system_commit,
                "system-commit",
                "system commit",
            )?,
            Request::RebootSystem(_) => self.require_feature(
                self.features.system_reboot,
                "system-reboot",
                "system reboot",
            )?,
            Request::ActivateApp(operation) => {
                self.require_app_lifecycle()?;
                self.authorize_compatibility_override(operation.skip_compatibility_check)?;
            }
            Request::DeactivateApp(operation) => {
                self.require_app_lifecycle()?;
                self.authorize_compatibility_override(operation.skip_compatibility_check)?;
            }
            Request::StartApp(_) | Request::StopApp(_) | Request::GarbageCollectApps(_) => {
                self.require_app_lifecycle()?
            }
            Request::RollbackApp(operation) => {
                self.require_app_lifecycle()?;
                self.authorize_compatibility_override(operation.skip_compatibility_check)?;
            }
            Request::RemoveApp(operation) => {
                self.require_app_lifecycle()?;
                self.authorize_compatibility_override(operation.skip_compatibility_check)?;
            }
            Request::QuerySystem(_)
            | Request::CheckComponents(_)
            | Request::ListApps(_)
            | Request::QueryApp(_) => {}
        }
        Ok(())
    }

    fn authorize_install_options(&self, options: &BundleInstallOptions) -> SystemResult<()> {
        let BundleInstallOptions {
            bundle_hash,
            root_cert,
            insecure_skip_bundle_verification,
            insecure_allow_missing_block_index,
            skip_compatibility_check,
        } = options;
        let has_security_override = bundle_hash.is_some()
            || root_cert.is_some()
            || *insecure_skip_bundle_verification
            || *insecure_allow_missing_block_index
            || *skip_compatibility_check;
        if has_security_override && !self.dangerously_insecure {
            bail!(
                "daemon installation security overrides are disabled; set `dangerously-insecure = true` in /etc/rugix/daemon.toml to enable them"
            );
        }
        Ok(())
    }

    fn authorize_compatibility_override(&self, skip_compatibility_check: bool) -> SystemResult<()> {
        if skip_compatibility_check && !self.dangerously_insecure {
            bail!(
                "daemon compatibility overrides are disabled; set `dangerously-insecure = true` in /etc/rugix/daemon.toml to enable them"
            );
        }
        Ok(())
    }

    fn require_app_lifecycle(&self) -> SystemResult<()> {
        self.require_feature(
            self.features.app_lifecycle,
            "app-lifecycle",
            "application lifecycle management",
        )
    }

    fn require_feature(&self, enabled: bool, feature: &str, operation: &str) -> SystemResult<()> {
        if !enabled {
            bail!(
                "daemon {operation} operations are disabled; set `features.{feature} = true` in /etc/rugix/daemon.toml to enable them"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use si_crypto_hashes::HashAlgorithm;
    use si_crypto_hashes::HashDigest;

    use super::AdmissionPolicy;
    use crate::daemon::config::DaemonFeatureSettings;
    use crate::daemon::config::DaemonSettings;
    use crate::daemon::protocol::Request;
    use crate::operations::apps::ActivateApp;
    use crate::operations::apps::StartApp;
    use crate::operations::install::BundleInstallOptions;
    use crate::operations::install::InstallBundle;
    use crate::operations::install::InstallSource;
    use crate::operations::install::InstallTarget;
    use crate::operations::install::SystemRebootMode;
    use crate::operations::state::FactoryReset;
    use crate::operations::system::CommitSystem;
    use crate::operations::system::QuerySystem;
    use crate::operations::system::RebootSystem;

    #[test]
    fn default_policy_allows_queries_and_secure_installs() {
        let policy = policy(false, DaemonFeatureSettings::default());

        policy
            .authorize(&Request::QuerySystem(QuerySystem))
            .unwrap();
        policy
            .authorize(&Request::InstallBundle(app_install(secure_options())))
            .unwrap();
        policy
            .authorize(&Request::InstallBundle(system_install(None)))
            .unwrap();
    }

    #[test]
    fn privileged_operation_families_require_their_own_feature() {
        let disabled = policy(false, DaemonFeatureSettings::default());
        assert!(disabled
            .authorize(&Request::FactoryReset(FactoryReset {
                backup: false,
                backup_name: None,
            }))
            .is_err());
        assert!(disabled
            .authorize(&Request::CommitSystem(CommitSystem))
            .is_err());
        assert!(disabled
            .authorize(&Request::RebootSystem(RebootSystem { spare: false }))
            .is_err());
        assert!(disabled
            .authorize(&Request::StartApp(StartApp {
                name: "example".to_owned(),
            }))
            .is_err());

        let enabled = policy(
            false,
            DaemonFeatureSettings {
                factory_reset: true,
                system_commit: true,
                system_reboot: true,
                app_lifecycle: true,
            },
        );
        enabled
            .authorize(&Request::FactoryReset(FactoryReset {
                backup: false,
                backup_name: None,
            }))
            .unwrap();
        enabled
            .authorize(&Request::CommitSystem(CommitSystem))
            .unwrap();
        enabled
            .authorize(&Request::RebootSystem(RebootSystem { spare: true }))
            .unwrap();
        enabled
            .authorize(&Request::StartApp(StartApp {
                name: "example".to_owned(),
            }))
            .unwrap();
    }

    #[test]
    fn explicit_update_reboots_require_the_reboot_feature_but_defaults_do_not() {
        let disabled = policy(false, DaemonFeatureSettings::default());
        disabled
            .authorize(&Request::InstallBundle(system_install(None)))
            .unwrap();
        assert!(disabled
            .authorize(&Request::InstallBundle(system_install(Some(
                SystemRebootMode::Yes,
            ))))
            .is_err());
        assert!(disabled
            .authorize(&Request::InstallBundle(system_install(Some(
                SystemRebootMode::Deferred,
            ))))
            .is_err());
        disabled
            .authorize(&Request::InstallBundle(system_install(Some(
                SystemRebootMode::No,
            ))))
            .unwrap();

        let enabled = policy(
            false,
            DaemonFeatureSettings {
                system_reboot: true,
                ..DaemonFeatureSettings::default()
            },
        );
        enabled
            .authorize(&Request::InstallBundle(system_install(Some(
                SystemRebootMode::Yes,
            ))))
            .unwrap();
    }

    #[test]
    fn every_install_security_override_requires_dangerously_insecure_mode() {
        let secure_policy = policy(false, DaemonFeatureSettings::default());
        let mut overrides = Vec::new();

        let mut options = secure_options();
        options.bundle_hash =
            Some(HashDigest::new(HashAlgorithm::Sha256, Arc::<[u8]>::from([0; 32])).unwrap());
        overrides.push(options);

        let mut options = secure_options();
        options.root_cert = Some(b"certificate".to_vec());
        overrides.push(options);

        let mut options = secure_options();
        options.insecure_skip_bundle_verification = true;
        overrides.push(options);

        let mut options = secure_options();
        options.insecure_allow_missing_block_index = true;
        overrides.push(options);

        let mut options = secure_options();
        options.skip_compatibility_check = true;
        overrides.push(options);

        for options in overrides {
            assert!(secure_policy
                .authorize(&Request::InstallBundle(app_install(options.clone())))
                .is_err());
            policy(true, DaemonFeatureSettings::default())
                .authorize(&Request::InstallBundle(app_install(options)))
                .unwrap();
        }
    }

    #[test]
    fn app_compatibility_overrides_require_both_lifecycle_and_insecure_features() {
        let operation = || {
            Request::ActivateApp(ActivateApp {
                name: "example".to_owned(),
                generation: Some(1),
                skip_compatibility_check: true,
            })
        };
        let lifecycle = DaemonFeatureSettings {
            app_lifecycle: true,
            ..DaemonFeatureSettings::default()
        };

        assert!(policy(false, lifecycle).authorize(&operation()).is_err());
        policy(true, lifecycle).authorize(&operation()).unwrap();
    }

    fn policy(dangerously_insecure: bool, features: DaemonFeatureSettings) -> AdmissionPolicy {
        AdmissionPolicy::new(&DaemonSettings {
            socket_path: PathBuf::from("/tmp/rugix-test.sock"),
            max_control_frame_size: 1024,
            dangerously_insecure,
            features,
        })
    }

    fn secure_options() -> BundleInstallOptions {
        BundleInstallOptions {
            bundle_hash: None,
            root_cert: None,
            insecure_skip_bundle_verification: false,
            insecure_allow_missing_block_index: false,
            skip_compatibility_check: false,
        }
    }

    fn app_install(options: BundleInstallOptions) -> InstallBundle {
        InstallBundle {
            source: InstallSource::Stream,
            target: InstallTarget::Apps,
            options,
        }
    }

    fn system_install(reboot: Option<SystemRebootMode>) -> InstallBundle {
        InstallBundle {
            source: InstallSource::Stream,
            target: InstallTarget::System {
                reboot,
                keep_overlay: false,
                boot_group: None,
            },
            options: secure_options(),
        }
    }
}
