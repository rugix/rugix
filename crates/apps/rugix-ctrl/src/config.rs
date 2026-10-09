use std::fs;
use std::path::Path;

use reportify::bail;
use reportify::ResultExt;

use crate::system::SystemResult;

sidex::include_bundle! {
    #[allow(clippy::redundant_static_lifetimes, clippy::empty_docs)]
    rugix_ctrl as generated
}

// Re-export the generated data structures.
pub use generated::*;

/// Ctrl config path.
const CTRL_CONFIG_PATH: &str = "/etc/rugix/ctrl.toml";

pub fn load_ctrl_config() -> SystemResult<config::Config> {
    let config = if Path::new(CTRL_CONFIG_PATH).exists() {
        toml::from_str(
            &fs::read_to_string(CTRL_CONFIG_PATH).whatever("unable to read configuration file")?,
        )
        .whatever("unable to parse configuration file")?
    } else {
        config::Config::default()
    };
    validate_grant_policy(&config)?;
    Ok(config)
}

/// Reject a grant policy that could never authorize an installation.
///
/// These are configuration errors rather than authorization failures, so they are
/// reported once at load time instead of on every installation attempt.
fn validate_grant_policy(config: &config::Config) -> SystemResult<()> {
    let Some(grants) = &config.grants else {
        return Ok(());
    };
    if grants.authorities.is_empty() {
        bail!("grant policy requires at least one entry in `grants.authorities`");
    }
    if grants.namespace.is_empty() {
        bail!("grant policy requires a non-empty `grants.namespace`");
    }
    if !Path::new(&grants.identity_helper).is_absolute() {
        bail!("`grants.identity-helper` must be an absolute path");
    }
    for authority in &grants.authorities {
        if authority.root.is_empty() {
            bail!("every grant authority requires a `root` certificate path");
        }
        if authority.max_lifetime == Some(0) {
            bail!(
                "grant authority {} requires a non-zero `max-lifetime`",
                authority.root
            );
        }
    }
    let independent_publisher = config
        .signatures
        .as_ref()
        .is_some_and(|signatures| !signatures.roots.is_empty());
    if matches!(grants.mode, Some(grants::GrantPolicy::EmbeddedAndGrant)) && !independent_publisher
    {
        bail!(
            "`grants.mode = \"embedded-and-grant\"` additionally requires `signatures.roots` for publisher verification"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> grants::GrantsConfig {
        grants::GrantsConfig {
            authorities: vec![grants::GrantAuthorityConfig {
                root: "/etc/rugix/grant-root.pem".into(),
                permissions: vec![grants::InstallPermission::Apps],
                max_lifetime: None,
            }],
            namespace: "example".into(),
            identity_helper: "/usr/lib/rugix/grant-identity".into(),
            mode: None,
        }
    }

    /// A complete grant policy loads, and an absent one imposes no requirements.
    #[test]
    fn valid_policies_are_accepted() {
        validate_grant_policy(&config::Config::default()).unwrap();
        validate_grant_policy(&config::Config::default().with_grants(Some(policy()))).unwrap();
    }

    /// Policies that could never authorize an installation are rejected at load time.
    #[test]
    fn unenforceable_policies_are_rejected() {
        let changes: [fn(&mut grants::GrantsConfig); 6] = [
            |policy| policy.authorities.clear(),
            |policy| policy.namespace = String::new(),
            |policy| policy.identity_helper = "helper".into(),
            |policy| policy.authorities[0].root = String::new(),
            |policy| policy.authorities[0].max_lifetime = Some(0),
            |policy| policy.mode = Some(grants::GrantPolicy::EmbeddedAndGrant),
        ];
        for change in changes {
            let mut policy = policy();
            change(&mut policy);
            let config = config::Config::default().with_grants(Some(policy));
            assert!(validate_grant_policy(&config).is_err());
        }
    }

    /// Requiring an embedded publisher signature needs configured publisher roots.
    #[test]
    fn embedded_and_grant_accepts_configured_publisher_roots() {
        let mut policy = policy();
        policy.mode = Some(grants::GrantPolicy::EmbeddedAndGrant);
        let config = config::Config::default()
            .with_grants(Some(policy))
            .with_signatures(Some(config::SignaturesConfig {
                roots: vec!["/etc/rugix/publisher-root.pem".into()],
            }));
        validate_grant_policy(&config).unwrap();
    }
}
