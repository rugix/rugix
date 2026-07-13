//! Mender-compatible boot flows.

/*

# Grub

There are redundant Grub environment files:

- `grub-mender-grubenv/mender_grubenv1/env`
- `grub-mender-grubenv/mender_grubenv2/env`

In addition, there are two lock files:

- `grub-mender-grubenv/mender_grubenv1/lock`
- `grub-mender-grubenv/mender_grubenv2/lock`

The lock files are Grub environment files with a variable `editing`. This variable is set
to `1` prior to editing the respective environment file and to `0` afterwards.

Within the environment files, there are three variables:

- `bootcount`: Number of attempts of booting the update.
- `upgrade_available`: Indicates whether an update is available.
- `mender_boot_part`: Boot partition to boot from next.

*/

use std::path::Path;
use std::str::FromStr;

use hashbrown::HashMap;
use reportify::bail;
use reportify::ResultExt;
use rugix_common::boot::grub::load_grub_env;
use rugix_common::boot::grub::save_grub_env;
use rugix_common::boot::grub::GrubEnv;
use tracing::error;
use tracing::warn;

use crate::boot::fwenv::load_vars;
use crate::boot::fwenv::set_vars;
use crate::config::system::MenderBootFlowConfig;
use crate::system::boot_flows::BootFlow;
use crate::system::boot_flows::BootFlowResult;
use crate::system::boot_groups::BootGroupIdx;
use crate::system::boot_groups::BootGroups;
use crate::system::System;

#[derive(Debug)]
struct MenderBootFlow {
    config: MenderBootFlowConfig,
    entry_a: BootGroupIdx,
    entry_b: BootGroupIdx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenderGroup {
    A,
    B,
}

impl MenderBootFlow {
    pub fn boot_root(&self) -> &Path {
        self.config
            .boot_dir
            .as_deref()
            .map(Path::new)
            .unwrap_or(Path::new("/boot/efi"))
    }

    pub fn boot_part_a(&self) -> u32 {
        self.config.boot_part_a.unwrap_or(2)
    }

    pub fn boot_part_b(&self) -> u32 {
        self.config.boot_part_b.unwrap_or(3)
    }
}

fn mender_boot_flow(
    boot_entries: &BootGroups,
    config: &MenderBootFlowConfig,
) -> BootFlowResult<MenderBootFlow> {
    let mut entries = boot_entries.iter();
    let Some((entry_a_idx, _)) = entries.next() else {
        bail!("invalid number of entries");
    };
    let Some((entry_b_idx, _)) = entries.next() else {
        bail!("invalid number of entries");
    };
    if entries.next().is_some() {
        bail!("Mender boot flows require exactly two boot groups");
    }
    validate_mender_layout(
        2,
        config.boot_part_a.unwrap_or(2),
        config.boot_part_b.unwrap_or(3),
    )?;
    Ok(MenderBootFlow {
        config: config.clone(),
        entry_a: entry_a_idx,
        entry_b: entry_b_idx,
    })
}

fn validate_mender_layout(
    boot_group_count: usize,
    boot_part_a: u32,
    boot_part_b: u32,
) -> BootFlowResult<()> {
    if boot_group_count != 2 {
        bail!("Mender boot flows require exactly two boot groups");
    }
    if boot_part_a == boot_part_b {
        bail!("Mender boot partitions A and B must be different");
    }
    Ok(())
}

fn mender_default_group(
    mender_boot_part: u32,
    upgrade_available: bool,
    boot_part_a: u32,
    boot_part_b: u32,
) -> BootFlowResult<MenderGroup> {
    let selected = if mender_boot_part == boot_part_a {
        MenderGroup::A
    } else if mender_boot_part == boot_part_b {
        MenderGroup::B
    } else {
        bail!("unknown Mender boot partition {mender_boot_part}");
    };

    if upgrade_available {
        Ok(match selected {
            MenderGroup::A => MenderGroup::B,
            MenderGroup::B => MenderGroup::A,
        })
    } else {
        Ok(selected)
    }
}

fn mender_group_idx(inner: &MenderBootFlow, group: MenderGroup) -> BootGroupIdx {
    match group {
        MenderGroup::A => inner.entry_a,
        MenderGroup::B => inner.entry_b,
    }
}

fn mender_group(inner: &MenderBootFlow, group: BootGroupIdx) -> BootFlowResult<MenderGroup> {
    if group == inner.entry_a {
        Ok(MenderGroup::A)
    } else if group == inner.entry_b {
        Ok(MenderGroup::B)
    } else {
        bail!("boot group does not belong to the Mender boot flow")
    }
}

fn mender_state_values(
    group: MenderGroup,
    upgrade_available: bool,
    boot_part_a: u32,
    boot_part_b: u32,
) -> Vec<(String, String)> {
    let boot_part = match group {
        MenderGroup::A => boot_part_a,
        MenderGroup::B => boot_part_b,
    };
    vec![
        ("bootcount".to_owned(), "0".to_owned()),
        (
            "upgrade_available".to_owned(),
            u8::from(upgrade_available).to_string(),
        ),
        ("mender_boot_part".to_owned(), boot_part.to_string()),
        ("mender_boot_part_hex".to_owned(), format!("{boot_part:#x}")),
    ]
}

const MENDER_GRUB_ENV1: &str = "grub-mender-grubenv/mender_grubenv1/env";
const MENDER_GRUB_LOCK1: &str = "grub-mender-grubenv/mender_grubenv1/lock";
const MENDER_GRUB_LOCK1_SHA256: &str = "grub-mender-grubenv/mender_grubenv1/lock.sha256sum";
const MENDER_GRUB_ENV2: &str = "grub-mender-grubenv/mender_grubenv2/env";
const MENDER_GRUB_LOCK2: &str = "grub-mender-grubenv/mender_grubenv2/lock";
const MENDER_GRUB_LOCK2_SHA256: &str = "grub-mender-grubenv/mender_grubenv2/lock.sha256sum";

// We only write the sum after writing the unlocking. This is fine as a locked environment
// must be considered corrupted anyway, so the hash does not have to match.
const MENDER_LOCK_SHA256: &str =
    "181eaea8e394c79982e4d61d58aeb7ffb5a4e75f0c62bd5f30ec2d839aa4e12c  lock\n";

fn mender_save_grub_env(boot_root: &Path, env: &GrubEnv) -> BootFlowResult<()> {
    let mut locked = std::collections::HashMap::new();
    locked.insert("editing".to_owned(), "1".to_owned());
    let mut unlocked = std::collections::HashMap::new();
    unlocked.insert("editing".to_owned(), "0".to_owned());
    // Primary environment file.
    save_grub_env(boot_root.join(MENDER_GRUB_LOCK1), &locked)
        .whatever("unable to lock primary Mender GRUB environment")?;
    save_grub_env(boot_root.join(MENDER_GRUB_ENV1), env)
        .whatever("unable to save Grub environment")?;
    save_grub_env(boot_root.join(MENDER_GRUB_LOCK1), &unlocked)
        .whatever("unable to unlock primary Mender GRUB environment")?;
    std::fs::write(boot_root.join(MENDER_GRUB_LOCK1_SHA256), MENDER_LOCK_SHA256)
        .whatever("unable to write primary Mender GRUB lock checksum")?;
    // Secondary environment file.
    save_grub_env(boot_root.join(MENDER_GRUB_LOCK2), &locked)
        .whatever("unable to lock secondary Mender GRUB environment")?;
    save_grub_env(boot_root.join(MENDER_GRUB_ENV2), env)
        .whatever("unable to save Grub environment")?;
    save_grub_env(boot_root.join(MENDER_GRUB_LOCK2), &unlocked)
        .whatever("unable to unlock secondary Mender GRUB environment")?;
    std::fs::write(boot_root.join(MENDER_GRUB_LOCK2_SHA256), MENDER_LOCK_SHA256)
        .whatever("unable to write secondary Mender GRUB lock checksum")?;
    Ok(())
}

fn repair_mender_grub_env(
    boot_root: &Path,
    env: &GrubEnv,
    lock: &str,
    lock_checksum: &str,
    environment: &str,
) -> BootFlowResult<()> {
    let mut locked = std::collections::HashMap::new();
    locked.insert("editing".to_owned(), "1".to_owned());
    let mut unlocked = std::collections::HashMap::new();
    unlocked.insert("editing".to_owned(), "0".to_owned());
    save_grub_env(boot_root.join(lock), &locked).whatever("unable to lock environment copy")?;
    save_grub_env(boot_root.join(environment), env)
        .whatever("unable to repair environment copy")?;
    save_grub_env(boot_root.join(lock), &unlocked).whatever("unable to unlock environment copy")?;
    std::fs::write(boot_root.join(lock_checksum), MENDER_LOCK_SHA256)
        .whatever("unable to repair environment lock checksum")?;
    Ok(())
}

fn mender_load_grub_env(system: &System, boot_root: &Path) -> BootFlowResult<GrubEnv> {
    let primary_ok = load_grub_env(boot_root.join(MENDER_GRUB_LOCK1))
        .map(|env| matches!(env.get("editing"), Some(value) if value == "0"))
        .unwrap_or(false);
    let secondary_ok = load_grub_env(boot_root.join(MENDER_GRUB_LOCK2))
        .map(|env| matches!(env.get("editing"), Some(value) if value == "0"))
        .unwrap_or(false);
    let boot_env = if primary_ok {
        load_grub_env(boot_root.join(MENDER_GRUB_ENV1))
            .whatever("unable to load Grub environment")?
    } else if secondary_ok {
        load_grub_env(boot_root.join(MENDER_GRUB_ENV2))
            .whatever("unable to load Grub environment")?
    } else {
        error!("both primary and secondary environment files are corrupted");
        // Try to load the primary environment anyway.
        load_grub_env(boot_root.join(MENDER_GRUB_ENV1))
            .whatever("unable to load Grub environment")?
    };

    if !primary_ok || !secondary_ok {
        let _write_guard = if let Some(config) = system
            .config_partition()
            .filter(|config| boot_root.starts_with(config.path()))
        {
            Some(
                config
                    .acquire_write_guard()
                    .whatever("unable to make Mender GRUB environment writable")?,
            )
        } else {
            None
        };
        if !primary_ok {
            if let Err(error) = repair_mender_grub_env(
                boot_root,
                &boot_env,
                MENDER_GRUB_LOCK1,
                MENDER_GRUB_LOCK1_SHA256,
                MENDER_GRUB_ENV1,
            ) {
                warn!(?error, "unable to repair primary Mender GRUB environment");
            }
        }
        if !secondary_ok {
            if let Err(error) = repair_mender_grub_env(
                boot_root,
                &boot_env,
                MENDER_GRUB_LOCK2,
                MENDER_GRUB_LOCK2_SHA256,
                MENDER_GRUB_ENV2,
            ) {
                warn!(?error, "unable to repair secondary Mender GRUB environment");
            }
        }
    }
    Ok(boot_env)
}

#[derive(Debug)]
pub struct MenderGrub {
    inner: MenderBootFlow,
}

impl MenderGrub {
    pub fn new(boot_entries: &BootGroups, config: &MenderBootFlowConfig) -> BootFlowResult<Self> {
        let inner = mender_boot_flow(boot_entries, config)?;
        Ok(Self { inner })
    }
}

impl BootFlow for MenderGrub {
    fn name(&self) -> &str {
        "mender-grub"
    }

    fn set_try_next(
        &self,
        system: &crate::system::System,
        group: BootGroupIdx,
    ) -> super::BootFlowResult<()> {
        let mut boot_env = load_grub_env(self.inner.boot_root().join(MENDER_GRUB_ENV1))
            .whatever("unable to load Grub environment")?;
        let trial = group != self.get_default(system)?;
        let group = mender_group(&self.inner, group)?;
        boot_env.extend(mender_state_values(
            group,
            trial,
            self.inner.boot_part_a(),
            self.inner.boot_part_b(),
        ));
        // Load the boot environment once and repair it if necessary.
        mender_load_grub_env(system, self.inner.boot_root())?;
        let _write_guard = if let Some(config) = system
            .config_partition()
            .filter(|config| self.inner.boot_root().starts_with(config.path()))
        {
            Some(
                config
                    .acquire_write_guard()
                    .whatever("unable to make Mender GRUB environment writable")?,
            )
        } else {
            None
        };
        mender_save_grub_env(self.inner.boot_root(), &boot_env)?;
        Ok(())
    }

    fn get_default(&self, system: &crate::system::System) -> super::BootFlowResult<BootGroupIdx> {
        let boot_env = mender_load_grub_env(system, self.inner.boot_root())?;
        let Some(mender_boot_part) = boot_env
            .get("mender_boot_part")
            .map(|v| v.trim())
            .and_then(|v| u32::from_str(v).ok())
        else {
            bail!("Mender boot partition is not set");
        };
        let Some(upgrade_available) = boot_env.get("upgrade_available").map(|v| v.trim()) else {
            bail!("Update available flag is not set");
        };
        let group = mender_default_group(
            mender_boot_part,
            upgrade_available == "1",
            self.inner.boot_part_a(),
            self.inner.boot_part_b(),
        )?;
        Ok(mender_group_idx(&self.inner, group))
    }

    fn commit(&self, system: &crate::system::System) -> super::BootFlowResult<()> {
        let mut boot_env = load_grub_env(self.inner.boot_root().join(MENDER_GRUB_ENV1))
            .whatever("unable to load Grub environment")?;
        let active = system
            .require_active_boot_entry()
            .whatever("unable to commit Mender GRUB boot flow")?;
        boot_env.extend(mender_state_values(
            mender_group(&self.inner, active)?,
            false,
            self.inner.boot_part_a(),
            self.inner.boot_part_b(),
        ));
        mender_load_grub_env(system, self.inner.boot_root())?;
        let _write_guard = if let Some(config) = system
            .config_partition()
            .filter(|config| self.inner.boot_root().starts_with(config.path()))
        {
            Some(
                config
                    .acquire_write_guard()
                    .whatever("unable to make Mender GRUB environment writable")?,
            )
        } else {
            None
        };
        mender_save_grub_env(self.inner.boot_root(), &boot_env)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct MenderUboot {
    inner: MenderBootFlow,
}

impl MenderUboot {
    pub fn new(boot_entries: &BootGroups, config: &MenderBootFlowConfig) -> BootFlowResult<Self> {
        let inner = mender_boot_flow(boot_entries, config)?;
        Ok(Self { inner })
    }
}

impl BootFlow for MenderUboot {
    fn name(&self) -> &str {
        "mender-uboot"
    }

    fn set_try_next(
        &self,
        system: &crate::system::System,
        group: BootGroupIdx,
    ) -> super::BootFlowResult<()> {
        let trial = group != self.get_default(system)?;
        let boot_env = mender_state_values(
            mender_group(&self.inner, group)?,
            trial,
            self.inner.boot_part_a(),
            self.inner.boot_part_b(),
        )
        .into_iter()
        .collect::<HashMap<_, _>>();
        set_vars(&boot_env)?;
        Ok(())
    }

    fn get_default(&self, _: &crate::system::System) -> super::BootFlowResult<BootGroupIdx> {
        let boot_env = load_vars()?;
        let Some(mender_boot_part) = boot_env
            .get("mender_boot_part")
            .map(|v| v.trim())
            .and_then(|v| u32::from_str(v).ok())
        else {
            bail!("Mender boot partition is not set");
        };
        let Some(upgrade_available) = boot_env.get("upgrade_available").map(|v| v.trim()) else {
            bail!("Update available flag is not set");
        };
        let group = mender_default_group(
            mender_boot_part,
            upgrade_available == "1",
            self.inner.boot_part_a(),
            self.inner.boot_part_b(),
        )?;
        Ok(mender_group_idx(&self.inner, group))
    }

    fn commit(&self, system: &crate::system::System) -> super::BootFlowResult<()> {
        let active = system
            .require_active_boot_entry()
            .whatever("unable to commit Mender U-Boot flow")?;
        let boot_env = mender_state_values(
            mender_group(&self.inner, active)?,
            false,
            self.inner.boot_part_a(),
            self.inner.boot_part_b(),
        )
        .into_iter()
        .collect::<HashMap<_, _>>();
        set_vars(&boot_env)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::mender_default_group;
    use super::mender_save_grub_env;
    use super::mender_state_values;
    use super::validate_mender_layout;
    use super::MenderGroup;

    #[test]
    fn default_group_covers_stable_trial_commit_and_rollback_states() {
        let cases = [
            // Stable systems and the state after committing a trial.
            (2, false, MenderGroup::A),
            (3, false, MenderGroup::B),
            // During a trial, the pre-update group remains the default.
            (3, true, MenderGroup::A),
            (2, true, MenderGroup::B),
            // After an exhausted trial, Mender restores the old partition and clears the flag.
            (2, false, MenderGroup::A),
            (3, false, MenderGroup::B),
        ];

        for (mender_boot_part, upgrade_available, expected) in cases {
            assert_eq!(
                mender_default_group(mender_boot_part, upgrade_available, 2, 3).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn unknown_boot_partitions_are_rejected() {
        assert!(mender_default_group(4, false, 2, 3).is_err());
        assert!(mender_default_group(4, true, 2, 3).is_err());
    }

    #[test]
    fn layout_requires_two_groups_and_distinct_partitions() {
        assert!(validate_mender_layout(2, 2, 3).is_ok());
        assert!(validate_mender_layout(1, 2, 3).is_err());
        assert!(validate_mender_layout(3, 2, 3).is_err());
        assert!(validate_mender_layout(2, 2, 2).is_err());
    }

    #[test]
    fn state_values_cover_trial_commit_and_rollback_transitions() {
        let values = |group, trial| {
            mender_state_values(group, trial, 2, 3)
                .into_iter()
                .collect::<hashbrown::HashMap<_, _>>()
        };

        let stable_a = values(MenderGroup::A, false);
        assert_eq!(stable_a["mender_boot_part"], "2");
        assert_eq!(stable_a["upgrade_available"], "0");

        let trial_b = values(MenderGroup::B, true);
        assert_eq!(trial_b["mender_boot_part"], "3");
        assert_eq!(trial_b["mender_boot_part_hex"], "0x3");
        assert_eq!(trial_b["upgrade_available"], "1");

        let committed_b = values(MenderGroup::B, false);
        assert_eq!(committed_b["mender_boot_part"], "3");
        assert_eq!(committed_b["upgrade_available"], "0");

        let rolled_back_a = values(MenderGroup::A, false);
        assert_eq!(rolled_back_a, stable_a);
    }

    #[test]
    fn grub_redundancy_write_failures_are_propagated() {
        let tempdir = tempfile::tempdir().unwrap();
        let env = std::collections::HashMap::new();
        assert!(mender_save_grub_env(tempdir.path(), &env).is_err());
    }
}
