//! RAUC-compatible boot flows.

use hashbrown::HashMap;
use reportify::bail;
use reportify::ResultExt;

use crate::boot::fwenv::load_vars;
use crate::boot::fwenv::set_vars;
use crate::config::system::RaucBootFlowConfig;
use crate::system::boot_flows::BootFlow;
use crate::system::boot_flows::BootFlowCapabilities;
use crate::system::boot_flows::BootFlowResult;
use crate::system::boot_groups::BootGroupIdx;
use crate::system::boot_groups::BootGroups;

#[derive(Debug, Clone)]
struct RaucBootGroup {
    idx: BootGroupIdx,
    name: String,
}

#[derive(Debug)]
struct RaucBootFlow {
    groups: HashMap<BootGroupIdx, RaucBootGroup>,
}

fn rauc_boot_flow(
    boot_entries: &BootGroups,
    config: &RaucBootFlowConfig,
) -> BootFlowResult<RaucBootFlow> {
    let boot_entries = boot_entries.iter().collect::<Vec<_>>();
    if boot_entries.len() < 2 {
        bail!("at least two boot groups are required");
    }

    let group_names = match &config.group_names {
        Some(group_names) => group_names.clone(),
        None => boot_entries
            .iter()
            .map(|(_, group)| group.name().to_uppercase())
            .collect(),
    };
    validate_group_names(&group_names, boot_entries.len())?;

    let groups = boot_entries
        .iter()
        .enumerate()
        .map(|(no, (idx, _))| {
            (
                *idx,
                RaucBootGroup {
                    idx: *idx,
                    name: group_names[no].clone(),
                },
            )
        })
        .collect::<HashMap<_, _>>();
    Ok(RaucBootFlow { groups })
}

fn validate_group_names(group_names: &[String], boot_group_count: usize) -> BootFlowResult<()> {
    if group_names.len() != boot_group_count {
        bail!("the number of RAUC group names must match the number of boot groups");
    }
    let mut unique_names = hashbrown::HashSet::new();
    for name in group_names {
        if name.trim().is_empty() {
            bail!("RAUC group names must not be empty");
        }
        if !unique_names.insert(name) {
            bail!("duplicate RAUC group name {name:?}");
        }
    }
    Ok(())
}

fn grub_default_group<'a>(
    boot_order: impl IntoIterator<Item = &'a str>,
    boot_env: &HashMap<String, String>,
    configured_names: &[&str],
) -> Option<&'a str> {
    boot_order.into_iter().find(|group| {
        if !configured_names.contains(group) {
            return false;
        }
        let group_ok = boot_env
            .get(&format!("{group}_OK"))
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(0);
        let group_try = boot_env
            .get(&format!("{group}_TRY"))
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(1);
        group_ok > 0 && group_try < 1
    })
}

fn uboot_default_group<'a>(
    boot_order: impl IntoIterator<Item = &'a str>,
    boot_env: &HashMap<String, String>,
    configured_names: &[&str],
) -> Option<&'a str> {
    boot_order.into_iter().find(|group| {
        configured_names.contains(group)
            && boot_env
                .get(&format!("BOOT_{group}_LEFT"))
                .and_then(|value| value.trim().parse::<u32>().ok())
                .unwrap_or(0)
                > 0
    })
}

fn prioritize_boot_group(boot_order: &str, group: &str) -> String {
    std::iter::once(group)
        .chain(
            boot_order
                .split_whitespace()
                .filter(|candidate| *candidate != group),
        )
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug)]
pub struct RaucUboot {
    inner: RaucBootFlow,
}

impl RaucUboot {
    pub fn new(boot_entries: &BootGroups, config: &RaucBootFlowConfig) -> BootFlowResult<Self> {
        let inner = rauc_boot_flow(boot_entries, config)?;
        Ok(Self { inner })
    }
}

impl BootFlow for RaucUboot {
    fn name(&self) -> &str {
        "rauc-uboot"
    }

    fn capabilities(&self) -> BootFlowCapabilities {
        BootFlowCapabilities {
            userspace_failure_recovery: Some(true),
        }
    }

    fn set_try_next(
        &self,
        system: &crate::system::System,
        group: BootGroupIdx,
    ) -> super::BootFlowResult<()> {
        if group != self.get_default(system)? {
            let boot_env = load_vars()?;
            let Some(rauc_group) = self.inner.groups.get(&group) else {
                bail!("invalid boot group");
            };
            let Some(boot_order) = boot_env.get("BOOT_ORDER").map(|v| v.trim()) else {
                bail!("unable to determine the boot order");
            };
            let mut env = HashMap::new();
            // Allow booting into the selected slot once.
            env.insert(format!("BOOT_{}_LEFT", rauc_group.name), "1".to_owned());
            env.insert(
                "BOOT_ORDER".to_owned(),
                prioritize_boot_group(boot_order, &rauc_group.name),
            );
            set_vars(&env)?;
        }
        Ok(())
    }

    fn get_default(&self, _: &crate::system::System) -> super::BootFlowResult<BootGroupIdx> {
        let boot_env = load_vars()?;
        let Some(boot_order) = boot_env
            .get("BOOT_ORDER")
            .map(|v| v.trim())
            .map(|v| v.split_whitespace().collect::<Vec<_>>())
        else {
            bail!("unable to determine the boot order");
        };
        let configured_names = self
            .inner
            .groups
            .values()
            .map(|group| group.name.as_str())
            .collect::<Vec<_>>();
        if let Some(group) = uboot_default_group(boot_order, &boot_env, &configured_names) {
            if let Some(group) = self
                .inner
                .groups
                .values()
                .find(|candidate| candidate.name == group)
            {
                return Ok(group.idx);
            }
        }
        bail!("unable to determine the default boot group");
    }

    fn commit(&self, system: &crate::system::System) -> super::BootFlowResult<()> {
        let boot_env = load_vars()?;
        let group = system
            .require_active_boot_entry()
            .whatever("unable to commit RAUC U-Boot flow")?;
        let Some(rauc_group) = self.inner.groups.get(&group) else {
            bail!("invalid boot group");
        };
        let Some(boot_order) = boot_env.get("BOOT_ORDER").map(|v| v.trim()) else {
            bail!("unable to determine the boot order");
        };
        let mut env = HashMap::new();
        // Allow booting into the selected slot once.
        env.insert(format!("BOOT_{}_LEFT", rauc_group.name), "3".to_owned());
        env.insert(
            "BOOT_ORDER".to_owned(),
            prioritize_boot_group(boot_order, &rauc_group.name),
        );
        set_vars(&env)?;
        Ok(())
    }

    fn mark_good(&self, _: &crate::system::System, group: BootGroupIdx) -> BootFlowResult<()> {
        let mut env = HashMap::new();
        let Some(rauc_group) = self.inner.groups.get(&group) else {
            bail!("invalid boot group");
        };
        env.insert(format!("BOOT_{}_LEFT", rauc_group.name), "3".to_owned());
        set_vars(&env)?;
        Ok(())
    }

    fn mark_bad(&self, system: &crate::system::System, group: BootGroupIdx) -> BootFlowResult<()> {
        let mut env = HashMap::new();
        if group
            == system
                .require_active_boot_entry()
                .whatever("unable to mark RAUC U-Boot group as bad")?
        {
            bail!("cannot mark the active boot group as bad");
        }
        let Some(rauc_group) = self.inner.groups.get(&group) else {
            bail!("invalid boot group");
        };
        env.insert(format!("BOOT_{}_LEFT", rauc_group.name), "0".to_owned());
        set_vars(&env)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct RaucGrub {
    inner: RaucBootFlow,
}

impl RaucGrub {
    pub fn new(boot_entries: &BootGroups, config: &RaucBootFlowConfig) -> BootFlowResult<Self> {
        let inner = rauc_boot_flow(boot_entries, config)?;
        Ok(Self { inner })
    }
}

impl BootFlow for RaucGrub {
    fn name(&self) -> &str {
        "rauc-grub"
    }

    fn capabilities(&self) -> BootFlowCapabilities {
        BootFlowCapabilities {
            userspace_failure_recovery: Some(true),
        }
    }

    fn set_try_next(
        &self,
        system: &crate::system::System,
        group: BootGroupIdx,
    ) -> super::BootFlowResult<()> {
        if group != self.get_default(system)? {
            let boot_env = load_vars()?;
            let Some(rauc_group) = self.inner.groups.get(&group) else {
                bail!("invalid boot group");
            };
            let Some(boot_order) = boot_env.get("BOOT_ORDER").map(|v| v.trim()) else {
                bail!("unable to determine the boot order");
            };
            let mut env = HashMap::new();
            env.insert(format!("{}_OK", rauc_group.name), "1".to_owned());
            env.insert(format!("{}_TRY", rauc_group.name), "0".to_owned());
            env.insert(
                "BOOT_ORDER".to_owned(),
                prioritize_boot_group(boot_order, &rauc_group.name),
            );
            set_vars(&env)?;
        }
        Ok(())
    }

    fn get_default(&self, _: &crate::system::System) -> super::BootFlowResult<BootGroupIdx> {
        let boot_env = load_vars()?;
        let Some(boot_order) = boot_env
            .get("BOOT_ORDER")
            .map(|v| v.trim())
            .map(|v| v.split_whitespace().collect::<Vec<_>>())
        else {
            bail!("unable to determine the boot order");
        };
        let configured_names = self
            .inner
            .groups
            .values()
            .map(|group| group.name.as_str())
            .collect::<Vec<_>>();
        if let Some(group) = grub_default_group(boot_order, &boot_env, &configured_names) {
            if let Some(group) = self
                .inner
                .groups
                .values()
                .find(|candidate| candidate.name == group)
            {
                return Ok(group.idx);
            }
        }
        bail!("unable to determine the default boot group");
    }

    fn commit(&self, system: &crate::system::System) -> super::BootFlowResult<()> {
        let boot_env = load_vars()?;
        let group = system
            .require_active_boot_entry()
            .whatever("unable to commit RAUC GRUB flow")?;
        let Some(rauc_group) = self.inner.groups.get(&group) else {
            bail!("invalid boot group");
        };
        let Some(boot_order) = boot_env.get("BOOT_ORDER").map(|v| v.trim()) else {
            bail!("unable to determine the boot order");
        };
        let mut env = HashMap::new();
        // Allow booting into the selected slot once.
        env.insert(format!("{}_OK", rauc_group.name), "1".to_owned());
        env.insert(format!("{}_TRY", rauc_group.name), "0".to_owned());
        env.insert(
            "BOOT_ORDER".to_owned(),
            prioritize_boot_group(boot_order, &rauc_group.name),
        );
        set_vars(&env)?;
        Ok(())
    }

    fn mark_good(&self, _: &crate::system::System, group: BootGroupIdx) -> BootFlowResult<()> {
        let mut env = HashMap::new();
        let Some(rauc_group) = self.inner.groups.get(&group) else {
            bail!("invalid boot group");
        };
        env.insert(format!("{}_OK", rauc_group.name), "1".to_owned());
        env.insert(format!("{}_TRY", rauc_group.name), "0".to_owned());
        set_vars(&env)?;
        Ok(())
    }

    fn mark_bad(&self, system: &crate::system::System, group: BootGroupIdx) -> BootFlowResult<()> {
        let mut env = HashMap::new();
        if group
            == system
                .require_active_boot_entry()
                .whatever("unable to mark RAUC GRUB group as bad")?
        {
            bail!("cannot mark the active boot group as bad");
        }
        let Some(rauc_group) = self.inner.groups.get(&group) else {
            bail!("invalid boot group");
        };
        env.insert(format!("{}_OK", rauc_group.name), "0".to_owned());
        env.insert(format!("{}_TRY", rauc_group.name), "0".to_owned());
        set_vars(&env)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;

    use super::grub_default_group;
    use super::prioritize_boot_group;
    use super::uboot_default_group;
    use super::validate_group_names;

    fn grub_env(values: &[(&str, &str)]) -> HashMap<String, String> {
        values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn grub_default_follows_boot_order_and_group_state() {
        let cases = [
            ("A B", vec![("A_OK", "1"), ("A_TRY", "0")], Some("A")),
            ("B A", vec![("A_OK", "1"), ("A_TRY", "0")], Some("A")),
            ("A B", vec![("B_OK", "1"), ("B_TRY", "0")], Some("B")),
            (
                "B A",
                vec![("A_OK", "1"), ("A_TRY", "0"), ("B_OK", "1"), ("B_TRY", "0")],
                Some("B"),
            ),
            ("A B", vec![("A_OK", "1"), ("A_TRY", "1")], None),
        ];

        for (boot_order, values, expected) in cases {
            let env = grub_env(&values);
            assert_eq!(
                grub_default_group(boot_order.split_whitespace(), &env, &["A", "B"]),
                expected
            );
        }
    }

    #[test]
    fn uboot_default_covers_stable_trial_commit_rollback_and_invalid_states() {
        let cases = [
            (
                "A B",
                vec![("BOOT_A_LEFT", "3"), ("BOOT_B_LEFT", "0")],
                Some("A"),
            ),
            (
                "B A",
                vec![("BOOT_A_LEFT", "3"), ("BOOT_B_LEFT", "1")],
                Some("B"),
            ),
            (
                "B A",
                vec![("BOOT_A_LEFT", "3"), ("BOOT_B_LEFT", "3")],
                Some("B"),
            ),
            (
                "B A",
                vec![("BOOT_A_LEFT", "3"), ("BOOT_B_LEFT", "0")],
                Some("A"),
            ),
            ("UNKNOWN", vec![("BOOT_UNKNOWN_LEFT", "3")], None),
        ];

        for (order, values, expected) in cases {
            let env = grub_env(&values);
            assert_eq!(
                uboot_default_group(order.split_whitespace(), &env, &["A", "B"]),
                expected
            );
        }
    }

    #[test]
    fn selecting_and_committing_prioritizes_the_requested_group_once() {
        assert_eq!(prioritize_boot_group("A B", "B"), "B A");
        assert_eq!(prioritize_boot_group("B A", "B"), "B A");
        assert_eq!(prioritize_boot_group("A B C", "B"), "B A C");
    }

    #[test]
    fn grub_default_ignores_unconfigured_groups() {
        let env = grub_env(&[("UNKNOWN_OK", "1"), ("UNKNOWN_TRY", "0")]);
        assert_eq!(
            grub_default_group("UNKNOWN A".split_whitespace(), &env, &["A", "B"]),
            None
        );
    }

    #[test]
    fn grub_default_does_not_depend_on_configured_group_order() {
        let env = grub_env(&[("B_OK", "1"), ("B_TRY", "0")]);
        for configured_names in [["A", "B"], ["B", "A"]] {
            assert_eq!(
                grub_default_group("A B".split_whitespace(), &env, &configured_names),
                Some("B")
            );
        }
    }

    #[test]
    fn group_names_must_be_nonempty_and_unique() {
        assert!(validate_group_names(&["A".into(), "B".into()], 2).is_ok());
        assert!(validate_group_names(&["A".into()], 2).is_err());
        assert!(validate_group_names(&["A".into(), "B".into(), "C".into()], 2).is_err());
        assert!(validate_group_names(&["A".into(), "A".into()], 2).is_err());
        assert!(validate_group_names(&["A".into(), "  ".into()], 2).is_err());
    }
}
