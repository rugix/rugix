//! System bundle installation.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process::Child;

use reportify::bail;
use reportify::whatever;
use reportify::ErrorExt;
use reportify::ResultExt;
use rugix_bundle::format;
use rugix_bundle::reader::block_provider::StoredBlockProvider;
use rugix_bundle::reader::BundleReader;
use rugix_bundle::reader::DecodedPayloadInfo;
use rugix_bundle::reader::PayloadTarget;
use rugix_bundle::source::BundleSource;
use rugix_bundle::xdelta::xdelta_decompress;
use rugix_common::pipe::buffered_pipe;
use rugix_common::slots::SlotState;
use rugix_hooks::HooksLoader;
use rugix_hooks::RunOptions;
use tracing::info;
use tracing::trace;
use tracing::warn;
use xscript::vars;

use super::enforce_bundle_component_policy;
use super::report_compatibility_skip;
use super::require_compatible_components;
use super::run_compatibility_check;
use super::BufferedPipeTarget;
use super::BundleInstallEvent;
use super::BundleInstallOptions;
use super::BundleKind;
use super::HashWriter;
use super::ProgressCursors;
use super::SystemRebootMode;
use crate::operations::EventSink;
use crate::overlay::overlay_dir;
use crate::payload_db;
use crate::payload_db::BlockProvider;
use crate::system::boot_groups::BootGroup;
use crate::system::boot_groups::BootGroupIdx;
use crate::system::slots::SlotIdx;
use crate::system::slots::SlotKind;
use crate::system::slots::SystemSlots;
use crate::system::System;
use crate::system::SystemResult;

pub(super) fn install_payloads<R: BundleSource>(
    system: &System,
    config: &crate::config::config::Config,
    mut bundle_reader: BundleReader<R>,
    boot_group: Option<&(BootGroupIdx, &BootGroup)>,
    options: &BundleInstallOptions,
    keep_overlay: bool,
    events: &mut dyn EventSink<BundleInstallEvent>,
) -> SystemResult<SystemRebootMode> {
    run_compatibility_check(options, BundleKind::System, events, |events| {
        check_system_update_compatibility(config, &bundle_reader, events)
    })?;

    let update_hooks = HooksLoader::default()
        .load_hooks("update-install")
        .whatever("unable to load `update-install` hooks")?;
    let hook_vars = vars! {
        RUGIX_BOOT_GROUP = boot_group.map(|group| group.1.name()).unwrap_or(""),
    };
    let payload_destinations = prepare_system_update(
        || {
            preflight_system_payloads(
                bundle_reader.header(),
                system.slots(),
                boot_group.map(|(_, group)| *group),
            )
        },
        || {
            update_hooks
                .run_hooks("pre-update", hook_vars.clone(), &Default::default())
                .whatever("error running `pre-update` hooks")
        },
        || {
            if !keep_overlay {
                if let Some(boot_group) = &boot_group {
                    clear_target_overlay(&overlay_dir(boot_group.1))?;
                }
            }
            Ok(())
        },
        || {
            if !bundle_reader.header().is_incremental {
                let (entry_idx, _) = boot_group
                    .ok_or_else(|| whatever!("full update requires a target boot group"))?;
                system
                    .boot_flow()
                    .pre_install(system, *entry_idx)
                    .whatever("error executing pre-install step")?;
            }
            Ok(())
        },
    )?;

    let mut progress_cursors = ProgressCursors::default();
    let hooks = HooksLoader::default()
        .load_hooks("update-install")
        .whatever("unable to load `update-install` hooks")?;
    let mut emit_progress = |current_progress: f64, bytes_read: u64, bytes_total: u64| {
        if progress_cursors.should_emit_hook(current_progress) {
            let hook_vars = vars! {
                RUGIX_UPDATE_PROGRESS = format!("{current_progress:.2}")
            };
            match hooks.run_hooks(
                "progress",
                hook_vars,
                RunOptions::default().with_silent(true),
            ) {
                Ok(()) => progress_cursors.mark_hook_emitted(current_progress),
                Err(error) => {
                    warn!("error running 'update-install/progress' hooks: {error:?}");
                }
            }
        }
        events.emit(BundleInstallEvent::UpdateProgress {
            progress: current_progress,
            bytes_read,
            bytes_total,
        });
    };
    let mut latest_bytes_read = 0;
    let mut latest_bytes_total = 0;
    let mut progress = {
        |source: &R| {
            let Some(bytes_total) = source.bytes_total() else {
                return;
            };
            if bytes_total.raw == 0 {
                return;
            }
            let Some(bytes_read) = source.bytes_read() else {
                return;
            };
            let current_progress =
                ((bytes_read.raw as f64) / (bytes_total.raw as f64) * 100.0).min(100.0);
            latest_bytes_read = bytes_read.raw;
            latest_bytes_total = bytes_total.raw;
            emit_progress(current_progress, latest_bytes_read, latest_bytes_total);
        }
    };

    while let Some(payload) = bundle_reader
        .next_payload()
        .whatever("unable to read payload")?
    {
        let payload_entry = payload.entry();
        let destination = payload_destinations
            .get(payload.idx())
            .copied()
            .ok_or_else(|| {
                whatever!("payload {} is missing from the bundle index", payload.idx())
            })?;
        match destination {
            SystemPayloadDestination::Slot(slot_idx) => {
                let slot = &system.slots()[slot_idx];
                info!(
                    "installing bundle payload {} to slot {}",
                    payload.idx(),
                    slot.name()
                );
                payload_db::erase(slot.name())?;
                let block_provider = if !options.insecure_allow_missing_block_index {
                    let block_encoding =
                        payload.header().block_encoding.as_ref().ok_or_else(|| {
                            whatever!(
                                "payload {} does not have a block index, refusing to install",
                                payload.idx()
                            )
                        })?;
                    let mut provider = BlockProvider::new(
                        block_encoding.chunker.clone(),
                        block_encoding.hash_algorithm,
                    );
                    for (_, source_slot) in system.slots().iter() {
                        match source_slot.kind() {
                            SlotKind::Block(block_slot) => {
                                let Some(device) = block_slot.device() else {
                                    continue;
                                };
                                provider
                                    .add_slot(source_slot.name(), device.path().to_path_buf())?;
                            }
                            SlotKind::File { path } => {
                                provider.add_slot(source_slot.name(), path.to_path_buf())?;
                            }
                            SlotKind::Custom { .. } => {}
                        }
                    }
                    Some(provider)
                } else {
                    None
                };
                let _write_guard = if let SlotKind::File { path } = slot.kind() {
                    system
                        .config_partition()
                        .filter(|partition| path.starts_with(partition.path()))
                        .map(|partition| partition.acquire_write_guard())
                        .transpose()
                        .whatever("unable to make config partition writable")?
                } else {
                    None
                };
                let delta_encoding = payload_entry.delta_encoding.clone();
                finalize_payload_and_record(
                    || {
                        let decoded_payload_info = if let Some(delta_encoding) = &delta_encoding {
                            let delta_encoding = delta_encoding.clone();
                            if delta_encoding.inputs.len() != 1 {
                                bail!("unsupported number of delta encoding inputs");
                            }
                            let input = &delta_encoding.inputs[0];
                            let mut source = None;
                            'slots: for (_, delta_slot) in system.slots().iter() {
                                let Ok(Some(slot_state)) =
                                    payload_db::get_stored_state(delta_slot.name())
                                else {
                                    continue;
                                };
                                for input_hash in &input.hashes {
                                    let Some(slot_hash) =
                                        slot_state.hashes.get(&input_hash.algorithm())
                                    else {
                                        trace!(
                                            slot_name = delta_slot.name(),
                                            algorithm = ?input_hash.algorithm(),
                                            "no hash found"
                                        );
                                        continue;
                                    };
                                    if slot_hash == input_hash {
                                        source = Some(delta_slot);
                                        trace!(slot_name = delta_slot.name(), "delta source found");
                                        break 'slots;
                                    }
                                    trace!(
                                        slot_name = delta_slot.name(),
                                        %slot_hash,
                                        %input_hash,
                                        "hash does not match"
                                    );
                                }
                            }
                            let Some(source) = source else {
                                bail!("no slot suitable delta source found");
                            };
                            match delta_encoding.format {
                                rugix_bundle::manifest::DeltaEncodingFormat::Xdelta => {}
                            }
                            let source = match source.kind() {
                                SlotKind::Block(_) => {
                                    source.require_available_block()?.path().to_owned()
                                }
                                SlotKind::File { path } => path.to_owned(),
                                SlotKind::Custom { .. } => {
                                    bail!("source slot must not be a custom slot");
                                }
                            };
                            let target = match slot.kind() {
                                SlotKind::Block(_) => {
                                    let device = slot.require_available_block()?;
                                    fs::OpenOptions::new()
                                        .read(true)
                                        .write(true)
                                        .open(device)
                                        .whatever("unable to open payload target")?
                                }
                                SlotKind::File { path } => fs::OpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .create(true)
                                    .truncate(true)
                                    .open(path)
                                    .whatever("unable to open payload target")?,
                                SlotKind::Custom { .. } => {
                                    bail!("custom slots do not support delta updates yet")
                                }
                            };
                            let mut target_writer =
                                HashWriter::new(delta_encoding.original_hash.algorithm(), target);
                            let (mut patch_reader, patch_writer) = buffered_pipe(8192);
                            let (decode_result, xdelta_result) = std::thread::scope(|scope| {
                                let target_writer = &mut target_writer;
                                let handle = scope.spawn(move || {
                                    trace!("starting xdelta");
                                    let result = xdelta_decompress(
                                        &source,
                                        &mut patch_reader,
                                        target_writer,
                                    );
                                    trace!(?result, "xdelta terminated");
                                    result
                                });
                                let decode_result = payload.decode_into(
                                    BufferedPipeTarget::new(patch_writer),
                                    block_provider
                                        .as_ref()
                                        .map(|provider| provider as &dyn StoredBlockProvider),
                                    &mut progress,
                                );
                                trace!("finished decoding payload into pipe");
                                (decode_result, handle.join())
                            });
                            decode_result.whatever("unable to decode payload")?;
                            let xdelta_result = xdelta_result.map_err(|_| {
                                whatever!("delta payload worker terminated unexpectedly")
                            })?;
                            xdelta_result.whatever("unable to decode delta update")?;
                            let (target_hash, target_size) = target_writer
                                .finalize_synced()
                                .whatever("unable to synchronize delta payload target")?;
                            if target_hash != delta_encoding.original_hash {
                                bail!("decoded slot data does not match hash");
                            }
                            DecodedPayloadInfo {
                                hash: target_hash,
                                size: target_size.into(),
                            }
                        } else {
                            match slot.kind() {
                                SlotKind::Block(_) => {
                                    let device = slot.require_available_block()?;
                                    let target = fs::OpenOptions::new()
                                        .read(true)
                                        .write(true)
                                        .open(device)
                                        .whatever("unable to open payload target")?;
                                    payload
                                        .decode_into(
                                            target,
                                            block_provider.as_ref().map(|provider| {
                                                provider as &dyn StoredBlockProvider
                                            }),
                                            &mut progress,
                                        )
                                        .whatever("unable to decode payload")?
                                }
                                SlotKind::File { path } => {
                                    let target = fs::OpenOptions::new()
                                        .read(true)
                                        .write(true)
                                        .create(true)
                                        .truncate(true)
                                        .open(path)
                                        .whatever("unable to open payload target")?;
                                    payload
                                        .decode_into(
                                            target,
                                            block_provider.as_ref().map(|provider| {
                                                provider as &dyn StoredBlockProvider
                                            }),
                                            &mut progress,
                                        )
                                        .whatever("unable to decode payload")?
                                }
                                SlotKind::Custom { handler } => {
                                    let target = CustomTarget::new(
                                        handler.iter().map(|argument| argument.as_str()),
                                    )?;
                                    payload
                                        .decode_into(
                                            target,
                                            block_provider.as_ref().map(|provider| {
                                                provider as &dyn StoredBlockProvider
                                            }),
                                            &mut progress,
                                        )
                                        .whatever("unable to decode payload")?
                                }
                            }
                        };
                        Ok(decoded_payload_info)
                    },
                    |decoded_payload_info| {
                        payload_db::save_slot_state(
                            slot.name(),
                            &SlotState {
                                hashes: if slot.is_immutable() {
                                    [(
                                        decoded_payload_info.hash.algorithm(),
                                        decoded_payload_info.hash,
                                    )]
                                    .into_iter()
                                    .collect()
                                } else {
                                    Default::default()
                                },
                                size: if slot.is_immutable() {
                                    Some(decoded_payload_info.size)
                                } else {
                                    None
                                },
                                updated_at: Some(jiff::Timestamp::now()),
                            },
                        )
                        .whatever("unable to save slot state")
                    },
                )?;
            }
            SystemPayloadDestination::Execute => {
                let type_execute = payload_entry
                    .type_execute
                    .as_ref()
                    .ok_or_else(|| whatever!("execute delivery disappeared after preflight"))?;
                eprintln!("executing update payload {}", payload.idx());
                let target = CustomTarget::new(
                    type_execute
                        .handler
                        .iter()
                        .map(|argument| argument.as_str()),
                )?;
                payload
                    .decode_into(target, None, &mut progress)
                    .whatever("unable to decode payload")?;
            }
        }
    }
    #[allow(
        clippy::drop_non_drop,
        reason = "release the mutable borrow of emit_progress"
    )]
    drop(progress);
    emit_progress(100.0, latest_bytes_read, latest_bytes_total);

    let reboot_mode = if !bundle_reader.header().is_incremental {
        let (target, _) =
            boot_group.ok_or_else(|| whatever!("full update requires a target boot group"))?;
        system
            .boot_flow()
            .post_install(system, *target)
            .whatever("error executing post-install step")?;
        SystemRebootMode::Yes
    } else {
        SystemRebootMode::No
    };
    update_hooks
        .run_hooks("post-update", hook_vars, &Default::default())
        .whatever("error running `post-update` hooks")?;
    Ok(reboot_mode)
}

fn check_system_update_compatibility<S: BundleSource>(
    config: &crate::config::config::Config,
    bundle_reader: &BundleReader<S>,
    events: &mut dyn EventSink<BundleInstallEvent>,
) -> SystemResult<()> {
    let Some(bundle_components) = bundle_reader.header().components.as_ref() else {
        enforce_bundle_component_policy(config, false, "update")?;
        report_compatibility_skip(
            "system",
            "bundle component metadata is absent and not required by policy",
            events,
        );
        return Ok(());
    };
    let installed = crate::components::InstalledComponents::load()
        .whatever("unable to load installed components")?;
    let output = if bundle_reader.header().is_incremental {
        installed
            .check_incremental_update(bundle_components)
            .whatever("unable to check incremental update compatibility")?
    } else {
        installed
            .check_system_update(bundle_components)
            .whatever("unable to check system update compatibility")?
    };
    require_compatible_components(output, events)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemPayloadDestination {
    Slot(SlotIdx),
    Execute,
}

#[derive(Debug, Clone, Copy)]
struct PayloadDelivery<'a> {
    slot: Option<&'a str>,
    execute: bool,
    app_file: bool,
    app_archive: bool,
}

fn preflight_system_payloads(
    header: &format::BundleHeader,
    slots: &SystemSlots,
    boot_group: Option<&BootGroup>,
) -> SystemResult<Vec<SystemPayloadDestination>> {
    let deliveries = header
        .payload_index
        .iter()
        .map(|entry| PayloadDelivery {
            slot: entry
                .type_slot
                .as_ref()
                .map(|delivery| delivery.slot.as_str()),
            execute: entry.type_execute.is_some(),
            app_file: entry.type_app_file.is_some(),
            app_archive: entry.type_app_archive.is_some(),
        })
        .collect::<Vec<_>>();
    preflight_system_deliveries(header.is_incremental, &deliveries, slots, boot_group)
}

fn preflight_system_deliveries(
    is_incremental: bool,
    deliveries: &[PayloadDelivery<'_>],
    slots: &SystemSlots,
    boot_group: Option<&BootGroup>,
) -> SystemResult<Vec<SystemPayloadDestination>> {
    if !is_incremental && boot_group.is_none() {
        bail!("full system updates require the specification of a boot group");
    }

    let mut destinations = Vec::with_capacity(deliveries.len());
    let mut targeted_slots = HashSet::new();
    let mut system_payloads = 0usize;

    for (payload_idx, delivery) in deliveries.iter().enumerate() {
        let delivery_type_count = [
            delivery.slot.is_some(),
            delivery.execute,
            delivery.app_file,
            delivery.app_archive,
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if delivery_type_count != 1 {
            bail!(
                "bundle payload {payload_idx} must declare exactly one delivery type, found {delivery_type_count}"
            );
        }
        if delivery.app_file || delivery.app_archive {
            bail!(
                "bundle payload {payload_idx} is an app payload and cannot be installed as a system update"
            );
        }

        if let Some(slot_name) = delivery.slot {
            let slot_idx = boot_group
                .and_then(|group| group.get_slot(slot_name))
                .or_else(|| slots.find_by_name(slot_name).map(|(idx, _)| idx))
                .ok_or_else(|| {
                    whatever!(
                        "unknown destination slot {:?} for bundle payload {payload_idx}",
                        slot_name
                    )
                })?;
            let slot = &slots[slot_idx];
            if !slot.is_available() {
                bail!(
                    "destination slot {:?} for bundle payload {payload_idx} is unavailable",
                    slot.name()
                );
            }
            if slot.active() {
                bail!(
                    "refusing to install bundle payload {payload_idx} to active slot {:?}",
                    slot.name()
                );
            }
            if !targeted_slots.insert(slot_idx) {
                bail!(
                    "multiple bundle payloads resolve to destination slot {:?}",
                    slot.name()
                );
            }
            system_payloads += 1;
            destinations.push(SystemPayloadDestination::Slot(slot_idx));
        } else if delivery.execute {
            destinations.push(SystemPayloadDestination::Execute);
        } else {
            unreachable!("delivery type was validated above");
        }
    }

    if destinations.is_empty() {
        bail!("bundle does not contain any payloads applicable to a system update");
    }
    if !is_incremental && system_payloads == 0 {
        bail!("full system update does not contain a system-slot payload");
    }
    Ok(destinations)
}

fn clear_target_overlay(path: &Path) -> SystemResult<()> {
    clear_target_overlay_with(path, |path| fs::remove_dir_all(path))
}

fn clear_target_overlay_with<F>(path: &Path, remove: F) -> SystemResult<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    match remove(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error
            .whatever("unable to clear target boot-group overlay")
            .field("path", path.display().to_string())),
    }
}

fn prepare_system_update<T>(
    preflight: impl FnOnce() -> SystemResult<T>,
    pre_update_hook: impl FnOnce() -> SystemResult<()>,
    overlay_cleanup: impl FnOnce() -> SystemResult<()>,
    pre_install: impl FnOnce() -> SystemResult<()>,
) -> SystemResult<T> {
    let preflight = preflight()?;
    pre_update_hook()?;
    overlay_cleanup()?;
    pre_install()?;
    Ok(preflight)
}

fn finalize_payload_and_record<T>(
    finalize: impl FnOnce() -> SystemResult<T>,
    record: impl FnOnce(T) -> SystemResult<()>,
) -> SystemResult<()> {
    let finalized = finalize()?;
    record(finalized)
}

#[derive(Debug)]
struct CustomTarget {
    child: Child,
}

impl CustomTarget {
    fn new<'arg>(mut command: impl Iterator<Item = &'arg str>) -> SystemResult<Self> {
        let Some(program) = command.next() else {
            bail!("custom update handler cannot be an empty sequence");
        };
        let child = std::process::Command::new(program)
            .args(command)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .whatever("unable to spawn custom update handler")?;
        Ok(Self { child })
    }
}

impl PayloadTarget for CustomTarget {
    fn write(&mut self, bytes: &[u8]) -> rugix_bundle::BundleResult<()> {
        self.child
            .stdin
            .as_mut()
            .ok_or_else(|| whatever!("custom update handler stdin is already closed"))?
            .write_all(bytes)
            .whatever("unable to write payload to custom handler")
    }

    fn finalize(mut self) -> rugix_bundle::BundleResult<()> {
        info!("waiting on custom update handler to finalize");
        let stdin = self
            .child
            .stdin
            .take()
            .ok_or_else(|| whatever!("custom update handler stdin is already closed"))?;
        drop(stdin);
        let status = self
            .child
            .wait()
            .whatever("error waiting for update handler")?;
        if !status.success() {
            bail!(
                "error running custom update handler, code {:?}",
                status.code()
            )
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io;
    use std::path::Path;

    use indexmap::IndexMap;

    use super::clear_target_overlay_with;
    use super::finalize_payload_and_record;
    use super::preflight_system_deliveries;
    use super::prepare_system_update;
    use super::PayloadDelivery;
    use super::SystemPayloadDestination;
    use crate::config::system::BlockSlotConfig;
    use crate::config::system::BootGroupConfig;
    use crate::config::system::FileSlotConfig;
    use crate::config::system::SlotConfig;
    use crate::system::boot_groups::BootGroups;
    use crate::system::slots::SystemSlots;
    use crate::system::SystemResult;

    fn no_delivery() -> PayloadDelivery<'static> {
        PayloadDelivery {
            slot: None,
            execute: false,
            app_file: false,
            app_archive: false,
        }
    }

    fn slot_delivery(slot: &'static str) -> PayloadDelivery<'static> {
        PayloadDelivery {
            slot: Some(slot),
            ..no_delivery()
        }
    }

    fn execute_delivery() -> PayloadDelivery<'static> {
        PayloadDelivery {
            execute: true,
            ..no_delivery()
        }
    }

    fn file_slots(names: &[&str]) -> SystemSlots {
        let config = names
            .iter()
            .map(|name| {
                (
                    (*name).to_owned(),
                    SlotConfig::File(FileSlotConfig {
                        path: format!("/tmp/{name}"),
                        immutable: Some(true),
                    }),
                )
            })
            .collect::<IndexMap<_, _>>();
        SystemSlots::from_config(None, Some(&config)).unwrap()
    }

    #[test]
    fn preflight_resolves_group_aliases_before_installation() {
        let slots = file_slots(&["system-a", "system-b"]);
        let mut aliases = IndexMap::new();
        aliases.insert("system".to_owned(), "system-b".to_owned());
        let groups_config = [("b".to_owned(), BootGroupConfig { slots: aliases })]
            .into_iter()
            .collect::<IndexMap<_, _>>();
        let groups = BootGroups::from_config(&slots, Some(&groups_config)).unwrap();
        let (_, group) = groups.iter().next().unwrap();
        let target_idx = slots.find_by_name("system-b").unwrap().0;

        assert_eq!(
            preflight_system_deliveries(false, &[slot_delivery("system")], &slots, Some(group))
                .unwrap(),
            vec![SystemPayloadDestination::Slot(target_idx)]
        );
    }

    #[test]
    fn preflight_rejects_unknown_active_and_duplicate_destinations() {
        let slots = file_slots(&["target"]);
        assert!(
            preflight_system_deliveries(true, &[slot_delivery("missing")], &slots, None).is_err()
        );

        let (_, active) = slots.find_by_name("target").unwrap();
        active.mark_active();
        assert!(
            preflight_system_deliveries(true, &[slot_delivery("target")], &slots, None).is_err()
        );

        let slots = file_slots(&["target"]);
        assert!(preflight_system_deliveries(
            true,
            &[slot_delivery("target"), slot_delivery("target")],
            &slots,
            None
        )
        .is_err());
    }

    #[test]
    fn preflight_requires_one_supported_delivery_type() {
        let slots = file_slots(&["target"]);
        assert!(preflight_system_deliveries(true, &[no_delivery()], &slots, None).is_err());

        let mut ambiguous = slot_delivery("target");
        ambiguous.execute = true;
        assert!(preflight_system_deliveries(true, &[ambiguous], &slots, None).is_err());
    }

    #[test]
    fn preflight_rejects_unavailable_optional_block_slots() {
        let config = [(
            "optional".to_owned(),
            SlotConfig::Block(BlockSlotConfig {
                device: Some("/dev/rugix-test-device-does-not-exist".to_owned()),
                partition: None,
                immutable: Some(true),
                optional: Some(true),
            }),
        )]
        .into_iter()
        .collect::<IndexMap<_, _>>();
        let slots = SystemSlots::from_config(None, Some(&config)).unwrap();

        assert!(
            preflight_system_deliveries(true, &[slot_delivery("optional")], &slots, None).is_err()
        );
    }

    #[test]
    fn preflight_rejects_app_only_empty_and_inapplicable_full_bundles() {
        let slots = file_slots(&["target"]);
        let app_delivery = PayloadDelivery {
            app_archive: true,
            ..no_delivery()
        };
        assert!(preflight_system_deliveries(true, &[app_delivery], &slots, None).is_err());
        assert!(preflight_system_deliveries(true, &[], &slots, None).is_err());

        let groups_config = [(
            "target".to_owned(),
            BootGroupConfig {
                slots: IndexMap::new(),
            },
        )]
        .into_iter()
        .collect::<IndexMap<_, _>>();
        let groups = BootGroups::from_config(&slots, Some(&groups_config)).unwrap();
        let (_, group) = groups.iter().next().unwrap();
        assert!(
            preflight_system_deliveries(false, &[execute_delivery()], &slots, Some(group)).is_err()
        );
    }

    #[test]
    fn overlay_cleanup_ignores_only_missing_directories() {
        let path = Path::new("/test/overlay");
        assert!(clear_target_overlay_with(path, |_| {
            Err(io::Error::from(io::ErrorKind::NotFound))
        })
        .is_ok());
        assert!(clear_target_overlay_with(path, |_| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .is_err());
    }

    #[test]
    fn failed_preflight_runs_no_mutating_update_stage() {
        let hook = Cell::new(false);
        let overlay = Cell::new(false);
        let bootloader = Cell::new(false);
        let target = Cell::new(false);
        let payload_database = Cell::new(false);
        let result = prepare_system_update(
            || -> SystemResult<()> { reportify::bail!("invalid destination") },
            || {
                hook.set(true);
                Ok(())
            },
            || {
                overlay.set(true);
                Ok(())
            },
            || {
                bootloader.set(true);
                Ok(())
            },
        );
        if result.is_ok() {
            target.set(true);
            payload_database.set(true);
        }
        assert!(result.is_err());
        assert!(!hook.get());
        assert!(!overlay.get());
        assert!(!bootloader.get());
        assert!(!target.get());
        assert!(!payload_database.get());
    }

    #[test]
    fn failed_overlay_cleanup_stops_before_bootloader_or_payload_stages() {
        let pre_install = Cell::new(false);
        let payload_written = Cell::new(false);
        let prepared = prepare_system_update(
            || Ok(()),
            || Ok(()),
            || -> SystemResult<()> { reportify::bail!("injected overlay failure") },
            || {
                pre_install.set(true);
                Ok(())
            },
        );
        if prepared.is_ok() {
            payload_written.set(true);
        }
        assert!(prepared.is_err());
        assert!(!pre_install.get());
        assert!(!payload_written.get());
    }

    #[test]
    fn failed_payload_synchronization_preserves_state_and_boot_selection() {
        let payload_state_written = Cell::new(false);
        let boot_selection_changed = Cell::new(false);
        let result = finalize_payload_and_record(
            || -> SystemResult<()> { reportify::bail!("injected payload synchronization failure") },
            |_| {
                payload_state_written.set(true);
                Ok(())
            },
        );
        if result.is_ok() {
            boot_selection_changed.set(true);
        }

        assert!(result.is_err());
        assert!(!payload_state_written.get());
        assert!(!boot_selection_changed.get());
    }
}
