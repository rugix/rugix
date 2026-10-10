//! Application bundle installation.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use reportify::bail;
use reportify::whatever;
use reportify::ResultExt;
use rugix_bundle::format;
use rugix_bundle::reader::block_provider::StoredBlockProvider;
use rugix_bundle::reader::BundleReader;
use rugix_bundle::reader::DecodedPayloadInfo;
use rugix_bundle::source::BundleSource;
use rugix_bundle::xdelta::xdelta_decompress;
use rugix_common::path::ensure_no_symlink_components;
use rugix_common::path::ValidatedRelativePath;
use rugix_common::pipe::buffered_pipe;
use tracing::info;
use tracing::warn;

use super::enforce_bundle_component_policy;
use super::require_compatible_components;
use super::run_compatibility_check;
use super::BufferedPipeTarget;
use super::BundleInstallEvent;
use super::BundleInstallOptions;
use super::BundleKind;
use super::HashWriter;
use crate::apps::manager::AppManager;
use crate::config::config::Config;
use crate::operations::EventSink;
use crate::payload_db;
use crate::payload_db::BlockProvider;
use crate::system::SystemResult;

pub(super) fn install_payloads<S: BundleSource>(
    config: &Config,
    app_manager: &AppManager,
    mut bundle_reader: BundleReader<S>,
    options: &BundleInstallOptions,
    events: &mut dyn EventSink<BundleInstallEvent>,
) -> SystemResult<()> {
    let app_name = validate_app_bundle_header(bundle_reader.header())?;

    let bundle_components = bundle_reader.header().components.clone();
    if let Some(components) = &bundle_components {
        crate::components::validate_bundle_components(components)?;
    }

    let lock = app_manager
        .lock_app(&app_name)
        .whatever("unable to lock app")?;

    run_compatibility_check(options, BundleKind::App, events, |events| {
        check_app_bundle_compatibility(config, &bundle_reader, &app_name, events)
    })?;

    let (generation, generation_dir) = app_manager
        .create_generation(&lock, &app_name)
        .whatever("unable to create app generation")?;
    let mut payload_states: HashMap<String, payload_db::PayloadState> = HashMap::new();
    let mut progress = |_source: &_| {};

    while let Some(payload) = bundle_reader
        .next_payload()
        .whatever("unable to read payload")?
    {
        let payload_entry = payload.entry();
        if let Some(type_app_file) = &payload_entry.type_app_file {
            let payload_path = ValidatedRelativePath::new(type_app_file.path.clone())
                .whatever("invalid app-file path")?;
            let file_mode = type_app_file.mode;
            let delta_encoding = payload_entry.delta_encoding.clone();
            ensure_no_symlink_components(&generation_dir, &payload_path)
                .whatever("app-file path contains a symbolic link")?;
            let file_path = generation_dir.join(&payload_path);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).whatever("unable to create parent directory")?;
            }

            let block_provider = if !options.insecure_allow_missing_block_index {
                let block_encoding = payload.header().block_encoding.as_ref().ok_or_else(|| {
                    whatever!(
                        "payload {} does not have a block index, refusing to install",
                        payload.idx()
                    )
                })?;
                let mut provider = BlockProvider::new(
                    block_encoding.chunker.clone(),
                    block_encoding.hash_algorithm,
                );
                for generation in app_manager.list_generations(&app_name).unwrap_or_default() {
                    if !generation.complete {
                        continue;
                    }
                    let old_generation_dir = app_manager
                        .generation_dir(&app_name, generation.meta.number)
                        .whatever("invalid app name")?;
                    let indices = payload_db::get_app_file_indices(
                        &old_generation_dir,
                        payload_path.as_str(),
                    )
                    .unwrap_or_default();
                    if !indices.is_empty() {
                        let data_file = old_generation_dir.join(&payload_path);
                        if data_file.exists() {
                            if let Err(error) = provider.add_indices(&indices, data_file) {
                                warn!("failed to load app-file block indices: {error:?}");
                            }
                        }
                    }
                }
                Some(provider)
            } else {
                None
            };

            let decoded_payload_info = if let Some(delta_encoding) = delta_encoding {
                info!(
                    app = app_name,
                    path = %payload_path,
                    "installing delta app file payload {}",
                    payload.idx()
                );
                if delta_encoding.inputs.len() != 1 {
                    bail!("unsupported number of delta encoding inputs");
                }
                let input = &delta_encoding.inputs[0];
                let mut source_path = None;
                'generations: for generation in
                    app_manager.list_generations(&app_name).unwrap_or_default()
                {
                    if !generation.complete {
                        continue;
                    }
                    let old_generation_dir = app_manager
                        .generation_dir(&app_name, generation.meta.number)
                        .whatever("invalid app name")?;
                    let old_states = AppManager::load_payload_states(&old_generation_dir);
                    let Some(old_state) = old_states.get(payload_path.as_str()) else {
                        continue;
                    };
                    for input_hash in &input.hashes {
                        if let Some(stored_hash) = old_state.hashes.get(&input_hash.algorithm()) {
                            if stored_hash == input_hash {
                                let candidate = old_generation_dir.join(&payload_path);
                                if candidate.exists() {
                                    source_path = Some(candidate);
                                    break 'generations;
                                }
                            }
                        }
                    }
                }
                let Some(source_path) = source_path else {
                    bail!("no suitable delta source found for app-file {payload_path}");
                };
                match delta_encoding.format {
                    rugix_bundle::manifest::DeltaEncodingFormat::Xdelta => {}
                }
                let target = fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .read(true)
                    .write(true)
                    .open(&file_path)
                    .whatever("unable to open app file target")?;
                let mut target_writer =
                    HashWriter::new(delta_encoding.original_hash.algorithm(), target);
                let (mut patch_reader, patch_writer) = buffered_pipe(8192);
                let (decode_result, xdelta_result) = std::thread::scope(|scope| {
                    let target_writer = &mut target_writer;
                    let handle = scope.spawn(move || {
                        xdelta_decompress(&source_path, &mut patch_reader, target_writer)
                    });
                    let decode_result = payload.decode_into(
                        BufferedPipeTarget::new(patch_writer),
                        block_provider
                            .as_ref()
                            .map(|provider| provider as &dyn StoredBlockProvider),
                        &mut progress,
                    );
                    (decode_result, handle.join())
                });
                decode_result.whatever("unable to decode delta app payload")?;
                let xdelta_result = xdelta_result
                    .map_err(|_| whatever!("delta app payload worker terminated unexpectedly"))?;
                xdelta_result.whatever("unable to decompress delta app payload")?;
                let (target_hash, target_size) = target_writer
                    .finalize_synced()
                    .whatever("unable to synchronize delta app payload")?;
                if target_hash != delta_encoding.original_hash {
                    bail!("decoded app file data does not match hash");
                }
                DecodedPayloadInfo {
                    hash: target_hash,
                    size: target_size.into(),
                    block_index: None,
                }
            } else {
                info!(
                    app = app_name,
                    path = %payload_path,
                    "extracting app file payload {}",
                    payload.idx()
                );
                let target = fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .read(true)
                    .write(true)
                    .open(&file_path)
                    .whatever("unable to open app file target")?;
                payload
                    .decode_into(
                        target,
                        block_provider
                            .as_ref()
                            .map(|provider| provider as &dyn StoredBlockProvider),
                        &mut progress,
                    )
                    .whatever("unable to decode app payload")?
            };

            #[cfg(unix)]
            if let Some(mode) = file_mode {
                fs::set_permissions(&file_path, fs::Permissions::from_mode(mode))
                    .whatever("unable to set app file permissions")?;
            }

            payload_states.insert(
                payload_path.as_str().to_owned(),
                payload_db::PayloadState {
                    hashes: [(
                        decoded_payload_info.hash.algorithm(),
                        decoded_payload_info.hash,
                    )]
                    .into_iter()
                    .collect(),
                    size: Some(decoded_payload_info.size),
                    updated_at: Some(jiff::Timestamp::now()),
                },
            );
            continue;
        }

        if payload_entry.type_app_archive.is_some() {
            info!(
                app = app_name,
                "extracting app archive payload {}",
                payload.idx()
            );
            let temporary_archive = tempfile::NamedTempFile::new()
                .whatever("unable to create temporary file for archive")?;
            let temporary_file = temporary_archive
                .as_file()
                .try_clone()
                .whatever("unable to clone temp file handle")?;
            let block_provider = if !options.insecure_allow_missing_block_index {
                let block_encoding = payload.header().block_encoding.as_ref().ok_or_else(|| {
                    whatever!(
                        "payload {} does not have a block index, refusing to install",
                        payload.idx()
                    )
                })?;
                Some(BlockProvider::new(
                    block_encoding.chunker.clone(),
                    block_encoding.hash_algorithm,
                ))
            } else {
                None
            };
            payload
                .decode_into(
                    temporary_file,
                    block_provider
                        .as_ref()
                        .map(|provider| provider as &dyn StoredBlockProvider),
                    &mut progress,
                )
                .whatever("unable to decode app archive payload")?;
            let archive_file = File::open(temporary_archive.path())
                .whatever("unable to reopen archive for extraction")?;
            validate_app_archive(archive_file)?;
            let archive_file = File::open(temporary_archive.path())
                .whatever("unable to reopen validated archive for extraction")?;
            tar::Archive::new(archive_file)
                .unpack(&generation_dir)
                .whatever("unable to extract app archive")?;
            continue;
        }

        payload.skip().whatever("unable to skip payload")?;
    }

    AppManager::save_payload_states(&generation_dir, &payload_states)
        .whatever("unable to save app payload states")?;
    info!(app = %app_name, generation, "finalizing app generation");
    if let Some(bundle_components) = &bundle_components {
        crate::components::write_bundle_components(
            bundle_components,
            &generation_dir.join(".rugix/components"),
        )
        .whatever("unable to install app component metadata")?;
    }
    app_manager
        .write_generation_metadata(
            &generation_dir,
            &crate::config::apps::AppGeneration::new(
                generation,
                jiff::Timestamp::now().to_string(),
            ),
        )
        .whatever("unable to write generation metadata")?;
    AppManager::finalize_generation(&generation_dir)
        .whatever("unable to finalize app generation")?;

    // Resolving configuration before activation means a document that does not satisfy
    // the new generation's schema fails the installation without stopping a running
    // workload. The generation is finalized first, so a rejected document leaves a
    // complete generation that `apps activate --config` can take over without
    // downloading the bundle again.
    let target = app_manager
        .prepare_configuration(
            &lock,
            &app_name,
            generation,
            options.app_configuration.as_ref(),
        )
        .whatever("unable to prepare app configuration")?;
    app_manager
        .activate_deployment(&lock, &app_name, target)
        .whatever("unable to activate app generation")?;

    Ok(())
}

fn check_app_bundle_compatibility<S: BundleSource>(
    config: &Config,
    bundle_reader: &BundleReader<S>,
    app_name: &str,
    events: &mut dyn EventSink<BundleInstallEvent>,
) -> SystemResult<()> {
    let bundle_components = bundle_reader.header().components.as_ref();
    enforce_bundle_component_policy(config, bundle_components.is_some(), "app")?;
    if bundle_components.is_none() {
        warn!("app bundle does not declare components, checking removal of touched app components");
    }
    let installed = crate::components::InstalledComponents::load()
        .whatever("unable to load installed components")?;
    let touched_apps = [app_name.to_owned()];
    let output = installed
        .check_app_update(&touched_apps, bundle_components)
        .whatever("unable to check app bundle compatibility")?;
    require_compatible_components(output, events)
}

#[derive(Debug, Clone, Copy)]
struct AppPayloadDelivery<'a> {
    app_file: Option<(&'a str, &'a str)>,
    app_archive: Option<&'a str>,
    slot: bool,
    execute: bool,
}

/// Validate an app bundle header and return the app it installs.
fn validate_app_bundle_header(header: &format::BundleHeader) -> SystemResult<String> {
    let deliveries = header
        .payload_index
        .iter()
        .map(|entry| AppPayloadDelivery {
            app_file: entry
                .type_app_file
                .as_ref()
                .map(|delivery| (delivery.app.as_str(), delivery.path.as_str())),
            app_archive: entry
                .type_app_archive
                .as_ref()
                .map(|delivery| delivery.app.as_str()),
            slot: entry.type_slot.is_some(),
            execute: entry.type_execute.is_some(),
        })
        .collect::<Vec<_>>();
    Ok(validate_app_deliveries(&deliveries)?.to_owned())
}

/// Validate every app payload delivery and return the app the bundle installs.
fn validate_app_deliveries<'a>(deliveries: &[AppPayloadDelivery<'a>]) -> SystemResult<&'a str> {
    if deliveries.is_empty() {
        bail!("app bundle does not contain any payloads");
    }
    let mut installed_app = None;
    for (payload_idx, delivery) in deliveries.iter().enumerate() {
        let delivery_count = [
            delivery.app_file.is_some(),
            delivery.app_archive.is_some(),
            delivery.slot,
            delivery.execute,
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if delivery_count != 1 {
            bail!(
                "app bundle payload {payload_idx} must declare exactly one delivery type, found {delivery_count}"
            );
        }
        if delivery.slot || delivery.execute {
            bail!("app bundle payload {payload_idx} is not an app payload");
        }
        let (app, path) = match (delivery.app_file, delivery.app_archive) {
            (Some((app, path)), None) => (app, Some(path)),
            (None, Some(app)) => (app, None),
            _ => unreachable!("delivery count validated above"),
        };
        rugix_bundle::manifest::validate_app_name(app)
            .whatever("invalid app name in bundle payload")?;
        if let Some(path) = path {
            ValidatedRelativePath::new(path).whatever("invalid app-file path in bundle payload")?;
        }
        match installed_app {
            Some(installed) if installed != app => bail!(
                "app bundle installs more than one app ({installed:?} and {app:?}); \
                 pack one bundle per app"
            ),
            _ => installed_app = Some(app),
        }
    }
    Ok(installed_app.expect("a bundle with payloads always names an app"))
}

fn validate_app_archive(file: File) -> SystemResult<()> {
    let mut archive = tar::Archive::new(file);
    let mut paths = Vec::new();
    let mut link_paths = HashSet::new();
    let mut unique_paths = HashSet::new();
    for entry in archive
        .entries()
        .whatever("unable to read app archive entries")?
    {
        let entry = entry.whatever("unable to read app archive entry")?;
        let path = entry.path().whatever("unable to read app archive path")?;
        let path = path
            .to_str()
            .ok_or_else(|| whatever!("app archive path is not UTF-8"))?;
        let path = ValidatedRelativePath::new(path).whatever("invalid path in app archive")?;
        if !unique_paths.insert(path.as_str().to_owned()) {
            bail!("duplicate path in app archive: {path}");
        }
        if entry.header().entry_type().is_symlink() || entry.header().entry_type().is_hard_link() {
            let target = entry
                .link_name()
                .whatever("unable to read app archive link target")?
                .ok_or_else(|| whatever!("app archive link has no target"))?;
            let target = target
                .to_str()
                .ok_or_else(|| whatever!("app archive link target is not UTF-8"))?;
            ValidatedRelativePath::new(target).whatever("invalid link target in app archive")?;
            link_paths.insert(path.as_str().to_owned());
        }
        paths.push(path);
    }

    for path in &paths {
        if link_paths.iter().any(|link| {
            path.as_str() != link
                && path
                    .as_str()
                    .strip_prefix(link)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) {
            bail!("app archive contains a path beneath a symbolic or hard link: {path}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::validate_app_archive;
    use super::validate_app_deliveries;
    use super::AppPayloadDelivery;

    #[test]
    fn app_bundle_paths_are_validated_before_installation() {
        let valid = [
            AppPayloadDelivery {
                app_file: Some(("example_app", "config/settings.json")),
                app_archive: None,
                slot: false,
                execute: false,
            },
            AppPayloadDelivery {
                app_file: None,
                app_archive: Some("example_app"),
                slot: false,
                execute: false,
            },
        ];
        assert_eq!(validate_app_deliveries(&valid).unwrap(), "example_app");

        for (app, path) in [
            ("../escape", "file"),
            ("example", "/absolute"),
            ("example", "../escape"),
            ("example", "directory/./file"),
            ("example", ""),
        ] {
            let delivery = [AppPayloadDelivery {
                app_file: Some((app, path)),
                app_archive: None,
                slot: false,
                execute: false,
            }];
            assert!(
                validate_app_deliveries(&delivery).is_err(),
                "{app:?} {path:?}"
            );
        }

        let system_delivery = [AppPayloadDelivery {
            app_file: None,
            app_archive: None,
            slot: true,
            execute: false,
        }];
        assert!(validate_app_deliveries(&system_delivery).is_err());
    }

    /// Verifies an app bundle may only install a single app.
    #[test]
    fn app_bundle_payloads_for_several_apps_are_rejected() {
        let deliveries = [
            AppPayloadDelivery {
                app_file: None,
                app_archive: Some("first-app"),
                slot: false,
                execute: false,
            },
            AppPayloadDelivery {
                app_file: None,
                app_archive: Some("second-app"),
                slot: false,
                execute: false,
            },
        ];

        let error = validate_app_deliveries(&deliveries).unwrap_err();

        assert!(format!("{error:?}").contains("more than one app"));
    }

    #[test]
    fn app_archive_validation_rejects_escaping_and_redirected_paths() {
        fn archive_with<F>(build: F) -> tempfile::NamedTempFile
        where
            F: FnOnce(&mut tar::Builder<File>),
        {
            let file = tempfile::NamedTempFile::new().unwrap();
            let mut builder = tar::Builder::new(file.as_file().try_clone().unwrap());
            build(&mut builder);
            builder.finish().unwrap();
            drop(builder);
            file
        }

        let safe = archive_with(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_size(4);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "directory/file", b"safe".as_slice())
                .unwrap();
        });
        assert!(validate_app_archive(File::open(safe.path()).unwrap()).is_ok());

        let escaping_link = archive_with(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            builder
                .append_link(&mut header, "redirect", "../outside")
                .unwrap();
        });
        assert!(validate_app_archive(File::open(escaping_link.path()).unwrap()).is_err());

        let redirected_write = archive_with(|builder| {
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            link.set_mode(0o777);
            link.set_cksum();
            builder
                .append_link(&mut link, "redirect", "directory")
                .unwrap();

            let mut file = tar::Header::new_gnu();
            file.set_size(4);
            file.set_mode(0o644);
            file.set_cksum();
            builder
                .append_data(&mut file, "redirect/file", b"data".as_slice())
                .unwrap();
        });
        assert!(validate_app_archive(File::open(redirected_write.path()).unwrap()).is_err());
    }
}
