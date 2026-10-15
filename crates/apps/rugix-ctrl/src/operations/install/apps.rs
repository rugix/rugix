//! Application bundle installation.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use byte_calc::NumBytes;
use reportify::bail;
use reportify::whatever;
use reportify::ResultExt;
use rugix_bundle::format;
use rugix_bundle::reader::BundleReader;
use rugix_bundle::reader::PayloadReader;
use rugix_bundle::reader::StoredBlockProvider;
use rugix_bundle::xdelta::xdelta_decompress;
use rugix_common::path::ensure_no_symlink_components;
use rugix_common::path::ValidatedRelativePath;
use rugix_common::pipe::buffered_pipe;
use rugix_store::DEFAULT_CHUNKER;
use rugix_store::DEFAULT_HASH_ALGORITHM;
use si_crypto_hashes::HashDigest;
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
use crate::apps::files::GenerationFiles;
use crate::apps::manager::AppManager;
use crate::config::config::Config;
use crate::operations::EventSink;
use crate::payload_db;
use crate::payload_db::BlockProvider;
use crate::system::SystemResult;

pub(crate) fn install_payloads(
    config: &Config,
    app_manager: &AppManager,
    mut bundle_reader: BundleReader,
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
    let new_generation = NewGeneration {
        manager: app_manager,
        app_name: &app_name,
        number: generation,
        dir: &generation_dir,
    };
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
            let mode = type_app_file.mode;
            let store = type_app_file.store == Some(true);
            let state = install_app_file(
                &new_generation,
                &payload_path,
                mode,
                store,
                payload,
                options,
            )?;
            payload_states.insert(payload_path.as_str().to_owned(), state);
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
                let mut provider = BlockProvider::new(
                    block_encoding.chunker.clone(),
                    block_encoding.hash_algorithm,
                );
                provider.add_store(app_manager.store());
                Some(provider)
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

/// Generation an app bundle is installed into.
struct NewGeneration<'generation> {
    manager: &'generation AppManager,
    app_name: &'generation str,
    number: u64,
    dir: &'generation Path,
}

/// Install an `app-file` payload into the generation directory or, if `store` is set,
/// the store.
///
/// The file `mode` applies to files in the generation directory.
fn install_app_file(
    generation: &NewGeneration<'_>,
    payload_path: &ValidatedRelativePath,
    mode: Option<u32>,
    store: bool,
    payload: PayloadReader<'_>,
    options: &BundleInstallOptions,
) -> SystemResult<payload_db::PayloadState> {
    ensure_no_symlink_components(generation.dir, payload_path)
        .whatever("app-file path contains a symbolic link")?;
    let file_path = generation.dir.join(payload_path);
    let block_provider = app_file_block_provider(generation, payload_path, &payload, options)?;
    let block_provider = block_provider
        .as_ref()
        .map(|provider| provider as &dyn StoredBlockProvider);
    let delta_encoding = payload.entry().delta_encoding.clone();
    let mut store_writer = if store {
        // Blocks of a delta payload encode the patch, not the file, so the file is
        // chunked like files that do not arrive as blocks.
        let (chunker, hash_algorithm) = match &payload.header().block_encoding {
            Some(encoding) if delta_encoding.is_none() => {
                (encoding.chunker.clone(), encoding.hash_algorithm)
            }
            _ => (DEFAULT_CHUNKER, DEFAULT_HASH_ALGORITHM),
        };
        Some(
            generation
                .manager
                .store()
                .writer(chunker, hash_algorithm)
                .whatever("unable to write to store")?,
        )
    } else {
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).whatever("unable to create parent directory")?;
        }
        None
    };
    let open_file = || {
        fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&file_path)
            .whatever("unable to open app file target")
    };

    let (hash, size) = if let Some(delta_encoding) = delta_encoding {
        info!(
            app = generation.app_name,
            path = %payload_path,
            "installing delta app file payload {}",
            payload.idx()
        );
        let [input] = delta_encoding.inputs.as_slice() else {
            bail!("unsupported number of delta encoding inputs");
        };
        match delta_encoding.format {
            rugix_bundle::manifest::DeltaEncodingFormat::Xdelta => {}
        }
        let source = find_delta_source(generation, payload_path, &input.hashes)?;
        let algorithm = delta_encoding.original_hash.algorithm();
        let (hash, size) = match &mut store_writer {
            Some(writer) => {
                let mut output = HashWriter::new(algorithm, writer);
                apply_xdelta(payload, source.path(), &mut output, block_provider)?;
                output.finalize()
            }
            None => {
                let mut output = HashWriter::new(algorithm, open_file()?);
                apply_xdelta(payload, source.path(), &mut output, block_provider)?;
                output
                    .finalize_synced()
                    .whatever("unable to synchronize delta app payload")?
            }
        };
        if hash != delta_encoding.original_hash {
            bail!("decoded app file data does not match hash");
        }
        (hash, NumBytes::new(size))
    } else {
        info!(
            app = generation.app_name,
            path = %payload_path,
            "extracting app file payload {}",
            payload.idx()
        );
        let mut progress = |_source: &_| {};
        let info = match &mut store_writer {
            Some(writer) => payload.decode_into(writer, block_provider, &mut progress),
            None => payload.decode_into(open_file()?, block_provider, &mut progress),
        }
        .whatever("unable to decode app payload")?;
        (info.hash, info.size)
    };

    // A later payload replaces an earlier one at the same path, wherever it is kept.
    let name = GenerationFiles::file_ref(generation.app_name, generation.number, payload_path);
    match store_writer {
        Some(writer) => {
            writer
                .commit(&name)
                .whatever("unable to commit app file to store")?;
            match fs::remove_file(&file_path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => {
                    return Err(error).whatever("unable to remove replaced app file");
                }
                _ => {}
            }
        }
        None => {
            generation
                .manager
                .store()
                .remove(&name)
                .whatever("unable to remove replaced stored app file")?;
            #[cfg(unix)]
            if let Some(mode) = mode {
                fs::set_permissions(&file_path, fs::Permissions::from_mode(mode))
                    .whatever("unable to set app file permissions")?;
            }
        }
    }
    Ok(payload_db::PayloadState {
        hashes: [(hash.algorithm(), hash)].into_iter().collect(),
        size: Some(size),
        updated_at: Some(jiff::Timestamp::now()),
    })
}

/// Collect local block candidates for an `app-file` payload.
///
/// Candidates come from indexed copies of the file in earlier generations and from
/// the store. Returns `None` for payloads that may lack a block encoding.
fn app_file_block_provider(
    generation: &NewGeneration<'_>,
    payload_path: &ValidatedRelativePath,
    payload: &PayloadReader<'_>,
    options: &BundleInstallOptions,
) -> SystemResult<Option<BlockProvider>> {
    if options.insecure_allow_missing_block_index {
        return Ok(None);
    }
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
    for old_generation in generation
        .manager
        .list_generations(generation.app_name)
        .unwrap_or_default()
    {
        if !old_generation.complete {
            continue;
        }
        let old_generation_dir = generation
            .manager
            .generation_dir(generation.app_name, old_generation.meta.number)
            .whatever("invalid app name")?;
        let indices = payload_db::get_app_file_indices(&old_generation_dir, payload_path.as_str())
            .unwrap_or_default();
        if !indices.is_empty() {
            let data_file = old_generation_dir.join(payload_path);
            if data_file.exists() {
                if let Err(error) = provider.add_indices(&indices, data_file) {
                    warn!("failed to load app-file block indices: {error:?}");
                }
            }
        }
    }
    provider.add_store(generation.manager.store());
    Ok(Some(provider))
}

/// Source file of a delta payload.
enum DeltaSource {
    /// File in the directory of an earlier generation.
    File(PathBuf),
    /// Copy of a stored file of an earlier generation.
    Materialized(tempfile::NamedTempFile),
}

impl DeltaSource {
    fn path(&self) -> &Path {
        match self {
            DeltaSource::File(path) => path,
            DeltaSource::Materialized(file) => file.path(),
        }
    }
}

/// Find the copy of the file in an earlier generation that a delta payload applies to.
///
/// The source must match one of the `input_hashes`. Xdelta requires a seekable source,
/// so a stored file is copied into the new generation directory, which an interrupted
/// installation leaves incomplete.
fn find_delta_source(
    generation: &NewGeneration<'_>,
    payload_path: &ValidatedRelativePath,
    input_hashes: &[HashDigest],
) -> SystemResult<DeltaSource> {
    let store = generation.manager.store();
    for old_generation in generation
        .manager
        .list_generations(generation.app_name)
        .unwrap_or_default()
    {
        if !old_generation.complete {
            continue;
        }
        let number = old_generation.meta.number;
        let old_generation_dir = generation
            .manager
            .generation_dir(generation.app_name, number)
            .whatever("invalid app name")?;
        let old_states = AppManager::load_payload_states(&old_generation_dir);
        let Some(old_state) = old_states.get(payload_path.as_str()) else {
            continue;
        };
        if !input_hashes
            .iter()
            .any(|hash| old_state.hashes.get(&hash.algorithm()) == Some(hash))
        {
            continue;
        }
        let candidate = old_generation_dir.join(payload_path);
        if candidate.exists() {
            return Ok(DeltaSource::File(candidate));
        }
        let name = GenerationFiles::file_ref(generation.app_name, number, payload_path);
        if let Some(object) = store
            .resolve(&name)
            .whatever("unable to resolve stored file")?
        {
            let staging_dir = generation.dir.join(".rugix");
            fs::create_dir_all(&staging_dir).whatever("unable to create .rugix directory")?;
            let mut copy = tempfile::NamedTempFile::new_in(&staging_dir)
                .whatever("unable to create delta source")?;
            let mut reader = store.open(&object).whatever("unable to open stored file")?;
            io::copy(&mut reader, &mut copy).whatever("unable to copy stored delta source")?;
            return Ok(DeltaSource::Materialized(copy));
        }
    }
    bail!("no suitable delta source found for app-file {payload_path}");
}

/// Apply an Xdelta payload to `source`, writing the reconstructed file to `output`.
fn apply_xdelta<W: Write + Send>(
    payload: PayloadReader<'_>,
    source: &Path,
    output: &mut W,
    block_provider: Option<&dyn StoredBlockProvider>,
) -> SystemResult<()> {
    let (mut patch_reader, patch_writer) = buffered_pipe(8192);
    let mut progress = |_source: &_| {};
    let (decode_result, xdelta_result) = std::thread::scope(|scope| {
        let handle = scope.spawn(move || xdelta_decompress(source, &mut patch_reader, output));
        let decode_result = payload.decode_into(
            BufferedPipeTarget::new(patch_writer),
            block_provider,
            &mut progress,
        );
        (decode_result, handle.join())
    });
    decode_result.whatever("unable to decode delta app payload")?;
    let xdelta_result =
        xdelta_result.map_err(|_| whatever!("delta app payload worker terminated unexpectedly"))?;
    xdelta_result.whatever("unable to decompress delta app payload")
}

fn check_app_bundle_compatibility(
    config: &Config,
    bundle_reader: &BundleReader,
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
    for (payload_idx, entry) in header.payload_index.iter().enumerate() {
        if entry
            .type_app_file
            .as_ref()
            .is_some_and(|file| file.store == Some(true) && file.mode.is_some())
        {
            bail!("app bundle payload {payload_idx} declares a file mode for a stored file");
        }
    }
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
    use std::collections::HashMap;
    use std::fs;
    use std::fs::File;
    use std::io::Read;
    use std::io::Write;

    use rugix_bundle::reader::BundleReader;
    use rugix_bundle::reader::BundleSource;
    use rugix_common::path::ValidatedRelativePath;
    use rugix_store::Store;
    use rugix_store::DEFAULT_CHUNKER;
    use rugix_store::DEFAULT_HASH_ALGORITHM;
    use si_crypto_hashes::HashDigest;

    use super::find_delta_source;
    use super::install_app_file;
    use super::validate_app_archive;
    use super::validate_app_deliveries;
    use super::AppPayloadDelivery;
    use super::BundleInstallOptions;
    use super::DeltaSource;
    use super::NewGeneration;
    use crate::apps::files::GenerationFiles;
    use crate::apps::manager::AppManager;
    use crate::config::apps::AppsConfig;
    use crate::payload_db::PayloadState;

    /// Verifies that a stored file of an earlier generation is copied out of the store
    /// as the seekable source of a delta payload.
    #[test]
    fn stored_delta_sources_are_copied_out_of_the_store() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(
            tempdir.path().join("apps"),
            Store::new(tempdir.path().join("store")),
            AppsConfig::new(),
        );
        let path = ValidatedRelativePath::new("images/app.tar").unwrap();
        let content = b"content of the old image";
        let hash: HashDigest = DEFAULT_HASH_ALGORITHM.hash(content);
        let old_dir = manager.generation_dir("example", 1).unwrap();
        fs::create_dir_all(&old_dir).unwrap();
        let state = PayloadState {
            hashes: [(hash.algorithm(), hash.clone())].into_iter().collect(),
            ..PayloadState::default()
        };
        AppManager::save_payload_states(
            &old_dir,
            &HashMap::from([(path.as_str().to_owned(), state)]),
        )
        .unwrap();
        AppManager::mark_complete(&old_dir).unwrap();
        let mut writer = manager
            .store()
            .writer(DEFAULT_CHUNKER, DEFAULT_HASH_ALGORITHM)
            .unwrap();
        writer.write_all(content).unwrap();
        writer
            .commit(&GenerationFiles::file_ref("example", 1, &path))
            .unwrap();
        let new_dir = manager.generation_dir("example", 2).unwrap();
        fs::create_dir_all(&new_dir).unwrap();
        let generation = NewGeneration {
            manager: &manager,
            app_name: "example",
            number: 2,
            dir: &new_dir,
        };

        let source = find_delta_source(&generation, &path, &[hash]).unwrap();
        assert!(matches!(source, DeltaSource::Materialized(_)));
        assert_eq!(fs::read(source.path()).unwrap(), content);
    }

    /// Verifies that a stored app file payload is written to the store instead of the
    /// generation directory, replacing a file installed earlier at the same path.
    #[test]
    fn stored_app_files_replace_earlier_files_in_the_generation_directory() {
        let tempdir = tempfile::tempdir().unwrap();
        let bundle_dir = tempdir.path().join("bundle");
        fs::create_dir_all(bundle_dir.join("payloads")).unwrap();
        let content = (0..20_000)
            .map(|line| format!("layer {line}\n"))
            .collect::<String>();
        fs::write(bundle_dir.join("payloads/image.tar"), &content).unwrap();
        fs::write(
            bundle_dir.join("rugix-bundle.toml"),
            r#"
            update-type = "full"
            [[payloads]]
            filename = "image.tar"
            delivery = { type = "app-file", app = "example", path = "images/image.tar", store = true }
            block-encoding = { chunker = "casync-64", compression = { type = "xz" } }
            "#,
        )
        .unwrap();
        let bundle = tempdir.path().join("bundle.rugixb");
        rugix_bundle::builder::pack(&bundle_dir, &bundle).unwrap();
        let source = BundleSource::from_seekable(File::open(&bundle).unwrap()).unwrap();
        let mut reader = BundleReader::start(source, None).unwrap();
        let payload = reader.next_payload().unwrap().unwrap();

        let manager = AppManager::new(
            tempdir.path().join("apps"),
            Store::new(tempdir.path().join("store")),
            AppsConfig::new(),
        );
        let path = ValidatedRelativePath::new("images/image.tar").unwrap();
        let dir = manager.generation_dir("example", 1).unwrap();
        fs::create_dir_all(dir.join("images")).unwrap();
        fs::write(dir.join(&path), "from an earlier payload").unwrap();
        let generation = NewGeneration {
            manager: &manager,
            app_name: "example",
            number: 1,
            dir: &dir,
        };
        let options = BundleInstallOptions {
            bundle_hash: None,
            root_cert: None,
            insecure_skip_bundle_verification: false,
            insecure_allow_missing_block_index: false,
            skip_compatibility_check: false,
            app_configuration: None,
        };

        let state = install_app_file(&generation, &path, None, true, payload, &options).unwrap();
        assert_eq!(state.size.unwrap().raw, content.len() as u64);
        assert!(!dir.join(&path).exists());
        let mut stored = String::new();
        manager
            .generation_files("example", 1)
            .unwrap()
            .open(&path)
            .unwrap()
            .read_to_string(&mut stored)
            .unwrap();
        assert_eq!(stored, content);
    }

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
