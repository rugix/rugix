use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;

use cms::cert::x509::der::oid::db::rfc5911::ID_SIGNED_DATA;
use cms::cert::x509::der::Decode;
use reportify::bail;
use reportify::ResultExt;
use rugix_bundle::add_bundle_signature;
use rugix_bundle::bundle_hash;
use rugix_bundle::format;
use rugix_bundle::format::decode::decode_slice;
use rugix_bundle::format::tags::TagNameResolver;
use rugix_bundle::manifest::BlockEncoding;
use rugix_bundle::manifest::BundleManifest;
use rugix_bundle::manifest::Compression;
use rugix_bundle::manifest::DeliveryConfig;
use rugix_bundle::manifest::DeltaEncoding;
use rugix_bundle::manifest::DeltaEncodingFormat;
use rugix_bundle::manifest::DeltaEncodingInput;
use rugix_bundle::manifest::HashAlgorithm;
use rugix_bundle::manifest::XzCompression;
use rugix_bundle::reader::BundleReader;
use rugix_bundle::signed_metadata;
use rugix_bundle::source::FileSource;
use rugix_bundle::xdelta::xdelta_compress;
use rugix_bundle::BundleResult;
use rugix_chunker::ChunkerAlgorithm;
use si_crypto_hashes::HashDigest;
use tracing::info;
use tracing::Level;

mod apps;
mod simulation;

#[derive(Debug, Parser)]
#[clap(version = rugix_version::RUGIX_GIT_VERSION)]
pub struct Args {
    #[clap(subcommand)]
    cmd: Cmd,
    #[clap(flatten)]
    logging: si_observability::clap4::LoggingArgs,
}

#[derive(Debug, Parser)]
pub enum Cmd {
    /// Create a bundle from a bundle directory.
    Bundle(BundleCmd),
    /// Unpack a bundle into a bundle directory.
    Unpack(UnpackCmd),
    /// Hash the header of a bundle.
    Hash(HashCmd),
    /// Extract a payload from a bundle.
    Extract(ExtractCmd),
    /// Compute a static delta update.
    Delta(DeltaCmd),
    /// Inspect an update bundle.
    Inspect(InspectCmd),
    /// App bundle commands.
    #[clap(subcommand)]
    Apps(AppsCmd),
    /// Manipulate and inspect signatures.
    #[clap(subcommand)]
    Signatures(SignaturesCmd),
    /// Simulate an update.
    #[clap(subcommand)]
    Simulator(simulation::SimulationCmd),
    /// Print the low-level structure of a bundle.
    #[clap(hide(true))]
    PrintStructure(PrintCmd),
}

#[derive(Debug, Subcommand)]
pub enum AppsCmd {
    /// Pack an app into a bundle.
    #[clap(subcommand)]
    Pack(AppsPackCmd),
}

#[derive(Debug, Subcommand)]
pub enum AppsPackCmd {
    /// Pack a Docker Compose app into an app bundle.
    DockerCompose(PackDockerComposeCmd),
    /// Pack a binary app into an app bundle.
    Binary(PackBinaryCmd),
    /// Pack a generic app into an app bundle.
    Generic(PackGenericCmd),
}

#[derive(Debug, Parser)]
pub struct PackDockerComposeCmd {
    /// App name.
    #[clap(long)]
    app: String,
    /// Target platform for Docker images (e.g., `linux/arm64`, `linux/amd64`).
    /// If not specified, images are saved for the host platform.
    #[clap(long)]
    platform: Option<String>,
    /// Pull newer base images while building local Compose images.
    #[clap(long)]
    pull: bool,
    /// Container builder to use for Compose `build:` services.
    #[clap(long, value_enum, default_value_t = ImageBuilder::Podman)]
    builder: ImageBuilder,
    /// Keep Compose image references as-is instead of rewriting bundled images
    /// to Rugix-owned content tags. Images are still included in the bundle.
    #[clap(long)]
    disable_pinning: bool,
    /// Skip saving Docker images (by default, images referenced in the compose
    /// file are saved and included in the bundle).
    #[clap(long)]
    disable_image_bundling: bool,
    /// Extra files or directories to include in the archive.
    /// Each entry is added at the same relative path inside the generation directory.
    #[clap(long = "include")]
    includes: Vec<PathBuf>,
    /// Component TOML/JSON files or directories to include in the bundle metadata.
    #[clap(long = "components")]
    components: Vec<PathBuf>,
    /// Health check timeout in seconds.  During activation, `docker compose up`
    /// waits up to this many seconds for containers with health checks to become
    /// healthy.  Set to 0 to disable.  Default: 120.
    #[clap(long)]
    health_check_timeout: Option<u64>,
    /// Path to a JSON file with arbitrary metadata to include in the bundle.
    #[clap(long)]
    metadata_file: Option<PathBuf>,
    /// Path to the Docker Compose file.
    compose_file: PathBuf,
    /// Output bundle file.
    output: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ImageBuilder {
    /// Build Compose images with Podman and package them from containers-storage.
    Podman,
    /// Build Compose images with Docker and package them from the Docker daemon.
    Docker,
}

#[derive(Debug, Parser)]
pub struct PackBinaryCmd {
    /// App name.
    #[clap(long)]
    app: String,
    /// Path to the executable binary.
    binary: PathBuf,
    /// Path to the systemd service unit template.
    #[clap(long)]
    service: PathBuf,
    /// Extra files or directories to include in the archive.
    #[clap(long = "include")]
    includes: Vec<PathBuf>,
    /// Component TOML/JSON files or directories to include in the bundle metadata.
    #[clap(long = "components")]
    components: Vec<PathBuf>,
    /// Path to a JSON file with arbitrary metadata to include in the bundle.
    #[clap(long)]
    metadata_file: Option<PathBuf>,
    /// Output bundle file.
    output: PathBuf,
}

#[derive(Debug, Parser)]
pub struct PackGenericCmd {
    /// App name.
    #[clap(long)]
    app: String,
    /// Path to the orchestrator script.
    orchestrator: PathBuf,
    /// Extra files or directories to include in the archive.
    #[clap(long = "include")]
    includes: Vec<PathBuf>,
    /// Component TOML/JSON files or directories to include in the bundle metadata.
    #[clap(long = "components")]
    components: Vec<PathBuf>,
    /// Path to a JSON file with arbitrary metadata to include in the bundle.
    #[clap(long)]
    metadata_file: Option<PathBuf>,
    /// Output bundle file.
    output: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum SignaturesCmd {
    /// Add a signature to a bundle.
    Add {
        /// Bundle to add the signature to.
        bundle: PathBuf,
        /// Signature in CMS format.
        signature: PathBuf,
        /// Output bundle.
        out: PathBuf,
    },
    /// Extract bundle metadata for signing.
    Prepare {
        /// Bundle to extract metadata from.
        bundle: PathBuf,
        /// Output path.
        out: PathBuf,
    },
    /// List the signatures in a bundle.
    List {
        /// Bundle to inspect.
        bundle: PathBuf,
    },
    /// Sign a bundle.
    Sign {
        /// Additional intermediate certificates to include.
        #[clap(long = "intermediate-cert")]
        certs: Vec<PathBuf>,
        /// Bundle to sign.
        bundle: PathBuf,
        /// Signer certificate.
        cert: PathBuf,
        /// Signer private key.
        key: PathBuf,
        /// Output path.
        out: PathBuf,
    },
    /// Verify that the bundle has been signed using the given certificate.
    Verify {
        /// Bundle to verify.
        bundle: PathBuf,
        /// Root certificate.
        cert: PathBuf,
    },
}

#[derive(Debug, Parser)]
pub struct PrintCmd {
    /// Path to the update bundle.
    bundle: PathBuf,
}

#[derive(Debug, Parser)]
pub struct BundleCmd {
    /// Source bundle directory.
    src: PathBuf,
    /// Output bundle file.
    dst: PathBuf,
}

#[derive(Debug, Parser)]
pub struct ExtractCmd {
    /// Expected bundle hash to verify while reading.
    #[clap(long)]
    bundle_hash: Option<HashDigest>,
    /// Path to the update bundle.
    bundle: PathBuf,
    /// Index of the payload to extract.
    payload: usize,
    /// Output file path.
    dst: PathBuf,
}

#[derive(Debug, Parser)]
pub struct DeltaCmd {
    /// Slots to compute patches for.
    #[clap(long = "slot")]
    slots: Vec<String>,
    /// Path to the old bundle.
    old: PathBuf,
    /// Path to the new bundle.
    new: PathBuf,
    /// Path to the output patch bundle.
    out: PathBuf,
    /// Disable compression of individual patch blocks.
    #[clap(long)]
    disable_compression: bool,
}

#[derive(Debug, Parser)]
pub struct UnpackCmd {
    /// Path to the bundle.
    src: PathBuf,
    /// Output directory.
    out: PathBuf,
}

#[derive(Debug, Parser)]
pub struct InspectCmd {
    /// Expected bundle hash to verify while reading.
    #[clap(long)]
    bundle_hash: Option<HashDigest>,
    /// Path to the update bundle.
    bundle: PathBuf,
}

#[derive(Debug, Parser)]
pub struct HashCmd {
    /// Path to the update bundle.
    bundle: PathBuf,
}

fn main() -> BundleResult<()> {
    let args = Args::parse();
    let _guard = si_observability::Initializer::new("RUGIX")
        .apply(&args.logging)
        .init();
    match args.cmd {
        Cmd::Bundle(create_cmd) => {
            let hash = rugix_bundle::builder::pack(&create_cmd.src, &create_cmd.dst)?;
            println!("{hash}");
        }
        Cmd::Unpack(cmd) => {
            unpack(&cmd.src, &cmd.out)?;
        }
        Cmd::Extract(unpack_cmd) => {
            let source = FileSource::from_unbuffered(File::open(&unpack_cmd.bundle).unwrap());
            let mut reader = BundleReader::start(source, unpack_cmd.bundle_hash)?;
            let mut did_read = false;
            while let Some(payload_reader) = reader.next_payload()? {
                if payload_reader.idx() != unpack_cmd.payload {
                    payload_reader.skip()?;
                } else {
                    println!("unpacking payload...");
                    let target = std::fs::OpenOptions::new()
                        .create(true)
                        .truncate(true)
                        .read(true)
                        .write(true)
                        .open(&unpack_cmd.dst)
                        .whatever("unable to open payload target")?;
                    payload_reader.decode_into(target, None, &mut |_| {})?;
                    did_read = true;
                    break;
                }
            }
            if !did_read {
                bail!("not enough payloads");
            }
        }
        Cmd::PrintStructure(print_cmd) => {
            let mut source = FileSource::from_unbuffered(File::open(&print_cmd.bundle).unwrap());
            rugix_bundle::format::stlv::pretty_print(&mut source, Some(&TagNameResolver)).unwrap();
        }
        Cmd::Hash(hash_cmd) => {
            let hash = rugix_bundle::bundle_hash(&hash_cmd.bundle).unwrap();
            println!("{hash}");
        }
        Cmd::Inspect(inspect_cmd) => {
            let source = FileSource::from_unbuffered(File::open(&inspect_cmd.bundle).unwrap());
            let reader = BundleReader::start(source, inspect_cmd.bundle_hash)?;
            println!("Payloads:");
            for (idx, entry) in reader.header().payload_index.iter().enumerate() {
                if let Some(slot_type) = &entry.type_slot {
                    println!(
                        "  {idx}: slot={:?} file={}",
                        slot_type.slot,
                        HashDigest::new_unchecked(
                            reader.header().hash_algorithm,
                            &entry.file_hash.raw
                        )
                    );
                }
                if let Some(type_execute) = &entry.type_execute {
                    let command = type_execute.handler.join(" ");
                    println!(
                        "  {idx}: execute({command}) file={}",
                        HashDigest::new_unchecked(
                            reader.header().hash_algorithm,
                            &entry.file_hash.raw
                        )
                    );
                }
                if let Some(type_app_file) = &entry.type_app_file {
                    println!(
                        "  {idx}: app-file app={:?} path={:?} file={}",
                        type_app_file.app,
                        type_app_file.path,
                        HashDigest::new_unchecked(
                            reader.header().hash_algorithm,
                            &entry.file_hash.raw
                        )
                    );
                }
                if let Some(type_app_archive) = &entry.type_app_archive {
                    println!(
                        "  {idx}: app-archive app={:?} file={}",
                        type_app_archive.app,
                        HashDigest::new_unchecked(
                            reader.header().hash_algorithm,
                            &entry.file_hash.raw
                        )
                    );
                }
            }
        }
        Cmd::Apps(apps_cmd) => match apps_cmd {
            AppsCmd::Pack(pack_cmd) => match pack_cmd {
                AppsPackCmd::DockerCompose(cmd) => {
                    apps::pack_docker_compose(&cmd)?;
                }
                AppsPackCmd::Binary(cmd) => {
                    apps::pack_binary(&cmd)?;
                }
                AppsPackCmd::Generic(cmd) => {
                    apps::pack_generic(&cmd)?;
                }
            },
        },
        Cmd::Delta(cmd) => {
            let old_dir =
                tempfile::TempDir::new().whatever("unable to create old-bundle workspace")?;
            info!(directory = ?old_dir.path(), "unpacking old update bundle");
            unpack(&cmd.old, old_dir.path())?;
            let new_dir =
                tempfile::TempDir::new().whatever("unable to create new-bundle workspace")?;
            info!(directory = ?new_dir.path(), "unpacking new update bundle");
            unpack(&cmd.new, new_dir.path())?;
            let old_manifest_path = old_dir.path().join("rugix-bundle.toml");
            let old_manifest = toml::from_str::<BundleManifest>(
                &std::fs::read_to_string(&old_manifest_path)
                    .whatever("unable to read old bundle manifest")?,
            )
            .whatever("unable to parse old bundle manifest")?;
            let new_manifest_path = new_dir.path().join("rugix-bundle.toml");
            let mut new_manifest = toml::from_str::<BundleManifest>(
                &std::fs::read_to_string(&new_manifest_path)
                    .whatever("unable to read new bundle manifest")?,
            )
            .whatever("unable to parse new bundle manifest")?;
            let explicit_slots = !cmd.slots.is_empty();
            let slots = if explicit_slots {
                cmd.slots.as_slice()
            } else {
                &["system".to_owned(), "boot:system".to_owned()]
            };
            for slot in slots {
                let (new_slot, old_slot) = slot
                    .split_once(':')
                    .unwrap_or((slot.as_str(), slot.as_str()));
                let Some(new_payload_idx) = slot_payload_index(&new_manifest, new_slot) else {
                    if explicit_slots {
                        bail!("unable to find slot {new_slot:?} in new bundle");
                    }
                    continue;
                };
                let Some(old_payload_idx) = slot_payload_index(&old_manifest, old_slot) else {
                    if explicit_slots {
                        bail!("unable to find slot {old_slot:?} in old bundle");
                    }
                    continue;
                };
                info!(%old_slot, %new_slot, "computing delta");
                let (old_filename, new_filename) = delta_payload_filenames(
                    &old_manifest,
                    &new_manifest,
                    old_payload_idx,
                    new_payload_idx,
                )?;
                let new_filename_patched = format!("{new_filename}.xdelta");
                let old_path = old_dir.path().join("payloads").join(&old_filename);
                let new_path = new_dir.path().join("payloads").join(&new_filename);
                let hash_algorithm = new_manifest
                    .hash_algorithm
                    .unwrap_or(si_crypto_hashes::HashAlgorithm::Sha512_256);
                let old_hash = hash_file(hash_algorithm, &old_path)?;
                let new_hash = hash_file(hash_algorithm, &new_path)?;
                let patch_path = new_dir.path().join("payloads").join(&new_filename_patched);
                xdelta_compress(&old_path, &new_path, &patch_path)?;
                std::fs::remove_file(&new_path)
                    .whatever("unable to replace new payload with its delta")?;
                let new_payload = &mut new_manifest.payloads[new_payload_idx];
                new_payload.filename = new_filename_patched;
                new_payload.block_encoding = Some(
                    BlockEncoding::new(ChunkerAlgorithm::Fixed {
                        block_size_kib: 256,
                    })
                    .with_compression(if cmd.disable_compression {
                        None
                    } else {
                        Some(Compression::Xz(XzCompression::new()))
                    }),
                );
                new_payload.delta_encoding = Some(DeltaEncoding::new(
                    vec![DeltaEncodingInput {
                        hashes: vec![old_hash],
                    }],
                    DeltaEncodingFormat::Xdelta,
                    new_hash,
                ));
            }
            // Compute deltas for app-file payloads with matching paths.
            for new_payload_idx in 0..new_manifest.payloads.len() {
                let DeliveryConfig::AppFile(ref new_config) =
                    new_manifest.payloads[new_payload_idx].delivery
                else {
                    continue;
                };
                let new_app = new_config.app.clone();
                let new_app_path = new_config.path.clone();
                let Some(old_payload_idx) = old_manifest.payloads.iter().position(|p| {
                    matches!(
                        &p.delivery,
                        DeliveryConfig::AppFile(config)
                            if config.app == new_app && config.path == new_app_path
                    )
                }) else {
                    info!(app = %new_app, path = %new_app_path, "no matching app-file in old bundle, skipping");
                    continue;
                };
                info!(app = %new_app, path = %new_app_path, "computing app-file delta");
                let (old_filename, new_filename) = delta_payload_filenames(
                    &old_manifest,
                    &new_manifest,
                    old_payload_idx,
                    new_payload_idx,
                )?;
                let new_filename_patched = format!("{new_filename}.xdelta");
                let old_path = old_dir.path().join("payloads").join(&old_filename);
                let new_path = new_dir.path().join("payloads").join(&new_filename);
                let hash_algorithm = new_manifest
                    .hash_algorithm
                    .unwrap_or(si_crypto_hashes::HashAlgorithm::Sha512_256);
                let old_hash = hash_file(hash_algorithm, &old_path)?;
                let new_hash = hash_file(hash_algorithm, &new_path)?;
                let patch_path = new_dir.path().join("payloads").join(&new_filename_patched);
                xdelta_compress(&old_path, &new_path, &patch_path)?;
                std::fs::remove_file(&new_path)
                    .whatever("unable to replace new app payload with its delta")?;
                let new_payload = &mut new_manifest.payloads[new_payload_idx];
                new_payload.filename = new_filename_patched;
                new_payload.block_encoding = Some(
                    BlockEncoding::new(ChunkerAlgorithm::Fixed {
                        block_size_kib: 256,
                    })
                    .with_compression(if cmd.disable_compression {
                        None
                    } else {
                        Some(Compression::Xz(XzCompression::new()))
                    }),
                );
                new_payload.delta_encoding = Some(DeltaEncoding::new(
                    vec![DeltaEncodingInput {
                        hashes: vec![old_hash],
                    }],
                    DeltaEncodingFormat::Xdelta,
                    new_hash,
                ));
            }
            std::fs::write(
                new_manifest_path,
                toml::to_string(&new_manifest).whatever("unable to serialize delta manifest")?,
            )
            .whatever("unable to write delta manifest")?;
            rugix_bundle::builder::pack(new_dir.path(), &cmd.out)?;
        }
        Cmd::Simulator(cmd) => {
            simulation::run(&cmd);
        }
        Cmd::Signatures(cmd) => match cmd {
            SignaturesCmd::Add {
                bundle,
                signature,
                out,
            } => {
                let signature = std::fs::read(&signature).whatever("unable to read signature")?;
                let content_info = cms::content_info::ContentInfo::from_der(&signature)
                    .expect("invalid signature");
                if content_info.content_type != ID_SIGNED_DATA {
                    bail!("invalid signature content type");
                }
                let signed_data = content_info
                    .content
                    .decode_as::<cms::signed_data::SignedData>()
                    .expect("invalid signature");
                println!("CMS Version: {:?}", signed_data.version);
                println!(
                    "Embedded Certificates: {}",
                    signed_data.certificates.map(|c| c.0.len()).unwrap_or(0)
                );
                let bundle_hash = bundle_hash(&bundle)?;
                if let Some(content) = signed_data.encap_content_info.econtent {
                    let signed_metadata = decode_slice::<format::SignedMetadata>(content.value())?;
                    if bundle_hash != signed_metadata.header_hash {
                        bail!("bundle hash does not match signature");
                    }
                } else {
                    bail!("no encapsulated content");
                }
                add_bundle_signature(&bundle, signature, &out)?;
            }
            SignaturesCmd::List { bundle } => {
                let source = FileSource::from_unbuffered(File::open(&bundle).unwrap());
                let reader = BundleReader::start(source, None)?;
                if let Some(signatures) = reader.signatures() {
                    for (idx, signature) in signatures.cms_signatures.iter().enumerate() {
                        println!("CMS Signature {} (length={})", idx, signature.raw.len());
                    }
                } else {
                    println!("No signatures found");
                }
            }
            SignaturesCmd::Prepare { bundle, out } => {
                let metadata = signed_metadata(&bundle)?;
                std::fs::write(out, metadata).whatever("unable to write metadata")?;
            }
            SignaturesCmd::Sign {
                certs,
                bundle,
                cert,
                key,
                out,
            } => {
                let metadata = signed_metadata(&bundle)?;
                let cert_pem =
                    std::fs::read(&cert).whatever("unable to read signer certificate")?;
                let key_pem = std::fs::read(&key).whatever("unable to read private key")?;
                let mut builder = rugix_pki::CmsSignerBuilder::new(&cert_pem, &key_pem)
                    .whatever("unable to create CMS signer")?;
                for cert in certs {
                    let cert_pem =
                        std::fs::read(&cert).whatever("unable to read intermediate certificate")?;
                    builder = builder
                        .with_intermediate_cert(&cert_pem)
                        .whatever("unable to add intermediate certificate")?;
                }
                let signer = builder.build().whatever("unable to build CMS signer")?;
                let signature = signer.sign(&metadata).whatever("unable to sign bundle")?;
                add_bundle_signature(&bundle, signature, &out)?;
            }
            SignaturesCmd::Verify { bundle, cert } => {
                let source = FileSource::from_unbuffered(File::open(&bundle).unwrap());
                let reader = BundleReader::start(source, None)?;
                let Some(signatures) = reader.signatures() else {
                    bail!("no signatures found");
                };
                let cert_pem = std::fs::read(&cert).whatever("unable to read root certificate")?;
                let verifier = rugix_pki::CmsVerifier::new(&cert_pem)
                    .whatever("unable to create CMS verifier")?;
                let mut found_valid_signature = false;
                for signature in signatures.cms_signatures.iter() {
                    let result = match verifier.verify(&signature.raw) {
                        Ok(result) => result,
                        Err(error) => {
                            println!("{error}");
                            continue;
                        }
                    };
                    let signed_metadata = decode_slice::<format::SignedMetadata>(&result.content)
                        .whatever("unable to decode signed metadata")?;
                    if signed_metadata.header_hash
                        == reader.header_hash(signed_metadata.header_hash.algorithm())
                    {
                        found_valid_signature = true;
                        println!("Found valid signature!");
                        break;
                    }
                }
                if !found_valid_signature {
                    bail!("no valid signature found");
                }
            }
        },
    }
    Ok(())
}

fn delta_payload_filenames(
    old_manifest: &BundleManifest,
    new_manifest: &BundleManifest,
    old_payload_idx: usize,
    new_payload_idx: usize,
) -> BundleResult<(String, String)> {
    let old_filename = old_manifest
        .payloads
        .get(old_payload_idx)
        .ok_or_else(|| reportify::whatever!("old payload index {old_payload_idx} is out of range"))?
        .filename
        .clone();
    let new_filename = new_manifest
        .payloads
        .get(new_payload_idx)
        .ok_or_else(|| reportify::whatever!("new payload index {new_payload_idx} is out of range"))?
        .filename
        .clone();
    Ok((old_filename, new_filename))
}

fn slot_payload_index(manifest: &BundleManifest, slot: &str) -> Option<usize> {
    manifest.payloads.iter().position(
        |payload| matches!(&payload.delivery, DeliveryConfig::Slot(config) if config.slot == slot),
    )
}

pub fn unpack(src: &Path, dst: &Path) -> BundleResult<()> {
    if std::fs::symlink_metadata(dst)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        bail!("bundle output directory must not be a symbolic link");
    }
    std::fs::create_dir_all(dst).whatever("unable to create bundle output directory")?;
    let source = FileSource::from_unbuffered(
        File::open(src).whatever("unable to open bundle for unpacking")?,
    );
    let mut reader = BundleReader::start(source, None)?;
    let Some(manifest) = &reader.header().manifest else {
        bail!("unpacking requires a manifest");
    };
    let manifest = serde_json::from_str::<BundleManifest>(manifest)
        .whatever("unable to parse embedded bundle manifest")?;
    rugix_bundle::manifest::validate_manifest_paths(&manifest)?;
    std::fs::write(
        dst.join("rugix-bundle.toml"),
        toml::to_string_pretty(&manifest).whatever("unable to serialize bundle manifest")?,
    )
    .whatever("unable to write unpacked bundle manifest")?;
    let payload_dir = dst.join("payloads");
    std::fs::create_dir_all(&payload_dir).whatever("unable to create payload output directory")?;
    while let Some(payload_reader) = reader.next_payload()? {
        let filename = &manifest.payloads[payload_reader.idx()].filename;
        info!(%filename, "unpacking bundle payload");
        let relative = rugix_common::path::ValidatedRelativePath::new(filename.clone())
            .whatever("invalid payload filename")?;
        rugix_common::path::ensure_no_symlink_components(&payload_dir, &relative)
            .whatever("payload output path contains a symbolic link")?;
        let target_path = payload_dir.join(&relative);
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)
                .whatever("unable to create payload output parent directory")?;
        }
        let target = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(target_path)
            .whatever("unable to open payload target")?;
        payload_reader.decode_into(target, None, &mut |_| {})?;
    }
    Ok(())
}

#[tracing::instrument(level = Level::DEBUG)]
pub fn hash_file(algorithm: HashAlgorithm, path: &Path) -> BundleResult<HashDigest> {
    let mut file = std::fs::File::open(path).whatever("unable to open payload for hashing")?;
    let mut buffer = vec![0u8; 8096];
    let mut hasher = algorithm.hasher();
    loop {
        let chunk_size = file
            .read(&mut buffer)
            .whatever("unable to read payload for hashing")?;
        if chunk_size > 0 {
            hasher.update(&buffer[..chunk_size]);
        } else {
            break;
        }
    }
    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use rugix_bundle::manifest::BundleManifest;
    use rugix_bundle::manifest::DeliveryConfig;
    use rugix_bundle::manifest::Payload;
    use rugix_bundle::manifest::SlotDeliveryConfig;
    use rugix_bundle::manifest::UpdateType;

    use super::delta_payload_filenames;
    use super::slot_payload_index;
    use super::unpack;

    fn payload(slot: &str, filename: &str) -> Payload {
        Payload::new(
            DeliveryConfig::Slot(SlotDeliveryConfig::new(slot.to_owned())),
            filename.to_owned(),
        )
    }

    #[test]
    fn delta_filenames_come_from_their_respective_manifests() {
        let old = BundleManifest::new(
            UpdateType::Full,
            vec![payload("a", "old-a.img"), payload("b", "old-b.img")],
        );
        let new = BundleManifest::new(
            UpdateType::Full,
            vec![payload("b", "new-b.img"), payload("a", "renamed-a.img")],
        );

        assert_eq!(
            delta_payload_filenames(&old, &new, 0, 1).unwrap(),
            ("old-a.img".to_owned(), "renamed-a.img".to_owned())
        );
        assert!(delta_payload_filenames(&old, &new, 0, 2).is_err());
        assert_eq!(slot_payload_index(&old, "a"), Some(0));
        assert_eq!(slot_payload_index(&new, "a"), Some(1));
        assert_eq!(slot_payload_index(&old, "missing"), None);
    }

    #[cfg(unix)]
    #[test]
    fn unpack_rejects_symlinked_payload_output_components() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().unwrap();
        let source_dir = tempdir.path().join("source");
        std::fs::create_dir_all(source_dir.join("payloads/redirect")).unwrap();
        let manifest = BundleManifest::new(
            UpdateType::Full,
            vec![payload("system", "redirect/system.img")],
        );
        std::fs::write(
            source_dir.join("rugix-bundle.toml"),
            toml::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(source_dir.join("payloads/redirect/system.img"), b"payload").unwrap();
        let bundle = tempdir.path().join("bundle.rugixb");
        rugix_bundle::builder::pack(&source_dir, &bundle).unwrap();

        let output = tempdir.path().join("output");
        let outside = tempdir.path().join("outside");
        std::fs::create_dir_all(output.join("payloads")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, output.join("payloads/redirect")).unwrap();

        assert!(unpack(&bundle, &output).is_err());
        assert!(!outside.join("system.img").exists());
    }
}
