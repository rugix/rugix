//! Benchmark driver for the production HTTP source and block-based bundle decoder.
//!
//! Fixture creation and local block indexing happen outside the timed region.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::num::NonZeroU64;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use byte_calc::NumBytes;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use reportify::bail;
use reportify::ResultExt;
use rugix_bundle::reader::BundleReader;
use rugix_bundle::reader::PayloadTarget;
use rugix_bundle::reader::StoredBlock;
use rugix_bundle::reader::StoredBlockProvider;
use rugix_bundle::BundleResult;
use si_crypto_hashes::HashAlgorithm;

use http_source::parse_max_range_size;
use http_source::HttpSource;
use http_source::RangeQueryStrategy;
use http_source::RetryConfig;

#[allow(dead_code)]
#[path = "../../crates/apps/rugix-ctrl/src/http_source/mod.rs"]
mod http_source;

#[path = "../../crates/apps/rugix-ctrl/src/http.rs"]
mod http;

/// Supply the source's error alias without compiling the system installer.
mod system {
    pub type SystemResult<T> = rugix_bundle::BundleResult<T>;
}

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a deterministic, uncompressed block-encoded bundle.
    Prepare {
        directory: PathBuf,
        #[arg(long, default_value_t = 32)]
        payload_mib: u32,
        #[arg(long, default_value_t = 64)]
        block_kib: u16,
    },
    /// Decode a bundle through the production HTTP source.
    Fetch {
        directory: PathBuf,
        url: String,
        #[arg(long, value_enum)]
        strategy: Strategy,
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=100))]
        reuse_percent: u8,
        #[arg(long, value_enum, default_value_t = Layout::Scattered)]
        layout: Layout,
        #[arg(long, default_value = "60")]
        http_stall_timeout: NonZeroU64,
        #[arg(long, default_value = "1MiB", value_parser = parse_max_range_size)]
        http_max_range_size: NonZeroUsize,
        #[arg(long, default_value = "4")]
        http_concurrency: NonZeroUsize,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Strategy {
    Disabled,
    Resume,
    Dynamic,
}

#[derive(Clone, Copy, ValueEnum)]
enum Layout {
    Scattered,
    Contiguous,
}

fn main() -> BundleResult<()> {
    match Args::parse().command {
        Command::Prepare {
            directory,
            payload_mib,
            block_kib,
        } => prepare(&directory, payload_mib, block_kib),
        Command::Fetch {
            directory,
            url,
            strategy,
            reuse_percent,
            layout,
            http_stall_timeout,
            http_max_range_size,
            http_concurrency,
        } => fetch(
            &directory,
            &url,
            strategy,
            reuse_percent,
            layout,
            http_source::HttpFetchConfig {
                stall_timeout: Duration::from_secs(http_stall_timeout.get()),
                max_range_size: http_max_range_size,
                concurrency: http_concurrency,
            },
        ),
    }
}

fn prepare(directory: &Path, payload_mib: u32, block_kib: u16) -> BundleResult<()> {
    if payload_mib == 0 || block_kib == 0 {
        bail!("payload and block sizes must be positive");
    }
    let payload_size = u64::from(payload_mib) * 1024 * 1024;
    let block_size = usize::from(block_kib) * 1024;
    if payload_size % block_size as u64 != 0 {
        bail!("payload size must be a multiple of the block size");
    }
    std::fs::create_dir_all(directory.join("payloads"))
        .whatever("unable to create fixture directory")?;
    let mut payload = File::create(directory.join("payloads/system.img"))
        .whatever("unable to create fixture payload")?;
    let mut block = vec![0; block_size];
    for block_idx in 0..payload_size / block_size as u64 {
        for (word_idx, word) in block.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            let counter = block_idx * (block_size as u64 / 8) + word_idx as u64;
            word.copy_from_slice(&counter.to_le_bytes());
        }
        payload
            .write_all(&block)
            .whatever("unable to write fixture payload")?;
    }
    let manifest = format!(
        r#"update-type = "full"

[[payloads]]
filename = "system.img"
delivery = {{ type = "slot", slot = "system" }}
block-encoding = {{ chunker = "fixed-{block_kib}", deduplicate = false }}
"#,
    );
    std::fs::write(directory.join("rugix-bundle.toml"), manifest)
        .whatever("unable to write fixture manifest")?;
    rugix_bundle::builder::pack(directory, &directory.join("bundle.rugixb"))?;
    std::fs::write(directory.join("block-size"), block_size.to_string())
        .whatever("unable to write fixture block size")?;
    Ok(())
}

fn fetch(
    directory: &Path,
    url: &str,
    strategy: Strategy,
    reuse_percent: u8,
    layout: Layout,
    options: http_source::HttpFetchConfig,
) -> BundleResult<()> {
    let provider = FixtureProvider::load(directory, reuse_percent, layout)?;
    let strategy = match strategy {
        Strategy::Disabled => RangeQueryStrategy::Disabled,
        Strategy::Resume => RangeQueryStrategy::Resume,
        Strategy::Dynamic => RangeQueryStrategy::Dynamic,
    };
    http::setup();
    let started = Instant::now();
    let (input, tracker) = HttpSource::new(
        url,
        strategy,
        RetryConfig {
            max_retries: 0,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        },
        &options,
    )?
    .into_parts();
    let mut reader = BundleReader::start_with_options(input, None, options.reader_options())?
        .with_size_hint(tracker.size_hint());
    let payload = reader
        .next_payload()?
        .ok_or_else(|| reportify::whatever!("missing fixture payload"))?;
    let decoded = payload.decode_into(DiscardTarget, Some(&provider), &mut |_| {})?;
    if reader.next_payload()?.is_some() {
        bail!("fixture has more than one payload");
    }
    let elapsed = started.elapsed().as_secs_f64();
    drop(reader);
    let stats = tracker.get_download_stats();
    if decoded.size.raw != provider.payload_size {
        bail!("decoded payload size does not match fixture");
    }
    println!(
        "{elapsed:.9},{},{},{},{}",
        decoded.size.raw, provider.reused_bytes, stats.bytes_read.raw, stats.bytes_skipped.raw,
    );
    Ok(())
}

/// Index selected blocks in a local payload, as a system slot's block provider would.
struct FixtureProvider {
    file: PathBuf,
    blocks: HashMap<Vec<u8>, (u64, u64)>,
    payload_size: u64,
    reused_bytes: u64,
}

impl FixtureProvider {
    fn load(directory: &Path, reuse_percent: u8, layout: Layout) -> BundleResult<Self> {
        let block_size = std::fs::read_to_string(directory.join("block-size"))
            .whatever("unable to read fixture block size")?
            .parse::<usize>()
            .whatever("invalid fixture block size")?;
        if block_size == 0 {
            bail!("fixture block size must be positive");
        }
        let file = directory.join("payloads/system.img");
        let mut payload = File::open(&file).whatever("unable to open fixture payload")?;
        let payload_size = payload
            .metadata()
            .whatever("unable to inspect fixture payload")?
            .len();
        let num_blocks = payload_size / block_size as u64;
        let reused_blocks = num_blocks * u64::from(reuse_percent) / 100;
        let mut blocks = HashMap::new();
        let mut buffer = vec![0; block_size];
        for idx in 0..num_blocks {
            payload
                .read_exact(&mut buffer)
                .whatever("unable to read fixture block")?;
            let reused = match layout {
                Layout::Contiguous => idx < reused_blocks,
                Layout::Scattered => {
                    (idx + 1) * reused_blocks / num_blocks > idx * reused_blocks / num_blocks
                }
            };
            if reused {
                let hash = HashAlgorithm::Sha512_256.hash::<Box<[u8]>>(&buffer);
                blocks.insert(
                    hash.raw().to_vec(),
                    (idx * block_size as u64, block_size as u64),
                );
            }
        }
        Ok(Self {
            file,
            blocks,
            payload_size,
            reused_bytes: reused_blocks * block_size as u64,
        })
    }
}

impl StoredBlockProvider for FixtureProvider {
    fn query(&self, hash: &[u8]) -> Option<StoredBlock> {
        let &(offset, size) = self.blocks.get(hash)?;
        Some(StoredBlock {
            file: self.file.clone(),
            offset: NumBytes::new(offset),
            size: NumBytes::new(size),
            compression: None,
        })
    }
}

/// Decode and verify every block and the payload hash without timing disk writes.
struct DiscardTarget;

impl PayloadTarget for DiscardTarget {
    fn write(&mut self, _bytes: &[u8]) -> BundleResult<()> {
        Ok(())
    }
}
