//! Data partition drivers.
//!
//! A driver owns the data partition's lifecycle: bootstrap-time `format`,
//! per-boot `mount`, and `wipe` for cryptographic factory reset. The trait
//! is parallel to [`BootFlow`](crate::system::boot_flows::BootFlow) — multiple
//! in-tree implementations live alongside each other and the active one is
//! resolved from [`SystemConfig`](crate::config::system::SystemConfig).

use std::path::Path;
use std::path::PathBuf;

use reportify::ResultExt;
use rugix_common::partitions::mkfs_ext4;
use tracing::info;
use tracing::warn;
use xscript::cmd_os;
use xscript::run;
use xscript::ParentEnv;
use xscript::Run;

use crate::config::system::CustomDataPartitionDriverConfig;
use crate::config::system::DataPartitionDriverConfig;
use crate::config::system::Luks2PassphraseDriverConfig;
use crate::config::system::Luks2Tpm2DriverConfig;
use crate::config::system::PartitionConfig;
use crate::config::system::PlaintextExt4DriverConfig;

use super::SystemResult;

const DEFAULT_LABEL: &str = "data";
const DEFAULT_MAPPER_NAME: &str = "rugix-data";

/// Lifecycle hooks for a data partition.
pub trait DataPartitionDriver {
    /// Initialise a fresh partition (encryption layer + filesystem).
    fn format(&self, ctx: &DriverContext) -> SystemResult<()>;

    /// Make the partition available at the configured mount point.
    fn mount(&self, ctx: &DriverContext) -> SystemResult<()>;

    /// Render existing partition contents unrecoverable and leave the
    /// partition in a fresh, mountable state. For encrypting drivers this
    /// rotates the master key (so the previous ciphertext is permanently
    /// undecryptable); for plaintext drivers it discards and reformats.
    fn wipe(&self, ctx: &DriverContext) -> SystemResult<()>;
}

/// Inputs threaded through to driver lifecycle calls.
pub struct DriverContext {
    pub device: PathBuf,
    pub mount_point: PathBuf,
}

impl DriverContext {
    pub fn new(device: PathBuf, mount_point: PathBuf) -> Self {
        Self {
            device,
            mount_point,
        }
    }
}

/// Resolve the active driver for a data partition configuration.
///
/// Precedence: explicit `driver` field, then legacy `mount-script`, then
/// the default plaintext Ext4 driver.
pub fn resolve_driver(config: &PartitionConfig) -> Box<dyn DataPartitionDriver> {
    if let Some(driver) = &config.driver {
        return match driver {
            DataPartitionDriverConfig::PlaintextExt4(cfg) => {
                Box::new(PlaintextExt4Driver::new(cfg.clone()))
            }
            DataPartitionDriverConfig::Luks2Passphrase(cfg) => {
                Box::new(Luks2PassphraseDriver::new(cfg.clone()))
            }
            DataPartitionDriverConfig::Luks2Tpm2(cfg) => {
                Box::new(Luks2Tpm2Driver::new(cfg.clone()))
            }
            DataPartitionDriverConfig::Custom(cfg) => Box::new(CustomDriver::new(cfg.clone())),
        };
    }
    if let Some(mount_script) = &config.mount_script {
        return Box::new(LegacyMountScriptDriver::new(mount_script.clone()));
    }
    Box::new(PlaintextExt4Driver::default())
}

/// Default driver: bare Ext4 on the partition device.
pub struct PlaintextExt4Driver {
    label: String,
    additional_options: Vec<String>,
}

impl PlaintextExt4Driver {
    pub fn new(config: PlaintextExt4DriverConfig) -> Self {
        Self {
            label: config.label.unwrap_or_else(|| DEFAULT_LABEL.to_owned()),
            additional_options: config.additional_options.unwrap_or_default(),
        }
    }
}

impl Default for PlaintextExt4Driver {
    fn default() -> Self {
        Self::new(PlaintextExt4DriverConfig::new())
    }
}

impl DataPartitionDriver for PlaintextExt4Driver {
    fn format(&self, ctx: &DriverContext) -> SystemResult<()> {
        mkfs_ext4(&ctx.device, &self.label, &self.additional_options)
            .whatever("unable to create Ext4 filesystem on data partition")
    }

    fn mount(&self, ctx: &DriverContext) -> SystemResult<()> {
        fsck_best_effort(&ctx.device);
        mount_noatime(&ctx.device, &ctx.mount_point)
    }

    fn wipe(&self, ctx: &DriverContext) -> SystemResult<()> {
        // Best-effort discard so the FTL can drop blocks on hardware that
        // supports TRIM; non-fatal otherwise. The reformat below is what
        // actually makes the partition usable again.
        if let Err(error) = run!(["/usr/bin/env", "blkdiscard", "--force", &ctx.device]) {
            warn!("blkdiscard reported: {error}");
        }
        self.format(ctx)
    }
}

/// LUKS2 driver with the passphrase loaded from a file.
///
/// **Not** a stand-alone production encryption mode: a passphrase living on
/// plaintext flash defeats the encryption. Useful for testing and for
/// out-of-band-delivered keys that are never persisted locally.
pub struct Luks2PassphraseDriver {
    config: Luks2PassphraseDriverConfig,
}

impl Luks2PassphraseDriver {
    pub fn new(config: Luks2PassphraseDriverConfig) -> Self {
        Self { config }
    }

    fn label(&self) -> &str {
        self.config.label.as_deref().unwrap_or(DEFAULT_LABEL)
    }

    fn mapper_name(&self) -> &str {
        self.config
            .mapper_name
            .as_deref()
            .unwrap_or(DEFAULT_MAPPER_NAME)
    }

    fn passphrase_path(&self) -> &Path {
        Path::new(&self.config.passphrase_file)
    }
}

impl DataPartitionDriver for Luks2PassphraseDriver {
    fn format(&self, ctx: &DriverContext) -> SystemResult<()> {
        require_passphrase(self.passphrase_path())?;
        ensure_dm_module();
        info!("luks2-passphrase: formatting {:?}", ctx.device);
        luks2_format_with_keyfile(&ctx.device, self.passphrase_path())?;
        cryptsetup_open_with_keyfile(&ctx.device, self.passphrase_path(), self.mapper_name())?;
        let mapper = mapper_device(self.mapper_name());
        let mkfs_result = mkfs_ext4(
            &mapper,
            self.label(),
            self.config
                .additional_mkfs_options
                .as_deref()
                .unwrap_or(&[]),
        )
        .whatever("unable to create Ext4 filesystem on LUKS mapper");
        let close_result = cryptsetup_close(self.mapper_name());
        mkfs_result?;
        close_result?;
        Ok(())
    }

    fn mount(&self, ctx: &DriverContext) -> SystemResult<()> {
        require_passphrase(self.passphrase_path())?;
        ensure_dm_module();
        let mapper = mapper_device(self.mapper_name());
        if !mapper.exists() {
            cryptsetup_open_with_keyfile(&ctx.device, self.passphrase_path(), self.mapper_name())?;
        }
        fsck_best_effort(&mapper);
        mount_noatime(&mapper, &ctx.mount_point)
    }

    fn wipe(&self, ctx: &DriverContext) -> SystemResult<()> {
        ensure_dm_module();
        cryptsetup_erase(&ctx.device)?;
        self.format(ctx)
    }
}

/// LUKS2 driver with the unseal key sealed by a TPM 2.0 device.
///
/// At format time, generates a throwaway random passphrase, formats the
/// partition with it, then enrols the TPM via `systemd-cryptenroll` and
/// wipes the throwaway slot — leaving the TPM as the only unseal path. At
/// unlock time, `cryptsetup open --token-only` reads the TPM2 token from
/// the LUKS2 header, asks the TPM to unseal, and unlocks the volume — no
/// passphrase touches local flash.
pub struct Luks2Tpm2Driver {
    config: Luks2Tpm2DriverConfig,
}

impl Luks2Tpm2Driver {
    pub fn new(config: Luks2Tpm2DriverConfig) -> Self {
        Self { config }
    }

    fn label(&self) -> &str {
        self.config.label.as_deref().unwrap_or(DEFAULT_LABEL)
    }

    fn mapper_name(&self) -> &str {
        self.config
            .mapper_name
            .as_deref()
            .unwrap_or(DEFAULT_MAPPER_NAME)
    }

    fn device_arg(&self) -> &str {
        self.config.device.as_deref().unwrap_or("auto")
    }

    fn pcrs_arg(&self) -> Option<String> {
        self.config
            .pcrs
            .as_deref()
            .filter(|p| !p.is_empty())
            .map(|pcrs| {
                pcrs.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join("+")
            })
    }
}

impl DataPartitionDriver for Luks2Tpm2Driver {
    fn format(&self, ctx: &DriverContext) -> SystemResult<()> {
        ensure_dm_module();
        info!("luks2-tpm2: formatting {:?}", ctx.device);

        // The throwaway passphrase only exists for the duration of this
        // function — long enough to luksFormat + mkfs + enrol, then wiped.
        let bytes = read_throwaway_entropy(32)?;
        let key_dir = tempfile::Builder::new()
            .prefix("rugix-luks-")
            .tempdir_in("/run")
            .whatever("unable to create temp dir for throwaway key on /run")?;
        let key_path = key_dir.path().join("luks-throwaway.key");
        std::fs::write(&key_path, hex::encode(bytes).as_bytes())
            .whatever("unable to write throwaway key file")?;

        luks2_format_with_keyfile(&ctx.device, &key_path)?;
        cryptsetup_open_with_keyfile(&ctx.device, &key_path, self.mapper_name())?;
        let mapper = mapper_device(self.mapper_name());
        let mkfs_result = mkfs_ext4(
            &mapper,
            self.label(),
            self.config
                .additional_mkfs_options
                .as_deref()
                .unwrap_or(&[]),
        )
        .whatever("unable to create Ext4 filesystem on LUKS mapper");
        let close_result = cryptsetup_close(self.mapper_name());
        mkfs_result?;
        close_result?;

        let mut enroll_cmd = cmd_os!(
            "/usr/bin/env",
            "systemd-cryptenroll",
            "--unlock-key-file",
            &key_path,
            format!("--tpm2-device={}", self.device_arg())
        );
        if let Some(pcrs) = self.pcrs_arg() {
            enroll_cmd.add_arg(format!("--tpm2-pcrs={pcrs}"));
        }
        enroll_cmd.add_arg(&ctx.device);
        ParentEnv
            .run(enroll_cmd)
            .whatever("systemd-cryptenroll TPM2 enrollment failed")?;

        // Drop the throwaway slot — the TPM-bound slot enrolled above is
        // now the only path into the volume.
        ParentEnv
            .run(cmd_os!(
                "/usr/bin/env",
                "systemd-cryptenroll",
                "--wipe-slot=password",
                &ctx.device
            ))
            .whatever("systemd-cryptenroll --wipe-slot=password failed")?;

        Ok(())
    }

    fn mount(&self, ctx: &DriverContext) -> SystemResult<()> {
        ensure_dm_module();
        let mapper = mapper_device(self.mapper_name());
        if !mapper.exists() {
            cryptsetup_open_token_only(&ctx.device, self.mapper_name())?;
        }
        fsck_best_effort(&mapper);
        mount_noatime(&mapper, &ctx.mount_point)
    }

    fn wipe(&self, ctx: &DriverContext) -> SystemResult<()> {
        ensure_dm_module();
        cryptsetup_erase(&ctx.device)?;
        self.format(ctx)
    }
}

/// Compatibility wrapper for the legacy `mount-script` field. Bootstrap
/// formats as plain Ext4; the script handles only the per-boot mount.
pub struct LegacyMountScriptDriver {
    script: String,
    plaintext: PlaintextExt4Driver,
}

impl LegacyMountScriptDriver {
    pub fn new(script: String) -> Self {
        Self {
            script,
            plaintext: PlaintextExt4Driver::default(),
        }
    }
}

impl DataPartitionDriver for LegacyMountScriptDriver {
    fn format(&self, ctx: &DriverContext) -> SystemResult<()> {
        self.plaintext.format(ctx)
    }

    fn mount(&self, ctx: &DriverContext) -> SystemResult<()> {
        let mut cmd = cmd_os!(&self.script, &ctx.mount_point);
        cmd.add_arg(&ctx.device);
        ParentEnv
            .run(cmd)
            .whatever("legacy `mount-script` failed")?;
        Ok(())
    }

    fn wipe(&self, ctx: &DriverContext) -> SystemResult<()> {
        self.plaintext.wipe(ctx)
    }
}

/// Driver implemented by external user-supplied scripts.
pub struct CustomDriver {
    config: CustomDataPartitionDriverConfig,
}

impl CustomDriver {
    pub fn new(config: CustomDataPartitionDriverConfig) -> Self {
        Self { config }
    }

    fn run_script(
        &self,
        script: &str,
        ctx: &DriverContext,
        kind: &'static str,
    ) -> SystemResult<()> {
        let cmd = cmd_os!(script, &ctx.device, &ctx.mount_point)
            .with_var("RUGIX_DATA_DEVICE", ctx.device.as_os_str())
            .with_var("RUGIX_DATA_MOUNT_POINT", ctx.mount_point.as_os_str());
        ParentEnv
            .run(cmd)
            .whatever("custom data partition driver script failed")
            .field("phase", kind)?;
        Ok(())
    }
}

impl DataPartitionDriver for CustomDriver {
    fn format(&self, ctx: &DriverContext) -> SystemResult<()> {
        match &self.config.format_script {
            Some(script) => self.run_script(script, ctx, "format"),
            None => Ok(()),
        }
    }

    fn mount(&self, ctx: &DriverContext) -> SystemResult<()> {
        self.run_script(&self.config.mount_script, ctx, "mount")
    }

    fn wipe(&self, ctx: &DriverContext) -> SystemResult<()> {
        match &self.config.wipe_script {
            Some(script) => self.run_script(script, ctx, "wipe"),
            None => Err(reportify::whatever!(
                "custom data partition driver has no `wipe-script`; cannot perform `data wipe`"
            )),
        }
    }
}

fn mapper_device(name: &str) -> PathBuf {
    Path::new("/dev/mapper").join(name)
}

fn require_passphrase(path: &Path) -> SystemResult<()> {
    if path.exists() {
        Ok(())
    } else {
        Err(reportify::whatever!(
            "passphrase file {path:?} not found for LUKS2 data partition"
        ))
    }
}

/// Load `dm_mod` if it isn't already, and create `/dev/mapper/control`.
///
/// Pre-init runs before systemd/udev — without this, every cryptsetup
/// invocation fails with an opaque "command failed" before producing
/// useful diagnostics. Best-effort: if the kernel already has dm built-in
/// or modprobe fails, cryptsetup will surface the real error itself.
fn ensure_dm_module() {
    if Path::new("/dev/mapper/control").exists() {
        return;
    }
    if let Err(error) = run!(["/usr/bin/env", "modprobe", "dm_mod"]) {
        warn!("modprobe dm_mod failed (will let cryptsetup retry): {error}");
    }
}

fn luks2_format_with_keyfile(device: &Path, key: &Path) -> SystemResult<()> {
    let cmd = cmd_os!(
        "/usr/bin/env",
        "cryptsetup",
        "luksFormat",
        "--type",
        "luks2",
        "--batch-mode",
        "--key-file",
        key,
        device
    )
    .with_var("DM_DISABLE_UDEV", "1");
    ParentEnv
        .run(cmd)
        .whatever("cryptsetup luksFormat failed")?;
    Ok(())
}

/// `cryptsetup` waits for udev to populate `/dev/mapper/<name>` by default;
/// pre-init runs before udevd so we set `DM_DISABLE_UDEV=1` and create
/// the node ourselves with `dmsetup mknodes`.
fn cryptsetup_open_with_keyfile(device: &Path, key: &Path, mapper: &str) -> SystemResult<()> {
    let cmd = cmd_os!(
        "/usr/bin/env",
        "cryptsetup",
        "open",
        "--type",
        "luks2",
        "--batch-mode",
        "--key-file",
        key,
        device,
        mapper
    )
    .with_var("DM_DISABLE_UDEV", "1");
    ParentEnv.run(cmd).whatever("cryptsetup open failed")?;
    dmsetup_mknodes()
}

fn cryptsetup_open_token_only(device: &Path, mapper: &str) -> SystemResult<()> {
    let cmd = cmd_os!(
        "/usr/bin/env",
        "cryptsetup",
        "open",
        "--token-only",
        "--batch-mode",
        device,
        mapper
    )
    .with_var("DM_DISABLE_UDEV", "1");
    ParentEnv
        .run(cmd)
        .whatever("cryptsetup open --token-only failed")?;
    dmsetup_mknodes()
}

fn cryptsetup_close(mapper: &str) -> SystemResult<()> {
    let cmd =
        cmd_os!("/usr/bin/env", "cryptsetup", "close", mapper).with_var("DM_DISABLE_UDEV", "1");
    ParentEnv.run(cmd).whatever("cryptsetup close failed")?;
    Ok(())
}

fn cryptsetup_erase(device: &Path) -> SystemResult<()> {
    let cmd = cmd_os!(
        "/usr/bin/env",
        "cryptsetup",
        "erase",
        "--batch-mode",
        device
    )
    .with_var("DM_DISABLE_UDEV", "1");
    ParentEnv.run(cmd).whatever("cryptsetup erase failed")?;
    Ok(())
}

fn dmsetup_mknodes() -> SystemResult<()> {
    run!(["/usr/bin/env", "dmsetup", "mknodes"])
        .whatever("dmsetup mknodes failed after cryptsetup open")?;
    Ok(())
}

fn fsck_best_effort(device: &Path) {
    if let Err(error) = run!(["/usr/bin/env", "fsck", "-p", device]) {
        warn!("fsck reported: {error}");
    }
}

fn mount_noatime(device: &Path, mount_point: &Path) -> SystemResult<()> {
    run!([
        "/usr/bin/env",
        "mount",
        "-o",
        "noatime",
        device,
        mount_point
    ])
    .whatever("unable to mount data partition")?;
    Ok(())
}

/// Read entropy bytes for one-shot use as a throwaway secret.
///
/// Pre-init runs before systemd seeds the kernel CSPRNG, so the
/// `getrandom(2)` syscall blocks indefinitely. We bypass the pool by
/// reading directly from `/dev/hwrng` (with `/dev/urandom` as fallback).
/// The bytes returned here only ever live as a transient passphrase that
/// is wiped before this process exits, so degraded entropy is acceptable.
fn read_throwaway_entropy(len: usize) -> SystemResult<Vec<u8>> {
    use std::io::Read;
    let mut buf = vec![0u8; len];
    for source in ["/dev/hwrng", "/dev/urandom"] {
        if let Ok(mut f) = std::fs::File::open(source) {
            if f.read_exact(&mut buf).is_ok() {
                return Ok(buf);
            }
        }
    }
    Err(reportify::whatever!(
        "unable to read entropy from /dev/hwrng or /dev/urandom"
    ))
}
