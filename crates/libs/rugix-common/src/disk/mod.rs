//! Utilities for working with disks, disk images, and disk streams.

use std::path::Path;

use rand::RngExt;
use reportify::bail;
use reportify::Report;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use self::gpt::Guid;
use self::gpt::GUID_STRING_LENGTH;
use crate::partitions::DiskError;
use crate::utils::ascii_numbers::parse_ascii_decimal_digit;
use crate::utils::ascii_numbers::Case;
use crate::utils::units::NumBytes;
use crate::utils::units::Quantity;
use crate::utils::units::Unit;

pub mod blkdev;
pub mod blkpg;
pub mod gpt;
pub mod mbr;
pub mod repart;
pub mod stream;

mod sfdisk;

/// Default size of blocks.
pub const DEFAULT_BLOCK_SIZE: u64 = 512;

/// Unique identifier of a disk.
///
/// The disk ID also includes the type of the partition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiskId {
    /// Unique identifier of an MBR disk.
    Mbr(mbr::MbrId),
    /// Unique identifier of a GPT disk.
    Gpt(gpt::Guid),
}

impl DiskId {
    pub fn random_mbr() -> Self {
        Self::Mbr(mbr::MbrId::new(rand::rng().random()))
    }

    pub fn random_gpt() -> Self {
        Self::Gpt(gpt::Guid::from_random_bytes(rand::rng().random()))
    }
}

impl std::fmt::Display for DiskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiskId::Mbr(id) => id.fmt(f),
            DiskId::Gpt(id) => id.fmt(f),
        }
    }
}

/// Partition table.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PartitionTable {
    /// Disk ID.
    pub disk_id: DiskId,
    /// Size of the disk.
    pub disk_size: NumBlocks,
    /// Block size of the disk.
    pub block_size: NumBytes,
    /// First usable block recorded in a GPT header.
    pub gpt_first_usable: Option<NumBlocks>,
    /// Number of entries in a non-default GPT partition-entry array.
    pub gpt_table_length: Option<u64>,
    /// Partitions of the disk.
    pub partitions: Vec<Partition>,
}

impl PartitionTable {
    /// Create an empty partition table with the given ID.
    pub fn new(id: DiskId, size: NumBlocks) -> Self {
        Self {
            disk_id: id,
            disk_size: size,
            block_size: NumBytes::from_raw(DEFAULT_BLOCK_SIZE),
            gpt_first_usable: None,
            gpt_table_length: None,
            partitions: Vec::new(),
        }
    }

    /// Read the partition table from a device or image.
    pub fn read(dev: impl AsRef<Path>) -> Result<Self, Report<DiskError>> {
        sfdisk::sfdisk_read(dev.as_ref())
    }

    /// The size of the disk in bytes.
    pub fn size(&self) -> NumBytes {
        NumBytes::from_raw(self.block_size.into_raw() * self.disk_size.into_raw())
    }

    /// The type of the partition table.
    pub fn ty(&self) -> PartitionTableType {
        match self.disk_id {
            DiskId::Mbr(_) => PartitionTableType::Mbr,
            DiskId::Gpt(_) => PartitionTableType::Gpt,
        }
    }

    /// Returns whether the table is a GUID partition table.
    pub fn is_gpt(&self) -> bool {
        matches!(self.disk_id, DiskId::Gpt(_))
    }

    /// Returns whether the table is an MBR partition table.
    pub fn is_mbr(&self) -> bool {
        matches!(self.disk_id, DiskId::Mbr(_))
    }

    /// Convert blocks to bytes.
    pub fn blocks_to_bytes(&self, blocks: NumBlocks) -> NumBytes {
        NumBytes::from_raw(blocks.into_raw() * self.block_size.into_raw())
    }

    /// Convert bytes to blocks.
    pub fn bytes_to_blocks(&self, bytes: NumBytes) -> NumBlocks {
        NumBlocks::from_raw(bytes.into_raw().div_ceil(self.block_size.into_raw()))
    }

    /// The first usable block.
    pub fn first_usable_block(&self) -> NumBlocks {
        match self.disk_id {
            DiskId::Mbr(_) => gpt::GPT_TABLE_BLOCKS + NumBlocks::ONE,
            DiskId::Gpt(_) => self
                .gpt_first_usable
                .unwrap_or(self.gpt_table_blocks() + NumBlocks::ONE),
        }
    }

    /// The last usable block.
    ///
    /// For GPT disks, this is derived from the current device size rather than
    /// the header's recorded end, which may be stale after an image is enlarged.
    pub fn last_usable_block(&self) -> NumBlocks {
        match self.disk_id {
            DiskId::Mbr(_) => {
                (self.disk_size - NumBlocks::ONE).min(NumBlocks::from_raw(u32::MAX.into()))
            }
            DiskId::Gpt(_) => self.disk_size - self.gpt_table_blocks() - NumBlocks::ONE,
        }
    }

    /// Number of blocks occupied by one GPT header and its partition-entry array.
    fn gpt_table_blocks(&self) -> NumBlocks {
        let table_length = self
            .gpt_table_length
            .unwrap_or(gpt::GPT_DEFAULT_TABLE_LENGTH);
        let table_bytes = table_length.saturating_mul(gpt::GPT_PARTITION_ENTRY_SIZE);
        let block_size = self.block_size.into_raw();
        if block_size == 0 {
            return gpt::GPT_TABLE_BLOCKS;
        }
        NumBlocks::from_raw(table_bytes.div_ceil(block_size).saturating_add(1))
    }

    /// Write the partition table to a device or image.
    pub fn write(&self, dev: impl AsRef<Path>) -> Result<(), Report<DiskError>> {
        // Make sure that we never write an invalid partition table.
        self.validate()?;
        sfdisk::sfdisk_write(self, dev.as_ref())
    }

    /// Validate the partition table.
    ///
    /// This function checks the following criteria:
    /// - Partitions are sorted based on their number and starting block.
    /// - Partitions do not overlap except for the extended MBR partition.
    /// - Partitions are within the usable range of the disk.
    pub fn validate(&self) -> Result<(), Report<DiskError>> {
        let mut last_usable = self.last_usable_block();
        let mut next_free = self.first_usable_block();
        let mut next_number = 1;
        let mut in_extended = false;
        for partition in &self.partitions {
            if in_extended {
                // We need space for the EBR.
                next_free += NumBlocks::ONE;
            }
            if partition.start < next_free {
                bail!(
                    "invalid starting block of partition ({} < {next_free})",
                    partition.start
                )
            }
            if partition.number < next_number {
                bail!(
                    "invalid partition number ({} < {next_number})",
                    partition.number
                );
            }
            if in_extended && partition.number != next_number {
                // Extended partitions must be consecutively numbered.
                bail!(
                    "invalid number of extended partition ({} != {next_number})",
                    partition.number
                )
            }
            if partition.ty.is_extended() {
                if partition.number > 4 {
                    bail!(
                        "invalid number of extended partition ({})",
                        partition.number
                    )
                }
                next_number = 5;
                next_free = partition.start + NumBlocks::from_raw(63);
                last_usable = partition.start + partition.size;
                in_extended = true;
            } else {
                next_number = partition.number + 1;
                next_free = partition.start + partition.size;
            }
        }
        if next_free - NumBlocks::from_raw(1) > last_usable {
            bail!("partitions extend beyond usable range ({next_free} > {last_usable})");
        }
        Ok(())
    }
}

/// Partition of a disk.
#[derive(Clone, Debug)]
pub struct Partition {
    /// Number of the partition.
    pub number: u8,
    /// Start sector of the partition.
    pub start: NumBlocks,
    /// Size of the partition.
    pub size: NumBlocks,
    /// Type of the partition.
    pub ty: PartitionType,
    /// Optional GPT name of the partition.
    pub name: Option<String>,
    /// Optional unique identifier of the partition.
    pub gpt_id: Option<gpt::Guid>,
    /// Optional GPT partition attributes.
    pub gpt_attrs: Option<String>,
    /// Whether the partition has its bootable flag set.
    pub bootable: bool,
}

impl Partition {
    /// The end of the partition.
    pub fn end(&self) -> NumBlocks {
        self.start + self.size
    }
}

/// Partition type.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartitionType {
    /// MBR partition type.
    Mbr(u8),
    /// GPT partition type.
    Gpt(gpt::Guid),
}

impl PartitionType {
    pub fn table_type(&self) -> PartitionTableType {
        match self {
            PartitionType::Mbr(_) => PartitionTableType::Mbr,
            PartitionType::Gpt(_) => PartitionTableType::Gpt,
        }
    }

    pub fn is_free(&self) -> bool {
        match self {
            PartitionType::Mbr(ty) => *ty == 0x00,
            PartitionType::Gpt(guid) => guid.is_zero(),
        }
    }

    pub fn is_extended(&self) -> bool {
        match self {
            PartitionType::Mbr(id) => matches!(id, 0x05 | 0x0F),
            PartitionType::Gpt(_) => false,
        }
    }
}

impl<'de> serde::Deserialize<'de> for PartitionType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        if string.len() == GUID_STRING_LENGTH {
            Ok(Self::Gpt(Guid::from_hex_str(&string).map_err(|_| {
                <D::Error as serde::de::Error>::invalid_value(
                    serde::de::Unexpected::Str(&string),
                    &"a partition type",
                )
            })?))
        } else {
            Ok(Self::Mbr(u8::from_str_radix(&string, 16).map_err(
                |_| {
                    <D::Error as serde::de::Error>::invalid_value(
                        serde::de::Unexpected::Str(&string),
                        &"a partition type",
                    )
                },
            )?))
        }
    }
}

impl Serialize for PartitionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            PartitionType::Mbr(part) => serializer.serialize_str(&format!("{part:02x}")),
            PartitionType::Gpt(guid) => serializer.serialize_str(&guid.to_hex_str(Case::Upper)),
        }
    }
}

impl std::fmt::Display for PartitionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PartitionType::Mbr(id) => f.write_fmt(format_args!("{:02x}", *id)),
            PartitionType::Gpt(id) => id.fmt(f),
        }
    }
}

impl std::fmt::Debug for PartitionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mbr(id) => f.write_fmt(format_args!("Mbr(0x{id:02x})")),
            Self::Gpt(id) => f.write_fmt(format_args!("Gpt({id})")),
        }
    }
}

/// Number of blocks unit.
pub struct NumBlocksUnit(());

impl Unit for NumBlocksUnit {
    fn name() -> &'static str {
        "NumBlocks"
    }

    fn symbol() -> &'static str {
        "blocks"
    }
}

/// Number of blocks.
pub type NumBlocks = Quantity<u64, NumBlocksUnit>;

impl NumBlocks {
    /// One block.
    pub const ONE: NumBlocks = NumBlocks::from_raw(1);

    /// Align the block number rounding downward.
    #[must_use]
    pub fn floor_align_to(self, align: Self) -> Self {
        Self::from_raw(align.into_raw() * (self / align))
    }

    /// Align the block number rounding upward.
    #[must_use]
    pub fn ceil_align_to(self, align: Self) -> Self {
        Self::from_raw(align.into_raw() * (self.into_raw().div_ceil(align.into_raw())))
    }
}

/// Convert a size string to bytes.
pub const fn parse_size(size: &str) -> Result<NumBytes, InvalidSize> {
    let size = size.as_bytes();
    if size.is_empty() {
        return Ok(NumBytes::from_raw(0));
    }
    let mut last = size.len() - 1;
    let factor: u64 = match size[last] {
        b'K' => 1 << 10,
        b'M' => 1 << 20,
        b'G' => 1 << 30,
        b'T' => 1 << 40,
        _ => 1,
    };
    if factor != 1 {
        last -= 1;
    }
    while last > 0 && size[last] == b' ' {
        last -= 1;
    }
    let mut pos = 0;
    let mut value = 0;
    while pos <= last {
        if size[pos] != b'_' {
            value *= 10;
            value += match parse_ascii_decimal_digit(size[pos], pos) {
                Ok(digit) => digit as u64,
                Err(_) => return Err(InvalidSize { pos }),
            };
        }
        pos += 1;
    }
    Ok(NumBytes::from_raw(value * factor))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PartitionTableType {
    Gpt,
    #[default]
    Mbr,
}

impl PartitionTableType {
    pub fn is_mbr(self) -> bool {
        matches!(self, Self::Mbr)
    }

    pub fn is_gpt(self) -> bool {
        matches!(self, Self::Gpt)
    }
}

impl std::fmt::Display for PartitionTableType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PartitionTableType::Gpt => f.write_str("gpt"),
            PartitionTableType::Mbr => f.write_str("mbr"),
        }
    }
}

/// Error indicating an invalid size.
#[derive(Debug, Clone, Error)]
#[error("invalid character at position {pos}")]
pub struct InvalidSize {
    pos: usize,
}

impl<'de> serde::Deserialize<'de> for NumBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        parse_size(&string).map_err(|_| {
            <D::Error as serde::de::Error>::invalid_value(
                serde::de::Unexpected::Str(&string),
                &"a size",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_parse_size() {
        assert_eq!(
            parse_size("512M").unwrap(),
            NumBytes::from_raw(512 * (1 << 20))
        );
    }

    #[test]
    pub fn test_block_alignment() {
        assert_eq!(
            NumBlocks::from_raw(2048).ceil_align_to(NumBlocks::from_raw(2048)),
            NumBlocks::from_raw(2048)
        );
        assert_eq!(
            NumBlocks::from_raw(2048).floor_align_to(NumBlocks::from_raw(2048)),
            NumBlocks::from_raw(2048)
        );
        assert_eq!(
            NumBlocks::from_raw(2049).ceil_align_to(NumBlocks::from_raw(2048)),
            NumBlocks::from_raw(4096)
        );
        assert_eq!(
            NumBlocks::from_raw(2049).floor_align_to(NumBlocks::from_raw(2048)),
            NumBlocks::from_raw(2048)
        )
    }

    #[test]
    fn gpt_last_usable_tracks_disk_size() {
        let mut table = PartitionTable::new(
            DiskId::Gpt(Guid::from_random_bytes([0; 16])),
            NumBlocks::from_raw(8192),
        );
        table.block_size = NumBytes::from_raw(4096);
        table.gpt_table_length = Some(256);

        assert_eq!(table.last_usable_block(), NumBlocks::from_raw(8182));

        table.disk_size = NumBlocks::from_raw(16384);
        assert_eq!(table.last_usable_block(), NumBlocks::from_raw(16374));
    }
}
