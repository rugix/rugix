//! Utilities for repartitioning disks.

use reportify::bail;
use reportify::Report;
use serde::Deserialize;

use super::parse_size;
use super::PartitionTable;
use super::PartitionTableType;
use crate::disk::gpt::gpt_types;
use crate::disk::mbr::mbr_types;
use crate::disk::NumBlocks;
use crate::disk::Partition;
use crate::disk::PartitionType;
use crate::partitions::DiskError;
use crate::utils::units::NumBytes;

/// Partition schema.
#[derive(Debug, Clone, Deserialize)]
pub struct PartitionSchema {
    #[serde(rename = "type")]
    pub ty: PartitionTableType,
    pub partitions: Vec<SchemaPartition>,
}

/// Partition of a schema.
#[derive(Debug, Clone, Deserialize)]
pub struct SchemaPartition {
    pub number: Option<u8>,
    pub name: Option<String>,
    pub size: Option<NumBytes>,
    #[serde(rename = "type")]
    pub ty: Option<PartitionType>,
}

/// Repartition the given table based on the provided schema.
///
/// Currently, the algorithm is very simple and matches up partitions based on their
/// index in the schema and partition table.
pub fn repart(
    old_table: &PartitionTable,
    schema: &PartitionSchema,
) -> Result<Option<PartitionTable>, Report<DiskError>> {
    if old_table.ty() != schema.ty {
        bail!(
            "partition table types do not match ({} != {})",
            old_table.ty(),
            schema.ty
        );
    }
    let default_partition_ty = match schema.ty {
        PartitionTableType::Gpt => gpt_types::LINUX,
        PartitionTableType::Mbr => mbr_types::LINUX,
    };
    let align = NumBlocks::from_raw(2048);
    let mut new_table = old_table.clone();
    let mut next_start = old_table.first_usable_block().ceil_align_to(align);
    let mut last_usable = old_table.last_usable_block();
    let mut in_extended = false;
    let mut has_changed = false;
    for (idx, partition) in schema.partitions.iter().enumerate() {
        eprintln!(
            "Partition: {}, Next Start: {next_start}, Last Useable: {last_usable}",
            idx + 1
        );
        if in_extended {
            // We need to leave some space for the EBR.
            next_start += NumBlocks::from_raw(63);
        }
        let mut start = next_start;
        let mut size = partition.size.map(|size| old_table.bytes_to_blocks(size));
        let old = old_table.partitions.get(idx);
        let old_next = old_table.partitions.get(idx + 1);
        let ty = partition.ty.unwrap_or(default_partition_ty);
        if let Some(old) = old {
            start = old.start;
            if old.ty != ty {
                bail!(
                    "partition types of partition {} do not match ({} != {})",
                    idx + 1,
                    old.ty,
                    ty
                )
            }
            size = size.map(|size| size.max(old.size));
        } else {
            // If we are not using the old offset, align partition.
            start = start.ceil_align_to(align);
        }
        // Compute available space.
        let available = if ty.is_extended() {
            // We need to add one block as the last block is still usable.
            last_usable - start + NumBlocks::ONE
        } else if let Some(old_next) = old_next {
            if in_extended {
                // We need to account for the EBR.
                (old_next.start - start - NumBlocks::from_raw(63)).floor_align_to(align)
            } else {
                old_next.start - start
            }
        } else {
            if start >= last_usable {
                bail!("insufficient space, cannot add partition {}", idx + 1);
            }
            // We need to add one block as the last block is still usable.
            last_usable - start + NumBlocks::ONE
        };
        let mut size = size.unwrap_or(available).min(available);
        eprintln!(
            "  Start: {start}, End: {}, Available: {available}, Size: {size}",
            start + size - NumBlocks::ONE,
        );
        if let Some(new) = new_table.partitions.get_mut(idx) {
            size = size.max(new.size);
            if new.size != size {
                has_changed = true;
            }
            new.size = size;
            if schema.ty == PartitionTableType::Gpt {
                if let Some(name) = &partition.name {
                    if new.name.as_ref() != Some(name) {
                        has_changed = true;
                        new.name = Some(name.clone());
                    }
                }
            }
        } else {
            has_changed = true;
            new_table.partitions.push(Partition {
                number: (idx + 1) as u8,
                start,
                size,
                ty,
                name: if schema.ty == PartitionTableType::Gpt {
                    partition.name.clone()
                } else {
                    None
                },
                gpt_id: None,
                gpt_attrs: None,
                bootable: false,
            })
        }
        if ty.is_extended() {
            last_usable = start + size - NumBlocks::ONE;
            in_extended = true;
            next_start = start;
        } else {
            next_start = start + size;
        }
    }
    if has_changed {
        check_new_table(old_table, &new_table)?;
        Ok(Some(new_table))
    } else {
        Ok(None)
    }
}

/// Perform a sanity check of the new partition table.
///
/// The conditions checked here should always be ensured by the repartitioning algorithm.
/// Nevertheless, we check it them here explicitly to catch bugs that otherwise would mess
/// up the partition table leading to potential data loss.
///
/// Arguably the checks here should panic as they correspond to internal invariants. We
/// return errors instead such that they are handled gracefully.
fn check_new_table(
    old_table: &PartitionTable,
    new_table: &PartitionTable,
) -> Result<(), Report<DiskError>> {
    // We first validate the new table ensuring that no partitions overlap.
    new_table.validate()?;
    if old_table.disk_id != new_table.disk_id {
        bail!("BUG: Partition table id must not be changed.");
    }
    if old_table.ty() != new_table.ty() {
        bail!("BUG: Types of old and new partition table must be the same.");
    }
    if old_table.partitions.len() > new_table.partitions.len() {
        bail!("BUG: Partitions must not be deleted.");
    }
    for (old, new) in old_table.partitions.iter().zip(new_table.partitions.iter()) {
        if old.ty != new.ty {
            bail!("BUG: Types of old and new partition must be the same.");
        }
        if old.start != new.start {
            bail!("BUG: Old and new partition must start at the same offset.");
        }
        if old.size > new.size {
            bail!("BUG: New partition must not be smaller than old partition.");
        }
        if old.gpt_id != new.gpt_id {
            bail!("BUG: GPT UUID of partition must not be changed.");
        }
        if old.gpt_attrs != new.gpt_attrs {
            bail!("BUG: GPT attributes of partition must not be changed.");
        }
        if old.bootable != new.bootable {
            bail!("BUG: Bootable flag of partition must not be changed.");
        }
    }
    Ok(())
}

pub fn generic_mbr_partition_schema(system_size: NumBytes) -> PartitionSchema {
    PartitionSchema {
        ty: PartitionTableType::Mbr,
        partitions: vec![
            SchemaPartition {
                number: None,
                name: None,
                size: Some(parse_size("256M").unwrap()),
                ty: Some(mbr_types::FAT32_LBA),
            },
            SchemaPartition {
                number: None,
                name: None,
                size: Some(parse_size("128M").unwrap()),
                ty: Some(mbr_types::FAT32_LBA),
            },
            SchemaPartition {
                number: None,
                name: None,
                size: Some(parse_size("128M").unwrap()),
                ty: Some(mbr_types::FAT32_LBA),
            },
            SchemaPartition {
                number: None,
                name: None,
                size: None,
                ty: Some(mbr_types::EXTENDED),
            },
            SchemaPartition {
                number: None,
                name: None,
                size: Some(system_size),
                ty: Some(mbr_types::LINUX),
            },
            SchemaPartition {
                number: None,
                name: None,
                size: Some(system_size),
                ty: Some(mbr_types::LINUX),
            },
            SchemaPartition {
                number: None,
                name: None,
                size: None,
                ty: Some(mbr_types::LINUX),
            },
        ],
    }
}

pub fn generic_efi_partition_schema(system_size: NumBytes) -> PartitionSchema {
    PartitionSchema {
        ty: PartitionTableType::Gpt,
        partitions: vec![
            SchemaPartition {
                number: None,
                name: None,
                size: Some(parse_size("256M").unwrap()),
                ty: Some(gpt_types::EFI),
            },
            SchemaPartition {
                number: None,
                name: None,
                size: Some(parse_size("256M").unwrap()),
                ty: Some(gpt_types::LINUX),
            },
            SchemaPartition {
                number: None,
                name: None,
                size: Some(parse_size("256M").unwrap()),
                ty: Some(gpt_types::LINUX),
            },
            SchemaPartition {
                number: None,
                name: None,
                size: Some(system_size),
                ty: Some(gpt_types::LINUX),
            },
            SchemaPartition {
                number: None,
                name: None,
                size: Some(system_size),
                ty: Some(gpt_types::LINUX),
            },
            SchemaPartition {
                number: None,
                name: None,
                size: None,
                ty: Some(gpt_types::LINUX),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::generic_efi_partition_schema;
    use super::generic_mbr_partition_schema;
    use super::repart;
    use crate::disk::gpt::gpt_types;
    use crate::disk::gpt::Guid;
    use crate::disk::mbr::mbr_types;
    use crate::disk::mbr::MbrId;
    use crate::disk::parse_size;
    use crate::disk::DiskId;
    use crate::disk::NumBlocks;
    use crate::disk::Partition;
    use crate::disk::PartitionTable;

    #[test]
    fn test_repart_mbr() {
        let mut old_table = PartitionTable::new(
            DiskId::Mbr(MbrId::new(0x123456)),
            NumBlocks::from_raw(6 * 1024 * 1024 * 1024),
        );
        for (number, (start, size)) in [(2048, 524288), (526336, 262144), (788480, 26144)]
            .into_iter()
            .enumerate()
        {
            old_table.partitions.push(Partition {
                number: (1 + number).try_into().unwrap(),
                start: start.into(),
                size: size.into(),
                ty: mbr_types::FAT32_LBA,
                name: None,
                gpt_id: None,
                gpt_attrs: None,
                bootable: false,
            })
        }
        old_table.partitions.push(Partition {
            number: 4,
            start: 1050624.into(),
            size: old_table.disk_size - NumBlocks::from_raw(1050624),
            ty: mbr_types::EXTENDED,
            name: None,
            gpt_id: None,
            gpt_attrs: None,
            bootable: false,
        });
        old_table.partitions.push(Partition {
            number: 5,
            start: 1052672.into(),
            size: 2016836.into(),
            ty: mbr_types::LINUX,
            name: None,
            gpt_id: None,
            gpt_attrs: None,
            bootable: false,
        });
        old_table.validate().unwrap();
        repart(
            &old_table,
            &generic_mbr_partition_schema(parse_size("4G").unwrap()),
        )
        .unwrap();
    }

    #[test]
    fn test_repart_gpt() {
        let mut old_table = PartitionTable::new(
            DiskId::Gpt(Guid::from_random_bytes([0x42; 16])),
            NumBlocks::from_raw(6 * 1024 * 1024 * 1024),
        );
        for (number, (start, size)) in [(2048, 524288), (526336, 262144), (788480, 26144)]
            .into_iter()
            .enumerate()
        {
            old_table.partitions.push(Partition {
                number: (1 + number).try_into().unwrap(),
                start: start.into(),
                size: size.into(),
                ty: if number == 0 {
                    gpt_types::EFI
                } else {
                    gpt_types::LINUX
                },
                name: None,
                gpt_id: None,
                gpt_attrs: None,
                bootable: false,
            })
        }
        old_table.partitions.push(Partition {
            number: 4,
            start: 1050624.into(),
            size: 2016836.into(),
            ty: gpt_types::LINUX,
            name: None,
            gpt_id: None,
            gpt_attrs: None,
            bootable: false,
        });
        old_table.partitions[0].gpt_attrs = Some("GUID:63".to_owned());
        old_table.partitions[0].bootable = true;
        old_table.validate().unwrap();
        let mut schema = generic_efi_partition_schema(parse_size("4G").unwrap());
        schema.partitions[0].name = Some("efi-system".to_owned());
        schema.partitions[4].name = Some("system-b".to_owned());
        let new_table = repart(&old_table, &schema).unwrap().unwrap();
        assert_eq!(new_table.partitions[0].name.as_deref(), Some("efi-system"));
        assert_eq!(new_table.partitions[4].name.as_deref(), Some("system-b"));
        assert_eq!(
            new_table.partitions[0].gpt_attrs.as_deref(),
            Some("GUID:63")
        );
        assert!(new_table.partitions[0].bootable);
    }
}
