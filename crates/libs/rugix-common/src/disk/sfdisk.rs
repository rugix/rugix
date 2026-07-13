use std::fmt::Write;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::str::FromStr;

use reportify::whatever;
use reportify::Report;
use reportify::ResultExt;
use serde::Deserialize;
use xscript::read_str;
use xscript::run;
use xscript::Run;

use super::blkdev::BlockDevice;
use super::gpt::Guid;
use super::mbr;
use super::DiskId;
use super::NumBlocks;
use super::Partition;
use super::PartitionTable;
use super::PartitionType;
use crate::partitions::DiskError;
use crate::utils::units::NumBytes;

pub(crate) fn sfdisk_read(dev: &Path) -> Result<PartitionTable, Report<DiskError>> {
    let json_table = serde_json::from_str::<SfdiskJson>(
        &read_str!(["sfdisk", "--dump", "--json", dev])
            .whatever("unable to read partition table")?,
    )
    .whatever("unable to parse partition table")?
    .partition_table;
    let metadata = dev.metadata().whatever("unable to read device metadata")?;
    let size = if metadata.file_type().is_block_device() {
        NumBlocks::from_raw(
            BlockDevice::new(dev)
                .whatever("device is not a block device")?
                .size()
                .whatever("unable to read size of block device")?
                / json_table.sector_size,
        )
    } else {
        NumBlocks::from_raw(metadata.size() / json_table.sector_size)
    };
    let id = match json_table.label {
        SfdiskJsonLabel::Dos => DiskId::Mbr(
            json_table
                .id
                .get(2..)
                .and_then(|id| u32::from_str_radix(id, 16).ok().map(mbr::MbrId::new))
                .ok_or_else(|| {
                    whatever!(
                        "invalid MBR disk id {:?} returned by `sfdisk`",
                        json_table.id,
                    )
                })?,
        ),
        SfdiskJsonLabel::Gpt => DiskId::Gpt(json_table.id.parse().map_err(|_| {
            whatever!(
                "invalid GPT disk id {:?} returned from `sfdisk`",
                json_table.id
            )
        })?),
    };
    let gpt_table_length = json_table
        .table_length
        .as_deref()
        .map(|length| {
            length.parse().map_err(|_| {
                whatever!(
                    "invalid GPT table length {:?} returned from `sfdisk`",
                    length
                )
            })
        })
        .transpose()?;
    let mut partitions = json_table
        .partitions
        .into_iter()
        .map(|partition| {
            let number = partition
                .node
                .rsplit_once(|c: char| !c.is_ascii_digit())
                .and_then(|(_, suffix)| u8::from_str(suffix).ok())
                .ok_or_else(|| {
                    whatever!(
                        "invalid partition name {:?} returned from `sfdisk`",
                        partition.node
                    )
                })?;
            let ty = match id {
                DiskId::Mbr(_) => PartitionType::Mbr(
                    u8::from_str_radix(&partition.ty, 16)
                        .whatever("unable to parse partition type from `sfdisk` output")?,
                ),
                DiskId::Gpt(_) => {
                    PartitionType::Gpt(Guid::from_hex_str(&partition.ty).map_err(|_| {
                        whatever!(
                            "invalid GPT partition type {:?} returned from `sfdisk`",
                            partition.ty
                        )
                    })?)
                }
            };
            let gpt_id = partition
                .uuid
                .map(|guid| {
                    Guid::from_hex_str(&guid).map_err(|_| {
                        whatever!("invalid partition GUID {:?} returned from `sfdisk`", guid)
                    })
                })
                .transpose()?;
            Ok(Partition {
                number,
                start: NumBlocks::from_raw(partition.start),
                size: NumBlocks::from_raw(partition.size),
                ty,
                name: partition.name,
                gpt_id,
                gpt_attrs: partition.attrs,
                bootable: partition.bootable,
            })
        })
        .collect::<Result<Vec<_>, Report<DiskError>>>()?;
    partitions.sort_by_key(|x| x.start);
    Ok(PartitionTable {
        disk_id: id,
        disk_size: size,
        block_size: NumBytes::from_raw(json_table.sector_size),
        gpt_first_usable: json_table.first_lba.map(NumBlocks::from_raw),
        gpt_last_usable: json_table.last_lba.map(NumBlocks::from_raw),
        gpt_table_length,
        partitions,
    })
}

pub(crate) fn sfdisk_write(table: &PartitionTable, dev: &Path) -> Result<(), Report<DiskError>> {
    let script = sfdisk_script(table);

    println!("{script}");

    run!(["sfdisk", "--no-reread", dev].with_stdin(script))
        .whatever("unable to write partition table")?;
    Ok(())
}

fn sfdisk_script(table: &PartitionTable) -> String {
    let mut script = String::new();
    match table.disk_id {
        DiskId::Mbr(_) => script.push_str("label: dos\n"),
        DiskId::Gpt(_) => script.push_str("label: gpt\n"),
    }
    writeln!(&mut script, "label-id: {}", table.disk_id).unwrap();
    script.push_str("unit: sectors\n");
    writeln!(&mut script, "sector-size: {}", table.block_size.into_raw()).unwrap();
    if table.is_gpt() {
        if let Some(first_usable) = table.gpt_first_usable {
            writeln!(&mut script, "first-lba: {}", first_usable.into_raw()).unwrap();
        }
        if let Some(last_usable) = table.gpt_last_usable {
            writeln!(&mut script, "last-lba: {}", last_usable.into_raw()).unwrap();
        }
        if let Some(table_length) = table.gpt_table_length {
            writeln!(&mut script, "table-length: {table_length}").unwrap();
        }
    }
    for partition in &table.partitions {
        write!(&mut script, "{}: ", partition.number).unwrap();
        write!(
            &mut script,
            "start={},size={},type={}",
            partition.start.into_raw(),
            partition.size.into_raw(),
            partition.ty
        )
        .unwrap();
        if let Some(gpt_id) = partition.gpt_id {
            write!(&mut script, ",uuid={}", gpt_id).unwrap();
        }
        if table.is_gpt() {
            if let Some(name) = &partition.name {
                script.push_str(",name=");
                write_sfdisk_quoted(&mut script, name);
            }
            if let Some(attrs) = &partition.gpt_attrs {
                script.push_str(",attrs=");
                write_sfdisk_quoted(&mut script, attrs);
            }
        }
        if partition.bootable {
            script.push_str(",bootable");
        }
        script.push('\n');
    }
    script
}

/// Write a string using the escaping used by util-linux's `sfdisk --dump`.
fn write_sfdisk_quoted(output: &mut String, value: &str) {
    output.push('"');
    for byte in value.bytes() {
        if matches!(byte, b'"' | b'\\' | b'`' | b'$') || !(b' '..=b'~').contains(&byte) {
            write!(output, "\\x{byte:02x}").unwrap();
        } else {
            output.push(char::from(byte));
        }
    }
    output.push('"');
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct SfdiskJson {
    #[serde(rename = "partitiontable")]
    partition_table: SfdiskJsonTable,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct SfdiskJsonTable {
    label: SfdiskJsonLabel,
    id: String,
    device: String,
    unit: String,
    #[serde(rename = "sectorsize")]
    sector_size: u64,
    #[serde(rename = "firstlba")]
    first_lba: Option<u64>,
    #[serde(rename = "lastlba")]
    last_lba: Option<u64>,
    #[serde(rename = "table-length")]
    table_length: Option<String>,
    // This field is missing if there are no partitions.
    #[serde(default)]
    partitions: Vec<SfdiskJsonPartition>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
enum SfdiskJsonLabel {
    Dos,
    Gpt,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SfdiskJsonPartition {
    node: String,
    start: u64,
    size: u64,
    #[serde(rename = "type")]
    ty: String,
    uuid: Option<String>,
    name: Option<String>,
    attrs: Option<String>,
    #[serde(default)]
    bootable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::gpt::gpt_types;
    use crate::disk::mbr::mbr_types;
    use crate::disk::mbr::MbrId;

    #[test]
    fn deserialize_partition_name() {
        let partition: SfdiskJsonPartition = serde_json::from_str(
            r#"{
                "node": "/dev/loop0p1",
                "start": 2048,
                "size": 4096,
                "type": "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                "uuid": "B921B045-1DF0-41C3-AF44-4C6F280D3FAE",
                "name": "boot-a",
                "attrs": "GUID:63",
                "bootable": true
            }"#,
        )
        .unwrap();

        assert_eq!(partition.name.as_deref(), Some("boot-a"));
        assert_eq!(partition.attrs.as_deref(), Some("GUID:63"));
        assert!(partition.bootable);
    }

    #[test]
    fn deserialize_gpt_geometry() {
        let json: SfdiskJson = serde_json::from_str(
            r#"{
                "partitiontable": {
                    "label": "gpt",
                    "id": "B921B045-1DF0-41C3-AF44-4C6F280D3FAE",
                    "device": "/dev/loop0",
                    "unit": "sectors",
                    "firstlba": 64,
                    "lastlba": 8127,
                    "table-length": "256",
                    "sectorsize": 4096
                }
            }"#,
        )
        .unwrap();

        let table = json.partition_table;
        assert_eq!(table.first_lba, Some(64));
        assert_eq!(table.last_lba, Some(8127));
        assert_eq!(table.table_length.as_deref(), Some("256"));
        assert_eq!(table.sector_size, 4096);
    }

    #[test]
    fn write_gpt_partition_name() {
        let mut table = PartitionTable::new(
            DiskId::Gpt(Guid::from_random_bytes([0; 16])),
            NumBlocks::from_raw(8192),
        );
        table.block_size = NumBytes::from_raw(4096);
        table.gpt_first_usable = Some(NumBlocks::from_raw(64));
        table.gpt_last_usable = Some(NumBlocks::from_raw(8127));
        table.gpt_table_length = Some(256);
        table.partitions.push(Partition {
            number: 1,
            start: NumBlocks::from_raw(2048),
            size: NumBlocks::from_raw(4096),
            ty: gpt_types::LINUX,
            name: Some("boot A `$` é".to_owned()),
            gpt_id: None,
            gpt_attrs: Some("GUID:63".to_owned()),
            bootable: true,
        });

        let script = sfdisk_script(&table);
        assert!(script.contains("unit: sectors\n"));
        assert!(script.contains("sector-size: 4096\n"));
        assert!(script.contains("first-lba: 64\n"));
        assert!(script.contains("last-lba: 8127\n"));
        assert!(script.contains("table-length: 256\n"));
        assert!(script.contains(r#",name="boot A \x60\x24\x60 \xc3\xa9",attrs="GUID:63",bootable"#));
    }

    #[test]
    fn write_mbr_bootable_flag() {
        let mut table = PartitionTable::new(
            DiskId::Mbr(MbrId::new(0x12345678)),
            NumBlocks::from_raw(8192),
        );
        table.partitions.push(Partition {
            number: 1,
            start: NumBlocks::from_raw(2048),
            size: NumBlocks::from_raw(4096),
            ty: mbr_types::FAT32_LBA,
            name: None,
            gpt_id: None,
            gpt_attrs: None,
            bootable: true,
        });

        assert!(sfdisk_script(&table).contains(",bootable\n"));
    }
}
