//! Linux's `blkpg` to directly manipulate partition tables in the kernel.
//!
//! We may repartition the disk while it is in use. This prevents the normal re-reading
//! of partition tables via `BLKRRPART` to fail. The solution is to instead directly
//! inform the Kernel about any changes made to the partitions.

use std::ffi::c_void;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::path::Path;

use nix::libc::c_char;
use nix::libc::c_int;
use nix::libc::c_longlong;
use reportify::Report;
use reportify::ResultExt;

use super::PartitionTable;
use crate::disk::NumBlocks;
use crate::utils::units::NumBytes;

reportify::new_whatever_type! {
    pub BlkpgError
}

pub fn update_kernel_partitions(
    dev: &Path,
    old_table: &PartitionTable,
    new_table: &PartitionTable,
) -> Result<(), Report<BlkpgError>> {
    let file = File::open(dev).whatever("unable to open block device")?;

    for (idx, partition) in new_table.partitions.iter().enumerate() {
        let start = new_table.blocks_to_bytes(partition.start);
        let mut size = new_table.blocks_to_bytes(partition.size);
        if let Some(old) = old_table.partitions.get(idx) {
            if partition.ty.is_extended() {
                continue;
            }
            assert_eq!(partition.ty, old.ty);
            assert_eq!(partition.start, old.start);
            assert_eq!(partition.number, old.number);
            assert!(partition.size >= old.size);
            if partition.size > old.size {
                eprintln!("Resize Partition: {} {} {}", partition.number, start, size);
                blkpg_command(
                    file.as_raw_fd(),
                    BLKPG_RESIZE_PARTITION,
                    &BlkpgPartition::new(start, size, partition.number),
                )?;
            }
        } else {
            if partition.ty.is_extended() {
                size = new_table.blocks_to_bytes(NumBlocks::from_raw(1));
            }
            println!("Add Partition: {} {} {}", partition.number, start, size);
            if let Err(error) = blkpg_command(
                file.as_raw_fd(),
                BLKPG_ADD_PARTITION,
                &BlkpgPartition::new(start, size, partition.number),
            ) {
                eprintln!("Unable to add partition {}: {error:?}.", partition.number);
            }
        }
    }
    Ok(())
}

fn blkpg_command(
    fd: RawFd,
    cmd: c_int,
    partition: &BlkpgPartition,
) -> Result<(), Report<BlkpgError>> {
    let ioctl_arg = BlkpgIoctlArg {
        op: cmd,
        flags: 0,
        datalen: std::mem::size_of::<BlkpgPartition>() as c_int,
        data: partition as *const _ as *const c_void,
    };
    unsafe {
        ioctl_blkpg(fd, &ioctl_arg).whatever("unable to issue blkpg ioctl")?;
    }
    Ok(())
}

nix::ioctl_write_ptr_bad!(
    ioctl_blkpg,
    nix::request_code_none!(0x12, 105),
    BlkpgIoctlArg
);

const BLKPG_DEVNAMELTH: usize = 64;
const BLKPG_VOLNAMELTH: usize = 64;

#[repr(C)]
struct BlkpgPartition {
    start: c_longlong,
    length: c_longlong,
    pno: c_int,
    devname: [c_char; BLKPG_DEVNAMELTH],
    volname: [c_char; BLKPG_VOLNAMELTH],
}

impl BlkpgPartition {
    pub fn new(start: NumBytes, size: NumBytes, number: u8) -> Self {
        Self {
            start: start.into_raw() as c_longlong,
            length: size.into_raw() as c_longlong,
            pno: number as c_int,
            devname: [0; BLKPG_DEVNAMELTH],
            volname: [0; BLKPG_VOLNAMELTH],
        }
    }
}

#[repr(C)]
struct BlkpgIoctlArg {
    op: c_int,
    flags: c_int,
    datalen: c_int,
    data: *const c_void,
}

const BLKPG_ADD_PARTITION: c_int = 1;
#[allow(dead_code)]
const BLKPG_DEL_PARTITION: c_int = 2;
const BLKPG_RESIZE_PARTITION: c_int = 3;
