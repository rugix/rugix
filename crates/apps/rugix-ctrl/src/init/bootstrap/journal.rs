//! Durable bootstrap intent and completion checkpoints.
//!
//! A journal records target geometry and newly created filesystem partitions before
//! repartitioning. Completion checkpoints retain only pending work across boots.

use std::fs;
use std::io;
use std::path::Path;

use reportify::ensure;
use reportify::ResultExt;
use rugix_common::disk::Partition;
use rugix_common::disk::PartitionTable;
use rugix_common::disk::PartitionType;
use serde::Deserialize;
use serde::Serialize;

use crate::system::SystemResult;

/// A bootstrap plan bound to a disk and configuration, with unfinished initialization
/// work.
///
/// Recording which partitions were originally new prevents replay from treating
/// pre-existing partitions as initialization targets.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    version: u32,
    disk_id: String,
    configuration: String,
    /// Bytes per block for the recorded partition extents.
    block_size: u64,
    partitions: Vec<Geometry>,
    /// Increasing partition numbers without a durable completion checkpoint.
    pub pending: Vec<u8>,
}

impl Journal {
    /// Record the target table, configuration digest, and initial work before
    /// repartitioning.
    ///
    /// `pending` must list only newly created partitions requiring initialization,
    /// in increasing partition-number order.
    pub fn new(table: &PartitionTable, configuration: String, pending: Vec<u8>) -> Self {
        Self {
            version: 1,
            disk_id: table.disk_id.to_string(),
            configuration,
            block_size: table.block_size.into_raw(),
            partitions: table.partitions.iter().map(Geometry::from).collect(),
            pending,
        }
    }

    /// Decode a saved journal, returning `None` only when the file is absent.
    pub fn load(path: &Path) -> SystemResult<Option<Self>> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).whatever("unable to read bootstrap journal"),
        };
        serde_json::from_slice(&bytes)
            .whatever("unable to decode bootstrap journal")
            .map(Some)
    }

    /// Atomically persist the plan or checkpoint, including newly created parent entries.
    pub fn save(&self, path: &Path) -> SystemResult<()> {
        let bytes =
            serde_json::to_vec_pretty(self).whatever("unable to encode bootstrap journal")?;
        rugix_common::fsutils::atomic_write(path, &bytes)
            .whatever("unable to persist bootstrap journal")
    }

    /// Validate the journal version, disk identity, and configuration before pre-layout
    /// hooks.
    pub fn validate_binding(
        &self,
        table: &PartitionTable,
        configuration: &str,
    ) -> SystemResult<()> {
        ensure!(self.version == 1, "unsupported bootstrap journal version");
        ensure!(
            self.disk_id == table.disk_id.to_string(),
            "bootstrap journal belongs to another disk"
        );
        ensure!(
            self.configuration == configuration,
            "bootstrap configuration changed while initialization is pending"
        );
        Ok(())
    }

    /// Validate disk identity, target geometry, and pending partition numbers after
    /// hooks.
    pub fn validate_plan(&self, table: &PartitionTable) -> SystemResult<()> {
        ensure!(
            self.disk_id == table.disk_id.to_string(),
            "bootstrap journal belongs to another disk"
        );
        ensure!(
            self.block_size == table.block_size.into_raw()
                && self.partitions.len() == table.partitions.len()
                && self
                    .partitions
                    .iter()
                    .zip(&table.partitions)
                    .all(|(expected, actual)| expected.matches(actual)),
            "partition geometry changed while bootstrapping is pending"
        );
        ensure!(
            self.pending.windows(2).all(|pair| pair[0] < pair[1])
                && self.pending.iter().all(|number| self
                    .partitions
                    .iter()
                    .any(|partition| partition.number == *number)),
            "bootstrap journal contains invalid pending partitions"
        );
        Ok(())
    }
}

/// Partition properties that must match the recorded plan during replay.
///
/// Extents use the journal's block size. GPT UUIDs are omitted because writing the
/// partition table may assign them after the plan has been saved.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Geometry {
    number: u8,
    start: u64,
    size: u64,
    ty: PartitionType,
    name: Option<String>,
}

impl Geometry {
    /// Compare all recorded properties with a recomputed target partition.
    fn matches(&self, partition: &Partition) -> bool {
        self.number == partition.number
            && self.start == partition.start.into_raw()
            && self.size == partition.size.into_raw()
            && self.ty == partition.ty
            && self.name == partition.name
    }
}

impl From<&Partition> for Geometry {
    /// Record a partition's number, extent, type, and name.
    fn from(partition: &Partition) -> Self {
        Self {
            number: partition.number,
            start: partition.start.into_raw(),
            size: partition.size.into_raw(),
            ty: partition.ty,
            name: partition.name.clone(),
        }
    }
}
