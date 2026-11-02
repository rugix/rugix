//! Durable bootstrap intent and completion checkpoints.
//!
//! A journal records the target geometry before repartitioning and retains the
//! original list of partitions to initialize across subsequent boots.

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
use xscript::Run;

use crate::system::SystemResult;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    version: u32,
    disk_id: String,
    configuration: String,
    block_size: u64,
    partitions: Vec<Geometry>,
    pub pending: Vec<u8>,
}

impl Journal {
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

    pub fn save(&self, path: &Path) -> SystemResult<()> {
        let bytes =
            serde_json::to_vec_pretty(self).whatever("unable to encode bootstrap journal")?;
        rugix_common::fsutils::atomic_write(path, &bytes)
            .whatever("unable to persist bootstrap journal")?;
        // The journal directory may also be new; persist its parent entry before repartitioning.
        xscript::run!(["sync", "-f", path])
            .whatever("unable to synchronize bootstrap journal filesystem")?;
        Ok(())
    }

    /// Reject a fallback image before executing any pre-layout hooks.
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

    /// Recomputed geometry must agree with the plan recorded before the first write.
    pub fn validate_plan(&self, table: &PartitionTable) -> SystemResult<()> {
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
    fn matches(&self, partition: &Partition) -> bool {
        self.number == partition.number
            && self.start == partition.start.into_raw()
            && self.size == partition.size.into_raw()
            && self.ty == partition.ty
            && self.name == partition.name
    }
}

impl From<&Partition> for Geometry {
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
