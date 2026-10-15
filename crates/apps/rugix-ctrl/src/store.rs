//! Content-addressed store of the device and its `store` commands.
//!
//! Rugix Apps keeps `app-file` payloads that opt into the store there. Installations
//! of system and app bundles use its chunks as local block candidates.

use reportify::bail;
use reportify::ResultExt;
use rugix_store::RefName;
use rugix_store::Store;

use crate::cli::StoreCommand;
use crate::config::output::StoreGcOutput;
use crate::config::output::StoreInfoOutput;
use crate::config::output::StoreRefOutput;
use crate::config::output::StoreVerifyOutput;
use crate::system::SystemResult;

/// Open the store of the device, below the [state directory](crate::state::state_dir).
pub fn open() -> Store {
    Store::new(crate::state::state_dir().join("store"))
}

/// Run a `store` command, printing its JSON output.
pub fn run_command(command: &StoreCommand) -> SystemResult<()> {
    let store = open();
    match command {
        StoreCommand::Info => {
            let info = store.info().whatever("unable to inspect store")?;
            let output = StoreInfoOutput::new(
                info.refs,
                info.objects,
                info.chunks,
                info.referenced_size.raw,
                info.stored_size.raw,
            );
            print(&output)
        }
        StoreCommand::List { prefix } => {
            let prefix = prefix
                .as_ref()
                .map(|prefix| RefName::new(prefix.clone()))
                .transpose()
                .whatever("invalid ref prefix")?;
            let output = store
                .list(prefix.as_ref())
                .whatever("unable to list refs")?
                .into_iter()
                .map(|stored| {
                    let size = store.size(&stored.object).whatever_with(|_| {
                        format!("unable to read object of ref {}", stored.name)
                    })?;
                    Ok(StoreRefOutput::new(
                        stored.name,
                        stored.object.to_string(),
                        size.raw,
                    ))
                })
                .collect::<SystemResult<Vec<_>>>()?;
            print(&output)
        }
        StoreCommand::Verify => {
            let problems = store.verify().whatever("unable to verify store")?;
            let count = problems.len();
            print(&StoreVerifyOutput::new(
                problems
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<_>>()
                    .into(),
            ))?;
            if count > 0 {
                bail!("store verification found {count} problems");
            }
            Ok(())
        }
        StoreCommand::Gc => {
            // Only Rugix Apps knows which of its refs are no longer needed.
            let summary = crate::cli::load_cli_app_manager()?
                .collect_store_garbage()
                .whatever("unable to collect store garbage")?;
            print(&StoreGcOutput::new(
                summary.removed_refs,
                summary.removed_objects,
                summary.removed_chunks,
                summary.freed_size.raw,
            ))
        }
    }
}

fn print<T: serde::Serialize>(output: &T) -> SystemResult<()> {
    rugix_cli::json::print_json(output, false).whatever("unable to write output to stdout")
}
