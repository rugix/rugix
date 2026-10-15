//! Payload files of app generations, kept in generation directories or in the store.
//!
//! An `app-file` payload either lands in the generation directory or, if it opts
//! into the store, is named by the ref `apps/<app>/<generation>/<path>`.
//! [`GenerationFiles`] hides this distinction from orchestrators and the CLI.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use reportify::ResultExt;
use rugix_common::path::ensure_no_symlink_components;
use rugix_common::path::ValidatedRelativePath;
use rugix_store::ObjectId;
use rugix_store::RefName;
use rugix_store::Store;

use super::manager::AppManager;
use super::AppsResult;
use crate::payload_db::PayloadState;

/// Payload files of one app generation.
pub struct GenerationFiles {
    store: Store,
    app_name: String,
    generation: u64,
    generation_dir: PathBuf,
}

impl GenerationFiles {
    pub(crate) fn new(
        store: Store,
        app_name: &str,
        generation: u64,
        generation_dir: PathBuf,
    ) -> Self {
        Self {
            store,
            app_name: app_name.to_owned(),
            generation,
            generation_dir,
        }
    }

    /// Ref naming the stored file `path` of a generation.
    pub fn file_ref(app_name: &str, generation: u64, path: &ValidatedRelativePath) -> RefName {
        RefName::new(format!("apps/{app_name}/{generation}/{path}"))
            .expect("valid app names and relative paths form a valid ref name")
    }

    /// Ref prefix of all stored files of a generation.
    pub fn generation_ref(app_name: &str, generation: u64) -> RefName {
        RefName::new(format!("apps/{app_name}/{generation}"))
            .expect("valid app names form a valid ref name")
    }

    /// List the generation's payload files, ordered by path.
    pub fn list(&self) -> AppsResult<Vec<GenerationFile>> {
        let mut states = AppManager::load_payload_states(&self.generation_dir)
            .into_iter()
            .collect::<Vec<_>>();
        states.sort_by(|(left, _), (right, _)| left.cmp(right));
        states
            .into_iter()
            .map(|(path, state)| {
                let validated =
                    ValidatedRelativePath::new(path.clone()).whatever("invalid payload path")?;
                let object = self
                    .store
                    .resolve(&Self::file_ref(&self.app_name, self.generation, &validated))
                    .whatever("unable to resolve stored file")?;
                Ok(GenerationFile {
                    path,
                    state,
                    object,
                })
            })
            .collect()
    }

    /// Open a file of the generation, wherever it is kept.
    pub fn open(&self, path: &ValidatedRelativePath) -> AppsResult<Box<dyn Read + Send>> {
        let name = Self::file_ref(&self.app_name, self.generation, path);
        if let Some(object) = self
            .store
            .resolve(&name)
            .whatever("unable to resolve stored file")?
        {
            let reader = self
                .store
                .open(&object)
                .whatever("unable to open stored file")?;
            return Ok(Box::new(reader));
        }
        ensure_no_symlink_components(&self.generation_dir, path)
            .whatever("file path contains a symbolic link")?;
        let file = File::open(self.generation_dir.join(path))
            .whatever_with(|_| format!("unable to open file {path}"))?;
        Ok(Box::new(file))
    }
}

/// Payload file of a generation.
pub struct GenerationFile {
    /// Path of the file relative to the generation directory.
    pub path: String,
    /// Hashes and size of the file.
    pub state: PayloadState,
    /// Stored object holding the file, if the file is kept in the store.
    pub object: Option<ObjectId>,
}
