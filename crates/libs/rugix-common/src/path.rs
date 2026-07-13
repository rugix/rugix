//! Validated paths for filesystem-confined operations.

use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use thiserror::Error;

/// A non-empty, portable relative path containing only normal components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidatedRelativePath(String);

impl ValidatedRelativePath {
    /// Validate and construct a relative path.
    pub fn new(path: impl Into<String>) -> Result<Self, InvalidRelativePath> {
        let path = path.into();
        validate_relative_path(&path)?;
        Ok(Self(path))
    }

    /// Return the validated path as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the validated path as a [`Path`].
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// Return whether the path consists of exactly one normal component.
    pub fn is_single_component(&self) -> bool {
        self.as_path().components().count() == 1
    }
}

impl AsRef<Path> for ValidatedRelativePath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl std::fmt::Display for ValidatedRelativePath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Ensure that no existing component beneath `root` is a symbolic link.
///
/// Missing components are allowed so callers can validate immediately before creating
/// them.
pub fn ensure_no_symlink_components(
    root: &Path,
    relative: &ValidatedRelativePath,
) -> std::io::Result<()> {
    let mut current = PathBuf::from(root);
    for component in relative.as_path().components() {
        let Component::Normal(component) = component else {
            unreachable!("relative path was validated");
        };
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(std::io::Error::other(format!(
                    "path component is a symbolic link: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Error returned for an unsafe or non-portable relative path.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid relative path {path:?}: {reason}")]
pub struct InvalidRelativePath {
    path: String,
    reason: &'static str,
}

fn invalid(path: &str, reason: &'static str) -> InvalidRelativePath {
    InvalidRelativePath {
        path: path.to_owned(),
        reason,
    }
}

fn validate_relative_path(path: &str) -> Result<(), InvalidRelativePath> {
    if path.is_empty() {
        return Err(invalid(path, "path is empty"));
    }
    if path.contains('\0') {
        return Err(invalid(path, "path contains a NUL byte"));
    }
    // Backslashes are separators on Windows and accepting them as ordinary characters on Unix
    // would make validation platform-dependent. This also rejects UNC and device prefixes.
    if path.contains('\\') {
        return Err(invalid(path, "backslashes are not permitted"));
    }
    if path
        .as_bytes()
        .get(1)
        .is_some_and(|byte| *byte == b':' && path.as_bytes()[0].is_ascii_alphabetic())
    {
        return Err(invalid(path, "Windows drive prefixes are not permitted"));
    }

    for part in path.split('/') {
        match part {
            "" => return Err(invalid(path, "empty path components are not permitted")),
            "." => {
                return Err(invalid(
                    path,
                    "current-directory components are not permitted",
                ))
            }
            ".." => {
                return Err(invalid(
                    path,
                    "parent-directory components are not permitted",
                ))
            }
            _ => {}
        }
    }
    if !Path::new(path)
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(invalid(
            path,
            "path contains a root, prefix, or special component",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ensure_no_symlink_components;
    use super::ValidatedRelativePath;

    #[test]
    fn accepts_only_nonempty_normal_relative_paths() {
        for path in ["file", "directory/file", "a-b_c/123"] {
            assert!(ValidatedRelativePath::new(path).is_ok(), "{path:?}");
        }
    }

    #[test]
    fn rejects_unsafe_and_nonportable_paths() {
        for path in [
            "",
            "/absolute",
            "./file",
            "directory/./file",
            "../file",
            "directory/../file",
            "directory//file",
            "directory/",
            "C:/Windows/file",
            "C:\\Windows\\file",
            "\\\\server\\share",
            "file\0name",
        ] {
            assert!(ValidatedRelativePath::new(path).is_err(), "{path:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_nested_existing_symlink_components() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join("root");
        let outside = tempdir.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("redirect")).unwrap();

        let safe = ValidatedRelativePath::new("directory/file").unwrap();
        let escaped = ValidatedRelativePath::new("redirect/file").unwrap();
        assert!(ensure_no_symlink_components(&root, &safe).is_ok());
        assert!(ensure_no_symlink_components(&root, &escaped).is_err());
    }
}
