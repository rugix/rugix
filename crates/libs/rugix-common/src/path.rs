//! Validated paths for filesystem-confined operations.

use std::path::Component;
use std::path::Path;

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
}
