//! Private state writes shared by the catalog and its offline operator.
//!
//! File contents are flushed before publication in the same directory. Unix
//! additionally flushes the parent directory; Windows has no equivalent through
//! `std::fs`. This does not promise survival of every filesystem/power failure.
use std::{io::Write, path::Path};

/// Replace a state file with a flushed, owner-only temporary file.
pub fn atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write(path, bytes, true)
}

/// Publish a new owner-only file without overwriting an existing output.
pub fn create_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write(path, bytes, false)
}

fn write(path: &Path, bytes: &[u8], replace: bool) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("create private state: {error}"))?;
    // Apply and verify the Windows owner/DACL before writing sensitive bytes.
    gcoms_private_fs::make_private(temporary.path(), false)?;
    gcoms_private_fs::validate_private_file(temporary.path(), "temporary state")?;
    temporary
        .write_all(bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("persist private state: {error}"))?;
    if replace {
        temporary.persist(path)
    } else {
        temporary.persist_noclobber(path)
    }
    .map_err(|error| format!("publish private state: {}", error.error))?;
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync private state directory: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_is_private_and_new_outputs_never_clobber_existing_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        create_new(&path, b"original").unwrap();
        gcoms_private_fs::validate_private_file(&path, "state").unwrap();
        assert!(create_new(&path, b"unexpected").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        atomic_bytes(&path, b"replacement").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        gcoms_private_fs::validate_private_file(&path, "state").unwrap();
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
