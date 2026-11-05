use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::CoordError;

pub fn create_private_dir(path: &Path) -> Result<(), CoordError> {
    fs::create_dir_all(path).map_err(CoordError::io)?;
    let mut perms = fs::metadata(path).map_err(CoordError::io)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms).map_err(CoordError::io)?;
    Ok(())
}

pub fn write_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<(), CoordError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(CoordError::io)?;
    }
    let tmp = temp_path(path);
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(CoordError::io)?;
        let mut perms = file.metadata().map_err(CoordError::io)?.permissions();
        perms.set_mode(mode);
        file.set_permissions(perms).map_err(CoordError::io)?;
        file.write_all(bytes).map_err(CoordError::io)?;
        file.sync_all().map_err(CoordError::io)?;
    }
    fs::rename(&tmp, path).map_err(CoordError::io)?;
    Ok(())
}

pub fn write_text(path: &Path, text: &str, mode: u32) -> Result<(), CoordError> {
    write_bytes(path, text.as_bytes(), mode)
}

/// Write a file through a temp file, sync it, rename it, and sync the directory.
///
/// `mode` is the mode of the new file. The coordinator deny file uses `0o644`.
/// The seq file uses `0o600`.
pub(crate) fn write_synced(path: &Path, bytes: &[u8], mode: u32) -> Result<(), CoordError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(CoordError::io)?;
    }
    let tmp = temp_path(path);
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .map_err(CoordError::io)?;
        file.write_all(bytes).map_err(CoordError::io)?;
        file.sync_all().map_err(CoordError::io)?;
    }
    fs::rename(&tmp, path).map_err(CoordError::io)?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(CoordError::io)?;
    }
    Ok(())
}

pub fn read_text(path: &Path) -> Result<String, CoordError> {
    fs::read_to_string(path).map_err(CoordError::io)
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}
