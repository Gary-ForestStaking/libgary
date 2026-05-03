//! Atomic replace: temp → fsync → rename → fsync parent (`docs/v0-state-integrity.md` §3.1).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::StorageError;

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), StorageError> {
    let parent = path
        .parent()
        .ok_or(StorageError::BundleDecode("no parent dir"))?;
    fs::create_dir_all(parent)?;
    let tmp = path.with_extension("atomic_tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_dir(parent)?;
    Ok(())
}

pub fn read_if_exists(path: &Path) -> Result<Option<Vec<u8>>, StorageError> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn sync_dir(dir: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        let f = OpenOptions::new().read(true).open(dir)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}
