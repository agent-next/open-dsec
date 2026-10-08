//! Filesystem operations of a chronus session (P §3.3).

use std::path::Path;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::{ctx, require_abs};

/// Largest file `read_file` returns in one call.
pub const MAX_READ: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

pub async fn read_file(path: &str) -> Result<Vec<u8>> {
    let p = require_abs(path)?;
    let md = ctx(tokio::fs::metadata(p).await, path)?;
    if md.len() > MAX_READ {
        bail!("{path}: {} bytes exceeds the {MAX_READ}-byte read limit", md.len());
    }
    ctx(tokio::fs::read(p).await, path)
}

pub async fn write_file(path: &str, data: &[u8], mode: Option<u32>) -> Result<()> {
    let p = require_abs(path)?;
    if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
        ctx(tokio::fs::create_dir_all(parent).await, path)?;
    }
    ctx(tokio::fs::write(p, data).await, path)?;
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt;
        ctx(tokio::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).await, path)?;
    }
    Ok(())
}

pub async fn list_dir(path: &str) -> Result<Vec<DirEntry>> {
    let p: &Path = require_abs(path)?;
    let mut rd = ctx(tokio::fs::read_dir(p).await, path)?;
    let mut out = vec![];
    while let Some(e) = ctx(rd.next_entry().await, path)? {
        let md = ctx(e.metadata().await, path)?;
        out.push(DirEntry { name: e.file_name().to_string_lossy().into_owned(), is_dir: md.is_dir(), size: md.len() });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}
