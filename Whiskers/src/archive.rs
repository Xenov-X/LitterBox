//! Zip / 7z extraction with password support and zip-slip protection.

use std::io;
use std::path::{Component, Path, PathBuf};

const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const SEVEN_Z_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Extract an archive (zip or 7z) into `dest_dir`, auto-detecting format by
/// magic bytes. The archive file is deleted after successful extraction.
pub async fn extract(
    archive_path: &Path,
    dest_dir: &Path,
    password: Option<&str>,
) -> io::Result<()> {
    use tokio::io::AsyncReadExt;

    let mut magic = [0u8; 6];
    let mut f = tokio::fs::File::open(archive_path).await?;
    let n = f.read(&mut magic).await?;
    let magic = &magic[..n];

    if magic.starts_with(ZIP_MAGIC) {
        let data = tokio::fs::read(archive_path).await?;
        let dest = dest_dir.to_path_buf();
        let pw = password.map(String::from);
        tokio::task::spawn_blocking(move || {
            extract_zip(&data, &dest, pw.as_deref())
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;
    } else if magic.starts_with(SEVEN_Z_MAGIC) {
        let src = archive_path.to_path_buf();
        let dest = dest_dir.to_path_buf();
        let pw = password.map(String::from);
        tokio::task::spawn_blocking(move || {
            extract_7z(&src, &dest, pw.as_deref())
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unrecognized archive format (not zip or 7z)",
        ));
    }

    tokio::fs::remove_file(archive_path).await.ok();
    Ok(())
}

/// Validate that a path from an archive entry is safe (no zip-slip).
fn sanitize_path(entry_name: &str) -> io::Result<PathBuf> {
    let p = Path::new(entry_name);
    let mut out = PathBuf::new();
    for component in p.components() {
        match component {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsafe archive entry path: {entry_name:?}"),
                ));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("empty archive entry path: {entry_name:?}"),
        ));
    }
    Ok(out)
}

fn extract_zip(data: &[u8], dest_dir: &Path, password: Option<&str>) -> io::Result<()> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    for i in 0..archive.len() {
        let mut file = if let Some(pw) = password.filter(|s| !s.is_empty()) {
            match archive.by_index_decrypt(i, pw.as_bytes()) {
                Ok(f) => f,
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        } else {
            archive
                .by_index(i)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        };

        let name = file.name().to_string();
        if file.is_dir() {
            let dir_path = dest_dir.join(sanitize_path(&name)?);
            std::fs::create_dir_all(&dir_path)?;
            continue;
        }

        let safe = sanitize_path(&name)?;
        let out_path = dest_dir.join(&safe);

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut out = std::fs::File::create(&out_path)?;
        std::io::copy(&mut file, &mut out)?;
    }

    Ok(())
}

fn extract_7z(archive_path: &Path, dest_dir: &Path, password: Option<&str>) -> io::Result<()> {
    std::fs::create_dir_all(dest_dir)?;

    let file = std::fs::File::open(archive_path)?;
    let reader = std::io::BufReader::new(file);

    let result = if let Some(pw) = password.filter(|s| !s.is_empty()) {
        sevenz_rust::decompress_with_password(reader, dest_dir, pw.into())
    } else {
        sevenz_rust::decompress(reader, dest_dir)
    };

    result.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    validate_no_escape(dest_dir)?;

    Ok(())
}

/// Walk `dest_dir` and reject if any entry resolved outside of it.
/// Checks lazily — returns on the first violation without collecting all paths.
fn validate_no_escape(dest_dir: &Path) -> io::Result<()> {
    let canonical_base = std::fs::canonicalize(dest_dir)?;
    let mut stack = vec![dest_dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)? {
            let path = entry?.path();
            let canonical = std::fs::canonicalize(&path)?;
            if !canonical.starts_with(&canonical_base) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("archive entry escaped dest dir: {}", path.display()),
                ));
            }
            if path.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}
