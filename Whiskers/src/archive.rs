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

/// Validate that an executable name from `exec_command` contains only normal
/// path components (no `..`, `/`, `\`, or prefix like `C:`).
pub fn validate_exe_name(name: &str) -> io::Result<()> {
    let p = Path::new(name);
    if p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsafe exe name: {name:?}"),
        ));
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ── sanitize_path ──

    #[test]
    fn sanitize_normal_file() {
        assert_eq!(sanitize_path("hello.txt").unwrap(), PathBuf::from("hello.txt"));
    }

    #[test]
    fn sanitize_nested_path() {
        assert_eq!(
            sanitize_path("subdir/inner/file.dll").unwrap(),
            PathBuf::from("subdir/inner/file.dll"),
        );
    }

    #[test]
    fn sanitize_strips_curdir() {
        assert_eq!(sanitize_path("./file.exe").unwrap(), PathBuf::from("file.exe"));
    }

    #[test]
    fn sanitize_rejects_parent_dir() {
        assert!(sanitize_path("../etc/passwd").is_err());
    }

    #[test]
    fn sanitize_rejects_mid_parent() {
        assert!(sanitize_path("subdir/../../escape.exe").is_err());
    }

    #[test]
    fn sanitize_rejects_absolute() {
        assert!(sanitize_path("/etc/passwd").is_err());
    }

    #[test]
    fn sanitize_rejects_empty() {
        assert!(sanitize_path("").is_err());
    }

    #[test]
    fn sanitize_rejects_dot_only() {
        assert!(sanitize_path(".").is_err());
    }

    // ── validate_exe_name ──

    #[test]
    fn exe_name_simple() {
        assert!(validate_exe_name("loader.exe").is_ok());
    }

    #[test]
    fn exe_name_no_extension() {
        assert!(validate_exe_name("rundll32").is_ok());
    }

    #[test]
    fn exe_name_rejects_parent_traversal() {
        assert!(validate_exe_name("../evil.exe").is_err());
    }

    #[test]
    fn exe_name_rejects_absolute() {
        assert!(validate_exe_name("/bin/sh").is_err());
    }

    #[test]
    fn exe_name_rejects_dot() {
        assert!(validate_exe_name(".").is_err());
    }

    #[test]
    fn exe_name_rejects_dotdot() {
        assert!(validate_exe_name("..").is_err());
    }

    #[test]
    fn exe_name_allows_subdirectory() {
        assert!(validate_exe_name("sub/loader.exe").is_ok());
    }

    // ── validate_no_escape ──

    #[test]
    fn no_escape_clean_dir() {
        let dir = tempdir();
        fs::write(dir.join("a.txt"), b"ok").unwrap();
        fs::create_dir(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/b.txt"), b"ok").unwrap();
        assert!(validate_no_escape(&dir).is_ok());
    }

    #[test]
    fn no_escape_empty_dir() {
        let dir = tempdir();
        assert!(validate_no_escape(&dir).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn no_escape_rejects_symlink_outside() {
        let base = tempdir();
        let outside = tempdir();
        fs::write(outside.join("secret.txt"), b"leaked").unwrap();
        std::os::unix::fs::symlink(
            outside.join("secret.txt"),
            base.join("link"),
        )
        .unwrap();
        assert!(validate_no_escape(&base).is_err());
    }

    // ── extract (format detection) ──

    #[tokio::test]
    async fn extract_rejects_unknown_format() {
        let dir = tempdir();
        let fake = dir.join("not_an_archive.bin");
        fs::write(&fake, b"this is not an archive").unwrap();
        let dest = dir.join("out");
        let err = extract(&fake, &dest, None).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("unrecognized"));
    }

    #[tokio::test]
    async fn extract_zip_roundtrip() {
        let dir = tempdir();
        let zip_path = dir.join("test.zip");

        {
            let file = fs::File::create(&zip_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            writer.start_file("hello.txt", opts).unwrap();
            std::io::Write::write_all(&mut writer, b"world").unwrap();
            writer.finish().unwrap();
        }

        let dest = dir.join("out");
        extract(&zip_path, &dest, None).await.unwrap();
        assert_eq!(fs::read_to_string(dest.join("hello.txt")).unwrap(), "world");
        assert!(!zip_path.exists(), "archive should be deleted after extraction");
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("whiskers_test_{}", std::process::id()));
        let unique = dir.join(format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&unique).unwrap();
        unique
    }
}
