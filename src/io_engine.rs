use anyhow::Result;
use std::fs::File;

/// Cross-platform positional write (`pwrite` on Unix, `seek_write` on Windows)
/// allowing lock-free, out-of-order parallel decompression directly to exact file offsets
/// with ZERO reorder buffer RAM overhead!
#[cfg(unix)]
pub fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> Result<()> {
    use std::os::unix::fs::FileExt;
    while !buf.is_empty() {
        let n = file.write_at(buf, offset)?;
        if n == 0 {
            anyhow::bail!("short write_at (0 bytes)");
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(windows)]
pub fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_write(buf, offset)?;
        if n == 0 {
            anyhow::bail!("short seek_write (0 bytes)");
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

/// Cross-platform positional read (`pread` on Unix, `seek_read` on Windows).
#[cfg(unix)]
pub fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> Result<()> {
    use std::os::unix::fs::FileExt;
    while !buf.is_empty() {
        let n = file.read_at(buf, offset)?;
        if n == 0 {
            anyhow::bail!("unexpected EOF in read_at at offset {}", offset);
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(windows)]
pub fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_read(buf, offset)?;
        if n == 0 {
            anyhow::bail!("unexpected EOF in seek_read at offset {}", offset);
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}
