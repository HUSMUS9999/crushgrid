use crate::codec::{CodecId, compress_block, decompress_block};
use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

pub const ZSTD_MAGIC: u32 = 0xFD2F_B528;
pub const ZSTD_SKIPPABLE_MAGIC: u32 = 0x184D_2A5E;
pub const ZSTD_SEEKABLE_FOOTER_MAGIC: u32 = 0x8F92_EAB1;

/// `.sqz` / `.hsq` container header & footer constants.
/// Supports v1 (legacy `.hsq`), v2 (`.sqz`), and v3 (per-slab multi-codec + BLAKE3 dedup + raw bypass + directory manifest).
pub const HSQ_HEADER_MAGIC: [u8; 4] = *b"HSQZ";
pub const SQZ_HEADER_MAGIC: [u8; 4] = *b"SQZA";
pub const HSQ_FOOTER_MAGIC: [u8; 8] = *b"ZQSH_V01";
pub const SQZ_FOOTER_MAGIC: [u8; 8] = *b"AZQS_V02";

pub const HSQ_HEADER_LEN: usize = 64;
pub const SQZ_HEADER_LEN: usize = 80;
pub const HSQ_ENTRY_LEN: usize = 32;
pub const SQZ_ENTRY_LEN: usize = 36;
pub const HSQ_TRAILER_LEN: usize = 24;

pub const CHUNK_FLAG_COMPRESSED: u8 = 0;
pub const CHUNK_FLAG_RAW_STORED: u8 = 1;
pub const CHUNK_FLAG_DEDUP_REF: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerFormat {
    /// Standard Zstd multi-frame + Zstd Seekable skippable footer (100% compatible with `zstd -d`)
    ZstdSeekable,
    /// Universal Squiz Archive v3 container (`.sqz`: multi-codec, BLAKE3 dedup, raw bypass, directory manifest)
    Sqz,
}

#[derive(Debug, Clone)]
pub struct ChunkIndexEntry {
    pub chunk_id: u64,
    pub comp_offset: u64,
    pub comp_len: u32,
    pub orig_offset: u64,
    pub orig_len: u32,
    pub xxh3_64: u64,
    pub chunk_flags: u8,
    /// Per-slab codec (v3 `.sqz` multi-codec support; 0xFF = use archive header default codec)
    pub slab_codec: CodecId,
}

/// File metadata inside a multi-file / whole-directory `.sqz` archive.
#[derive(Debug, Clone)]
pub struct PackedFileEntry {
    pub rel_path: String,
    pub stream_offset: u64,
    pub size: u64,
    pub mtime_secs: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone)]
pub struct ArchiveManifest {
    pub format: ContainerFormat,
    pub codec: CodecId,
    pub total_orig_size: u64,
    pub whole_file_blake3: Option<[u8; 32]>,
    pub entries: Vec<ChunkIndexEntry>,
    pub files: Vec<PackedFileEntry>,
}

pub fn encode_file_manifest(files: &[PackedFileEntry]) -> Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(files.len() * 64 + 8);
    raw.extend_from_slice(&(files.len() as u64).to_le_bytes());
    for f in files {
        let p = f.rel_path.as_bytes();
        raw.extend_from_slice(&(p.len() as u32).to_le_bytes());
        raw.extend_from_slice(p);
        raw.extend_from_slice(&f.stream_offset.to_le_bytes());
        raw.extend_from_slice(&f.size.to_le_bytes());
        raw.extend_from_slice(&f.mtime_secs.to_le_bytes());
        raw.push(if f.is_dir { 1 } else { 0 });
    }
    // Compress manifest itself with Zstd L6 so even 500,000-file trees take tiny bytes!
    let comp = compress_block(CodecId::Zstd, 6, &raw)?;
    let mut out = Vec::with_capacity(8 + comp.len());
    out.extend_from_slice(&(raw.len() as u64).to_le_bytes());
    out.extend_from_slice(&comp);
    Ok(out)
}

pub const MAX_MANIFEST_UNCOMPRESSED_BYTES: usize = 256 * 1024 * 1024; // 256 MiB hard safety cap

pub fn decode_file_manifest(blob: &[u8]) -> Result<Vec<PackedFileEntry>> {
    if blob.is_empty() {
        return Ok(Vec::new());
    }
    if blob.len() < 8 {
        bail!("truncated .sqz file manifest");
    }
    let orig_len_u64 = u64::from_le_bytes(blob[0..8].try_into().unwrap());
    if orig_len_u64 > MAX_MANIFEST_UNCOMPRESSED_BYTES as u64 {
        bail!(
            "corrupted .sqz manifest: uncompressed size {} exceeds safety cap {}",
            orig_len_u64,
            MAX_MANIFEST_UNCOMPRESSED_BYTES
        );
    }
    let orig_len = orig_len_u64 as usize;
    let raw = decompress_block(CodecId::Zstd, &blob[8..], orig_len)?;
    if raw.len() < 8 {
        bail!("corrupted .sqz file manifest payload");
    }
    let count = u64::from_le_bytes(raw[0..8].try_into().unwrap()) as usize;
    let mut cur = &raw[8..];
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if cur.len() < 4 {
            bail!("truncated manifest path length");
        }
        let plen = u32::from_le_bytes(cur[0..4].try_into().unwrap()) as usize;
        cur = &cur[4..];
        if cur.len() < plen + 25 {
            bail!("truncated manifest entry");
        }
        let rel_path = String::from_utf8_lossy(&cur[..plen]).into_owned();
        cur = &cur[plen..];
        let stream_offset = u64::from_le_bytes(cur[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(cur[8..16].try_into().unwrap());
        let mtime_secs = u64::from_le_bytes(cur[16..24].try_into().unwrap());
        let is_dir = cur[24] != 0;
        cur = &cur[25..];
        out.push(PackedFileEntry {
            rel_path,
            stream_offset,
            size,
            mtime_secs,
            is_dir,
        });
    }
    Ok(out)
}

/// Write placeholder 80-byte SQZ v2 header at offset 0.
pub fn write_sqz_header_placeholder<W: Write>(writer: &mut W) -> Result<()> {
    writer.write_all(&[0u8; SQZ_HEADER_LEN])?;
    Ok(())
}

/// Finalize SQZ v2 archive: writes compressed file manifest (if any), seek/dedup table + trailer, then header at 0.
#[allow(clippy::too_many_arguments)]
pub fn finalize_sqz(
    file: &mut File,
    codec: CodecId,
    level: i32,
    block_size: u32,
    total_orig_size: u64,
    whole_blake3: [u8; 32],
    entries: &[ChunkIndexEntry],
    files: &[PackedFileEntry],
) -> Result<()> {
    let (manifest_offset, manifest_len) = if !files.is_empty() {
        let m_off = file.stream_position()?;
        let blob = encode_file_manifest(files)?;
        file.write_all(&blob)?;
        (m_off, blob.len() as u64)
    } else {
        (0u64, 0u64)
    };

    let table_offset = file.stream_position()?;
    let mut table_buf = Vec::with_capacity(entries.len() * SQZ_ENTRY_LEN + HSQ_TRAILER_LEN);
    for e in entries {
        table_buf.extend_from_slice(&e.comp_offset.to_le_bytes());
        table_buf.extend_from_slice(&e.comp_len.to_le_bytes());
        table_buf.extend_from_slice(&e.orig_offset.to_le_bytes());
        table_buf.extend_from_slice(&e.orig_len.to_le_bytes());
        table_buf.extend_from_slice(&e.xxh3_64.to_le_bytes());
        table_buf.push(e.chunk_flags);
        table_buf.push(e.slab_codec as u8); // v3 per-slab codec (zero extra bytes!)
        table_buf.extend_from_slice(&[0u8; 2]);
    }
    table_buf.extend_from_slice(&table_offset.to_le_bytes());
    table_buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    table_buf.extend_from_slice(&SQZ_FOOTER_MAGIC);
    file.write_all(&table_buf)?;

    // Seek back to 0 and write 80-byte SQZ v3 header (backwards-compatible layout with v2!)
    let mut hdr = [0u8; SQZ_HEADER_LEN];
    hdr[0..4].copy_from_slice(&SQZ_HEADER_MAGIC);
    hdr[4] = 3; // version 3 (per-slab multi-codec)
    hdr[5] = codec as u8;
    hdr[6] = level as i8 as u8;
    hdr[7] = if files.is_empty() { 0 } else { 1 };
    hdr[8..12].copy_from_slice(&block_size.to_le_bytes());
    hdr[12..20].copy_from_slice(&total_orig_size.to_le_bytes());
    hdr[20..28].copy_from_slice(&(entries.len() as u64).to_le_bytes());
    hdr[28..60].copy_from_slice(&whole_blake3);
    hdr[60..68].copy_from_slice(&manifest_offset.to_le_bytes());
    hdr[68..76].copy_from_slice(&manifest_len.to_le_bytes());
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&hdr)?;
    file.flush()?;
    Ok(())
}

/// Append official Zstd Seekable Format skippable frame at EOF (`0x184D2A5E` + `0x8F92EAB1`).
pub fn write_zstd_seekable_footer<W: Write>(writer: &mut W, entries: &[ChunkIndexEntry]) -> Result<()> {
    let num_frames = entries.len() as u32;
    let payload_size = num_frames
        .checked_mul(8)
        .and_then(|v| v.checked_add(9))
        .context("too many frames for zstd seekable footer")?;

    let mut buf = Vec::with_capacity(8 + payload_size as usize);
    buf.extend_from_slice(&ZSTD_SKIPPABLE_MAGIC.to_le_bytes());
    buf.extend_from_slice(&payload_size.to_le_bytes());
    for e in entries {
        buf.extend_from_slice(&e.comp_len.to_le_bytes());
        buf.extend_from_slice(&e.orig_len.to_le_bytes());
    }
    buf.extend_from_slice(&num_frames.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&ZSTD_SEEKABLE_FOOTER_MAGIC.to_le_bytes());
    writer.write_all(&buf)?;
    writer.flush()?;
    Ok(())
}

/// Inspect an archive (`.sqz` v2, legacy `.hsq` v1, or standard Seekable `.zst`) in O(1).
pub fn read_manifest(file: &mut File) -> Result<ArchiveManifest> {
    let file_len = file.metadata()?.len();
    if file_len < 12 {
        bail!("input archive too small ({} bytes)", file_len);
    }

    let mut magic4 = [0u8; 4];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut magic4)?;

    if magic4 == SQZ_HEADER_MAGIC {
        return read_sqz_v2_manifest(file, file_len);
    }
    if magic4 == HSQ_HEADER_MAGIC {
        return read_hsq_v1_manifest(file, file_len);
    }

    let zmagic = u32::from_le_bytes(magic4);
    if zmagic == ZSTD_MAGIC || zmagic == ZSTD_SKIPPABLE_MAGIC {
        return read_zstd_seekable_manifest(file, file_len);
    }

    bail!(
        "unrecognized archive format (magic {:02x?}): expected .sqz, .hsq, or seekable .zst",
        magic4
    );
}

fn read_sqz_v2_manifest(file: &mut File, file_len: u64) -> Result<ArchiveManifest> {
    if file_len < (SQZ_HEADER_LEN + HSQ_TRAILER_LEN) as u64 {
        bail!("corrupted .sqz archive (truncated)");
    }
    let mut hdr = [0u8; SQZ_HEADER_LEN];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut hdr)?;
    let version = hdr[4];
    if version != 2 && version != 3 {
        bail!("unsupported .sqz version: {}", version);
    }
    let codec = CodecId::from_u8(hdr[5])?;
    let total_orig_size = u64::from_le_bytes(hdr[12..20].try_into().unwrap());
    let hdr_chunks = u64::from_le_bytes(hdr[20..28].try_into().unwrap());
    let mut blake3_hash = [0u8; 32];
    blake3_hash.copy_from_slice(&hdr[28..60]);
    let manifest_offset = u64::from_le_bytes(hdr[60..68].try_into().unwrap());
    let manifest_len = u64::from_le_bytes(hdr[68..76].try_into().unwrap());

    let mut trailer = [0u8; HSQ_TRAILER_LEN];
    file.seek(SeekFrom::End(-(HSQ_TRAILER_LEN as i64)))?;
    file.read_exact(&mut trailer)?;
    if trailer[16..24] != SQZ_FOOTER_MAGIC {
        bail!("corrupted .sqz footer magic");
    }
    let table_offset = u64::from_le_bytes(trailer[0..8].try_into().unwrap());
    let num_chunks = u64::from_le_bytes(trailer[8..16].try_into().unwrap());
    if num_chunks != hdr_chunks {
        bail!("corrupted .sqz chunk count mismatch ({} vs {})", hdr_chunks, num_chunks);
    }

    let table_bytes = (num_chunks as usize)
        .checked_mul(SQZ_ENTRY_LEN)
        .context("overflow reading .sqz seek table")?;
    let table_end = table_offset
        .checked_add(table_bytes as u64)
        .context("overflow computing .sqz seek table end")?;
    if table_end > file_len.saturating_sub(HSQ_TRAILER_LEN as u64) {
        bail!("corrupted .sqz seek table bounds (exceeds file length)");
    }
    file.seek(SeekFrom::Start(table_offset))?;
    let mut raw = vec![0u8; table_bytes];
    file.read_exact(&mut raw)?;

    let mut entries = Vec::with_capacity(num_chunks as usize);
    for i in 0..num_chunks as usize {
        let base = i * SQZ_ENTRY_LEN;
        let flags = raw[base + 32];
        let slab_codec = if version >= 3 {
            let cid = raw[base + 33];
            if cid == 0xFF {
                codec
            } else {
                CodecId::from_u8(cid)?
            }
        } else if (flags & CHUNK_FLAG_RAW_STORED) != 0 {
            CodecId::Raw
        } else {
            codec
        };
        entries.push(ChunkIndexEntry {
            chunk_id: i as u64,
            comp_offset: u64::from_le_bytes(raw[base..base + 8].try_into().unwrap()),
            comp_len: u32::from_le_bytes(raw[base + 8..base + 12].try_into().unwrap()),
            orig_offset: u64::from_le_bytes(raw[base + 12..base + 20].try_into().unwrap()),
            orig_len: u32::from_le_bytes(raw[base + 20..base + 24].try_into().unwrap()),
            xxh3_64: u64::from_le_bytes(raw[base + 24..base + 32].try_into().unwrap()),
            chunk_flags: flags,
            slab_codec,
        });
    }

    let files = if manifest_len > 0 {
        let m_end = manifest_offset
            .checked_add(manifest_len)
            .context("overflow computing .sqz manifest end")?;
        if m_end > file_len || manifest_len > MAX_MANIFEST_UNCOMPRESSED_BYTES as u64 {
            bail!("corrupted .sqz manifest bounds (offset={}, len={}, file={})", manifest_offset, manifest_len, file_len);
        }
        file.seek(SeekFrom::Start(manifest_offset))?;
        let mut mblob = vec![0u8; manifest_len as usize];
        file.read_exact(&mut mblob)?;
        decode_file_manifest(&mblob)?
    } else {
        Vec::new()
    };

    Ok(ArchiveManifest {
        format: ContainerFormat::Sqz,
        codec,
        total_orig_size,
        whole_file_blake3: Some(blake3_hash),
        entries,
        files,
    })
}

fn read_hsq_v1_manifest(file: &mut File, file_len: u64) -> Result<ArchiveManifest> {
    if file_len < (HSQ_HEADER_LEN + HSQ_TRAILER_LEN) as u64 {
        bail!("corrupted .hsq archive (truncated)");
    }
    let mut hdr = [0u8; HSQ_HEADER_LEN];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut hdr)?;
    let codec = CodecId::from_u8(hdr[5])?;
    let total_orig_size = u64::from_le_bytes(hdr[12..20].try_into().unwrap());
    let hdr_chunks = u64::from_le_bytes(hdr[20..28].try_into().unwrap());
    let mut blake3_hash = [0u8; 32];
    blake3_hash.copy_from_slice(&hdr[28..60]);

    let mut trailer = [0u8; HSQ_TRAILER_LEN];
    file.seek(SeekFrom::End(-(HSQ_TRAILER_LEN as i64)))?;
    file.read_exact(&mut trailer)?;
    if trailer[16..24] != HSQ_FOOTER_MAGIC {
        bail!("corrupted .hsq footer magic");
    }
    let table_offset = u64::from_le_bytes(trailer[0..8].try_into().unwrap());
    let num_chunks = u64::from_le_bytes(trailer[8..16].try_into().unwrap());
    if num_chunks != hdr_chunks {
        bail!("corrupted .hsq chunk count mismatch");
    }

    let table_bytes = (num_chunks as usize)
        .checked_mul(HSQ_ENTRY_LEN)
        .context("overflow reading .hsq seek table")?;
    let table_end = table_offset
        .checked_add(table_bytes as u64)
        .context("overflow computing .hsq seek table end")?;
    if table_end > file_len.saturating_sub(HSQ_TRAILER_LEN as u64) {
        bail!("corrupted .hsq seek table bounds (exceeds file length)");
    }
    file.seek(SeekFrom::Start(table_offset))?;
    let mut raw = vec![0u8; table_bytes];
    file.read_exact(&mut raw)?;

    let mut entries = Vec::with_capacity(num_chunks as usize);
    for i in 0..num_chunks as usize {
        let base = i * HSQ_ENTRY_LEN;
        entries.push(ChunkIndexEntry {
            chunk_id: i as u64,
            comp_offset: u64::from_le_bytes(raw[base..base + 8].try_into().unwrap()),
            comp_len: u32::from_le_bytes(raw[base + 8..base + 12].try_into().unwrap()),
            orig_offset: u64::from_le_bytes(raw[base + 12..base + 20].try_into().unwrap()),
            orig_len: u32::from_le_bytes(raw[base + 20..base + 24].try_into().unwrap()),
            xxh3_64: u64::from_le_bytes(raw[base + 24..base + 32].try_into().unwrap()),
            chunk_flags: CHUNK_FLAG_COMPRESSED,
            slab_codec: codec,
        });
    }

    Ok(ArchiveManifest {
        format: ContainerFormat::Sqz,
        codec,
        total_orig_size,
        whole_file_blake3: Some(blake3_hash),
        entries,
        files: Vec::new(),
    })
}

fn read_zstd_seekable_manifest(file: &mut File, file_len: u64) -> Result<ArchiveManifest> {
    if file_len < 17 {
        bail!("truncated zstd seekable archive");
    }
    let mut footer = [0u8; 9];
    file.seek(SeekFrom::End(-9))?;
    file.read_exact(&mut footer)?;
    let num_frames = u32::from_le_bytes(footer[0..4].try_into().unwrap()) as usize;
    let desc = footer[4];
    let magic = u32::from_le_bytes(footer[5..9].try_into().unwrap());
    if magic != ZSTD_SEEKABLE_FOOTER_MAGIC {
        bail!("standard .zst file lacks a Zstd Seekable footer");
    }
    let has_checksum = (desc & 0x80) != 0;
    let entry_size = if has_checksum { 12usize } else { 8usize };
    let table_bytes = num_frames * entry_size;
    let total_skippable = 8 + table_bytes + 9;
    if (total_skippable as u64) > file_len {
        bail!("corrupted zstd seekable table length");
    }

    file.seek(SeekFrom::End(-(total_skippable as i64)))?;
    let mut skippable_hdr = [0u8; 8];
    file.read_exact(&mut skippable_hdr)?;
    if u32::from_le_bytes(skippable_hdr[0..4].try_into().unwrap()) != ZSTD_SKIPPABLE_MAGIC {
        bail!("invalid zstd skippable frame magic");
    }

    let mut raw = vec![0u8; table_bytes];
    file.read_exact(&mut raw)?;

    let mut entries = Vec::with_capacity(num_frames);
    let mut comp_off = 0u64;
    let mut orig_off = 0u64;
    for i in 0..num_frames {
        let base = i * entry_size;
        let comp_len = u32::from_le_bytes(raw[base..base + 4].try_into().unwrap());
        let orig_len = u32::from_le_bytes(raw[base + 4..base + 8].try_into().unwrap());
        entries.push(ChunkIndexEntry {
            chunk_id: i as u64,
            comp_offset: comp_off,
            comp_len,
            orig_offset: orig_off,
            orig_len,
            xxh3_64: 0,
            chunk_flags: CHUNK_FLAG_COMPRESSED,
            slab_codec: CodecId::Zstd,
        });
        comp_off += comp_len as u64;
        orig_off += orig_len as u64;
    }

    Ok(ArchiveManifest {
        format: ContainerFormat::ZstdSeekable,
        codec: CodecId::Zstd,
        total_orig_size: orig_off,
        whole_file_blake3: None,
        entries,
        files: Vec::new(),
    })
}
