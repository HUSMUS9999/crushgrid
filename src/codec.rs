use anyhow::{Result, bail};
use std::cell::RefCell;
use std::io::{Read, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CodecId {
    Raw = 0,
    Zstd = 1,
    Lzma2 = 2,
    Lz4 = 3,
    Lzma2Bcj = 4,
    Bzip3 = 5,
    Ppmd = 6,
}

impl CodecId {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Raw),
            1 => Ok(Self::Zstd),
            2 => Ok(Self::Lzma2),
            3 => Ok(Self::Lz4),
            4 => Ok(Self::Lzma2Bcj),
            5 => Ok(Self::Bzip3),
            6 => Ok(Self::Ppmd),
            _ => bail!("unknown codec id: {}", v),
        }
    }

    pub fn from_name(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "zstd" | "zst" => Ok(Self::Zstd),
            "lzma2" | "xz" | "lzma" => Ok(Self::Lzma2),
            "lzma2-bcj" | "xz-bcj" | "bcj" => Ok(Self::Lzma2Bcj),
            "bzip3" | "bz3" => Ok(Self::Bzip3),
            "ppmd" | "ppmd7" => Ok(Self::Ppmd),
            "lz4" => Ok(Self::Lz4),
            "raw" | "store" => Ok(Self::Raw),
            _ => bail!(
                "unsupported codec '{}': use auto, zstd, bzip3, ppmd, lzma2, lzma2-bcj, or lz4",
                s
            ),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Zstd => "zstd",
            Self::Lzma2 => "lzma2",
            Self::Lz4 => "lz4",
            Self::Lzma2Bcj => "lzma2-bcj",
            Self::Bzip3 => "bzip3",
            Self::Ppmd => "ppmd",
        }
    }

    pub fn default_level(self) -> i32 {
        match self {
            Self::Raw => 0,
            Self::Zstd => 9,
            Self::Lzma2 => 6,
            Self::Lzma2Bcj => 6,
            Self::Bzip3 => 8,  // block size in MiB (1..=32)
            Self::Ppmd => 8,   // model order (4..=12)
            Self::Lz4 => 1,
        }
    }

    pub fn clamp_level(self, level: i32) -> i32 {
        match self {
            Self::Raw => 0,
            Self::Zstd => level.clamp(1, 22),
            Self::Lzma2 | Self::Lzma2Bcj => level.clamp(0, 9),
            Self::Bzip3 => level.clamp(1, 32),
            Self::Ppmd => level.clamp(4, 12),
            Self::Lz4 => level.clamp(1, 12),
        }
    }
}

/// High-level human-friendly compression presets so users don't need to know algorithm internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// Maximum speed (LZ4 / Zstd L3)
    Fast,
    /// Everyday speed and ratio (Zstd L9 + LDM)
    Balanced,
    /// High compression with fast throughput (per-slab auto: bzip3 on text/CSV, lzma2-bcj on binaries, lzma2 L6 on mixed)
    Small,
    /// Smallest possible archive (per-slab auto: bzip3 on text/code, lzma2-bcj L9 on binaries, lzma2 L9 on mixed, 16M blocks)
    Max,
}

impl Preset {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "fast" | "speed" | "quick" => Ok(Self::Fast),
            "balanced" | "default" | "normal" | "auto" => Ok(Self::Balanced),
            "small" | "compact" | "high" | "smart" => Ok(Self::Small),
            "max" | "ultra" | "best" | "extreme" => Ok(Self::Max),
            _ => bail!("invalid preset '{}': use fast, balanced, small, or max", s),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Balanced => "balanced",
            Self::Small => "small",
            Self::Max => "max",
        }
    }

    /// Default primary codec and level for this preset (when `--codec` is not manually forced).
    pub fn default_codec_and_level(self) -> (CodecId, i32, bool) {
        // Returns (fallback_codec, level, enable_per_slab_auto)
        match self {
            Self::Fast => (CodecId::Zstd, 3, false),
            Self::Balanced => (CodecId::Zstd, 9, false),
            Self::Small => (CodecId::Lzma2, 6, true),
            Self::Max => (CodecId::Lzma2, 9, true),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlabKind {
    Text,
    Executable,
    Binary,
}

pub const MAX_DECODE_MEM_BYTES: usize = 64 * 1024 * 1024; // 64 MiB hard cap per decoder instance

/// Fast (<0.05 ms) general-purpose content classifier for per-slab codec selection.
/// Inspects up to 8 KiB across the slab to distinguish ASCII/UTF-8 text, x86 executables, and general binary.
pub fn classify_slab_content(data: &[u8]) -> SlabKind {
    if data.is_empty() {
        return SlabKind::Binary;
    }
    if data.len() >= 4 && (&data[0..4] == b"\x7fELF" || (&data[0..2] == b"MZ" && data.len() > 64)) {
        return SlabKind::Executable;
    }

    let sample = &data[..data.len().min(8192)];
    // Check valid UTF-8 text (trimming at most 3 trailing incomplete UTF-8 bytes at the 8 KiB slice boundary)
    let mut text_bytes = 0usize;
    let mut i = 0usize;
    let mut x86_opcodes = 0usize;
    while i < sample.len() {
        let b = sample[i];
        if b == 0xE8 || b == 0xE9 {
            x86_opcodes += 1;
        }
        if (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
            text_bytes += 1;
            i += 1;
        } else if b >= 0xC2 {
            let seq_len = if b < 0xE0 {
                2
            } else if b < 0xF0 {
                3
            } else if b <= 0xF4 {
                4
            } else {
                0
            };
            if seq_len >= 2 && i + seq_len <= sample.len() && std::str::from_utf8(&sample[i..i + seq_len]).is_ok() {
                text_bytes += seq_len;
                i += seq_len;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    if text_bytes * 100 >= sample.len() * 88 {
        return SlabKind::Text;
    }
    if x86_opcodes * 1000 >= sample.len() * 14 && text_bytes * 100 < sample.len() * 55 {
        return SlabKind::Executable;
    }
    SlabKind::Binary
}

/// Choose the optimal `(CodecId, level)` for a single slab when per-slab auto-codec is active.
pub fn pick_auto_slab_codec(data: &[u8], preset: Preset, fallback_level: i32) -> (CodecId, i32) {
    let kind = classify_slab_content(data);
    match preset {
        Preset::Fast => (CodecId::Zstd, 3),
        Preset::Balanced => match kind {
            SlabKind::Text => (CodecId::Bzip3, 8),
            SlabKind::Executable => (CodecId::Zstd, 9),
            SlabKind::Binary => (CodecId::Zstd, 9),
        },
        Preset::Small => match kind {
            SlabKind::Text => (CodecId::Bzip3, 8),
            SlabKind::Executable => (CodecId::Lzma2Bcj, 6),
            SlabKind::Binary => (CodecId::Lzma2, fallback_level.clamp(4, 6)),
        },
        Preset::Max => match kind {
            SlabKind::Text => (CodecId::Bzip3, 16),
            SlabKind::Executable => (CodecId::Lzma2Bcj, 9),
            SlabKind::Binary => (CodecId::Lzma2, 9),
        },
    }
}

thread_local! {
    static ZSTD_CCTX: RefCell<zstd_safe::CCtx<'static>> = RefCell::new(zstd_safe::CCtx::create());
    static ZSTD_DCTX: RefCell<zstd_safe::DCtx<'static>> = RefCell::new(zstd_safe::DCtx::create());
    static ZSTD_WIRE_CCTX: RefCell<zstd_safe::CCtx<'static>> = RefCell::new(zstd_safe::CCtx::create());
    static ZSTD_WIRE_DCTX: RefCell<zstd_safe::DCtx<'static>> = RefCell::new(zstd_safe::DCtx::create());
}

/// Ultra-fast (<0.05 ms) entropy/pre-compressed slab detector.
pub fn is_likely_incompressible(data: &[u8]) -> bool {
    if data.len() < 65_536 {
        return false;
    }
    let sample_len = 16_384usize;
    let step = (data.len() - sample_len) / 3;
    let mut total_in = 0usize;
    let mut total_out = 0usize;
    for i in 0..4 {
        let start = (i * step).min(data.len() - sample_len);
        let slice = &data[start..start + sample_len];
        let comp = lz4_flex::block::compress(slice);
        total_in += sample_len;
        total_out += comp.len();
    }
    total_out * 1000 >= total_in * 985
}

/// Ultra-fast wire pre-shrink using reusable thread-local Zstd Level 1.
pub fn wire_shrink_zstd1(input: &[u8]) -> Result<Vec<u8>> {
    ZSTD_WIRE_CCTX.with(|cell| {
        let mut cctx = cell.borrow_mut();
        cctx.reset(zstd_safe::ResetDirective::SessionOnly)
            .map_err(|e| anyhow::anyhow!("wire zstd1 reset: {}", zstd_safe::get_error_name(e)))?;
        cctx.set_parameter(zstd_safe::CParameter::CompressionLevel(1))
            .map_err(|e| anyhow::anyhow!("wire zstd1 level: {}", zstd_safe::get_error_name(e)))?;
        cctx.set_parameter(zstd_safe::CParameter::ChecksumFlag(false))
            .map_err(|e| anyhow::anyhow!("wire zstd1 csum: {}", zstd_safe::get_error_name(e)))?;
        cctx.set_parameter(zstd_safe::CParameter::ContentSizeFlag(true))
            .map_err(|e| anyhow::anyhow!("wire zstd1 size: {}", zstd_safe::get_error_name(e)))?;

        let bound = zstd_safe::compress_bound(input.len());
        let mut out = vec![0u8; bound];
        let written = cctx
            .compress2(&mut out, input)
            .map_err(|e| anyhow::anyhow!("wire zstd1 compress: {}", zstd_safe::get_error_name(e)))?;
        out.truncate(written);
        Ok(out)
    })
}

pub fn wire_expand_lz4(input: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    if input.len() < 4 {
        bail!("truncated lz4 block");
    }
    let declared = u32::from_le_bytes(input[0..4].try_into().unwrap()) as usize;
    if declared > MAX_DECODE_MEM_BYTES || (expected_len > 0 && declared != expected_len) {
        bail!(
            "lz4 declared size {} invalid (expected {}, cap {})",
            declared,
            expected_len,
            MAX_DECODE_MEM_BYTES
        );
    }
    lz4_flex::block::decompress_size_prepended(input)
        .map_err(|e| anyhow::anyhow!("lz4 decompress failed: {}", e))
}

pub fn wire_expand_zstd1(input: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    ZSTD_WIRE_DCTX.with(|cell| {
        let mut dctx = cell.borrow_mut();
        let mut out = vec![0u8; expected_len];
        let written = dctx
            .decompress(&mut out, input)
            .map_err(|e| anyhow::anyhow!("wire zstd1 expand: {}", zstd_safe::get_error_name(e)))?;
        out.truncate(written);
        Ok(out)
    })
}

/// Compress a single independent slab with any of the 6 supported codecs.
pub fn compress_block(codec: CodecId, level: i32, input: &[u8]) -> Result<Vec<u8>> {
    let level = codec.clamp_level(level);
    match codec {
        CodecId::Raw => Ok(input.to_vec()),
        CodecId::Zstd => ZSTD_CCTX.with(|cell| {
            let mut cctx = cell.borrow_mut();
            cctx.reset(zstd_safe::ResetDirective::SessionOnly)
                .map_err(|e| anyhow::anyhow!("zstd reset failed: {}", zstd_safe::get_error_name(e)))?;
            cctx.set_parameter(zstd_safe::CParameter::CompressionLevel(level))
                .map_err(|e| anyhow::anyhow!("zstd level failed: {}", zstd_safe::get_error_name(e)))?;
            cctx.set_parameter(zstd_safe::CParameter::ChecksumFlag(true))
                .map_err(|e| anyhow::anyhow!("zstd checksum flag failed: {}", zstd_safe::get_error_name(e)))?;
            cctx.set_parameter(zstd_safe::CParameter::ContentSizeFlag(true))
                .map_err(|e| anyhow::anyhow!("zstd content size flag failed: {}", zstd_safe::get_error_name(e)))?;
            if input.len() >= 1024 * 1024 {
                let _ = cctx.set_parameter(zstd_safe::CParameter::EnableLongDistanceMatching(true));
                let _ = cctx.set_parameter(zstd_safe::CParameter::WindowLog(25));
            }

            let bound = zstd_safe::compress_bound(input.len());
            let mut out = vec![0u8; bound];
            let written = cctx
                .compress2(&mut out, input)
                .map_err(|e| anyhow::anyhow!("zstd compress2 failed: {}", zstd_safe::get_error_name(e)))?;
            out.truncate(written);
            Ok(out)
        }),
        CodecId::Lzma2 => {
            let mut encoder = xz2::bufread::XzEncoder::new(input, level as u32);
            let mut out = Vec::with_capacity(input.len() / 2 + 1024);
            encoder.read_to_end(&mut out)?;
            Ok(out)
        }
        CodecId::Lzma2Bcj => {
            let mut filters = xz2::stream::Filters::new();
            filters.x86();
            let opts = xz2::stream::LzmaOptions::new_preset(level as u32)
                .map_err(|e| anyhow::anyhow!("lzma2-bcj preset failed: {}", e))?;
            filters.lzma2(&opts);
            let stream = xz2::stream::Stream::new_stream_encoder(&filters, xz2::stream::Check::Crc64)
                .map_err(|e| anyhow::anyhow!("lzma2-bcj encoder init failed: {}", e))?;
            let mut encoder = xz2::bufread::XzEncoder::new_stream(input, stream);
            let mut out = Vec::with_capacity(input.len() / 2 + 1024);
            encoder.read_to_end(&mut out)?;
            Ok(out)
        }
        CodecId::Bzip3 => {
            let bs_mib = (level as u32).clamp(1, 32);
            // Match block size cleanly to slab length to avoid wasting RAM on small tail slabs
            let slab_mib = ((input.len() + 1_048_575) / 1_048_576).max(1) as u32;
            let eff_mib = bs_mib.min(slab_mib).max(1);
            let block_size = bzip3::BlockSize::mib(eff_mib)
                .unwrap_or_else(|| bzip3::BlockSize::mib(8).unwrap());
            let mut encoder = bzip3::read::Bz3Encoder::new(input, block_size)
                .map_err(|e| anyhow::anyhow!("bzip3 encoder init failed: {}", e))?;
            let mut out = Vec::with_capacity(input.len() / 2 + 1024);
            encoder.read_to_end(&mut out)?;
            Ok(out)
        }
        CodecId::Ppmd => {
            let order = (level as u32).clamp(4, 12);
            let mem_size: u32 = 32 * 1024 * 1024;
            let mut out = Vec::with_capacity(input.len() / 2 + 1024);
            // Prepend 5-byte PPMd7 header: [order:1][mem_size:4 LE]
            out.push(order as u8);
            out.extend_from_slice(&mem_size.to_le_bytes());
            {
                let mut enc = ppmd_rust::Ppmd7Encoder::new(&mut out, order, mem_size)
                    .map_err(|e| anyhow::anyhow!("ppmd7 encoder init failed: {}", e))?;
                enc.write_all(input)?;
                enc.finish(true)?;
            }
            Ok(out)
        }
        CodecId::Lz4 => Ok(lz4_flex::block::compress_prepend_size(input)),
    }
}

/// Decompress a single independent slab into an exact-sized output buffer.
pub fn decompress_block(codec: CodecId, input: &[u8], expected_orig_len: usize) -> Result<Vec<u8>> {
    match codec {
        CodecId::Raw => {
            if input.len() != expected_orig_len {
                bail!(
                    "raw block size mismatch: got {}, expected {}",
                    input.len(),
                    expected_orig_len
                );
            }
            Ok(input.to_vec())
        }
        CodecId::Zstd => ZSTD_DCTX.with(|cell| {
            let mut dctx = cell.borrow_mut();
            let _ = dctx.set_parameter(zstd_safe::DParameter::WindowLogMax(27));
            let mut out = vec![0u8; expected_orig_len];
            let written = dctx
                .decompress(&mut out, input)
                .map_err(|e| anyhow::anyhow!("zstd decompress failed: {}", zstd_safe::get_error_name(e)))?;
            if written != expected_orig_len {
                bail!(
                    "zstd decompressed size mismatch: got {}, expected {}",
                    written,
                    expected_orig_len
                );
            }
            Ok(out)
        }),
        CodecId::Lzma2 | CodecId::Lzma2Bcj => {
            // Standard XZ stream header self-describes BCJ + LZMA2 filter chain!
            let mut decoder = xz2::bufread::XzDecoder::new(input);
            let mut out = Vec::with_capacity(expected_orig_len);
            decoder.read_to_end(&mut out)?;
            if out.len() != expected_orig_len {
                bail!(
                    "lzma2 decompressed size mismatch: got {}, expected {}",
                    out.len(),
                    expected_orig_len
                );
            }
            Ok(out)
        }
        CodecId::Bzip3 => {
            // Validate BZ3v1 header block size BEFORE allocating to block OOM DoS (BZ3v1: 5B magic + 4B LE block_size)
            if input.len() < 9 || &input[0..5] != b"BZ3v1" {
                bail!("invalid bzip3 frame header");
            }
            let declared_blk = u32::from_le_bytes(input[5..9].try_into().unwrap()) as usize;
            if declared_blk == 0 || declared_blk > MAX_DECODE_MEM_BYTES {
                bail!(
                    "bzip3 declared block size {} exceeds hard safety limit {}",
                    declared_blk,
                    MAX_DECODE_MEM_BYTES
                );
            }
            let mut decoder = bzip3::read::Bz3Decoder::new(input)
                .map_err(|e| anyhow::anyhow!("bzip3 decoder init failed: {}", e))?;
            let mut out = Vec::with_capacity(expected_orig_len);
            decoder.read_to_end(&mut out)?;
            if out.len() != expected_orig_len {
                bail!(
                    "bzip3 decompressed size mismatch: got {}, expected {}",
                    out.len(),
                    expected_orig_len
                );
            }
            Ok(out)
        }
        CodecId::Ppmd => {
            if input.len() < 5 {
                bail!("truncated ppmd7 block");
            }
            let order = input[0] as u32;
            let mem_size = u32::from_le_bytes(input[1..5].try_into().unwrap());
            if !(2..=16).contains(&order) {
                bail!("ppmd7 order {} outside safe range 2..=16", order);
            }
            if (mem_size as usize) < 1024 || (mem_size as usize) > MAX_DECODE_MEM_BYTES {
                bail!(
                    "ppmd7 declared memory {} outside safe limit 1 KiB..={} MiB",
                    mem_size,
                    MAX_DECODE_MEM_BYTES / (1024 * 1024)
                );
            }
            let mut dec = ppmd_rust::Ppmd7Decoder::new(&input[5..], order, mem_size)
                .map_err(|e| anyhow::anyhow!("ppmd7 decoder init failed: {}", e))?;
            let mut out = vec![0u8; expected_orig_len];
            dec.read_exact(&mut out)?;
            Ok(out)
        }
        CodecId::Lz4 => {
            let out = wire_expand_lz4(input, expected_orig_len)?;
            if out.len() != expected_orig_len {
                bail!(
                    "lz4 decompressed size mismatch: got {}, expected {}",
                    out.len(),
                    expected_orig_len
                );
            }
            Ok(out)
        }
    }
}
