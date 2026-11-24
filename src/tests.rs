use crate::archiver::safe_join_unpack;
use crate::codec::{
    CodecId, Preset, SlabKind, classify_slab_content, compress_block, decompress_block,
};
use crate::container::{ContainerFormat, decode_file_manifest, read_manifest};
use crate::nl::{format_resolved_command, parse_natural_tokens};
use crate::protocol::{
    FrameHeader, MsgType, SecurityMode, WorkerCaps, client_handshake, server_handshake,
};
use crate::resource::{NodeSpec, ThreadAlloc, load_cluster_file};
use crate::scheduler::{
    CompressParams, DecompressParams, PackParams, ScheduleMode, probe_nodes, run_compress,
    run_decompress, run_pack, run_unpack,
};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread;

fn temp_test_dir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "squiz_archive_test_{}_{}",
        tag,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn all_six_codecs_roundtrip_edge_sizes() {
    let codecs = [
        CodecId::Zstd,
        CodecId::Bzip3,
        CodecId::Ppmd,
        CodecId::Lzma2,
        CodecId::Lzma2Bcj,
        CodecId::Lz4,
    ];
    let sizes = [1usize, 12, 4096, 64_512, 102_400];

    for &codec in &codecs {
        let lvl = codec.default_level();
        for &sz in &sizes {
            // Mix structured ASCII + binary pattern
            let mut data = Vec::with_capacity(sz);
            for i in 0..sz {
                data.push(((i * 31 + (i >> 4)) & 0x7F) as u8);
            }
            let comp = compress_block(codec, lvl, &data)
                .unwrap_or_else(|e| panic!("compress failed for {:?} sz={}: {}", codec, sz, e));
            let dec = decompress_block(codec, &comp, data.len())
                .unwrap_or_else(|e| panic!("decompress failed for {:?} sz={}: {}", codec, sz, e));
            assert_eq!(data, dec, "roundtrip mismatch for {:?} sz={}", codec, sz);
        }

        // Also test high-entropy incompressible data (pseudo-random LCG)
        let mut x: u64 = 0xDEADBEEF_CAFEBABE;
        let mut rnd = vec![0u8; 70_000];
        for b in &mut rnd {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (x >> 33) as u8;
        }
        let comp = compress_block(codec, lvl, &rnd).unwrap();
        let dec = decompress_block(codec, &comp, rnd.len()).unwrap();
        assert_eq!(rnd, dec, "incompressible roundtrip mismatch for {:?}", codec);
    }
}

#[test]
fn reject_malicious_decoder_oom_headers() {
    // 1. Crafted PPMd7 header requesting 4 GiB RAM
    let mut bad_ppmd = vec![8u8]; // order 8
    bad_ppmd.extend_from_slice(&u32::MAX.to_le_bytes());
    bad_ppmd.extend_from_slice(&[0u8; 32]);
    let err = decompress_block(CodecId::Ppmd, &bad_ppmd, 1024).unwrap_err();
    assert!(err.to_string().contains("outside safe limit"), "unexpected err: {}", err);

    // 2. Crafted PPMd7 invalid order 99
    let mut bad_order = vec![99u8];
    bad_order.extend_from_slice(&(1024 * 1024u32).to_le_bytes());
    bad_order.extend_from_slice(&[0u8; 32]);
    assert!(decompress_block(CodecId::Ppmd, &bad_order, 1024).is_err());

    // 3. Crafted Bzip3 header declaring 511 MiB block size
    let mut bad_bz3 = b"BZ3v1".to_vec();
    bad_bz3.extend_from_slice(&(511 * 1024 * 1024u32).to_le_bytes());
    bad_bz3.extend_from_slice(&[0u8; 32]);
    let err = decompress_block(CodecId::Bzip3, &bad_bz3, 1024).unwrap_err();
    assert!(err.to_string().contains("exceeds hard safety limit"), "unexpected err: {}", err);

    // 4. Crafted LZ4 size-prepended header declaring 4 GiB uncompressed output
    let mut bad_lz4 = u32::MAX.to_le_bytes().to_vec();
    bad_lz4.extend_from_slice(&[0u8; 32]);
    assert!(decompress_block(CodecId::Lz4, &bad_lz4, 1024).is_err());

    // 5. Crafted .sqz manifest claiming 500 GiB uncompressed size
    let mut bad_manifest = (500u64 * 1024 * 1024 * 1024).to_le_bytes().to_vec();
    bad_manifest.extend_from_slice(&[0u8; 32]);
    assert!(decode_file_manifest(&bad_manifest).is_err());
}

#[test]
fn utf8_and_executable_content_classification() {
    // Multilingual UTF-8 prose (French + Arabic + CJK) must classify as Text!
    let utf8_text = "Bonjour résumé naïve 日本語テスト مرحبا بالعالم hello world\n".repeat(100);
    assert_eq!(classify_slab_content(utf8_text.as_bytes()), SlabKind::Text);

    // ELF magic must classify as Executable
    let mut elf = vec![0x7F, b'E', b'L', b'F'];
    elf.extend_from_slice(&[0u8; 256]);
    assert_eq!(classify_slab_content(&elf), SlabKind::Executable);
}

#[test]
fn path_traversal_blocked_on_unpack() {
    let root = Path::new("/tmp/safe_dest");
    assert!(safe_join_unpack(root, "subdir/file.txt").is_ok());
    assert!(safe_join_unpack(root, "../escape.txt").is_err());
    assert!(safe_join_unpack(root, "a/../../escape.txt").is_err());
    assert!(safe_join_unpack(root, "/etc/passwd").is_err());
}

#[test]
fn sqz_v3_multicodec_pack_unpack_and_zst_roundtrip() {
    let dir = temp_test_dir("pack_roundtrip");
    let src = dir.join("src");
    fs::create_dir_all(src.join("nested")).unwrap();

    // Text, ELF-like binary, duplicate file, and high-entropy file
    let text = "fn main() { println!(\"hello UTF-8 café 日本語\"); }\n".repeat(4000);
    fs::write(src.join("main.rs"), &text).unwrap();
    fs::write(src.join("nested/copy.rs"), &text).unwrap();

    let mut fake_elf = vec![0x7F, b'E', b'L', b'F'];
    fake_elf.extend((0..120_000usize).map(|i| ((i * 13) & 0xFF) as u8));
    fs::write(src.join("app.elf"), &fake_elf).unwrap();

    let mut x: u64 = 123456789;
    let mut rnd = vec![0u8; 150_000];
    for b in &mut rnd {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        *b = (x >> 33) as u8;
    }
    fs::write(src.join("random.bin"), &rnd).unwrap();

    let arc = dir.join("out.sqz");
    let restored = dir.join("restored");
    let probed = probe_nodes(&[NodeSpec::local_default()], "", SecurityMode::Aead);

    run_pack(PackParams {
        source_dir: &src,
        output_path: &arc,
        excludes: &[],
        codec: CodecId::Lzma2,
        level: 6,
        preset: Preset::Small,
        auto_codec: true,
        block_size: Some(128 * 1024),
        mem_limit_bytes: 256 * 1024 * 1024,
        security: SecurityMode::Aead,
        schedule: ScheduleMode::LocalOnly,
        wire_codec: crate::protocol::WireCodec::Auto,
        hedge: false,
        dedup: true,
        entropy_bypass: true,
        token: "",
        nodes: &probed,
        quiet: true,
    })
    .unwrap();

    let mut f = fs::File::open(&arc).unwrap();
    let manifest = read_manifest(&mut f).unwrap();
    assert_eq!(manifest.format, ContainerFormat::Sqz);
    assert!(manifest.entries.iter().any(|e| e.slab_codec == CodecId::Bzip3));

    run_unpack(DecompressParams {
        input_path: &arc,
        output_path: &restored,
        mem_limit_bytes: 256 * 1024 * 1024,
        security: SecurityMode::Aead,
        schedule: ScheduleMode::LocalOnly,
        wire_codec: crate::protocol::WireCodec::Auto,
        hedge: false,
        verify: true,
        token: "",
        nodes: &probed,
        quiet: true,
    })
    .unwrap();

    assert_eq!(fs::read(src.join("main.rs")).unwrap(), fs::read(restored.join("main.rs")).unwrap());
    assert_eq!(fs::read(src.join("app.elf")).unwrap(), fs::read(restored.join("app.elf")).unwrap());
    assert_eq!(fs::read(src.join("random.bin")).unwrap(), fs::read(restored.join("random.bin")).unwrap());

    // Also verify single-file .zst seekable compress/decompress
    let zst_arc = dir.join("main.rs.zst");
    let zst_out = dir.join("main_restored.rs");
    run_compress(CompressParams {
        input_path: &src.join("main.rs"),
        output_path: &zst_arc,
        codec: CodecId::Zstd,
        level: 6,
        preset: Preset::Balanced,
        auto_codec: false,
        format: ContainerFormat::ZstdSeekable,
        block_size: Some(64 * 1024),
        mem_limit_bytes: 128 * 1024 * 1024,
        security: SecurityMode::Aead,
        schedule: ScheduleMode::LocalOnly,
        wire_codec: crate::protocol::WireCodec::Auto,
        hedge: false,
        dedup: false,
        entropy_bypass: false,
        token: "",
        nodes: &probed,
        quiet: true,
    })
    .unwrap();
    run_decompress(DecompressParams {
        input_path: &zst_arc,
        output_path: &zst_out,
        mem_limit_bytes: 128 * 1024 * 1024,
        security: SecurityMode::Aead,
        schedule: ScheduleMode::LocalOnly,
        wire_codec: crate::protocol::WireCodec::Auto,
        hedge: false,
        verify: true,
        token: "",
        nodes: &probed,
        quiet: true,
    })
    .unwrap();
    assert_eq!(fs::read(src.join("main.rs")).unwrap(), fs::read(&zst_out).unwrap());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn natural_language_parser_all_cases() {
    let parse1 = |s: &str| parse_natural_tokens(&[s.to_string()]).unwrap();

    // Quick-start example from `-h` & README: must NOT emit `-o possible`!
    let r = parse1("compress ./logs as small as possible");
    assert_eq!(r, vec!["pack", "./logs", "--preset", "max"]);

    // Must NOT emit `-o maximum`!
    let r = parse1("compress ./my_dir to maximum");
    assert_eq!(r, vec!["pack", "./my_dir", "--preset", "max"]);

    // Filename containing trigger keyword (`audit.log`) must NOT route to `doctor`!
    let r = parse1("compress audit.log");
    assert_eq!(r, vec!["compress", "audit.log"]);

    // `"big ram"` must NOT become `--mem-limit BIG`!
    let r = parse1("compress ./logs using big ram");
    assert!(!r.contains(&"--mem-limit".to_string()), "got {:?}", r);

    // Valid GiB memory + percentage CPU + locally
    let r = parse1("compress ./logs using 50% cpu and 2GiB ram locally");
    assert_eq!(
        r,
        vec!["pack", "./logs", "--mem-limit", "2GIB", "--node", "local:threads=50%", "--local"]
    );

    // Explicit `decompress foo.sqz` routes to `decompress` (single-file safe)
    let r = parse1("decompress foo.sqz into foo.bin");
    assert_eq!(r, vec!["decompress", "foo.sqz", "-o", "foo.bin"]);

    // `extract backup.sqz` routes to `unpack`
    let r = parse1("extract backup.sqz into ./restored");
    assert_eq!(r, vec!["unpack", "backup.sqz", "-o", "./restored"]);

    // Quoted Windows path with spaces preserved cleanly!
    let r = parse1("compress \"D:\\my folder\\data\" as small as possible into \"D:\\out dir\\backup.sqz\"");
    assert_eq!(
        r,
        vec!["pack", "D:\\my folder\\data", "-o", "D:\\out dir\\backup.sqz", "--preset", "max"]
    );
    assert!(format_resolved_command(&r).contains("\"D:\\my folder\\data\""));

    // Worker with percentage CPU resolves cleanly to integer `--max-threads`
    let r = parse1("start worker using 50% cpu and 4G ram");
    assert_eq!(r[0], "worker");
    assert!(r.contains(&"--max-threads".to_string()));
    assert!(r.contains(&"--max-mem".to_string()));
}

#[test]
fn protocol_post_auth_caps_and_aead_tamper_rejection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let caps = WorkerCaps {
        hostname: "secret-host".into(),
        os_arch: "linux/x86_64".into(),
        cpu_brand: "TestCPU".into(),
        total_threads: 16,
        max_threads: 8,
        avail_mem_mb: 8192,
        max_mem_mb: 4096,
    };

    // 1. Valid handshake + AEAD round-trip
    let caps_c = caps.clone();
    let srv = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let (mut c, _, _, _) = server_handshake(&mut s, "StrongSecretToken123!", false, &caps_c).unwrap();
        let mut buf = Vec::new();
        let hdr = c.read_frame_into(&mut s, &mut buf, 1024 * 1024).unwrap();
        assert_eq!(hdr.msg_type, MsgType::ProbeReq);
        assert_eq!(&buf, b"hello-aead");
    });

    let mut cli = TcpStream::connect(addr).unwrap();
    let (mut c, got_caps) = client_handshake(&mut cli, "StrongSecretToken123!", SecurityMode::Aead, 0, 4, 1024).unwrap();
    assert_eq!(got_caps.hostname, "secret-host");
    assert_eq!(got_caps.max_threads, 8);
    let mut payload = b"hello-aead".to_vec();
    c.write_frame(
        &mut cli,
        FrameHeader {
            msg_type: MsgType::ProbeReq,
            codec: 0,
            level: 0,
            flags: 0,
            chunk_id: 1,
            orig_len: 10,
            payload_len: 10,
            xxh3: 0,
        },
        &mut payload,
    )
    .unwrap();
    srv.join().unwrap();

    // 2. Wrong token must fail BEFORE receiving WorkerCaps
    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap();
    let srv2 = thread::spawn(move || {
        let (mut s, _) = listener2.accept().unwrap();
        let _ = server_handshake(&mut s, "StrongSecretToken123!", false, &caps);
    });
    let mut cli2 = TcpStream::connect(addr2).unwrap();
    let res = client_handshake(&mut cli2, "WrongToken999999!", SecurityMode::Aead, 0, 4, 1024);
    assert!(res.is_err());
    srv2.join().unwrap();
}

#[test]
fn cluster_config_quoted_hash_and_local_override() {
    let dir = temp_test_dir("cfg_parse");
    let cfg_path = dir.join("cluster.conf");
    fs::write(
        &cfg_path,
        "token = \"my#secret#token#1234\" # trailing comment\nsecurity = aead\nnode = local:threads=50%,mem=1G\n",
    )
    .unwrap();

    let cfg = load_cluster_file(&cfg_path).unwrap();
    assert_eq!(cfg.token.as_deref(), Some("my#secret#token#1234"));
    assert_eq!(cfg.nodes.len(), 1);

    // Verify `--local` preserves explicit `--node local:threads=50%`
    let rc = crate::resolve_cluster(
        None,
        true,
        &["local:threads=50%".to_string()],
        None,
        "",
        None,
        None,
        None,
        None,
        2,
    )
    .unwrap();
    assert_eq!(rc.specs.len(), 1);
    assert!(rc.specs[0].is_local);
    assert!(matches!(rc.specs[0].threads, ThreadAlloc::Percent(50)));

    let _ = fs::remove_dir_all(&dir);
}
