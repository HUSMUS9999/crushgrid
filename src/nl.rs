use anyhow::{Result, bail};
use std::path::Path;

/// Deterministic, offline natural-language intent parser for `squiz-archive do "<request>"`.
/// Translates plain-English requests into exact standard CLI arguments so beginners don't
/// have to memorize codecs, presets, or flags, while always displaying the resolved command.
pub fn parse_natural_command(prompt: &str) -> Result<Vec<String>> {
    let raw = prompt.trim();
    if raw.is_empty() {
        bail!("empty natural-language request; example: squiz-archive do \"compress ./folder as small as possible\"");
    }

    let tokens = tokenize_preserving_quotes(raw);
    // Match verbs/keywords ONLY against non-path prose words so folder names like
    // `/home/user/shared-compress-decompress/src` never falsely trigger `decompress`!
    let prose_words: Vec<String> = tokens
        .iter()
        .filter(|t| !t.contains('/') && !t.contains('\\') && !Path::new(t).exists())
        .map(|t| t.to_ascii_lowercase())
        .collect();
    let prose = prose_words.join(" ");

    // 1. Detect primary action intent on prose words only
    let is_doctor = contains_any(&prose, &["doctor", "diagnose", "check system", "health", "audit"]);
    let is_init = contains_any(&prose, &["init", "setup cluster", "configure cluster", "create config"]);
    let is_net_bench = contains_any(&prose, &["net bench", "network speed", "bandwidth test", "test network", "wire speed"]);
    let is_bench = !is_net_bench && contains_any(&prose, &["benchmark", "bench", "compare speed"]);
    let is_probe = contains_any(&prose, &["probe", "check nodes", "check cluster", "list nodes", "show devices", "check devices"]);
    let is_worker = contains_any(&prose, &["start worker", "run worker", "join cluster", "listen as worker"]);
    let is_inspect = contains_any(&prose, &["inspect", "list files", "what is inside", "show contents", "info about"]);
    let is_extract = has_word(&prose_words, &["extract", "unpack", "decompress", "unzip", "restore"])
        || prose.contains("open archive");
    let is_compress = has_word(&prose_words, &["compress", "pack", "archive", "shrink", "squeeze", "backup", "zip"]);

    if is_doctor {
        return Ok(vec!["doctor".into()]);
    }
    if is_init {
        return Ok(vec!["init".into()]);
    }
    if is_probe {
        return Ok(vec!["probe".into()]);
    }
    if is_net_bench {
        return Ok(vec!["net-bench".into()]);
    }

    // Extract optional resource modifiers: threads/cpu%, mem/ram, output path, exclude, pick, local-only
    let cpu_spec = extract_cpu_spec(&tokens);
    let mem_spec = extract_mem_spec(&tokens);
    let output_path = extract_output_path(&tokens);
    let excludes = extract_excludes(&tokens);
    let want_pick = contains_any(&prose, &["pick", "choose device", "select device", "interactive"]);
    let want_local = contains_any(&prose, &["only local", "local only", "locally", "this pc only", "without remote"]);
    let want_list = has_word(&prose_words, &["list", "files", "contents"]);

    if is_worker {
        let mut args = vec!["worker".to_string()];
        if let Some(ref c) = cpu_spec {
            if let Ok(n) = c.parse::<usize>() {
                args.push("--max-threads".into());
                args.push(n.to_string());
            }
        }
        if let Some(ref m) = mem_spec {
            args.push("--max-mem".into());
            args.push(m.clone());
        }
        return Ok(args);
    }

    // Extract input path candidate (first token that looks like a path or exists on disk, excluding output/exclude targets)
    let input_path = extract_input_path(&tokens, output_path.as_deref(), &excludes);

    if is_inspect {
        let inp = input_path.ok_or_else(|| anyhow::anyhow!("could not find an archive path in: \"{}\"", raw))?;
        let mut args = vec!["inspect".into(), inp];
        if want_list {
            args.push("--list".into());
        }
        return Ok(args);
    }

    if is_extract {
        let inp = input_path.ok_or_else(|| anyhow::anyhow!("could not find an archive path to extract in: \"{}\"", raw))?;
        let is_zst = inp.to_ascii_lowercase().ends_with(".zst");
        let sub = if is_zst { "decompress" } else { "unpack" };
        let mut args = vec![sub.into(), inp];
        if let Some(out) = output_path {
            args.push("-o".into());
            args.push(out);
        }
        append_common_resource_flags(&mut args, cpu_spec.as_deref(), mem_spec.as_deref(), want_pick, want_local);
        return Ok(args);
    }

    if is_bench || is_compress {
        let inp = input_path.ok_or_else(|| {
            anyhow::anyhow!(
                "could not identify a file or directory path in: \"{}\"\nTip: quote paths with spaces, e.g. squiz-archive do \"compress ./my_folder as small as possible\"",
                raw
            )
        })?;

        let preset = detect_preset(&prose);
        let explicit_codec = detect_explicit_codec(&prose);

        let sub = if is_bench {
            "bench"
        } else if Path::new(&inp).is_dir()
            || contains_any(&prose, &["folder", "directory", "dir", "backup", "pack"])
        {
            "pack"
        } else {
            "compress"
        };

        let mut args = vec![sub.into(), inp];
        if sub != "bench" {
            if let Some(out) = output_path {
                args.push("-o".into());
                args.push(out);
            }
        }
        if let Some(p) = preset {
            args.push("--preset".into());
            args.push(p.into());
        }
        if let Some(c) = explicit_codec {
            args.push("--codec".into());
            args.push(c.into());
        }
        if sub == "pack" {
            for ex in excludes {
                args.push("--exclude".into());
                args.push(ex);
            }
        }
        append_common_resource_flags(&mut args, cpu_spec.as_deref(), mem_spec.as_deref(), want_pick, want_local);
        return Ok(args);
    }

    bail!(
        "could not understand request: \"{}\"\nExamples:\n  squiz-archive do \"compress ./backups as small as possible\"\n  squiz-archive do \"fast backup of ./logs using 50% cpu\"\n  squiz-archive do \"extract backups.sqz into ./restored\"\n  squiz-archive do \"check cluster nodes\"",
        raw
    );
}

fn append_common_resource_flags(
    args: &mut Vec<String>,
    cpu_spec: Option<&str>,
    mem_spec: Option<&str>,
    want_pick: bool,
    want_local: bool,
) {
    if let Some(m) = mem_spec {
        args.push("--mem-limit".into());
        args.push(m.to_string());
    }
    if let Some(c) = cpu_spec {
        args.push("--node".into());
        args.push(format!("local:threads={}", c));
    }
    if want_pick {
        args.push("--pick".into());
    }
    if want_local {
        args.push("--local".into());
    }
}

fn detect_preset(lower: &str) -> Option<&'static str> {
    if contains_any(lower, &["maximum", "as small as possible", "smallest", "ultra", "max compression", "extreme", "best ratio", "highest"]) {
        Some("max")
    } else if contains_any(lower, &["small", "compact", "high compression", "tight", "smart"]) {
        Some("small")
    } else if contains_any(lower, &["fastest", "fast", "quick", "speed", "hurry"]) {
        Some("fast")
    } else if contains_any(lower, &["balanced", "normal", "default"]) {
        Some("balanced")
    } else {
        None
    }
}

fn detect_explicit_codec(lower: &str) -> Option<&'static str> {
    if lower.contains("lzma2-bcj") || lower.contains("bcj") {
        Some("lzma2-bcj")
    } else if lower.contains("bzip3") || lower.contains("bz3") {
        Some("bzip3")
    } else if lower.contains("ppmd") {
        Some("ppmd")
    } else if lower.contains("lzma2") || lower.contains("lzma") || lower.contains("xz") {
        Some("lzma2")
    } else if lower.contains("lz4") {
        Some("lz4")
    } else if lower.contains("zstd") || lower.contains("zst") {
        Some("zstd")
    } else {
        None
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

fn has_word(words: &[String], needles: &[&str]) -> bool {
    words.iter().any(|w| needles.iter().any(|n| w == n))
}

fn tokenize_preserving_quotes(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for ch in s.chars() {
        match quote {
            Some(q) if ch == q => {
                quote = None;
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            Some(_) => cur.push(ch),
            None if ch == '"' || ch == '\'' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                quote = Some(ch);
            }
            None if ch.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            None => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn extract_cpu_spec(tokens: &[String]) -> Option<String> {
    for i in 0..tokens.len().saturating_sub(1) {
        let next = tokens[i + 1].to_ascii_lowercase();
        if matches!(next.as_str(), "cpu" | "threads" | "thread" | "cores" | "core") {
            let v = tokens[i].trim_end_matches(',');
            if v.ends_with('%') && v[..v.len() - 1].parse::<u8>().is_ok() {
                return Some(v.to_string());
            }
            if v.parse::<usize>().is_ok() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn extract_mem_spec(tokens: &[String]) -> Option<String> {
    for i in 0..tokens.len().saturating_sub(1) {
        let next = tokens[i + 1].to_ascii_lowercase();
        if matches!(next.as_str(), "ram" | "memory" | "mem") {
            let v = tokens[i].trim_end_matches(',').to_ascii_uppercase();
            if v.ends_with('G') || v.ends_with("GB") || v.ends_with('M') || v.ends_with("MB") {
                return Some(v);
            }
        }
    }
    None
}

fn extract_output_path(tokens: &[String]) -> Option<String> {
    for i in 0..tokens.len().saturating_sub(1) {
        let w = tokens[i].to_ascii_lowercase();
        if matches!(w.as_str(), "into" | "to" | "as" | "output" | "-o") {
            let cand = &tokens[i + 1];
            let cl = cand.to_ascii_lowercase();
            // Avoid matching "as small as possible" or "to max"
            if !matches!(cl.as_str(), "small" | "fast" | "max" | "balanced" | "high" | "a" | "an" | "the")
                && (cand.contains('/') || cand.contains('\\') || cand.contains('.') || i + 1 == tokens.len() - 1)
            {
                return Some(cand.clone());
            }
        }
    }
    None
}

fn extract_excludes(tokens: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..tokens.len().saturating_sub(1) {
        let w = tokens[i].to_ascii_lowercase();
        if matches!(w.as_str(), "exclude" | "excluding" | "skip" | "skipping" | "ignore") {
            out.push(tokens[i + 1].trim_end_matches(',').to_string());
        }
    }
    out
}

fn extract_input_path(tokens: &[String], output: Option<&str>, excludes: &[String]) -> Option<String> {
    // 1. Prefer an existing filesystem path first!
    for tok in tokens {
        if output == Some(tok.as_str()) || excludes.iter().any(|e| e == tok) {
            continue;
        }
        if Path::new(tok).exists() {
            return Some(tok.clone());
        }
    }
    // 2. Otherwise match path-like token (contains /, \, :, or file extension)
    for tok in tokens {
        if output == Some(tok.as_str()) || excludes.iter().any(|e| e == tok) {
            continue;
        }
        let tl = tok.to_ascii_lowercase();
        if matches!(tl.as_str(), "compress" | "pack" | "archive" | "extract" | "unpack" | "decompress" | "inspect") {
            continue;
        }
        if tok.contains('/') || tok.contains('\\') || tok.contains(':') || (tok.contains('.') && tok.len() > 2) {
            return Some(tok.clone());
        }
    }
    None
}
