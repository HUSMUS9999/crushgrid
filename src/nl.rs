use anyhow::{Result, bail};
use std::path::Path;

/// Format resolved CLI arguments safely for display (quoting arguments containing spaces).
pub fn format_resolved_command(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.contains(' ') || a.contains('\t') {
                format!("\"{}\"", a)
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Deterministic, offline natural-language intent parser for `squiz-archive do <request...>`.
/// Preserves shell token boundaries when multiple arguments are passed, and tokenizes quoted
/// strings when a single quoted sentence is passed.
pub fn parse_natural_tokens(raw_args: &[String]) -> Result<Vec<String>> {
    let tokens: Vec<String> = if raw_args.len() == 1 {
        tokenize_preserving_quotes(&raw_args[0])
    } else {
        raw_args.to_vec()
    };

    if tokens.is_empty() {
        bail!("empty natural-language request; example: squiz-archive do \"compress ./folder as small as possible\"");
    }

    // 1. Extract modifiers & explicit targets FIRST so filenames like `audit.log` or `init.sql`
    //    cannot hijack prose verb detection.
    let cpu_spec = extract_cpu_spec(&tokens);
    let mem_spec = extract_mem_spec(&tokens);
    let output_path = extract_output_path(&tokens);
    let excludes = extract_excludes(&tokens);
    let input_path = extract_input_path(&tokens, output_path.as_deref(), &excludes);

    // Build clean prose words excluding paths, filenames (containing / \ : or .), and modifier targets.
    let prose_words: Vec<String> = tokens
        .iter()
        .filter(|t| {
            let s = t.as_str();
            if input_path.as_deref() == Some(s)
                || output_path.as_deref() == Some(s)
                || excludes.iter().any(|e| e == s)
            {
                return false;
            }
            !looks_like_path(s)
        })
        .map(|t| t.trim_matches(|c: char| c == ',' || c == ';').to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    let prose = prose_words.join(" ");

    // 2. Detect primary action intent using whole-word and multi-word phrase matching
    let is_doctor = has_word(&prose_words, &["doctor", "diagnose", "health"])
        || contains_phrase(&prose, &["check system", "system check"]);
    let is_init = has_word(&prose_words, &["init"])
        || contains_phrase(&prose, &["setup cluster", "configure cluster", "create config"]);
    let is_net_bench = contains_phrase(
        &prose,
        &["net bench", "net-bench", "network speed", "bandwidth test", "test network", "wire speed"],
    );
    let is_bench = !is_net_bench
        && (has_word(&prose_words, &["benchmark", "bench"]) || contains_phrase(&prose, &["compare speed"]));
    let is_probe = has_word(&prose_words, &["probe"])
        || contains_phrase(&prose, &["check nodes", "check cluster", "list nodes", "show devices", "check devices"]);
    let is_worker = contains_phrase(&prose, &["start worker", "run worker", "join cluster", "listen as worker"]);
    let is_inspect = has_word(&prose_words, &["inspect"])
        || contains_phrase(&prose, &["what is inside", "show contents", "info about"])
        || (contains_phrase(&prose, &["list files"]) && input_path.is_some());
    let is_decompress_verb = has_word(&prose_words, &["decompress"]);
    let is_extract = is_decompress_verb
        || has_word(&prose_words, &["extract", "unpack", "unzip", "restore"])
        || contains_phrase(&prose, &["open archive"]);
    let is_compress = has_word(
        &prose_words,
        &["compress", "pack", "archive", "shrink", "squeeze", "backup", "zip"],
    );

    if is_doctor && !is_compress && !is_extract {
        return Ok(vec!["doctor".into()]);
    }
    if is_init && !is_compress && !is_extract {
        return Ok(vec!["init".into()]);
    }
    if is_probe && !is_compress && !is_extract {
        return Ok(vec!["probe".into()]);
    }
    if is_net_bench {
        return Ok(vec!["net-bench".into()]);
    }

    let want_pick = has_word(&prose_words, &["pick", "interactive"])
        || contains_phrase(&prose, &["choose device", "select device", "choose devices", "select devices"]);
    let want_local = has_word(&prose_words, &["locally"])
        || contains_phrase(&prose, &["only local", "local only", "this pc only", "without remote"]);
    let want_list = has_word(&prose_words, &["list", "files", "contents"]);

    if is_worker {
        let mut args = vec!["worker".to_string()];
        if let Some(ref c) = cpu_spec {
            let max_t = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
            let resolved = if let Some(pct) = c.strip_suffix('%') {
                pct.parse::<usize>()
                    .ok()
                    .map(|p| ((max_t * p.clamp(1, 100)) / 100).max(1))
            } else {
                c.parse::<usize>().ok().map(|n| n.clamp(1, max_t))
            };
            if let Some(n) = resolved {
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

    if is_inspect {
        let inp = input_path.ok_or_else(|| anyhow::anyhow!("could not find an archive path to inspect"))?;
        let mut args = vec!["inspect".into(), inp];
        if want_list {
            args.push("--list".into());
        }
        return Ok(args);
    }

    if is_extract {
        let inp = input_path.ok_or_else(|| anyhow::anyhow!("could not find an archive path to extract"))?;
        let lower_inp = inp.to_ascii_lowercase();
        let sub = if lower_inp.ends_with(".zst") || is_decompress_verb {
            "decompress"
        } else {
            "unpack"
        };
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
                "could not identify a file or directory path\nTip: quote paths with spaces, e.g. squiz-archive do \"compress ./my_folder as small as possible\""
            )
        })?;

        let preset = detect_preset(&prose, &prose_words);
        let explicit_codec = detect_explicit_codec(&prose_words);

        let sub = if is_bench {
            "bench"
        } else if Path::new(&inp).is_dir()
            || has_word(&prose_words, &["folder", "directory", "dir", "backup", "pack"])
            || (!Path::new(&inp).is_file() && !has_file_extension(&inp))
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
        "could not understand request\nExamples:\n  squiz-archive do \"compress ./backups as small as possible\"\n  squiz-archive do \"fast backup of ./logs using 50% cpu\"\n  squiz-archive do \"extract backups.sqz into ./restored\"\n  squiz-archive do \"check cluster nodes\""
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

fn detect_preset(prose: &str, words: &[String]) -> Option<&'static str> {
    if contains_phrase(
        prose,
        &["as small as possible", "max compression", "best ratio", "highest compression"],
    ) || has_word(words, &["maximum", "smallest", "ultra", "extreme"])
    {
        Some("max")
    } else if contains_phrase(prose, &["high compression"])
        || has_word(words, &["small", "compact", "tight", "smart"])
    {
        Some("small")
    } else if has_word(words, &["fastest", "fast", "quick", "speed", "hurry"]) {
        Some("fast")
    } else if has_word(words, &["balanced", "normal", "default"]) {
        Some("balanced")
    } else {
        None
    }
}

fn detect_explicit_codec(words: &[String]) -> Option<&'static str> {
    if has_word(words, &["lzma2-bcj", "bcj"]) {
        Some("lzma2-bcj")
    } else if has_word(words, &["bzip3", "bz3"]) {
        Some("bzip3")
    } else if has_word(words, &["ppmd", "ppmd7"]) {
        Some("ppmd")
    } else if has_word(words, &["lzma2", "lzma", "xz"]) {
        Some("lzma2")
    } else if has_word(words, &["lz4"]) {
        Some("lz4")
    } else if has_word(words, &["zstd", "zst"]) {
        Some("zstd")
    } else {
        None
    }
}

fn contains_phrase(haystack: &str, phrases: &[&str]) -> bool {
    phrases.iter().any(|p| haystack.contains(p))
}

fn has_word(words: &[String], needles: &[&str]) -> bool {
    words.iter().any(|w| needles.iter().any(|n| w == n))
}

fn looks_like_path(tok: &str) -> bool {
    if tok.starts_with('-') {
        return false;
    }
    if tok.contains('/') || tok.contains('\\') {
        return true;
    }
    // Windows drive prefix like D:foo or C:
    if tok.len() >= 2 && tok.as_bytes()[0].is_ascii_alphabetic() && tok.as_bytes()[1] == b':' {
        return true;
    }
    has_file_extension(tok)
}

fn has_file_extension(tok: &str) -> bool {
    if let Some((stem, ext)) = tok.rsplit_once('.') {
        !stem.is_empty()
            && !ext.is_empty()
            && ext.len() <= 8
            && ext.chars().all(|c| c.is_ascii_alphanumeric())
    } else {
        false
    }
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
        let next = tokens[i + 1].trim_end_matches(',').to_ascii_lowercase();
        if matches!(next.as_str(), "cpu" | "threads" | "thread" | "cores" | "core") {
            let v = tokens[i].trim_end_matches(',');
            if let Some(pct) = v.strip_suffix('%') {
                if pct.parse::<u8>().map(|p| (1..=100).contains(&p)).unwrap_or(false) {
                    return Some(v.to_string());
                }
            } else if v.parse::<usize>().map(|n| n >= 1).unwrap_or(false) {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn is_valid_mem_size_token(v: &str) -> bool {
    let upper = v.to_ascii_uppercase();
    for suffix in ["GIB", "MIB", "KIB", "GB", "MB", "KB", "G", "M", "K"] {
        if let Some(num) = upper.strip_suffix(suffix) {
            return !num.is_empty() && num.parse::<f64>().map(|x| x > 0.0 && x.is_finite()).unwrap_or(false);
        }
    }
    false
}

fn extract_mem_spec(tokens: &[String]) -> Option<String> {
    for i in 0..tokens.len().saturating_sub(1) {
        let next = tokens[i + 1].trim_end_matches(',').to_ascii_lowercase();
        if matches!(next.as_str(), "ram" | "memory" | "mem") {
            let v = tokens[i].trim_end_matches(',');
            if is_valid_mem_size_token(v) {
                return Some(v.to_ascii_uppercase());
            }
        }
    }
    None
}

const NON_OUTPUT_WORDS: &[&str] = &[
    "small", "smallest", "possible", "fast", "fastest", "max", "maximum", "balanced", "high",
    "highest", "compact", "ultra", "best", "extreme", "tight", "default", "normal", "locally",
    "local", "a", "an", "the", "my", "this", "all", "speed", "size", "ratio", "compression",
];

fn extract_output_path(tokens: &[String]) -> Option<String> {
    for i in 0..tokens.len().saturating_sub(1) {
        let w = tokens[i].to_ascii_lowercase();
        if matches!(w.as_str(), "into" | "to" | "as" | "output" | "-o") {
            let cand = tokens[i + 1].trim_end_matches(',');
            let cl = cand.to_ascii_lowercase();
            if NON_OUTPUT_WORDS.contains(&cl.as_str()) {
                continue;
            }
            // For "as", require an explicit path/filename so English phrases like "as small as possible" never match!
            if w == "as" && !looks_like_path(cand) {
                continue;
            }
            if looks_like_path(cand) || matches!(w.as_str(), "into" | "output" | "-o") {
                return Some(cand.to_string());
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
    // 1. Prefer an existing filesystem path first
    for tok in tokens {
        if output == Some(tok.as_str()) || excludes.iter().any(|e| e == tok) {
            continue;
        }
        if Path::new(tok).exists() {
            return Some(tok.clone());
        }
    }
    // 2. Otherwise match explicit path-like token
    for tok in tokens {
        if output == Some(tok.as_str()) || excludes.iter().any(|e| e == tok) {
            continue;
        }
        if looks_like_path(tok) {
            return Some(tok.clone());
        }
    }
    None
}
