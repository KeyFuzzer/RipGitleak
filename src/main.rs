use aho_corasick::{AhoCorasick, MatchKind};
use clap::{Parser, ValueEnum};
use colored::*;
use fancy_regex::Regex;
use ignore::WalkBuilder;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;

use memmap2::Mmap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// Calculate Shannon entropy of a string
/// Higher entropy indicates more randomness, typical of cryptographic secrets
fn calculate_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut frequency_map = HashMap::new();
    let total_chars = text.len() as f64;

    // Count character frequencies
    for ch in text.chars() {
        *frequency_map.entry(ch).or_insert(0) += 1;
    }

    // Calculate entropy
    let entropy = frequency_map
        .values()
        .map(|&count| {
            let probability = count as f64 / total_chars;
            -probability * probability.log2()
        })
        .sum::<f64>();

    entropy
}

/// Check if a matched text has sufficient entropy to be considered a real secret
/// This helps filter out false positives like variable names, function names, etc.
fn has_sufficient_entropy(text: &str, pattern_name: &str) -> bool {
    let entropy = calculate_entropy(text);

    // Different entropy thresholds based on pattern type
    match pattern_name {
        // API keys and tokens typically have high entropy
        name if name.contains("API Key") || name.contains("Token") => entropy >= 3.6,
        // Generic secrets
        name if name.contains("Secret") => entropy >= 3.45,
        // Default threshold for other patterns
        _ => entropy >= 3.5,
    }
}

#[derive(ValueEnum, Clone, Debug)]
enum IntegrityFilter {
    Part,
    Full,
    All,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory to scan
    #[arg(short, long)]
    path: PathBuf,

    /// Pattern database file
    #[arg(short, long, default_value = "rules/golden-rules.yml")]
    database: PathBuf,

    /// Only show high confidence matches
    #[arg(short = 'H', long)]
    high_confidence_only: bool,

    /// Output format: simple, detailed, json
    #[arg(short, long, default_value = "detailed")]
    format: String,

    /// File extensions to include (comma separated)
    #[arg(short, long, default_value = "")]
    include_ext: String,

    /// File extensions to exclude (comma separated)
    #[arg(short, long, default_value = "")]
    exclude_ext: String,

    /// Batch size for parallel processing (auto-detected if not specified)
    #[arg(short, long)]
    batch_size: Option<usize>,

    /// Maximum file size to scan in MB (default: 10MB)
    #[arg(short = 'M', long, default_value = "10")]
    max_file_size: u64,

    /// Output directory for JSON results
    #[arg(short = 'o', long)]
    output_dir: Option<PathBuf>,

    /// Output matches in token format
    #[arg(short = 't', long)]
    token_format: bool,

    /// Integrity filter: part, full, or all
    #[arg(short = 'I', long, default_value = "all")]
    integrity_filter: IntegrityFilter,

    /// Maximum line length to scan (skip lines longer than this)
    #[arg(short = 'L', long, default_value = "1000")]
    max_line_length: usize,
}

#[derive(Debug, Deserialize)]
struct Pattern {
    name: String,
    regex: String,
    confidence: String,
    integrity: String,
}

#[derive(Debug, Deserialize)]
struct PatternEntry {
    pattern: Pattern,
}

#[derive(Debug, Deserialize)]
struct PatternDatabase {
    patterns: Vec<PatternEntry>,
}

#[derive(Debug)]
struct MatchResult {
    file_path: PathBuf,
    line_number: usize,
    pattern_name: String,
    confidence: String,
    integrity: String,
    matched_text: String,
    line_content: String,
}

#[derive(Debug, Serialize)]
struct TokenMatch {
    file_hash: String,
    value: String,
}

#[derive(Debug)]
struct CompiledPatterns {
    individual_regexes: Vec<Regex>,
    names: Vec<String>,
    confidences: Vec<String>,
    integrities: Vec<String>,
    // Layered prefiltering for better performance
    fast_prefilter: AhoCorasick, // High-confidence keywords only
    full_prefilter: AhoCorasick, // All keywords
}

fn extract_tiered_keywords(pattern_entries: &[PatternEntry]) -> (Vec<String>, Vec<String>) {
    let mut fast_keywords = std::collections::HashSet::new();
    let mut full_keywords = std::collections::HashSet::new();

    // Fast filter: only most common/high-value keywords
    let fast_keyword_set = vec![
        "key", "password", "token", "secret", "api", "akia", "ghp_", "sk-", "auth",
    ];

    // Full filter: comprehensive keyword list
    let full_keyword_set = vec![
        "key",
        "password",
        "token",
        "secret",
        "api",
        "auth",
        "credential",
        "private",
        "access",
        "session",
        "jwt",
        "bearer",
        "oauth",
        "cert",
        "hash",
        "sign",
        "encrypt",
        "akia",
        "asia",
        "ghp_",
        "sk-",
        "github",
        "aws",
        "passwd",
        "pwd",
        "cred",
        "database",
        "db",
        "sql",
        "ssh",
        "ssl",
        "tls",
        "guid",
        "uuid",
    ];

    for keyword in fast_keyword_set {
        fast_keywords.insert(keyword.to_string());
        full_keywords.insert(keyword.to_string());
    }

    for keyword in full_keyword_set {
        full_keywords.insert(keyword.to_string());
    }

    // Extract from patterns
    for entry in pattern_entries {
        let pattern = &entry.pattern;

        // Extract from pattern name
        let name_lower = pattern.name.to_lowercase();
        let name_words: Vec<&str> = name_lower.split_whitespace().collect();
        for word in name_words {
            if word.len() >= 3 && word.len() <= 15 {
                full_keywords.insert(word.to_string());

                // Add to fast filter if it's a high-value keyword
                if word == "key"
                    || word == "password"
                    || word == "token"
                    || word == "secret"
                    || word == "api"
                    || word == "auth"
                {
                    fast_keywords.insert(word.to_string());
                }
            }
        }

        // Extract from regex (only important patterns)
        let regex_lower = pattern.regex.to_lowercase();

        // Fast filter keywords
        if regex_lower.contains("akia") {
            fast_keywords.insert("akia".to_string());
            full_keywords.insert("akia".to_string());
        }
        if regex_lower.contains("ghp_") {
            fast_keywords.insert("ghp_".to_string());
            full_keywords.insert("ghp_".to_string());
        }
        if regex_lower.contains("sk-") {
            fast_keywords.insert("sk-".to_string());
            full_keywords.insert("sk-".to_string());
        }

        // Full filter only
        if regex_lower.contains("token") {
            full_keywords.insert("token".to_string());
        }
        if regex_lower.contains("password") {
            full_keywords.insert("password".to_string());
        }
        if regex_lower.contains("secret") {
            full_keywords.insert("secret".to_string());
        }
        if regex_lower.contains("key") && !regex_lower.contains("akia") {
            full_keywords.insert("key".to_string());
        }
    }

    let mut fast_list: Vec<String> = fast_keywords.into_iter().collect();
    let mut full_list: Vec<String> = full_keywords.into_iter().collect();
    fast_list.sort();
    full_list.sort();

    println!(
        "{} Tiered keywords: {} fast, {} full",
        "INFO:".blue(),
        fast_list.len(),
        full_list.len()
    );

    (fast_list, full_list)
}

fn load_patterns(
    database_path: &Path,
    high_confidence_only: bool,
    integrity_filter: &IntegrityFilter,
) -> Result<CompiledPatterns, Box<dyn std::error::Error>> {
    let file = File::open(database_path)?;
    let db: PatternDatabase = serde_yaml::from_reader(file)?;

    let pattern_entries: Vec<_> = db
        .patterns
        .into_iter()
        .filter(|entry| !high_confidence_only || entry.pattern.confidence == "high")
        .filter(|entry| match integrity_filter {
            IntegrityFilter::Part => entry.pattern.integrity == "part",
            IntegrityFilter::Full => entry.pattern.integrity == "full",
            IntegrityFilter::All => true,
        })
        .collect();

    // Extract tiered keywords for optimized prefiltering
    let (fast_keywords, full_keywords) = extract_tiered_keywords(&pattern_entries);

    // Build fast prefilter (high-confidence keywords only)
    let fast_prefilter = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(&fast_keywords)
        .map_err(|e| format!("Failed to build fast Aho-Corasick automaton: {}", e))?;

    // Build full prefilter (all keywords)
    let full_prefilter = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(&full_keywords)
        .map_err(|e| format!("Failed to build full Aho-Corasick automaton: {}", e))?;

    // Compile individual regexes in parallel
    let compiled: Vec<_> = pattern_entries
        .par_iter()
        .enumerate()
        .filter_map(|(idx, entry)| {
            let pattern = &entry.pattern;
            match Regex::new(&pattern.regex) {
                Ok(regex) => Some((
                    idx,
                    pattern.name.clone(),
                    regex,
                    pattern.confidence.clone(),
                    pattern.integrity.clone(),
                )),
                Err(e) => {
                    eprintln!(
                        "{} Failed to compile pattern '{}': {}",
                        "WARNING:".yellow(),
                        pattern.name,
                        e
                    );
                    None
                }
            }
        })
        .collect();

    // Sort by original index to maintain order
    let mut compiled = compiled;
    compiled.sort_by_key(|(idx, _, _, _, _)| *idx);

    let mut names = Vec::new();
    let mut regexes = Vec::new();
    let mut confidences = Vec::new();
    let mut integrities = Vec::new();

    for (_, name, regex, confidence, integrity) in compiled {
        names.push(name);
        regexes.push(regex);
        confidences.push(confidence);
        integrities.push(integrity);
    }

    println!(
        "{} Loaded {} patterns ({} compiled, {} skipped) with tiered prefilter",
        "INFO:".blue(),
        pattern_entries.len(),
        regexes.len(),
        pattern_entries.len() - regexes.len()
    );

    Ok(CompiledPatterns {
        individual_regexes: regexes,
        names: names,
        confidences: confidences,
        integrities: integrities,
        fast_prefilter,
        full_prefilter,
    })
}

fn should_scan_file(file_path: &Path, include_ext: &[String], exclude_ext: &[String]) -> bool {
    if let Some(extension) = file_path.extension() {
        let ext = extension.to_string_lossy().to_lowercase();

        // Check exclude list first
        if !exclude_ext.is_empty() && exclude_ext.contains(&ext) {
            return false;
        }

        // Check include list
        if !include_ext.is_empty() && !include_ext.contains(&ext) {
            return false;
        }

        true
    } else {
        // Files without extensions are always scanned unless explicitly excluded
        true
    }
}

fn should_apply_regex_patterns_optimized(
    content: &str,
    fast_prefilter: &AhoCorasick,
    full_prefilter: &AhoCorasick,
    file_size: u64,
) -> bool {
    let content_lower = content.to_lowercase();

    // For small files (<1KB), use fast prefilter only to minimize overhead
    if file_size < 1024 {
        return fast_prefilter.find(&content_lower).is_some();
    }

    // For medium files (1KB-10KB), try fast first, then full if needed
    if file_size < 10 * 1024 {
        if fast_prefilter.find(&content_lower).is_some() {
            return true; // Fast keyword found, proceed to regex
        }
        return false; // No fast keywords, skip
    }

    // For large files (>10KB), use full prefilter for comprehensive coverage
    full_prefilter.find(&content_lower).is_some()
}

/// Check if a URL contains parameters (query string)
fn url_has_parameters(url: &str) -> bool {
    url.contains('?') || url.contains('&')
}

/// Extract multi-line private key content when a private key header is detected
/// Stops at the first occurrence of the private key end marker
fn extract_multiline_private_key(lines: &[&str], start_line: usize) -> Option<(String, usize)> {
    if start_line >= lines.len() {
        return None;
    }

    let current_line = lines[start_line];

    // Check if this line contains a private key header
    if !current_line.contains("-----BEGIN") || !current_line.contains("PRIVATE KEY-----") {
        return None;
    }

    // Extract the key type from the BEGIN marker
    let key_type = if current_line.contains("RSA") {
        "RSA"
    } else if current_line.contains("DSA") {
        "DSA"
    } else if current_line.contains("EC") {
        "EC"
    } else if current_line.contains("OPENSSH") {
        "OPENSSH"
    } else if current_line.contains("PGP") {
        "PGP"
    } else {
        "" // Generic private key
    };

    let mut private_key_lines = vec![current_line.to_string()];
    let mut current_idx = start_line + 1;
    let mut found_end = false;

    // Read lines until we find the private key end marker
    while current_idx < lines.len() && current_idx < start_line + 1000 {
        let line = lines[current_idx];
        
        // Check if this line contains the private key end marker
        if line.contains("-----END") && line.contains("PRIVATE KEY-----") {
            // Check if the END marker type matches the BEGIN marker type
            let end_matches_begin = match key_type {
                "RSA" => line.contains("RSA"),
                "DSA" => line.contains("DSA"),
                "EC" => line.contains("EC"),
                "OPENSSH" => line.contains("OPENSSH"),
                "PGP" => line.contains("PGP"),
                _ => true, // For generic private keys, any END marker is acceptable
            };
            
            if end_matches_begin {
                private_key_lines.push(line.to_string());
                found_end = true;
                break;
            } else {
                // If we found an END marker but it doesn't match the BEGIN type,
                // this is an incomplete key block - don't return anything
                return None;
            }
        }
        
        private_key_lines.push(line.to_string());
        current_idx += 1;
    }

    // If we found the end marker, return the full private key content
    if found_end {
        let private_key_content = private_key_lines.join("\n");
        Some((private_key_content, current_idx - start_line + 1))
    } else {
        // If we didn't find the end marker, don't return anything
        None
    }
}

fn scan_file(
    file_path: &Path,
    patterns: &CompiledPatterns,
    include_ext: &[String],
    exclude_ext: &[String],
    max_file_size: u64,
    max_line_length: usize,
    current_file_pb: Option<&ProgressBar>,
    current_pattern_pb: Option<&ProgressBar>,
) -> Result<Vec<MatchResult>, Box<dyn std::error::Error>> {
    if !should_scan_file(file_path, include_ext, exclude_ext) {
        return Ok(Vec::new());
    }

    // Check file size first
    let metadata = std::fs::metadata(file_path)?;
    if metadata.len() > max_file_size * 1024 * 1024 {
        return Ok(Vec::new());
    }

    let file = File::open(file_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let content = std::str::from_utf8(&mmap)?;
    let file_size = metadata.len();

    // Apply optimized tiered prefilter: only proceed with regex matching if keywords are found
    if !should_apply_regex_patterns_optimized(
        content,
        &patterns.fast_prefilter,
        &patterns.full_prefilter,
        file_size,
    ) {
        return Ok(Vec::new()); // Skip regex matching - no keywords found
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut matches = Vec::new();

    // Update current file progress (lazy update)
    if let Some(pb) = current_file_pb {
        pb.set_message(
            file_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        );
    }

    // Track lines we've already processed to avoid duplicate multi-line matches
    let mut processed_lines = std::collections::HashSet::new();

    // Process lines in parallel chunks for large files
    if lines.len() > 1000 {
        let chunk_size = std::cmp::max(100, lines.len() / num_cpus::get());
        let line_matches: Vec<Vec<MatchResult>> = lines
            .chunks(chunk_size)
            .enumerate()
            .par_bridge()
            .map(|(chunk_idx, chunk)| {
                let mut chunk_matches = Vec::new();
                let mut processed_lines = std::collections::HashSet::new();

                let mut local_line_idx = 0;
                while local_line_idx < chunk.len() {
                    let line = chunk[local_line_idx];
                    let line_number = chunk_idx * chunk_size + local_line_idx + 1;

                    // Skip lines that are too long (likely noise)
                    if line.len() > max_line_length {
                        local_line_idx += 1;
                        continue;
                    }

                    // Skip if we've already processed this line as part of a multi-line match
                    if processed_lines.contains(&local_line_idx) {
                        local_line_idx += 1;
                        continue;
                    }

                    // Check for multi-line private keys first
                    if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
                        // For parallel processing, we need to handle multi-line matches carefully
                        // We'll extract the private key from this chunk only
                        let mut private_key_lines = vec![line.to_string()];
                        let mut lines_consumed = 1;
                        let mut found_end = false;

                        // Read lines until we find the private key end marker
                        let mut next_idx = local_line_idx + 1;
                        while next_idx < chunk.len() && lines_consumed < 1000 {
                            let next_line = chunk[next_idx];
                            
                            // Check if this line contains the private key end marker
                            if next_line.contains("-----END") && next_line.contains("PRIVATE KEY-----") {
                                private_key_lines.push(next_line.to_string());
                                lines_consumed += 1;
                                found_end = true;
                                break;
                            }
                            
                            private_key_lines.push(next_line.to_string());
                            lines_consumed += 1;
                            next_idx += 1;
                        }

                        // Only report if we found the complete private key block
                        if found_end {
                            // Mark all lines in this multi-line match as processed
                            for i in 0..lines_consumed {
                                processed_lines.insert(local_line_idx + i);
                            }

                            let private_key_content = private_key_lines.join("\n");
                            chunk_matches.push(MatchResult {
                                file_path: file_path.to_path_buf(),
                                line_number,
                                pattern_name: "Private Key Block".to_string(),
                                confidence: "high".to_string(),
                                integrity: "full".to_string(),
                                matched_text: private_key_content,
                                line_content: line.to_string(),
                            });

                            // Skip to the next unprocessed line
                            local_line_idx += lines_consumed;
                            continue;
                        }
                    }

                    let mut found_high_confidence = false;

                    // Check high confidence patterns first
                    for (pattern_idx, regex) in patterns.individual_regexes.iter().enumerate() {
                        if patterns.confidences[pattern_idx] == "high" {
                            if let Ok(Some(captures)) = regex.captures(line) {
                                if let Some(matched_text) = captures.get(0) {
                                    let matched_text_str = matched_text.as_str();
                                    let pattern_name = &patterns.names[pattern_idx];

                                    // Rule 1: For URL patterns, skip if no parameters are present
                                    if pattern_name.contains("URL") || pattern_name.contains("URI") {
                                        if !url_has_parameters(matched_text_str) {
                                            continue; // Skip URL matches without parameters
                                        }
                                    }

                                    // For full integrity patterns, apply entropy filtering
                                    if patterns.integrities[pattern_idx] == "full" {
                                        if !has_sufficient_entropy(matched_text_str, pattern_name) {
                                            continue; // Skip low entropy matches for full integrity patterns
                                        }
                                    }

                                    chunk_matches.push(MatchResult {
                                        file_path: file_path.to_path_buf(),
                                        line_number,
                                        pattern_name: pattern_name.clone(),
                                        confidence: patterns.confidences[pattern_idx].clone(),
                                        integrity: patterns.integrities[pattern_idx].clone(),
                                        matched_text: matched_text_str.to_string(),
                                        line_content: line.to_string(),
                                    });
                                    found_high_confidence = true;
                                    break; // Skip remaining patterns for this line
                                }
                            }
                        }
                    }

                    // If no high confidence match found, check low confidence patterns
                    if !found_high_confidence {
                        for (pattern_idx, regex) in patterns.individual_regexes.iter().enumerate() {
                            if patterns.confidences[pattern_idx] == "low" {
                                if let Ok(Some(captures)) = regex.captures(line) {
                                    if let Some(matched_text) = captures.get(0) {
                                        let matched_text_str = matched_text.as_str();
                                        let pattern_name = &patterns.names[pattern_idx];

                                        // Rule 1: For URL patterns, skip if no parameters are present
                                        if pattern_name.contains("URL") || pattern_name.contains("URI") {
                                            if !url_has_parameters(matched_text_str) {
                                                continue; // Skip URL matches without parameters
                                            }
                                        }

                                        // For full integrity patterns, apply entropy filtering
                                        if patterns.integrities[pattern_idx] == "full" {
                                            if !has_sufficient_entropy(
                                                matched_text_str,
                                                pattern_name,
                                            ) {
                                                continue; // Skip low entropy matches for full integrity patterns
                                            }
                                        }

                                        chunk_matches.push(MatchResult {
                                            file_path: file_path.to_path_buf(),
                                            line_number,
                                            pattern_name: pattern_name.clone(),
                                            confidence: patterns.confidences[pattern_idx].clone(),
                                            integrity: patterns.integrities[pattern_idx].clone(),
                                            matched_text: matched_text_str.to_string(),
                                            line_content: line.to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }

                    local_line_idx += 1;
                }

                chunk_matches
            })
            .collect();

        // Flatten all matches
        for chunk_match in line_matches {
            matches.extend(chunk_match);
        }
    } else {
        // For small files, use sequential processing
        let mut line_number = 1;
        while line_number <= lines.len() {
            let line = lines[line_number - 1];

            // Skip lines that are too long (likely noise)
            if line.len() > max_line_length {
                line_number += 1;
                continue;
            }

            // Skip if we've already processed this line as part of a multi-line match
            if processed_lines.contains(&line_number) {
                line_number += 1;
                continue;
            }

            // Update current pattern progress (lazy update - only every 100 lines)
            if let Some(pb) = current_pattern_pb {
                if line_number % 100 == 0 {
                    pb.set_message(format!("Line {}/{}", line_number, lines.len()));
                }
            }

            // Check for multi-line private keys first
            if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
                if let Some((private_key_content, lines_consumed)) =
                    extract_multiline_private_key(&lines, line_number - 1)
                {
                    // Mark all lines in this multi-line match as processed
                    for i in 0..lines_consumed {
                        processed_lines.insert(line_number + i);
                    }

                    matches.push(MatchResult {
                        file_path: file_path.to_path_buf(),
                        line_number,
                        pattern_name: "Private Key Block".to_string(),
                        confidence: "high".to_string(),
                        integrity: "full".to_string(),
                        matched_text: private_key_content,
                        line_content: line.to_string(),
                    });

                    // Skip to the next unprocessed line
                    line_number += lines_consumed;
                    continue;
                }
            }

            let mut found_high_confidence = false;

            // Check high confidence patterns first
            for (pattern_idx, regex) in patterns.individual_regexes.iter().enumerate() {
                if patterns.confidences[pattern_idx] == "high" {
                    if let Ok(Some(captures)) = regex.captures(line) {
                        if let Some(matched_text) = captures.get(0) {
                            let matched_text_str = matched_text.as_str();
                            let pattern_name = &patterns.names[pattern_idx];

                            // Rule 1: For URL patterns, skip if no parameters are present
                            if pattern_name.contains("URL") || pattern_name.contains("URI") {
                                if !url_has_parameters(matched_text_str) {
                                    continue; // Skip URL matches without parameters
                                }
                            }

                            // Rule 2: Skip individual private key header matches since we handle them with multi-line extraction
                            if pattern_name == "Private Key Block" || pattern_name == "PGP Private Key Block" {
                                continue; // Skip individual private key header matches
                            }

                            // For full integrity patterns, apply entropy filtering
                            if patterns.integrities[pattern_idx] == "full" {
                                if !has_sufficient_entropy(matched_text_str, pattern_name) {
                                    continue; // Skip low entropy matches for full integrity patterns
                                }
                            }

                            matches.push(MatchResult {
                                file_path: file_path.to_path_buf(),
                                line_number,
                                pattern_name: pattern_name.clone(),
                                confidence: patterns.confidences[pattern_idx].clone(),
                                integrity: patterns.integrities[pattern_idx].clone(),
                                matched_text: matched_text_str.to_string(),
                                line_content: line.to_string(),
                            });
                            found_high_confidence = true;
                            break; // Skip remaining patterns for this line
                        }
                    }
                }
            }

            // If no high confidence match found, check low confidence patterns
            if !found_high_confidence {
                for (pattern_idx, regex) in patterns.individual_regexes.iter().enumerate() {
                    if patterns.confidences[pattern_idx] == "low" {
                        if let Ok(Some(captures)) = regex.captures(line) {
                            if let Some(matched_text) = captures.get(0) {
                                let matched_text_str = matched_text.as_str();
                                let pattern_name = &patterns.names[pattern_idx];

                                // Rule 1: For URL patterns, skip if no parameters are present
                                if pattern_name.contains("URL") || pattern_name.contains("URI") {
                                    if !url_has_parameters(matched_text_str) {
                                        continue; // Skip URL matches without parameters
                                    }
                                }

                                // Rule 2: Skip individual private key header matches since we handle them with multi-line extraction
                                if pattern_name == "Private Key Block" || pattern_name == "PGP Private Key Block" {
                                    continue; // Skip individual private key header matches
                                }

                                // For full integrity patterns, apply entropy filtering
                                if patterns.integrities[pattern_idx] == "full" {
                                    if !has_sufficient_entropy(matched_text_str, pattern_name) {
                                        continue; // Skip low entropy matches for full integrity patterns
                                    }
                                }

                                matches.push(MatchResult {
                                    file_path: file_path.to_path_buf(),
                                    line_number,
                                    pattern_name: pattern_name.clone(),
                                    confidence: patterns.confidences[pattern_idx].clone(),
                                    integrity: patterns.integrities[pattern_idx].clone(),
                                    matched_text: matched_text_str.to_string(),
                                    line_content: line.to_string(),
                                });
                            }
                        }
                    }
                }
            }

            line_number += 1;
        }
    }

    Ok(matches)
}

fn print_simple_results(results: &[MatchResult]) {
    for result in results {
        println!(
            "{}:{} {} [{}]",
            result.file_path.display(),
            result.line_number,
            result.pattern_name,
            result.confidence
        );
    }
}

fn print_detailed_results(results: &[MatchResult]) {
    for result in results {
        let confidence_color = match result.confidence.as_str() {
            "high" => "red",
            "low" => "yellow",
            _ => "white",
        };

        let integrity_color = match result.integrity.as_str() {
            "full" => "green",
            "part" => "yellow",
            _ => "white",
        };

        println!(
            "\n{} {}:{} {}",
            "→".cyan(),
            result.file_path.display().to_string().bold(),
            result.line_number.to_string().bold(),
            result.pattern_name.bold()
        );
        println!(
            "  {}: {}",
            "Confidence".dimmed(),
            result.confidence.color(confidence_color)
        );
        println!(
            "  {}: {}",
            "Integrity".dimmed(),
            result.integrity.color(integrity_color)
        );
        println!("  {}: {}", "Match".dimmed(), result.matched_text.red());
        println!("  {}: {}", "Line".dimmed(), result.line_content.trim());
    }
}

fn print_json_results(results: &[MatchResult]) {
    let json_results: Vec<HashMap<&str, String>> = results
        .iter()
        .map(|r| {
            let mut map = HashMap::new();
            map.insert("file", r.file_path.to_string_lossy().to_string());
            map.insert("line", r.line_number.to_string());
            map.insert("pattern", r.pattern_name.clone());
            map.insert("confidence", r.confidence.clone());
            map.insert("match", r.matched_text.clone());
            map.insert("content", r.line_content.clone());
            map
        })
        .collect();

    match serde_json::to_string_pretty(&json_results) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize results: {}", e),
    }
}

fn print_token_results(results: &[MatchResult]) {
    let token_results: Vec<TokenMatch> = results
        .iter()
        .map(|r| TokenMatch {
            file_hash: r
                .file_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            value: r.matched_text.clone(),
        })
        .collect();

    match serde_json::to_string_pretty(&token_results) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize token results: {}", e),
    }
}

fn write_json_results_to_file(
    results: &[MatchResult],
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let json_results: Vec<HashMap<&str, String>> = results
        .iter()
        .map(|r| {
            let mut map = HashMap::new();
            map.insert("file", r.file_path.to_string_lossy().to_string());
            map.insert("line", r.line_number.to_string());
            map.insert("pattern", r.pattern_name.clone());
            map.insert("confidence", r.confidence.clone());
            map.insert("match", r.matched_text.clone());
            map.insert("content", r.line_content.clone());
            map
        })
        .collect();

    // Create output directory if it doesn't exist
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = File::create(output_path)?;
    serde_json::to_writer_pretty(file, &json_results)?;

    println!(
        "{} Results written to: {}",
        "INFO:".blue(),
        output_path.display()
    );

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let start_time = Instant::now();

    // Parse file extension filters
    let include_ext: Vec<String> = args
        .include_ext
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_lowercase())
        .collect();

    let exclude_ext: Vec<String> = args
        .exclude_ext
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_lowercase())
        .collect();

    println!(
        "{} Scanning directory: {}",
        "INFO:".blue(),
        args.path.display()
    );
    println!(
        "{} Using pattern database: {}",
        "INFO:".blue(),
        args.database.display()
    );

    // Load patterns
    let pattern_load_start = Instant::now();
    let patterns = load_patterns(
        &args.database,
        args.high_confidence_only,
        &args.integrity_filter,
    )?;
    let pattern_load_time = pattern_load_start.elapsed();

    if patterns.individual_regexes.is_empty() {
        eprintln!(
            "{} No patterns loaded. Check your database file.",
            "ERROR:".red()
        );
        return Ok(());
    }

    // Collect all files to scan first
    let files_to_scan: Vec<PathBuf> = WalkBuilder::new(&args.path)
        .build()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.into_path())
        .filter(|path| path.is_file())
        .filter(|path| should_scan_file(path, &include_ext, &exclude_ext))
        .collect();

    let total_files = files_to_scan.len();
    println!("{} Found {} files to scan", "INFO:".blue(), total_files);

    // Dynamic batch sizing based on file count
    let batch_size = if let Some(user_batch) = args.batch_size {
        user_batch
    } else {
        match total_files {
            0..=1000 => 100,        // Small directories: process all at once
            1001..=10000 => 500,    // Medium directories: medium batches
            10001..=100000 => 1000, // Large directories: larger batches
            _ => 2000,              // Very large directories: largest batches
        }
    };

    println!(
        "{} Using batch size: {} files per batch",
        "INFO:".blue(),
        batch_size
    );

    let scanned_files = files_to_scan.len();
    println!("{} Found {} files to scan", "INFO:".blue(), scanned_files);

    // Use Arc to share patterns across threads efficiently
    let patterns_arc = Arc::new(patterns);

    // Create multi-progress display for three-line status
    let multi_progress = MultiProgress::new();

    // Line 1: Overall progress bar
    let overall_pb = ProgressBar::new(total_files as u64);
    overall_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) Files scanned")
            .unwrap()
            .progress_chars("█▓▒░")
    );
    let overall_pb = multi_progress.add(overall_pb);

    // Line 2: Current file being processed
    let current_file_pb = ProgressBar::new(1);
    current_file_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.yellow} Current file: {msg}")
            .unwrap(),
    );
    current_file_pb.enable_steady_tick(std::time::Duration::from_millis(100));
    let current_file_pb = multi_progress.add(current_file_pb);

    // Line 3: Current pattern being matched
    let current_pattern_pb = ProgressBar::new(1);
    current_pattern_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} Current pattern: {msg}")
            .unwrap(),
    );
    current_pattern_pb.enable_steady_tick(std::time::Duration::from_millis(100));
    let current_pattern_pb = multi_progress.add(current_pattern_pb);

    println!("{} Starting scan with progress tracking...", "INFO:".blue());

    // Parallel file scanning with progress tracking
    let all_matches: Vec<MatchResult> = files_to_scan
        .par_iter()
        .filter_map(|file_path| {
            overall_pb.inc(1);
            scan_file(
                file_path,
                &patterns_arc,
                &include_ext,
                &exclude_ext,
                args.max_file_size,
                args.max_line_length,
                Some(&current_file_pb),
                Some(&current_pattern_pb),
            )
            .ok()
        })
        .flatten()
        .collect();

    // Clean up progress bars
    overall_pb.finish_with_message("Complete");
    current_file_pb.finish_with_message("Done");
    current_pattern_pb.finish_with_message("Done");

    let scan_time = start_time.elapsed();
    let files_per_second = scanned_files as f64 / scan_time.as_secs_f64();

    println!(
        "\n{} Scanned {} files, found {} matches",
        "SUMMARY:".green(),
        scanned_files,
        all_matches.len()
    );
    println!(
        "{} Pattern loading: {:.2?}",
        "PERF:".cyan(),
        pattern_load_time
    );
    println!("{} Total scan time: {:.2?}", "PERF:".cyan(), scan_time);
    println!(
        "{} Files per second: {:.1}",
        "PERF:".cyan(),
        files_per_second
    );

    // Output results
    if args.token_format {
        print_token_results(&all_matches);
    } else {
        match args.format.as_str() {
            "simple" => print_simple_results(&all_matches),
            "json" => print_json_results(&all_matches),
            _ => print_detailed_results(&all_matches),
        }
    }

    // Write to file if output directory is specified
    if let Some(output_dir) = &args.output_dir {
        let output_path = output_dir.join("result.json");
        if let Err(e) = write_json_results_to_file(&all_matches, &output_path) {
            eprintln!("{} Failed to write results to file: {}", "ERROR:".red(), e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_insensitive_detection() {
        // Create simple prefilters with just a few keywords
        let fast_prefilter = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&["token", "key", "password"])
            .unwrap();

        let full_prefilter = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&["token", "key", "password", "api", "secret"])
            .unwrap();

        // Test various case combinations
        let test_cases = vec![
            ("token", true),
            ("TOKEN", true),
            ("Token", true),
            ("ToKeN", true),
            ("api_key=abc123", true),
            ("API_KEY=ABC123", true),
            ("Password123", true),
            ("PASSWORD123", true),
            ("normal text", false),
            ("", false),
        ];

        for (content, expected) in test_cases {
            let result = should_apply_regex_patterns_optimized(
                content,
                &fast_prefilter,
                &full_prefilter,
                1000,
            );
            assert_eq!(result, expected, "Failed for content: '{}'", content);
        }
    }

    #[test]
    fn test_extract_keywords_from_patterns() {
        let pattern_entries = vec![
            PatternEntry {
                pattern: Pattern {
                    name: "AWS API Key".to_string(),
                    regex: "AKIA[0-9A-Z]{16}".to_string(),
                    confidence: "high".to_string(),
                    integrity: "full".to_string(),
                },
            },
            PatternEntry {
                pattern: Pattern {
                    name: "Password in URL".to_string(),
                    regex: "password=[^\\s&]+".to_string(),
                    confidence: "high".to_string(),
                    integrity: "full".to_string(),
                },
            },
        ];

        let (fast_keywords, full_keywords) = extract_tiered_keywords(&pattern_entries);

        // Should contain common keywords in both lists
        assert!(fast_keywords.contains(&"key".to_string()));
        assert!(fast_keywords.contains(&"password".to_string()));
        assert!(fast_keywords.contains(&"akia".to_string()));

        // Full list should contain more keywords
        assert!(full_keywords.contains(&"key".to_string()));
        assert!(full_keywords.contains(&"password".to_string()));
        assert!(full_keywords.contains(&"akia".to_string()));
        assert!(full_keywords.len() >= fast_keywords.len());
    }

    #[test]
    fn test_should_apply_regex_patterns() {
        // Create simple prefilters
        let fast_prefilter = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&["key", "password", "token"])
            .unwrap();

        let full_prefilter = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&["key", "password", "token", "api", "secret"])
            .unwrap();

        // Content with keywords should return true
        let content_with_keywords = "This file contains an API_KEY=abc123";
        assert!(should_apply_regex_patterns_optimized(
            content_with_keywords,
            &fast_prefilter,
            &full_prefilter,
            1000
        ));

        // Content without keywords should return false
        let content_without_keywords = "This is just a normal file with regular content";
        assert!(!should_apply_regex_patterns_optimized(
            content_without_keywords,
            &fast_prefilter,
            &full_prefilter,
            1000
        ));

        // Case insensitive matching
        let content_case_insensitive = "The PASSWORD is secret";
        assert!(should_apply_regex_patterns_optimized(
            content_case_insensitive,
            &fast_prefilter,
            &full_prefilter,
            1000
        ));
    }

    #[test]
    fn test_prefilter_performance() {
        let fast_prefilter = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&["key", "password", "token", "api", "secret"])
            .unwrap();

        let full_prefilter = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&[
                "key", "password", "token", "api", "secret", "auth", "cred", "hash",
            ])
            .unwrap();

        // Test different file sizes
        let small_content = "This is a normal file with no matching words.";
        let large_content = "This is a large file with normal content only. ".repeat(1000);

        // Small file should use fast prefilter
        let result = should_apply_regex_patterns_optimized(
            &small_content,
            &fast_prefilter,
            &full_prefilter,
            500,
        );
        assert!(!result);

        // Large content without keywords
        let result = should_apply_regex_patterns_optimized(
            &large_content,
            &fast_prefilter,
            &full_prefilter,
            50000,
        );
        assert!(!result);

        // Content with keywords
        let content_with_keyword = large_content.clone() + " Here is a secret key";
        let result = should_apply_regex_patterns_optimized(
            &content_with_keyword,
            &fast_prefilter,
            &full_prefilter,
            50000,
        );
        assert!(result);
    }

    #[test]
    fn test_entropy_filtering() {
        // High entropy secrets should pass
        assert!(has_sufficient_entropy(
            "AKIAIOSFODNN7EXAMPLE",
            "AWS API Key"
        ));
        assert!(has_sufficient_entropy(
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "GitHub Token"
        ));

        // Low entropy strings should be filtered out
        assert!(!has_sufficient_entropy("password", "Password"));

        // Different thresholds for different pattern types
        assert!(has_sufficient_entropy("MyPass123", "Password")); // Lower threshold for passwords
        assert!(!has_sufficient_entropy("MyPass123", "API Key")); // Higher threshold for API keys
    }
}
