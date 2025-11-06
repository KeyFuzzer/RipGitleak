use clap::Parser;
use colored::*;
use ignore::WalkBuilder;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use memmap2::Mmap;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory to scan
    #[arg(short, long, default_value = ".")]
    path: PathBuf,

    /// Pattern database file
    #[arg(short, long, default_value = "secrets-patterns-db/db/rules-stable.yml")]
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
}

#[derive(Debug, Deserialize)]
struct Pattern {
    name: String,
    regex: String,
    confidence: String,
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
    matched_text: String,
    line_content: String,
}

#[derive(Debug)]
struct CompiledPatterns {
    individual_regexes: Vec<Regex>,
    names: Vec<String>,
    confidences: Vec<String>,
}

fn load_patterns(database_path: &Path, high_confidence_only: bool) -> Result<CompiledPatterns, Box<dyn std::error::Error>> {
    let file = File::open(database_path)?;
    let db: PatternDatabase = serde_yaml::from_reader(file)?;

    let pattern_entries: Vec<_> = db.patterns
        .into_iter()
        .filter(|entry| !high_confidence_only || entry.pattern.confidence == "high")
        .collect();

    // Skip RegexSet since it can be too large for many patterns

    // Compile individual regexes in parallel
    let compiled: Vec<_> = pattern_entries
        .par_iter()
        .enumerate()
        .filter_map(|(idx, entry)| {
            let pattern = &entry.pattern;
            match Regex::new(&pattern.regex) {
                Ok(regex) => Some((idx, pattern.name.clone(), regex, pattern.confidence.clone())),
                Err(e) => {
                    eprintln!("{} Failed to compile pattern '{}': {}", "WARNING:".yellow(), pattern.name, e);
                    None
                }
            }
        })
        .collect();

    // Sort by original index to maintain order
    let mut compiled = compiled;
    compiled.sort_by_key(|(idx, _, _, _)| *idx);

    let mut names = Vec::new();
    let mut regexes = Vec::new();
    let mut confidences = Vec::new();

    for (_, name, regex, confidence) in compiled {
        names.push(name);
        regexes.push(regex);
        confidences.push(confidence);
    }

    println!("{} Loaded {} patterns ({} compiled, {} skipped)", 
        "INFO:".blue(), 
        pattern_entries.len(),
        regexes.len(),
        pattern_entries.len() - regexes.len()
    );

    Ok(CompiledPatterns {
        individual_regexes: regexes,
        names: names,
        confidences: confidences,
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

fn scan_file(
    file_path: &Path,
    patterns: &CompiledPatterns,
    include_ext: &[String],
    exclude_ext: &[String],
    max_file_size: u64,
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
    
    let lines: Vec<&str> = content.lines().collect();
    let mut matches = Vec::new();

    // Update current file progress (lazy update)
    if let Some(pb) = current_file_pb {
        pb.set_message(file_path.file_name().unwrap_or_default().to_string_lossy().to_string());
    }

    // Process lines in parallel chunks for large files
    if lines.len() > 1000 {
        let chunk_size = std::cmp::max(100, lines.len() / num_cpus::get());
        let line_matches: Vec<Vec<MatchResult>> = lines
            .chunks(chunk_size)
            .enumerate()
            .par_bridge()
            .map(|(chunk_idx, chunk)| {
                let mut chunk_matches = Vec::new();
                
                for (local_line_idx, line) in chunk.iter().enumerate() {
                    let line_number = chunk_idx * chunk_size + local_line_idx + 1;
                    let mut found_high_confidence = false;
                    
                    // Check high confidence patterns first
                    for (pattern_idx, regex) in patterns.individual_regexes.iter().enumerate() {
                        if patterns.confidences[pattern_idx] == "high" {
                            if let Some(captures) = regex.captures(line) {
                                if let Some(matched_text) = captures.get(0) {
                                    chunk_matches.push(MatchResult {
                                        file_path: file_path.to_path_buf(),
                                        line_number,
                                        pattern_name: patterns.names[pattern_idx].clone(),
                                        confidence: patterns.confidences[pattern_idx].clone(),
                                        matched_text: matched_text.as_str().to_string(),
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
                                if let Some(captures) = regex.captures(line) {
                                    if let Some(matched_text) = captures.get(0) {
                                        chunk_matches.push(MatchResult {
                                            file_path: file_path.to_path_buf(),
                                            line_number,
                                            pattern_name: patterns.names[pattern_idx].clone(),
                                            confidence: patterns.confidences[pattern_idx].clone(),
                                            matched_text: matched_text.as_str().to_string(),
                                            line_content: line.to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
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
        for (line_number, line) in lines.iter().enumerate() {
            let line_number = line_number + 1;
            
            // Update current pattern progress (lazy update - only every 100 lines)
            if let Some(pb) = current_pattern_pb {
                if line_number % 100 == 0 {
                    pb.set_message(format!("Line {}/{}", line_number, lines.len()));
                }
            }
            
            let mut found_high_confidence = false;
            
            // Check high confidence patterns first
            for (pattern_idx, regex) in patterns.individual_regexes.iter().enumerate() {
                if patterns.confidences[pattern_idx] == "high" {
                    if let Some(captures) = regex.captures(line) {
                        if let Some(matched_text) = captures.get(0) {
                            matches.push(MatchResult {
                                file_path: file_path.to_path_buf(),
                                line_number,
                                pattern_name: patterns.names[pattern_idx].clone(),
                                confidence: patterns.confidences[pattern_idx].clone(),
                                matched_text: matched_text.as_str().to_string(),
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
                        if let Some(captures) = regex.captures(line) {
                            if let Some(matched_text) = captures.get(0) {
                                matches.push(MatchResult {
                                    file_path: file_path.to_path_buf(),
                                    line_number,
                                    pattern_name: patterns.names[pattern_idx].clone(),
                                    confidence: patterns.confidences[pattern_idx].clone(),
                                    matched_text: matched_text.as_str().to_string(),
                                    line_content: line.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(matches)
}

fn print_simple_results(results: &[MatchResult]) {
    for result in results {
        println!("{}:{} {} [{}]", 
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

        println!("\n{} {}:{} {}", 
            "→".cyan(),
            result.file_path.display().to_string().bold(),
            result.line_number.to_string().bold(),
            result.pattern_name.bold()
        );
        println!("  {}: {}", "Confidence".dimmed(), result.confidence.color(confidence_color));
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

fn write_json_results_to_file(results: &[MatchResult], output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
    
    println!("{} Results written to: {}", "INFO:".blue(), output_path.display());
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let start_time = Instant::now();

    // Parse file extension filters
    let include_ext: Vec<String> = args.include_ext
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_lowercase())
        .collect();

    let exclude_ext: Vec<String> = args.exclude_ext
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_lowercase())
        .collect();

    println!("{} Scanning directory: {}", "INFO:".blue(), args.path.display());
    println!("{} Using pattern database: {}", "INFO:".blue(), args.database.display());

    // Load patterns
    let pattern_load_start = Instant::now();
    let patterns = load_patterns(&args.database, args.high_confidence_only)?;
    let pattern_load_time = pattern_load_start.elapsed();

    if patterns.individual_regexes.is_empty() {
        eprintln!("{} No patterns loaded. Check your database file.", "ERROR:".red());
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
            0..=1000 => 100,           // Small directories: process all at once
            1001..=10000 => 500,       // Medium directories: medium batches
            10001..=100000 => 1000,    // Large directories: larger batches
            _ => 2000,                 // Very large directories: largest batches
        }
    };

    println!("{} Using batch size: {} files per batch", "INFO:".blue(), batch_size);

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
            .unwrap()
    );
    current_file_pb.enable_steady_tick(std::time::Duration::from_millis(100));
    let current_file_pb = multi_progress.add(current_file_pb);

    // Line 3: Current pattern being matched
    let current_pattern_pb = ProgressBar::new(1);
    current_pattern_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} Current pattern: {msg}")
            .unwrap()
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
                Some(&current_file_pb),
                Some(&current_pattern_pb)
            ).ok()
        })
        .flatten()
        .collect();

    // Clean up progress bars
    overall_pb.finish_with_message("Complete");
    current_file_pb.finish_with_message("Done");
    current_pattern_pb.finish_with_message("Done");

    let scan_time = start_time.elapsed();
    let files_per_second = scanned_files as f64 / scan_time.as_secs_f64();
    
    println!("\n{} Scanned {} files, found {} matches", 
        "SUMMARY:".green(),
        scanned_files,
        all_matches.len()
    );
    println!("{} Pattern loading: {:.2?}", "PERF:".cyan(), pattern_load_time);
    println!("{} Total scan time: {:.2?}", "PERF:".cyan(), scan_time);
    println!("{} Files per second: {:.1}", "PERF:".cyan(), files_per_second);

    // Output results
    match args.format.as_str() {
        "simple" => print_simple_results(&all_matches),
        "json" => print_json_results(&all_matches),
        _ => print_detailed_results(&all_matches),
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
