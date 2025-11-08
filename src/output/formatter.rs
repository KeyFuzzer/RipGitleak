use colored::*;
use std::collections::HashMap;

use crate::config::patterns::TokenMatch;

/// 匹配结果结构
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub file_path: std::path::PathBuf,
    pub line_number: usize,
    pub pattern_name: String,
    pub confidence: String,
    pub integrity: String,
    pub matched_text: String,
    pub line_content: String,
}

/// 以简单格式打印结果
pub fn print_simple_results(results: &[MatchResult]) {
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

/// 以详细格式打印结果
pub fn print_detailed_results(results: &[MatchResult]) {
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

/// 以JSON格式打印结果
pub fn print_json_results(results: &[MatchResult]) {
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
        Err(e) => eprintln!("序列化结果失败: {}", e),
    }
}

/// 以token格式打印结果
pub fn print_token_results(results: &[MatchResult]) {
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
        Err(e) => eprintln!("序列化token结果失败: {}", e),
    }
}
