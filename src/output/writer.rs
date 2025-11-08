use colored::Colorize;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use crate::output::formatter::MatchResult;

/// 将JSON结果写入文件
pub fn write_json_results_to_file(
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

    // 如果输出目录不存在则创建
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = File::create(output_path)?;
    serde_json::to_writer_pretty(file, &json_results)?;

    println!(
        "{} 结果已写入: {}",
        "INFO:".blue(),
        output_path.display()
    );

    Ok(())
}
