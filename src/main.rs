//! RipGitleak - 代码库敏感信息检测工具
//! 
//! 模块化重构版本，将功能按职责分离到不同模块

use clap::Parser;
use colored::Colorize;
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::path::PathBuf;
use std::time::Instant;

// 导入模块
mod config;
mod scanner;
mod analysis;
mod output;
mod progress;
mod utils;

// 导入具体功能
use config::args::Args;
use output::formatter::{print_simple_results, print_detailed_results, print_json_results, print_token_results};
use output::writer::write_json_results_to_file;
use progress::display::create_multi_progress;
use scanner::engine::create_patterns_arc;
use scanner::file_scanner::scan_file;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let start_time = Instant::now();

    // 解析文件扩展名过滤器
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
        "{} 正在扫描目录: {}",
        "INFO:".blue(),
        args.path.display()
    );
    println!(
        "{} 使用模式数据库: {}",
        "INFO:".blue(),
        args.database.display()
    );

    // 加载模式
    let pattern_load_start = Instant::now();
    let patterns_arc = create_patterns_arc(
        &args.database,
        args.high_confidence_only,
        &args.integrity_filter,
    )?;
    let pattern_load_time = pattern_load_start.elapsed();

    if patterns_arc.individual_regexes.is_empty() {
        eprintln!(
            "{} 没有加载任何模式。请检查您的数据库文件。",
            "ERROR:".red()
        );
        return Ok(());
    }

    // 首先收集所有要扫描的文件
    let files_to_scan: Vec<PathBuf> = WalkBuilder::new(&args.path)
        .build()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.into_path())
        .filter(|path| path.is_file())
        .filter(|path| utils::keywords::should_scan_file(path, &include_ext, &exclude_ext))
        .collect();

    let total_files = files_to_scan.len();
    println!("{} 找到 {} 个文件需要扫描", "INFO:".blue(), total_files);

    // 基于文件数量的动态批次大小
    let batch_size = if let Some(user_batch) = args.batch_size {
        user_batch
    } else {
        match total_files {
            0..=1000 => 100,        // 小目录：一次性处理所有
            1001..=10000 => 500,    // 中等目录：中等批次
            10001..=100000 => 1000, // 大目录：较大批次
            _ => 2000,              // 非常大的目录：最大批次
        }
    };

    println!(
        "{} 使用批次大小: 每批次 {} 个文件",
        "INFO:".blue(),
        batch_size
    );

    let scanned_files = files_to_scan.len();
    println!("{} 找到 {} 个文件需要扫描", "INFO:".blue(), scanned_files);

    // 创建进度显示
    let (_multi_progress, overall_pb, current_file_pb, current_pattern_pb) = 
        create_multi_progress(total_files as u64);

    println!("{} 开始扫描并跟踪进度...", "INFO:".blue());

    // 并行文件扫描与进度跟踪
    let all_matches: Vec<output::formatter::MatchResult> = files_to_scan
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

    // 清理进度条
    overall_pb.finish_with_message("完成");
    current_file_pb.finish_with_message("完成");
    current_pattern_pb.finish_with_message("完成");

    let scan_time = start_time.elapsed();
    let files_per_second = scanned_files as f64 / scan_time.as_secs_f64();

    println!(
        "\n{} 已扫描 {} 个文件，找到 {} 个匹配",
        "SUMMARY:".green(),
        scanned_files,
        all_matches.len()
    );
    println!(
        "{} 模式加载时间: {:.2?}",
        "PERF:".cyan(),
        pattern_load_time
    );
    println!("{} 总扫描时间: {:.2?}", "PERF:".cyan(), scan_time);
    println!(
        "{} 每秒文件数: {:.1}",
        "PERF:".cyan(),
        files_per_second
    );

    // 输出结果
    if args.token_format {
        print_token_results(&all_matches);
    } else {
        match args.format.as_str() {
            "simple" => print_simple_results(&all_matches),
            "json" => print_json_results(&all_matches),
            _ => print_detailed_results(&all_matches),
        }
    }

    // 如果指定了输出目录，写入文件
    if let Some(output_dir) = &args.output_dir {
        let output_path = output_dir.join("result.json");
        if let Err(e) = write_json_results_to_file(&all_matches, &output_path) {
            eprintln!("{} 写入结果到文件失败: {}", "ERROR:".red(), e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aho_corasick::{AhoCorasick, MatchKind};

    #[test]
    fn test_case_insensitive_detection() {
        // 创建仅包含几个关键词的简单预过滤器
        let fast_prefilter = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&["token", "key", "password"])
            .unwrap();

        let full_prefilter = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&["token", "key", "password", "api", "secret"])
            .unwrap();

        // 测试各种大小写组合
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
            let result = scanner::prefilter::should_apply_regex_patterns_optimized(
                content,
                &fast_prefilter,
                &full_prefilter,
                1000,
            );
            assert_eq!(result, expected, "内容 '{}' 测试失败", content);
        }
    }

    #[test]
    fn test_entropy_filtering() {
        // 高熵密钥应该通过
        assert!(analysis::entropy::has_sufficient_entropy(
            "AKIAIOSFODNN7EXAMPLE",
            "AWS API Key"
        ));
        assert!(analysis::entropy::has_sufficient_entropy(
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "GitHub Token"
        ));

        // 低熵字符串应该被过滤掉
        assert!(!analysis::entropy::has_sufficient_entropy("password", "Password"));

        // 不同模式类型的不同阈值
        assert!(analysis::entropy::has_sufficient_entropy("MySecurePass123!", "Password")); // 密码的较低阈值
        assert!(!analysis::entropy::has_sufficient_entropy("MyPass123", "API Key")); // API密钥的较高阈值
    }
}
